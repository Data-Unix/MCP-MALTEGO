"""Transforms integrados: se ejecutan dentro del MCP, sin servidor de transforms.

- Sin API key: DNS sobre HTTPS (Google, con respaldo en Cloudflare), RDAP (WHOIS moderno), crt.sh (certificados),
  Team Cymru (ASN y prefijo por DNS), comprobación de perfiles por alias y análisis de correos/URLs.
- Con API key (se activan solos al definir la variable de entorno): VirusTotal, Shodan, SecurityTrails, Censys,
  Hunter.io, Have I Been Pwned, GreyNoise y Tatum.

Todos devuelven la misma estructura que un servidor de transforms de Maltego (TransformResponse), así que se
guardan, puntúan y exportan igual que los transforms TRX/iTDS.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import os
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from maltego_mcp import __version__
from maltego_mcp.breaches import classify_breach_indicator, query_local_breaches
from maltego_mcp.errors import TransformError
from maltego_mcp.humint import analyze_subject_behavior
from maltego_mcp.transforms.protocol import ResultEntity, TransformResponse

USER_AGENT = f"maltego-mcp/{__version__} (+https://github.com/Data-Unix/MCP-MALTEGO)"
DOH_ENDPOINTS = ("https://dns.google/resolve", "https://cloudflare-dns.com/dns-query")
RDAP_ENDPOINTS = ("https://rdap.org", "https://rdap-bootstrap.arin.net/bootstrap")
DNS_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}
HOST_TYPES = ("maltego.Domain", "maltego.DNSName", "maltego.Website", "maltego.MXRecord", "maltego.NSRecord")
IP_TYPES = ("maltego.IPv4Address", "maltego.IPv6Address")

Handler = Callable[["BuiltinContext", str, str, dict[str, str], int], Awaitable[TransformResponse]]


@dataclass(slots=True)
class BuiltinContext:
    http: httpx.AsyncClient
    env: dict[str, str] = field(default_factory=lambda: dict(os.environ))

    def key(self, name: str) -> str:
        value = self.env.get(name, "").strip()
        if not value:
            raise TransformError(f"Falta la variable de entorno {name} (clave de API del proveedor).")
        return value


@dataclass(frozen=True, slots=True)
class BuiltinTransform:
    name: str
    input_types: tuple[str, ...]
    output_types: tuple[str, ...]
    description: str
    category: str
    handler: Handler
    requires: tuple[str, ...] = ()

    def available(self, env: dict[str, str]) -> bool:
        return all(env.get(v, "").strip() for v in self.requires)


def new_http_client(timeout_s: float = 20.0, transport: httpx.AsyncBaseTransport | None = None) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=timeout_s, follow_redirects=True, headers={"User-Agent": USER_AGENT}, transport=transport
    )


# ------------------------------------------------------------------------------------------ utilidades
def _ent(etype: str, value: str, label: str, weight: int = 100, **props: str) -> ResultEntity:
    return ResultEntity(
        etype,
        value,
        weight,
        {k.replace("__", "."): v for k, v in props.items() if v},
        {"maltego.link.label": label} if label else {},
    )


async def _get_json(
    ctx: BuiltinContext,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    auth: tuple[str, str] | None = None,
    not_found_ok: bool = False,
) -> Any:
    try:
        resp = await ctx.http.get(url, headers=headers, params=params, auth=auth)
    except httpx.TimeoutException as exc:
        raise TransformError(f"Tiempo de espera agotado consultando {urlsplit(url).hostname}.") from exc
    except httpx.HTTPError as exc:
        raise TransformError(f"No se pudo contactar con {urlsplit(url).hostname}.") from exc
    if resp.status_code == 404 and not_found_ok:
        return None
    if resp.status_code in (401, 403):
        raise TransformError(f"{urlsplit(url).hostname} rechazó la petición ({resp.status_code}): revisa la API key.")
    if resp.status_code == 429:
        raise TransformError(f"{urlsplit(url).hostname} limita las peticiones (429). Reintenta más tarde.")
    if resp.status_code >= 400:
        raise TransformError(f"{urlsplit(url).hostname} respondió HTTP {resp.status_code}.")
    try:
        return resp.json()
    except ValueError as exc:
        raise TransformError(f"{urlsplit(url).hostname} devolvió una respuesta que no es JSON.") from exc


async def doh(ctx: BuiltinContext, name: str, rtype: str) -> list[str]:
    """Consulta DNS sobre HTTPS (JSON). Devuelve los datos de las respuestas del tipo pedido."""
    last: Exception | None = None
    for endpoint in DOH_ENDPOINTS:
        try:
            data = await _get_json(
                ctx, endpoint, params={"name": name, "type": rtype}, headers={"accept": "application/dns-json"}
            )
        except TransformError as exc:
            last = exc
            continue
        if data.get("Status") not in (0, 3):  # 3 = NXDOMAIN (sin resultados)
            last = TransformError(f"Error DNS {data.get('Status')} resolviendo {name}.")
            continue
        wanted = DNS_TYPES[rtype]
        return [str(a.get("data", "")) for a in data.get("Answer", []) if a.get("type") == wanted]
    raise last or TransformError("No se pudo resolver por DNS sobre HTTPS.")


_TXT_CHUNK_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _txt(data: str) -> str:
    """Une las cadenas de un registro TXT ("a" "b" -> ab), como hacen SPF/DKIM largos."""
    chunks = _TXT_CHUNK_RE.findall(data)
    return "".join(chunks) if chunks else data.strip('"')


def _host(value: str) -> str:
    return value.strip().rstrip(".").lower()


def _limit(items: list[ResultEntity], soft_limit: int) -> TransformResponse:
    seen: set[tuple[str, str]] = set()
    out: list[ResultEntity] = []
    for item in items:
        key = (item.entity_type, item.value.lower())
        if item.value and key not in seen:
            seen.add(key)
            out.append(item)
    return TransformResponse(entities=out[:soft_limit], truncated=len(out) > soft_limit)


# ------------------------------------------------------------------------------------------ DNS
def _dns_records(rtype: str, out_type: str, label: str) -> Handler:
    async def run(ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int) -> TransformResponse:
        items = []
        for data in await doh(ctx, _host(value), rtype):
            if rtype == "MX":
                prio, _, host = data.partition(" ")
                items.append(_ent(out_type, _host(host or prio), label, mx__priority=prio if host else ""))
            elif rtype == "TXT":
                items.append(_ent(out_type, f"[TXT] {_txt(data)}", label))
            else:
                items.append(_ent(out_type, _host(data) if rtype in ("NS", "CNAME", "PTR") else data, label))
        return _limit(items, n)

    return run


async def _reverse_dns(ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int) -> TransformResponse:
    ptr = ipaddress.ip_address(value.strip()).reverse_pointer
    return _limit([_ent("maltego.DNSName", _host(d), "reverse_dns") for d in await doh(ctx, ptr, "PTR")], n)


async def _cymru(ctx: BuiltinContext, ip: str) -> tuple[str, str, str, str]:
    addr = ipaddress.ip_address(ip.strip())
    if addr.version == 4:
        name = ".".join(reversed(str(addr).split("."))) + ".origin.asn.cymru.com"
    else:
        nibbles = addr.exploded.replace(":", "")
        name = ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"
    records = await doh(ctx, name, "TXT")
    if not records:
        return "", "", "", ""
    parts = [p.strip() for p in records[0].strip('"').split("|")]
    asn = parts[0].split()[0] if parts and parts[0] else ""
    return (
        asn,
        parts[1] if len(parts) > 1 else "",
        parts[2] if len(parts) > 2 else "",
        parts[3] if len(parts) > 3 else "",
    )


async def _ip_to_as(ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int) -> TransformResponse:
    asn, prefix, country, registry = await _cymru(ctx, value)
    if not asn:
        return TransformResponse(messages=[("Inform", f"Sin ASN conocido para {value}.")])
    name = ""
    info = await doh(ctx, f"AS{asn}.asn.cymru.com", "TXT")
    if info:
        name = info[0].strip('"').split("|")[-1].strip()
    return _limit(
        [
            _ent(
                "maltego.AS",
                asn,
                "announced_by",
                as__name=name,
                as__country=country,
                as__registry=registry,
                as__prefix=prefix,
            )
        ],
        n,
    )


async def _ip_to_netblock(
    ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int
) -> TransformResponse:
    asn, prefix, country, _ = await _cymru(ctx, value)
    if not prefix:
        return TransformResponse(messages=[("Inform", f"Sin prefijo anunciado para {value}.")])
    return _limit([_ent("maltego.Netblock", prefix, "in_netblock", netblock__asn=asn, netblock__country=country)], n)


# ------------------------------------------------------------------------------------------ RDAP / WHOIS
def _vcard(entity: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        for item in entity.get("vcardArray", [None, []])[1]:
            if item[0] in ("fn", "org", "email", "tel") and item[0] not in out:
                out[item[0]] = str(item[3] if not isinstance(item[3], list) else " ".join(map(str, item[3])))
    except (IndexError, TypeError):
        pass
    return out


def _rdap_entities(data: dict[str, Any], depth: int = 0) -> list[tuple[list[str], dict[str, str]]]:
    found: list[tuple[list[str], dict[str, str]]] = []
    for ent in data.get("entities", []) or []:
        found.append((list(ent.get("roles", [])), _vcard(ent)))
        if depth < 2:
            found.extend(_rdap_entities(ent, depth + 1))
    return found


async def _rdap_lookup(ctx: BuiltinContext, kind: str, target: str) -> Any:
    """Consulta RDAP con respaldo en el bootstrap de ARIN (rdap.org a veces sufre bloqueos por IP de Cloudflare)."""
    last: Exception | None = None
    for base in RDAP_ENDPOINTS:
        try:
            return await _get_json(ctx, f"{base}/{kind}/{quote(target)}", not_found_ok=True)
        except TransformError as exc:
            last = exc
    raise last or TransformError("No se pudo consultar RDAP.")


async def _domain_whois(
    ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int
) -> TransformResponse:
    data = await _rdap_lookup(ctx, "domain", _host(value))
    if not data:
        return TransformResponse(messages=[("Inform", f"RDAP no tiene registro de {value}.")])
    events = {e.get("eventAction", ""): e.get("eventDate", "") for e in data.get("events", [])}
    items = [_ent("maltego.NSRecord", _host(ns.get("ldhName", "")), "nameserver") for ns in data.get("nameservers", [])]
    for roles, card in _rdap_entities(data):
        name = card.get("org") or card.get("fn", "")
        role = "/".join(roles) or "contact"
        if name and "registrar" in roles:
            items.append(
                _ent(
                    "maltego.Organization",
                    name,
                    "registrar",
                    whois__created=events.get("registration", ""),
                    whois__expires=events.get("expiration", ""),
                    whois__updated=events.get("last changed", ""),
                )
            )
        elif name and not name.lower().startswith(("redacted", "data protected", "privacy")):
            items.append(_ent("maltego.Organization", name, role))
        if card.get("email") and "@" in card["email"]:
            items.append(_ent("maltego.EmailAddress", card["email"].lower(), f"whois_{role}"))
    return _limit(items, n)


async def _ip_whois(ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int) -> TransformResponse:
    data = await _rdap_lookup(ctx, "ip", value.strip())
    if not data:
        return TransformResponse(messages=[("Inform", f"RDAP no tiene registro de {value}.")])
    items = []
    cidrs = data.get("cidr0_cidrs") or []
    if cidrs:
        c = cidrs[0]
        prefix = f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
        items.append(_ent("maltego.Netblock", prefix, "in_netblock", netblock__name=str(data.get("name", ""))))
    elif data.get("startAddress") and data.get("endAddress"):
        items.append(
            _ent(
                "maltego.Netblock",
                f"{data['startAddress']}-{data['endAddress']}",
                "in_netblock",
                netblock__name=str(data.get("name", "")),
            )
        )
    for roles, card in _rdap_entities(data):
        name = card.get("org") or card.get("fn", "")
        if name:
            items.append(_ent("maltego.Organization", name, "/".join(roles) or "contact"))
        if card.get("email") and "@" in card["email"]:
            items.append(_ent("maltego.EmailAddress", card["email"].lower(), "whois_" + ("/".join(roles) or "contact")))
    if data.get("country"):
        items.append(_ent("maltego.Location", str(data["country"]), "located_in"))
    return _limit(items, n)


# ------------------------------------------------------------------------------------------ crt.sh / CertSpotter
async def _certspotter_names(ctx: BuiltinContext, domain: str) -> list[str]:
    data = (
        await _get_json(
            ctx,
            "https://api.certspotter.com/v1/issuances",
            params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
        )
        or []
    )
    out: list[str] = []
    for row in data:
        for name in row.get("dns_names", []) or []:
            host = _host(str(name)).removeprefix("*.")
            if host.endswith("." + domain) and _HOSTNAME_RE.match(host):
                out.append(host)
    return out


async def _crtsh(ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int) -> TransformResponse:
    domain = _host(value)
    names: list[str] = []
    try:
        data = await _get_json(ctx, "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
        for row in data or []:
            for name in str(row.get("name_value", "")).split("\n"):
                host = _host(name).removeprefix("*.")
                if host.endswith("." + domain) and _HOSTNAME_RE.match(host):
                    names.append(host)
    except TransformError:
        names = await _certspotter_names(ctx, domain)
    counts: dict[str, int] = {}
    for h in names:
        counts[h] = counts.get(h, 0) + 1
    ordered = sorted(counts, key=lambda h: (-counts[h], h))
    return _limit([_ent("maltego.DNSName", h, "certificate_san", ct__certificates=str(counts[h])) for h in ordered], n)


async def _certspotter(ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int) -> TransformResponse:
    domain = _host(value)
    names = await _certspotter_names(ctx, domain)
    return _limit([_ent("maltego.DNSName", h, "certificate_san") for h in sorted(set(names))], n)


# ------------------------------------------------------------------------------------------ fuentes públicas sin clave
async def _hackertarget_subdomains(
    ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int
) -> TransformResponse:
    domain = _host(value)
    url = "https://api.hackertarget.com/hostsearch/"
    try:
        resp = await ctx.http.get(url, params={"q": domain})
    except httpx.TimeoutException as exc:
        raise TransformError("Tiempo de espera agotado consultando api.hackertarget.com.") from exc
    except httpx.HTTPError as exc:
        raise TransformError("No se pudo contactar con api.hackertarget.com.") from exc
    if resp.status_code == 429:
        raise TransformError("api.hackertarget.com limita las peticiones (429). Reintenta más tarde.")
    if resp.status_code >= 400:
        raise TransformError(f"api.hackertarget.com respondió HTTP {resp.status_code}.")
    text = resp.text.strip()
    if not text or text.lower().startswith(("error", "api count exceeded", "no records")):
        return TransformResponse(messages=[("Inform", f"HackerTarget no devolvió hosts para {domain}.")])
    items: list[ResultEntity] = []
    for line in text.splitlines():
        host_raw, sep, ip_raw = line.partition(",")
        host = _host(host_raw)
        ip = ip_raw.strip()
        if sep and (host == domain or host.endswith("." + domain)) and _HOSTNAME_RE.match(host):
            if host != domain:
                items.append(_ent("maltego.DNSName", host, "subdomain", hackertarget__ip=ip))
            try:
                addr = ipaddress.ip_address(ip)
                items.append(
                    _ent(
                        "maltego.IPv4Address" if addr.version == 4 else "maltego.IPv6Address",
                        addr.compressed,
                        "resolves_to",
                        hackertarget__host=host,
                    )
                )
            except ValueError:
                pass
    return _limit(items, n)


async def _urlscan_domain(
    ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int
) -> TransformResponse:
    domain = _host(value)
    data = (
        await _get_json(
            ctx,
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": min(n, 50)},
        )
        or {}
    )
    items: list[ResultEntity] = []
    for r in data.get("results", []) or []:
        page = r.get("page", {}) or {}
        host = _host(str(page.get("domain", "")))
        if host and (host == domain or host.endswith("." + domain)) and _HOSTNAME_RE.match(host) and host != domain:
            items.append(
                _ent("maltego.DNSName", host, "observed_in_urlscan", urlscan__server=str(page.get("server", "")))
            )
        ip = str(page.get("ip", "")).strip()
        if ip:
            try:
                addr = ipaddress.ip_address(ip)
                items.append(
                    _ent(
                        "maltego.IPv4Address" if addr.version == 4 else "maltego.IPv6Address",
                        addr.compressed,
                        "resolves_to",
                        urlscan__country=str(page.get("country", "")),
                    )
                )
            except ValueError:
                pass
        url = str(page.get("url", "")).strip()
        if url.startswith(("http://", "https://")):
            items.append(_ent("maltego.URL", url, "observed_url", urlscan__status=str(page.get("status", ""))))
    return _limit(items, n)


async def _internetdb_ip(
    ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int
) -> TransformResponse:
    data = await _get_json(ctx, f"https://internetdb.shodan.io/{quote(value.strip())}", not_found_ok=True)
    if not data:
        return TransformResponse(messages=[("Inform", "InternetDB no tiene datos para esta IP.")])
    items: list[ResultEntity] = []
    for p in data.get("ports", []) or []:
        items.append(_ent("maltego.Port", str(p), "open_port", port__source="shodan-internetdb"))
    for cpe in (data.get("cpes", []) or [])[:15]:
        items.append(_ent("maltego.Service", str(cpe), "runs_service"))
    for host in data.get("hostnames", []) or []:
        h = _host(str(host))
        if _HOSTNAME_RE.match(h):
            items.append(_ent("maltego.DNSName", h, "hostname"))
    for vuln in (data.get("vulns", []) or [])[:20]:
        items.append(_ent("maltego.Phrase", f"[CVE] {vuln}", "vulnerable_to"))
    for tag in (data.get("tags", []) or [])[:10]:
        items.append(_ent("maltego.Phrase", f"[InternetDB] {tag}", "tagged_as"))
    return _limit(items, n)


async def _ripestat_asn(
    ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int
) -> TransformResponse:
    asn = value.strip().upper().removeprefix("AS")
    resource = f"AS{asn}"
    overview, prefixes = await asyncio.gather(
        _get_json(ctx, "https://stat.ripe.net/data/as-overview/data.json", params={"resource": resource}),
        _get_json(ctx, "https://stat.ripe.net/data/announced-prefixes/data.json", params={"resource": resource}),
    )
    items: list[ResultEntity] = []
    holder = str(((overview or {}).get("data") or {}).get("holder", "")).strip()
    if holder:
        items.append(_ent("maltego.Organization", holder, "operated_by", as__number=asn))
    for row in ((prefixes or {}).get("data") or {}).get("prefixes", []) or []:
        prefix = str(row.get("prefix", "")).strip()
        if prefix:
            try:
                net = ipaddress.ip_network(prefix, strict=False).compressed
                items.append(_ent("maltego.Netblock", net, "announces", netblock__asn=asn))
            except ValueError:
                pass
    return _limit(items, n)


async def _gravatar_email(
    ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int
) -> TransformResponse:
    email = value.strip().lower()
    digest = hashlib.md5(email.encode("utf-8")).hexdigest()
    data = await _get_json(ctx, f"https://en.gravatar.com/{digest}.json", not_found_ok=True)
    entries = (data or {}).get("entry", []) if isinstance(data, dict) else []
    if not entries:
        return TransformResponse(messages=[("Inform", "Sin perfil público en Gravatar para este correo.")])
    entry = entries[0] or {}
    items: list[ResultEntity] = []
    uname = str(entry.get("preferredUsername", "")).strip()
    if uname and _ALIAS_RE.match(uname):
        items.append(_ent("maltego.Alias", uname, "has_alias", gravatar__hash=digest))
    disp = str(entry.get("displayName", "")).strip()
    if disp and disp != uname:
        items.append(_ent("maltego.Person", disp, "display_name"))
    loc = str(entry.get("currentLocation", "")).strip()
    if loc:
        items.append(_ent("maltego.Location", loc, "located_in"))
    for acc in entry.get("accounts", []) or []:
        short = str(acc.get("shortname") or acc.get("domain") or "web").strip()
        user = str(acc.get("username") or acc.get("display") or uname or email).strip()
        url = str(acc.get("url", "")).strip()
        items.append(
            ResultEntity(
                "maltego.Affiliation",
                f"{user} ({short})",
                70,
                {"affiliation.network": short, "affiliation.uid": user, "affiliation.profile-url": url},
                {"maltego.link.label": "has_profile"},
            )
        )
    return _limit(items, n)


async def _github_alias(
    ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int
) -> TransformResponse:
    alias = value.strip().lstrip("@")
    if not _ALIAS_RE.match(alias):
        return TransformResponse(messages=[("PartialError", "El alias tiene caracteres no válidos para GitHub.")])
    data = await _get_json(ctx, f"https://api.github.com/users/{quote(alias)}", not_found_ok=True)
    if not data or not isinstance(data, dict):
        return TransformResponse(messages=[("Inform", f"GitHub no tiene usuario '{alias}'.")])
    items: list[ResultEntity] = []
    name = str(data.get("name") or "").strip()
    if name:
        items.append(
            _ent(
                "maltego.Person",
                name,
                "real_name",
                github__login=alias,
                github__name=name,
                github__bio=str(data.get("bio") or ""),
                github__location=str(data.get("location") or ""),
                github__company=str(data.get("company") or "").lstrip("@"),
                github__created_at=str(data.get("created_at") or ""),
                github__updated_at=str(data.get("updated_at") or ""),
                github__public_repos=str(data.get("public_repos") or ""),
                github__followers=str(data.get("followers") or ""),
            )
        )
    company = str(data.get("company") or "").strip().lstrip("@")
    if company:
        items.append(_ent("maltego.Organization", company, "works_at"))
    email = str(data.get("email") or "").strip().lower()
    if email and "@" in email:
        items.append(_ent("maltego.EmailAddress", email, "public_email"))
    blog = str(data.get("blog") or "").strip()
    if blog:
        url = blog if blog.startswith(("http://", "https://")) else f"https://{blog}"
        if urlsplit(url).hostname and "." in (urlsplit(url).hostname or ""):
            items.append(_ent("maltego.URL", url, "website"))
    loc = str(data.get("location") or "").strip()
    if loc:
        items.append(_ent("maltego.Location", loc, "located_in"))
    return _limit(items, n)


async def _otx_hash(ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int) -> TransformResponse:
    h = value.strip().lower()
    data = await _get_json(
        ctx, f"https://otx.alienvault.com/api/v1/indicators/file/{quote(h)}/general", not_found_ok=True
    )
    if not data or not isinstance(data, dict):
        return TransformResponse(messages=[("Inform", "AlienVault OTX no conoce este hash.")])
    pulse_info = data.get("pulse_info", {}) or {}
    pulses = pulse_info.get("pulses", []) or []
    count = int(pulse_info.get("count") or len(pulses))
    if count == 0 and not pulses:
        return TransformResponse(messages=[("Inform", "Sin pulsos de amenazas en AlienVault OTX para este hash.")])
    items: list[ResultEntity] = [
        _ent("maltego.Phrase", f"[OTX] Presente en {count} pulso(s) de amenazas", "threat_intel")
    ]
    for p in pulses[:10]:
        pname = str(p.get("name") or "").strip()
        if pname:
            items.append(_ent("maltego.Phrase", f"[OTX Pulse] {pname}", "observed_in"))
        for mf in (p.get("malware_families") or [])[:5]:
            mname = str(mf.get("display_name") if isinstance(mf, dict) else mf).strip()
            if mname:
                items.append(_ent("maltego.Phrase", f"[Malware] {mname}", "classified_as"))
        for att in (p.get("attack_ids") or [])[:5]:
            aid = str(att.get("id") if isinstance(att, dict) else att).strip()
            if aid:
                items.append(_ent("maltego.Phrase", f"[ATT&CK {aid}]", "uses_technique"))
    return _limit(items, n)


async def _breach_semantic_pivot(
    ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int
) -> TransformResponse:
    """Enrutador semántico de filtraciones: índice local SQLite + k-Anonymity HIBP (hashes) + XposedOrNot (emails)."""
    from pathlib import Path

    kind, norm_val = classify_breach_indicator(etype, value)
    home_raw = (ctx.env.get("MALTEGO_MCP_HOME") or os.environ.get("MALTEGO_MCP_HOME") or "").strip()
    home_dir = Path(home_raw) if home_raw else (Path.home() / ".maltego-mcp")
    items: list[ResultEntity] = []

    # 1. Consulta en base de datos local embebida (~/.maltego-mcp/breaches.sqlite)
    for hit in query_local_breaches(home_dir, kind, norm_val, limit=n):
        items.append(
            _ent(
                "maltego.Phrase",
                f"[Breach] {hit.breach_name}",
                "exposed_in",
                weight=85,
                breach__name=hit.breach_name,
                breach__date=hit.breach_date,
                breach__source=hit.source,
            )
        )
        if kind != "email" and hit.email:
            items.append(
                _ent(
                    "maltego.EmailAddress",
                    hit.email,
                    "leaked_email",
                    weight=80,
                    breach__name=hit.breach_name,
                    breach__date=hit.breach_date,
                )
            )
        if kind != "alias" and hit.alias:
            items.append(_ent("maltego.Alias", hit.alias, "leaked_alias", weight=75, breach__name=hit.breach_name))
        if kind != "phone" and hit.phone:
            items.append(
                _ent("maltego.PhoneNumber", hit.phone, "leaked_phone", weight=75, breach__name=hit.breach_name)
            )
        if kind != "hash" and hit.password_hash:
            items.append(
                _ent("maltego.Hash", hit.password_hash, "leaked_hash", weight=80, breach__name=hit.breach_name)
            )

    # 2. Enrutamiento gratuito sin API key según tipo semántico
    if kind == "hash" and len(norm_val) == 40 and all(c in "0123456789abcdef" for c in norm_val):
        prefix, suffix = norm_val[:5].upper(), norm_val[5:].upper()
        try:
            resp = await ctx.http.get(f"https://api.pwnedpasswords.com/range/{prefix}")
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    h_suf, _, count_str = line.strip().partition(":")
                    if h_suf.upper() == suffix and count_str.isdigit() and int(count_str) > 0:
                        items.append(
                            _ent(
                                "maltego.Phrase",
                                f"[PwnedPassword] Hash SHA-1 expuesto ({count_str} veces)",
                                "exposed_in",
                                weight=90,
                                breach__count=count_str,
                                breach__source="hibp_pwnedpasswords_kanon",
                            )
                        )
                        break
        except httpx.HTTPError:
            pass
    elif kind == "email":
        try:
            xon = await _get_json(
                ctx, f"https://api.xposedornot.com/v1/check-email/{quote(norm_val)}", not_found_ok=True
            )
        except TransformError:
            xon = None
        if isinstance(xon, dict):
            raw_b = xon.get("breaches") or []
            flat_b: list[str] = []
            for entry in raw_b:
                if isinstance(entry, list):
                    flat_b.extend(str(x).strip() for x in entry if str(x).strip())
                elif isinstance(entry, str) and entry.strip():
                    flat_b.append(entry.strip())
            for bname in flat_b[:n]:
                items.append(
                    _ent(
                        "maltego.Phrase",
                        f"[Breach] {bname}",
                        "exposed_in",
                        weight=80,
                        breach__name=bname,
                        breach__source="xposedornot",
                    )
                )
        if ctx.env.get("HIBP_API_KEY", "").strip():
            try:
                hibp_res = await _hibp(ctx, etype, norm_val, props, n)
                items.extend(hibp_res.entities)
            except TransformError:
                pass

    out = _limit(items, n)
    if not out.entities:
        out.messages.append(("Inform", f"Sin filtraciones detectadas para {kind} '{norm_val}'."))
    return out


async def _analyze_subject_behavior_tx(
    ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int
) -> TransformResponse:
    """Extrae rasgos conductuales, afiliaciones e historial de ubicación HUMINT a partir del sujeto y sus atributos."""
    analysis = analyze_subject_behavior(value, props, props.get("notes", ""))
    items = [
        ResultEntity(
            t.maltego_type,
            t.value,
            t.weight,
            t.properties,
            {"maltego.link.label": t.edge_label.strip()},
        )
        for t in analysis.traits
    ]
    out = _limit(items, n)
    out.messages.append(("Inform", analysis.summary_note))
    return out


# ------------------------------------------------------------------------------------------ análisis local
async def _email_to_domain(
    ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int
) -> TransformResponse:
    return _limit([_ent("maltego.Domain", _host(value.rpartition("@")[2]), "email_domain")], n)


async def _email_to_alias(
    ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int
) -> TransformResponse:
    local = value.partition("@")[0].split("+", 1)[0]
    return _limit([_ent("maltego.Alias", local, "possible_alias", weight=40)], n)


async def _url_to_domain(
    ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int
) -> TransformResponse:
    host = urlsplit(value.strip()).hostname or ""
    if not host:
        return TransformResponse(messages=[("PartialError", "La URL no tiene host.")])
    try:
        ipaddress.ip_address(host)
        return _limit([_ent("maltego.IPv4Address" if ":" not in host else "maltego.IPv6Address", host, "hosted_on")], n)
    except ValueError:
        pass
    return _limit(
        [_ent("maltego.Website", host, "hosted_on"), _ent("maltego.Domain", _registrable(host), "hosted_on")], n
    )


def _registrable(host: str) -> str:
    """Aproximación sin lista de sufijos públicos: quita 'www.' y conserva los dos (o tres en ccSLD) últimos niveles."""
    labels = _host(host).removeprefix("www.").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in {"co", "com", "org", "net", "gov", "edu", "ac"}:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


async def _website_to_domain(
    ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int
) -> TransformResponse:
    return _limit([_ent("maltego.Domain", _registrable(value), "part_of")], n)


async def _domain_to_website(
    ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int
) -> TransformResponse:
    d = _host(value)
    items = [
        _ent("maltego.Website", d if d.startswith("www.") else f"www.{d}", "has_website"),
        _ent("maltego.URL", f"https://{d}/", "has_url"),
    ]
    return _limit(items, n)


# ------------------------------------------------------------------------------------------ perfiles por alias
PROFILE_SITES: tuple[tuple[str, str, str], ...] = (
    # (red, URL de comprobación, URL pública del perfil)
    ("GitHub", "https://api.github.com/users/{a}", "https://github.com/{a}"),
    ("GitLab", "https://gitlab.com/api/v4/users?username={a}", "https://gitlab.com/{a}"),
    ("HackerNews", "https://hacker-news.firebaseio.com/v0/user/{a}.json", "https://news.ycombinator.com/user?id={a}"),
    ("Keybase", "https://keybase.io/_/api/1.0/user/lookup.json?usernames={a}", "https://keybase.io/{a}"),
    ("DEV", "https://dev.to/api/users/by_username?url={a}", "https://dev.to/{a}"),
)
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
_ALIAS_RE = re.compile(r"^[A-Za-z0-9._-]{2,39}$")


async def _alias_profiles(
    ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int
) -> TransformResponse:
    alias = value.strip().lstrip("@")
    if not _ALIAS_RE.match(alias):
        return TransformResponse(messages=[("PartialError", "El alias tiene caracteres no válidos para usuarios web.")])
    items: list[ResultEntity] = []
    unknown: list[str] = []

    async def probe(check: str) -> httpx.Response | None:
        try:
            return await ctx.http.get(check.format(a=quote(alias)))
        except httpx.HTTPError:
            return None

    responses = await asyncio.gather(*(probe(check) for _, check, _ in PROFILE_SITES))  # en paralelo
    for (network, _, public), resp in zip(PROFILE_SITES, responses, strict=True):
        if resp is None:
            unknown.append(network)
            continue
        found = False
        if resp.status_code == 200:
            try:
                body = resp.json()
            except ValueError:
                body = None
            if network == "GitLab":
                found = isinstance(body, list) and bool(body)
            elif network == "Keybase":
                them = body.get("them") if isinstance(body, dict) else None
                found = isinstance(them, list) and bool(them) and them[0] is not None
            else:
                found = body is not None
        elif resp.status_code != 404:
            unknown.append(network)
            continue
        if found:
            items.append(
                ResultEntity(
                    "maltego.Affiliation",
                    f"{alias} ({network})",
                    60,
                    {
                        "affiliation.network": network,
                        "affiliation.uid": alias,
                        "affiliation.profile-url": public.format(a=alias),
                    },
                    {"maltego.link.label": "has_profile"},
                )
            )
    out = _limit(items, n)
    if unknown:
        out.messages.append(("Inform", "Sin verificar (límite o bloqueo): " + ", ".join(unknown)))
    return out


# ------------------------------------------------------------------------------------------ proveedores con API key
async def _vt(ctx: BuiltinContext, path: str) -> Any:
    return await _get_json(
        ctx,
        f"https://www.virustotal.com/api/v3/{path}",
        headers={"x-apikey": ctx.key("VIRUSTOTAL_API_KEY")},
        not_found_ok=True,
    )


async def _vt_domain_to_ip(
    ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int
) -> TransformResponse:
    data = await _vt(ctx, f"domains/{quote(_host(value))}/resolutions?limit={min(n, 40)}") or {}
    items = []
    for r in data.get("data", []):
        ip = r.get("attributes", {}).get("ip_address", "")
        if ip:
            items.append(
                _ent(
                    "maltego.IPv6Address" if ":" in ip else "maltego.IPv4Address",
                    ip,
                    "resolved_to",
                    vt__last_resolved=str(r.get("attributes", {}).get("date", "")),
                )
            )
    return _limit(items, n)


async def _vt_ip_to_domain(
    ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int
) -> TransformResponse:
    data = await _vt(ctx, f"ip_addresses/{quote(value.strip())}/resolutions?limit={min(n, 40)}") or {}
    items = [
        _ent("maltego.DNSName", _host(r.get("attributes", {}).get("host_name", "")), "resolved_from")
        for r in data.get("data", [])
    ]
    return _limit(items, n)


async def _vt_subdomains(
    ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int
) -> TransformResponse:
    data = await _vt(ctx, f"domains/{quote(_host(value))}/subdomains?limit={min(n, 40)}") or {}
    return _limit([_ent("maltego.DNSName", _host(r.get("id", "")), "subdomain") for r in data.get("data", [])], n)


async def _vt_hash(ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int) -> TransformResponse:
    data = await _vt(ctx, f"files/{quote(value.strip().lower())}")
    if not data:
        return TransformResponse(messages=[("Inform", "VirusTotal no conoce este hash.")])
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    total = sum(int(v) for v in stats.values() if isinstance(v, int))
    items = [
        _ent(
            "maltego.Phrase",
            f"[VirusTotal] {stats.get('malicious', 0)}/{total} motores lo marcan malicioso",
            "detection",
        )
    ]
    label = attrs.get("popular_threat_classification", {}).get("suggested_threat_label")
    if label:
        items.append(_ent("maltego.Phrase", f"[Malware] {label}", "classified_as"))
    if attrs.get("meaningful_name"):
        items.append(_ent("maltego.File", str(attrs["meaningful_name"]), "file_name"))
    return _limit(items, n)


async def _shodan_ip(ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int) -> TransformResponse:
    data = await _get_json(
        ctx,
        f"https://api.shodan.io/shodan/host/{quote(value.strip())}",
        params={"key": ctx.key("SHODAN_API_KEY")},
        not_found_ok=True,
    )
    if not data:
        return TransformResponse(messages=[("Inform", "Shodan no tiene datos de esta IP.")])
    items = []
    for svc in data.get("data", []):
        port = str(svc.get("port", ""))
        product = " ".join(x for x in (svc.get("product"), svc.get("version")) if x)
        items.append(_ent("maltego.Port", port, "open_port", port__transport=str(svc.get("transport", ""))))
        if product:
            items.append(_ent("maltego.Service", f"{port}/{svc.get('transport', 'tcp')} {product}", "runs_service"))
    for host in data.get("hostnames", []):
        items.append(_ent("maltego.DNSName", _host(host), "hostname"))
    for vuln in list(data.get("vulns", []))[:20]:
        items.append(_ent("maltego.Phrase", f"[CVE] {vuln}", "vulnerable_to"))
    return _limit(items, n)


async def _shodan_subdomains(
    ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int
) -> TransformResponse:
    domain = _host(value)
    data = (
        await _get_json(
            ctx, f"https://api.shodan.io/dns/domain/{quote(domain)}", params={"key": ctx.key("SHODAN_API_KEY")}
        )
        or {}
    )
    return _limit([_ent("maltego.DNSName", f"{s}.{domain}", "subdomain") for s in data.get("subdomains", []) if s], n)


async def _st_subdomains(
    ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int
) -> TransformResponse:
    domain = _host(value)
    data = (
        await _get_json(
            ctx,
            f"https://api.securitytrails.com/v1/domain/{quote(domain)}/subdomains",
            headers={"APIKEY": ctx.key("SECURITYTRAILS_API_KEY")},
        )
        or {}
    )
    return _limit([_ent("maltego.DNSName", f"{s}.{domain}", "subdomain") for s in data.get("subdomains", []) if s], n)


async def _censys_ip(ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int) -> TransformResponse:
    data = await _get_json(
        ctx,
        f"https://search.censys.io/api/v2/hosts/{quote(value.strip())}",
        auth=(ctx.key("CENSYS_API_ID"), ctx.key("CENSYS_API_SECRET")),
        not_found_ok=True,
    )
    result = (data or {}).get("result", {})
    items = []
    for svc in result.get("services", []):
        port = str(svc.get("port", ""))
        items.append(_ent("maltego.Port", port, "open_port", port__transport=str(svc.get("transport_protocol", ""))))
        if svc.get("service_name"):
            items.append(_ent("maltego.Service", f"{port}/{svc['service_name']}", "runs_service"))
    asn = result.get("autonomous_system", {})
    if asn.get("asn"):
        items.append(_ent("maltego.AS", str(asn["asn"]), "announced_by", as__name=str(asn.get("name", ""))))
    return _limit(items, n)


async def _hunter(ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int) -> TransformResponse:
    data = await _get_json(
        ctx,
        "https://api.hunter.io/v2/domain-search",
        params={"domain": _host(value), "limit": min(n, 100), "api_key": ctx.key("HUNTER_API_KEY")},
    )
    items = []
    for e in (data or {}).get("data", {}).get("emails", []):
        conf = int(e.get("confidence") or 50)
        items.append(
            _ent(
                "maltego.EmailAddress",
                str(e.get("value", "")).lower(),
                "email_at",
                weight=conf,
                hunter__position=str(e.get("position") or ""),
            )
        )
        full = " ".join(x for x in (e.get("first_name"), e.get("last_name")) if x)
        if full:
            items.append(_ent("maltego.Person", full, "works_at", weight=conf))
    return _limit(items, n)


async def _hibp(ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int) -> TransformResponse:
    data = await _get_json(
        ctx,
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(value.strip())}",
        params={"truncateResponse": "false"},
        headers={"hibp-api-key": ctx.key("HIBP_API_KEY")},
        not_found_ok=True,
    )
    if not data:
        return TransformResponse(messages=[("Inform", "Sin filtraciones conocidas para este correo.")])
    items = [
        _ent(
            "maltego.Phrase",
            f"[Breach] {b.get('Name', '')}",
            "exposed_in",
            breach__date=str(b.get("BreachDate", "")),
            breach__domain=str(b.get("Domain", "")),
        )
        for b in data
    ]
    return _limit(items, n)


async def _greynoise(ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int) -> TransformResponse:
    data = await _get_json(
        ctx,
        f"https://api.greynoise.io/v3/community/{quote(value.strip())}",
        headers={"key": ctx.key("GREYNOISE_API_KEY")},
        not_found_ok=True,
    )
    if not data:
        return TransformResponse(messages=[("Inform", "GreyNoise no ha visto esta IP.")])
    items = [
        _ent(
            "maltego.Phrase",
            f"[GreyNoise] {data.get('classification', 'unknown')}",
            "classified_as",
            greynoise__noise=str(data.get("noise", "")),
            greynoise__riot=str(data.get("riot", "")),
        )
    ]
    if data.get("name") and data.get("name") != "unknown":
        items.append(_ent("maltego.Organization", str(data["name"]), "operated_by"))
    return _limit(items, n)


async def _tatum(ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int) -> TransformResponse:
    data = await _get_json(
        ctx,
        f"https://api.tatum.io/v3/bitcoin/transaction/address/{quote(value.strip())}",
        params={"pageSize": min(n, 50)},
        headers={"x-api-key": ctx.key("TATUM_API_KEY")},
    )
    items = [
        _ent(
            "maltego.CryptocurrencyTransaction",
            str(tx.get("hash", "")),
            "transacted",
            crypto__block=str(tx.get("blockNumber", "")),
            crypto__time=str(tx.get("time", "")),
        )
        for tx in (data or [])
    ]
    return _limit(items, n)


# ------------------------------------------------------------------------------------------ registro
def _b(
    name: str,
    inputs: tuple[str, ...],
    outputs: tuple[str, ...],
    desc: str,
    cat: str,
    handler: Handler,
    requires: tuple[str, ...] = (),
) -> BuiltinTransform:
    return BuiltinTransform(name, inputs, outputs, desc, cat, handler, requires)


BUILTIN_TRANSFORMS: tuple[BuiltinTransform, ...] = (
    _b(
        "DNSToIP",
        HOST_TYPES,
        ("maltego.IPv4Address",),
        "Registros A (DNS sobre HTTPS).",
        "dns",
        _dns_records("A", "maltego.IPv4Address", "resolves_to"),
    ),
    _b(
        "DNSToIPv6",
        HOST_TYPES,
        ("maltego.IPv6Address",),
        "Registros AAAA (DNS sobre HTTPS).",
        "dns",
        _dns_records("AAAA", "maltego.IPv6Address", "resolves_to"),
    ),
    _b(
        "DomainToMX",
        ("maltego.Domain",),
        ("maltego.MXRecord",),
        "Servidores de correo (MX).",
        "dns",
        _dns_records("MX", "maltego.MXRecord", "mail_server"),
    ),
    _b(
        "DomainToNS",
        ("maltego.Domain",),
        ("maltego.NSRecord",),
        "Servidores de nombres (NS).",
        "dns",
        _dns_records("NS", "maltego.NSRecord", "nameserver"),
    ),
    _b(
        "DomainToTXT",
        ("maltego.Domain",),
        ("maltego.Phrase",),
        "Registros TXT (SPF, verificaciones...).",
        "dns",
        _dns_records("TXT", "maltego.Phrase", "txt_record"),
    ),
    _b(
        "DNSToCNAME",
        HOST_TYPES,
        ("maltego.DNSName",),
        "Alias CNAME.",
        "dns",
        _dns_records("CNAME", "maltego.DNSName", "cname"),
    ),
    _b("IPToReverseDNS", IP_TYPES, ("maltego.DNSName",), "DNS inverso (PTR).", "dns", _reverse_dns),
    _b("IPToAS", IP_TYPES, ("maltego.AS",), "Sistema autónomo que anuncia la IP (Team Cymru).", "red", _ip_to_as),
    _b(
        "IPToNetblock",
        IP_TYPES,
        ("maltego.Netblock",),
        "Prefijo anunciado que contiene la IP (Team Cymru).",
        "red",
        _ip_to_netblock,
    ),
    _b(
        "DomainToWhois",
        ("maltego.Domain",),
        ("maltego.Organization", "maltego.NSRecord", "maltego.EmailAddress"),
        "WHOIS moderno (RDAP): registrador, fechas, contactos y nameservers.",
        "whois",
        _domain_whois,
    ),
    _b(
        "IPToWhois",
        IP_TYPES,
        ("maltego.Netblock", "maltego.Organization", "maltego.Location"),
        "WHOIS de la IP (RDAP): bloque, organización y país.",
        "whois",
        _ip_whois,
    ),
    _b(
        "DomainToSubdomains",
        ("maltego.Domain",),
        ("maltego.DNSName",),
        "Subdominios en certificados públicos (crt.sh con respaldo CertSpotter).",
        "certificados",
        _crtsh,
    ),
    _b(
        "CertSpotterSubdomains",
        ("maltego.Domain",),
        ("maltego.DNSName",),
        "Subdominios en logs de Certificate Transparency (CertSpotter).",
        "certificados",
        _certspotter,
    ),
    _b(
        "HackerTargetSubdomains",
        ("maltego.Domain",),
        ("maltego.DNSName", "maltego.IPv4Address"),
        "Subdominios e IPs asociadas (HackerTarget).",
        "dns",
        _hackertarget_subdomains,
    ),
    _b(
        "URLScanDomainSearch",
        ("maltego.Domain",),
        ("maltego.DNSName", "maltego.IPv4Address", "maltego.URL"),
        "Escaneos web públicos históricos del dominio (urlscan.io).",
        "web",
        _urlscan_domain,
    ),
    _b(
        "InternetDBIPToServices",
        IP_TYPES,
        ("maltego.Port", "maltego.Service", "maltego.DNSName", "maltego.Phrase"),
        "Puertos abiertos, CPEs, hostnames y CVEs sin clave (Shodan InternetDB).",
        "red",
        _internetdb_ip,
    ),
    _b(
        "RIPEStatASNToNetblocks",
        ("maltego.AS",),
        ("maltego.Organization", "maltego.Netblock"),
        "Titular y prefijos BGP anunciados por un sistema autónomo (RIPE Stat).",
        "red",
        _ripestat_asn,
    ),
    _b(
        "EmailToDomain",
        ("maltego.EmailAddress",),
        ("maltego.Domain",),
        "Dominio del correo.",
        "analisis",
        _email_to_domain,
    ),
    _b(
        "EmailToAlias",
        ("maltego.EmailAddress",),
        ("maltego.Alias",),
        "Parte local del correo como alias.",
        "analisis",
        _email_to_alias,
    ),
    _b(
        "URLToDomain",
        ("maltego.URL", "maltego.Document"),
        ("maltego.Website", "maltego.Domain"),
        "Web y dominio que alojan la URL.",
        "analisis",
        _url_to_domain,
    ),
    _b(
        "WebsiteToDomain",
        ("maltego.Website", "maltego.DNSName"),
        ("maltego.Domain",),
        "Dominio registrable.",
        "analisis",
        _website_to_domain,
    ),
    _b(
        "DomainToWebsite",
        ("maltego.Domain",),
        ("maltego.Website", "maltego.URL"),
        "Web y URL raíz del dominio.",
        "analisis",
        _domain_to_website,
    ),
    _b(
        "AliasToProfiles",
        ("maltego.Alias", "humint.Alias"),
        ("maltego.Affiliation",),
        "Comprueba si el alias existe en GitHub, GitLab, Hacker News, Keybase y DEV.",
        "social",
        _alias_profiles,
    ),
    _b(
        "GravatarEmailToProfile",
        ("maltego.EmailAddress",),
        ("maltego.Alias", "maltego.Person", "maltego.Location", "maltego.Affiliation"),
        "Perfil público asociado al correo en Gravatar (alias, nombre, ubicación y cuentas).",
        "social",
        _gravatar_email,
    ),
    _b(
        "GitHubAliasToDetails",
        ("maltego.Alias", "humint.Alias"),
        ("maltego.Person", "maltego.Organization", "maltego.EmailAddress", "maltego.URL", "maltego.Location"),
        "Detalle del perfil público en GitHub (nombre, organización, blog, ubicación y correo público).",
        "social",
        _github_alias,
    ),
    _b(
        "BreachSemanticPivot",
        (
            "maltego.EmailAddress",
            "maltego.Alias",
            "humint.Alias",
            "maltego.PhoneNumber",
            "maltego.Domain",
            "maltego.Hash",
        ),
        ("maltego.Phrase", "maltego.EmailAddress", "maltego.Alias", "maltego.Hash"),
        "Enrutador semántico de filtraciones: índice SQLite local + HIBP Pwned Passwords (k-Anonymity) + XposedOrNot.",
        "filtraciones",
        _breach_semantic_pivot,
    ),
    _b(
        "AnalyzeSubjectBehavior",
        ("maltego.Person", "maltego.Alias", "humint.Alias", "maltego.EmailAddress", "maltego.Affiliation"),
        ("humint.PsychologicalTrait", "humint.LocationHistory", "humint.Organization"),
        "Análisis conductual y estilométrico HUMINT: infiere rasgos [Hipótesis], ventana horaria y filiaciones.",
        "humint",
        _analyze_subject_behavior_tx,
    ),
    _b(
        "OTXHashToThreatPulses",
        ("maltego.Hash",),
        ("maltego.Phrase",),
        "Pulsos de inteligencia de amenazas para un hash MD5/SHA1/SHA256 (AlienVault OTX).",
        "amenazas",
        _otx_hash,
    ),
    _b(
        "VTDomainToIP",
        ("maltego.Domain", "maltego.DNSName"),
        ("maltego.IPv4Address",),
        "Resoluciones históricas (VirusTotal).",
        "proveedor:virustotal",
        _vt_domain_to_ip,
        ("VIRUSTOTAL_API_KEY",),
    ),
    _b(
        "VTIPToDomain",
        IP_TYPES,
        ("maltego.DNSName",),
        "Dominios que resolvieron a la IP (VirusTotal).",
        "proveedor:virustotal",
        _vt_ip_to_domain,
        ("VIRUSTOTAL_API_KEY",),
    ),
    _b(
        "VTDomainToSubdomains",
        ("maltego.Domain",),
        ("maltego.DNSName",),
        "Subdominios (VirusTotal).",
        "proveedor:virustotal",
        _vt_subdomains,
        ("VIRUSTOTAL_API_KEY",),
    ),
    _b(
        "VTHashToDetection",
        ("maltego.Hash",),
        ("maltego.Phrase", "maltego.File"),
        "Detecciones del fichero (VirusTotal).",
        "proveedor:virustotal",
        _vt_hash,
        ("VIRUSTOTAL_API_KEY",),
    ),
    _b(
        "ShodanIPToServices",
        IP_TYPES,
        ("maltego.Port", "maltego.Service", "maltego.DNSName", "maltego.Phrase"),
        "Puertos, servicios, hostnames y CVE (Shodan).",
        "proveedor:shodan",
        _shodan_ip,
        ("SHODAN_API_KEY",),
    ),
    _b(
        "ShodanDomainToSubdomains",
        ("maltego.Domain",),
        ("maltego.DNSName",),
        "Subdominios (Shodan).",
        "proveedor:shodan",
        _shodan_subdomains,
        ("SHODAN_API_KEY",),
    ),
    _b(
        "SecurityTrailsSubdomains",
        ("maltego.Domain",),
        ("maltego.DNSName",),
        "Subdominios (SecurityTrails).",
        "proveedor:securitytrails",
        _st_subdomains,
        ("SECURITYTRAILS_API_KEY",),
    ),
    _b(
        "CensysIPToServices",
        IP_TYPES,
        ("maltego.Port", "maltego.Service", "maltego.AS"),
        "Servicios (Censys).",
        "proveedor:censys",
        _censys_ip,
        ("CENSYS_API_ID", "CENSYS_API_SECRET"),
    ),
    _b(
        "HunterDomainToEmails",
        ("maltego.Domain",),
        ("maltego.EmailAddress", "maltego.Person"),
        "Correos corporativos (Hunter.io).",
        "proveedor:hunter",
        _hunter,
        ("HUNTER_API_KEY",),
    ),
    _b(
        "HIBPEmailToBreaches",
        ("maltego.EmailAddress",),
        ("maltego.Phrase",),
        "Filtraciones (Have I Been Pwned).",
        "proveedor:hibp",
        _hibp,
        ("HIBP_API_KEY",),
    ),
    _b(
        "GreyNoiseIPContext",
        IP_TYPES,
        ("maltego.Phrase", "maltego.Organization"),
        "Clasificación de la IP (GreyNoise).",
        "proveedor:greynoise",
        _greynoise,
        ("GREYNOISE_API_KEY",),
    ),
    _b(
        "TatumBTCAddressToTx",
        ("maltego.CryptocurrencyAddress",),
        ("maltego.CryptocurrencyTransaction",),
        "Transacciones de una dirección Bitcoin (Tatum).",
        "proveedor:tatum",
        _tatum,
        ("TATUM_API_KEY",),
    ),
)

PROVIDER_KEYS: dict[str, tuple[str, ...]] = {
    "virustotal": ("VIRUSTOTAL_API_KEY",),
    "shodan": ("SHODAN_API_KEY",),
    "securitytrails": ("SECURITYTRAILS_API_KEY",),
    "censys": ("CENSYS_API_ID", "CENSYS_API_SECRET"),
    "hunter": ("HUNTER_API_KEY",),
    "hibp": ("HIBP_API_KEY",),
    "greynoise": ("GREYNOISE_API_KEY",),
    "tatum": ("TATUM_API_KEY",),
}
