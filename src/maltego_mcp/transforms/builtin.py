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
import ipaddress
import os
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from maltego_mcp import __version__
from maltego_mcp.errors import TransformError
from maltego_mcp.transforms.protocol import ResultEntity, TransformResponse

USER_AGENT = f"maltego-mcp/{__version__} (+https://github.com/Data-Unix/MCP-MALTEGO)"
DOH_ENDPOINTS = ("https://dns.google/resolve", "https://cloudflare-dns.com/dns-query")
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


async def _domain_whois(
    ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int
) -> TransformResponse:
    data = await _get_json(ctx, f"https://rdap.org/domain/{quote(_host(value))}", not_found_ok=True)
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
    data = await _get_json(ctx, f"https://rdap.org/ip/{quote(value.strip())}", not_found_ok=True)
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


# ------------------------------------------------------------------------------------------ crt.sh
async def _crtsh(ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], n: int) -> TransformResponse:
    domain = _host(value)
    data = await _get_json(ctx, "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
    names: list[str] = []
    for row in data or []:
        for name in str(row.get("name_value", "")).split("\n"):
            host = _host(name).removeprefix("*.")
            if host.endswith("." + domain) and _HOSTNAME_RE.match(host):
                names.append(host)
    counts: dict[str, int] = {}
    for h in names:
        counts[h] = counts.get(h, 0) + 1
    ordered = sorted(counts, key=lambda h: (-counts[h], h))
    return _limit([_ent("maltego.DNSName", h, "certificate_san", ct__certificates=str(counts[h])) for h in ordered], n)


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
        "Subdominios en certificados públicos (crt.sh).",
        "certificados",
        _crtsh,
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
        ("maltego.Alias",),
        ("maltego.Affiliation",),
        "Comprueba si el alias existe en GitHub, GitLab, Hacker News, Keybase y DEV.",
        "social",
        _alias_profiles,
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
