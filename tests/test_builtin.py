"""Transforms integrados con respuestas HTTP simuladas (formato real de cada servicio)."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from maltego_mcp.errors import TransformError
from maltego_mcp.transforms.builtin import BUILTIN_TRANSFORMS, BuiltinContext, new_http_client

DNS = {
    ("example.com", "A"): ["93.184.216.34"],
    ("example.com", "AAAA"): ["2606:2800:220:1:248:1893:25c8:1946"],
    ("example.com", "MX"): ["10 mail.example.com."],
    ("example.com", "NS"): ["a.iana-servers.net.", "b.iana-servers.net."],
    ("example.com", "TXT"): ['"v=spf1 -all"'],
    ("www.example.com", "CNAME"): ["example.com."],
    ("www.example.com", "A"): ["93.184.216.34"],
    ("dev.example.com", "A"): ["93.184.216.35"],
    ("34.216.184.93.in-addr.arpa", "PTR"): ["host.example.net."],
    ("34.216.184.93.origin.asn.cymru.com", "TXT"): ['"15133 | 93.184.216.0/24 | US | arin | 2008-06-02"'],
    ("35.216.184.93.origin.asn.cymru.com", "TXT"): ['"15133 | 93.184.216.0/24 | US | arin | 2008-06-02"'],
    ("AS15133.asn.cymru.com", "TXT"): ['"15133 | US | arin | 2007-03-19 | EDGECAST, US"'],
    ("mail.example.com", "A"): ["93.184.216.40"],
    ("gmail.com", "MX"): ["5 gmail-smtp-in.l.google.com."],
}
TYPES = {"A": 1, "NS": 2, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}

RDAP_DOMAIN = {
    "ldhName": "EXAMPLE.COM",
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
    ],
    "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}],
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "RESERVED-IANA"]]],
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"], ["email", {}, "text", "Abuse@IANA.org"]]],
                }
            ],
        },
        {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "REDACTED FOR PRIVACY"]]]},
    ],
}
RDAP_IP = {
    "name": "EDGECAST-NETBLK",
    "country": "US",
    "cidr0_cidrs": [{"v4prefix": "93.184.216.0", "length": 24}],
    "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Edgecast Inc."]]]}],
}
CRT = [
    {"name_value": "www.example.com\n*.example.com"},
    {"name_value": "dev.example.com"},
    {"name_value": "subjectname@example.com"},
    {"name_value": "otro.dominio.org"},
    {"name_value": "www.example.com"},
]


class Router:
    """Simula los servicios externos; registra las peticiones para comprobar cabeceras y claves."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.fail: dict[str, int | str] = {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        host, path, params = request.url.host, request.url.path, dict(request.url.params)
        for key, mode in self.fail.items():
            if key in host:
                if mode == "timeout":
                    raise httpx.ReadTimeout("timeout", request=request)
                return httpx.Response(int(mode), json={})
        if host in ("dns.google", "cloudflare-dns.com"):
            name, rtype = params["name"].rstrip("."), params["type"]
            answers = [{"name": name, "type": TYPES[rtype], "data": d} for d in DNS.get((name, rtype), [])]
            return httpx.Response(200, json={"Status": 0 if answers else 3, "Answer": answers})
        if host == "rdap.org":
            if path.startswith("/domain/example.com"):
                return httpx.Response(200, json=RDAP_DOMAIN)
            if path.startswith("/ip/93.184.216.34"):
                return httpx.Response(200, json=RDAP_IP)
            return httpx.Response(404)
        if host == "crt.sh":
            return httpx.Response(200, json=CRT)
        profiles = {
            "api.github.com": (path == "/users/jdoe", {"login": "jdoe"}),
            "gitlab.com": (True, [{"id": 1}] if params.get("username") == "jdoe" else []),
            "hacker-news.firebaseio.com": (True, {"id": "jdoe"} if "jdoe" in path else None),
            "keybase.io": (True, {"them": [None]}),
            "dev.to": (False, None),
        }
        if host in profiles:
            exists, body = profiles[host]
            return httpx.Response(200 if exists else 404, json=body)
        return provider_response(host, path, params, request)


def provider_response(host: str, path: str, params: dict[str, str], request: httpx.Request) -> httpx.Response:
    if host == "www.virustotal.com":
        if "/resolutions" in path and "/domains/" in path:
            return httpx.Response(200, json={"data": [{"attributes": {"ip_address": "1.2.3.4", "date": 1700000000}}]})
        if "/resolutions" in path:
            return httpx.Response(200, json={"data": [{"attributes": {"host_name": "Evil.Example.com"}}]})
        if "/subdomains" in path:
            return httpx.Response(200, json={"data": [{"id": "api.example.com"}]})
        if "/files/" in path:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {"malicious": 40, "undetected": 30},
                            "popular_threat_classification": {"suggested_threat_label": "trojan.emotet"},
                            "meaningful_name": "invoice.exe",
                        }
                    }
                },
            )
    if host == "api.shodan.io":
        if path.startswith("/shodan/host/"):
            return httpx.Response(
                200,
                json={
                    "data": [{"port": 443, "transport": "tcp", "product": "nginx", "version": "1.25"}],
                    "hostnames": ["web.example.com"],
                    "vulns": ["CVE-2023-44487"],
                },
            )
        return httpx.Response(200, json={"subdomains": ["mail", "vpn"]})
    if host == "api.securitytrails.com":
        return httpx.Response(200, json={"subdomains": ["intranet"]})
    if host == "search.censys.io":
        return httpx.Response(
            200,
            json={
                "result": {
                    "services": [{"port": 22, "service_name": "SSH", "transport_protocol": "TCP"}],
                    "autonomous_system": {"asn": 15133, "name": "EDGECAST"},
                }
            },
        )
    if host == "api.hunter.io":
        return httpx.Response(
            200,
            json={
                "data": {
                    "emails": [
                        {
                            "value": "Ana@Example.com",
                            "confidence": 90,
                            "first_name": "Ana",
                            "last_name": "Pérez",
                            "position": "CTO",
                        }
                    ]
                }
            },
        )
    if host == "haveibeenpwned.com":
        if "nobody" in path:
            return httpx.Response(404)
        return httpx.Response(200, json=[{"Name": "Adobe", "BreachDate": "2013-10-04", "Domain": "adobe.com"}])
    if host == "api.greynoise.io":
        return httpx.Response(200, json={"classification": "benign", "name": "Google", "noise": False, "riot": True})
    if host == "api.tatum.io":
        return httpx.Response(200, json=[{"hash": "ab" * 32, "blockNumber": 1, "time": 1600000000}])
    return httpx.Response(599, json={"error": f"host no simulado {host}{path}"})


KEYS = {
    "VIRUSTOTAL_API_KEY": "vt",
    "SHODAN_API_KEY": "sh",
    "SECURITYTRAILS_API_KEY": "st",
    "CENSYS_API_ID": "id",
    "CENSYS_API_SECRET": "sec",
    "HUNTER_API_KEY": "hu",
    "HIBP_API_KEY": "hi",
    "GREYNOISE_API_KEY": "gn",
    "TATUM_API_KEY": "ta",
}


@pytest.fixture
def router() -> Router:
    return Router()


@pytest.fixture
def ctx(router: Router) -> BuiltinContext:
    return BuiltinContext(new_http_client(transport=httpx.MockTransport(router)), dict(KEYS))


def T(name: str):  # type: ignore[no-untyped-def]
    return next(b for b in BUILTIN_TRANSFORMS if b.name == name)


async def run(ctx: BuiltinContext, name: str, value: str, n: int = 20) -> list[tuple[str, str, str]]:
    b = T(name)
    r = await b.handler(ctx, b.input_types[0], value, {}, n)
    return [(e.entity_type, e.value, e.link_label) for e in r.entities]


@pytest.mark.parametrize(
    ("name", "value", "expected"),
    [
        ("DNSToIP", "Example.com.", [("maltego.IPv4Address", "93.184.216.34", "resolves_to")]),
        ("DNSToIPv6", "example.com", [("maltego.IPv6Address", "2606:2800:220:1:248:1893:25c8:1946", "resolves_to")]),
        ("DomainToMX", "example.com", [("maltego.MXRecord", "mail.example.com", "mail_server")]),
        (
            "DomainToNS",
            "example.com",
            [
                ("maltego.NSRecord", "a.iana-servers.net", "nameserver"),
                ("maltego.NSRecord", "b.iana-servers.net", "nameserver"),
            ],
        ),
        ("DomainToTXT", "example.com", [("maltego.Phrase", "[TXT] v=spf1 -all", "txt_record")]),
        ("DNSToCNAME", "www.example.com", [("maltego.DNSName", "example.com", "cname")]),
        ("IPToReverseDNS", "93.184.216.34", [("maltego.DNSName", "host.example.net", "reverse_dns")]),
        ("IPToAS", "93.184.216.34", [("maltego.AS", "15133", "announced_by")]),
        ("IPToNetblock", "93.184.216.34", [("maltego.Netblock", "93.184.216.0/24", "in_netblock")]),
        (
            "DomainToSubdomains",
            "example.com",
            [
                ("maltego.DNSName", "www.example.com", "certificate_san"),
                ("maltego.DNSName", "dev.example.com", "certificate_san"),
            ],
        ),
        ("EmailToDomain", "ana@Example.org", [("maltego.Domain", "example.org", "email_domain")]),
        ("EmailToAlias", "ana+news@example.org", [("maltego.Alias", "ana", "possible_alias")]),
        (
            "URLToDomain",
            "https://www.bbc.co.uk/x",
            [("maltego.Website", "www.bbc.co.uk", "hosted_on"), ("maltego.Domain", "bbc.co.uk", "hosted_on")],
        ),
        ("URLToDomain", "http://10.0.0.1/a", [("maltego.IPv4Address", "10.0.0.1", "hosted_on")]),
        ("WebsiteToDomain", "www.example.com", [("maltego.Domain", "example.com", "part_of")]),
        (
            "DomainToWebsite",
            "example.com",
            [("maltego.Website", "www.example.com", "has_website"), ("maltego.URL", "https://example.com/", "has_url")],
        ),
        ("VTDomainToIP", "example.com", [("maltego.IPv4Address", "1.2.3.4", "resolved_to")]),
        ("VTIPToDomain", "1.2.3.4", [("maltego.DNSName", "evil.example.com", "resolved_from")]),
        ("VTDomainToSubdomains", "example.com", [("maltego.DNSName", "api.example.com", "subdomain")]),
        (
            "ShodanDomainToSubdomains",
            "example.com",
            [("maltego.DNSName", "mail.example.com", "subdomain"), ("maltego.DNSName", "vpn.example.com", "subdomain")],
        ),
        ("SecurityTrailsSubdomains", "example.com", [("maltego.DNSName", "intranet.example.com", "subdomain")]),
        ("HIBPEmailToBreaches", "ana@example.com", [("maltego.Phrase", "[Breach] Adobe", "exposed_in")]),
        ("TatumBTCAddressToTx", "bc1qxyz", [("maltego.CryptocurrencyTransaction", "ab" * 32, "transacted")]),
    ],
)
async def test_transforms(ctx: BuiltinContext, name: str, value: str, expected: list[tuple[str, str, str]]) -> None:
    assert await run(ctx, name, value) == expected


async def test_whois_dominio_e_ip(ctx: BuiltinContext) -> None:
    dom = await run(ctx, "DomainToWhois", "example.com")
    assert ("maltego.NSRecord", "a.iana-servers.net", "nameserver") in dom
    assert ("maltego.Organization", "RESERVED-IANA", "registrar") in dom
    assert ("maltego.EmailAddress", "abuse@iana.org", "whois_abuse") in dom
    assert not any("REDACTED" in v for _, v, _ in dom)
    reg = await T("DomainToWhois").handler(ctx, "maltego.Domain", "example.com", {}, 20)
    org = next(e for e in reg.entities if e.link_label == "registrar")
    assert org.properties["whois.created"] == "1995-08-14T04:00:00Z"
    ip = await run(ctx, "IPToWhois", "93.184.216.34")
    assert ip[:2] == [
        ("maltego.Netblock", "93.184.216.0/24", "in_netblock"),
        ("maltego.Organization", "Edgecast Inc.", "registrant"),
    ]
    assert ("maltego.Location", "US", "located_in") in ip
    missing = await T("DomainToWhois").handler(ctx, "maltego.Domain", "nada.org", {}, 5)
    assert missing.entities == [] and "RDAP no tiene" in missing.messages[0][1]


async def test_perfiles_por_alias(ctx: BuiltinContext) -> None:
    r = await T("AliasToProfiles").handler(ctx, "maltego.Alias", "@jdoe", {}, 10)
    nets = {e.properties["affiliation.network"]: e.properties["affiliation.profile-url"] for e in r.entities}
    assert nets == {
        "GitHub": "https://github.com/jdoe",
        "GitLab": "https://gitlab.com/jdoe",
        "HackerNews": "https://news.ycombinator.com/user?id=jdoe",
    }
    bad = await T("AliasToProfiles").handler(ctx, "maltego.Alias", "a b", {}, 10)
    assert bad.entities == [] and "no válidos" in bad.messages[0][1]


async def test_proveedores_detalle_y_cabeceras(ctx: BuiltinContext, router: Router) -> None:
    vt = await T("VTHashToDetection").handler(ctx, "maltego.Hash", "AB" * 16, {}, 10)
    assert [e.value for e in vt.entities] == [
        "[VirusTotal] 40/70 motores lo marcan malicioso",
        "[Malware] trojan.emotet",
        "invoice.exe",
    ]
    sh = await run(ctx, "ShodanIPToServices", "1.2.3.4")
    assert ("maltego.Port", "443", "open_port") in sh and (
        "maltego.Phrase",
        "[CVE] CVE-2023-44487",
        "vulnerable_to",
    ) in sh
    assert ("maltego.Service", "443/tcp nginx 1.25", "runs_service") in sh
    ce = await run(ctx, "CensysIPToServices", "1.2.3.4")
    assert ("maltego.AS", "15133", "announced_by") in ce
    hu = await run(ctx, "HunterDomainToEmails", "example.com")
    assert hu == [("maltego.EmailAddress", "ana@example.com", "email_at"), ("maltego.Person", "Ana Pérez", "works_at")]
    gn = await run(ctx, "GreyNoiseIPContext", "8.8.8.8")
    assert gn == [
        ("maltego.Phrase", "[GreyNoise] benign", "classified_as"),
        ("maltego.Organization", "Google", "operated_by"),
    ]
    await run(ctx, "SecurityTrailsSubdomains", "example.com")
    await run(ctx, "HIBPEmailToBreaches", "ana@example.com")
    headers = {r.url.host: r.headers for r in router.requests}
    assert headers["www.virustotal.com"]["x-apikey"] == "vt"
    assert headers["api.securitytrails.com"]["apikey"] == "st"
    assert headers["haveibeenpwned.com"]["hibp-api-key"] == "hi"
    assert headers["api.greynoise.io"]["key"] == "gn"
    assert headers["search.censys.io"]["authorization"].startswith("Basic ")
    assert all("maltego-mcp/" in r.headers["user-agent"] for r in router.requests)


async def test_hibp_sin_filtraciones(ctx: BuiltinContext) -> None:
    r = await T("HIBPEmailToBreaches").handler(ctx, "maltego.EmailAddress", "nobody@example.com", {}, 5)
    assert r.entities == [] and "Sin filtraciones" in r.messages[0][1]


@pytest.mark.parametrize(
    ("fail", "fragment"),
    [(401, "API key"), (403, "API key"), (429, "429"), (500, "HTTP 500"), ("timeout", "Tiempo de espera")],
)
async def test_errores_de_proveedor(ctx: BuiltinContext, router: Router, fail: Any, fragment: str) -> None:
    router.fail["virustotal"] = fail
    with pytest.raises(TransformError, match=fragment):
        await run(ctx, "VTDomainToIP", "example.com")


async def test_falta_api_key(router: Router) -> None:
    ctx = BuiltinContext(httpx.AsyncClient(transport=httpx.MockTransport(router)), {})
    with pytest.raises(TransformError, match="SHODAN_API_KEY"):
        await run(ctx, "ShodanIPToServices", "1.2.3.4")
    assert T("ShodanIPToServices").available({}) is False
    assert T("ShodanIPToServices").available({"SHODAN_API_KEY": "x"}) is True
    assert T("CensysIPToServices").available({"CENSYS_API_ID": "x"}) is False


async def test_doh_usa_respaldo_si_falla_google(ctx: BuiltinContext, router: Router) -> None:
    router.fail["dns.google"] = 503
    assert await run(ctx, "DNSToIP", "example.com") == [("maltego.IPv4Address", "93.184.216.34", "resolves_to")]
    assert any(r.url.host == "cloudflare-dns.com" for r in router.requests)


async def test_soft_limit_y_deduplicado(ctx: BuiltinContext) -> None:
    r = await T("DomainToSubdomains").handler(ctx, "maltego.Domain", "example.com", {}, 1)
    assert len(r.entities) == 1 and r.truncated


def test_catalogo_integrado_coherente() -> None:
    names = [b.name for b in BUILTIN_TRANSFORMS]
    assert len(names) == len(set(names))
    for b in BUILTIN_TRANSFORMS:
        assert b.input_types and b.output_types and b.description
        assert b.category.startswith("proveedor") == bool(b.requires), b.name


def test_respuesta_serializable() -> None:
    assert json.dumps({"ok": True})


async def test_txt_con_varias_cadenas(ctx: BuiltinContext) -> None:
    DNS[("split.example", "TXT")] = ['"v=DKIM1; k=rsa; p=AAA" "BBB"']
    assert await run(ctx, "DomainToTXT", "split.example") == [
        ("maltego.Phrase", "[TXT] v=DKIM1; k=rsa; p=AAABBB", "txt_record")
    ]
