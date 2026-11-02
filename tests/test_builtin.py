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
        if host in ("rdap.org", "rdap-bootstrap.arin.net"):
            if "/domain/example.com" in path:
                return httpx.Response(200, json=RDAP_DOMAIN)
            if "/ip/93.184.216.34" in path:
                return httpx.Response(200, json=RDAP_IP)
            return httpx.Response(404)
        if host == "crt.sh":
            return httpx.Response(200, json=CRT)
        if host == "api.certspotter.com":
            return httpx.Response(
                200,
                json=[
                    {"dns_names": ["www.example.com", "*.example.com", "ct.example.com"]},
                    {"dns_names": ["otro.org"]},
                ],
            )
        if host == "api.hackertarget.com":
            if params.get("q") == "quota.example":
                return httpx.Response(200, text="API count exceeded - Increase Quota with Membership")
            return httpx.Response(200, text="www.example.com,93.184.216.34\ndev.example.com,93.184.216.35\n")
        if host == "urlscan.io":
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "page": {
                                "domain": "www.example.com",
                                "ip": "93.184.216.34",
                                "url": "https://www.example.com/",
                            }
                        }
                    ]
                },
            )
        if host == "internetdb.shodan.io":
            if path.endswith("/203.0.113.9"):
                return httpx.Response(404)
            return httpx.Response(
                200,
                json={
                    "ip": "93.184.216.34",
                    "ports": [80, 443],
                    "cpes": ["cpe:/a:igor_sysoev:nginx:1.25"],
                    "hostnames": ["edge.example.com"],
                    "tags": ["cdn"],
                    "vulns": ["CVE-2023-44487"],
                },
            )
        if host == "stat.ripe.net":
            if "as-overview" in path:
                return httpx.Response(
                    200, json={"data": {"holder": "EDGECAST - MCI Communications Services", "announced": True}}
                )
            if "announced-prefixes" in path:
                return httpx.Response(200, json={"data": {"prefixes": [{"prefix": "93.184.216.0/24"}]}})
        if host == "en.gravatar.com":
            if path.startswith("/0000"):
                return httpx.Response(404)
            return httpx.Response(
                200,
                json={
                    "entry": [
                        {
                            "preferredUsername": "jdoe",
                            "displayName": "John Doe",
                            "currentLocation": "Madrid",
                            "profileUrl": "https://gravatar.com/jdoe",
                            "accounts": [{"shortname": "github", "url": "https://github.com/jdoe"}],
                        }
                    ]
                },
            )
        if host == "otx.alienvault.com":
            return httpx.Response(
                200,
                json={
                    "pulse_info": {
                        "count": 2,
                        "pulses": [
                            {
                                "name": "Emotet Wave",
                                "created": "2026-01-10T00:00:00",
                                "malware_families": ["Emotet"],
                                "attack_ids": [{"id": "T1566"}],
                            }
                        ],
                    },
                },
            )
        if host == "api.pwnedpasswords.com":
            if path.endswith("/5BAA6"):
                return httpx.Response(200, text="1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\nABCDEF:1\n")
            return httpx.Response(200, text="00000000000000000000000000000000000:1\n")
        if host == "api.xposedornot.com":
            if "nobody@" in path:
                return httpx.Response(404)
            return httpx.Response(200, json={"breaches": [["Adobe", "Dropbox"]]})
        if host == "cavalier.hudsonrock.com":
            q_val = params.get("email") or params.get("domain") or params.get("username") or ""
            if "nobody" in q_val or q_val == "ana@example.com":
                return httpx.Response(200, json={"stealers": []})
            return httpx.Response(
                200,
                json={
                    "stealers": [
                        {
                            "stealer_family": "RedLine",
                            "date_compromised": "2026-01-15T10:00:00Z",
                            "computer_name": "WORKSTATION-01",
                            "operating_system": "Windows 11 Pro",
                            "ip": "198.51.100.42",
                        }
                    ]
                },
            )
        if host == "raw.githubusercontent.com":
            return httpx.Response(
                200,
                text=(
                    "| Name | Status | Type | Description |\n"
                    "| --- | --- | --- | --- |\n"
                    "| [BreachForums](http://breachforums222222222222.onion) | ONLINE | Forum | Leaks & Databases |\n"
                    "| [OldDeadMarket](http://deadmarket11111111111111.onion) | OFFLINE | Market | Seized |\n"
                ),
            )
        if host == "api.ransomware.live":
            return httpx.Response(
                200,
                json=[
                    {
                        "group_name": "lockbit3",
                        "post_title": "Acme Corp",
                        "discovered": "2026-02-01",
                        "post_url": "http://lockbit33333333333333333.onion/post/1",
                    }
                ],
            )
        if host == "ahmia.fi":
            return httpx.Response(
                200,
                text='<html><body><a href="http://ahmiaonion44444444444444.onion/">Mirror</a></body></html>',
            )
        if host.endswith(".onion"):
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text=(
                    "<html><head><title>Dark Forum Node</title></head><body>"
                    "Contact: admin@darkforum.org | Telegram: https://t.me/darkforum_ops "
                    "Escrow BTC: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq "
                    "PGP: 1234 5678 9ABC DEF0 1234 5678 9ABC DEF0 1234 5678 "
                    "Mirror: http://mirroronion5555555555555.onion/login"
                    "</body></html>"
                ),
            )
        if host == "www.reddit.com":
            return httpx.Response(
                200,
                json={
                    "data": {
                        "name": "jdoe",
                        "total_karma": 420,
                        "subreddit": {"public_description": "Security researcher"},
                    }
                },
            )
        if host == "hn.algolia.com":
            return httpx.Response(200, json={"username": "jdoe", "karma": 150, "about": "OSINT & CTI"})
        if host == "lobste.rs":
            return httpx.Response(
                200,
                json={"username": "jdoe", "invited_by_user": "alice_sec", "github_username": "jdoe"},
            )
        if host == "public.api.bsky.app":
            return httpx.Response(
                200,
                json={
                    "handle": "jdoe.bsky.social",
                    "displayName": "John Doe",
                    "description": "DFIR analyst",
                },
            )
        if host == "api.github.com" and path.endswith("/events/public"):
            return httpx.Response(
                200,
                json=[
                    {
                        "repo": {"name": "jdoe/osint-kit"},
                        "payload": {"commits": [{"author": {"email": "jdoe.commits@example.com", "name": "John Doe"}}]},
                    }
                ],
            )
        if host == "keybase.io" and params.get("usernames") == "kproof":
            return httpx.Response(
                200,
                json={
                    "them": [
                        {
                            "profile": {"full_name": "Keybase Proofer", "location": "Zurich"},
                            "proofs_summary": {
                                "all": [
                                    {
                                        "proof_type": "github",
                                        "nametag": "kproof_gh",
                                        "service_url": "https://github.com/kproof_gh",
                                    },
                                    {
                                        "proof_type": "dns",
                                        "nametag": "kproof.org",
                                        "service_url": "http://kproof.org",
                                    },
                                ]
                            },
                            "public_keys": {"primary": {"key_fingerprint": "AABBCCDDEEFF00112233445566778899AABBCCDD"}},
                            "cryptocurrency_addresses": {
                                "bitcoin": [{"address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"}]
                            },
                        }
                    ]
                },
            )
        profiles = {
            "api.github.com": (
                path == "/users/jdoe",
                {
                    "login": "jdoe",
                    "name": "John Doe",
                    "company": "@AcmeCorp",
                    "blog": "jdoe.dev",
                    "location": "Madrid",
                    "email": "jdoe@example.com",
                    "html_url": "https://github.com/jdoe",
                    "public_repos": 12,
                    "followers": 34,
                },
            ),
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
        (
            "CertSpotterSubdomains",
            "example.com",
            [
                ("maltego.DNSName", "ct.example.com", "certificate_san"),
                ("maltego.DNSName", "www.example.com", "certificate_san"),
            ],
        ),
        (
            "HackerTargetSubdomains",
            "example.com",
            [
                ("maltego.DNSName", "www.example.com", "subdomain"),
                ("maltego.IPv4Address", "93.184.216.34", "resolves_to"),
                ("maltego.DNSName", "dev.example.com", "subdomain"),
                ("maltego.IPv4Address", "93.184.216.35", "resolves_to"),
            ],
        ),
        (
            "URLScanDomainSearch",
            "example.com",
            [
                ("maltego.DNSName", "www.example.com", "observed_in_urlscan"),
                ("maltego.IPv4Address", "93.184.216.34", "resolves_to"),
                ("maltego.URL", "https://www.example.com/", "observed_url"),
            ],
        ),
        (
            "InternetDBIPToServices",
            "93.184.216.34",
            [
                ("maltego.Port", "80", "open_port"),
                ("maltego.Port", "443", "open_port"),
                ("maltego.Service", "cpe:/a:igor_sysoev:nginx:1.25", "runs_service"),
                ("maltego.DNSName", "edge.example.com", "hostname"),
                ("maltego.Phrase", "[CVE] CVE-2023-44487", "vulnerable_to"),
                ("maltego.Phrase", "[InternetDB] cdn", "tagged_as"),
            ],
        ),
        (
            "RIPEStatASNToNetblocks",
            "AS15133",
            [
                ("maltego.Organization", "EDGECAST - MCI Communications Services", "operated_by"),
                ("maltego.Netblock", "93.184.216.0/24", "announces"),
            ],
        ),
        (
            "GravatarEmailToProfile",
            "jdoe@example.com",
            [
                ("maltego.Alias", "jdoe", "has_alias"),
                ("maltego.Person", "John Doe", "display_name"),
                ("maltego.Location", "Madrid", "located_in"),
                ("maltego.Affiliation", "jdoe (github)", "has_profile"),
            ],
        ),
        (
            "GitHubAliasToDetails",
            "jdoe",
            [
                ("maltego.Person", "John Doe", "real_name"),
                ("maltego.Organization", "AcmeCorp", "works_at"),
                ("maltego.EmailAddress", "jdoe@example.com", "public_email"),
                ("maltego.URL", "https://jdoe.dev", "website"),
                ("maltego.Location", "Madrid", "located_in"),
            ],
        ),
        (
            "OTXHashToThreatPulses",
            "ab" * 32,
            [
                ("maltego.Phrase", "[OTX] Presente en 2 pulso(s) de amenazas", "threat_intel"),
                ("maltego.Phrase", "[OTX Pulse] Emotet Wave", "observed_in"),
                ("maltego.Phrase", "[Malware] Emotet", "classified_as"),
                ("maltego.Phrase", "[ATT&CK T1566]", "uses_technique"),
            ],
        ),
    ],
)
async def test_transforms(ctx: BuiltinContext, name: str, value: str, expected: list[tuple[str, str, str]]) -> None:
    assert await run(ctx, name, value) == expected


async def test_crtsh_usa_respaldo_certspotter_si_falla(ctx: BuiltinContext, router: Router) -> None:
    router.fail["crt.sh"] = 502
    sub = await run(ctx, "DomainToSubdomains", "example.com")
    assert ("maltego.DNSName", "ct.example.com", "certificate_san") in sub
    assert any(r.url.host == "api.certspotter.com" for r in router.requests)


async def test_hackertarget_cuota_y_internetdb_404(ctx: BuiltinContext) -> None:
    ht = await T("HackerTargetSubdomains").handler(ctx, "maltego.Domain", "quota.example", {}, 10)
    assert ht.entities == [] and "HackerTarget" in ht.messages[0][1]
    idb = await T("InternetDBIPToServices").handler(ctx, "maltego.IPv4Address", "203.0.113.9", {}, 10)
    assert idb.entities == [] and "InternetDB" in idb.messages[0][1]


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


async def test_rdap_usa_respaldo_arin_si_falla_rdap_org(ctx: BuiltinContext, router: Router) -> None:
    router.fail["rdap.org"] = "timeout"
    dom = await run(ctx, "DomainToWhois", "example.com")
    assert ("maltego.Organization", "RESERVED-IANA", "registrar") in dom
    assert any(r.url.host == "rdap-bootstrap.arin.net" for r in router.requests)


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


async def test_breach_semantic_pivot_email_y_hash(ctx: BuiltinContext) -> None:
    email_res = await run(ctx, "BreachSemanticPivot", "ana@example.com")
    assert ("maltego.Phrase", "[Breach] Adobe", "exposed_in") in email_res
    assert ("maltego.Phrase", "[Breach] Dropbox", "exposed_in") in email_res
    hash_res = await run(ctx, "BreachSemanticPivot", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")
    assert any(val.startswith("[PwnedPassword] Hash SHA-1 expuesto") for _, val, _ in hash_res)


async def test_analyze_subject_behavior_transform(ctx: BuiltinContext) -> None:
    props = {
        "bio": "Researcher & developer working on security architecture at @AcmeSec in Madrid UTC+1",
        "company": "@AcmeSec",
        "location": "Madrid, Spain",
    }
    res = await T("AnalyzeSubjectBehavior").handler(ctx, "maltego.Alias", "ana", props, 10)
    types_rels = [(e.entity_type, e.link_label) for e in res.entities]
    assert ("humint.PsychologicalTrait", "exhibits_trait") in types_rels
    assert ("humint.Organization", "affiliated_with") in types_rels
    assert ("humint.LocationHistory", "frequented_location") in types_rels
    assert all(
        e.properties.get("humint.epistemic_status") == "hypothesis"
        for e in res.entities
        if e.entity_type == "humint.PsychologicalTrait"
    )
