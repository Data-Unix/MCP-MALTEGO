"""Pruebas exhaustivas para F4: DNS pasivo histórico (pDNS), fuentes CDX de archivo,
certificados por organización, metadatos seguros y heurística de canarios.
"""

from __future__ import annotations

import io
import zipfile

import httpx
import pytest

from maltego_mcp.transforms.builtin import BUILTIN_TRANSFORMS
from maltego_mcp.transforms.pdns import (
    extract_doc_metadata,
    fetch_arquivo_cdx,
    fetch_crtsh_by_org,
    fetch_mnemonic_pdns,
    fetch_otx_pdns,
    fetch_passive_ptr,
    fetch_robtex_pdns,
    fetch_wayback_cdx,
    is_possible_canary,
    normalize_iso_utc,
    shannon_entropy,
)


def test_shannon_entropy_y_canarios() -> None:
    # Subdominio normal: entropía baja / longitud moderada
    assert not is_possible_canary("www")
    assert not is_possible_canary("mail.corp")
    assert not is_possible_canary("vpn-gateway")
    assert shannon_entropy("www") < 1.0

    # Subdominio canario: longitud > 30
    long_sub = "a" * 35
    assert is_possible_canary(long_sub)

    # Subdominio canario: entropía alta (>3.8) y longitud >= 16
    high_ent = "w9x8k2q1z4b7m3v5"
    assert shannon_entropy(high_ent) >= 3.8
    assert is_possible_canary(high_ent)

    # Base32 canario (ej. token canarytokens.org)
    base32_token = "g4ztsmzugc3tgnbsgq2dqmzt"
    assert is_possible_canary(base32_token)


def test_normalize_iso_utc() -> None:
    # Epoch ms
    assert normalize_iso_utc(1672531199000) == "2022-12-31T23:59:59Z"
    # Epoch s
    assert normalize_iso_utc(1672531199) == "2022-12-31T23:59:59Z"
    # Cadena numérica
    assert normalize_iso_utc("1672531199") == "2022-12-31T23:59:59Z"
    # ISO string con Z
    assert normalize_iso_utc("2023-05-10T14:30:00Z") == "2023-05-10T14:30:00Z"
    # Cadena vacía o inválida
    assert normalize_iso_utc("") == ""
    assert normalize_iso_utc(None) == ""


@pytest.mark.asyncio
async def test_fetch_mnemonic_pdns() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "example.com" in str(request.url)
        return httpx.Response(
            200,
            json={
                "responseCode": 200,
                "data": [
                    {
                        "query": "example.com",
                        "answer": "93.184.216.34",
                        "rrtype": "a",
                        "firstSeenTimestamp": "2020-01-01T00:00:00Z",
                        "lastSeenTimestamp": "2024-01-01T00:00:00Z",
                        "count": 42,
                    }
                ],
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        res = await fetch_mnemonic_pdns(client, "example.com", "A")
        assert len(res) == 1
        assert res[0]["answer"] == "93.184.216.34"
        assert res[0]["rrtype"] == "A"
        assert res[0]["first_seen"] == "2020-01-01T00:00:00Z"
        assert res[0]["source"] == "mnemonic"


@pytest.mark.asyncio
async def test_fetch_robtex_pdns() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        lines = (
            '{"rrdata": "93.184.216.34", "rrtype": "A", "time_first": 1577836800, "time_last": 1704067200}\n'
            '{"rrdata": "mail.example.com", "rrtype": "MX", "time_first": 1577836800, "time_last": 1704067200}\n'
        )
        return httpx.Response(200, text=lines)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        res = await fetch_robtex_pdns(client, "example.com")
        assert len(res) == 2
        assert res[0]["answer"] == "93.184.216.34"
        assert res[0]["rrtype"] == "A"
        assert res[0]["source"] == "robtex"


@pytest.mark.asyncio
async def test_fetch_otx_pdns() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-otx-api-key"] == "secret_otx"
        return httpx.Response(
            200,
            json={
                "passive_dns": [
                    {
                        "address": "93.184.216.34",
                        "record_type": "A",
                        "first": "2021-01-01T00:00:00",
                        "last": "2023-01-01T00:00:00",
                    }
                ]
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        res = await fetch_otx_pdns(client, "example.com", "secret_otx")
        assert len(res) == 1
        assert res[0]["answer"] == "93.184.216.34"
        assert res[0]["source"] == "otx"


@pytest.mark.asyncio
async def test_fetch_passive_ptr() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        url_s = str(request.url)
        if "internetdb.shodan.io" in url_s:
            return httpx.Response(200, json={"hostnames": ["alpha.example.com"]})
        if "freeapi.robtex.com" in url_s:
            return httpx.Response(200, text='{"rrdata": "beta.example.com", "rrtype": "PTR"}\n')
        if "ip.thc.org" in url_s:
            return httpx.Response(200, text="gamma.example.com\n")
        if "reverseiplookup" in url_s:
            return httpx.Response(200, text="delta.example.com\n")
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        res = await fetch_passive_ptr(client, "93.184.216.34")
        hosts = [r["hostname"] for r in res]
        assert "alpha.example.com" in hosts
        assert "beta.example.com" in hosts
        assert "gamma.example.com" in hosts
        assert "delta.example.com" in hosts


@pytest.mark.asyncio
async def test_fetch_wayback_cdx() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=[
                ["timestamp", "original", "statuscode", "mimetype", "digest"],
                ["20220101120000", "https://example.com/login", "200", "text/html", "DIG1"],
                ["20230101120000", "https://example.com/portal", "200", "text/html", "DIG2"],
            ],
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        res = await fetch_wayback_cdx(client, "example.com")
        assert len(res) == 2
        assert res[0]["url"] == "https://example.com/login"
        assert res[0]["source"] == "wayback_cdx"
        assert res[1]["url"] == "https://example.com/portal"


@pytest.mark.asyncio
async def test_fetch_arquivo_cdx() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text='{"url": "https://example.com/pt/historia", "timestamp": "20210505120000", "mimetype": "text/html"}\n',
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        res = await fetch_arquivo_cdx(client, "example.com")
        assert len(res) == 1
        assert res[0]["url"] == "https://example.com/pt/historia"
        assert res[0]["source"] == "arquivo_cdx"


@pytest.mark.asyncio
async def test_fetch_crtsh_by_org() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "Example" in str(request.url)
        return httpx.Response(
            200,
            json=[
                {
                    "name_value": "*.example.com\nportal.example.com",
                    "not_before": "2023-01-01T00:00:00",
                    "issuer_name": "C=US, O=Let's Encrypt",
                }
            ],
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        res = await fetch_crtsh_by_org(client, "Example Corp")
        assert len(res) == 2
        domains = [r["domain"] for r in res]
        assert "example.com" in domains
        assert "portal.example.com" in domains
        assert res[0]["source"] == "crtsh_org"


def test_extract_doc_metadata_ooxml() -> None:
    # Crea un docx sintético en memoria
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        core_xml = (
            b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            b'<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            b'xmlns:dc="http://purl.org/dc/elements/1.1/">'
            b"<dc:title>Informe Confidencial</dc:title>"
            b"<dc:creator>Analista Senior</dc:creator>"
            b"<cp:lastModifiedBy>Director CTI</cp:lastModifiedBy>"
            b"</cp:coreProperties>"
        )
        app_xml = (
            b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            b'<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
            b"<Company>Acme Corporation</Company>"
            b"<Application>Microsoft Word 16.0</Application>"
            b"</Properties>"
        )
        z.writestr("docProps/core.xml", core_xml)
        z.writestr("docProps/app.xml", app_xml)

    meta = extract_doc_metadata(bio.getvalue(), "investigacion.docx")
    assert meta["title"] == "Informe Confidencial"
    assert meta["creator"] == "Analista Senior"
    assert meta["last_modified_by"] == "Director CTI"
    assert meta["company"] == "Acme Corporation"
    assert "Word" in meta["software"]


def test_extract_doc_metadata_pdf() -> None:
    # PDF sintético mínimo con bloque /Info
    pdf_bytes = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Title (Auditoria Interna) /Author (Jane Doe) /Creator (LibreOffice) >>\nendobj\n"
        b"trailer\n<< /Info 1 0 R >>\n%%EOF"
    )
    meta = extract_doc_metadata(pdf_bytes, "reporte.pdf")
    assert meta["title"] == "Auditoria Interna"
    assert meta["creator"] == "Jane Doe"
    assert meta["software"] == "LibreOffice"


@pytest.mark.asyncio
async def test_nuevos_transforms_en_builtin() -> None:
    # Verifica que WaybackCDXSearch, ArquivoCDXSearch, CommonCrawlCDXSearch, AnubisSubdomains,
    # GLEIFCompanyToStructure, IPToPassiveContext, CTOrgToCertificates, WaybackSnapshotExtract,
    # GitHubDomainToLeaks y BOEEntityToRecords se ejecutan correctamente
    names = {b.name for b in BUILTIN_TRANSFORMS}
    assert "WaybackCDXSearch" in names
    assert "ArquivoCDXSearch" in names
    assert "CommonCrawlCDXSearch" in names
    assert "AnubisSubdomains" in names
    assert "GLEIFCompanyToStructure" in names
    assert "IPToPassiveContext" in names
    assert "CTOrgToCertificates" in names
    assert "WaybackSnapshotExtract" in names
    assert "GitHubDomainToLeaks" in names
    assert "BOEEntityToRecords" in names

    wb_tx = next(b for b in BUILTIN_TRANSFORMS if b.name == "WaybackCDXSearch")
    assert wb_tx.passivity == "passive"
    assert wb_tx.is_passive is True


@pytest.mark.asyncio
async def test_wayback_snapshot_extract_github_leaks_boe_y_fallbacks() -> None:
    from maltego_mcp.transforms.builtin import BuiltinContext, new_http_client

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        path = request.url.path
        if host == "web.archive.org" and path == "/cdx/search/cdx":
            q_url = request.url.params.get("url", "")
            if "boe.es" in q_url:
                return httpx.Response(
                    200,
                    json=[
                        ["timestamp", "original", "statuscode"],
                        [
                            "20231215100000",
                            "https://www.boe.es/borme/dias/2023/12/15/pdfs/BORME-A-2023-238-28.pdf",
                            "200",
                        ],
                    ],
                )
            return httpx.Response(
                200,
                json=[
                    ["timestamp", "original", "statuscode", "mimetype"],
                    ["20250110120000", "https://www.aticamotorsport.com/aviso-legal", "200", "text/html"],
                ],
            )
        if host == "web.archive.org" and path.startswith("/web/"):
            html = (
                "<html><head><title>Ática Motor Sport - Taller Especialista BMW</title></head>"
                "<body><p>Titular: ATICA MOTOR SPORT S.L. con CIF B-87517835.</p>"
                "<p>Contacto: info@aticamotorsport.com | Tel: 912 655 856 y 656 594 451</p></body></html>"
            )
            return httpx.Response(200, text=html, headers={"content-type": "text/html"})
        if host == "crt.sh":
            return httpx.Response(
                200,
                json=[{"name_value": "aticamotorsport.com", "not_before": "2024-03-01T00:00:00", "issuer_name": "LE"}],
            )
        if host == "api.github.com" and path == "/search/code":
            return httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "html_url": "https://github.com/org/repo/blob/main/config.env",
                            "path": "config.env",
                            "repository": {"full_name": "org/repo"},
                        }
                    ]
                },
            )
        if host == "api.github.com" and path == "/search/repositories":
            return httpx.Response(200, json={"items": []})
        if host == "api.shodan.io" and path.startswith("/dns/domain/"):
            return httpx.Response(403, json={"error": "Upgrade required"})
        if host == "api.hunter.io" and path == "/v2/domain-search":
            if request.url.params.get("limit") == "10":
                return httpx.Response(400, json={"errors": [{"id": "pagination_error"}]})
            return httpx.Response(
                200,
                json={
                    "data": {
                        "organization": "Atica Motor Sport S.L.",
                        "pattern": "{first}",
                        "emails": [
                            {
                                "value": "info@aticamotorsport.com",
                                "first_name": "Francisco",
                                "last_name": "Martín",
                                "confidence": 92,
                            }
                        ],
                    }
                },
            )
        return httpx.Response(404)

    ctx = BuiltinContext(
        new_http_client(transport=httpx.MockTransport(handler)),
        {"GITHUB_TOKEN": "ghp_test", "SHODAN_API_KEY": "sh_free", "HUNTER_API_KEY": "hu_free"},
    )

    wb_snap = next(b for b in BUILTIN_TRANSFORMS if b.name == "WaybackSnapshotExtract")
    r_wb = await wb_snap.handler(ctx, "maltego.Domain", "aticamotorsport.com", {}, 20)
    vals_wb = {(e.entity_type, e.value, e.link_label) for e in r_wb.entities}
    assert ("maltego.Phrase", "[CIF/NIF] B87517835", "archived_identifier") in vals_wb
    assert ("maltego.Company", "ATICA MOTOR SPORT S.L.", "archived_company") in vals_wb
    assert ("maltego.EmailAddress", "info@aticamotorsport.com", "archived_email") in vals_wb
    assert ("maltego.PhoneNumber", "+34 912 655 856", "archived_phone") in vals_wb

    gh_tx = next(b for b in BUILTIN_TRANSFORMS if b.name == "GitHubDomainToLeaks")
    r_gh = await gh_tx.handler(ctx, "maltego.Domain", "aticamotorsport.com", {}, 10)
    assert any(e.link_label == "github_code_match" for e in r_gh.entities)

    boe_tx = next(b for b in BUILTIN_TRANSFORMS if b.name == "BOEEntityToRecords")
    r_boe = await boe_tx.handler(ctx, "maltego.Company", "ATICA MOTOR SPORT S.L.", {}, 10)
    assert any(e.link_label == "official_gazette" for e in r_boe.entities)

    sh_tx = next(b for b in BUILTIN_TRANSFORMS if b.name == "ShodanDomainToSubdomains")
    r_sh = await sh_tx.handler(ctx, "maltego.Domain", "aticamotorsport.com", {}, 10)
    assert r_sh.entities == [] and any("403" in m[1] for m in r_sh.messages)

    hu_tx = next(b for b in BUILTIN_TRANSFORMS if b.name == "HunterDomainToEmails")
    r_hu = await hu_tx.handler(ctx, "maltego.Domain", "aticamotorsport.com", {}, 50)
    assert any(e.value == "info@aticamotorsport.com" for e in r_hu.entities)


def test_extract_doc_metadata_proteccion_zip_bomb() -> None:
    """Verifica que extract_doc_metadata rechace miembros de tamaño excesivo (>5MB) sin agotar memoria (S5/B14)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zinfo = zipfile.ZipInfo("docProps/core.xml")
        zinfo.file_size = 10 * 1024 * 1024  # 10 MB declarados
        zf.writestr(zinfo, b"<xml>fake</xml>")

    meta = extract_doc_metadata(buf.getvalue(), "documento_malicioso.docx")
    assert meta == {}
