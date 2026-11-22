"""Tests de salidas seguras (F6): defang, cabeceras CSP, sanitización .mtgx y aviso de Stealth Mode."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from starlette.testclient import TestClient

from maltego_mcp.config import Settings
from maltego_mcp.defang import defang, defang_text, refang
from maltego_mcp.domain.records import CaseRecord, EntityRecord, StepRecord
from maltego_mcp.maltego.mtgx import GRAPH_MEMBER, SIDECAR_MEMBER, write_mtgx
from maltego_mcp.report import ReportData, to_html, to_markdown
from maltego_mcp.server import INSTRUCTIONS, build_service, create_server
from maltego_mcp.web_app import attach_dashboard_routes


def test_defang_urls_domains_ips_emails() -> None:
    # 1. URLs
    assert defang("https://victim.com/login?id=1") == "hxxps[://]victim[.]com/login?id=1"
    assert defang("http://sub.victim.org:8080/path") == "hxxp[://]sub[.]victim[.]org:8080/path"
    assert defang("ftp://files.victim.net/pub") == "fxp[://]files[.]victim[.]net/pub"

    # 2. Dominios e IPs
    assert defang("victim.com") == "victim[.]com"
    assert defang("192.168.1.100") == "192[.]168[.]1[.]100"

    # 3. Correos
    assert defang("admin@victim.com") == "admin[@]victim[.]com"

    # 4. Refang
    assert refang("hxxps[://]victim[.]com/login") == "https://victim.com/login"
    assert refang("victim[.]com") == "victim.com"
    assert refang("admin[@]victim[.]com") == "admin@victim.com"


def test_defang_text_block() -> None:
    text = (
        "Contacte a admin@victim.com o visite https://portal.victim.com/test para ver el panel "
        "en 10.0.0.1 y http://legacy.victim.com."
    )
    neutralized = defang_text(text)
    assert "https://" not in neutralized
    assert "http://" not in neutralized
    assert "admin[@]victim[.]com" in neutralized
    assert "hxxps[://]portal[.]victim[.]com/test" in neutralized
    assert "hxxp[://]legacy[.]victim[.]com" in neutralized


def test_dashboard_security_headers(tmp_path: Path) -> None:
    settings = Settings(data_file=tmp_path / "graph.json", home=tmp_path)
    server = create_server(settings)
    app = server.streamable_http_app(stateless_http=True, json_response=True)
    svc = getattr(server, "_service", None) or build_service(settings)
    attach_dashboard_routes(app, svc, settings)

    client = TestClient(app)

    # 1. Raíz /
    r = client.get("/")
    assert r.status_code == 200
    csp = r.headers.get("content-security-policy", "")
    assert "default-src 'none'" in csp
    assert "script-src 'self'" in csp
    assert "img-src 'self' data:" in csp
    assert "connect-src 'self'" in csp
    assert "frame-src 'none'" in csp
    assert r.headers.get("x-dns-prefetch-control") == "off"
    assert r.headers.get("referrer-policy") == "no-referrer"
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"

    # 2. Endpoint REST /api/status
    r_api = client.get("/api/status")
    assert r_api.status_code == 200
    assert "default-src 'none'" in r_api.headers.get("content-security-policy", "")
    assert r_api.headers.get("x-dns-prefetch-control") == "off"


def test_index_html_has_meta_security_tags() -> None:
    index_path = Path("src/maltego_mcp/web/index.html")
    assert index_path.is_file()
    content = index_path.read_text(encoding="utf-8")
    assert '<meta name="referrer" content="no-referrer">' in content
    assert '<meta http-equiv="x-dns-prefetch-control" content="off">' in content
    assert 'http-equiv="Content-Security-Policy"' in content
    assert "default-src 'none'" in content


def test_mtgx_purges_remote_icons_images_and_html_display_info() -> None:
    # Entidad maliciosa o con propiedades remotas de rastreo
    e = EntityRecord(
        id="ent_malicious",
        case_id="case1",
        label="Host",
        maltego_type="maltego.IPv4Address",
        value="1.2.3.4",
        confidence=0.9,
        sources=["osint"],
        properties={
            "iconURL": "http://adversary.com/logger.png",
            "maltego.iconURL": "https://adversary.com/tracker.gif",
            "image": "http://evil.com/beacon.jpg",
            "overlayURL": "http://evil.com/overlay.png",
            "displayInformation": "<p>Detalles</p><img src='http://evil.com/leak.png'><script>alert(1)</script>",
            "safe_prop": "valor_legitimo",
        },
    )

    sidecar = {"case_id": "case1"}
    mtgx_bytes = write_mtgx([e], [], "hierarchical", sidecar)

    with zipfile.ZipFile(io.BytesIO(mtgx_bytes)) as zf:
        xml_content = zf.read(GRAPH_MEMBER).decode("utf-8")
        assert SIDECAR_MEMBER in zf.namelist()

    # 1. No debe existir iconURL, image remota ni overlayURL en las propiedades
    assert "http://adversary.com/logger.png" not in xml_content
    assert "https://adversary.com/tracker.gif" not in xml_content
    assert "http://evil.com/beacon.jpg" not in xml_content
    assert "http://evil.com/overlay.png" not in xml_content

    # 2. DisplayInformation no debe contener tags HTML ejecutables ni URLs
    assert "<img" not in xml_content
    assert "<script" not in xml_content
    assert "safe_prop" in xml_content

    # 3. Sidecar debe contener la advertencia de Stealth Mode
    assert "stealth_mode_warning" in sidecar
    assert "Stealth Mode" in sidecar["stealth_mode_warning"]


def test_reports_contain_stealth_mode_warning() -> None:
    case = CaseRecord("c_stealth", "Investigacion Sigilosa", "2026-03-30T10:00:00Z")
    e = EntityRecord("e1", "c_stealth", "Domain", "maltego.Domain", "target-domain.com", 1.0, ["crt.sh"], {})
    data = ReportData(
        case=case,
        entities=[e],
        edges=[],
        steps=[StepRecord(1, "c_stealth", "2026-03-30T10:00:00Z", "transform", "PassiveDomainRecon")],
        scores={},
        actions=[],
        generated="2026-03-30 18:00:00 UTC",
    )

    md = to_markdown(data)
    html_doc = to_html(data)

    # 1. Advertencia de Stealth Mode en Markdown
    assert "ADVERTENCIA DE SEGURIDAD OPERATIVA Y MODO SIGILOSO (STEALTH MODE)" in md
    assert "Stealth Mode" in md

    # 2. Advertencia de Stealth Mode en HTML
    assert "AVISO DE SEGURIDAD OPERATIVA Y MODO SIGILOSO (STEALTH MODE)" in html_doc
    assert "Stealth Mode" in html_doc

    # 3. Sin enlaces activos al objetivo
    assert 'href="http' not in html_doc
    assert 'src="http' not in html_doc


def test_server_instructions_has_safe_navigation_rule() -> None:
    assert "No abras URLs ni hosts del objetivo" in INSTRUCTIONS
