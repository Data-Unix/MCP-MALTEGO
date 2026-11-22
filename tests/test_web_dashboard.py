"""Tests exhaustivos para la aplicación web y suite REST del Dashboard MCP Maltego."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from maltego_mcp.config import Settings
from maltego_mcp.server import build_service, create_server
from maltego_mcp.web_app import attach_dashboard_routes


def _create_test_app(tmp_path: Path):
    settings = Settings(data_file=tmp_path / "graph.json", home=tmp_path)
    server = create_server(settings)
    app = server.streamable_http_app(stateless_http=True, json_response=True)
    svc = getattr(server, "_service", None) or build_service(settings)
    attach_dashboard_routes(app, svc, settings)
    return app


def test_dashboard_serves_html_and_assets(tmp_path: Path) -> None:
    app = _create_test_app(tmp_path)
    client = TestClient(app)

    # 1. Raíz y /dashboard
    r_root = client.get("/")
    assert r_root.status_code == 200
    assert "MCP Maltego" in r_root.text
    assert "Centro de Mando" in r_root.text
    assert "bg-canvas" in r_root.text
    assert "graph-filter-drawer" in r_root.text
    assert "graph-search-input" in r_root.text
    assert "btn-export-dropdown" in r_root.text
    assert "modal-import" in r_root.text
    assert "import-dropzone" in r_root.text
    assert "modal-aml-trace" in r_root.text
    assert "modal-path-trace" in r_root.text
    assert "table-toolbar-tactical" in r_root.text
    assert 'data-tab="profiling"' in r_root.text
    assert "view-profiling" in r_root.text
    assert "profiling-target-select" in r_root.text
    assert "profiling-typology-select" in r_root.text

    # Modulos y modales retirados en F7 no deben estar presentes
    assert "modal-bgp-trace" not in r_root.text
    assert "modal-country-geo" not in r_root.text
    assert "modal-evidence-trace" not in r_root.text
    assert "geomap-canvas" not in r_root.text
    assert "geomap-container" not in r_root.text
    assert "geomap-nodes-table" not in r_root.text
    assert "view-geo-map" not in r_root.text
    assert "view-threat-watchtower" not in r_root.text
    assert "view-mitre-matrix" not in r_root.text
    assert "view-rules-generator" not in r_root.text
    assert "view-forensics-vault" not in r_root.text
    assert "view-desktop-bridge" not in r_root.text

    r_dash = client.get("/dashboard")
    assert r_dash.status_code == 200
    assert "Bóveda & Sock Puppets" in r_dash.text
    assert "account-category-cards" in r_dash.text
    assert "Redes Sociales & Mensajería" in r_dash.text
    assert "Foros Ciber & Underground" in r_dash.text
    assert "Mercados Dark Web & Leaks" in r_dash.text
    assert "modal-category-tabs" in r_dash.text

    # 2. Ficheros estáticos
    r_css = client.get("/dashboard.css")
    assert r_css.status_code == 200
    assert "--bg-base" in r_css.text
    assert ".graph-filter-drawer" in r_css.text
    assert ".account-category-cards" in r_css.text
    assert ".modal-category-tabs" in r_css.text
    assert ".dropdown-menu" in r_css.text
    assert ".import-dropzone" in r_css.text
    assert ".table-toolbar-tactical" in r_css.text
    assert ".row-expand-btn" in r_css.text
    assert ".density-compact" in r_css.text
    assert ".trace-timeline" in r_css.text

    r_js = client.get("/dashboard.js")
    assert r_js.status_code == 200
    assert "initBackgroundCanvas" in r_js.text
    assert "applyAllGraphFilters" in r_js.text
    assert "drawNodeGlyph" in r_js.text
    assert "selectModalCategory" in r_js.text
    assert "setTorProxyPreset" in r_js.text
    assert "filterAccountsByCategory" in r_js.text
    assert "toggleExportMenu" in r_js.text
    assert "openImportModal" in r_js.text
    assert "initImportDropzone" in r_js.text
    assert "setTableDensity" in r_js.text
    assert "toggleRowDetail" in r_js.text
    assert "traceAmlTransaction" in r_js.text
    assert "openPathTracerModal" in r_js.text
    assert "traceBgpRoute" not in r_js.text
    assert "renderGeoMap" not in r_js.text
    assert "drawGeoMap" not in r_js.text
    assert "buildGeoModelFromActiveCase" not in r_js.text
    assert "populateGeoNodesTable" not in r_js.text
    assert "openCountryGoogleMapsModal" not in r_js.text

    r_worker = client.get("/bg-worker.js")
    assert r_worker.status_code == 200
    assert "OffscreenCanvas" in r_worker.text

    # 3. Logos y favicons transparentes
    r_logo = client.get("/logo.png")
    assert r_logo.status_code == 200
    assert r_logo.headers["content-type"] == "image/png"
    assert len(r_logo.content) > 1000

    r_fav = client.get("/favicon.png")
    assert r_fav.status_code == 200
    assert r_fav.headers["content-type"] == "image/png"
    assert len(r_fav.content) > 500

    r_fav32 = client.get("/favicon-32x32.png")
    assert r_fav32.status_code == 200
    assert r_fav32.headers["content-type"] == "image/png"

    r_ico = client.get("/favicon.ico")
    assert r_ico.status_code == 200
    assert r_ico.headers["content-type"] == "image/x-icon"
    assert len(r_ico.content) > 1000

    r_touch = client.get("/apple-touch-icon.png")
    assert r_touch.status_code == 200
    assert r_touch.headers["content-type"] == "image/png"


def test_api_status_and_providers(tmp_path: Path) -> None:
    app = _create_test_app(tmp_path)
    client = TestClient(app)

    r_status = client.get("/api/status")
    assert r_status.status_code == 200
    data = r_status.json()
    assert data["status"] == "online"
    assert data["transforms_count"] > 20
    assert data["machines_count"] >= 5

    r_prov = client.get("/api/providers")
    assert r_prov.status_code == 200
    prov_data = r_prov.json()
    assert "providers" in prov_data
    names = [p["name"].lower() for p in prov_data["providers"]]
    assert "shodan" in names
    assert "github" in names


def test_api_accounts_crud_and_masking(tmp_path: Path) -> None:
    app = _create_test_app(tmp_path)
    client = TestClient(app)

    # 1. Listar inicialmente
    r_init = client.get("/api/accounts")
    assert r_init.status_code == 200
    assert isinstance(r_init.json()["accounts"], list)

    # 2. Crear cuenta nueva (Red Social)
    payload = {
        "id": "test-bot-01",
        "platform": "github",
        "username": "osint_hunter",
        "token": "test_token_secret_1234567890",
        "rate_limit_rpm": 45,
        "enabled": True,
    }
    r_post = client.post("/api/accounts", json=payload)
    assert r_post.status_code == 200
    assert r_post.json()["ok"] is True

    # 2b. Crear cuenta de Foro Underground con Cookie y Tor Proxy
    payload_forum = {
        "id": "forum-puppet-01",
        "platform": "breachforums",
        "category": "forum",
        "username": "shadow_op",
        "cookie": "xf_user=987654; xf_session=abcdef123456",
        "target_site": "breachforums.is",
        "proxy": "socks5h://127.0.0.1:9050",
        "rate_limit_rpm": 15,
        "enabled": True,
    }
    r_forum = client.post("/api/accounts", json=payload_forum)
    assert r_forum.status_code == 200
    assert r_forum.json()["ok"] is True

    # 2c. Crear cuenta de Mercado / Leaks
    payload_market = {
        "id": "market-intelx-01",
        "platform": "intelx",
        "category": "market",
        "username": "intel_collector",
        "token": "IX-token-secret-99999",
        "rate_limit_rpm": 10,
        "enabled": True,
    }
    r_market = client.post("/api/accounts", json=payload_market)
    assert r_market.status_code == 200
    assert r_market.json()["ok"] is True

    # 3. Listar y verificar categorías y enmascaramiento estricto
    r_list = client.get("/api/accounts")
    assert r_list.status_code == 200
    accounts = r_list.json()["accounts"]
    found = next((a for a in accounts if a["id"] == "test-bot-01"), None)
    assert found is not None
    assert found["rate_limit_rpm"] == 45
    assert found["category"] == "social"
    # El secreto en texto plano NUNCA debe viajar al frontend
    assert "test_token_secret_1234567890" not in str(r_list.text)
    assert "test_token_secret_1234567890" not in str(found["status_text"])

    found_forum = next((a for a in accounts if a["id"] == "forum-puppet-01"), None)
    assert found_forum is not None
    assert found_forum["category"] == "forum"
    assert found_forum["has_cookie"] is True
    assert found_forum["proxy"] == "socks5h://127.0.0.1:9050"
    assert "xf_session=abcdef123456" not in str(r_list.text)

    found_market = next((a for a in accounts if a["id"] == "market-intelx-01"), None)
    assert found_market is not None
    assert found_market["category"] == "market"
    assert found_market["has_token"] is True
    assert "IX-token-secret-99999" not in str(r_list.text)

    # 4. Eliminar cuentas
    for aid in ("test-bot-01", "forum-puppet-01", "market-intelx-01"):
        r_del = client.delete(f"/api/accounts/{aid}")
        assert r_del.status_code == 200
        assert r_del.json()["ok"] is True

    # 5. Confirmar eliminación
    r_after = client.get("/api/accounts")
    assert not any(a["id"] == "test-bot-01" for a in r_after.json()["accounts"])


def test_api_verify_account_and_persona(tmp_path: Path) -> None:
    app = _create_test_app(tmp_path)
    client = TestClient(app)

    # 1. Verificación de cuenta genérica/offline
    r_verify = client.post(
        "/api/accounts/verify",
        json={"platform": "generic", "username": "dummy_analyst"},
    )
    assert r_verify.status_code == 200
    rep = r_verify.json()
    assert rep["status"] == "ok"
    assert "latencia_ms" in rep or "latency_ms" in rep

    # 2. Generación determinista de Sock Puppet Persona
    r_persona = client.post(
        "/api/accounts/generate-persona",
        json={
            "role": "threat_intel_collector",
            "region": "EE",
            "target_site": "exploit.in",
            "save": False,
        },
    )
    assert r_persona.status_code == 200
    p = r_persona.json()
    assert "drift_" in p["handle"] or len(p["handle"]) > 3
    assert p["totp_secret_base32"]
    assert len(p["opsec_checklist"]) >= 3


def test_api_transforms_and_lookup_playground(tmp_path: Path) -> None:
    app = _create_test_app(tmp_path)
    client = TestClient(app)

    # 1. Catálogo
    r_cat = client.get("/api/transforms")
    assert r_cat.status_code == 200
    data = r_cat.json()
    assert len(data["transforms"]) > 20
    assert any(m["name"] == "DarkWebFootprint" for m in data["machines"])

    # 2. Lookup en transform sin red (ej. DomainToWebsite)
    r_lookup = client.post(
        "/api/lookup",
        json={"transform": "DomainToWebsite", "value": "example.com", "type": "maltego.Domain"},
    )
    assert r_lookup.status_code == 200
    l_data = r_lookup.json()
    assert l_data["ok"] is True
    assert len(l_data["entities"]) >= 1


def test_api_security_host_protection(tmp_path: Path) -> None:
    app = _create_test_app(tmp_path)
    client = TestClient(app)

    # Intento de ataque por DNS rebinding o Host header externo
    r_evil = client.get("/api/status", headers={"Host": "attacker.malicious-site.com"})
    assert r_evil.status_code == 403

    r_evil_root = client.get("/", headers={"Host": "attacker.malicious-site.com"})
    assert r_evil_root.status_code == 403


def test_api_inbox_endpoints(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = _create_test_app(tmp_path)
    client = TestClient(app)

    # 1. Catálogo OPSEC de proveedores de correo
    r_prov = client.get("/api/inbox/providers")
    assert r_prov.status_code == 200
    p_data = r_prov.json()
    assert "providers" in p_data
    assert len(p_data["providers"]) >= 10
    names = [p["name"] for p in p_data["providers"]]
    assert "Proton Mail" in names
    assert "Mail.tm (API Automatizada)" in names

    # 2. Creación simulada de buzón
    async def mock_create_inbox(self, address="", password=""):
        return {
            "ok": True,
            "provider": "mail.tm",
            "inbox_id": "test_inbox_123",
            "address": address or "sockpuppet_test@mailtm.me",
            "password": password or "safe_pass_999",
            "token": "fake_jwt_token",
            "status": "ready",
        }

    monkeypatch.setattr("maltego_mcp.web_app.MailTmClient.create_inbox", mock_create_inbox)

    r_create = client.post(
        "/api/inbox/create",
        json={"save_as_sockpuppet": True, "address": "osint_agent@mailtm.me"},
    )
    assert r_create.status_code == 200
    c_data = r_create.json()
    assert c_data["ok"] is True
    assert c_data["address"] == "osint_agent@mailtm.me"

    # Verificar que se guardó en accounts.toml
    r_accs = client.get("/api/accounts")
    assert r_accs.status_code == 200
    acc_list = r_accs.json()["accounts"]
    assert any("mailtm_osint_agent" in a["id"] for a in acc_list)

    # 3. Validación de mensajes con token ausente
    r_no_token = client.get("/api/inbox/messages")
    assert r_no_token.status_code == 400


def test_api_case_export_and_import(tmp_path: Path) -> None:
    app = _create_test_app(tmp_path)
    client = TestClient(app)

    # 1. Crear un caso con entidad inicial
    r_create = client.post("/api/cases", json={"case_id": "caso-test-export", "description": "Caso de prueba"})
    assert r_create.status_code == 200
    assert r_create.json()["ok"] is True

    # 2. Probar exportación en todos los formatos soportados, incluido .mcpcase
    for fmt in ("mcpcase", "mtgx", "json", "csv", "graphml", "report_html", "report_md"):
        r_exp = client.get(f"/api/cases/caso-test-export/export/{fmt}")
        assert r_exp.status_code == 200, f"Fallo al exportar formato {fmt}"
        assert len(r_exp.content) > 0
        assert "Content-Disposition" in r_exp.headers

    # 3. Probar exportacion e importacion de paquete nativo .mcpcase con verificacion criptografica
    r_mcpcase = client.get("/api/cases/caso-test-export/export/mcpcase")
    assert r_mcpcase.status_code == 200
    mcpcase_bytes = r_mcpcase.content
    mcpcase_payload = json.loads(mcpcase_bytes.decode("utf-8"))
    assert mcpcase_payload["format"] == "maltego-mcp-case/v1"
    assert mcpcase_payload["checksum"].startswith("sha256:")

    # Importar el .mcpcase autentico creando nuevo caso
    r_imp_mcp = client.post(
        "/api/cases/import",
        files={"file": ("investigacion.mcpcase", mcpcase_bytes, "application/vnd.maltego-mcp.case+json")},
        data={"case_id": "caso-desde-mcpcase", "create_new": "true"},
    )
    assert r_imp_mcp.status_code == 200
    assert r_imp_mcp.json()["ok"] is True
    assert r_imp_mcp.json()["format"] == "mcpcase"

    # Verificar rechazo de integridad criptografica ante corrupcion o manipulacion
    tampered_payload = dict(mcpcase_payload)
    tampered_payload["case"] = dict(tampered_payload["case"])
    tampered_payload["case"]["description"] = "Descripcion manipulada maliciosamente"
    tampered_bytes = json.dumps(tampered_payload).encode("utf-8")
    r_tampered = client.post(
        "/api/cases/import",
        files={"file": ("tampered.mcpcase", tampered_bytes, "application/vnd.maltego-mcp.case+json")},
        data={"case_id": "caso-tampered", "create_new": "true"},
    )
    assert r_tampered.status_code == 400
    assert "checksum" in r_tampered.json()["error"].lower() or "corrupto" in r_tampered.json()["error"].lower()

    # 4. Probar importación creando una nueva investigación desde cero con CSV
    csv_data = (
        "source_type,source_value,relation,target_type,target_value,confidence\n"
        "maltego.Domain,target.com,has_ip,maltego.IPv4Address,1.2.3.4,0.9\n"
    )
    r_imp_new = client.post(
        "/api/cases/import",
        files={"file": ("red-objetivo.csv", csv_data.encode("utf-8"), "text/csv")},
        data={
            "case_id": "caso-nuevo-desde-cero",
            "description": "Investigación creada desde archivo",
            "create_new": "true",
        },
    )
    assert r_imp_new.status_code == 200
    imp_data = r_imp_new.json()
    assert imp_data["ok"] is True
    assert imp_data["case_id"] == "caso-nuevo-desde-cero"
    assert imp_data["entities"] == 2
    assert imp_data["links"] == 1

    # 4. Probar importación con JSON en el caso existente
    json_data = (
        '{"entities": [{"type": "maltego.EmailAddress", "value": "test@target.com", "confidence": 0.8}], "edges": []}'
    )
    r_imp_json = client.post(
        "/api/cases/import",
        files={"file": ("entidades.json", json_data.encode("utf-8"), "application/json")},
        data={"case_id": "caso-nuevo-desde-cero"},
    )
    assert r_imp_json.status_code == 200
    assert r_imp_json.json()["ok"] is True
    assert r_imp_json.json()["entities"] == 1

    # 5. Comprobar que el grafo del caso tiene ahora las entidades importadas
    r_graph = client.get("/api/cases/caso-nuevo-desde-cero/graph")
    assert r_graph.status_code == 200
    g_data = r_graph.json()
    assert g_data["ok"] is True
    assert len(g_data["nodes"]) == 3  # domain, ip, email
    assert len(g_data["links"]) == 1


def test_api_case_deletion_and_cleanup(tmp_path: Path) -> None:
    app = _create_test_app(tmp_path)
    client = TestClient(app)

    # 1. Crear un caso puntual para investigacion temporal
    r_create = client.post(
        "/api/cases",
        json={"case_id": "caso-temporal-para-borrar", "description": "Investigacion puntual sin relevancia"},
    )
    assert r_create.status_code == 200
    assert r_create.json()["ok"] is True

    # 2. Agregar entidades mediante importacion
    json_data = '{"entities": [{"type": "maltego.Domain", "value": "temp-target.org", "confidence": 0.9}], "edges": []}'
    r_imp = client.post(
        "/api/cases/import",
        files={"file": ("temp.json", json_data.encode("utf-8"), "application/json")},
        data={"case_id": "caso-temporal-para-borrar"},
    )
    assert r_imp.status_code == 200
    assert r_imp.json()["ok"] is True

    # 3. Comprobar que aparece en la lista de casos
    r_list = client.get("/api/cases")
    assert r_list.status_code == 200
    case_ids = [c["case_id"] for c in r_list.json()["cases"]]
    assert "caso-temporal-para-borrar" in case_ids

    # 4. Eliminar el caso mediante DELETE
    r_del = client.delete("/api/cases/caso-temporal-para-borrar")
    assert r_del.status_code == 200
    del_data = r_del.json()
    assert del_data["ok"] is True
    assert del_data["case_id"] == "caso-temporal-para-borrar"
    assert del_data["deleted_entities"] >= 1

    # 5. Comprobar que ya no existe en el sistema
    r_list_post = client.get("/api/cases")
    assert r_list_post.status_code == 200
    post_ids = [c["case_id"] for c in r_list_post.json()["cases"]]
    assert "caso-temporal-para-borrar" not in post_ids

    # 6. Intentar borrar un caso inexistente debe responder error 400
    r_del_nonexistent = client.delete("/api/cases/caso-inexistente-xyz")
    assert r_del_nonexistent.status_code == 400
    assert r_del_nonexistent.json()["ok"] is False


def test_api_cti_feeds_and_sources(tmp_path: Path) -> None:
    app = _create_test_app(tmp_path)
    client = TestClient(app)

    r = client.get("/api/cti-feeds")
    assert r.status_code == 200
    data = r.json()
    assert "active_count" in data
    assert "sources" in data
    assert data["active_count"] > 0
    assert len(data["sources"]) > 0
    s0 = data["sources"][0]
    assert "name" in s0
    assert "category" in s0
    assert "updated_at" in s0 or "updated_ts" in s0


def test_api_case_profiling(tmp_path: Path) -> None:
    app = _create_test_app(tmp_path)
    client = TestClient(app)

    # 1. Crear un caso de prueba con una persona objetivo
    import_payload = {
        "entities": [
            {
                "type": "maltego.Person",
                "value": "Carl Icahn",
                "properties": {"notes": "Líder de fondo activista con historial de OPA"},
            }
        ],
        "edges": [],
    }
    r_imp = client.post(
        "/api/cases/import",
        files={"file": ("target.json", json.dumps(import_payload).encode("utf-8"), "application/json")},
        data={"case_id": "caso-test-profiling"},
    )
    assert r_imp.status_code == 200
    assert r_imp.json()["ok"] is True

    # 2. Obtener el grafo del caso para conseguir el entity_id
    r_graph = client.get("/api/cases/caso-test-profiling/graph")
    assert r_graph.status_code == 200
    nodes = r_graph.json()["nodes"]
    assert len(nodes) >= 1
    target_node = nodes[0]
    eid = target_node["id"]

    # 3. Ejecutar el endpoint de perfilado POST /api/cases/{case_id}/profile
    r_prof = client.post(
        "/api/cases/caso-test-profiling/profile",
        json={
            "entity_id": eid,
            "typology": "activist_investor",
            "reason": "Auditoría pericial previa a OPA",
            "additional_corpus": "Declaraciones agresivas en prensa sobre venta de activos",
        },
    )
    assert r_prof.status_code == 200
    pdata = r_prof.json()
    assert pdata["ok"] is True
    profile = pdata["profile"]
    assert profile["typology"] == "investor"
    assert profile["archetype_label"]
    assert profile["risk_level"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
    assert len(profile["dimensions"]) >= 3
    assert isinstance(profile["anomalies"], list)
    assert len(profile["strategic_recommendations"]) >= 1
    assert pdata["emitted_count"] >= 1

    # 4. Consultar el historial de perfiles del caso GET /api/cases/{case_id}/profiles
    r_list = client.get("/api/cases/caso-test-profiling/profiles")
    assert r_list.status_code == 200
    list_data = r_list.json()
    assert list_data["ok"] is True
    assert list_data["count"] >= 1
    p0 = list_data["profiles"][0]
    assert p0["id"] == eid
    assert p0["typology"] == "investor"
    assert p0["archetype"] == profile["archetype_label"]


def test_dashboard_js_no_contiene_onclick_con_interpolaciones_en_pestanas_mantenidas() -> None:
    """Verifica estáticamente que todo el fichero usa data-* y delegación, excluyendo solo funciones retiradas en F7."""
    import re

    js_path = Path(__file__).resolve().parents[1] / "src" / "maltego_mcp" / "web" / "dashboard.js"
    assert js_path.exists()
    lines = js_path.read_text(encoding="utf-8").splitlines()

    removed_tabs_functions = {
        "renderForensicsVault",
        "renderMitreMatrix",
        "populateGeoNodesTable",
        "renderGoogleMapsModalContent",
        "renderWatchtower",
    }

    def get_enclosing_function(idx: int) -> str:
        for j in range(idx, -1, -1):
            line = lines[j].strip()
            if (
                line.startswith("function ")
                or line.startswith("async function ")
                or " = function" in line
                or " = async function" in line
                or (line.endswith("() {") and not line.startswith("if") and not line.startswith("for"))
            ):
                m = re.search(r"(?:function\s+([a-zA-Z0-9_]+)|([a-zA-Z0-9_]+)\s*=\s*(?:async\s+)?function)", line)
                if m:
                    return m.group(1) or m.group(2) or "unknown"
                return "unknown"
        return "global"

    violations: list[str] = []
    for i, line in enumerate(lines, 1):
        if "onclick=" in line and "${" in line:
            fn = get_enclosing_function(i - 1)
            if fn not in removed_tabs_functions:
                violations.append(f"Línea {i} (en {fn}): {line.strip()}")

    assert not violations, "Se encontraron onclick interpolados en pestañas mantenidas:\n" + "\n".join(violations)

    # 2. La bandeja de entrada y proveedores de correo deben usar escapeHtml en campos dinámicos
    content = "\n".join(lines)
    assert '${escapeHtml(m.from || "Desconocido")}' in content
    assert '${escapeHtml(m.subject || "(Sin asunto)")}' in content
    assert "${escapeHtml(err.message)}" in content
    assert "${escapeHtml(currentInbox.address)}" in content
    assert "${escapeHtml(p.name)}" in content
    assert "${escapeHtml(p.description)}" in content
    assert "${escapeHtml(tip)}" in content


def test_dashboard_js_syntax() -> None:
    """Verifica que dashboard.js no contenga errores de sintaxis (p. ej. bloques await huérfanos)."""
    import shutil
    import subprocess

    js_path = Path(__file__).resolve().parent.parent / "src" / "maltego_mcp" / "web" / "dashboard.js"
    assert js_path.exists()
    node = shutil.which("node")
    if node:
        proc = subprocess.run([node, "--check", str(js_path)], capture_output=True, text=True)
        assert proc.returncode == 0, f"Error de sintaxis detectado en dashboard.js:\n{proc.stderr}"


def test_panel_sin_manejadores_en_linea_y_acciones_declarativas_en_lista_blanca() -> None:
    """La CSP (script-src 'self') bloquea onclick/onchange en línea: el panel debe usar data-on-* y lista cerrada."""
    import re

    web = Path(__file__).resolve().parents[1] / "src" / "maltego_mcp" / "web"
    html = (web / "index.html").read_text(encoding="utf-8")
    js = (web / "dashboard.js").read_text(encoding="utf-8")

    # 1. Ningún manejador en línea: el navegador no los ejecuta y el control quedaría sin efecto.
    inline = re.compile(
        r"""\son(?:click|change|input|submit|keydown|keyup|mouseover|mouseout|focus|blur|load)\s*=\s*["']"""
    )
    assert not inline.findall(html), "index.html contiene manejadores en línea bloqueados por la CSP"
    assert not inline.findall(js), "dashboard.js genera manejadores en línea bloqueados por la CSP"

    # 2. Toda función invocada desde un data-on-* está en la lista cerrada y existe en dashboard.js.
    allow_block = re.search(r"const DECLARATIVE_ACTIONS = new Set\(\[(.*?)\]\);", js, re.S)
    assert allow_block, "No se encuentra DECLARATIVE_ACTIONS en dashboard.js"
    allowed = set(re.findall(r'"([A-Za-z_$][\w$]*)"', allow_block.group(1)))
    defined = set(re.findall(r"^(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(", js, re.M))
    assert allowed <= defined, f"Acciones en la lista blanca sin función definida: {sorted(allowed - defined)}"

    specials = {"event.stopPropagation()", "event.preventDefault()", "this.parentElement.remove()"}
    proxy_click = re.compile(r"^document\.getElementById\('[\w-]+'\)\.click\(\)$")
    arg_ok = re.compile(
        r"""^(?:'[^'\\]*'|"[^"\\]*"|-?\d+(?:\.\d+)?|true|false|null|this|this\.value|this\.checked|event)$"""
    )
    declared = re.findall(r'\sdata-on-(?:click|change|input|submit|keydown)="([^"]*)"', html + js)
    assert len(declared) >= 100
    for body in declared:
        assert "${" not in body, f"Acción declarativa con interpolación: {body}"
        for stmt in filter(None, (s.strip() for s in body.split(";"))):
            if stmt in specials or proxy_click.match(stmt):
                continue
            call = re.match(r"^(?:return\s+)?([A-Za-z_$][\w$]*)\((.*)\)$", stmt)
            assert call, f"Acción declarativa no admitida por el despachador: {stmt}"
            assert call.group(1) in allowed, f"Función fuera de la lista blanca: {call.group(1)}"
            raw_args = call.group(2).strip()
            if raw_args:
                for arg in (a.strip() for a in raw_args.split(",")):
                    assert arg_ok.match(arg), f"Argumento no admitido en '{stmt}': {arg}"
