"""Tests exhaustivos para la aplicación web y suite REST del Dashboard MCP Maltego."""

from __future__ import annotations

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

    r_dash = client.get("/dashboard")
    assert r_dash.status_code == 200
    assert "Bóveda & Sock Puppets" in r_dash.text

    # 2. Ficheros estáticos
    r_css = client.get("/dashboard.css")
    assert r_css.status_code == 200
    assert "--bg-base" in r_css.text

    r_js = client.get("/dashboard.js")
    assert r_js.status_code == 200
    assert "initBackgroundCanvas" in r_js.text

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

    # 2. Crear cuenta nueva
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

    # 3. Listar y verificar enmascaramiento estricto
    r_list = client.get("/api/accounts")
    assert r_list.status_code == 200
    accounts = r_list.json()["accounts"]
    found = next((a for a in accounts if a["id"] == "test-bot-01"), None)
    assert found is not None
    assert found["rate_limit_rpm"] == 45
    # El secreto en texto plano NUNCA debe viajar al frontend
    assert "test_token_secret_1234567890" not in str(r_list.text)
    assert "test_token_secret_1234567890" not in str(found["status_text"])

    # 4. Eliminar cuenta
    r_del = client.delete("/api/accounts/test-bot-01")
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
