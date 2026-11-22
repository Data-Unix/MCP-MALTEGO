"""Tests exhaustivos de anti-filtración de claves API y puerta de autenticación PBKDF2 del panel."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import httpx
import pytest
from starlette.testclient import TestClient

from maltego_mcp.accounts import (
    SocialAccount,
    generate_sockpuppet_persona,
    load_account_pool,
    save_account_to_toml,
    verify_account_connection,
)
from maltego_mcp.auth import (
    ADMIN_ROLES,
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
    hash_password_pbkdf2,
    verify_password_pbkdf2,
)
from maltego_mcp.config import Settings
from maltego_mcp.egress import (
    AuditLog,
    EgressPolicy,
    GuardedTransport,
    get_following,
    mask_url_secrets,
    redact_secrets,
)
from maltego_mcp.errors import EgressBlockedError
from maltego_mcp.server import build_service, create_server
from maltego_mcp.web_app import attach_dashboard_routes


def _build_auth_app(tmp_path: Path, password: str = "test-console-pass-2026"):
    pwd_hash = hash_password_pbkdf2(password, iterations=100_000)
    settings = Settings(
        data_file=tmp_path / "graph.json",
        home=tmp_path,
        dashboard_auth=True,
        dashboard_user="admin",
        dashboard_password_hash=pwd_hash,
        dashboard_session_ttl=3600,
    )
    server = create_server(settings)
    app = server.streamable_http_app(stateless_http=True, json_response=True)
    svc = getattr(server, "_service", None) or build_service(settings)
    svc.env = {
        "VIRUSTOTAL_API_KEY": "vt_live_super_secret_token_999999",
        "SHODAN_API_KEY": "shodan_live_super_secret_888888",
        "HUNTER_API_KEY": "hunter_live_super_secret_777777",
        "OTX_API_KEY": "otx_live_super_secret_666666",
        "URLSCAN_API_KEY": "urlscan_live_super_secret_555555",
        "URLHAUS_API_KEY": "urlhaus_live_super_secret_444444",
        "GITHUB_TOKEN": "ghp_liveSuperSecretToken3333333333",
        "TOR_SOCKS_PROXY": "socks5h://opuser:opsecretpass123@127.0.0.1:9050",
    }
    attach_dashboard_routes(app, svc, settings)
    return app, svc


def test_pbkdf2_hash_and_constant_time_verification() -> None:
    encoded = hash_password_pbkdf2("clave-operador-segura", iterations=100_000)
    assert encoded.startswith("pbkdf2_sha256$100000$")
    assert verify_password_pbkdf2("clave-operador-segura", encoded) is True
    assert verify_password_pbkdf2("clave-incorrecta", encoded) is False
    assert verify_password_pbkdf2("clave-operador-segura", "formato-invalido") is False


def test_dashboard_auth_gate_blocks_all_apis_and_sse_before_login(tmp_path: Path) -> None:
    app, _ = _build_auth_app(tmp_path)
    client = TestClient(app)

    # 1. HTML y estáticos sirven la puerta de acceso (#auth-gate) con CSP y sin filtrar datos
    r_html = client.get("/")
    assert r_html.status_code == 200
    assert 'id="auth-gate"' in r_html.text
    assert 'data-auth="checking"' in r_html.text

    # 2. Estado inicial de sesión: no autenticado
    r_sess = client.get("/api/auth/session")
    assert r_sess.status_code == 200
    assert r_sess.json()["authenticated"] is False
    assert r_sess.json()["auth_required"] is True
    assert "no-store" in r_sess.headers.get("cache-control", "")

    # 3. Ningún endpoint /api/* ni /api/events responde sin sesión activa
    protected_gets = [
        "/api/status",
        "/api/accounts",
        "/api/providers",
        "/api/transforms",
        "/api/cases",
        "/api/cti-feeds",
        "/api/egress/audit",
        "/api/inbox/providers",
        "/api/events",
    ]
    for path in protected_gets:
        resp = client.get(path)
        assert resp.status_code == 401, f"{path} debería devolver 401 sin sesión"
        assert "no-store" in resp.headers.get("cache-control", "")

    assert client.post("/api/cases", json={"case_id": "unauth-case"}).status_code == 401

    # 4. Protección DNS-rebinding actúa ANTES de autenticación (403, nunca 401)
    r_rebind = client.get("/api/status", headers={"Host": "evil.attacker.example"})
    assert r_rebind.status_code == 403


def test_dashboard_login_roles_csrf_logout_and_zero_key_leak(tmp_path: Path) -> None:
    secret_pwd = "test-console-pass-2026"
    app, svc = _build_auth_app(tmp_path, password=secret_pwd)
    client = TestClient(app)

    # 1. Login exitoso de admin con todos los roles
    r_login = client.post("/api/auth/login", json={"username": "admin", "password": secret_pwd})
    assert r_login.status_code == 200
    body = r_login.json()
    assert body["ok"] is True
    assert body["authenticated"] is True
    assert body["username"] == "admin"
    assert tuple(body["roles"]) == ADMIN_ROLES
    csrf_token = body["csrf_token"]
    assert len(csrf_token) >= 32

    set_cookie = r_login.headers.get("set-cookie", "").lower()
    assert SESSION_COOKIE_NAME in set_cookie
    assert "httponly" in set_cookie
    assert "samesite=strict" in set_cookie

    # 2. Mutación sin X-CSRF-Token es rechazada con 403
    r_no_csrf = client.post("/api/cases", json={"case_id": "csrf-blocked"})
    assert r_no_csrf.status_code == 403

    # 3. Mutación con Origin malicioso es rechazada con 403 incluso con token CSRF
    r_bad_origin = client.post(
        "/api/cases",
        json={"case_id": "origin-blocked"},
        headers={CSRF_HEADER_NAME: csrf_token, "Origin": "https://evil.example"},
    )
    assert r_bad_origin.status_code == 403

    # 4. Mutación legítima con X-CSRF-Token y mismo origen loopback funciona
    r_ok_case = client.post(
        "/api/cases",
        json={"case_id": "secure-case-01", "description": "Caso tras autenticación"},
        headers={CSRF_HEADER_NAME: csrf_token, "Origin": "http://127.0.0.1:8000"},
    )
    assert r_ok_case.status_code == 200
    assert r_ok_case.json()["ok"] is True

    # 5. Escaneo anti-fuga sobre todas las respuestas autenticadas: NINGÚN secreto de svc.env ni contraseña aparece
    forbidden_values = [*svc.env.values(), secret_pwd, "opsecretpass123"]
    for ep in ("/api/status", "/api/providers", "/api/accounts", "/api/cases", "/api/egress/audit"):
        r_ep = client.get(ep)
        assert r_ep.status_code == 200
        assert "no-store" in r_ep.headers.get("cache-control", "")
        raw_text = r_ep.text
        for secret_val in forbidden_values:
            assert secret_val not in raw_text, f"Fuga detectada en {ep}"

    # Verificar que tor_socks_proxy en /api/status enmascara user:pass@
    status_json = client.get("/api/status").json()
    assert "***:***@" in status_json["tor_socks_proxy"]
    assert "opsecretpass123" not in status_json["tor_socks_proxy"]

    # 6. Cierre de sesión revoca inmediatamente la cookie en servidor
    r_logout = client.post("/api/auth/logout", headers={CSRF_HEADER_NAME: csrf_token})
    assert r_logout.status_code == 200
    assert client.get("/api/status").status_code == 401


def test_dashboard_login_rate_limiting_429(tmp_path: Path) -> None:
    app, _ = _build_auth_app(tmp_path, password="correct-password-999")
    client = TestClient(app)

    for expected_rem in (4, 3, 2, 1, 0):
        r_fail = client.post("/api/auth/login", json={"username": "admin", "password": "wrong-password"})
        assert r_fail.status_code == 401
        assert r_fail.json()["remaining_attempts"] == expected_rem

    # El 6º intento dentro de la ventana devuelve 429 + Retry-After
    r_locked = client.post("/api/auth/login", json={"username": "admin", "password": "correct-password-999"})
    assert r_locked.status_code == 429
    assert int(r_locked.headers.get("retry-after", "0")) >= 1


@pytest.mark.asyncio
async def test_egress_masks_query_keys_userinfo_and_cross_host_redirect_headers(tmp_path: Path) -> None:
    # 1. mask_url_secrets cubre userinfo y query keys sensibles
    masked = mask_url_secrets("https://user:my_secret_pw@api.shodan.io/shodan/host/1.1.1.1?key=SECRET123&minify=true")
    assert "my_secret_pw" not in masked
    assert "SECRET123" not in masked
    assert "***:***@api.shodan.io" in masked
    assert "key=***" in masked
    assert "minify=true" in masked

    # 2. EgressBlockedError y AuditLog nunca filtran ?key=... cuando se bloquea un host
    audit = AuditLog(tmp_path / "audit.log")
    policy = EgressPolicy(allow_active=False)

    def _dummy_handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    transport = GuardedTransport(httpx.MockTransport(_dummy_handler), policy=policy, audit_log=audit)
    async with httpx.AsyncClient(transport=transport) as cl:
        with pytest.raises(EgressBlockedError) as exc_info:
            await cl.get("https://evil.unlisted.host/v1/test?api_key=ULTRA_SECRET_KEY_777")
        assert "ULTRA_SECRET_KEY_777" not in str(exc_info.value)

    audit_content = (tmp_path / "audit.log").read_text(encoding="utf-8")
    assert "ULTRA_SECRET_KEY_777" not in audit_content

    # 3. get_following elimina cabeceras de autenticación (X-API-KEY, Authorization) al saltar de host
    seen_requests: list[httpx.Request] = []

    def _redirect_handler(req: httpx.Request) -> httpx.Response:
        seen_requests.append(req)
        if req.url.host == "api.hunter.io":
            return httpx.Response(302, headers={"Location": "https://crt.sh/?q=example.com"})
        return httpx.Response(200, json=[])

    r_transport = GuardedTransport(httpx.MockTransport(_redirect_handler), policy=policy, audit_log=audit)
    async with httpx.AsyncClient(transport=r_transport) as cl:
        resp = await get_following(
            cl,
            "https://api.hunter.io/v2/domain-search",
            params={"domain": "example.com", "api_key": "SHOULD_NOT_CARRY"},
            headers={"X-API-KEY": "HUNTER_SECRET_HEADER_999", "Authorization": "Bearer TOP_SECRET"},
        )
        assert resp.status_code == 200

    assert len(seen_requests) == 2
    hop2 = seen_requests[1]
    assert hop2.url.host == "crt.sh"
    assert "x-api-key" not in {k.lower() for k in hop2.headers}
    assert "authorization" not in {k.lower() for k in hop2.headers}
    assert "SHOULD_NOT_CARRY" not in str(hop2.url)


@pytest.mark.asyncio
async def test_accounts_secret_status_toml_escaping_and_icd203_xss_hardening(tmp_path: Path) -> None:
    # 1. secret_status no revela ni siquiera los 3 primeros caracteres del token
    acc = SocialAccount(
        id="sp-gh-escape",
        platform="github",
        username='user"with\nnewline',
        token="ghp_ABCDEF1234567890SECRET",
        proxy="socks5h://u:proxy_secret_pw@127.0.0.1:9050",
    )
    status = acc.secret_status({})
    assert "ghp" not in status
    assert status == "configurada (****)"

    # 2. Escritura TOML escapa comillas y saltos de línea sin permitir inyección de claves TOML
    save_account_to_toml(tmp_path, acc)
    parsed = tomllib.loads((tmp_path / "accounts.toml").read_text(encoding="utf-8"))
    assert len(parsed["accounts"]) == 1
    assert parsed["accounts"][0]["username"] == 'user"with\nnewline'

    pool = load_account_pool(tmp_path, {})
    pub = json.dumps(pool.summary())
    assert "ghp_" not in pub
    assert "proxy_secret_pw" not in pub

    # 3. verify_account_connection enmascara credenciales de proxy Tor
    tor_acc = SocialAccount(
        id="sp-tor",
        platform="onion",
        username="anon",
        target_site="duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
        proxy="socks5h://toruser:tor_super_secret@127.0.0.1:1",
    )
    rep = await verify_account_connection(tor_acc, {"MALTEGO_MCP_HOME": str(tmp_path)}, timeout=0.2)
    assert "tor_super_secret" not in rep.message

    # 4. TOTP sin semilla explícita usa CSPRNG (dos llamadas producen secretos distintos)
    p_a = generate_sockpuppet_persona(role="journalist", region="EU", target_site="example.org")
    p_b = generate_sockpuppet_persona(role="journalist", region="EU", target_site="example.org")
    assert p_a.totp_secret_base32 != p_b.totp_secret_base32

    # 5. redact_secrets limpia valores sensibles del entorno y URLs
    scrubbed = redact_secrets(
        "Fallo en https://api.shodan.io/host/1.1.1.1?key=SHODAN999 con token ghp_MyPatToken12345",
        {"GITHUB_TOKEN": "ghp_MyPatToken12345"},
    )
    assert "SHODAN999" not in scrubbed
    assert "ghp_MyPatToken12345" not in scrubbed

    # 6. Informe ICD 203 escapa XSS en HTML y Fase 6 redacta secret_sample en disco
    _app, svc = _build_auth_app(tmp_path)
    await svc.save_case_recon(
        "xss-case",
        {
            "p0_framing": {"target": "<img src=x onerror=alert(1)>", "question": "<script>alert(2)</script>"},
            "hypotheses": [
                {
                    "id": "H1",
                    "statement": "<svg onload=alert(3)>",
                    "what_would_refute_it": "<b>ref</b>",
                    "probability": "probable",
                    "confidence": "media",
                }
            ],
        },
    )
    await svc.add_fase6_breach(
        "xss-case",
        {
            "identity": "ops@example.com",
            "breach_name": "Dump",
            "breach_date": "2025-01-01",
            "secret_sample": "RAW_PLAINTEXT_PASSWORD_DO_NOT_STORE",
        },
    )
    recon_on_disk = (tmp_path / "cases" / "xss-case_recon.json").read_text(encoding="utf-8")
    assert "RAW_PLAINTEXT_PASSWORD_DO_NOT_STORE" not in recon_on_disk
    assert "[REDACTED · sha256:" in recon_on_disk

    icd = await svc.generate_icd203_report("xss-case")
    html_out = icd["report_html"]
    assert "<script>alert(2)</script>" not in html_out
    assert "<img src=x onerror=alert(1)>" not in html_out
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in html_out
    assert "Content-Security-Policy" in html_out


def test_dashboard_handlers_redactan_secretos_en_errores(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifica que ningún endpoint del dashboard filtre secretos de entorno en mensajes de error (S7/B15)."""
    app, svc = _build_auth_app(tmp_path)
    client = TestClient(app)

    r_login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "test-console-pass-2026"},
    )
    assert r_login.status_code == 200
    csrf = r_login.json()["csrf_token"]

    secret_val = svc.env["VIRUSTOTAL_API_KEY"]
    assert secret_val == "vt_live_super_secret_token_999999"

    async def mock_fail_perimeter(cid: str, asset: str) -> list[str]:
        raise RuntimeError(f"Fallo critico con clave secreta {secret_val}")

    monkeypatch.setattr(svc, "add_custom_perimeter_asset", mock_fail_perimeter)

    resp = client.post(
        "/api/cases/caso1/perimeter",
        json={"action": "add", "asset": "test.com"},
        headers={"x-csrf-token": csrf},
    )
    assert resp.status_code == 400
    assert secret_val not in resp.text
    assert "[REDACTED" in resp.text
