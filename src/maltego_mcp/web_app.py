"""Módulo de aplicación web y endpoints REST para el Dashboard de MCP Maltego.

Proporciona:
- Servicio de la SPA local (HTML5 + CSS Impeccable + JS con OffscreenCanvas en Web Worker).
- Endpoints REST para gestión de la bóveda de cuentas (~/.maltego-mcp/accounts.toml).
- Verificación en vivo de conectividad (GitHub, Reddit, Bluesky, Tor/Dark Web, APIs).
- Generación y guardado de kits operativos de Sock Puppets con OPSEC.
- Playground de ejecución directa de transformadas y machines.
- Transmisión de telemetría y eventos en tiempo real vía Server-Sent Events (SSE).
- Aislamiento de seguridad restringido a loopback (127.0.0.1 / localhost).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import secrets
import socket
import time
import urllib.parse
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse

from maltego_mcp import __version__
from maltego_mcp.accounts import (
    PLATFORM_ENV_VARS,
    SocialAccount,
    ensure_accounts_template,
    generate_sockpuppet_persona,
    load_account_pool,
    remove_account_from_toml,
    save_account_to_toml,
    save_persona_to_accounts_toml,
    verify_account_connection,
)
from maltego_mcp.analysis import compute_entity_validity
from maltego_mcp.auth import CSRF_HEADER_NAME, SESSION_COOKIE_NAME, DashboardAuthManager
from maltego_mcp.config import Settings
from maltego_mcp.cti_feeds import _connect, ensure_seed_cti_db, sync_deepdark_cti
from maltego_mcp.egress import create_egress_client, mask_url_secrets, redact_secrets
from maltego_mcp.inbox import PROVIDER_CATALOG, MailTmClient
from maltego_mcp.service import IMPORT_SUFFIXES, OsintService

logger = logging.getLogger("maltego_mcp.web")

WEB_DIR = Path(__file__).resolve().parent / "web"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "testserver"})

_event_subscribers: set[asyncio.Queue[dict[str, Any]]] = set()


def broadcast_event(data: dict[str, Any]) -> None:
    """Envía un evento a todos los clientes SSE conectados."""
    dead: list[asyncio.Queue[dict[str, Any]]] = []
    for q in _event_subscribers:
        try:
            q.put_nowait(data)
        except (asyncio.QueueFull, Exception):
            dead.append(q)
    for q in dead:
        _event_subscribers.discard(q)


_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_PUBLIC_AUTH_API_PATHS = frozenset({"/api/auth/session", "/api/auth/login"})


def _extract_hostname(raw_host: str) -> str:
    val = (raw_host or "").strip().lower()
    if not val:
        return ""
    if val.startswith("["):
        end_bracket = val.find("]")
        return val[1:end_bracket] if end_bracket > 1 else ""
    return val.split(":", 1)[0]


def _check_host(request: Request) -> bool:
    host = _extract_hostname(request.headers.get("host", ""))
    return bool(host) and host in LOOPBACK_HOSTS


def _check_origin_and_fetch_site(request: Request) -> bool:
    sec_site = request.headers.get("sec-fetch-site", "").strip().lower()
    if sec_site == "cross-site":
        return False
    origin = request.headers.get("origin", "").strip()
    if origin:
        if origin.lower() == "null":
            return False
        parsed = urllib.parse.urlparse(origin)
        origin_host = (parsed.hostname or "").strip().lower()
        if not origin_host or origin_host not in LOOPBACK_HOSTS:
            return False
    return True


class SecurityHeadersMiddleware:
    """Añade cabeceras estrictas de Content Security Policy, anti-caché y privacidad a todas las respuestas."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path") or "")
        is_api = path.startswith("/api/")

        async def send_wrapper(message: Any) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                existing_keys = {k.lower() for k, _ in headers}
                headers.extend(
                    [
                        (
                            b"content-security-policy",
                            (
                                b"default-src 'none'; "
                                b"script-src 'self'; "
                                b"style-src 'self' 'unsafe-inline'; "
                                b"img-src 'self' data:; "
                                b"connect-src 'self'; "
                                b"frame-src 'none'; "
                                b"form-action 'none'; "
                                b"base-uri 'none'"
                            ),
                        ),
                        (b"x-dns-prefetch-control", b"off"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                    ]
                )
                if is_api and b"cache-control" not in existing_keys:
                    headers.append((b"cache-control", b"no-store, no-cache, must-revalidate, max-age=0"))
                    headers.append((b"pragma", b"no-cache"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


class DashboardAuthMiddleware:
    """Puerta de seguridad de host loopback, anti-CSRF y sesión autenticada para `/api/*`."""

    def __init__(self, app: Any, auth_manager: DashboardAuthManager) -> None:
        self.app = app
        self.auth = auth_manager

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        path = request.url.path
        method = request.method.upper()

        # 1. Protección DNS-Rebinding / Host loopback (siempre antes de autenticación -> HTTP 403)
        if path != "/mcp" and not _check_host(request):
            resp = (
                JSONResponse({"error": "forbidden"}, status_code=403)
                if path.startswith("/api/")
                else Response("Acceso denegado: solo permitido desde loopback", status_code=403)
            )
            await resp(scope, receive, send)
            return

        if not path.startswith("/api/"):
            await self.app(scope, receive, send)
            return

        # 2. Protección anti-CSRF por Origin / Sec-Fetch-Site en métodos mutadores
        if method in _MUTATING_METHODS and not _check_origin_and_fetch_site(request):
            resp = JSONResponse({"ok": False, "error": "Solicitud cross-site bloqueada (CSRF)."}, status_code=403)
            await resp(scope, receive, send)
            return

        # 3. Verificación de sesión y token CSRF cuando dashboard_auth está activo
        if self.auth.enabled and path not in _PUBLIC_AUTH_API_PATHS:
            cookie_val = request.cookies.get(SESSION_COOKIE_NAME, "")
            session = self.auth.get_valid_session(cookie_val)
            if session is None:
                resp = JSONResponse(
                    {"ok": False, "authenticated": False, "error": "Sesión requerida. Inicia sesión en el panel."},
                    status_code=401,
                )
                await resp(scope, receive, send)
                return

            scope.setdefault("state", {})["auth_session"] = session
            if method in _MUTATING_METHODS:
                csrf_token = request.headers.get(CSRF_HEADER_NAME, "")
                if not self.auth.verify_csrf(session, csrf_token):
                    resp = JSONResponse(
                        {"ok": False, "error": "Token CSRF inválido o ausente en X-CSRF-Token."},
                        status_code=403,
                    )
                    await resp(scope, receive, send)
                    return

        await self.app(scope, receive, send)


def _probe_tcp_sync(host: str, port: int, timeout: float = 0.15) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _get_cti_summary_sync(home: Path) -> dict[str, int]:
    try:
        db_path = ensure_seed_cti_db(home)
        with _connect(db_path) as conn:
            active_c = int(conn.execute("SELECT COUNT(*) FROM cti_sources").fetchone()[0])
            purged_c = int(conn.execute("SELECT COALESCE(SUM(purged_offline), 0) FROM cti_sync_meta").fetchone()[0])
            return {"active_sources": active_c, "purged_sources": purged_c}
    except Exception:
        return {"active_sources": 0, "purged_sources": 0}


def attach_dashboard_routes(
    app: Starlette,
    service: OsintService,
    settings: Settings,
    ring_control: bool | None = None,
) -> Starlette:
    """Registra las rutas de la interfaz web y APIs REST en la aplicación Starlette.

    ``ring_control``: permite controlar la VPN Mullvad desde el panel (por defecto, solo con autenticación activa;
    ``server.main`` lo desactiva fuera de loopback o con --allow-remote-unauthenticated)."""
    auth_manager = DashboardAuthManager(settings)
    app.state.auth_manager = auth_manager
    app.add_middleware(DashboardAuthMiddleware, auth_manager=auth_manager)
    app.add_middleware(SecurityHeadersMiddleware)

    def _read_active_case_id() -> str:
        for fname in ("active_case", "current_case"):
            f = settings.home / fname
            if f.is_file():
                with contextlib.suppress(Exception):
                    val = f.read_text(encoding="utf-8").strip()
                    if val:
                        return val
        return ""

    def _on_in_process_event(ev: dict[str, Any]) -> None:
        seq = int(ev.get("seq_ns") or 0)
        if seq > _watcher_state["last_seq_ns"]:
            _watcher_state["last_seq_ns"] = seq
        broadcast_event(ev)

    _watcher_state: dict[str, Any] = {
        "last_seq_ns": 0,
        "graph_mtime_ns": 0,
        "recon_mtimes": {},
    }
    ev_file_init = settings.home / "events.jsonl"
    if ev_file_init.is_file():
        with contextlib.suppress(Exception):
            for raw_ln in ev_file_init.read_text(encoding="utf-8", errors="ignore").splitlines()[-50:]:
                obj = json.loads(raw_ln)
                s_ns = int(obj.get("seq_ns") or 0)
                if s_ns > _watcher_state["last_seq_ns"]:
                    _watcher_state["last_seq_ns"] = s_ns
    g_file_init = settings.data_file or (settings.home / "graph.json")
    if g_file_init.is_file():
        with contextlib.suppress(Exception):
            _watcher_state["graph_mtime_ns"] = g_file_init.stat().st_mtime_ns

    service.add_event_listener(_on_in_process_event)

    def _poll_disk_events_sync() -> list[dict[str, Any]]:
        """Detecta eventos y cambios en disco emitidos por procesos MCP externos (p. ej. agente VS Code por stdio)."""
        emitted: list[dict[str, Any]] = []
        ev_path = settings.home / "events.jsonl"
        my_pid = os.getpid()
        if ev_path.is_file():
            with contextlib.suppress(Exception):
                lines = ev_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                for ln in lines[-120:]:
                    if not ln.strip():
                        continue
                    with contextlib.suppress(Exception):
                        ev = json.loads(ln)
                        seq_ns = int(ev.get("seq_ns") or 0)
                        if seq_ns > _watcher_state["last_seq_ns"]:
                            _watcher_state["last_seq_ns"] = seq_ns
                            if int(ev.get("pid") or 0) != my_pid:
                                emitted.append(ev)
                                broadcast_event(ev)

        # Vigilar mtime de graph.json y cases/*_recon.json por si un proceso externo escribió sin events.jsonl
        g_path = settings.data_file or (settings.home / "graph.json")
        if g_path.is_file():
            with contextlib.suppress(Exception):
                g_mtime = g_path.stat().st_mtime_ns
                if g_mtime > _watcher_state["graph_mtime_ns"]:
                    _watcher_state["graph_mtime_ns"] = g_mtime
                    active_cid = _read_active_case_id()
                    if not any(e.get("type") in ("graph_updated", "step", "case_created") for e in emitted):
                        ev_g = {"type": "graph_updated", "case_id": active_cid, "ts": time.time()}
                        emitted.append(ev_g)
                        broadcast_event(ev_g)

        cases_dir = settings.home / "cases"
        if cases_dir.is_dir():
            recon_mtimes: dict[str, int] = _watcher_state["recon_mtimes"]
            with contextlib.suppress(Exception):
                for rf in cases_dir.glob("*_recon.json"):
                    rmtime = rf.stat().st_mtime_ns
                    prev = recon_mtimes.get(rf.name, 0)
                    if rmtime > prev:
                        recon_mtimes[rf.name] = rmtime
                        if prev > 0 and not any(e.get("type") == "recon_updated" for e in emitted):
                            cid_r = rf.name[: -len("_recon.json")]
                            ev_r = {"type": "recon_updated", "case_id": cid_r, "ts": time.time()}
                            emitted.append(ev_r)
                            broadcast_event(ev_r)
        return emitted

    def _safe_err(exc: Exception) -> str:
        return redact_secrets(str(exc), service.env)

    # Asegurar plantillas y bases iniciales de forma desatendida y tolerante a fallos
    try:
        ensure_accounts_template(settings.home)
        ensure_seed_cti_db(settings.home)
    except Exception as _e:
        logger.debug("Inicialización previa silenciosa: %s", _e)

    _NO_CACHE_HEADERS = {
        "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
    }

    async def root_view(request: Request) -> Response:
        if not _check_host(request):
            return Response("Acceso denegado: solo permitido desde loopback", status_code=403)
        html_file = WEB_DIR / "index.html"
        if not html_file.is_file():
            return Response("Fichero index.html no encontrado en src/maltego_mcp/web", status_code=404)
        return HTMLResponse(html_file.read_text(encoding="utf-8"), headers=_NO_CACHE_HEADERS)

    async def static_css(request: Request) -> Response:
        f = WEB_DIR / "dashboard.css"
        if not f.is_file():
            return Response("/* no css */", media_type="text/css")
        return Response(f.read_text(encoding="utf-8"), media_type="text/css", headers=_NO_CACHE_HEADERS)

    async def static_js(request: Request) -> Response:
        f = WEB_DIR / "dashboard.js"
        if not f.is_file():
            return Response("// no js", media_type="application/javascript")
        return Response(f.read_text(encoding="utf-8"), media_type="application/javascript", headers=_NO_CACHE_HEADERS)

    async def static_ring_js(request: Request) -> Response:
        f = WEB_DIR / "egress-ring.js"
        if not f.is_file():
            return Response("// no ring", media_type="application/javascript")
        return Response(f.read_text(encoding="utf-8"), media_type="application/javascript", headers=_NO_CACHE_HEADERS)

    async def static_worker_js(request: Request) -> Response:
        f = WEB_DIR / "bg-worker.js"
        if not f.is_file():
            return Response("// no worker", media_type="application/javascript")
        return Response(f.read_text(encoding="utf-8"), media_type="application/javascript", headers=_NO_CACHE_HEADERS)

    async def static_favicon(request: Request) -> Response:
        f = WEB_DIR / "favicon.ico"
        if f.is_file():
            return FileResponse(f, media_type="image/x-icon")
        return Response(status_code=404)

    async def static_favicon_png(request: Request) -> Response:
        f = WEB_DIR / "favicon.png"
        if f.is_file():
            return FileResponse(f, media_type="image/png")
        return Response(status_code=404)

    async def static_favicon_32(request: Request) -> Response:
        f = WEB_DIR / "favicon-32x32.png"
        if f.is_file():
            return FileResponse(f, media_type="image/png")
        return Response(status_code=404)

    async def static_apple_touch_icon(request: Request) -> Response:
        f = WEB_DIR / "apple-touch-icon.png"
        if f.is_file():
            return FileResponse(f, media_type="image/png")
        return Response(status_code=404)

    async def static_logo(request: Request) -> Response:
        f = WEB_DIR / "logo.png"
        if f.is_file():
            return FileResponse(f, media_type="image/png")
        return Response(status_code=404)

    async def api_auth_session(request: Request) -> JSONResponse:
        if not auth_manager.enabled:
            return JSONResponse(
                {
                    "ok": True,
                    "authenticated": True,
                    "auth_required": False,
                    "username": auth_manager.username,
                    "roles": list(auth_manager.roles),
                    "csrf_token": "",
                    "kdf": "PBKDF2-HMAC-SHA256 (600.000 iter.)",
                }
            )
        cookie_val = request.cookies.get(SESSION_COOKIE_NAME, "")
        sess = auth_manager.get_valid_session(cookie_val)
        if sess is not None:
            return JSONResponse({"ok": True, **sess.to_public_dict()})
        resp = JSONResponse(
            {
                "ok": True,
                "authenticated": False,
                "auth_required": True,
                "kdf": "PBKDF2-HMAC-SHA256 (600.000 iter.)",
                "session_ttl": auth_manager.session_ttl,
            }
        )
        if cookie_val:
            resp.delete_cookie(key=SESSION_COOKIE_NAME, path="/", httponly=True, samesite="strict")
        return resp

    async def api_auth_login(request: Request) -> JSONResponse:
        try:
            raw = await request.body()
            if len(raw) > 4096:
                return JSONResponse({"ok": False, "error": "Carga de solicitud excesiva."}, status_code=400)
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            return JSONResponse({"ok": False, "error": "JSON de credenciales inválido."}, status_code=400)

        if not isinstance(body, dict):
            return JSONResponse({"ok": False, "error": "Formato inválido."}, status_code=400)

        username = str(body.get("username") or "").strip()
        password = str(body.get("password") or "")
        client_ip = request.client.host if request.client else "127.0.0.1"

        result = await auth_manager.authenticate(username, password, client_ip=client_ip)
        if not result.ok or result.session is None:
            extra_headers = {"Retry-After": str(result.retry_after)} if result.status_code == 429 else {}
            return JSONResponse(
                {
                    "ok": False,
                    "authenticated": False,
                    "error": result.error,
                    "remaining_attempts": result.remaining_attempts,
                    "retry_after": result.retry_after,
                },
                status_code=result.status_code,
                headers=extra_headers,
            )

        resp = JSONResponse({"ok": True, **result.session.to_public_dict()})
        resp.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=result.session.session_id,
            max_age=auth_manager.session_ttl,
            path="/",
            httponly=True,
            samesite="strict",
            secure=(request.url.scheme == "https"),
        )
        return resp

    async def api_auth_logout(request: Request) -> JSONResponse:
        cookie_val = request.cookies.get(SESSION_COOKIE_NAME, "")
        revoked = auth_manager.revoke_session(cookie_val)
        resp = JSONResponse({"ok": True, "authenticated": False, "revoked": revoked})
        resp.delete_cookie(key=SESSION_COOKIE_NAME, path="/", httponly=True, samesite="strict")
        return resp

    async def api_status(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        pool = load_account_pool(settings.home, service.env)
        tor_proxy = pool.env.get("TOR_SOCKS_PROXY", "socks5h://127.0.0.1:9050")
        tor_active = False
        target_host = "127.0.0.1"
        target_port = 9050
        try:
            cleaned = tor_proxy.split("://")[-1] if "://" in tor_proxy else tor_proxy
            host_port = cleaned.split("/")[0]
            if ":" in host_port:
                h_str, p_str = host_port.rsplit(":", 1)
                target_host = h_str.strip() or "127.0.0.1"
                target_port = int(p_str)
        except Exception:
            target_host = "127.0.0.1"
            target_port = 9050

        tor_active = await asyncio.to_thread(_probe_tcp_sync, target_host, target_port, 0.15)
        if not tor_active and target_host in ("127.0.0.1", "localhost") and target_port == 9050:
            tor_active = await asyncio.to_thread(_probe_tcp_sync, "127.0.0.1", 9150, 0.15)

        cti_summary = await asyncio.to_thread(_get_cti_summary_sync, settings.home)

        return JSONResponse(
            {
                "status": "online",
                "version": __version__,
                "transport": "http",
                "host": request.url.hostname or "127.0.0.1",
                "port": request.url.port or 8000,
                "home_dir": str(settings.home),
                "tor_socks_proxy": mask_url_secrets(tor_proxy),
                "tor_active": tor_active,
                "accounts_summary": pool.summary(),
                "cti_summary": cti_summary,
                "transforms_count": len(service.catalog.transforms),
                "machines_count": len(service.catalog.machines.machines),
                "mode": "passive" if service.is_passive_mode else "active",
                "is_passive": service.is_passive_mode,
            }
        )

    async def api_get_accounts(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        pool = load_account_pool(settings.home, service.env)
        accounts_data = [
            {
                "id": acc.id,
                "platform": acc.platform,
                "category": acc.category,
                "username": acc.username,
                "handle": acc.handle,
                "target_site": acc.target_site,
                "site": acc.site,
                "rate_limit_rpm": acc.rate_limit_rpm,
                "enabled": acc.enabled,
                "cooldown_until": acc.cooldown_until,
                "proxy": mask_url_secrets(acc.proxy) if acc.proxy else "",
                "user_agent": acc.user_agent,
                "status_text": acc.secret_status(service.env),
                "has_token": bool(acc.token or acc.token_env),
                "has_cookie": bool(acc.cookie),
            }
            for acc in pool.accounts
        ]
        return JSONResponse({"accounts": accounts_data})

    async def api_save_account(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        try:
            body = await request.json()
            plat = str(body.get("platform") or "generic").strip().lower()[:40]
            cat = str(body.get("category") or "").strip().lower()[:40]
            acc_id = str(body.get("id") or f"sp-{plat}-{int(time.time())}").strip()[:80]
            account = SocialAccount(
                id=acc_id,
                platform=plat,
                category=cat,
                username=str(body.get("username") or "").strip()[:80],
                handle=str(body.get("handle") or body.get("username") or "").strip()[:80],
                token=str(body.get("token") or "").strip(),
                cookie=str(body.get("cookie") or "").strip(),
                token_env=str(body.get("token_env") or "").strip()[:80],
                target_site=str(body.get("target_site") or "").strip()[:200],
                proxy=str(body.get("proxy") or "").strip()[:200],
                user_agent=str(body.get("user_agent") or "").strip()[:240],
                rate_limit_rpm=max(1, min(600, int(body.get("rate_limit_rpm", 30)))),
                enabled=bool(body.get("enabled", True)),
            )
            save_account_to_toml(settings.home, account)
            broadcast_event({"type": "accounts_updated"})
            return JSONResponse({"ok": True, "account": {"id": account.id, "platform": account.platform}})
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_delete_account(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        acc_id = request.path_params.get("account_id", "")
        ok = remove_account_from_toml(settings.home, acc_id)
        broadcast_event({"type": "accounts_updated"})
        return JSONResponse({"ok": ok})

    async def api_verify_account(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        try:
            body = await request.json()
            acc_id = str(body.get("account_id") or "").strip()
            pool = load_account_pool(settings.home, service.env)
            account = next((a for a in pool.accounts if a.id == acc_id), None)
            if not account:
                account = SocialAccount(
                    id="temp-check",
                    platform=str(body.get("platform") or "generic").strip().lower(),
                    username=str(body.get("username") or ""),
                    token=str(body.get("token") or ""),
                    cookie=str(body.get("cookie") or ""),
                    target_site=str(body.get("target_site") or ""),
                    proxy=str(body.get("proxy") or ""),
                    user_agent=str(body.get("user_agent") or ""),
                )
            report = await verify_account_connection(account, service.env)
            broadcast_event({"type": "pulse", "intensity": 0.8})
            return JSONResponse(report.to_dict())
        except Exception as exc:
            return JSONResponse({"ok": False, "status": "error", "message": _safe_err(exc)}, status_code=400)

    async def api_generate_persona(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        try:
            body = await request.json()
            role = str(body.get("role") or "threat_intel_collector")
            region = str(body.get("region") or "EE")
            site = str(body.get("target_site") or "exploit.in")
            save = bool(body.get("save", False))
            p = generate_sockpuppet_persona(role=role, region=region, target_site=site)
            if save:
                save_persona_to_accounts_toml(settings.home, p)
                broadcast_event({"type": "accounts_updated"})
            return JSONResponse(p.to_dict())
        except Exception as exc:
            return JSONResponse({"error": _safe_err(exc)}, status_code=400)

    async def api_providers(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        desc_map = {
            "github": "API pública y búsquedas de eventos/usuarios de GitHub",
            "reddit": "API de Reddit para extracción de perfiles y actividad de foros",
            "bluesky": "API de ATProto/Bluesky para perfiles descentralizados",
            "intelx": "Búsquedas en Intelligence X (filtraciones y archivos)",
            "tor": "Enrutamiento anónimo para resolución de servicios .onion",
            "shodan": "Motor de búsqueda de dispositivos y puertos expuestos (Comunidad gratuita)",
            "virustotal": "Detección de malware e infraestructura maliciosa (Comunidad gratuita)",
            "censys": "Escaneo de certificados y servicios de Internet",
            "greynoise": "Clasificación de ruido de escaneo y ataques en Internet (Comunidad gratuita)",
            "hunter": "Descubrimiento de patrones y correos corporativos (Free Tier)",
            "hibp": "Verificación de cuentas en filtraciones conocidas (Have I Been Pwned)",
            "tatum": "Trazabilidad de direcciones Bitcoin y transacciones blockchain (Free Tier)",
            "securitytrails": "Historial de DNS pasivo y subdominios (Free Tier)",
            "otx": "Pulsos de amenazas e IOCs de AlienVault OTX (100% gratuito)",
            "urlscan": "Escaneos web públicos e historial de URLs en urlscan.io (Comunidad gratuita)",
            "urlhaus": "Base de datos comunitaria de malware URLs y payloads (abuse.ch)",
        }
        providers_info: list[dict[str, Any]] = []
        for name, env_keys in PLATFORM_ENV_VARS.items():
            is_cfg = any(bool(service.env.get(k, "").strip()) for k in env_keys)
            providers_info.append(
                {
                    "name": name.capitalize(),
                    "platform": name,
                    "env_vars": list(env_keys),
                    "is_configured": is_cfg,
                    "description": desc_map.get(name, f"Integración con {name}"),
                }
            )
        extra_providers = [
            "shodan",
            "virustotal",
            "securitytrails",
            "censys",
            "greynoise",
            "hunter",
            "hibp",
            "tatum",
            "otx",
            "urlscan",
            "urlhaus",
        ]
        for p in extra_providers:
            keys: tuple[str, ...] = (f"{p.upper()}_API_KEY",)
            if p == "censys":
                keys = ("CENSYS_API_ID", "CENSYS_API_SECRET")
            is_cfg = all(bool(service.env.get(k, "").strip()) for k in keys)
            providers_info.append(
                {
                    "name": p.capitalize(),
                    "platform": p,
                    "env_vars": list(keys),
                    "is_configured": is_cfg,
                    "description": desc_map.get(p, f"Proveedor {p}"),
                }
            )
        return JSONResponse({"providers": providers_info})

    async def api_cti_feeds(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        db_path = ensure_seed_cti_db(settings.home)
        sources: list[dict[str, Any]] = []
        active_count = 0
        purged_count = 0
        try:
            with _connect(db_path) as conn:
                active_count = int(conn.execute("SELECT COUNT(*) FROM cti_sources").fetchone()[0])
                purged_count = int(
                    conn.execute("SELECT COALESCE(SUM(purged_offline), 0) FROM cti_sync_meta").fetchone()[0]
                )
                rows = conn.execute(
                    "SELECT name, category, url, status, updated_ts FROM cti_sources ORDER BY id DESC LIMIT 50"
                ).fetchall()
                for r in rows:
                    sources.append(
                        {
                            "name": r[0],
                            "category": r[1],
                            "url": r[2],
                            "status": r[3],
                            "updated_at": r[4],
                        }
                    )
        except Exception as exc:
            logger.warning("Error leyendo CTI sqlite: %s", exc)

        return JSONResponse({"active_count": active_count, "purged_count": purged_count, "sources": sources})

    async def api_cti_sync(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        from maltego_mcp.egress import create_egress_client

        async with create_egress_client(service.settings, timeout=15.0) as cl:
            summary = await sync_deepdark_cti(settings.home, cl, force=True)
        broadcast_event({"type": "cti_synced"})
        broadcast_event({"type": "pulse", "intensity": 1.0})
        return JSONResponse(
            {
                "ok": True,
                "active_rows": summary["active_rows"],
                "purged_rows": summary["purged_rows"],
                "files_updated": summary["files_updated"],
            }
        )

    async def api_transforms(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        tx_list = [
            {
                "name": t.name,
                "description": t.description,
                "category": t.category,
                "input_types": list(t.input_types),
                "output_types": list(t.output_types),
                "passivity": t.passivity,
                "is_passive": t.is_passive,
            }
            for t in service.catalog.transforms.values()
        ]
        machines_list = [
            {
                "name": m.name,
                "description": m.description,
                "stages": [list(st) for st in m.stages],
                "default_rounds": m.default_rounds,
            }
            for m in service.catalog.machines.machines.values()
        ]
        return JSONResponse({"transforms": tx_list, "machines": machines_list})

    async def api_lookup(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        body = await request.json()
        tx_name = str(body.get("transform") or "").strip()
        val = str(body.get("value") or "").strip()
        etype = str(body.get("type") or "auto").strip()
        cid = str(body.get("case_id") or "").strip()
        save_results = bool(body.get("save", False)) and bool(cid)

        if not tx_name or not val:
            return JSONResponse({"ok": False, "error": "Faltan parámetros 'transform' y 'value'"}, status_code=400)

        try:
            spec = service.catalog.get(tx_name)
        except Exception:
            return JSONResponse({"ok": False, "error": f"Transformada '{tx_name}' no encontrada"}, status_code=404)

        if service.is_passive_mode and not spec.is_passive:
            return JSONResponse(
                {
                    "ok": False,
                    "error": (
                        f"El transform '{spec.name}' está clasificado como '{spec.passivity}' y está bloqueado "
                        "en modo pasivo. Para permitir transforms activos, configure MALTEGO_MCP_MODE=active."
                    ),
                },
                status_code=400,
            )

        if etype == "auto" or not etype:
            etype = spec.input_types[0] if spec.input_types else "maltego.Phrase"

        try:
            run = await service.run_transform(cid if save_results else "", tx_name, etype, val, [], 50, save_results)
            broadcast_event({"type": "pulse", "intensity": 0.8})
            broadcast_event({"type": "transform", "transform": tx_name, "target": val, "case_id": cid})
            entities_out = [
                {
                    "type": r.entity.maltego_type,
                    "value": r.entity.value,
                    "label": r.edge_label,
                    "weight": getattr(r.entity, "weight", 100),
                    "properties": r.entity.properties,
                }
                for r in run.results
            ]
            msg = run.messages[0][1] if run.messages else ""
            return JSONResponse(
                {
                    "ok": True,
                    "entities": entities_out,
                    "message": msg,
                    "case_id": cid,
                    "saved": save_results,
                }
            )
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=500)

    _bgp_cache: dict[str, tuple[float, Any]] = {}

    async def api_bgp_ripestat(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        endpoint = str(request.query_params.get("endpoint") or "asn-neighbours").strip().lower()
        resource = str(request.query_params.get("resource") or "").strip()
        if not resource:
            return JSONResponse(
                {"ok": False, "error": "Falta parámetro resource (ej. AS47583 o 8.8.8.8)"}, status_code=400
            )

        valid_endpoints = ("asn-neighbours", "announced-prefixes", "routing-status", "network-info", "whois")
        if endpoint not in valid_endpoints:
            endpoint = "asn-neighbours"

        cache_key = f"ripestat:{endpoint}:{resource.upper()}"
        now = time.time()
        if cache_key in _bgp_cache:
            ts, cached_data = _bgp_cache[cache_key]
            if now - ts < 3600:
                return JSONResponse({"ok": True, "source": "cache", "data": cached_data})

        url = f"https://stat.ripe.net/data/{endpoint}/data.json"
        params = {"resource": resource}
        try:
            from maltego_mcp.egress import create_egress_client

            async with create_egress_client(service.settings, timeout=10.0) as http:
                resp = await http.get(url, params=params)
                if resp.status_code == 200:
                    payload = resp.json()
                    data = payload.get("data", {})
                    _bgp_cache[cache_key] = (now, data)
                    return JSONResponse({"ok": True, "source": "ripestat", "data": data})
                return JSONResponse(
                    {"ok": False, "error": f"RIPEstat status {resp.status_code}"}, status_code=resp.status_code
                )
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=502)

    async def api_bgp_peeringdb(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        endpoint = str(request.query_params.get("endpoint") or "net").strip().lower()
        valid_endpoints = ("net", "netfac", "fac", "ix", "ixfac")
        if endpoint not in valid_endpoints:
            endpoint = "net"

        asn = str(request.query_params.get("asn") or "").strip().upper().replace("AS", "")
        fac_id = str(request.query_params.get("id") or "").strip()
        name = str(request.query_params.get("name") or "").strip()

        params: dict[str, str] = {}
        if asn:
            params["asn"] = asn
        if fac_id:
            params["id"] = fac_id
        if name:
            params["name__icontains"] = name

        cache_key = f"peeringdb:{endpoint}:{sorted(params.items())}"
        now = time.time()
        if cache_key in _bgp_cache:
            ts, cached_data = _bgp_cache[cache_key]
            if now - ts < 3600:
                return JSONResponse({"ok": True, "source": "cache", "data": cached_data})

        url = f"https://www.peeringdb.com/api/{endpoint}"
        try:
            async with create_egress_client(
                service.settings, timeout=10.0, headers={"Accept": "application/json"}
            ) as http:
                resp = await http.get(url, params=params)
                if resp.status_code == 200:
                    payload = resp.json()
                    data = payload.get("data", [])
                    _bgp_cache[cache_key] = (now, data)
                    return JSONResponse({"ok": True, "source": "peeringdb", "data": data})
                return JSONResponse(
                    {"ok": False, "error": f"PeeringDB status {resp.status_code}"}, status_code=resp.status_code
                )
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=502)

    async def api_cases(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        await asyncio.to_thread(_poll_disk_events_sync)
        page = await service.list_cases(50, 0)
        items = []
        for c in page.items:
            summary = await service.case_summary(c.case_id, top=1)
            items.append(
                {
                    "case_id": c.case_id,
                    "description": c.description,
                    "confidential": c.confidential,
                    "entity_count": summary.entity_count,
                    "edge_count": summary.edge_count,
                    "updated": c.updated,
                }
            )
        active_cid = _read_active_case_id()
        if not active_cid and items:
            active_cid = str(items[0]["case_id"])
        return JSONResponse({"cases": items, "active_case": active_cid})

    async def api_case_graph(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        try:
            ents, edges = await service.store.export_case(cid, 1000)
            report = await service.report_data(cid)
            score_map = report.scores
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=404)

        nodes = []
        for e in ents:
            is_canary = (
                e.properties.get("possible_canary") == "true"
                or e.properties.get("is_canary") == "true"
                or e.properties.get("deception.canary") == "true"
            )
            val_assess = compute_entity_validity(e)
            nodes.append(
                {
                    "id": e.id,
                    "value": e.value,
                    "type": e.maltego_type,
                    "label": e.label,
                    "confidence": e.confidence,
                    "priority": score_map[e.id].priority if e.id in score_map else e.confidence,
                    "priority_rationale": score_map[e.id].rationale() if e.id in score_map else "",
                    "sources": list(e.sources),
                    "properties": dict(e.properties),
                    "notes": e.notes,
                    "is_canary": is_canary,
                    "vigencia": val_assess.status,
                    "vigencia_score": val_assess.score,
                    "vigencia_rationale": val_assess.rationale,
                }
            )
        links = [
            {
                "id": ed.id,
                "source": ed.out_id,
                "target": ed.in_id,
                "label": ed.label,
                "confidence": ed.confidence,
                "properties": dict(ed.properties),
            }
            for ed in edges
        ]
        steps_out = [
            {
                "seq": s.seq,
                "kind": s.kind,
                "action": s.action,
                "input_id": s.input_id,
                "input_value": s.input_value,
                "outputs": list(s.outputs),
                "reason": s.reason,
                "timestamp": s.timestamp,
            }
            for s in report.steps
        ]
        return JSONResponse(
            {
                "ok": True,
                "case_id": cid,
                "quality": report.quality(),
                "nodes": nodes,
                "links": links,
                "steps": steps_out,
            }
        )

    async def api_case_profile(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        if not cid:
            return JSONResponse({"ok": False, "error": "Falta case_id"}, status_code=400)
        try:
            body = await request.json()
            eid = str(body.get("entity_id") or "").strip()
            if not eid:
                return JSONResponse({"ok": False, "error": "Falta entity_id"}, status_code=400)
            typology = str(body.get("typology") or "auto").strip().lower()
            reason = str(body.get("reason") or "").strip()
            additional_corpus = str(body.get("additional_corpus") or "").strip()
            if additional_corpus:
                target_entity = await service.get_entity(cid, eid)
                merged_notes = f"{target_entity.notes}\n[CORPUS FORENSE ADICIONAL]\n{additional_corpus}".strip()
                await service.update_entity(
                    cid,
                    eid,
                    -1,
                    merged_notes,
                    [],
                    [],
                    "profiling_corpus_ingestion",
                )
            updated_ent, profile_rec, emitted = await service.profile_entity(cid, eid, typology=typology, reason=reason)
            broadcast_event(
                {
                    "type": "entity_profiled",
                    "case_id": cid,
                    "entity_id": eid,
                    "typology": profile_rec.typology,
                    "archetype": profile_rec.archetype_label,
                    "risk_level": profile_rec.risk_level,
                }
            )
            return JSONResponse(
                {
                    "ok": True,
                    "profile": profile_rec.to_dict(),
                    "target_entity": {
                        "id": updated_ent.id,
                        "value": updated_ent.value,
                        "type": updated_ent.maltego_type,
                        "properties": dict(updated_ent.properties),
                        "notes": updated_ent.notes,
                    },
                    "emitted_count": len(emitted),
                }
            )
        except Exception as exc:
            logger.exception("Error ejecutando perfilado pericial: %s", exc)
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_profiles(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        if not cid:
            return JSONResponse({"ok": False, "error": "Falta case_id"}, status_code=400)
        try:
            entities, _ = await service.store.export_case(cid, 1000)
            profiled = []
            for e in entities:
                if any(k.startswith("profiling.") for k in e.properties):
                    profiled.append(
                        {
                            "id": e.id,
                            "value": e.value,
                            "type": e.maltego_type,
                            "domain": e.properties.get("profiling.domain", ""),
                            "typology": e.properties.get("profiling.typology", ""),
                            "archetype": e.properties.get("profiling.archetype", ""),
                            "risk_level": e.properties.get("profiling.risk_level", ""),
                            "notes": e.notes,
                        }
                    )
            return JSONResponse({"ok": True, "case_id": cid, "profiles": profiled, "count": len(profiled)})
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_export_case(request: Request) -> Response:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        fmt = str(request.path_params.get("format") or request.query_params.get("format") or "mcpcase").strip().lower()
        if fmt not in ("mcpcase", "mtgx", "json", "csv", "graphml", "report_md", "report_html"):
            return JSONResponse({"ok": False, "error": f"Formato no soportado: {fmt}"}, status_code=400)
        try:
            path, _n, _m = await service.export_case(cid, fmt)  # type: ignore[arg-type]
            media_type = "application/octet-stream"
            if fmt == "mcpcase":
                media_type = "application/vnd.maltego-mcp.case+json"
            elif fmt == "mtgx":
                media_type = "application/vnd.maltego.graph"
            elif fmt == "json":
                media_type = "application/json"
            elif fmt == "csv":
                media_type = "text/csv; charset=utf-8"
            elif fmt == "graphml":
                media_type = "application/xml"
            elif fmt == "report_md":
                media_type = "text/markdown; charset=utf-8"
            elif fmt == "report_html":
                media_type = "text/html; charset=utf-8"
            return FileResponse(
                path,
                filename=path.name,
                media_type=media_type,
                headers={"Content-Disposition": f'attachment; filename="{path.name}"'},
            )
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=404)

    async def api_import_case(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)

        content_type = request.headers.get("content-type", "")
        cid = ""
        desc = ""
        create_new = False
        file_bytes: bytes = b""
        filename = ""

        if "multipart/form-data" in content_type:
            form = await request.form()
            upload = form.get("file")
            cid = str(form.get("case_id") or "").strip()
            desc = str(form.get("description") or "").strip()
            create_new = str(form.get("create_new", "false")).lower() in ("true", "1", "yes")

            if upload and hasattr(upload, "read"):
                filename = Path(str(getattr(upload, "filename", "import_data.mtgx"))).name
                file_bytes = await upload.read()
            elif isinstance(upload, str):
                filename = Path(upload).name
        else:
            try:
                body = await request.json()
            except Exception:
                body = {}
            cid = str(body.get("case_id") or "").strip()
            desc = str(body.get("description") or "").strip()
            create_new = bool(body.get("create_new", False))
            filename = str(body.get("file_name") or body.get("filename") or "").strip()
            raw_content = body.get("content")
            if raw_content:
                file_bytes = raw_content.encode("utf-8") if isinstance(raw_content, str) else bytes(raw_content)

        if file_bytes:
            safe_name = re.sub(r"[^\w\.-]", "_", filename or "import_data.mtgx")
            if not any(safe_name.lower().endswith(sfx) for sfx in IMPORT_SUFFIXES):
                return JSONResponse(
                    {
                        "ok": False,
                        "error": f"Extensión no permitida. Formatos soportados: {', '.join(IMPORT_SUFFIXES)}",
                    },
                    status_code=400,
                )
            service.import_dir.mkdir(parents=True, exist_ok=True)
            target_path = service.import_dir / safe_name
            await asyncio.to_thread(target_path.write_bytes, file_bytes)
            filename = safe_name

        if not filename:
            return JSONResponse({"ok": False, "error": "Debes proporcionar un archivo para importar."}, status_code=400)

        # Si no se especifica case_id o se solicitó explícitamente nueva investigación:
        if not cid or create_new:
            base_slug = re.sub(r"[^a-zA-Z0-9_-]", "-", Path(filename).stem).strip("-").lower()
            cid = cid or f"caso-{base_slug or 'import'}"
            cid = re.sub(r"[^a-zA-Z0-9_-]", "-", cid).strip("-")[:64]
            if not cid:
                cid = f"caso-{secrets.token_hex(4)}"

        case_created = False
        try:
            summary = await service.case_summary(cid, top=1)
            is_empty = summary.entity_count == 0 and summary.edge_count == 0
        except Exception:
            is_empty = True

        if is_empty or create_new:
            case_desc = desc or f"Caso importado desde {filename}"
            try:
                await service.create_case(cid, case_desc)
                case_created = True
                broadcast_event({"type": "case_created", "case_id": cid, "description": case_desc})
            except Exception:
                pass

        try:
            res = await service.import_graph(cid, filename)
            broadcast_event({"type": "case_imported", "case_id": cid, "entities": res.entities, "links": res.links})
            broadcast_event({"type": "pulse", "intensity": 0.8})
            return JSONResponse(
                {
                    "ok": True,
                    "case_id": cid,
                    "case_created": case_created,
                    "filename": filename,
                    "entities": res.entities,
                    "new_entities": res.new_entities,
                    "links": res.links,
                    "steps": res.steps,
                    "skipped": res.skipped,
                    "format": "mcpcase" if filename.lower().endswith(".mcpcase") else Path(filename).suffix.lstrip("."),
                }
            )
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_create_case(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        body = await request.json()
        cid = str(body.get("case_id") or "").strip()
        desc = str(body.get("description") or "").strip()
        confidential = bool(body.get("confidential", False))
        if not cid:
            return JSONResponse({"ok": False, "error": "Falta el identificador 'case_id'"}, status_code=400)
        try:
            case_rec, _ = await service.create_case(cid, desc)
            if confidential:
                case_rec = await service.set_case_confidential(cid, True)
            broadcast_event(
                {"type": "case_created", "case_id": cid, "description": desc, "confidential": case_rec.confidential}
            )
            broadcast_event({"type": "pulse", "intensity": 0.8})
            return JSONResponse(
                {
                    "ok": True,
                    "case_id": case_rec.case_id,
                    "description": case_rec.description,
                    "confidential": case_rec.confidential,
                }
            )
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_delete_case(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        if not cid:
            return JSONResponse({"ok": False, "error": "Falta 'case_id'"}, status_code=400)
        try:
            d_ents, d_edges = await service.delete_case(cid, confirm=cid)
            broadcast_event({"type": "case_deleted", "case_id": cid})
            return JSONResponse({"ok": True, "case_id": cid, "deleted_entities": d_ents, "deleted_edges": d_edges})
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_events(request: Request) -> StreamingResponse:
        if not _check_host(request):
            return StreamingResponse(iter(['data: {"error": "forbidden"}\n\n']), status_code=403)

        async def sse_stream() -> AsyncIterator[str]:
            queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
            _event_subscribers.add(queue)
            try:
                yield 'data: {"type": "connected"}\n\n'
                while True:
                    try:
                        msg = await asyncio.wait_for(queue.get(), timeout=0.35)
                        yield f"data: {json.dumps(msg)}\n\n"
                    except TimeoutError:
                        await asyncio.to_thread(_poll_disk_events_sync)
            except (asyncio.CancelledError, GeneratorExit):
                pass
            finally:
                _event_subscribers.discard(queue)

        return StreamingResponse(sse_stream(), media_type="text/event-stream")

    async def api_events_poll(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        emitted = await asyncio.to_thread(_poll_disk_events_sync)
        active_cid = _read_active_case_id()
        return JSONResponse({"ok": True, "active_case": active_cid, "events": emitted, "count": len(emitted)})

    async def api_inbox_providers(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        return JSONResponse({"providers": [p.to_dict() for p in PROVIDER_CATALOG]})

    async def api_inbox_create(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        try:
            body = await request.json() if "application/json" in request.headers.get("content-type", "") else {}
        except Exception:
            body = {}
        desired_addr = str(body.get("address") or "").strip()
        desired_pwd = str(body.get("password") or "").strip()
        save_as_sock = bool(body.get("save_as_sockpuppet", False))

        from maltego_mcp.egress import create_egress_client

        async with create_egress_client(service.settings, timeout=20.0) as http:
            client = MailTmClient(http)
            res = await client.create_inbox(address=desired_addr, password=desired_pwd)

        if not res.get("ok"):
            return JSONResponse(res, status_code=400)

        if save_as_sock and res.get("address"):
            try:
                acc = SocialAccount(
                    id=f"mailtm_{res['address'].split('@')[0]}",
                    platform="custom",
                    handle=res["address"],
                    token=res.get("token", ""),
                    target_site="mail.tm",
                    enabled=True,
                )
                save_account_to_toml(settings.home, acc)
                broadcast_event({"type": "account_created", "account_id": acc.id, "platform": "custom"})
            except Exception as e:
                logger.warning("No se pudo persistir buzón en accounts.toml: %s", e)

        broadcast_event({"type": "inbox_created", "address": res.get("address")})
        return JSONResponse(res)

    async def api_inbox_messages(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        token = request.headers.get("x-inbox-token") or ""
        if not token:
            return JSONResponse({"error": "Falta cabecera X-Inbox-Token del buzón"}, status_code=400)

        from maltego_mcp.egress import create_egress_client

        async with create_egress_client(service.settings, timeout=20.0) as http:
            client = MailTmClient(http)
            msgs = await client.get_messages(token)
        return JSONResponse({"ok": True, "messages": msgs, "count": len(msgs)})

    async def api_inbox_message_detail(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        msg_id = str(request.path_params.get("message_id") or "").strip()
        token = request.headers.get("x-inbox-token") or ""
        if not token or not msg_id:
            return JSONResponse({"error": "Falta cabecera X-Inbox-Token o message_id"}, status_code=400)

        async with create_egress_client(service.settings, timeout=20.0) as http:
            client = MailTmClient(http)
            detail = await client.get_message_detail(token, msg_id)
        if not detail.get("ok"):
            return JSONResponse(detail, status_code=404 if "No se pudo" in detail.get("error", "") else 400)
        return JSONResponse(detail)

    async def api_case_perimeter(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        if not cid:
            return JSONResponse({"ok": False, "error": "Falta case_id"}, status_code=400)
        if request.method in ("POST", "DELETE"):
            try:
                body = await request.json()
                action = str(body.get("action") or ("remove" if request.method == "DELETE" else "add")).strip().lower()
                asset = str(body.get("asset") or "").strip()
                if not asset:
                    return JSONResponse({"ok": False, "error": "Falta parámetro 'asset'"}, status_code=400)
                if action == "remove":
                    updated = await service.remove_custom_perimeter_asset(cid, asset)
                else:
                    updated = await service.add_custom_perimeter_asset(cid, asset)
                scope = await service.get_case_perimeter(cid)
                broadcast_event({"type": "perimeter_updated", "case_id": cid, "asset": asset, "action": action})
                return JSONResponse(
                    {
                        "ok": True,
                        "case_id": cid,
                        "asset_modified": asset,
                        "action": action,
                        "custom_assets": updated,
                        "domains": sorted(scope.domains),
                        "ips": sorted(scope.ips),
                        "networks": [str(n) for n in scope.networks],
                        "total": len(scope.domains) + len(scope.ips) + len(scope.networks),
                    }
                )
            except Exception as exc:
                return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)
        else:
            try:
                scope = await service.get_case_perimeter(cid)
                custom = await service.get_custom_perimeter_assets(cid)
                return JSONResponse(
                    {
                        "ok": True,
                        "case_id": cid,
                        "domains": sorted(scope.domains),
                        "ips": sorted(scope.ips),
                        "networks": [str(n) for n in scope.networks],
                        "custom_assets": custom,
                        "total": len(scope.domains) + len(scope.ips) + len(scope.networks),
                    }
                )
            except Exception as exc:
                return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_machines(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        machines_list = []
        for m in service.catalog.machines.machines.values():
            tx_names = [t for st in m.stages for t in st]
            all_passive = True
            for tn in tx_names:
                spec = service.catalog.transforms.get(tn)
                if spec and not spec.is_passive:
                    all_passive = False
                    break
            machines_list.append(
                {
                    "name": m.name,
                    "description": m.description,
                    "stages": [list(st) for st in m.stages],
                    "default_rounds": m.default_rounds,
                    "is_passive": all_passive,
                }
            )
        return JSONResponse({"ok": True, "case_id": cid, "machines": machines_list})

    async def api_case_machine_run(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        if not cid:
            return JSONResponse({"ok": False, "error": "Falta case_id"}, status_code=400)
        try:
            body = await request.json()
            m_name = str(body.get("machine") or "").strip()
            e_type = str(body.get("type") or "maltego.Domain").strip()
            val = str(body.get("value") or "").strip()
            rounds = int(body.get("rounds") or 1)
            limit = int(body.get("limit") or 25)
            reason = str(body.get("reason") or f"Web UI execution of {m_name}").strip()

            if not m_name or not val:
                return JSONResponse({"ok": False, "error": "Faltan parámetros 'machine' y 'value'"}, status_code=400)

            run = await service.run_machine(cid, e_type, val, m_name, [], rounds, 10, limit, limit, reason=reason)
            broadcast_event({"type": "pulse", "intensity": 1.0})
            broadcast_event({"type": "machine_run", "case_id": cid, "machine": m_name, "value": val})
            total_ents = sum(s.new_entities for s in run.steps)
            all_errors = [err for s in run.steps for err in s.errors]
            return JSONResponse(
                {
                    "ok": True,
                    "case_id": cid,
                    "machine": m_name,
                    "rounds_executed": run.rounds,
                    "total_entities": total_ents,
                    "errors": all_errors,
                }
            )
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_egress_audit(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        limit = int(request.query_params.get("limit") or 100)
        from maltego_mcp.egress import AuditLog

        log_file = service.audit_log.log_path or (settings.home / "audit.log")

        def _read_and_verify_audit(path: Path, lim: int) -> tuple[list[dict[str, Any]], bool, str]:
            if not path.is_file():
                return [], True, "Sin registros aún"
            recs: list[dict[str, Any]] = []
            try:
                lines = path.read_text(encoding="utf-8").strip().splitlines()
                for line in lines[-lim:]:
                    with contextlib.suppress(Exception):
                        recs.append(json.loads(line))
            except Exception as e:
                logger.warning("Error leyendo audit.log: %s", e)
            valid, msg = AuditLog.verify_file(path)
            return recs, valid, msg

        records, chain_valid, broken_msg = await asyncio.to_thread(_read_and_verify_audit, log_file, limit)
        return JSONResponse(
            {
                "ok": True,
                "records": records,
                "count": len(records),
                "chain_valid": chain_valid,
                "broken_at": broken_msg,
                "path": str(log_file),
            }
        )

    async def api_case_recon(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        if not cid:
            return JSONResponse({"ok": False, "error": "Falta case_id"}, status_code=400)
        if request.method == "PUT":
            try:
                body = await request.json()
                saved = await service.save_case_recon(cid, body)
                broadcast_event({"type": "recon_updated", "case_id": cid})
                return JSONResponse({"ok": True, "case_id": cid, "recon": saved})
            except Exception as exc:
                return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)
        else:
            try:
                recon = await service.get_case_recon(cid)
                return JSONResponse({"ok": True, "case_id": cid, "recon": recon})
            except Exception as exc:
                return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_seeds(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        if not cid:
            return JSONResponse({"ok": False, "error": "Falta case_id"}, status_code=400)
        try:
            body = await request.json()
            val = str(body.get("value") or "").strip()
            if not val:
                return JSONResponse({"ok": False, "error": "Falta 'value' para la semilla"}, status_code=400)
            recon = await service.add_recon_seed(cid, body)
            broadcast_event({"type": "recon_seed_added", "case_id": cid, "seed": val})
            return JSONResponse({"ok": True, "case_id": cid, "seeds": recon["seeds"]})
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_seed_delete(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        sid = str(request.path_params.get("seed_id") or "").strip()
        if not cid or not sid:
            return JSONResponse({"ok": False, "error": "Faltan parámetros"}, status_code=400)
        try:
            recon = await service.delete_recon_seed(cid, sid)
            broadcast_event({"type": "recon_seed_deleted", "case_id": cid, "seed_id": sid})
            return JSONResponse({"ok": True, "case_id": cid, "seeds": recon["seeds"]})
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_seed_patch(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        sid = str(request.path_params.get("seed_id") or "").strip()
        if not cid or not sid:
            return JSONResponse({"ok": False, "error": "Faltan parámetros"}, status_code=400)
        try:
            body = await request.json()
            recon = await service.update_recon_seed(cid, sid, body)
            broadcast_event({"type": "recon_seed_updated", "case_id": cid, "seed_id": sid, "patch": body})
            return JSONResponse({"ok": True, "case_id": cid, "seeds": recon["seeds"]})
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_pivots(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        if not cid:
            return JSONResponse({"ok": False, "error": "Falta case_id"}, status_code=400)
        recon = await service.get_case_recon(cid)
        seeds = recon.get("seeds") or []
        if not seeds:
            try:
                ents, _ = await service.store.export_case(cid, 20)
                seeds = [{"type": e.maltego_type, "value": e.value} for e in ents]
            except Exception:
                seeds = []
        pivots = service.generate_lateral_pivots(seeds)
        return JSONResponse({"ok": True, "case_id": cid, "pivots": pivots, "count": len(pivots)})

    async def api_case_recon_dorks(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        domain = str(request.query_params.get("domain") or "").strip()
        if not domain and cid:
            recon = await service.get_case_recon(cid)
            target = str((recon.get("p0_framing") or {}).get("target") or "").strip()
            if target and ("." in target or not target.startswith("http")):
                domain = target.replace("https://", "").replace("http://", "").split("/")[0].strip()
            if not domain:
                for s in recon.get("seeds", []):
                    if "Domain" in s.get("type", ""):
                        domain = s.get("value", "")
                        break
        if not domain and cid:
            try:
                ents, _ = await service.store.export_case(cid, 10)
                for e in ents:
                    if "Domain" in e.maltego_type:
                        domain = e.value
                        break
            except Exception:
                pass
        dorks = service.generate_safe_dorks(domain)
        return JSONResponse({"ok": True, "domain": domain, "dorks": dorks, "count": len(dorks)})

    async def api_case_recon_hypotheses(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        if not cid:
            return JSONResponse({"ok": False, "error": "Falta case_id"}, status_code=400)
        try:
            body = await request.json()
            statement = str(body.get("statement") or "").strip()
            what_would_refute = str(body.get("what_would_refute_it") or "").strip()
            if not statement:
                return JSONResponse(
                    {"ok": False, "error": "El enunciado de la hipótesis es obligatorio"}, status_code=400
                )
            if not what_would_refute:
                err_msg = (
                    "Rigor analítico No Zoom (§5): Es obligatorio especificar qué evidencia concreta "
                    "refutaría esta hipótesis."
                )
                return JSONResponse({"ok": False, "error": err_msg}, status_code=400)
            prob = str(body.get("probability") or "PROBABLE").strip()
            conf = str(body.get("confidence") or "MEDIA").strip()

            recon = await service.get_case_recon(cid)
            hid = f"H{len(recon.get('hypotheses', [])) + 1}"
            new_hyp = {
                "id": hid,
                "statement": statement,
                "probability": prob,
                "confidence": conf,
                "what_would_refute_it": what_would_refute,
                "created_at": datetime.now(UTC).isoformat(),
            }
            recon.setdefault("hypotheses", []).append(new_hyp)
            await service.save_case_recon(cid, recon)
            broadcast_event({"type": "recon_hypothesis_added", "case_id": cid, "hypothesis_id": hid})
            return JSONResponse({"ok": True, "case_id": cid, "hypotheses": recon["hypotheses"]})
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_infra(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        if not cid:
            return JSONResponse({"ok": False, "error": "Falta case_id"}, status_code=400)
        try:
            body = await request.json()
            res = await service.add_fase2_infra(cid, body)
            broadcast_event({"type": "recon_infra_updated", "case_id": cid})
            return JSONResponse(res)
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_infra_delete(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        item_id = str(request.path_params.get("item_id") or "").strip()
        try:
            res = await service.delete_fase2_infra(cid, item_id)
            broadcast_event({"type": "recon_infra_updated", "case_id": cid})
            return JSONResponse(res)
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_archive(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        if not cid:
            return JSONResponse({"ok": False, "error": "Falta case_id"}, status_code=400)
        try:
            body = await request.json()
            res = await service.add_fase3_archive(cid, body)
            broadcast_event({"type": "recon_archive_updated", "case_id": cid})
            return JSONResponse(res)
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_archive_delete(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        item_id = str(request.path_params.get("item_id") or "").strip()
        try:
            res = await service.delete_fase3_archive(cid, item_id)
            broadcast_event({"type": "recon_archive_updated", "case_id": cid})
            return JSONResponse(res)
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_reframing(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        try:
            body = await request.json()
            phase = str(body.get("phase") or "Fase 2").strip()
            res = await service.confirm_reframing(cid, phase)
            return JSONResponse(res)
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_gaps(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        try:
            body = await request.json()
            phase = str(body.get("phase") or "Fase 2").strip()
            desc = str(body.get("description") or "").strip()
            res = await service.declare_coverage_gap(cid, phase, desc)
            return JSONResponse(res)
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_symmetric_dorks(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        domain = str(request.query_params.get("domain") or "").strip()
        try:
            recon = await service.get_case_recon(cid)
            target = domain or recon.get("p0_framing", {}).get("target", "")
            seeds = [s.get("value", "") for s in recon.get("seeds", []) if s.get("value")]
            vals = [target] if target else []
            vals.extend([s for s in seeds if s not in vals])

            dorks_list = []
            for v in vals[:5]:
                dorks_list.extend(service.generate_symmetric_dorks(v))

            if not dorks_list and not vals:
                dorks_list = service.generate_symmetric_dorks("target.corp")

            return JSONResponse({"ok": True, "case_id": cid, "trios": dorks_list})
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_log_search(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        try:
            body = await request.json()
            stype = str(body.get("search_type") or "confirmatorio").strip()
            res = await service.log_recon_search(cid, stype)
            return JSONResponse(res)
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_breach(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        if not cid:
            return JSONResponse({"ok": False, "error": "Falta case_id"}, status_code=400)
        try:
            body = await request.json()
            res = await service.add_fase6_breach(cid, body)
            broadcast_event({"type": "recon_breaches_updated", "case_id": cid})
            return JSONResponse(res)
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_breach_delete(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        item_id = str(request.path_params.get("item_id") or "").strip()
        try:
            res = await service.delete_fase6_breach(cid, item_id)
            broadcast_event({"type": "recon_breaches_updated", "case_id": cid})
            return JSONResponse(res)
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_breach_link(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        item_id = str(request.path_params.get("item_id") or "").strip()
        try:
            res = await service.link_breach_to_graph(cid, item_id)
            broadcast_event({"type": "recon_breaches_updated", "case_id": cid})
            broadcast_event({"type": "graph_updated", "case_id": cid})
            return JSONResponse(res)
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_breach_local_search(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        q = str(request.query_params.get("q") or "").strip()
        limit = int(request.query_params.get("limit") or 25)
        try:
            hits = await asyncio.to_thread(service.search_local_breaches_service, q, limit)
            return JSONResponse({"ok": True, "query": q, "hits": hits})
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_humint(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        if not cid:
            return JSONResponse({"ok": False, "error": "Falta case_id"}, status_code=400)
        try:
            body = await request.json()
            res = await service.add_fase7_humint(cid, body)
            broadcast_event({"type": "recon_humint_updated", "case_id": cid})
            return JSONResponse(res)
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_humint_delete(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        item_id = str(request.path_params.get("item_id") or "").strip()
        try:
            res = await service.delete_fase7_humint(cid, item_id)
            broadcast_event({"type": "recon_humint_updated", "case_id": cid})
            return JSONResponse(res)
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_humint_link(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        item_id = str(request.path_params.get("item_id") or "").strip()
        try:
            res = await service.link_humint_to_graph(cid, item_id)
            broadcast_event({"type": "recon_humint_updated", "case_id": cid})
            broadcast_event({"type": "graph_updated", "case_id": cid})
            return JSONResponse(res)
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_ecosystem(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        if not cid:
            return JSONResponse({"ok": False, "error": "Falta case_id"}, status_code=400)
        try:
            body = await request.json()
            res = await service.add_fase8_ecosystem(cid, body)
            broadcast_event({"type": "recon_ecosystem_updated", "case_id": cid})
            return JSONResponse(res)
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_ecosystem_delete(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        item_id = str(request.path_params.get("item_id") or "").strip()
        try:
            res = await service.delete_fase8_ecosystem(cid, item_id)
            broadcast_event({"type": "recon_ecosystem_updated", "case_id": cid})
            return JSONResponse(res)
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_ecosystem_link(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        item_id = str(request.path_params.get("item_id") or "").strip()
        try:
            res = await service.link_ecosystem_to_graph(cid, item_id)
            broadcast_event({"type": "recon_ecosystem_updated", "case_id": cid})
            broadcast_event({"type": "graph_updated", "case_id": cid})
            return JSONResponse(res)
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_hypothesis_delete(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        hid = str(request.path_params.get("item_id") or "").strip()
        if not cid or not hid:
            return JSONResponse({"ok": False, "error": "Faltan parámetros"}, status_code=400)
        try:
            res = await service.delete_recon_hypothesis(cid, hid)
            broadcast_event({"type": "recon_hypothesis_deleted", "case_id": cid, "hypothesis_id": hid})
            return JSONResponse(res)
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_hypothesis_evaluate(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        hid = str(request.path_params.get("item_id") or "").strip()
        if not cid or not hid:
            return JSONResponse({"ok": False, "error": "Faltan parámetros"}, status_code=400)
        try:
            body = await request.json()
            evals = body.get("evaluations")
            prob = str(body.get("probability") or "")
            conf = str(body.get("confidence") or "")
            res = await service.update_hypothesis_evaluations(cid, hid, evals, prob, conf)
            broadcast_event({"type": "recon_hypothesis_evaluated", "case_id": cid, "hypothesis_id": hid})
            return JSONResponse(res)
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_key_evidence(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        if not cid:
            return JSONResponse({"ok": False, "error": "Falta case_id"}, status_code=400)
        try:
            body = await request.json()
            res = await service.save_key_evidence(cid, body)
            broadcast_event({"type": "recon_key_evidence_saved", "case_id": cid})
            return JSONResponse(res)
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    async def api_case_recon_icd203_report(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        if not cid:
            return JSONResponse({"ok": False, "error": "Falta case_id"}, status_code=400)
        try:
            res = await service.generate_icd203_report(cid)
            return JSONResponse(res)
        except Exception as exc:
            return JSONResponse({"ok": False, "error": _safe_err(exc)}, status_code=400)

    # Registro de rutas en la app Starlette
    app.add_route("/", root_view, methods=["GET"])
    app.add_route("/dashboard", root_view, methods=["GET"])
    app.add_route("/dashboard.css", static_css, methods=["GET"])
    app.add_route("/dashboard.js", static_js, methods=["GET"])
    app.add_route("/bg-worker.js", static_worker_js, methods=["GET"])
    app.add_route("/egress-ring.js", static_ring_js, methods=["GET"])
    app.add_route("/favicon.ico", static_favicon, methods=["GET"])
    app.add_route("/favicon.png", static_favicon_png, methods=["GET"])
    app.add_route("/favicon-32x32.png", static_favicon_32, methods=["GET"])
    app.add_route("/apple-touch-icon.png", static_apple_touch_icon, methods=["GET"])
    app.add_route("/logo.png", static_logo, methods=["GET"])
    app.add_route("/api/auth/session", api_auth_session, methods=["GET"])
    app.add_route("/api/auth/login", api_auth_login, methods=["POST"])
    app.add_route("/api/auth/logout", api_auth_logout, methods=["POST"])
    app.add_route("/api/status", api_status, methods=["GET"])
    app.add_route("/api/accounts", api_get_accounts, methods=["GET"])
    app.add_route("/api/accounts", api_save_account, methods=["POST"])
    app.add_route("/api/accounts/{account_id}", api_delete_account, methods=["DELETE"])
    app.add_route("/api/accounts/verify", api_verify_account, methods=["POST"])
    app.add_route("/api/accounts/generate-persona", api_generate_persona, methods=["POST"])
    app.add_route("/api/inbox/providers", api_inbox_providers, methods=["GET"])
    app.add_route("/api/inbox/create", api_inbox_create, methods=["POST"])
    app.add_route("/api/inbox/messages", api_inbox_messages, methods=["GET"])
    app.add_route("/api/inbox/messages/{message_id}", api_inbox_message_detail, methods=["GET"])
    app.add_route("/api/providers", api_providers, methods=["GET"])
    app.add_route("/api/cti-feeds", api_cti_feeds, methods=["GET"])
    app.add_route("/api/cti-feeds/sync", api_cti_sync, methods=["POST"])
    app.add_route("/api/transforms", api_transforms, methods=["GET"])
    app.add_route("/api/lookup", api_lookup, methods=["POST"])
    app.add_route("/api/bgp/ripestat", api_bgp_ripestat, methods=["GET"])
    app.add_route("/api/bgp/peeringdb", api_bgp_peeringdb, methods=["GET"])
    app.add_route("/api/cases", api_cases, methods=["GET"])
    app.add_route("/api/cases", api_create_case, methods=["POST"])
    app.add_route("/api/cases/{case_id}", api_delete_case, methods=["DELETE"])
    app.add_route("/api/cases/{case_id}/graph", api_case_graph, methods=["GET"])
    app.add_route("/api/cases/{case_id}/perimeter", api_case_perimeter, methods=["GET", "POST", "DELETE"])
    app.add_route("/api/cases/{case_id}/machines", api_case_machines, methods=["GET"])
    app.add_route("/api/cases/{case_id}/machines/run", api_case_machine_run, methods=["POST"])
    app.add_route("/api/cases/{case_id}/recon", api_case_recon, methods=["GET", "PUT"])
    app.add_route("/api/cases/{case_id}/recon/seeds", api_case_recon_seeds, methods=["POST"])
    app.add_route("/api/cases/{case_id}/recon/seeds/{seed_id}", api_case_recon_seed_delete, methods=["DELETE"])
    app.add_route("/api/cases/{case_id}/recon/seeds/{seed_id}", api_case_recon_seed_patch, methods=["PATCH"])
    app.add_route("/api/cases/{case_id}/recon/pivots", api_case_recon_pivots, methods=["GET"])
    app.add_route("/api/cases/{case_id}/recon/dorks", api_case_recon_dorks, methods=["GET"])
    app.add_route("/api/cases/{case_id}/recon/hypotheses", api_case_recon_hypotheses, methods=["POST"])
    app.add_route(
        "/api/cases/{case_id}/recon/hypotheses/{item_id}", api_case_recon_hypothesis_delete, methods=["DELETE"]
    )
    app.add_route(
        "/api/cases/{case_id}/recon/hypotheses/{item_id}/evaluate",
        api_case_recon_hypothesis_evaluate,
        methods=["POST"],
    )
    app.add_route("/api/cases/{case_id}/recon/key-evidence", api_case_recon_key_evidence, methods=["POST"])
    app.add_route("/api/cases/{case_id}/recon/icd203-report", api_case_recon_icd203_report, methods=["GET"])
    app.add_route("/api/cases/{case_id}/recon/infra", api_case_recon_infra, methods=["POST"])
    app.add_route("/api/cases/{case_id}/recon/infra/{item_id}", api_case_recon_infra_delete, methods=["DELETE"])
    app.add_route("/api/cases/{case_id}/recon/archive", api_case_recon_archive, methods=["POST"])
    app.add_route("/api/cases/{case_id}/recon/archive/{item_id}", api_case_recon_archive_delete, methods=["DELETE"])
    app.add_route("/api/cases/{case_id}/recon/reframing", api_case_recon_reframing, methods=["POST"])
    app.add_route("/api/cases/{case_id}/recon/gaps", api_case_recon_gaps, methods=["POST"])
    app.add_route("/api/cases/{case_id}/recon/symmetric-dorks", api_case_recon_symmetric_dorks, methods=["GET"])
    app.add_route("/api/cases/{case_id}/recon/log-search", api_case_recon_log_search, methods=["POST"])
    app.add_route("/api/cases/{case_id}/recon/breaches", api_case_recon_breach, methods=["POST"])
    app.add_route("/api/cases/{case_id}/recon/breaches/{item_id}", api_case_recon_breach_delete, methods=["DELETE"])
    app.add_route(
        "/api/cases/{case_id}/recon/breaches/{item_id}/link-graph", api_case_recon_breach_link, methods=["POST"]
    )
    app.add_route(
        "/api/cases/{case_id}/recon/breaches/local-search", api_case_recon_breach_local_search, methods=["GET"]
    )
    app.add_route("/api/cases/{case_id}/recon/humint", api_case_recon_humint, methods=["POST"])
    app.add_route("/api/cases/{case_id}/recon/humint/{item_id}", api_case_recon_humint_delete, methods=["DELETE"])
    app.add_route(
        "/api/cases/{case_id}/recon/humint/{item_id}/link-graph", api_case_recon_humint_link, methods=["POST"]
    )
    app.add_route("/api/cases/{case_id}/recon/ecosystem", api_case_recon_ecosystem, methods=["POST"])
    app.add_route("/api/cases/{case_id}/recon/ecosystem/{item_id}", api_case_recon_ecosystem_delete, methods=["DELETE"])
    app.add_route(
        "/api/cases/{case_id}/recon/ecosystem/{item_id}/link-graph", api_case_recon_ecosystem_link, methods=["POST"]
    )
    app.add_route("/api/cases/{case_id}/profile", api_case_profile, methods=["POST"])
    app.add_route("/api/cases/{case_id}/profiles", api_case_profiles, methods=["GET"])
    app.add_route("/api/egress/audit", api_egress_audit, methods=["GET"])
    from maltego_mcp.web_ring import attach_ring_routes

    attach_ring_routes(
        app,
        settings=settings,
        auth_manager=auth_manager,
        audit_log=service.audit_log,
        broadcast=broadcast_event,
        control_enabled=settings.dashboard_auth if ring_control is None else ring_control,
    )
    app.add_route("/api/cases/{case_id}/export", api_export_case, methods=["GET"])
    app.add_route("/api/cases/{case_id}/export/{format}", api_export_case, methods=["GET"])
    app.add_route("/api/cases/import", api_import_case, methods=["POST"])
    app.add_route("/api/events", api_events, methods=["GET"])
    app.add_route("/api/events/poll", api_events_poll, methods=["GET"])

    return app
