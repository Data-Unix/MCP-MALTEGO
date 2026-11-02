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
import json
import logging
import socket
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response, StreamingResponse

from maltego_mcp import __version__
from maltego_mcp.accounts import (
    PLATFORM_ENV_VARS,
    SocialAccount,
    generate_sockpuppet_persona,
    load_account_pool,
    remove_account_from_toml,
    save_account_to_toml,
    save_persona_to_accounts_toml,
    verify_account_connection,
)
from maltego_mcp.config import Settings
from maltego_mcp.cti_feeds import _connect, ensure_seed_cti_db, sync_deepdark_cti
from maltego_mcp.service import OsintService

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


def _check_host(request: Request) -> bool:
    host = request.headers.get("host", "").split(":")[0].lower()
    return not host or host in LOOPBACK_HOSTS


def attach_dashboard_routes(app: Starlette, service: OsintService, settings: Settings) -> Starlette:
    """Registra las rutas de la interfaz web y APIs REST en la aplicación Starlette."""

    async def root_view(request: Request) -> Response:
        if not _check_host(request):
            return Response("Acceso denegado: solo permitido desde loopback", status_code=403)
        html_file = WEB_DIR / "index.html"
        if not html_file.is_file():
            return Response("Fichero index.html no encontrado en src/maltego_mcp/web", status_code=404)
        return HTMLResponse(html_file.read_text(encoding="utf-8"))

    async def static_css(request: Request) -> Response:
        f = WEB_DIR / "dashboard.css"
        if not f.is_file():
            return Response("/* no css */", media_type="text/css")
        return Response(f.read_text(encoding="utf-8"), media_type="text/css")

    async def static_js(request: Request) -> Response:
        f = WEB_DIR / "dashboard.js"
        if not f.is_file():
            return Response("// no js", media_type="application/javascript")
        return Response(f.read_text(encoding="utf-8"), media_type="application/javascript")

    async def static_worker_js(request: Request) -> Response:
        f = WEB_DIR / "bg-worker.js"
        if not f.is_file():
            return Response("// no worker", media_type="application/javascript")
        return Response(f.read_text(encoding="utf-8"), media_type="application/javascript")

    async def api_status(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        pool = load_account_pool(settings.home, service.env)
        tor_proxy = pool.env.get("TOR_SOCKS_PROXY", "socks5h://127.0.0.1:9050")
        tor_active = False
        if "127.0.0.1:9050" in tor_proxy or "localhost:9050" in tor_proxy:
            try:
                with socket.create_connection(("127.0.0.1", 9050), timeout=0.15):
                    tor_active = True
            except OSError:
                tor_active = False

        cti_summary: dict[str, int] = {"active_sources": 0, "purged_sources": 0}
        try:
            db_path = ensure_seed_cti_db(settings.home)
            with _connect(db_path) as conn:
                active_c = int(conn.execute("SELECT COUNT(*) FROM cti_sources").fetchone()[0])
                purged_c = int(conn.execute("SELECT COALESCE(SUM(purged_offline), 0) FROM cti_sync_meta").fetchone()[0])
                cti_summary = {"active_sources": active_c, "purged_sources": purged_c}
        except Exception:
            pass

        return JSONResponse(
            {
                "status": "online",
                "version": __version__,
                "transport": "http",
                "host": request.url.hostname or "127.0.0.1",
                "port": request.url.port or 8000,
                "home_dir": str(settings.home),
                "tor_socks_proxy": tor_proxy,
                "tor_active": tor_active,
                "accounts_summary": pool.summary(),
                "cti_summary": cti_summary,
                "transforms_count": len(service.catalog.transforms),
                "machines_count": len(service.catalog.machines.machines),
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
                "username": acc.username,
                "handle": acc.handle,
                "target_site": acc.target_site,
                "site": acc.site,
                "rate_limit_rpm": acc.rate_limit_rpm,
                "enabled": acc.enabled,
                "cooldown_until": acc.cooldown_until,
                "proxy": acc.proxy,
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
            acc_id = str(body.get("id") or f"sp-{plat}-{int(time.time())}").strip()[:80]
            account = SocialAccount(
                id=acc_id,
                platform=plat,
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
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

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
            return JSONResponse({"ok": False, "status": "error", "message": str(exc)}, status_code=400)

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
            return JSONResponse({"error": str(exc)}, status_code=400)

    async def api_providers(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        desc_map = {
            "github": "API pública y búsquedas de eventos/usuarios de GitHub",
            "reddit": "API de Reddit para extracción de perfiles y actividad de foros",
            "bluesky": "API de ATProto/Bluesky para perfiles descentralizados",
            "intelx": "Búsquedas en Intelligence X (filtraciones y archivos)",
            "tor": "Enrutamiento anónimo para resolución de servicios .onion",
            "shodan": "Motor de búsqueda de dispositivos y puertos expuestos",
            "virustotal": "Detección de malware e infraestructura maliciosa",
            "censys": "Escaneo de certificados y servicios de Internet",
            "greynoise": "Clasificación de ruido de escaneo y ataques en Internet",
            "hunter": "Descubrimiento de patrones y correos corporativos",
            "hibp": "Verificación de cuentas en filtraciones conocidas (Have I Been Pwned)",
            "tatum": "Trazabilidad de direcciones Bitcoin y transacciones blockchain",
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
        extra_providers = ["shodan", "virustotal", "censys", "greynoise", "hunter", "hibp", "tatum"]
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
                    "SELECT name, category, url, status, updated_at FROM cti_sources ORDER BY id DESC LIMIT 50"
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
        async with httpx.AsyncClient(timeout=15.0) as cl:
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

        if not tx_name or not val:
            return JSONResponse({"ok": False, "error": "Faltan parámetros 'transform' y 'value'"}, status_code=400)

        try:
            spec = service.catalog.get(tx_name)
        except Exception:
            return JSONResponse({"ok": False, "error": f"Transformada '{tx_name}' no encontrada"}, status_code=404)

        if etype == "auto" or not etype:
            etype = spec.input_types[0] if spec.input_types else "maltego.Phrase"

        try:
            run = await service.run_transform("", tx_name, etype, val, [], 50, False)
            broadcast_event({"type": "pulse", "intensity": 0.8})
            broadcast_event({"type": "transform", "transform": tx_name, "target": val})
            entities_out = [
                {"type": r.entity.maltego_type, "value": r.entity.value, "label": r.edge_label} for r in run.results
            ]
            msg = run.messages[0][1] if run.messages else ""
            return JSONResponse({"ok": True, "entities": entities_out, "message": msg})
        except Exception as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)

    async def api_events(request: Request) -> StreamingResponse:
        if not _check_host(request):
            return StreamingResponse(iter(['data: {"error": "forbidden"}\n\n']), status_code=403)

        async def sse_stream() -> AsyncIterator[str]:
            queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
            _event_subscribers.add(queue)
            try:
                yield 'data: {"type": "connected"}\n\n'
                while True:
                    msg = await queue.get()
                    yield f"data: {json.dumps(msg)}\n\n"
            except (asyncio.CancelledError, GeneratorExit):
                pass
            finally:
                _event_subscribers.discard(queue)

        return StreamingResponse(sse_stream(), media_type="text/event-stream")

    # Registro de rutas en la app Starlette
    app.add_route("/", root_view, methods=["GET"])
    app.add_route("/dashboard", root_view, methods=["GET"])
    app.add_route("/dashboard.css", static_css, methods=["GET"])
    app.add_route("/dashboard.js", static_js, methods=["GET"])
    app.add_route("/bg-worker.js", static_worker_js, methods=["GET"])
    app.add_route("/api/status", api_status, methods=["GET"])
    app.add_route("/api/accounts", api_get_accounts, methods=["GET"])
    app.add_route("/api/accounts", api_save_account, methods=["POST"])
    app.add_route("/api/accounts/{account_id}", api_delete_account, methods=["DELETE"])
    app.add_route("/api/accounts/verify", api_verify_account, methods=["POST"])
    app.add_route("/api/accounts/generate-persona", api_generate_persona, methods=["POST"])
    app.add_route("/api/providers", api_providers, methods=["GET"])
    app.add_route("/api/cti-feeds", api_cti_feeds, methods=["GET"])
    app.add_route("/api/cti-feeds/sync", api_cti_sync, methods=["POST"])
    app.add_route("/api/transforms", api_transforms, methods=["GET"])
    app.add_route("/api/lookup", api_lookup, methods=["POST"])
    app.add_route("/api/events", api_events, methods=["GET"])

    return app
