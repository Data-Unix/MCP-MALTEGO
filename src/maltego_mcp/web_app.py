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
import re
import secrets
import socket
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
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
from maltego_mcp.config import Settings
from maltego_mcp.cti_feeds import _connect, ensure_seed_cti_db, sync_deepdark_cti
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


def _check_host(request: Request) -> bool:
    host = request.headers.get("host", "").split(":")[0].lower()
    return not host or host in LOOPBACK_HOSTS


def attach_dashboard_routes(app: Starlette, service: OsintService, settings: Settings) -> Starlette:
    """Registra las rutas de la interfaz web y APIs REST en la aplicación Starlette."""
    # Asegurar plantillas y bases iniciales de forma desatendida y tolerante a fallos
    try:
        ensure_accounts_template(settings.home)
        ensure_seed_cti_db(settings.home)
    except Exception as _e:
        logger.debug("Inicialización previa silenciosa: %s", _e)

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

        try:
            with socket.create_connection((target_host, target_port), timeout=0.15):
                tor_active = True
        except OSError:
            # Fallback tolerante si en macOS/Windows se usa el bundle gráfico de Tor Browser (puerto 9150)
            if target_host in ("127.0.0.1", "localhost") and target_port == 9050:
                try:
                    with socket.create_connection(("127.0.0.1", 9150), timeout=0.15):
                        tor_active = True
                except OSError:
                    tor_active = False
            else:
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
                "category": acc.category,
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
        cid = str(body.get("case_id") or "").strip()
        save_results = bool(body.get("save", False)) and bool(cid)

        if not tx_name or not val:
            return JSONResponse({"ok": False, "error": "Faltan parámetros 'transform' y 'value'"}, status_code=400)

        try:
            spec = service.catalog.get(tx_name)
        except Exception:
            return JSONResponse({"ok": False, "error": f"Transformada '{tx_name}' no encontrada"}, status_code=404)

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
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)

    async def api_cases(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        page = await service.list_cases(50, 0)
        items = []
        for c in page.items:
            summary = await service.case_summary(c.case_id, top=1)
            items.append(
                {
                    "case_id": c.case_id,
                    "description": c.description,
                    "entity_count": summary.entity_count,
                    "edge_count": summary.edge_count,
                    "updated": c.updated,
                }
            )
        return JSONResponse({"cases": items})

    async def api_case_graph(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        cid = str(request.path_params.get("case_id") or "").strip()
        try:
            ents, edges = await service.store.export_case(cid, 1000)
            report = await service.report_data(cid)
            score_map = report.scores
        except Exception as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=404)

        nodes = [
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
            }
            for e in ents
        ]
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
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=404)

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
            target_path.write_bytes(file_bytes)
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
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    async def api_create_case(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        body = await request.json()
        cid = str(body.get("case_id") or "").strip()
        desc = str(body.get("description") or "").strip()
        if not cid:
            return JSONResponse({"ok": False, "error": "Falta el identificador 'case_id'"}, status_code=400)
        try:
            case_rec, _ = await service.create_case(cid, desc)
            broadcast_event({"type": "case_created", "case_id": cid, "description": desc})
            broadcast_event({"type": "pulse", "intensity": 0.8})
            return JSONResponse({"ok": True, "case_id": case_rec.case_id, "description": case_rec.description})
        except Exception as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

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
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

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

        async with httpx.AsyncClient(timeout=20.0) as http:
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
        token = request.headers.get("x-inbox-token") or request.query_params.get("token") or ""
        if not token:
            return JSONResponse({"error": "Falta token de autenticación del buzón"}, status_code=400)

        async with httpx.AsyncClient(timeout=20.0) as http:
            client = MailTmClient(http)
            msgs = await client.get_messages(token)
        return JSONResponse({"ok": True, "messages": msgs, "count": len(msgs)})

    async def api_inbox_message_detail(request: Request) -> JSONResponse:
        if not _check_host(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        msg_id = str(request.path_params.get("message_id") or "").strip()
        token = request.headers.get("x-inbox-token") or request.query_params.get("token") or ""
        if not token or not msg_id:
            return JSONResponse({"error": "Falta token o message_id"}, status_code=400)

        async with httpx.AsyncClient(timeout=20.0) as http:
            client = MailTmClient(http)
            detail = await client.get_message_detail(token, msg_id)
        if not detail.get("ok"):
            return JSONResponse(detail, status_code=404 if "No se pudo" in detail.get("error", "") else 400)
        return JSONResponse(detail)

    # Registro de rutas en la app Starlette
    app.add_route("/", root_view, methods=["GET"])
    app.add_route("/dashboard", root_view, methods=["GET"])
    app.add_route("/dashboard.css", static_css, methods=["GET"])
    app.add_route("/dashboard.js", static_js, methods=["GET"])
    app.add_route("/bg-worker.js", static_worker_js, methods=["GET"])
    app.add_route("/favicon.ico", static_favicon, methods=["GET"])
    app.add_route("/favicon.png", static_favicon_png, methods=["GET"])
    app.add_route("/favicon-32x32.png", static_favicon_32, methods=["GET"])
    app.add_route("/apple-touch-icon.png", static_apple_touch_icon, methods=["GET"])
    app.add_route("/logo.png", static_logo, methods=["GET"])
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
    app.add_route("/api/cases", api_cases, methods=["GET"])
    app.add_route("/api/cases", api_create_case, methods=["POST"])
    app.add_route("/api/cases/{case_id}", api_delete_case, methods=["DELETE"])
    app.add_route("/api/cases/{case_id}/graph", api_case_graph, methods=["GET"])
    app.add_route("/api/cases/{case_id}/export", api_export_case, methods=["GET"])
    app.add_route("/api/cases/{case_id}/export/{format}", api_export_case, methods=["GET"])
    app.add_route("/api/cases/import", api_import_case, methods=["POST"])
    app.add_route("/api/events", api_events, methods=["GET"])

    return app
