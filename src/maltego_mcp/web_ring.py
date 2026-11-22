"""Panel del Anillo de egreso Mullvad (Centro de Mando): estado veraz y control de la VPN desde el dashboard.

Endpoints (todos bajo el middleware del panel: Host loopback, Origin/Sec-Fetch-Site, sesión y X-CSRF-Token):
- ``GET  /api/egress/ring``            estado atestado por el servidor (nunca IP real ni geolocalización).
- ``POST /api/egress/ring/connect``    conecta (aumenta la protección: no pide reautenticación).
- ``POST /api/egress/ring/disconnect`` desconecta: BLOQUEA el egreso del MCP (y, con lockdown, el del sistema).
- ``POST /api/egress/ring/relay``      cambia el relay de salida o de entrada (solo relays propios y online).

Desconectar y cambiar de relay reducen la protección: exigen contraseña confirmada hace menos de 5 minutos.
Una sola operación a la vez (409 si hay otra). Cada acción queda en el audit.log encadenado. Sin tool MCP: los
agentes no pueden controlar la VPN. Con el panel sin autenticación o fuera de loopback, la vista es de solo lectura.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse

from maltego_mcp.auth import DashboardAuthManager
from maltego_mcp.config import Settings
from maltego_mcp.mullvad import (
    Attestation,
    MullvadError,
    MullvadGate,
    get_gate,
    is_valid_relay_hostname,
    ring_snapshot,
    ring_state,
)

logger = logging.getLogger("maltego_mcp.web.ring")

RING_POLL_MAX_AGE = 5.0  # el panel consulta cada ~5 s; la atestación mostrada nunca supera esa edad
SETTLE_TIMEOUT = 20.0  # espera máxima a que el daemon deje "connecting" tras una acción


def attach_ring_routes(
    app: Starlette,
    *,
    settings: Settings,
    auth_manager: DashboardAuthManager,
    audit_log: Any,
    broadcast: Callable[[dict[str, Any]], None],
    control_enabled: bool,
    gate: MullvadGate | None = None,
) -> None:
    ring_gate = gate or get_gate(
        settings.home, settings.mullvad_socks, settings.mullvad_attest_ttl, remote_check=settings.mullvad_remote_check
    )
    op_lock = asyncio.Lock()
    can_control = bool(control_enabled and auth_manager.enabled)
    readonly_reason = (
        ""
        if can_control
        else (
            "Panel sin autenticación: el control de la VPN está desactivado."
            if not auth_manager.enabled
            else "Panel expuesto fuera de loopback: el control de la VPN está desactivado."
        )
    )

    def _session(request: Request) -> Any:
        return getattr(request.state, "auth_session", None)

    def _payload(att: Attestation, request: Request) -> dict[str, Any]:
        sess = _session(request)
        return {
            "ok": True,
            "ring": ring_snapshot(ring_gate, att),
            "mandatory": settings.require_mullvad,
            "control": {"enabled": can_control, "reason": readonly_reason},
            "busy": op_lock.locked(),
            "reauth_fresh": bool(sess is not None and auth_manager.has_recent_reauth(sess)),
            "server_time": time.time(),
        }

    async def _audit(request: Request, action: str, target: str, before: str, after: str, result: str) -> None:
        sess = _session(request)
        operator = getattr(sess, "username", "") or "anónimo"
        if audit_log is None:
            return
        try:
            await audit_log.record(
                case_id="egress_ring",
                decision="vpn_control",
                reason=f"operador={operator}; accion={action}; antes={before}; despues={after}; resultado={result}",
                method="CLI",
                url=f"mullvad://{action}/{target}" if target else f"mullvad://{action}/",
                status_code=None,
                response_sha256="",
                egress_profile="control",
            )
        except Exception as exc:  # la auditoría nunca debe tumbar la acción, pero se registra en stderr
            logger.error("No se pudo auditar la acción del anillo (%s): %s", action, exc.__class__.__name__)

    async def _body(request: Request) -> dict[str, Any]:
        raw = await request.body()
        if len(raw) > 4096:
            raise ValueError("Carga excesiva.")
        data = json.loads(raw.decode("utf-8")) if raw else {}
        if not isinstance(data, dict):
            raise ValueError("Formato inválido.")
        return data

    async def _settle() -> Attestation:
        """Espera a que el daemon salga de la transición y devuelve una atestación fresca."""
        deadline = time.monotonic() + SETTLE_TIMEOUT
        att = await ring_gate.attest(force=True)
        while att.code == "connecting" and time.monotonic() < deadline:
            await asyncio.sleep(1.0)
            att = await ring_gate.attest(force=True)
        return att

    def _deny(status: int, error: str, **extra: Any) -> JSONResponse:
        return JSONResponse({"ok": False, "error": error, **extra}, status_code=status)

    async def _reauth(request: Request, body: dict[str, Any]) -> JSONResponse | None:
        """Exige contraseña reciente (< 5 min) para acciones que reducen la protección."""
        sess = _session(request)
        if sess is None:
            return _deny(401, "Sesión requerida.")
        if auth_manager.has_recent_reauth(sess):
            return None
        password = str(body.get("password") or "")
        if not password:
            return _deny(401, "Confirma tu contraseña para continuar.", reauth_required=True)
        client_ip = request.client.host if request.client else "127.0.0.1"
        res = await auth_manager.reauthenticate(sess, password, client_ip=client_ip)
        if not res.ok:
            headers = {"Retry-After": str(res.retry_after)} if res.status_code == 429 else {}
            return JSONResponse(
                {
                    "ok": False,
                    "error": res.error,
                    "reauth_required": True,
                    "remaining_attempts": res.remaining_attempts,
                    "retry_after": res.retry_after,
                },
                status_code=res.status_code,
                headers=headers,
            )
        return None

    def _guard_control() -> JSONResponse | None:
        if not can_control:
            return _deny(403, readonly_reason, readonly=True)
        if op_lock.locked():
            return _deny(409, "Ya hay una operación del anillo en curso. Espera a que termine.", busy=True)
        return None

    def _publish(att: Attestation) -> None:
        broadcast({"type": "egress_ring", "state": ring_state(att), "checked_at": att.checked_at})

    # ---------------------------------------------------------------------------------------------- GET
    async def api_ring(request: Request) -> JSONResponse:
        att = await ring_gate.attest(max_age=RING_POLL_MAX_AGE)
        return JSONResponse(_payload(att, request))

    async def api_ring_relays(request: Request) -> JSONResponse:
        reg = ring_gate.registry
        return JSONResponse(
            {
                "ok": True,
                "relays": [r.to_public_dict() for r in reg.all()],
                "source": reg.source,
                "updated_at": reg.updated_at,
            }
        )

    # ---------------------------------------------------------------------------------------------- CONNECT
    async def api_ring_connect(request: Request) -> JSONResponse:
        denied = _guard_control()
        if denied:
            return denied
        async with op_lock:
            before_att = ring_gate.cached or await ring_gate.attest(max_age=RING_POLL_MAX_AGE)
            before = ring_state(before_att)
            try:
                rc, _ = await ring_gate.cli.run("connect")
            except MullvadError as exc:
                await _audit(request, "connect", "", before, before, f"error:{exc}")
                return _deny(502, str(exc))
            att = await _settle()
            after = ring_state(att)
            await _audit(request, "connect", "", before, after, "ok" if rc == 0 else f"rc={rc}")
            _publish(att)
            payload = _payload(att, request)
            if rc != 0:
                payload.update(ok=False, error="Mullvad no pudo conectar. Revisa la cuenta y la app de Mullvad.")
                return JSONResponse(payload, status_code=502)
            return JSONResponse(payload)

    # ---------------------------------------------------------------------------------------------- DISCONNECT
    async def api_ring_disconnect(request: Request) -> JSONResponse:
        denied = _guard_control()
        if denied:
            return denied
        try:
            body = await _body(request)
        except ValueError as exc:
            return _deny(400, str(exc))
        denied = await _reauth(request, body)
        if denied:
            return denied
        async with op_lock:
            before = ring_state(ring_gate.cached or await ring_gate.attest(max_age=RING_POLL_MAX_AGE))
            # D7: el MCP cierra su compuerta ANTES de tocar el túnel: ninguna petición puede colarse en la transición.
            ring_gate.close("desconexión solicitada por el operador")
            try:
                rc, _ = await ring_gate.cli.run("disconnect")
            except MullvadError as exc:
                ring_gate.open()
                await _audit(request, "disconnect", "", before, before, f"error:{exc}")
                return _deny(502, str(exc))
            ring_gate.open()  # desconectado, la atestación falla sola: el egreso queda bloqueado (fail-closed)
            att = await ring_gate.attest(force=True)
            after = ring_state(att)
            await _audit(request, "disconnect", "", before, after, "ok" if rc == 0 else f"rc={rc}")
            _publish(att)
            payload = _payload(att, request)
            if rc != 0:
                payload.update(ok=False, error="Mullvad no confirmó la desconexión.")
                return JSONResponse(payload, status_code=502)
            return JSONResponse(payload)

    # ---------------------------------------------------------------------------------------------- RELAY
    async def api_ring_relay(request: Request) -> JSONResponse:
        denied = _guard_control()
        if denied:
            return denied
        try:
            body = await _body(request)
        except ValueError as exc:
            return _deny(400, str(exc))
        role = str(body.get("role") or "").strip().lower()
        host = str(body.get("hostname") or "").strip().lower()
        if role not in ("exit", "entry"):
            return _deny(400, "El rol debe ser 'exit' o 'entry'.")
        # La lista de la interfaz no es de confianza: validación estricta contra la lista viva de relays propios.
        if not is_valid_relay_hostname(host) or not ring_gate.registry.is_owned(host):
            return _deny(400, "Ese servidor no es un relay propio y online de Mullvad.")
        current = ring_gate.cached
        other = (current.entry_hostname if role == "exit" else current.exit_hostname) if current else ""
        if other and other == host:
            return _deny(400, "La entrada y la salida no pueden ser el mismo servidor.")
        denied = await _reauth(request, body)
        if denied:
            return denied
        async with op_lock:
            before = ring_state(current or await ring_gate.attest(max_age=RING_POLL_MAX_AGE))
            ring_gate.close(f"cambio de relay de {'salida' if role == 'exit' else 'entrada'}")
            try:
                rc, _ = await ring_gate.cli.run("relay_exit" if role == "exit" else "relay_entry", host)
            except MullvadError as exc:
                ring_gate.open()
                await _audit(request, f"relay_{role}", host, before, before, f"error:{exc}")
                return _deny(502, str(exc))
            ring_gate.open()
            att = await _settle()
            after = ring_state(att)
            await _audit(request, f"relay_{role}", host, before, after, "ok" if rc == 0 else f"rc={rc}")
            _publish(att)
            payload = _payload(att, request)
            if rc != 0:
                payload.update(ok=False, error="Mullvad rechazó el cambio de servidor.")
                return JSONResponse(payload, status_code=502)
            return JSONResponse(payload)

    app.add_route("/api/egress/ring", api_ring, methods=["GET"])
    app.add_route("/api/egress/ring/relays", api_ring_relays, methods=["GET"])
    app.add_route("/api/egress/ring/connect", api_ring_connect, methods=["POST"])
    app.add_route("/api/egress/ring/disconnect", api_ring_disconnect, methods=["POST"])
    app.add_route("/api/egress/ring/relay", api_ring_relay, methods=["POST"])
