"""Anillo 2: salida obligatoria por Mullvad VPN con relays propios (owned) y atestación doble.

Piezas:
- ``OwnedRelayRegistry``: lista de relays WireGuard **propios y activos** de Mullvad. Arranca con una instantánea
  empaquetada, usa la caché de ``~/.maltego-mcp`` y se refresca (cada hora) desde la API pública de Mullvad, siempre
  a través del túnel. La lista de la interfaz web NUNCA es de confianza: todo hostname se valida aquí.
- ``MullvadCli``: envoltorio mínimo de ``mullvad`` (ruta fija, firma Authenticode "Mullvad VPN AB" en Windows,
  argv en lista, sin shell, timeout y allowlist de subcomandos). Nunca expone lockdown off, account, split-tunnel,
  ownership any, relay custom, api-access ni dns.
- ``MullvadGate``: compuerta fail-closed del MCP. Antes de cada petición exige la atestación doble:
  1) daemon (``mullvad status -j`` + ``lockdown-mode get``): conectado, bloqueo activo, entrada y salida propias;
  2) remota (``am.i.mullvad.net`` a través del proxy SOCKS interno del túnel): ``mullvad_exit_ip`` y relay propio.
  El resultado se cachea con TTL corto. El operador puede cerrar la compuerta (p. ej. antes de desconectar).

Privacidad: la salida de ``status -j`` incluye la IP real y la geolocalización cuando el túnel está caído. Este
módulo las descarta al parsear: solo salen de aquí estados, booleanos y hostnames de relays de Mullvad.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
import time
from collections.abc import Iterable
from importlib import resources
from pathlib import Path
from typing import Any

import httpx

from maltego_mcp.errors import EgressKillSwitchError, MaltegoMcpError

logger = logging.getLogger("maltego_mcp.mullvad")

# ------------------------------------------------------------------------------------- CONSTANTES
MULLVAD_PROXY_IP = "10.64.0.1"  # proxy SOCKS5 del relay de salida actual: solo existe DENTRO del túnel
MULLVAD_SOCKS_PORT = 1080
DEFAULT_MULLVAD_SOCKS = f"socks5h://{MULLVAD_PROXY_IP}:{MULLVAD_SOCKS_PORT}"
MULLVAD_SOCKS_NETWORK = ipaddress.ip_network("10.124.0.0/16")  # proxies SOCKS por relay (socks_name -> 10.124.x.x)
AMI_URL = "https://am.i.mullvad.net/json"
RELAYS_URL = "https://api.mullvad.net/www/relays/wireguard/"
RELAY_CACHE_FILE = "mullvad_owned_relays.json"
RELAY_REFRESH_SECONDS = 3600
MIN_VALID_RELAYS = 20  # una respuesta con menos relays propios se considera anómala y se descarta
SIGNER_SUBJECT = "Mullvad VPN AB"

_HOSTNAME_RE = re.compile(r"^[a-z]{2}-[a-z]{3}-wg-\d{3}$")
_SOCKS_NAME_RE = re.compile(r"^[a-z]{2}-[a-z]{3}-wg-socks5-\d{3}\.relays\.mullvad\.net$")


class MullvadError(MaltegoMcpError):
    """Fallo controlado al consultar o accionar Mullvad (mensaje seguro, sin IP ni geolocalización)."""


def is_valid_relay_hostname(host: str) -> bool:
    """Formato estricto de hostname WireGuard de Mullvad (``se-got-wg-001``)."""
    return bool(_HOSTNAME_RE.fullmatch(host or ""))


def is_mullvad_proxy_endpoint(ip: str, port: int) -> bool:
    """¿Es ``(ip, port)`` un proxy SOCKS interno de Mullvad (10.64.0.1:1080 o 10.124.0.0/16:1080)?"""
    if port != MULLVAD_SOCKS_PORT:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return str(addr) == MULLVAD_PROXY_IP or addr in MULLVAD_SOCKS_NETWORK


# ------------------------------------------------------------------------------------- RELAYS PROPIOS
@dataclasses.dataclass(frozen=True, slots=True)
class OwnedRelay:
    hostname: str
    country_code: str
    country_name: str
    city_code: str
    city_name: str
    socks_name: str

    def to_public_dict(self) -> dict[str, str]:
        return {
            "hostname": self.hostname,
            "country_code": self.country_code,
            "country": self.country_name,
            "city_code": self.city_code,
            "city": self.city_name,
        }


def _parse_relays(rows: Iterable[Any], *, require_flags: bool) -> list[OwnedRelay]:
    """Valida filas de la API (o de la instantánea). Descarta todo lo que no sea WireGuard propio, activo y bien
    formado. ``require_flags`` exige los campos ``owned``/``active``/``type`` (respuesta viva de la API)."""
    out: dict[str, OwnedRelay] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        if require_flags and not (
            row.get("owned") is True and row.get("active") is True and row.get("type", "wireguard") == "wireguard"
        ):
            continue
        host = str(row.get("hostname") or "").strip().lower()
        if not is_valid_relay_hostname(host):
            continue
        socks = str(row.get("socks_name") or "").strip().lower()
        if socks and not _SOCKS_NAME_RE.fullmatch(socks):
            socks = ""
        out[host] = OwnedRelay(
            hostname=host,
            country_code=str(row.get("country_code") or "")[:2].lower(),
            country_name=str(row.get("country_name") or "")[:64],
            city_code=str(row.get("city_code") or "")[:3].lower(),
            city_name=str(row.get("city_name") or "")[:64],
            socks_name=socks,
        )
    return sorted(out.values(), key=lambda r: r.hostname)


def _load_snapshot() -> list[OwnedRelay]:
    try:
        raw = (
            resources.files("maltego_mcp")
            .joinpath("resources", "mullvad_owned_relays.json")
            .read_text(encoding="utf-8")
        )
        doc = json.loads(raw)
        return _parse_relays(doc.get("relays", []), require_flags=False)
    except (OSError, ValueError, AttributeError) as exc:  # pragma: no cover - empaquetado roto
        logger.error("Instantánea de relays propios de Mullvad ilegible: %s", exc)
        return []


class OwnedRelayRegistry:
    """Lista viva de relays propios y online. Fuente: API viva > caché en home > instantánea empaquetada."""

    def __init__(self, cache_path: Path | None = None, refresh_seconds: int = RELAY_REFRESH_SECONDS) -> None:
        self.cache_path = cache_path
        self.refresh_seconds = max(300, int(refresh_seconds))
        self._relays: dict[str, OwnedRelay] = {}
        self.source = "snapshot"
        self.updated_at = 0.0
        self._last_attempt = 0.0
        self._set(_load_snapshot(), "snapshot", 0.0)
        self._load_cache()

    def _set(self, relays: list[OwnedRelay], source: str, updated_at: float) -> None:
        if relays:
            self._relays = {r.hostname: r for r in relays}
            self.source = source
            self.updated_at = updated_at

    def _load_cache(self) -> None:
        if not self.cache_path or not self.cache_path.is_file():
            return
        try:
            doc = json.loads(self.cache_path.read_text(encoding="utf-8"))
            relays = _parse_relays(doc.get("relays", []), require_flags=False)
            if len(relays) >= MIN_VALID_RELAYS:
                self._set(relays, "cache", float(doc.get("updated_at") or 0.0))
        except (OSError, ValueError, AttributeError) as exc:
            logger.warning("Caché de relays Mullvad ilegible, se usa la instantánea: %s", exc)

    def _save_cache(self) -> None:
        if not self.cache_path:
            return
        doc = {
            "source": RELAYS_URL,
            "filter": "owned && active && type == wireguard",
            "updated_at": self.updated_at,
            "relays": [dataclasses.asdict(r) for r in self._relays.values()],
        }
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.cache_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, self.cache_path)
        except OSError as exc:
            logger.warning("No se pudo guardar la caché de relays Mullvad: %s", exc)

    # -- consulta
    def is_owned(self, hostname: str | None) -> bool:
        if not hostname:
            return False
        h = str(hostname).lower()
        if h in self._relays:
            return True
        canonical = re.sub(r"-socks5(?=-\d+$)", "", h)
        return canonical in self._relays

    def get(self, hostname: str | None) -> OwnedRelay | None:
        if not hostname:
            return None
        h = str(hostname).lower()
        relay = self._relays.get(h)
        if relay is not None:
            return relay
        canonical = re.sub(r"-socks5(?=-\d+$)", "", h)
        return self._relays.get(canonical)

    def all(self) -> list[OwnedRelay]:
        return list(self._relays.values())

    def __len__(self) -> int:
        return len(self._relays)

    def needs_refresh(self, now: float | None = None) -> bool:
        t = time.time() if now is None else now
        return (t - self.updated_at) >= self.refresh_seconds and (t - self._last_attempt) >= 300

    async def refresh(self, client: httpx.AsyncClient) -> bool:
        """Descarga la lista viva (por el túnel) y la adopta si es coherente. Nunca amplía la confianza: solo
        relays ``owned && active`` con hostname bien formado."""
        self._last_attempt = time.time()
        try:
            resp = await client.get(RELAYS_URL)
            if resp.status_code != 200:
                return False
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.info("Refresco de relays Mullvad fallido (%s); se mantiene %s", exc.__class__.__name__, self.source)
            return False
        relays = _parse_relays(data if isinstance(data, list) else [], require_flags=True)
        if len(relays) < MIN_VALID_RELAYS:
            logger.warning("Lista de relays Mullvad anómala (%d propios); se descarta", len(relays))
            return False
        self._set(relays, "live", time.time())
        self._save_cache()
        return True


# ------------------------------------------------------------------------------------- CLI
def default_cli_path() -> Path:
    """Ruta fija del binario oficial. No se busca en PATH (evita binarios suplantados)."""
    if sys.platform == "win32":
        base = os.environ.get("PROGRAMW6432") or os.environ.get("PROGRAMFILES") or r"C:\Program Files"
        return Path(base) / "Mullvad VPN" / "resources" / "mullvad.exe"
    if sys.platform == "darwin":
        return Path("/usr/local/bin/mullvad")
    return Path("/usr/bin/mullvad")


# Subcomandos permitidos. Nada más se puede ejecutar desde el MCP o el panel.
_READ_ACTIONS = {
    "status": ("status", "-j"),
    "lockdown_get": ("lockdown-mode", "get"),
}
_WRITE_ACTIONS = {
    "connect": ("connect", "--wait"),
    "disconnect": ("disconnect", "--wait"),
    "reconnect": ("reconnect", "--wait"),
    "relay_exit": ("relay", "set", "location"),  # + hostname validado
    "relay_entry": ("relay", "set", "entry", "location"),  # + hostname validado
}
WRITE_ACTIONS = frozenset(_WRITE_ACTIONS)


def build_argv(cli: Path, action: str, hostname: str = "") -> list[str]:
    """Construye el argv de una acción de la allowlist. Los relays exigen hostname con formato estricto."""
    if action in _READ_ACTIONS:
        return [str(cli), *_READ_ACTIONS[action]]
    if action not in _WRITE_ACTIONS:
        raise MullvadError(f"Acción de Mullvad no permitida: {action!r}")
    argv = [str(cli), *_WRITE_ACTIONS[action]]
    if action.startswith("relay_"):
        if not is_valid_relay_hostname(hostname):
            raise MullvadError("Hostname de relay inválido.")
        argv.append(hostname)
    elif hostname:
        raise MullvadError("Esta acción no admite parámetros.")
    return argv


@dataclasses.dataclass(frozen=True, slots=True)
class DaemonStatus:
    """Estado del daemon SIN IP real ni geolocalización."""

    state: str  # connected | connecting | disconnected | disconnecting | error | unknown
    locked_down: bool | None
    exit_hostname: str
    entry_hostname: str
    error_cause: str = ""


def parse_status(raw: Any, lockdown: bool | None = None) -> DaemonStatus:
    """Reduce ``mullvad status -j`` a lo imprescindible. Descarta ipv4/ipv6/lat/lon/city/country."""
    if not isinstance(raw, dict):
        return DaemonStatus("unknown", lockdown, "", "")
    state = str(raw.get("state") or "unknown").lower()
    d_raw = raw.get("details")
    details: dict[str, Any] = d_raw if isinstance(d_raw, dict) else {}
    l_raw = details.get("location")
    loc: dict[str, Any] = l_raw if isinstance(l_raw, dict) else {}
    exit_host = str(loc.get("hostname") or "").lower() if state in ("connected", "connecting") else ""
    entry_host = str(loc.get("entry_hostname") or "").lower() if state in ("connected", "connecting") else ""
    if exit_host and not is_valid_relay_hostname(exit_host):
        exit_host = "?"
    if entry_host and not is_valid_relay_hostname(entry_host):
        entry_host = "?"
    ld = details.get("locked_down")
    locked = ld if isinstance(ld, bool) else lockdown
    cause = ""
    if state == "error":
        c = details.get("cause")
        cause = (json.dumps(c) if not isinstance(c, str) else c)[:120] if c else "error"
        cause = re.sub(r"\d{1,3}(?:\.\d{1,3}){3}", "[ip]", cause)
    return DaemonStatus(state, locked, exit_host, entry_host, cause)


def parse_lockdown(text: str) -> bool | None:
    t = (text or "").strip().lower()
    if t.endswith(": on") or t.endswith(" on"):
        return True
    if t.endswith(": off") or t.endswith(" off"):
        return False
    return None


class MullvadCli:
    """Ejecuta el binario oficial de Mullvad con argv en lista, sin shell, con timeout y firma verificada."""

    def __init__(self, path: Path | None = None, timeout: float = 25.0, verify_signature: bool = True) -> None:
        self.path = path or default_cli_path()
        self.timeout = timeout
        self.verify_signature = verify_signature
        self._sig_cache: tuple[tuple[int, int], bool, str] | None = None

    def _signature_ok_sync(self) -> tuple[bool, str]:
        p = self.path
        if not p.is_absolute() or not p.is_file():
            return False, "cli_missing"
        if not self.verify_signature or sys.platform != "win32":
            return True, ""
        st = p.stat()
        key = (int(st.st_mtime_ns), int(st.st_size))
        if self._sig_cache and self._sig_cache[0] == key:
            return self._sig_cache[1], self._sig_cache[2]
        ps = (
            Path(os.environ.get("SYSTEMROOT", r"C:\Windows"))
            / "System32"
            / "WindowsPowerShell"
            / "v1.0"
            / "powershell.exe"
        )
        literal = str(p).replace("'", "''")
        script = (
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
            f"$s = Get-AuthenticodeSignature -LiteralPath '{literal}'; "
            "Write-Output ('{0}|{1}' -f $s.Status, $s.SignerCertificate.Subject)"
        )
        try:
            res = subprocess.run(
                [str(ps), "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                check=False,
            )
            status, _, subject = res.stdout.strip().partition("|")
            stdout = res.stdout or ""
            status, _, subject = stdout.strip().partition("|")
            ok = status.strip() == "Valid" and f"O={SIGNER_SUBJECT}" in subject
        except (OSError, subprocess.SubprocessError):
            ok = False
        result = (ok, "" if ok else "cli_unsigned")
        self._sig_cache = (key, result[0], result[1])
        return result

    def _run_sync(self, action: str, hostname: str = "") -> tuple[int, str]:
        ok, code = self._signature_ok_sync()
        if not ok:
            raise MullvadError(
                "Binario de Mullvad no encontrado."
                if code == "cli_missing"
                else "Firma del binario de Mullvad no válida."
            )
        argv = build_argv(self.path, action, hostname)
        try:
            res = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                stdin=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise MullvadError(f"Mullvad no respondió en {int(self.timeout)} s ({action}).") from exc
        except OSError as exc:
            raise MullvadError(f"No se pudo ejecutar Mullvad ({exc.__class__.__name__}).") from exc
        return res.returncode, res.stdout
        return res.returncode, res.stdout or ""

    async def run(self, action: str, hostname: str = "") -> tuple[int, str]:
        # subprocess.run en hilo: funciona con cualquier bucle (uvicorn puede usar SelectorEventLoop en Windows).
        return await asyncio.to_thread(self._run_sync, action, hostname)

    async def signature_code(self) -> str:
        ok, code = await asyncio.to_thread(self._signature_ok_sync)
        return "" if ok else code

    async def status(self) -> DaemonStatus:
        rc, out = await self.run("status")
        if rc != 0:
            raise MullvadError("El daemon de Mullvad no responde.")
        try:
            raw = json.loads(out)
        except ValueError as exc:
            raise MullvadError("Salida de estado de Mullvad ilegible.") from exc
        lockdown: bool | None = None
        details = raw.get("details") if isinstance(raw, dict) else None
        if not (isinstance(details, dict) and isinstance(details.get("locked_down"), bool)):
            with contextlib.suppress(MullvadError):
                rc2, out2 = await self.run("lockdown_get")
                lockdown = parse_lockdown(out2) if rc2 == 0 else None
        return parse_status(raw, lockdown)


# ------------------------------------------------------------------------------------- ATESTACIÓN Y COMPUERTA
@dataclasses.dataclass(frozen=True, slots=True)
class Attestation:
    ok: bool
    code: str  # ok | cli_missing | cli_unsigned | daemon | disconnected | connecting | error |
    #            lockdown_off | rented_exit | rented_entry | remote_failed | remote_not_mullvad | remote_mismatch
    reason: str
    checked_at: float
    state: str = "unknown"
    locked_down: bool | None = None
    exit_hostname: str = ""
    entry_hostname: str = ""
    exit_owned: bool = False
    entry_owned: bool = False
    remote_checked: bool = False
    remote_ok: bool = False
    remote_hostname_verified: bool = False
    error_cause: str = ""
    gate_closed: bool = False  # el operador cerró la compuerta (transición): bloquea aunque el daemon esté bien


def _fail(code: str, reason: str, **kw: Any) -> Attestation:
    return Attestation(ok=False, code=code, reason=reason, checked_at=time.time(), **kw)


class MullvadGate:
    """Compuerta fail-closed del egreso del MCP (Anillo 2)."""

    def __init__(
        self,
        cli: MullvadCli | None = None,
        registry: OwnedRelayRegistry | None = None,
        socks_url: str = DEFAULT_MULLVAD_SOCKS,
        ttl_seconds: float = 30.0,
        remote_check: bool = True,
        remote_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.cli = cli or MullvadCli()
        self.registry = registry or OwnedRelayRegistry()
        self.socks_url = socks_url
        self.ttl = max(5.0, float(ttl_seconds))
        self.remote_check = remote_check
        self._remote_transport = remote_transport
        self._cached: Attestation | None = None
        self._closed_reason = ""
        self._locks: dict[int, asyncio.Lock] = {}

    # -- cierre manual (D7: antes de desconectar/cambiar de relay)
    @property
    def closed(self) -> bool:
        return bool(self._closed_reason)

    @property
    def closed_reason(self) -> str:
        return self._closed_reason

    def close(self, reason: str) -> None:
        self._closed_reason = reason or "cerrada por el operador"
        self._cached = None

    def open(self) -> None:
        self._closed_reason = ""
        self._cached = None

    def invalidate(self) -> None:
        self._cached = None

    @property
    def cached(self) -> Attestation | None:
        return self._cached

    def _lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        lk = self._locks.get(id(loop))
        if lk is None:
            self._locks = {id(loop): (lk := asyncio.Lock())}
        return lk

    def _proxy_client(self, timeout: float = 10.0) -> httpx.AsyncClient:
        from maltego_mcp.egress import create_mullvad_probe_client  # único punto de salida HTTP: egress.py

        return create_mullvad_probe_client(self.socks_url, timeout=timeout, transport=self._remote_transport)

    async def _remote(self, expected_exit: str) -> tuple[bool, str, bool]:
        """Comprobación remota por el proxy interno del túnel. Devuelve (ok, código, hostname_verificado)."""
        try:
            async with self._proxy_client() as client:
                resp = await client.get(AMI_URL)
                if resp.status_code != 200:
                    return False, "remote_failed", False
                data = resp.json()
                if self.registry.needs_refresh():
                    await self.registry.refresh(client)
        except (httpx.HTTPError, ValueError, OSError) as exc:
            logger.info("Atestación remota Mullvad fallida: %s", exc.__class__.__name__)
            return False, "remote_failed", False
        if not isinstance(data, dict) or data.get("mullvad_exit_ip") is not True:
            return False, "remote_not_mullvad", False
        remote_host = str(data.get("mullvad_exit_ip_hostname") or "").lower()
        if remote_host:
            # Los proxies SOCKS5 internos de Mullvad en WireGuard (10.64.0.1:1080) se anuncian
            # en am.i.mullvad.net con el sufijo '-socks5-', ej. 'de-dus-wg-socks5-101'.
            canonical_host = re.sub(r"-socks5(?=-\d+$)", "", remote_host)
            if not self.registry.is_owned(canonical_host):
                return False, "rented_exit", True
            if expected_exit and canonical_host != expected_exit:
                return False, "remote_mismatch", True
            return True, "ok", True
        return True, "ok", False

    async def attest(self, force: bool = False, max_age: float | None = None) -> Attestation:
        """Atestación con caché (``ttl`` o ``max_age`` si es menor). Con la compuerta cerrada se informa del estado
        real del daemon pero el resultado nunca es ``ok``."""
        if self._closed_reason:
            att = await self._attest_uncached(remote=False)
            return dataclasses.replace(
                att, ok=False, gate_closed=True, reason=f"Compuerta cerrada: {self._closed_reason}"
            )
        limit = self.ttl if max_age is None else min(self.ttl, max(0.0, max_age))
        cached = self._cached
        if not force and cached is not None and (time.time() - cached.checked_at) < limit:
            return cached
        async with self._lock():
            cached = self._cached
            if not force and cached is not None and (time.time() - cached.checked_at) < limit:
                return cached
            att = await self._attest_uncached()
            if not self._closed_reason:
                self._cached = att
            return att

    async def _attest_uncached(self, remote: bool = True) -> Attestation:
        sig = await self.cli.signature_code()
        if sig:
            reason = "Mullvad no está instalado." if sig == "cli_missing" else "La firma de mullvad.exe no es válida."
            return _fail(sig, reason)
        try:
            st = await self.cli.status()
        except MullvadError as exc:
            return _fail("daemon", str(exc))
        base: dict[str, Any] = {
            "state": st.state,
            "locked_down": st.locked_down,
            "exit_hostname": st.exit_hostname,
            "entry_hostname": st.entry_hostname,
            "exit_owned": self.registry.is_owned(st.exit_hostname),
            "entry_owned": self.registry.is_owned(st.entry_hostname) if st.entry_hostname else True,
            "error_cause": st.error_cause,
        }
        if st.state == "error":
            return _fail("error", "El daemon de Mullvad está en estado de error (bloqueando).", **base)
        if st.state in ("connecting", "disconnecting"):
            return _fail("connecting", "Mullvad está cambiando de estado.", **base)
        if st.state != "connected":
            return _fail("disconnected", "Mullvad no está conectado.", **base)
        if st.locked_down is not True:
            return _fail("lockdown_off", "El bloqueo de Mullvad (lockdown) está desactivado.", **base)
        if not base["exit_owned"]:
            return _fail("rented_exit", "El relay de salida no es propio de Mullvad.", **base)
        if not base["entry_owned"]:
            return _fail("rented_entry", "El relay de entrada no es propio de Mullvad.", **base)
        if not (self.remote_check and remote):
            return Attestation(ok=True, code="ok", reason="Atestación local superada.", checked_at=time.time(), **base)
        ok, code, verified = await self._remote(st.exit_hostname)
        if not ok:
            reasons = {
                "remote_failed": "La comprobación remota por el túnel falló.",
                "remote_not_mullvad": "am.i.mullvad.net no confirma una salida de Mullvad.",
                "rented_exit": "La salida vista desde fuera no es un relay propio.",
                "remote_mismatch": "La salida vista desde fuera no coincide con la del daemon.",
            }
            return _fail(code, reasons.get(code, code), remote_checked=True, remote_hostname_verified=verified, **base)
        return Attestation(
            ok=True,
            code="ok",
            reason="Atestación doble superada.",
            checked_at=time.time(),
            remote_checked=True,
            remote_ok=True,
            remote_hostname_verified=verified,
            **base,
        )

    async def ensure(self) -> Attestation:
        """Exige la atestación. Fail-closed: cualquier fallo lanza ``EgressKillSwitchError``."""
        if self._closed_reason:
            raise EgressKillSwitchError(
                f"Compuerta Mullvad cerrada por el operador ({self._closed_reason}). Petición abortada."
            )
        att = await self.attest()
        if not att.ok:
            raise EgressKillSwitchError(
                f"Compuerta Mullvad cerrada ({att.code}): {att.reason} Petición abortada sin salir a la red."
            )
        return att


# ------------------------------------------------------------------------------------- SINGLETON DE PROCESO
_GATE: MullvadGate | None = None
_GATE_OVERRIDE: MullvadGate | None = None


def get_gate(
    home: Path | None = None,
    socks_url: str = DEFAULT_MULLVAD_SOCKS,
    ttl_seconds: float = 30.0,
    remote_check: bool = True,
) -> MullvadGate:
    """Compuerta única del proceso (caché de atestación y cierre manual compartidos por MCP y panel). La primera
    llamada fija la configuración; las siguientes reutilizan la misma instancia."""
    global _GATE
    if _GATE_OVERRIDE is not None:
        return _GATE_OVERRIDE
    if _GATE is None:
        cache = (home / RELAY_CACHE_FILE) if home else None
        _GATE = MullvadGate(
            registry=OwnedRelayRegistry(cache),
            socks_url=socks_url,
            ttl_seconds=ttl_seconds,
            remote_check=remote_check,
        )
    return _GATE


def set_gate_for_tests(gate: MullvadGate | None) -> None:
    """Sustituye la compuerta del proceso (solo tests)."""
    global _GATE_OVERRIDE
    _GATE_OVERRIDE = gate


# ------------------------------------------------------------------------------------- ESTADO DEL ANILLO (PANEL)
RING_STATES = (
    "protected",  # conectado, bloqueo activo, entrada/salida propias y atestación remota superada
    "unverified",  # conectado y propio, pero la comprobación remota falla
    "connecting",
    "blocked",  # desconectado con bloqueo: nada sale (seguro, pero sin servicio)
    "unlocked",  # desconectado o conectado SIN bloqueo: peligro para los agentes
    "rented",  # relay no propio: el MCP bloquea
    "daemon",  # daemon caído, CLI ausente o sin firma válida
    "account",  # cuenta caducada / sin sesión
    "error",
)


def ring_state(att: Attestation) -> str:
    if att.ok:
        return "protected"
    code = att.code
    if att.gate_closed and code == "ok":
        return "connecting"  # el daemon está bien pero hay una operación del operador en curso
    if code in ("cli_missing", "cli_unsigned", "daemon"):
        return "daemon"
    if code == "error":
        cause = att.error_cause.lower()
        return "account" if any(k in cause for k in ("auth", "account", "expired", "time")) else "error"
    if code == "connecting":
        return "connecting"
    if code == "disconnected":
        return "blocked" if att.locked_down else "unlocked"
    if code == "lockdown_off":
        return "unlocked"
    if code in ("rented_exit", "rented_entry"):
        return "rented"
    if code in ("remote_failed", "remote_not_mullvad", "remote_mismatch"):
        return "unverified"
    return "error"


def ring_snapshot(gate: MullvadGate, att: Attestation) -> dict[str, Any]:
    """Vista pública del anillo para el panel. Sin IP real ni geolocalización del operador."""
    reg = gate.registry

    def relay(host: str) -> dict[str, Any] | None:
        if not host:
            return None
        r = reg.get(host)
        if r is None:
            return {"hostname": host if is_valid_relay_hostname(host) else "?", "owned": False}
        return r.to_public_dict() | {"owned": True}

    connected = att.state == "connected"
    checks = [
        {"id": "daemon", "ok": att.code not in ("cli_missing", "cli_unsigned", "daemon")},
        {"id": "lockdown", "ok": att.locked_down is True},
        {"id": "entry", "ok": connected and att.entry_owned},
        {"id": "exit", "ok": connected and att.exit_owned},
        {"id": "remote", "ok": att.remote_ok},
        {"id": "gate", "ok": att.ok and not att.gate_closed},
    ]
    return {
        "state": ring_state(att),
        "code": att.code,
        "reason": att.reason,
        "checked_at": att.checked_at,
        "daemon_state": att.state,
        "locked_down": att.locked_down,
        "exit": relay(att.exit_hostname),
        "entry": relay(att.entry_hostname) if att.entry_hostname and att.entry_hostname != att.exit_hostname else None,
        "remote_hostname_verified": att.remote_hostname_verified,
        "gate_open": att.ok and not att.gate_closed,
        "gate_closed_reason": gate.closed_reason,
        "checks": checks,
        "relays": {"count": len(reg), "source": reg.source, "updated_at": reg.updated_at},
    }
