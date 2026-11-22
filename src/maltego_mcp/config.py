"""Configuración por variables de entorno (sin secretos en código).

Por defecto todo el estado vive en un directorio por usuario (`~/.maltego-mcp`), compartido por
todos los worktrees de Orca y por todos los agentes: un único grafo, un único catálogo.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from maltego_mcp.errors import ConfigError

logger = logging.getLogger("maltego_mcp.config")

Backend = Literal["memory", "gremlin"]
REPO_TRANSFORMS_FILE = Path("config/transforms.toml")
LEGACY_DATA_FILE = Path("data/graph.json")  # ubicación usada hasta la v0.1 (dentro del repo)
ONTOLOGY_FILE = "entities.json"  # ontología importada de Maltego (maltegoctl import-entities)
ENV_FILE = ".env"  # claves opcionales de proveedores en ~/.maltego-mcp/.env (fuera del repo)


def default_home(env: dict[str, str] | None = None) -> Path:
    e = os.environ if env is None else env
    raw = e.get("MALTEGO_MCP_HOME", "").strip()
    return Path(raw).expanduser() if raw else Path.home() / ".maltego-mcp"


def parse_dotenv(text: str) -> dict[str, str]:
    """Parsea un fichero .env sencillo (CLAVE=valor, comentarios #, comillas opcionales) sin dependencias."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        key, _, val = line.partition("=")
        k = key.strip()
        v = val.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
            v = v[1:-1]
        elif " #" in v:
            v = v.split(" #", 1)[0].strip()
        if k and v:
            out[k] = v
    return out


def load_home_dotenv(home: Path | None = None, base_env: dict[str, str] | None = None) -> dict[str, str]:
    """Combina ~/.maltego-mcp/.env (si existe) con el entorno; las variables del entorno tienen prioridad."""
    env = dict(os.environ if base_env is None else base_env)
    target = (home or default_home(env)) / ENV_FILE
    try:
        file_vars = parse_dotenv(target.read_text(encoding="utf-8")) if target.is_file() else {}
    except OSError:
        file_vars = {}
    for k, v in file_vars.items():
        if not env.get(k, "").strip():
            env[k] = v
    return env


_MULLVAD_COMPATIBLE_PROFILES = ("mullvad", "tor")


def _validate_mullvad_socks(url: str) -> None:
    """El proxy del Anillo 2 solo puede ser un SOCKS interno de Mullvad (10.64.0.1 o 10.124.0.0/16, puerto 1080)."""
    import urllib.parse

    from maltego_mcp.mullvad import is_mullvad_proxy_endpoint

    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("socks5", "socks5h") or parsed.username or parsed.password:
        raise ConfigError("MALTEGO_MCP_MULLVAD_SOCKS debe ser socks5h://10.64.0.1:1080 (sin credenciales).")
    if not is_mullvad_proxy_endpoint(parsed.hostname or "", parsed.port or 0):
        raise ConfigError(
            "MALTEGO_MCP_MULLVAD_SOCKS solo admite el proxy interno de Mullvad (10.64.0.1:1080 o 10.124.x.x:1080)."
        )


def _enforce_mullvad(egress: str, per_provider: str) -> tuple[str, str]:
    """Con Mullvad obligatorio el perfil efectivo es `mullvad` (o `tor`, que también exige la atestación).
    `direct` y `vpn` se elevan a `mullvad` con aviso; los overrides por proveedor no pueden rebajar el perfil."""
    if egress not in _MULLVAD_COMPATIBLE_PROFILES:
        if egress != "direct":
            logger.warning("MALTEGO_MCP_EGRESS=%s ignorado: Mullvad es obligatorio (perfil efectivo: mullvad).", egress)
        egress = "mullvad"
    pairs: list[str] = []
    for item in per_provider.split(","):
        if "=" not in item:
            continue
        prov, prof = (x.strip() for x in item.split("=", 1))
        if prof.lower() not in _MULLVAD_COMPATIBLE_PROFILES:
            raise ConfigError(
                f"MALTEGO_MCP_EGRESS_PER_PROVIDER: '{prov}={prof}' rebajaría el Anillo Mullvad obligatorio. "
                "Solo se admiten 'mullvad' o 'tor' (o desactiva MALTEGO_MCP_REQUIRE_MULLVAD de forma consciente)."
            )
        pairs.append(f"{prov}={prof.lower()}")
    return egress, ",".join(pairs)


@dataclass(frozen=True, slots=True)
class Settings:
    backend: Backend = "memory"
    home: Path = field(default_factory=default_home)
    data_file: Path | None = None
    transforms_file: Path | None = None
    export_dir: Path = field(default_factory=lambda: default_home() / "exports")
    import_dir: Path = field(default_factory=lambda: default_home() / "imports")
    gremlin_endpoint: str = ""
    gremlin_username: str = ""
    gremlin_password: str = ""
    egress: str = "direct"
    egress_proxy: str = ""
    tor_socks: str = "socks5h://127.0.0.1:9050"
    tor_control: str = ""
    tor_control_password: str = ""
    tor_rotation: str = "per_provider"
    egress_per_provider: str = ""
    egress_check_min: int = 15
    # Anillo 2 (Mullvad obligatorio). El dataclass lo deja apagado (tests, embebidos); `from_env` lo enciende por
    # defecto (MALTEGO_MCP_REQUIRE_MULLVAD=1): todo el egreso del MCP sale por el proxy SOCKS interno del túnel y
    # solo tras la atestación doble (daemon + am.i.mullvad.net) con relays propios.
    require_mullvad: bool = False
    mullvad_socks: str = "socks5h://10.64.0.1:1080"
    mullvad_attest_ttl: int = 30
    mullvad_remote_check: bool = True
    mullvad_isolation: str = "off"
    mode: str = "passive"
    dashboard_auth: bool = False
    dashboard_user: str = "admin"
    dashboard_password_hash: str = ""
    dashboard_session_ttl: int = 28800

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        raw_env = dict(os.environ if env is None else env)
        home = default_home(raw_env)
        e = load_home_dotenv(home, raw_env)
        backend = e.get("MALTEGO_MCP_BACKEND", "memory").strip().lower()
        if backend not in ("memory", "gremlin"):
            raise ConfigError("MALTEGO_MCP_BACKEND debe ser 'memory' o 'gremlin'.")

        data_raw = e.get("MALTEGO_MCP_DATA_FILE", "").strip()
        if data_raw.lower() == "none":
            data_file: Path | None = None
        else:
            data_file = Path(data_raw).expanduser() if data_raw else home / "graph.json"

        transforms_raw = e.get("MALTEGO_MCP_TRANSFORMS_FILE", "").strip()
        transforms_file: Path | None
        if transforms_raw:
            transforms_file = Path(transforms_raw).expanduser()
        elif (home / "transforms.toml").exists():
            transforms_file = home / "transforms.toml"
        elif REPO_TRANSFORMS_FILE.exists():
            transforms_file = REPO_TRANSFORMS_FILE
        else:
            transforms_file = None

        egress = e.get("MALTEGO_MCP_EGRESS", "direct").strip().lower()
        if egress not in ("direct", "vpn", "tor", "mullvad"):
            egress = "direct"

        require_mullvad = e.get("MALTEGO_MCP_REQUIRE_MULLVAD", "1").strip().lower() not in ("0", "false", "no", "off")
        per_provider = e.get("MALTEGO_MCP_EGRESS_PER_PROVIDER", "").strip()
        mullvad_socks = e.get("MALTEGO_MCP_MULLVAD_SOCKS", "").strip() or "socks5h://10.64.0.1:1080"
        _validate_mullvad_socks(mullvad_socks)
        isolation = e.get("MALTEGO_MCP_MULLVAD_ISOLATION", "off").strip().lower()
        if isolation not in ("off", "per_provider"):
            raise ConfigError("MALTEGO_MCP_MULLVAD_ISOLATION debe ser 'off' o 'per_provider'.")
        if require_mullvad:
            egress, per_provider = _enforce_mullvad(egress, per_provider)
        try:
            attest_ttl = max(5, min(300, int(e.get("MALTEGO_MCP_MULLVAD_ATTEST_TTL", "30").strip())))
        except ValueError:
            attest_ttl = 30
        remote_check = e.get("MALTEGO_MCP_MULLVAD_REMOTE_CHECK", "1").strip().lower() not in ("0", "false", "no", "off")

        check_min_raw = e.get("MALTEGO_MCP_EGRESS_CHECK_MIN", "15").strip()
        try:
            check_min = int(check_min_raw)
        except ValueError:
            check_min = 15

        mode = e.get("MALTEGO_MCP_MODE", "").strip().lower()
        if e.get("MALTEGO_MCP_ALLOW_ACTIVE", "").strip() in ("1", "true", "yes"):
            mode = "active"
        elif mode not in ("passive", "active"):
            mode = "passive"

        dash_auth_raw = e.get("MALTEGO_MCP_DASHBOARD_AUTH", "1").strip().lower()
        dashboard_auth = dash_auth_raw not in ("0", "false", "no", "off")
        dashboard_user = e.get("MALTEGO_MCP_DASHBOARD_USER", "admin").strip() or "admin"
        dashboard_password_hash = e.get("MALTEGO_MCP_DASHBOARD_PASSWORD_HASH", "").strip()
        if not dashboard_password_hash:
            raw_pwd = e.get("MALTEGO_MCP_DASHBOARD_PASSWORD", "").strip()
            if raw_pwd:
                from maltego_mcp.auth import hash_password_pbkdf2

                dashboard_password_hash = hash_password_pbkdf2(raw_pwd)

        ttl_raw = e.get("MALTEGO_MCP_DASHBOARD_SESSION_TTL", "28800").strip()
        try:
            dashboard_session_ttl = max(300, int(ttl_raw))
        except ValueError:
            dashboard_session_ttl = 28800

        settings = cls(
            backend=backend,  # type: ignore[arg-type]
            home=home,
            data_file=data_file,
            transforms_file=transforms_file,
            export_dir=Path(e.get("MALTEGO_MCP_EXPORT_DIR", "") or home / "exports").expanduser(),
            import_dir=Path(e.get("MALTEGO_MCP_IMPORT_DIR", "") or home / "imports").expanduser(),
            gremlin_endpoint=e.get("GREMLIN_ENDPOINT", ""),
            gremlin_username=e.get("GREMLIN_USERNAME", ""),
            gremlin_password=e.get("GREMLIN_PASSWORD", ""),
            egress=egress,
            egress_proxy=e.get("MALTEGO_MCP_EGRESS_PROXY", "").strip(),
            tor_socks=e.get("MALTEGO_MCP_TOR_SOCKS", "socks5h://127.0.0.1:9050").strip(),
            tor_control=e.get("MALTEGO_MCP_TOR_CONTROL", "").strip(),
            tor_control_password=e.get("MALTEGO_MCP_TOR_CONTROL_PASSWORD", "").strip(),
            tor_rotation=e.get("MALTEGO_MCP_TOR_ROTATION", "per_provider").strip().lower(),
            egress_per_provider=per_provider,
            egress_check_min=check_min,
            require_mullvad=require_mullvad,
            mullvad_socks=mullvad_socks,
            mullvad_attest_ttl=attest_ttl,
            mullvad_remote_check=remote_check,
            mullvad_isolation=isolation,
            mode=mode,
            dashboard_auth=dashboard_auth,
            dashboard_user=dashboard_user,
            dashboard_password_hash=dashboard_password_hash,
            dashboard_session_ttl=dashboard_session_ttl,
        )
        if settings.backend == "gremlin" and not (
            settings.gremlin_endpoint and settings.gremlin_username and settings.gremlin_password
        ):
            raise ConfigError(
                "El backend gremlin requiere GREMLIN_ENDPOINT, GREMLIN_USERNAME (/dbs/<db>/colls/<grafo>) "
                "y GREMLIN_PASSWORD."
            )
        return settings
