"""Configuración por variables de entorno (sin secretos en código).

Por defecto todo el estado vive en un directorio por usuario (`~/.maltego-mcp`), compartido por
todos los worktrees de Orca y por todos los agentes: un único grafo, un único catálogo.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from maltego_mcp.errors import ConfigError

Backend = Literal["memory", "gremlin"]
REPO_TRANSFORMS_FILE = Path("config/transforms.toml")
LEGACY_DATA_FILE = Path("data/graph.json")  # ubicación usada hasta la v0.1 (dentro del repo)


def default_home(env: dict[str, str] | None = None) -> Path:
    e = os.environ if env is None else env
    raw = e.get("MALTEGO_MCP_HOME", "").strip()
    return Path(raw).expanduser() if raw else Path.home() / ".maltego-mcp"


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

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        e = dict(os.environ if env is None else env)
        home = default_home(e)
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
        )
        if settings.backend == "gremlin" and not (
            settings.gremlin_endpoint and settings.gremlin_username and settings.gremlin_password
        ):
            raise ConfigError(
                "El backend gremlin requiere GREMLIN_ENDPOINT, GREMLIN_USERNAME (/dbs/<db>/colls/<grafo>) "
                "y GREMLIN_PASSWORD."
            )
        return settings
