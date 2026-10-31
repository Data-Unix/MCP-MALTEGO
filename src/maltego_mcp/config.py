"""Configuración por variables de entorno (sin secretos en código)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from maltego_mcp.errors import ConfigError

Backend = Literal["memory", "gremlin"]
DEFAULT_TRANSFORMS_FILE = Path("config/transforms.toml")


@dataclass(frozen=True, slots=True)
class Settings:
    backend: Backend = "memory"
    data_file: Path | None = Path("data/graph.json")
    transforms_file: Path | None = None
    export_dir: Path = Path("exports")
    gremlin_endpoint: str = ""
    gremlin_username: str = ""
    gremlin_password: str = ""

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        e = dict(os.environ if env is None else env)
        backend = e.get("MALTEGO_MCP_BACKEND", "memory").strip().lower()
        if backend not in ("memory", "gremlin"):
            raise ConfigError("MALTEGO_MCP_BACKEND debe ser 'memory' o 'gremlin'.")
        data_file_raw = e.get("MALTEGO_MCP_DATA_FILE", "data/graph.json").strip()
        transforms_raw = e.get("MALTEGO_MCP_TRANSFORMS_FILE", "").strip()
        transforms_file = Path(transforms_raw) if transforms_raw else None
        if transforms_file is None and DEFAULT_TRANSFORMS_FILE.exists():
            transforms_file = DEFAULT_TRANSFORMS_FILE
        settings = cls(
            backend=backend,  # type: ignore[arg-type]
            data_file=Path(data_file_raw) if data_file_raw and data_file_raw.lower() != "none" else None,
            transforms_file=transforms_file,
            export_dir=Path(e.get("MALTEGO_MCP_EXPORT_DIR", "exports")),
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
