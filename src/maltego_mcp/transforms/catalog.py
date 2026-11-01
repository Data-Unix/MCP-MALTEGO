"""Catálogo de transforms disponibles (fichero TOML).

Los servidores TRX/iTDS no exponen un listado de transforms, por eso se declaran aquí.
Las URLs solo salen de este fichero: el agente nunca puede indicar una URL arbitraria (anti-SSRF).
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from maltego_mcp.errors import ConfigError, InvalidInput
from maltego_mcp.machines import MachineCatalog, load_machines
from maltego_mcp.transforms.builtin import BUILTIN_TRANSFORMS, BuiltinTransform

_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


@dataclass(frozen=True, slots=True)
class TransformServer:
    name: str
    url: str
    api_key_env: str = ""
    timeout_s: float = 60.0

    def headers(self) -> dict[str, str]:
        if self.api_key_env:
            key = os.environ.get(self.api_key_env, "")
            if not key:
                raise ConfigError(f"Falta la variable de entorno {self.api_key_env} para el servidor '{self.name}'.")
            return {"Authorization": f"Bearer {key}"}
        return {}


@dataclass(frozen=True, slots=True)
class TransformSpec:
    name: str
    server: TransformServer
    path: str
    input_types: tuple[str, ...]
    output_types: tuple[str, ...] = ()
    description: str = ""
    settings: dict[str, str] = field(default_factory=dict)
    builtin: BuiltinTransform | None = None
    category: str = "servidor"

    @property
    def requires(self) -> tuple[str, ...]:
        return self.builtin.requires if self.builtin else ()

    def available(self, env: dict[str, str]) -> bool:
        return self.builtin.available(env) if self.builtin else True

    @property
    def origin(self) -> str:
        return "integrado" if self.builtin else f"servidor {self.server.name}"

    def accepts(self, maltego_type: str) -> bool:
        return not self.input_types or maltego_type.lower() in {t.lower() for t in self.input_types}

    @property
    def run_url(self) -> str:
        return f"{self.server.url.rstrip('/')}/run/{self.path}/"


BUILTIN_SERVER = TransformServer(name="integrado", url="builtin://maltego-mcp", timeout_s=30.0)


def builtin_specs() -> dict[str, TransformSpec]:
    return {
        b.name.lower(): TransformSpec(
            name=b.name,
            server=BUILTIN_SERVER,
            path=b.name.lower(),
            input_types=b.input_types,
            output_types=b.output_types,
            description=b.description,
            builtin=b,
            category=b.category,
        )
        for b in BUILTIN_TRANSFORMS
    }


@dataclass(frozen=True, slots=True)
class TransformCatalog:
    transforms: dict[str, TransformSpec] = field(default_factory=dict)
    machines: MachineCatalog = field(default_factory=lambda: load_machines([]))

    def with_builtins(self) -> TransformCatalog:
        """Integrados + los del fichero (si coinciden de nombre, gana el del fichero)."""
        return TransformCatalog({**builtin_specs(), **self.transforms}, self.machines)

    def get(self, name: str) -> TransformSpec:
        spec = self.transforms.get(name.lower())
        if spec is None:
            available = ", ".join(sorted(s.name for s in self.transforms.values())[:30]) or "ninguno"
            raise InvalidInput(f"El transform '{name[:80]}' no está en el catálogo. Disponibles: {available}.")
        return spec


def _validate_url(url: str, server: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ConfigError(f"URL inválida para el servidor de transforms '{server}': usa http(s)://host:puerto.")
    return url


def load_catalog(path: Path | None) -> TransformCatalog:
    if path is None:
        return TransformCatalog()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"No existe el catálogo de transforms {path}.") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Catálogo de transforms {path.name} con TOML inválido: {exc}.") from exc

    servers: dict[str, TransformServer] = {}
    for raw in data.get("servers", []):
        name = str(raw.get("name", ""))
        if not _NAME_RE.match(name):
            raise ConfigError(f"Servidor de transforms con nombre inválido: '{name}'.")
        servers[name] = TransformServer(
            name=name,
            url=_validate_url(str(raw.get("url", "")), name),
            api_key_env=str(raw.get("api_key_env", "")),
            timeout_s=float(raw.get("timeout_s", 60)),
        )

    transforms: dict[str, TransformSpec] = {}
    for raw in data.get("transforms", []):
        name = str(raw.get("name", ""))
        if not _NAME_RE.match(name):
            raise ConfigError(f"Transform con nombre inválido: '{name}'.")
        server_name = str(raw.get("server", ""))
        if server_name not in servers:
            raise ConfigError(f"El transform '{name}' usa el servidor '{server_name}', que no está declarado.")
        path_part = str(raw.get("path", "")) or _to_path(name)
        if not re.match(r"^[a-z0-9-]+$", path_part):
            raise ConfigError(f"path inválido para el transform '{name}': usa minúsculas, números y '-'.")
        if name.lower() in transforms:
            raise ConfigError(f"Transform duplicado en el catálogo: '{name}'.")
        transforms[name.lower()] = TransformSpec(
            name=name,
            server=servers[server_name],
            path=path_part,
            input_types=tuple(str(t) for t in raw.get("input_types", [])),
            output_types=tuple(str(t) for t in raw.get("output_types", [])),
            description=str(raw.get("description", ""))[:500],
            settings={str(k): str(v) for k, v in dict(raw.get("settings", {})).items()},
        )
    return TransformCatalog(transforms, load_machines(list(data.get("machines", []))))


def _to_path(name: str) -> str:
    """Igual que maltego_trx.utils.name_to_path: '_' -> '-' y minúsculas (DNSToIP -> dnstoip)."""
    return name.replace("_", "-").replace(".", "-").lower()
