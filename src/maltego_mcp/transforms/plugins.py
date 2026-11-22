"""Motor de plugins comunitarios y extensibilidad dinámica para MCP Maltego.

Permite a desarrolladores y analistas añadir transformadas personalizadas
en Python sin necesidad de modificar el código central del proyecto.

Uso en plugins de usuario (~/.maltego-mcp/plugins/*.py o ./plugins/*.py):
```python
from maltego_mcp.transforms.plugins import custom_transform, result_entity, transform_response

@custom_transform(
    name="MiTransform",
    input_types=("maltego.Domain",),
    output_types=("maltego.Phrase",),
    description="Mi transformada personalizada de la comunidad",
    category="comunidad",
)
async def mi_transform(ctx, etype, value, props, limit):
    return transform_response([
        result_entity("maltego.Phrase", f"Dato para {value}", label="resultado")
    ])
```
"""

from __future__ import annotations

import importlib.util
import logging
import os
from collections.abc import Callable
from pathlib import Path

from maltego_mcp.transforms.builtin import BuiltinTransform, Handler, PassivityLevel
from maltego_mcp.transforms.protocol import ResultEntity, TransformResponse

logger = logging.getLogger("maltego_mcp.plugins")

_COMMUNITY_REGISTRY: list[BuiltinTransform] = []


def custom_transform(
    name: str,
    input_types: tuple[str, ...] | list[str],
    output_types: tuple[str, ...] | list[str] = (),
    description: str = "",
    category: str = "comunidad",
    requires: tuple[str, ...] = (),
    passivity: PassivityLevel = "active_direct",
) -> Callable[[Handler], Handler]:
    """Decorador para registrar una transformada comunitaria en el motor de plugins."""

    def decorator(handler: Handler) -> Handler:
        transform = BuiltinTransform(
            name=name,
            input_types=tuple(input_types),
            output_types=tuple(output_types),
            description=description,
            category=category,
            handler=handler,
            requires=tuple(requires),
            passivity=passivity,
        )
        # Reemplazar si ya existe una con el mismo nombre para permitir recarga en caliente
        for idx, existing in enumerate(_COMMUNITY_REGISTRY):
            if existing.name.lower() == name.lower():
                _COMMUNITY_REGISTRY[idx] = transform
                return handler
        _COMMUNITY_REGISTRY.append(transform)
        return handler

    return decorator


def result_entity(
    etype: str,
    value: str,
    label: str = "",
    weight: int = 100,
    **props: str,
) -> ResultEntity:
    """Construye una ResultEntity de Maltego de forma limpia y tipada."""
    return ResultEntity(
        entity_type=etype,
        value=value,
        weight=weight,
        properties={k.replace("__", "."): str(v) for k, v in props.items() if v is not None},
        link_properties={"maltego.link.label": label} if label else {},
    )


def transform_response(entities: list[ResultEntity] | None = None) -> TransformResponse:
    """Construye un TransformResponse a partir de una lista de entidades."""
    return TransformResponse(entities=entities or [])


def get_default_plugin_dirs() -> list[Path]:
    """Retorna los directorios predeterminados de búsqueda de plugins (opt-in explícito para home y cwd)."""
    dirs: list[Path] = []
    home_plugins = Path.home() / ".maltego-mcp" / "plugins"
    if os.environ.get("MALTEGO_MCP_PLUGINS_HOME", "").strip() in ("1", "true", "yes"):
        dirs.append(home_plugins)
    elif home_plugins.is_dir():
        logger.info(
            "Directorio de plugins en home '~/.maltego-mcp/plugins' detectado pero ignorado por política de seguridad. "
            "Defina MALTEGO_MCP_PLUGINS_HOME=1 para habilitar su ejecución."
        )

    cwd_plugins = Path.cwd() / "plugins"
    if os.environ.get("MALTEGO_MCP_PLUGINS_CWD", "").strip() in ("1", "true", "yes"):
        dirs.append(cwd_plugins)
    elif cwd_plugins.is_dir():
        logger.info(
            "Directorio local de plugins './plugins' detectado pero ignorado por política de seguridad. "
            "Defina MALTEGO_MCP_PLUGINS_CWD=1 para habilitar la carga desde el directorio de trabajo."
        )
    return [d for d in dirs if d.is_dir()]


def load_plugin_file(file_path: Path) -> list[BuiltinTransform]:
    """Carga de forma segura un fichero de plugin en Python y extrae sus transformadas registradas."""
    if not file_path.is_file() or not file_path.name.endswith(".py"):
        return []

    count_before = len(_COMMUNITY_REGISTRY)
    module_name = f"maltego_mcp_plugin_{file_path.stem}"

    try:
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None or spec.loader is None:
            logger.warning("No se pudo obtener el cargador para el plugin: %s", file_path)
            return []

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        new_transforms = _COMMUNITY_REGISTRY[count_before:]
        logger.info("Plugin '%s' cargado con éxito: %d transform(s)", file_path.name, len(new_transforms))
        return new_transforms
    except Exception as exc:
        from maltego_mcp.egress import redact_secrets

        logger.warning("Fallo al cargar el plugin comunitario %s: %s", file_path, redact_secrets(str(exc)))
        return []


def discover_plugins(search_dirs: list[Path] | None = None) -> list[BuiltinTransform]:
    """Descubre y carga todos los plugins encontrados en los directorios especificados."""
    dirs = search_dirs if search_dirs is not None else get_default_plugin_dirs()
    for d in dirs:
        if not d.is_dir():
            continue
        for py_file in sorted(d.glob("*.py")):
            if not py_file.name.startswith("_"):
                load_plugin_file(py_file)
    return list(_COMMUNITY_REGISTRY)


def clear_community_registry() -> None:
    """Limpia el registro de transformadas comunitarias (útil para pruebas unitarias)."""
    _COMMUNITY_REGISTRY.clear()
