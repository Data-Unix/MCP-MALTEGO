"""Comprobaciones de portabilidad de esquemas entre clientes LLM (Gemini, Claude, OpenAI...).

Gemini valida las declaraciones de funciones contra un subconjunto OpenAPI de JSON Schema y
rechaza (HTTP 400) varias claves que Pydantic genera por defecto. Ver AGENTS.md.
"""

import re
from typing import Any

FORBIDDEN_SCHEMA_KEYS: frozenset[str] = frozenset(
    {
        "$ref",
        "$defs",
        "definitions",
        "anyOf",
        "oneOf",
        "allOf",
        "additionalProperties",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "propertyNames",
        "patternProperties",
        "const",
    }
)
# Tipos permitidos en propiedades. "object" solo se admite en la raíz del inputSchema.
ALLOWED_PROPERTY_TYPES: frozenset[str] = frozenset({"string", "integer", "number", "boolean", "array"})
ALLOWED_ITEM_TYPES: frozenset[str] = frozenset({"string", "integer", "number", "boolean"})
# Claves cuyo valor son datos (no subesquemas): no se inspeccionan como esquema.
DATA_KEYS: frozenset[str] = frozenset({"default", "enum", "examples", "example", "required", "description", "title"})
TOOL_NAME_RE = re.compile(r"^osint_[a-z0-9_]+$")
MAX_TOOL_NAME_LEN = 40
MAX_TOOLS = 20


def find_schema_issues(schema: Any) -> list[str]:
    """Devuelve los problemas de portabilidad de un inputSchema de tool (raíz = objeto)."""
    if not isinstance(schema, dict):
        return ["$: el inputSchema debe ser un objeto"]
    issues = _check_node(schema, "$", allowed_types=frozenset({"object"}))
    for prop, sub in (schema.get("properties") or {}).items():
        issues.extend(_check_property(sub, f"$.properties.{prop}"))
    return issues


def _check_property(schema: Any, path: str) -> list[str]:
    if not isinstance(schema, dict):
        return [f"{path}: la propiedad debe ser un esquema"]
    issues = _check_node(schema, path, allowed_types=ALLOWED_PROPERTY_TYPES)
    if "properties" in schema:
        issues.append(f"{path}: objetos anidados no permitidos; usa parámetros planos")
    if schema.get("type") == "array":
        items = schema.get("items")
        if not isinstance(items, dict):
            issues.append(f"{path}: los arrays deben declarar 'items' con un tipo primitivo")
        else:
            issues.extend(_check_node(items, f"{path}.items", allowed_types=ALLOWED_ITEM_TYPES))
            if "properties" in items or "items" in items:
                issues.append(f"{path}.items: solo se permiten arrays de primitivos")
    return issues


def _check_node(node: dict[str, Any], path: str, allowed_types: frozenset[str]) -> list[str]:
    issues = [f"{path}.{k}: clave no portable '{k}'" for k in node if k in FORBIDDEN_SCHEMA_KEYS]
    if "type" not in node:
        issues.append(f"{path}: falta 'type'")
    else:
        t = node["type"]
        if not isinstance(t, str):
            issues.append(f"{path}.type: 'type' debe ser un único string, no {t!r}")
        elif t not in allowed_types:
            issues.append(f"{path}.type: tipo '{t}' no permitido aquí (permitidos: {sorted(allowed_types)})")
    return issues


def find_tool_name_issues(name: str) -> list[str]:
    issues: list[str] = []
    if not TOOL_NAME_RE.match(name):
        issues.append(f"{name}: no cumple el patrón osint_<verbo>_<objeto> en snake_case")
    if len(name) > MAX_TOOL_NAME_LEN:
        issues.append(f"{name}: supera {MAX_TOOL_NAME_LEN} caracteres")
    return issues
