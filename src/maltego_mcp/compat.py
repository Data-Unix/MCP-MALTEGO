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
ALLOWED_TYPES: frozenset[str] = frozenset({"string", "integer", "number", "boolean", "array", "object"})
TOOL_NAME_RE = re.compile(r"^osint_[a-z0-9_]+$")
MAX_TOOL_NAME_LEN = 40
MAX_TOOLS = 20


def find_schema_issues(schema: Any, path: str = "$") -> list[str]:
    """Devuelve una lista de problemas de portabilidad encontrados en un JSON Schema."""
    issues: list[str] = []
    if isinstance(schema, dict):
        for key, value in schema.items():
            here = f"{path}.{key}"
            if key in FORBIDDEN_SCHEMA_KEYS:
                issues.append(f"{here}: clave no portable '{key}'")
            if key == "type":
                if not isinstance(value, str):
                    issues.append(f"{here}: 'type' debe ser un único string, no {value!r}")
                elif value not in ALLOWED_TYPES:
                    issues.append(f"{here}: tipo no soportado '{value}'")
            if key == "properties" and isinstance(value, dict):
                for prop, sub in value.items():
                    issues.extend(find_schema_issues(sub, f"{here}.{prop}"))
            elif key != "properties":
                issues.extend(find_schema_issues(value, here))
    elif isinstance(schema, list):
        for i, item in enumerate(schema):
            issues.extend(find_schema_issues(item, f"{path}[{i}]"))
    return issues


def find_tool_name_issues(name: str) -> list[str]:
    issues: list[str] = []
    if not TOOL_NAME_RE.match(name):
        issues.append(f"{name}: no cumple el patrón osint_<verbo>_<objeto> en snake_case")
    if len(name) > MAX_TOOL_NAME_LEN:
        issues.append(f"{name}: supera {MAX_TOOL_NAME_LEN} caracteres")
    return issues
