"""Garantiza que todas las tools son aceptadas por clientes con validación estricta (Gemini)."""

import pytest

from maltego_mcp.compat import MAX_TOOLS, find_schema_issues, find_tool_name_issues
from maltego_mcp.server import create_server


@pytest.fixture
async def tools():  # type: ignore[no-untyped-def]
    return await create_server().list_tools()


async def test_hay_tools_y_no_superan_el_maximo(tools) -> None:  # type: ignore[no-untyped-def]
    assert 0 < len(tools) <= MAX_TOOLS


async def test_nombres_de_tool_portables(tools) -> None:  # type: ignore[no-untyped-def]
    issues = [i for t in tools for i in find_tool_name_issues(t.name)]
    assert issues == []


async def test_input_schemas_portables(tools) -> None:  # type: ignore[no-untyped-def]
    issues = [f"{t.name}: {i}" for t in tools for i in find_schema_issues(t.input_schema)]
    assert issues == []


async def test_todas_las_tools_tienen_descripcion_y_anotaciones(tools) -> None:  # type: ignore[no-untyped-def]
    for t in tools:
        assert t.description and len(t.description) <= 1024, t.name
        assert t.annotations is not None, t.name


@pytest.mark.parametrize(
    ("schema", "expected"),
    [
        ({"type": "object", "properties": {"x": {"anyOf": [{"type": "string"}, {"type": "null"}]}}}, "anyOf"),
        ({"type": "object", "additionalProperties": False}, "additionalProperties"),
        (
            {"type": "object", "properties": {"n": {"type": "integer", "exclusiveMinimum": 0}}},
            "exclusiveMinimum",
        ),
        ({"type": "object", "$defs": {}}, "$defs"),
        ({"type": ["string", "null"]}, "único string"),
    ],
)
def test_el_validador_detecta_claves_prohibidas(schema: dict[str, object], expected: str) -> None:
    assert any(expected in issue for issue in find_schema_issues(schema))


def test_propiedad_llamada_como_clave_prohibida_no_es_falso_positivo() -> None:
    schema = {"type": "object", "properties": {"const": {"type": "string"}}}
    assert find_schema_issues(schema) == []


def test_el_validador_detecta_nombres_invalidos() -> None:
    assert find_tool_name_issues("listEntities")
    assert find_tool_name_issues("osint_" + "x" * 40)
    assert find_tool_name_issues("osint_list_entity_types") == []
