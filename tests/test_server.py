import json

from mcp import Client
from mcp.types import TextContent

from maltego_mcp.domain.entity_types import ENTITY_TYPES
from maltego_mcp.server import create_server


def _text(result) -> str:  # type: ignore[no-untyped-def]
    assert not result.is_error
    block = result.content[0]
    assert isinstance(block, TextContent)
    return block.text


async def test_list_entity_types_markdown_por_defecto() -> None:
    async with Client(create_server()) as client:
        text = _text(await client.call_tool("osint_list_entity_types", {}))
    assert text.startswith("| Tipo Maltego")
    for e in ENTITY_TYPES:
        assert e.maltego_type in text


async def test_list_entity_types_json() -> None:
    async with Client(create_server()) as client:
        text = _text(await client.call_tool("osint_list_entity_types", {"response_format": "json"}))
    data = json.loads(text)
    assert data["count"] == len(ENTITY_TYPES)
    assert {i["maltego_type"] for i in data["items"]} == {e.maltego_type for e in ENTITY_TYPES}


async def test_formato_invalido_devuelve_error_no_excepcion() -> None:
    async with Client(create_server()) as client:
        result = await client.call_tool("osint_list_entity_types", {"response_format": "xml"})
    assert result.is_error


async def test_anotaciones_de_solo_lectura() -> None:
    async with Client(create_server()) as client:
        tools = (await client.list_tools()).tools
    tool = next(t for t in tools if t.name == "osint_list_entity_types")
    assert tool.annotations is not None
    assert tool.annotations.read_only_hint is True
    assert tool.annotations.destructive_hint is False
