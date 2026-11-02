"""Tests para el motor de plugins y extensibilidad comunitaria."""

from __future__ import annotations

from pathlib import Path

import pytest

from maltego_mcp.transforms.builtin import BuiltinContext
from maltego_mcp.transforms.plugins import (
    clear_community_registry,
    custom_transform,
    discover_plugins,
    load_plugin_file,
    result_entity,
    transform_response,
)


@pytest.fixture(autouse=True)
def clean_registry() -> None:
    clear_community_registry()
    yield
    clear_community_registry()


def test_custom_transform_registration() -> None:
    @custom_transform(
        name="TestCustomEcho",
        input_types=("maltego.Domain",),
        output_types=("maltego.Phrase",),
        description="Transform de prueba",
        category="comunidad",
    )
    async def handler(ctx: BuiltinContext, etype: str, value: str, props: dict[str, str], limit: int):
        return transform_response([result_entity("maltego.Phrase", f"Echo: {value}", label="echo")])

    plugins = discover_plugins([])
    names = [p.name for p in plugins]
    assert "TestCustomEcho" in names
    t = next(p for p in plugins if p.name == "TestCustomEcho")
    assert t.input_types == ("maltego.Domain",)
    assert t.category == "comunidad"


def test_load_plugin_from_file(tmp_path: Path) -> None:
    plugin_file = tmp_path / "community_sample.py"
    code = """
from maltego_mcp.transforms.plugins import custom_transform, result_entity, transform_response

@custom_transform(
    name="SampleFileTransform",
    input_types=("maltego.IPv4Address",),
    output_types=("maltego.Phrase",),
    description="Plugin desde fichero",
    category="comunidad",
)
async def sample_handler(ctx, etype, value, props, limit):
    return transform_response([result_entity("maltego.Phrase", f"IP: {value}")])
"""
    plugin_file.write_text(code, encoding="utf-8")

    loaded = load_plugin_file(plugin_file)
    assert len(loaded) == 1
    assert loaded[0].name == "SampleFileTransform"


def test_load_plugin_resilience_to_errors(tmp_path: Path) -> None:
    broken_file = tmp_path / "broken_plugin.py"
    broken_file.write_text("def invalid_syntax( broken!!", encoding="utf-8")

    loaded = load_plugin_file(broken_file)
    assert loaded == []

    runtime_error_file = tmp_path / "runtime_err.py"
    runtime_error_file.write_text("raise RuntimeError('Fallo forzado al importar')", encoding="utf-8")

    loaded_err = load_plugin_file(runtime_error_file)
    assert loaded_err == []


def test_result_entity_and_response_helpers() -> None:
    ent = result_entity(
        "maltego.Domain",
        "example.com",
        label="subdominio",
        weight=90,
        custom__prop="valor",
    )
    assert ent.entity_type == "maltego.Domain"
    assert ent.value == "example.com"
    assert ent.weight == 90
    assert ent.properties["custom.prop"] == "valor"
    assert ent.link_label == "subdominio"

    resp = transform_response([ent])
    assert len(resp.entities) == 1
    assert resp.entities[0].value == "example.com"
