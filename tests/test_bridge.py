"""Puente con Maltego Desktop: transforms locales y .mtz generado con el SDK oficial."""

import asyncio
import zipfile
from pathlib import Path

import pytest

from maltego_mcp.config import Settings
from maltego_mcp.maltego.bridge import BY_NAME, read_current_case, run_local, write_mtz
from maltego_mcp.server import build_service
from maltego_mcp.transforms.protocol import parse_response


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings.from_env({"MALTEGO_MCP_HOME": str(tmp_path)})


def call(name: str, settings: Settings, *args: str):  # type: ignore[no-untyped-def]
    return parse_response(run_local(name, list(args), settings=settings).encode())


def test_flujo_maltego_completo(settings: Settings) -> None:
    svc = build_service(settings)

    async def seed() -> None:
        d, _ = await svc.upsert_entity("demo", "maltego.Domain", "example.com", 0.9, "agente", [])
        i, _ = await svc.upsert_entity("demo", "maltego.IPv4Address", "1.2.3.4", 0.8, "agente", [])
        await svc.link("demo", d.id, i.id, "resolves_to", "agente", 0.8)

    asyncio.run(seed())
    assert "No hay caso actual" in call("mcpneighbors-domain", settings, "example.com").messages[0][1]
    assert [e.value for e in call("mcplistcases", settings, "x").entities] == ["demo"]
    opened = call("mcpopencase", settings, "Demo")
    assert {e.value for e in opened.entities} == {"example.com", "1.2.3.4"}
    assert read_current_case(settings) == "demo"
    out = call("mcpneighbors-domain", settings, "Example.COM")
    assert [(e.entity_type, e.value, e.link_label, e.reversed_link) for e in out.entities] == [
        ("maltego.IPv4Address", "1.2.3.4", "resolves_to", False)
    ]
    assert out.entities[0].properties["mcp.case"] == "demo"
    back = call("mcpneighbors-ipv4address", settings, "1.2.3.4")
    assert back.entities[0].reversed_link is True
    missing = call("mcpneighbors-domain", settings, "otro.com")
    assert "no está en el caso" in missing.messages[0][1]
    saved = call("mcpsave-emailaddress", settings, "Ana@Example.com", "nota=vista en foro#email=Ana@Example.com")
    assert "Guardada en el caso demo" in saved.messages[0][1]
    ent = asyncio.run(build_service(settings).search("demo", "ana@", "", 5, 0)).items[0]
    assert ent.properties == {"nota": "vista en foro"}
    assert ent.sources == ["maltego"]


def test_errores_controlados(settings: Settings) -> None:
    assert "desconocido" in call("nope", settings, "x").messages[0][1]
    assert "case_id" in call("mcpopencase", settings, "caso con espacios").messages[0][1]
    assert "no existe" in call("mcpopencase", settings, "inexistente").messages[0][1]


def test_mtz_generado_con_sdk_oficial(tmp_path: Path) -> None:
    out = write_mtz(tmp_path / "x.mtz", tmp_path, "C:\\Users\\Alvaro\\.local\\bin\\uv.exe")
    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
        assert "Servers/Local.tas" in names and "TransformSets/MCP Maltego.set" in names
        for name in BY_NAME:
            assert f"TransformRepositories/Local/{name}.transform" in names
            settings_xml = zf.read(f"TransformRepositories/Local/{name}.transformsettings").decode()
            assert f"run --quiet maltego-mcp-bridge local {name}<" in settings_xml
            assert "uv.exe" in settings_xml
        neighbors = zf.read("TransformRepositories/Local/mcpneighbors-domain.transform").decode()
        assert 'type="maltego.Domain"' in neighbors
    assert len(BY_NAME) == 42


def test_caso_viaja_en_la_entidad_y_urls_usan_su_propiedad(settings: Settings) -> None:
    svc = build_service(settings)
    asyncio.run(svc.upsert_entity("caso-a", "maltego.URL", "https://example.com/x", 0.9, "agente", []))
    asyncio.run(svc.create_case("caso-b", ""))
    call("mcpopencase", settings, "caso-b")  # el caso actual es b...
    opened = call("mcpopencase", settings, "caso-a")
    url = opened.entities[0]
    assert url.properties["url"] == "https://example.com/x"
    call("mcpopencase", settings, "caso-b")  # ...pero la entidad trae mcp.case=caso-a
    # Maltego muestra el título (short-title) como valor; la URL real viaja en la propiedad "url"
    res = call(
        "mcpsave-url",
        settings,
        "Example Domain",
        "url=https://example.com/x#mcp.case=caso-a#short-title=Example Domain",
    )
    assert "Actualizada en el caso caso-a: https://example.com/x" in res.messages[0][1]
    ent = asyncio.run(svc.search("caso-a", "example", "", 5, 0)).items[0]
    assert "short-title" not in ent.properties and "url" not in ent.properties


def test_salida_utf8_con_declaracion(
    settings: Settings, capsysbinary: pytest.CaptureFixture[bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    from maltego_mcp.maltego import bridge

    monkeypatch.setenv("MALTEGO_MCP_HOME", str(settings.home))
    asyncio.run(build_service(settings).upsert_entity("ru", "maltego.Alias", "Иван", 0.5, "m", []))
    bridge.main(["local", "mcpopencase", "ru"])
    out = capsysbinary.readouterr().out
    assert out.startswith(b'<?xml version="1.0" encoding="UTF-8"?>')
    assert "Иван".encode() in out
    assert [e.value for e in parse_response(out).entities] == ["Иван"]
