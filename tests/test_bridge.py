"""Puente con Maltego Desktop: transforms locales y .mtz generado con el SDK oficial."""

import asyncio
import zipfile
from pathlib import Path

import pytest

from maltego_mcp.config import Settings
from maltego_mcp.maltego.bridge import default_uv, read_current_case, run_local, transforms_by_name, write_mtz
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
        for name in transforms_by_name():
            assert f"TransformRepositories/Local/{name}.transform" in names
            settings_xml = zf.read(f"TransformRepositories/Local/{name}.transformsettings").decode()
            assert f"run --quiet maltego-mcp-bridge local {name}<" in settings_xml
            assert "uv.exe" in settings_xml
        neighbors = zf.read("TransformRepositories/Local/mcpneighbors-domain.transform").decode()
        assert 'type="maltego.Domain"' in neighbors
    from maltego_mcp.domain.entity_types import all_entity_types

    assert len(transforms_by_name()) == 2 + 2 * len(all_entity_types())


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


def test_tipos_importados_tienen_transforms_puente(settings: Settings) -> None:
    import json

    from maltego_mcp.domain.entity_types import register_imported_types

    settings.home.mkdir(parents=True, exist_ok=True)
    (settings.home / "entities.json").write_text(
        json.dumps(
            {
                "entity_types": [
                    {"maltego_type": "acme.Employee", "main_property": "employee.id", "description": "Empleado"}
                ]
            }
        ),
        "utf-8",
    )
    try:
        asyncio.run(build_service(settings).create_case("emp", ""))
        call("mcpopencase", settings, "emp")
        saved = call("mcpsave-employee", settings, "E-42")
        assert "Guardada en el caso emp: E-42 (acme.Employee)" in saved.messages[0][1]
        assert "mcpneighbors-employee" in transforms_by_name()
    finally:
        register_imported_types([])


def test_default_uv_detecta_variable_y_home_bin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = tmp_path / "custom-uv.exe"
    fake.write_text("x", encoding="utf-8")
    monkeypatch.setenv("MCP_MALTEGO_UV", str(fake))
    assert default_uv() == str(fake)
    monkeypatch.delenv("MCP_MALTEGO_UV", raising=False)
    monkeypatch.setattr("shutil.which", lambda _: None)
    monkeypatch.setenv("MALTEGO_MCP_HOME", str(tmp_path))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    home_uv = bin_dir / ("uv.exe" if __import__("sys").platform == "win32" else "uv")
    home_uv.write_text("x", encoding="utf-8")
    assert default_uv() == str(home_uv)
