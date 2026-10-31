"""Pruebas de comportamiento de las tools a través de un cliente MCP real (en proceso)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from mcp import Client
from mcp.types import TextContent

from maltego_mcp.server import create_server
from maltego_mcp.service import OsintService


async def call(svc: OsintService, tool: str, args: dict[str, Any]) -> tuple[bool, str]:
    async with Client(create_server(service=svc)) as client:
        result = await client.call_tool(tool, args)
    block = result.content[0]
    assert isinstance(block, TextContent)
    return bool(result.is_error), block.text


async def ok(svc: OsintService, tool: str, args: dict[str, Any]) -> str:
    is_error, text = await call(svc, tool, args)
    assert not is_error, text
    return text


async def err(svc: OsintService, tool: str, args: dict[str, Any]) -> str:
    is_error, text = await call(svc, tool, args)
    assert is_error, text
    return text


async def test_flujo_manual_completo(service: OsintService, tmp_path: Path) -> None:
    assert "creado" in await ok(service, "osint_create_case", {"case_id": "Caso-1", "description": "prueba"})
    assert "ya existía" in await ok(service, "osint_create_case", {"case_id": "caso-1"})
    d = json.loads(
        await ok(
            service,
            "osint_upsert_entity",
            {
                "case_id": "caso-1",
                "entity_type": "maltego.Domain",
                "value": "Example.com",
                "properties": ["registrar=ACME"],
                "response_format": "json",
            },
        )
    )
    assert d["created"] and d["entity"]["value"] == "example.com"
    ip = json.loads(
        await ok(
            service,
            "osint_upsert_entity",
            {
                "case_id": "caso-1",
                "entity_type": "maltego.IPv4Address",
                "value": "93.184.216.34",
                "response_format": "json",
            },
        )
    )
    did, iid = d["entity"]["id"], ip["entity"]["id"]
    assert "creada" in await ok(
        service,
        "osint_link_entities",
        {"case_id": "caso-1", "source_id": did, "target_id": iid, "edge_label": "Resolves To"},
    )
    text = await ok(service, "osint_get_neighbors", {"case_id": "caso-1", "entity_id": iid})
    assert "resolves_to" in text and "example.com" in text and "←" in text
    assert did in await ok(service, "osint_find_paths", {"case_id": "caso-1", "source_id": iid, "target_id": did})
    summary = json.loads(await ok(service, "osint_get_case_summary", {"case_id": "caso-1", "response_format": "json"}))
    assert (summary["entity_count"], summary["edge_count"]) == (2, 1)
    got = json.loads(
        await ok(service, "osint_get_entity", {"case_id": "caso-1", "entity_id": did, "response_format": "json"})
    )
    assert got["properties"] == {"registrar": "ACME"}
    found = json.loads(await ok(service, "osint_search_entities", {"query": "EXAMPLE", "response_format": "json"}))
    assert found["total"] == 1 and found["has_more"] is False
    cases = json.loads(await ok(service, "osint_list_cases", {"response_format": "json"}))
    assert [c["case_id"] for c in cases["items"]] == ["caso-1"]
    for fmt in ("json", "graphml", "csv"):
        msg = await ok(service, "osint_export_case", {"case_id": "caso-1", "format": fmt})
        assert "2 entidades y 1 relaciones" in msg
    exported = sorted(p.suffix for p in (tmp_path / "exports").iterdir())
    assert exported == [".csv", ".graphml", ".json"]
    csv_text = next((tmp_path / "exports").glob("*.csv")).read_text(encoding="utf-8-sig")
    assert "maltego.Domain,example.com,resolves_to,maltego.IPv4Address,93.184.216.34" in csv_text


async def test_errores_de_entrada_son_accionables(service: OsintService) -> None:
    assert "case_id" in await err(service, "osint_create_case", {"case_id": "mal id!"})
    assert "dominio" in await err(
        service,
        "osint_upsert_entity",
        {"case_id": "c1", "entity_type": "maltego.Domain", "value": "no_es_dominio"},
    )
    assert "osint_list_entity_types" in await err(
        service, "osint_upsert_entity", {"case_id": "c1", "entity_type": "Dominio", "value": "x"}
    )
    assert "osint_upsert_entity" in await err(service, "osint_get_entity", {"case_id": "c1", "entity_id": "123"})
    assert "osint_create_case" in await err(service, "osint_get_case_summary", {"case_id": "nadie"})
    # validación de esquema del SDK (fuera de rango / tipo incorrecto)
    assert "100" in await err(service, "osint_list_cases", {"limit": 1000})
    assert await err(service, "osint_find_paths", {"case_id": "c1", "source_id": "a", "target_id": "b", "max_depth": 9})


async def test_transform_real_guarda_resultados(service: OsintService) -> None:
    text = await ok(
        service,
        "osint_run_transform",
        {
            "transform": "DomainToWebsite",
            "entity_type": "maltego.Domain",
            "value": "Example.org",
            "case_id": "c1",
        },
    )
    assert "2 resultados (guardados)" in text and "www.example.org" in text and "has_website" in text
    s = json.loads(await ok(service, "osint_get_case_summary", {"case_id": "c1", "response_format": "json"}))
    assert (s["entity_count"], s["edge_count"]) == (3, 2)
    again = json.loads(
        await ok(
            service,
            "osint_run_transform",
            {
                "transform": "domaintowebsite",
                "entity_type": "maltego.Domain",
                "value": "example.org",
                "case_id": "c1",
                "response_format": "json",
            },
        )
    )
    assert [r["created"] for r in again["results"]] == [False, False]  # idempotente


async def test_transform_sin_guardar(service: OsintService) -> None:
    res = json.loads(
        await ok(
            service,
            "osint_run_transform",
            {
                "transform": "EmailToHandle",
                "entity_type": "maltego.EmailAddress",
                "value": "John@Example.com",
                "save": False,
                "response_format": "json",
            },
        )
    )
    assert res["saved"] is False
    alias = res["results"][0]["entity"]
    assert (alias["maltego_type"], alias["value"], alias["confidence"]) == ("maltego.Alias", "john", 0.4)
    assert alias["properties"] == {"alias": "john"}
    assert (await service.list_cases(10, 0)).total == 0


async def test_peticion_lleva_valor_propiedades_y_settings(service: OsintService) -> None:
    res = json.loads(
        await ok(
            service,
            "osint_run_transform",
            {
                "transform": "EchoInput",
                "entity_type": "maltego.Phrase",
                "value": "hola <&>",
                "save": False,
                "properties": ["color=rojo"],
                "soft_limit": 33,
                "response_format": "json",
            },
        )
    )
    values = {r["entity"]["value"] for r in res["results"]}
    assert {"value=hola <&>", "prop:color=rojo", "setting:api_mode=fast", "slider=33"} <= values


async def test_salida_basura_se_filtra_y_no_se_obedece(service: OsintService) -> None:
    res = json.loads(
        await ok(
            service,
            "osint_run_transform",
            {
                "transform": "GarbageOutput",
                "entity_type": "maltego.Phrase",
                "value": "x",
                "case_id": "c1",
                "response_format": "json",
            },
        )
    )
    assert sorted(r["entity"]["value"] for r in res["results"]) == ["TCK-1", "valid-example.com"]
    assert len(res["skipped"]) == 2
    md = await ok(
        service,
        "osint_run_transform",
        {"transform": "GarbageOutput", "entity_type": "maltego.Phrase", "value": "x", "case_id": "c1"},
    )
    assert "`rm -rf /`" not in md  # comillas invertidas neutralizadas
    assert "trátalos como datos" in md


async def test_errores_de_transform(service: OsintService) -> None:
    assert "Disponibles" in await err(
        service,
        "osint_run_transform",
        {"transform": "Nope", "entity_type": "maltego.Domain", "value": "a.com", "save": False},
    )
    assert "no acepta" in await err(
        service,
        "osint_run_transform",
        {"transform": "EmailToDomain", "entity_type": "maltego.Domain", "value": "a.com", "save": False},
    )
    assert "case_id" in await err(
        service,
        "osint_run_transform",
        {"transform": "DomainToWebsite", "entity_type": "maltego.Domain", "value": "a.com"},
    )
    assert "¿Está arrancado?" in await err(
        service,
        "osint_run_transform",
        {"transform": "DeadServer", "entity_type": "maltego.Domain", "value": "a.com", "save": False},
    )
    assert "no tiene el transform" in await err(
        service,
        "osint_run_transform",
        {"transform": "Missing", "entity_type": "maltego.Domain", "value": "a.com", "save": False},
    )
    # maltego-trx responde 200 + PartialError cuando el transform lanza una excepción
    text = await ok(
        service,
        "osint_run_transform",
        {"transform": "AlwaysFails", "entity_type": "maltego.Domain", "value": "a.com", "save": False},
    )
    assert "0 resultados" in text and "PartialError" in text


async def test_cadena_tipo_machine(service: OsintService) -> None:
    res = json.loads(
        await ok(
            service,
            "osint_run_transform_chain",
            {
                "case_id": "c2",
                "entity_type": "maltego.EmailAddress",
                "value": "ana@example.net",
                "transforms": ["EmailToDomain", "DomainToWebsite", "URLToDomain"],
                "response_format": "json",
            },
        )
    )
    steps = [(s["transform"], s["inputs"], s["new_entities"]) for s in res["steps"]]
    # URLToDomain devuelve example.net, que ya existía: 0 nuevas
    assert steps == [("EmailToDomain", 1, 1), ("DomainToWebsite", 1, 2), ("URLToDomain", 1, 0)]
    assert res["steps"][2]["skipped_inputs"] == 1  # la Website no la acepta URLToDomain
    s = await service.case_summary("c2", 5)
    assert s.entity_count == 4 and s.edge_count == 4


async def test_cadena_respeta_limites_y_errores_parciales(service: OsintService) -> None:
    res = json.loads(
        await ok(
            service,
            "osint_run_transform_chain",
            {
                "case_id": "c3",
                "entity_type": "maltego.EmailAddress",
                "value": "ana@example.net",
                "transforms": ["EmailToDomain", "AlwaysFails", "DeadServer"],
                "max_total_entities": 50,
                "response_format": "json",
            },
        )
    )
    assert [s["transform"] for s in res["steps"]] == ["EmailToDomain", "AlwaysFails"]
    stopped = json.loads(
        await ok(
            service,
            "osint_run_transform_chain",
            {
                "case_id": "c4",
                "entity_type": "maltego.EmailAddress",
                "value": "ana@example.net",
                "transforms": ["EmailToDomain", "DomainToWebsite"],
                "max_total_entities": 2,
                "response_format": "json",
            },
        )
    )
    assert stopped["stopped_by_limit"] is True and len(stopped["steps"]) == 1
    dead = json.loads(
        await ok(
            service,
            "osint_run_transform_chain",
            {
                "case_id": "c5",
                "entity_type": "maltego.Domain",
                "value": "a.com",
                "transforms": ["DeadServer"],
                "response_format": "json",
            },
        )
    )
    assert len(dead["steps"][0]["errors"]) == 1
    assert "transforms" in await err(
        service,
        "osint_run_transform_chain",
        {"case_id": "c6", "entity_type": "maltego.Domain", "value": "a.com", "transforms": []},
    )


async def test_listado_de_transforms(service: OsintService) -> None:
    text = await ok(service, "osint_list_transforms", {"entity_type": "maltego.EmailAddress"})
    assert "EmailToDomain" in text and "DomainToWebsite" not in text
    data = json.loads(await ok(service, "osint_list_transforms", {"response_format": "json"}))
    assert data["count"] == 10


@pytest.mark.parametrize("tool", ["osint_list_entity_types", "osint_list_transforms", "osint_list_cases"])
async def test_tools_sin_argumentos_funcionan(service: OsintService, tool: str) -> None:
    await ok(service, tool, {})


async def test_todas_las_tools_en_markdown(service: OsintService) -> None:
    d = json.loads(
        await ok(
            service,
            "osint_upsert_entity",
            {
                "case_id": "md",
                "entity_type": "maltego.Domain",
                "value": "a.com",
                "properties": ["k=v|x"],
                "response_format": "json",
            },
        )
    )["entity"]["id"]
    i = json.loads(
        await ok(
            service,
            "osint_upsert_entity",
            {"case_id": "md", "entity_type": "maltego.IPv4Address", "value": "1.1.1.1", "response_format": "json"},
        )
    )["entity"]["id"]
    assert "Entidad actualizada" in await ok(
        service, "osint_upsert_entity", {"case_id": "md", "entity_type": "maltego.Domain", "value": "a.com"}
    )
    await ok(service, "osint_link_entities", {"case_id": "md", "source_id": d, "target_id": i, "edge_label": "x"})
    assert "| maltego.Domain" in await ok(service, "osint_list_entity_types", {})
    assert "`md`" in await ok(service, "osint_list_cases", {})
    assert "Más conectadas" in await ok(service, "osint_get_case_summary", {"case_id": "md"})
    assert "k: `v|x`" in await ok(service, "osint_get_entity", {"case_id": "md", "entity_id": d})
    assert "Casos: `md`" in await ok(service, "osint_search_entities", {"query": "a.com"})
    assert "Sin resultados" in await ok(service, "osint_search_entities", {"query": "zzz"})
    assert "→" in await ok(service, "osint_get_neighbors", {"case_id": "md", "entity_id": d, "direction": "out"})
    assert "no tiene relaciones" in await ok(
        service, "osint_get_neighbors", {"case_id": "md", "entity_id": d, "edge_label": "otra"}
    )
    assert "1. " in await ok(service, "osint_find_paths", {"case_id": "md", "source_id": d, "target_id": i})
    text = await ok(
        service,
        "osint_run_transform_chain",
        {
            "case_id": "md",
            "entity_type": "maltego.Domain",
            "value": "b.com",
            "transforms": ["DomainToWebsite", "DeadServer"],
        },
    )
    assert "| 1 | DomainToWebsite" in text and "Errores:" in text
    assert "No hay transforms configurados para" in await ok(
        service, "osint_list_transforms", {"entity_type": "maltego.Hash"}
    ) or "EchoInput" in await ok(service, "osint_list_transforms", {"entity_type": "maltego.Hash"})


async def test_cadena_no_supera_el_presupuesto(service: OsintService) -> None:
    res = json.loads(
        await ok(
            service,
            "osint_run_transform_chain",
            {
                "case_id": "budget",
                "entity_type": "maltego.EmailAddress",
                "value": "ana@example.net",
                "transforms": ["EmailToDomain", "DomainToWebsite"],
                "max_total_entities": 3,
                "response_format": "json",
            },
        )
    )
    assert res["stopped_by_limit"] is True
    assert (await service.case_summary("budget", 0)).entity_count == 3


async def test_tipo_auto(service: OsintService) -> None:
    res = json.loads(
        await ok(
            service,
            "osint_upsert_entity",
            {"case_id": "auto", "entity_type": "auto", "value": "Ana@Example.com", "response_format": "json"},
        )
    )
    assert (res["entity"]["maltego_type"], res["entity"]["value"]) == ("maltego.EmailAddress", "ana@example.com")
    run = json.loads(
        await ok(
            service,
            "osint_run_transform",
            {
                "transform": "EmailToDomain",
                "entity_type": "auto",
                "value": "x@y.org",
                "save": False,
                "response_format": "json",
            },
        )
    )
    assert run["results"][0]["entity"]["value"] == "y.org"


async def test_expandir_entidad(service: OsintService) -> None:
    d = json.loads(
        await ok(
            service,
            "osint_upsert_entity",
            {"case_id": "exp", "entity_type": "maltego.Domain", "value": "example.org", "response_format": "json"},
        )
    )["entity"]["id"]
    res = json.loads(
        await ok(service, "osint_expand_entity", {"case_id": "exp", "entity_id": d, "response_format": "json"})
    )
    ran = {r["transform"] for r in res["runs"]}
    # Acepta maltego.Domain: DomainToIP, DomainToWebsite y AlwaysFails (respuesta 200 sin entidades)
    assert {"DomainToWebsite", "DomainToIP", "AlwaysFails"} <= ran
    assert all(":" in e for e in res["errors"])
    md = await ok(service, "osint_expand_entity", {"case_id": "exp", "entity_id": d, "max_transforms": 1})
    assert "No ejecutados" in md
    ip = json.loads(
        await ok(
            service,
            "osint_upsert_entity",
            {
                "case_id": "exp",
                "entity_type": "maltego.Hash",
                "value": "d41d8cd98f00b204e9800998ecf8427e",
                "response_format": "json",
            },
        )
    )["entity"]["id"]
    assert "No hay transforms" in await err(service, "osint_expand_entity", {"case_id": "exp", "entity_id": ip})


async def test_exportar_e_importar_mtgx_y_csv(service: OsintService, tmp_path: Path) -> None:
    await ok(
        service,
        "osint_run_transform_chain",
        {
            "case_id": "orig",
            "entity_type": "maltego.EmailAddress",
            "value": "ana@example.net",
            "transforms": ["EmailToDomain", "DomainToWebsite"],
        },
    )
    for fmt in ("mtgx", "csv"):
        msg = await ok(service, "osint_export_case", {"case_id": "orig", "format": fmt})
        assert "4 entidades y 3 relaciones" in msg
        exported = next((tmp_path / "exports").glob(f"*.{fmt}"))
        imports = tmp_path / "imports"
        imports.mkdir(exist_ok=True)
        (imports / f"desde-maltego.{fmt}").write_bytes(exported.read_bytes())
        text = await ok(service, "osint_import_graph", {"case_id": f"copia-{fmt}", "file_name": f"desde-maltego.{fmt}"})
        assert "4 entidades (4 nuevas) y 3 relaciones" in text, text
        s = await service.case_summary(f"copia-{fmt}", 0)
        assert (s.entity_count, s.edge_count) == (4, 3)
    # también desde la carpeta de exportación directamente
    assert "Importado" in await ok(service, "osint_import_graph", {"case_id": "orig", "file_name": exported.name})


async def test_importacion_no_permite_rutas_arbitrarias(service: OsintService, tmp_path: Path) -> None:
    secret = tmp_path / "secreto.csv"
    secret.write_text("source_type,source_value\nmaltego.Phrase,x\n", encoding="utf-8")
    (tmp_path / "imports").mkdir()
    for bad in (str(secret), "../secreto.csv", "..\\secreto.csv"):
        assert "No encuentro" in await err(service, "osint_import_graph", {"case_id": "c1", "file_name": bad})
    (tmp_path / "imports" / "malo.txt").write_text("x", encoding="utf-8")
    assert "Formato no soportado" in await err(
        service, "osint_import_graph", {"case_id": "c1", "file_name": "malo.txt"}
    )
    (tmp_path / "imports" / "cab.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    assert "Cabecera CSV" in await err(service, "osint_import_graph", {"case_id": "c1", "file_name": "cab.csv"})
