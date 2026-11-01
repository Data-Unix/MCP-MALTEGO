"""Pruebas integrales de las 8 capacidades avanzadas (Core 1-3 + HUMINT/SOCMINT 1-5)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
from mcp import Client
from mcp.types import TextContent

from maltego_mcp.breaches import index_breach_file, query_local_breaches
from maltego_mcp.cli import inspect_mtgx
from maltego_mcp.cli import main as cli_main
from maltego_mcp.maltego.mtgx import read_mtgx
from maltego_mcp.server import create_server
from maltego_mcp.service import OsintService
from maltego_mcp.transforms.builtin import new_http_client
from tests.test_builtin import Router


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


async def test_core1_multi_agent_swarms_fork_optimistic_lock_y_merge(service: OsintService) -> None:
    """Core 1: Delegación en sub-casos virtuales, control optimista de versión y fusión automática."""
    await ok(service, "osint_manage_case", {"case_id": "op-swarm", "description": "Caso maestro"})
    await ok(
        service,
        "osint_upsert_entity",
        {"case_id": "op-swarm", "entity_type": "maltego.Domain", "value": "example.com"},
    )
    fork_json = json.loads(
        await ok(
            service,
            "osint_manage_case",
            {
                "case_id": "op-swarm",
                "action": "delegate",
                "sub_roles": ["infra", "humint"],
                "response_format": "json",
            },
        )
    )
    assert fork_json["parent_case_id"] == "op-swarm"
    assert [s["sub_case_id"] for s in fork_json["sub_cases"]] == ["op-swarm--infra", "op-swarm--humint"]

    # Cada sub-agente añade hallazgos independientes a su sub-caso
    await ok(
        service,
        "osint_upsert_entity",
        {"case_id": "op-swarm--infra", "entity_type": "maltego.IPv4Address", "value": "93.184.216.34"},
    )
    await ok(
        service,
        "osint_upsert_entity",
        {"case_id": "op-swarm--humint", "entity_type": "humint.Alias", "value": "sec_operator"},
    )

    # Si se pasa un expected_version obsoleto, debe abortar con mensaje accionable
    conflict_msg = await err(
        service,
        "osint_manage_case",
        {
            "case_id": "op-swarm",
            "action": "merge",
            "source_case": "all",
            "expected_version": 999,
        },
    )
    assert "Conflicto de versión optimista" in conflict_msg

    # Fusión automática de todos los sub-casos derivados (source_case="all")
    merge_res = json.loads(
        await ok(
            service,
            "osint_manage_case",
            {
                "case_id": "op-swarm",
                "action": "merge",
                "source_case": "all",
                "response_format": "json",
            },
        )
    )
    assert merge_res["new_entities"] == 2
    ents, _ = await service.store.export_case("op-swarm", 500)
    values = {e.value for e in ents}
    assert {"example.com", "93.184.216.34", "sec_operator"} <= values


async def test_core2_breach_semantic_router_sqlite_local_y_cli(
    service: OsintService, tmp_path: Path, monkeypatch: Any
) -> None:
    """Core 2: Indexación SQLite local (.csv, .jsonl, .txt), CLI index-breaches y BreachSemanticPivot."""
    monkeypatch.setenv("MALTEGO_MCP_HOME", str(tmp_path))
    csv_file = tmp_path / "leak_2025.csv"
    csv_file.write_text(
        "email,username,domain,phone,hash,breach,date\n"
        "operador@corp.example,op_zero,corp.example,+34600112233,5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8,DarkVault,2025-02-14\n",
        encoding="utf-8",
    )
    assert cli_main(["index-breaches", str(csv_file)]) == 0

    db_path = tmp_path / "breaches.sqlite"
    assert db_path.is_file()
    hits = query_local_breaches(db_path, "email", "operador@corp.example")
    assert len(hits) == 1
    assert hits[0].breach_name == "DarkVault"
    assert hits[0].alias == "op_zero"

    # También probamos fichero .jsonl directo
    jsonl_file = tmp_path / "combo.jsonl"
    jsonl_file.write_text(
        json.dumps({"email": "otro@corp.example", "alias": "otro_op", "breach": "Dump2026", "date": "2026-01-10"})
        + "\n",
        encoding="utf-8",
    )
    assert index_breach_file(db_path, jsonl_file) == 1

    # Servicio con transforms integrados y HTTP simulado (sin red real)
    svc_builtin = OsintService(
        service.store,
        service.catalog.with_builtins(),
        service.export_dir,
    )
    svc_builtin._http = new_http_client(transport=httpx.MockTransport(Router()))
    svc_builtin.env = {"MALTEGO_MCP_HOME": str(tmp_path)}
    res = json.loads(
        await ok(
            svc_builtin,
            "osint_run_transform",
            {
                "case_id": "caso-breach",
                "transform": "BreachSemanticPivot",
                "entity_type": "maltego.EmailAddress",
                "value": "operador@corp.example",
                "response_format": "json",
            },
        )
    )
    out_values = {e["entity"]["value"] for e in res["results"]}
    assert "[Breach] DarkVault" in out_values
    assert "op_zero" in out_values
    assert "+34600112233" in out_values


async def test_core3_dynamic_visual_layouts_y_mtgx_styles(service: OsintService) -> None:
    """Core 3: osint_manage_entity(action='visual_style') e inyección de estilos/notas en .mtgx."""
    ent = json.loads(
        await ok(
            service,
            "osint_upsert_entity",
            {
                "case_id": "caso-visual",
                "entity_type": "humint.Alias",
                "value": "target_alpha",
                "notes": "Nota de inteligencia HUMINT",
                "response_format": "json",
            },
        )
    )
    eid = ent["entity"]["id"]
    styled = json.loads(
        await ok(
            service,
            "osint_manage_entity",
            {
                "case_id": "caso-visual",
                "entity_id": eid,
                "action": "visual_style",
                "visual_weight": 95,
                "visual_color": "#e11d48",
                "visual_size": "xl",
                "response_format": "json",
            },
        )
    )
    assert styled["entity"]["properties"]["visual.weight"] == "95"
    assert styled["entity"]["properties"]["visual.color"] == "#e11d48"
    assert styled["entity"]["properties"]["visual.size"] == "xl"

    # Crear rasgo psicológico (hipótesis) y enlazarlo para verificar estilo discontinuo (dashed) en .mtgx
    trait = json.loads(
        await ok(
            service,
            "osint_upsert_entity",
            {
                "case_id": "caso-visual",
                "entity_type": "humint.PsychologicalTrait",
                "value": "[Hipótesis] Alta apertura técnica",
                "properties": ["humint.epistemic_status=hypothesis"],
                "response_format": "json",
            },
        )
    )
    await ok(
        service,
        "osint_link_entities",
        {
            "case_id": "caso-visual",
            "source_id": eid,
            "target_id": trait["entity"]["id"],
            "edge_label": "exhibits_trait",
            "action": "analyze",
            "role": "operador",
            "sentiment": "profesional",
            "weight": 80,
        },
    )

    exp_txt = await ok(
        service,
        "osint_export_case",
        {"case_id": "caso-visual", "format": "mtgx"},
    )
    mtgx_file = next(service.export_dir.glob("caso-visual-*.mtgx"))
    assert str(mtgx_file) in exp_txt
    raw_bytes = mtgx_file.read_bytes()
    info = inspect_mtgx(raw_bytes)
    assert info["valid"] is True

    imported = read_mtgx(raw_bytes)
    by_val = {e.value: e for e in imported.entities}
    assert by_val["target_alpha"].properties.get("visual.color") == "#e11d48"
    assert len(imported.links) == 1
    assert imported.links[0].properties.get("humint.role") == "operador"
    assert imported.links[0].properties.get("humint.epistemic_status") == "hypothesis"


async def test_humint1_ontologia_humint_nativa(service: OsintService) -> None:
    """HUMINT 1: Ontología HUMINT nativa empaquetada en el servidor y normalización de sus 4 tipos."""
    types_json = json.loads(
        await ok(
            service,
            "osint_list_entity_types",
            {"category": "humint", "response_format": "json"},
        )
    )
    humint_types = {t["maltego_type"] for t in types_json["items"]}
    assert humint_types == {
        "humint.Alias",
        "humint.Organization",
        "humint.LocationHistory",
        "humint.PsychologicalTrait",
    }

    # Verificar creación e id determinista de los 4 tipos HUMINT
    for mtype, val in [
        ("humint.Alias", "@Ghost_Op"),
        ("humint.Organization", "Colectivo Sigma"),
        ("humint.LocationHistory", "Madrid (UTC+1)"),
        ("humint.PsychologicalTrait", "[Hipótesis] Alta meticulosidad técnica"),
    ]:
        created = json.loads(
            await ok(
                service,
                "osint_upsert_entity",
                {
                    "case_id": "caso-ontologia-humint",
                    "entity_type": mtype,
                    "value": val,
                    "response_format": "json",
                },
            )
        )
        assert created["created"] is True
        assert created["entity"]["maltego_type"] == mtype


async def test_humint2_perfilado_conductual_y_persona_footprint_machine(service: OsintService) -> None:
    """HUMINT 2: Perfilado conductual con salvaguarda [Hipótesis] y Machine PersonaFootprint."""
    subj = json.loads(
        await ok(
            service,
            "osint_upsert_entity",
            {
                "case_id": "caso-humint-beh",
                "entity_type": "humint.Alias",
                "value": "jdoe",
                "properties": [
                    "bio=Security researcher & developer at @AcmeLabs in Madrid UTC+1. Building open source tools!",
                    "location=Madrid, Spain",
                    "company=@AcmeLabs",
                ],
                "notes": "Publica análisis técnicos detallados y coordina equipo en @AcmeLabs.",
                "response_format": "json",
            },
        )
    )
    sid = subj["entity"]["id"]
    beh = json.loads(
        await ok(
            service,
            "osint_manage_entity",
            {
                "case_id": "caso-humint-beh",
                "entity_id": sid,
                "action": "analyze_behavior",
                "response_format": "json",
            },
        )
    )
    assert beh["emitted"]
    assert all(
        e["value"].startswith("[Hipótesis]") for e in beh["emitted"] if e["maltego_type"] == "humint.PsychologicalTrait"
    )

    # Ejecutar la Machine PersonaFootprint con HTTP simulado (sin red)
    svc_builtin = OsintService(
        service.store,
        service.catalog.with_builtins(),
        service.export_dir,
    )
    svc_builtin._http = new_http_client(transport=httpx.MockTransport(Router()))
    m_res = json.loads(
        await ok(
            svc_builtin,
            "osint_run_machine",
            {
                "case_id": "caso-persona-machine",
                "machine": "PersonaFootprint",
                "entity_type": "humint.Alias",
                "value": "jdoe",
                "max_rounds": 1,
                "response_format": "json",
            },
        )
    )
    assert m_res["machine"] == "PersonaFootprint"
    assert m_res["new_entities"] >= 3


async def test_humint3_correlacion_identidades_pseudonym_linker(service: OsintService) -> None:
    """HUMINT 3: Motor matemático de correlación de identidades (handle, metadatos, estilometría y grafo)."""
    a1 = json.loads(
        await ok(
            service,
            "osint_upsert_entity",
            {
                "case_id": "caso-corr",
                "entity_type": "humint.Alias",
                "value": "c0d3_w0lf",
                "properties": [
                    "bio= Offensive security researcher & kernel hacker building rust tools in Madrid ",
                    "location=Madrid",
                    "timezone=UTC+1",
                    "url=https://codewolf.dev",
                ],
                "response_format": "json",
            },
        )
    )["entity"]["id"]
    a2 = json.loads(
        await ok(
            service,
            "osint_upsert_entity",
            {
                "case_id": "caso-corr",
                "entity_type": "maltego.Alias",
                "value": "code_wolf",
                "properties": [
                    "bio=Offensive security researcher and kernel hacker building rust tools in Madrid!",
                    "location=Madrid",
                    "timezone=UTC+1",
                    "website=https://codewolf.dev",
                ],
                "response_format": "json",
            },
        )
    )["entity"]["id"]
    # Vecino común en el grafo (repositorio o dominio compartido)
    dom = json.loads(
        await ok(
            service,
            "osint_upsert_entity",
            {
                "case_id": "caso-corr",
                "entity_type": "maltego.Website",
                "value": "codewolf.dev",
                "response_format": "json",
            },
        )
    )["entity"]["id"]
    await ok(service, "osint_link_entities", {"case_id": "caso-corr", "source_id": a1, "target_id": dom})
    await ok(service, "osint_link_entities", {"case_id": "caso-corr", "source_id": a2, "target_id": dom})

    corr = json.loads(
        await ok(
            service,
            "osint_link_entities",
            {
                "case_id": "caso-corr",
                "source_id": a1,
                "target_id": a2,
                "action": "correlate",
                "response_format": "json",
            },
        )
    )
    assert corr["count"] == 1
    match = corr["matches"][0]
    assert match["probability"] >= 0.85
    assert match["same_individual"] is True

    _, edges = await service.store.export_case("caso-corr", 500)
    auto_edges = [e for e in edges if e.label == "humint_highly_likely_same_individual"]
    assert len(auto_edges) == 1
    assert auto_edges[0].properties.get("maltego.link.manual.type") == "humint.HighlyLikelySameIndividual"


async def test_humint4_timeline_conductual_sujeto_y_anomalias(service: OsintService) -> None:
    """HUMINT 4: Línea temporal conductual de sujeto y detección de paradojas/rotación post-brecha."""
    # Dominio creado en 2024, pero perfil que afirma existir desde 2021 con ese dominio -> paradoja cronológica
    dom = json.loads(
        await ok(
            service,
            "osint_upsert_entity",
            {
                "case_id": "caso-time",
                "entity_type": "maltego.Domain",
                "value": "shadowops.example",
                "properties": ["whois.created=2024-06-01T00:00:00Z"],
                "response_format": "json",
            },
        )
    )["entity"]["id"]
    alias_old = json.loads(
        await ok(
            service,
            "osint_upsert_entity",
            {
                "case_id": "caso-time",
                "entity_type": "humint.Alias",
                "value": "admin_shadowops",
                "properties": [
                    "website=shadowops.example",
                    "github.created_at=2021-03-10T12:00:00Z",
                    "timezone=UTC-5",
                ],
                "response_format": "json",
            },
        )
    )["entity"]["id"]
    breach = json.loads(
        await ok(
            service,
            "osint_upsert_entity",
            {
                "case_id": "caso-time",
                "entity_type": "maltego.Phrase",
                "value": "[Breach] LeakCorp",
                "properties": ["breach.date=2025-01-10"],
                "response_format": "json",
            },
        )
    )["entity"]["id"]
    await ok(
        service,
        "osint_upsert_entity",
        {
            "case_id": "caso-time",
            "entity_type": "humint.Alias",
            "value": "new_handle_2025",
            "properties": [
                "github.created_at=2025-01-25T09:00:00Z",
                "timezone=UTC+3",
            ],
            "response_format": "json",
        },
    )
    await ok(service, "osint_link_entities", {"case_id": "caso-time", "source_id": alias_old, "target_id": dom})
    await ok(service, "osint_link_entities", {"case_id": "caso-time", "source_id": alias_old, "target_id": breach})

    tl = json.loads(
        await ok(
            service,
            "osint_get_timeline",
            {"case_id": "caso-time", "mode": "subject", "response_format": "json"},
        )
    )
    assert tl["mode"] == "subject"
    assert len(tl["events"]) >= 4
    anomaly_kinds = {a["kind"] for a in tl["anomalies"]}
    assert "timezone_conflict" in anomaly_kinds
    assert "chronology_paradox" in anomaly_kinds
    assert "post_breach_pivot" in anomaly_kinds


async def test_humint5_relaciones_ponderadas_y_anotadas(service: OsintService) -> None:
    """HUMINT 5: Relaciones ponderadas y anotadas (explícitas e inferidas topológicamente)."""
    lead = json.loads(
        await ok(
            service,
            "osint_upsert_entity",
            {
                "case_id": "caso-rel",
                "entity_type": "humint.Alias",
                "value": "coordinator_alpha",
                "notes": "Coordina operaciones y mantiene actitud hostil frente a grupos rivales.",
                "response_format": "json",
            },
        )
    )["entity"]["id"]
    org = json.loads(
        await ok(
            service,
            "osint_upsert_entity",
            {
                "case_id": "caso-rel",
                "entity_type": "humint.Organization",
                "value": "Grupo Eclipse",
                "response_format": "json",
            },
        )
    )["entity"]["id"]

    # 1. Enlace con rol, sentimiento y peso explícitos
    link_explicit = json.loads(
        await ok(
            service,
            "osint_link_entities",
            {
                "case_id": "caso-rel",
                "source_id": lead,
                "target_id": org,
                "edge_label": "directs_group",
                "action": "analyze",
                "role": "lider",
                "sentiment": "estrecho",
                "weight": 92,
                "properties": ["channel=matrix"],
                "response_format": "json",
            },
        )
    )
    props = link_explicit["edge"]["properties"]
    assert props["humint.role"] == "lider"
    assert props["humint.sentiment"] == "estrecho"
    assert props["humint.weight"] == "92"
    assert props["channel"] == "matrix"
    assert props["humint.epistemic_status"] == "observed"

    # 2. Inferencia automática (sin indicar role ni sentiment)
    rival = json.loads(
        await ok(
            service,
            "osint_upsert_entity",
            {
                "case_id": "caso-rel",
                "entity_type": "humint.Alias",
                "value": "rival_node",
                "notes": "Conflicto directo y rival de coordinator_alpha.",
                "response_format": "json",
            },
        )
    )["entity"]["id"]
    link_inferred = json.loads(
        await ok(
            service,
            "osint_link_entities",
            {
                "case_id": "caso-rel",
                "source_id": lead,
                "target_id": rival,
                "edge_label": "disputes_with",
                "action": "analyze",
                "response_format": "json",
            },
        )
    )
    inf_props = link_inferred["edge"]["properties"]
    assert inf_props["humint.sentiment"] == "hostil"
    assert inf_props["humint.epistemic_status"] == "hypothesis"
