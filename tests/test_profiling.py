"""Tests unitarios y de integración para el módulo unificado de perfilado (profiling).

Comprueba las 21 tipologías de los 6 pilares operativos, deducción automática,
proyección de nodos y aristas en el grafo, compatibilidad con la tool osint_manage_entity
y ausencia total de emojis prohibidos.
"""

from __future__ import annotations

import re
from typing import Any

import pytest
from mcp import Client

from maltego_mcp.domain.profiling import (
    GOLDWATER_ETHICAL_WARNING,
    TYPOLOGY_TITLES,
    TYPOLOGY_TO_DOMAIN,
    ProfileTypology,
)
from maltego_mcp.domain.records import EntityRecord
from maltego_mcp.graph.memory import MemoryGraphStore
from maltego_mcp.profiling.engine import deduce_typology, execute_profile
from maltego_mcp.server import create_server
from maltego_mcp.service import OsintService
from maltego_mcp.transforms.catalog import TransformCatalog

EMOJI_PATTERN = re.compile(
    r"[\U0001F600-\U0001F64F"
    r"\U0001F300-\U0001F5FF"
    r"\U0001F680-\U0001F6FF"
    r"\U0001F1E0-\U0001F1FF"
    r"\U00002600-\U000026FF"
    r"\U00002700-\U000027BF]"
)


def _make_entity(eid: str, mtype: str, val: str, notes: str = "", props: dict[str, str] | None = None) -> EntityRecord:
    return EntityRecord(
        id=eid,
        case_id="case-test-profiling",
        label=mtype.split(".")[-1],
        maltego_type=mtype,
        value=val,
        confidence=1.0,
        sources=["test"],
        properties=dict(props or {}),
        notes=notes,
    )


def test_deduccion_automatica_de_tipologia() -> None:
    e_apt = _make_entity("e1", "maltego.ThreatActor", "Lazarus Group")
    assert deduce_typology(e_apt, "") == "cyber"

    e_dev = _make_entity("e2", "maltego.Device", "iPhone 15 Pro")
    assert deduce_typology(e_dev, "") == "device"

    e_net = _make_entity("e3", "maltego.AS", "AS13335")
    assert deduce_typology(e_net, "") == "network"

    e_geo = _make_entity("e4", "maltego.GPS", "40.4168,-3.7038")
    assert deduce_typology(e_geo, "") == "geographic"

    e_comp = _make_entity("e5", "maltego.Company", "ACME Corp")
    assert deduce_typology(e_comp, "competidor directo en el mercado") == "competitor"

    e_inv = _make_entity("e6", "maltego.Company", "Elliott Management", notes="Lanzó OPA hostil y proxy fight")
    assert deduce_typology(e_inv, "campaña de desinversión") == "investor"

    e_pol = _make_entity("e7", "maltego.Person", "General Smith", notes="Presidente y comandante militar supremo")
    assert deduce_typology(e_pol, "líder de estado") == "political_leader"

    e_insider = _make_entity("e8", "maltego.Person", "John Doe", notes="Empleado con acceso denegado y descarga masiva")
    assert deduce_typology(e_insider, "amenaza interna dlp") == "insider_threat"


@pytest.mark.parametrize("typology", list(TYPOLOGY_TO_DOMAIN.keys()))
def test_ejecucion_las_21_tipologias_de_perfilado(typology: ProfileTypology) -> None:
    target = _make_entity(
        eid="target-1",
        mtype="maltego.Person" if typology != "competitor" and typology != "investor" else "maltego.Company",
        val="Subject Target X",
        notes="Registro de prueba para perfilado pericial multifuente con coordenadas 40.4168,-3.7038.",
        props={"email": "target@example.com", "gps.coordinate": "40.4168,-3.7038"},
    )
    neighbors: list[tuple[str, str, dict[str, Any]]] = [
        ("maltego.GPS", "40.4200,-3.7100", {"radius": "2km"}),
        ("maltego.Company", "Holding Corp", {"stake": "35%"}),
        ("maltego.Phrase", "Evidencia de auditoría", {"verified": "true"}),
    ]

    record = execute_profile(target, neighbors, typology)

    assert record.typology == typology
    assert record.domain == TYPOLOGY_TO_DOMAIN[typology]
    assert record.title == TYPOLOGY_TITLES[typology]
    assert len(record.archetype_label) > 3
    assert record.risk_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
    assert len(record.dimensions) >= 1
    assert len(record.traits_to_emit) >= 1
    assert len(record.strategic_recommendations) >= 1

    # Regla Goldwater en clínica
    if typology == "clinical_risk":
        assert GOLDWATER_ETHICAL_WARNING in record.summary
        assert "Regla Goldwater" in record.epistemic_warning

    # Verificación estricta de CERO EMOJIS
    dump_text = f"{record.title} {record.summary} {record.archetype_label} {' '.join(record.anomalies)}"
    assert not EMOJI_PATTERN.search(dump_text), f"Emoji prohibido detectado en tipología {typology}"


async def test_servicio_profile_entity_y_grafo(tmp_path: Any, catalog: TransformCatalog) -> None:
    svc = OsintService(
        store=MemoryGraphStore(tmp_path / "g.json"),
        catalog=catalog,
        export_dir=tmp_path,
    )
    case, _ = await svc.create_case("case-profiling-test", "Caso de validación del módulo de profiling")

    ent, _ = await svc.upsert_entity(
        case.case_id,
        "maltego.Company",
        "Target Invest Corp",
        1.0,
        "test",
        ["aum=500M", "hostil=true", "proxy=true"],
        notes="Fondo activista agresivo preparando OPA hostil y desmantelamiento.",
    )

    updated, profile, emitted = await svc.profile_entity(case.case_id, ent.id, "investor", "test_run")

    assert profile.typology == "investor"
    assert profile.domain == "corporate"
    assert "Inversor Activista" in profile.archetype_label
    assert len(emitted) >= 2

    # Verificar que el grafo vinculó los nodos emitidos con el target
    nbs = await svc.neighbors(case.case_id, ent.id, "", "both", 20)
    nb_ids = {n.entity.id for n in nbs}
    for em in emitted:
        assert em.id in nb_ids

    # Verificar propiedades añadidas al target
    assert updated.properties.get("profiling.domain") == "corporate"
    assert updated.properties.get("profiling.typology") == "investor"
    assert "Inversor Activista" in updated.properties.get("profiling.archetype", "")


async def test_tool_osint_manage_entity_action_profile() -> None:
    server = create_server()
    async with Client(server) as client:
        # 1. Crear caso
        await client.call_tool(
            "osint_manage_case",
            {"action": "create", "case_id": "case-mcp-profiling", "description": "Prueba de tool profiling"},
        )

        # 2. Insertar entidad
        res_ent = await client.call_tool(
            "osint_upsert_entity",
            {
                "case_id": "case-mcp-profiling",
                "entity_type": "maltego.Person",
                "value": "Marcus Vance",
                "notes": "Director de operaciones con alta aversión a la pérdida y gran desconfianza.",
            },
        )
        assert not res_ent.is_error

        # Buscar entity_id
        summary_res = await client.call_tool(
            "osint_search_entities",
            {"case_id": "case-mcp-profiling", "query": "Marcus Vance", "response_format": "json"},
        )
        import json

        summary_data = json.loads(summary_res.content[0].text)  # type: ignore[union-attr]
        ent_id = summary_data["items"][0]["id"]

        # 3. Ejecutar profiling en Markdown
        res_prof_md = await client.call_tool(
            "osint_manage_entity",
            {
                "case_id": "case-mcp-profiling",
                "entity_id": ent_id,
                "action": "profile",
                "profile_type": "negotiation",
                "properties": [],
                "remove_properties": [],
                "response_format": "markdown",
            },
        )
        assert not res_prof_md.is_error
        md_text = res_prof_md.content[0].text  # type: ignore[union-attr]
        assert "Perfilado de Negociación Estratégica" in md_text
        assert "Sesgo de Aversión a la Pérdida" in md_text
        assert not EMOJI_PATTERN.search(md_text), "Emoji prohibido detectado en la salida Markdown del perfilado"

        # 4. Ejecutar profiling en JSON
        res_prof_json = await client.call_tool(
            "osint_manage_entity",
            {
                "case_id": "case-mcp-profiling",
                "entity_id": ent_id,
                "action": "profile",
                "profile_type": "clinical_risk",
                "properties": [],
                "remove_properties": [],
                "response_format": "json",
            },
        )
        assert not res_prof_json.is_error
        json_data = json.loads(res_prof_json.content[0].text)  # type: ignore[union-attr]
        assert json_data["profile"]["typology"] == "clinical_risk"
        assert json_data["profile"]["domain"] == "clinical_risk"
        assert (
            "Tríada Oscura" in json_data["profile"]["title"]
            or "Tríada Oscura" in json_data["profile"]["dimensions"][0]["name"]
        )
        assert len(json_data["emitted"]) >= 1
