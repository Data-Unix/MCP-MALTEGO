"""Pruebas exhaustivas para F5: Machines pasivas, DEFAULT_MACHINE_BY_TYPE y vigencia (§4.4)."""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp import Client
from mcp.types import TextContent

from maltego_mcp.analysis import compute_entity_validity
from maltego_mcp.domain.records import EntityRecord
from maltego_mcp.graph.memory import MemoryGraphStore
from maltego_mcp.machines import (
    BUILTIN_MACHINES,
    DEFAULT_MACHINE_BY_TYPE_ACTIVE,
    DEFAULT_MACHINE_BY_TYPE_PASSIVE,
    MachineCatalog,
)
from maltego_mcp.server import create_server
from maltego_mcp.service import OsintService
from maltego_mcp.transforms.builtin import TRANSFORM_PASSIVITY, new_http_client
from maltego_mcp.transforms.catalog import TransformCatalog
from tests.test_builtin import Router


@pytest.fixture
def passive_svc(tmp_path: Path, catalog: TransformCatalog) -> OsintService:
    s = OsintService(
        MemoryGraphStore(tmp_path / "g_f5.json"),
        catalog.with_builtins(),
        tmp_path / "exports",
        tmp_path / "imports",
    )
    s.env = {}  # modo pasivo
    s._http = new_http_client(transport=httpx.MockTransport(Router()))
    return s


async def call(svc: OsintService, tool: str, args: dict[str, Any]) -> tuple[bool, str]:
    async with Client(create_server(service=svc)) as client:
        result = await client.call_tool(tool, args)
    block = result.content[0]
    assert isinstance(block, TextContent)
    return bool(result.is_error), block.text


async def ok(svc: OsintService, tool: str, args: dict[str, Any]) -> str:
    is_err, text = await call(svc, tool, args)
    assert not is_err, text
    return text


def test_nuevas_machines_pasivas_100_por_ciento_pasivas() -> None:
    """Verifica que las 5 nuevas machines pasivas están registradas y solo usan transforms pasivos/locales."""
    by_name = {m.name: m for m in BUILTIN_MACHINES}
    passive_machine_names = (
        "PassiveDomainRecon",
        "PassiveInfrastructureRecon",
        "PassiveEmailRecon",
        "PassiveURLRecon",
        "PassiveCompanyFootprint",
    )
    for name in passive_machine_names:
        assert name in by_name, f"Falta la machine pasiva {name}"
        m = by_name[name]
        for stage_idx, stage in enumerate(m.stages, start=1):
            for tx in stage:
                passivity = TRANSFORM_PASSIVITY.get(tx)
                assert passivity in (
                    "passive",
                    "local",
                ), (
                    f"Machine pasiva '{name}' incluye transform '{tx}' con nivel no pasivo "
                    f"'{passivity}' en etapa {stage_idx}"
                )


def test_default_machine_by_type_segun_modo() -> None:
    """Comprueba que DEFAULT_MACHINE_BY_TYPE resuelve a pasivas en modo pasivo y activas en modo activo."""
    mc = MachineCatalog({m.name.lower(): m for m in BUILTIN_MACHINES})

    # Modo pasivo por defecto
    m_dom_passive = mc.for_type("maltego.Domain", is_passive=True)
    assert m_dom_passive is not None
    assert m_dom_passive.name == "PassiveDomainRecon"

    m_ip_passive = mc.for_type("maltego.IPv4Address", is_passive=True)
    assert m_ip_passive is not None
    assert m_ip_passive.name == "PassiveInfrastructureRecon"

    m_email_passive = mc.for_type("maltego.EmailAddress", is_passive=True)
    assert m_email_passive is not None
    assert m_email_passive.name == "PassiveEmailRecon"

    # Modo activo
    m_dom_active = mc.for_type("maltego.Domain", is_passive=False)
    assert m_dom_active is not None
    assert m_dom_active.name == "DomainRecon"

    m_ip_active = mc.for_type("maltego.IPv4Address", is_passive=False)
    assert m_ip_active is not None
    assert m_ip_active.name == "InfrastructureRecon"

    # Tablas directas
    assert DEFAULT_MACHINE_BY_TYPE_PASSIVE["maltego.domain"] == "PassiveDomainRecon"
    assert DEFAULT_MACHINE_BY_TYPE_ACTIVE["maltego.domain"] == "DomainRecon"


def test_vigencia_observado_reciente() -> None:
    """2 clústeres independientes recientes (<=30d pDNS, <=90d CT) -> OBSERVADO_RECIENTE."""
    now = datetime.datetime(2024, 6, 1, 12, 0, 0, tzinfo=datetime.UTC)
    ent = EntityRecord(
        id="ent-1",
        case_id="c1",
        label="target.example",
        maltego_type="maltego.Domain",
        value="target.example",
        properties={
            "pdns__source": "mnemonic",
            "independence_cluster": "pdns_sensor_mnemonic",
            "pdns__mnemonic__last_seen": "2024-05-25T00:00:00Z",  # hace 7 días
            "ct__source": "crt.sh",
            "ct__not_before": "2024-04-01T00:00:00Z",  # hace 61 días (<90d)
        },
    )
    val = compute_entity_validity(ent, now=now)
    assert val.status == "OBSERVADO_RECIENTE"
    assert val.recent_clusters_count >= 2
    assert val.score >= 50
    assert "Activo confirmado" in val.rationale
    assert "muerto" not in val.rationale.lower()


def test_vigencia_historico_sin_recientes() -> None:
    """Evidencias fechadas pero antiguas (>30d pDNS, >90d CT) -> HISTORICO. Nunca 'muerto'."""
    now = datetime.datetime(2024, 6, 1, 12, 0, 0, tzinfo=datetime.UTC)
    ent = EntityRecord(
        id="ent-2",
        case_id="c1",
        label="old.example",
        maltego_type="maltego.Domain",
        value="old.example",
        properties={
            "pdns__source": "robtex",
            "independence_cluster": "pdns_aggregator_robtex",
            "pdns__robtex__last_seen": "2023-01-01T00:00:00Z",  # hace más de 1 año
        },
    )
    val = compute_entity_validity(ent, now=now)
    assert val.status == "HISTORICO"
    assert val.recent_clusters_count == 0
    assert "Sin evidencia reciente" in val.rationale
    assert "muerto" not in val.rationale.lower()


def test_vigencia_mencionado_sin_fecha() -> None:
    """Solo agregadores sin fecha -> MENCIONADO_SIN_FECHA."""
    now = datetime.datetime(2024, 6, 1, 12, 0, 0, tzinfo=datetime.UTC)
    ent = EntityRecord(
        id="ent-3",
        case_id="c1",
        label="agg.example",
        maltego_type="maltego.Domain",
        value="agg.example",
        properties={
            "pdns__source": "hackertarget",
            "independence_cluster": "osint_hackertarget_reverse",
        },
    )
    val = compute_entity_validity(ent, now=now)
    assert val.status == "MENCIONADO_SIN_FECHA"
    assert "sin marca temporal" in val.rationale


def test_vigencia_maximo_por_cluster_no_duplica() -> None:
    """Dos registros del mismo clúster toman el máximo y no duplican la puntuación."""
    now = datetime.datetime(2024, 6, 1, 12, 0, 0, tzinfo=datetime.UTC)
    ent = EntityRecord(
        id="ent-4",
        case_id="c1",
        label="cluster.example",
        maltego_type="maltego.Domain",
        value="cluster.example",
        properties={
            "pdns__source": "mnemonic",
            "independence_cluster": "pdns_sensor_mnemonic",
            "pdns__mnemonic__last_seen": "2024-05-25T00:00:00Z",
        },
    )
    val1 = compute_entity_validity(ent, now=now)

    # Entidad con misma observación duplicada
    ent_dup = EntityRecord(
        id="ent-5",
        case_id="c1",
        label="cluster.example",
        maltego_type="maltego.Domain",
        value="cluster.example",
        properties={
            "pdns__source": "mnemonic",
            "independence_cluster": "pdns_sensor_mnemonic",
            "pdns__mnemonic__last_seen": "2024-05-25T00:00:00Z",
            "pdns__mnemonic__first_seen": "2024-05-25T00:00:00Z",
        },
    )
    val2 = compute_entity_validity(ent_dup, now=now)
    assert val1.score == val2.score
    assert val2.independent_clusters_count == 1


@pytest.mark.asyncio
async def test_osint_investigate_pasivo_ejecuta_passivedomainrecon(passive_svc: OsintService) -> None:
    """En modo pasivo, osint_investigate usa automáticamente PassiveDomainRecon."""
    res_raw = await ok(
        passive_svc,
        "osint_investigate",
        {"value": "example.com", "entity_type": "maltego.Domain", "response_format": "json"},
    )
    data = json.loads(res_raw)
    assert data["strategy"] == "PassiveDomainRecon"


@pytest.mark.asyncio
async def test_explain_entity_muestra_vigencia(passive_svc: OsintService) -> None:
    """osint_get_entity incluye la sección de vigencia objetiva (§4.4) en JSON y Markdown."""
    await ok(
        passive_svc,
        "osint_upsert_entity",
        {
            "case_id": "vig_case",
            "entity_type": "maltego.Domain",
            "value": "portal.corp",
            "properties": [
                "pdns.source=mnemonic",
                "independence_cluster=pdns_sensor_mnemonic",
                "pdns.mnemonic.last_seen=2024-01-01T00:00:00Z",
            ],
        },
    )
    ents = json.loads(
        await ok(
            passive_svc,
            "osint_search_entities",
            {"case_id": "vig_case", "pattern": "portal.corp", "response_format": "json"},
        )
    )["items"]
    eid = ents[0]["id"]

    # Formato JSON
    res_json = json.loads(
        await ok(
            passive_svc,
            "osint_get_entity",
            {"case_id": "vig_case", "entity_id": eid, "response_format": "json"},
        )
    )
    assert "validity" in res_json
    assert res_json["validity"]["status"] in ("OBSERVADO_RECIENTE", "HISTORICO")

    # Formato Markdown
    res_md = await ok(
        passive_svc,
        "osint_get_entity",
        {"case_id": "vig_case", "entity_id": eid, "response_format": "markdown"},
    )
    assert "Vigencia objetiva" in res_md
