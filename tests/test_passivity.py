"""Pruebas exhaustivas de política pasiva global, clasificación de 53 transforms,
modo confidencial y pivotes indirectos M3 (F3).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp import Client
from mcp.types import TextContent

from maltego_mcp.analysis import indirect_pivots_for_entity
from maltego_mcp.domain.records import EntityRecord
from maltego_mcp.errors import EgressBlockedError
from maltego_mcp.graph.memory import MemoryGraphStore
from maltego_mcp.server import create_server
from maltego_mcp.service import OsintService
from maltego_mcp.transforms.builtin import BUILTIN_TRANSFORMS, TRANSFORM_PASSIVITY, new_http_client
from maltego_mcp.transforms.catalog import TransformCatalog
from maltego_mcp.transforms.pdns import (
    fetch_anubis_subdomains,
    fetch_mnemonic_pdns,
    fetch_otx_pdns,
    fetch_passive_ptr,
    fetch_robtex_pdns,
    fetch_wayback_cdx,
)
from tests.test_builtin import Router


@pytest.fixture
def passive_svc(tmp_path: Path, catalog: TransformCatalog) -> OsintService:
    s = OsintService(
        MemoryGraphStore(tmp_path / "g.json"),
        catalog.with_builtins(),
        tmp_path / "exports",
        tmp_path / "imports",
    )
    s.env = {}  # modo pasivo por defecto
    s._http = new_http_client(transport=httpx.MockTransport(Router()))
    return s


@pytest.fixture
def active_svc(tmp_path: Path, catalog: TransformCatalog, monkeypatch: pytest.MonkeyPatch) -> OsintService:
    monkeypatch.setenv("MALTEGO_MCP_ALLOW_ACTIVE", "1")
    s = OsintService(
        MemoryGraphStore(tmp_path / "g_active.json"),
        catalog.with_builtins(),
        tmp_path / "exports",
        tmp_path / "imports",
    )
    s.env = {"MALTEGO_MCP_ALLOW_ACTIVE": "1"}  # modo activo explícito
    s._http = new_http_client(transport=httpx.MockTransport(Router()), allow_active=True)
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


async def err(svc: OsintService, tool: str, args: dict[str, Any]) -> str:
    is_err, text = await call(svc, tool, args)
    assert is_err, text
    return text


def test_clasificacion_exacta_56_transforms() -> None:
    """Verifica que los 63 transforms integrados están clasificados en los 4 niveles."""
    assert len(BUILTIN_TRANSFORMS) == 63
    counts: dict[str, int] = {"local": 0, "passive": 0, "active_proxy": 0, "active_direct": 0}
    for b in BUILTIN_TRANSFORMS:
        assert b.name in TRANSFORM_PASSIVITY, f"Falta clasificación de passivity para {b.name}"
        lvl = b.passivity
        assert lvl in counts, f"Nivel inválido {lvl} en {b.name}"
        counts[lvl] += 1
        assert b.is_passive == (lvl in ("local", "passive"))

    assert counts["local"] == 10
    assert counts["passive"] == 48
    assert counts["active_proxy"] == 4
    assert counts["active_direct"] == 1
    assert sum(counts.values()) == 63


@pytest.mark.asyncio
async def test_run_transform_bloquea_activo_en_modo_pasivo(passive_svc: OsintService) -> None:
    """En modo pasivo, ejecutar VTDomainToIP o OnionPassivePivot falla con mensaje accionable."""
    msg = await err(
        passive_svc,
        "osint_run_transform",
        {"case_id": "c1", "transform": "VTDomainToIP", "entity_type": "maltego.Domain", "value": "example.com"},
    )
    assert "bloqueado en modo pasivo" in msg
    assert "MALTEGO_MCP_MODE=active" in msg

    msg_onion = await err(
        passive_svc,
        "osint_run_transform",
        {"case_id": "c1", "transform": "OnionPassivePivot", "entity_type": "maltego.URL", "value": "http://test.onion"},
    )
    assert "bloqueado en modo pasivo" in msg_onion


@pytest.mark.asyncio
async def test_run_transform_permite_pasivo_en_modo_pasivo(passive_svc: OsintService) -> None:
    """En modo pasivo, transforms catalogados como passive o local se ejecutan normalmente."""
    text = await ok(
        passive_svc,
        "osint_run_transform",
        {"case_id": "c1", "transform": "DomainToWhois", "entity_type": "maltego.Domain", "value": "example.com"},
    )
    assert "DomainToWhois" in text


@pytest.mark.asyncio
async def test_run_transform_permite_activo_en_modo_activo(active_svc: OsintService) -> None:
    """En modo activo (MALTEGO_MCP_ALLOW_ACTIVE=1), VTDomainToIP se ejecuta sin bloqueo."""
    active_svc.env["VIRUSTOTAL_API_KEY"] = "fake_vt"
    text = await ok(
        active_svc,
        "osint_run_transform",
        {"case_id": "c1", "transform": "VTDomainToIP", "entity_type": "maltego.Domain", "value": "example.com"},
    )
    assert "VTDomainToIP" in text


@pytest.mark.asyncio
async def test_expand_entity_filtra_activos_en_modo_pasivo(passive_svc: OsintService) -> None:
    """osint_expand_entity omite transforms no pasivos en modo pasivo."""
    await ok(
        passive_svc,
        "osint_upsert_entity",
        {"case_id": "exp_case", "entity_type": "maltego.Domain", "value": "example.com"},
    )
    ents = json.loads(
        await ok(
            passive_svc,
            "osint_search_entities",
            {"case_id": "exp_case", "pattern": "example.com", "response_format": "json"},
        )
    )["items"]
    eid = ents[0]["id"]
    res = json.loads(
        await ok(
            passive_svc,
            "osint_expand_entity",
            {"case_id": "exp_case", "entity_id": eid, "response_format": "json"},
        )
    )
    executed = {r["transform"] for r in res["runs"]}
    assert "VTDomainToIP" not in executed
    assert "VTDomainToSubdomains" not in executed
    assert "OnionPassivePivot" not in executed


@pytest.mark.asyncio
async def test_run_machine_omite_pasos_activos_en_modo_pasivo(passive_svc: OsintService) -> None:
    """run_machine no revienta si la machine incluye pasos activos; los marca en unavailable."""
    res = json.loads(
        await ok(
            passive_svc,
            "osint_run_machine",
            {
                "case_id": "mach_case",
                "entity_type": "maltego.Domain",
                "value": "example.com",
                "machine": "DomainRecon",
                "response_format": "json",
            },
        )
    )
    unavail = set(res.get("unavailable", []))
    assert "VTDomainToSubdomains" in unavail
    by_stage = {(s["stage"], s["transform"]) for s in res["steps"]}
    assert (1, "VTDomainToSubdomains") not in by_stage
    assert (1, "DomainToWhois") in by_stage


@pytest.mark.asyncio
async def test_sugerencias_solo_pasivas_en_modo_pasivo(passive_svc: OsintService) -> None:
    """osint_suggest_next_steps solo sugiere transforms pasivos/locales en modo pasivo."""
    await ok(
        passive_svc,
        "osint_upsert_entity",
        {"case_id": "sug_case", "entity_type": "maltego.Domain", "value": "example.com"},
    )
    res = json.loads(
        await ok(
            passive_svc,
            "osint_suggest_next_steps",
            {"case_id": "sug_case", "response_format": "json"},
        )
    )
    for act in res["actions"]:
        spec = passive_svc.catalog.get(act["transform"])
        assert spec.is_passive, f"Transform activo '{act['transform']}' sugerido en modo pasivo"


def test_pivotes_indirectos_m3() -> None:
    """Verifica generador de pivotes indirectos ('¿Quién más habla de esto?')."""
    ent_domain = EntityRecord(
        id="dom1", case_id="c1", label="example.com", maltego_type="maltego.Domain", value="example.com"
    )
    pivs = indirect_pivots_for_entity(ent_domain)
    assert len(pivs) >= 4
    assert any("Wayback" in p or "históricas" in p for p in pivs)
    assert any("Certificate Transparency" in p for p in pivs)

    ent_ip = EntityRecord(
        id="ip1", case_id="c1", label="93.184.216.34", maltego_type="maltego.IPv4Address", value="93.184.216.34"
    )
    pivs_ip = indirect_pivots_for_entity(ent_ip)
    assert any("BGP" in p or "prefijos" in p for p in pivs_ip)


@pytest.mark.asyncio
async def test_modo_confidencial_por_caso(passive_svc: OsintService) -> None:
    """osint_manage_case permite crear caso confidencial o activarlo como action."""
    # Crear como confidencial
    res_create = json.loads(
        await ok(
            passive_svc,
            "osint_manage_case",
            {"case_id": "sec-01", "description": "Caso confidencial", "confidential": True, "response_format": "json"},
        )
    )
    assert res_create["case"]["confidential"] is True

    # Caso normal cambiado a confidencial
    await ok(
        passive_svc,
        "osint_manage_case",
        {"case_id": "sec-02", "description": "Caso normal"},
    )
    case_before = await passive_svc.store.get_case("sec-02")
    assert case_before is not None and not case_before.confidential

    res_toggle = json.loads(
        await ok(
            passive_svc,
            "osint_manage_case",
            {"case_id": "sec-02", "action": "set_confidential", "confidential": True, "response_format": "json"},
        )
    )
    assert res_toggle["confidential"] is True
    case_after = await passive_svc.store.get_case("sec-02")
    assert case_after is not None and case_after.confidential


@pytest.mark.asyncio
async def test_list_transforms_muestra_passivity(passive_svc: OsintService) -> None:
    """osint_list_transforms expone el campo passivity y el modo MCP actual."""
    data = json.loads(await ok(passive_svc, "osint_list_transforms", {"response_format": "json"}))
    txs = {t["name"]: t for t in data["transforms"]}
    assert txs["VTDomainToIP"]["passivity"] == "active_proxy"
    assert txs["VTDomainToIP"]["is_passive"] is False
    assert txs["DNSToIP"]["passivity"] == "passive"
    assert txs["DNSToIP"]["is_passive"] is True
    assert txs["DomainToWhois"]["passivity"] == "passive"
    assert txs["DomainToWhois"]["is_passive"] is True
    assert txs["EmailToDomain"]["passivity"] == "local"
    assert txs["EmailToDomain"]["is_passive"] is True

    md = await ok(passive_svc, "osint_list_transforms", {"response_format": "markdown"})
    assert "pasividad" in md.lower()
    assert "modo mcp" in md.lower() and "pasivo" in md.lower()


# ------------------------------------------------------------------------------------- NO TRAGAR EGRESS ERRORS (S2)
@pytest.mark.asyncio
async def test_fetchers_propagan_egress_blocked_error() -> None:
    """Verifica que los fetchers pasivos NO traguen EgressBlockedError ni EgressKillSwitchError (S2/B12)."""

    def raising_handler(req: httpx.Request) -> httpx.Response:
        raise EgressBlockedError(f"Bloqueado por pasividad: {req.url}")

    blocking_client = httpx.AsyncClient(transport=httpx.MockTransport(raising_handler))

    async with blocking_client:
        with pytest.raises(EgressBlockedError):
            await fetch_mnemonic_pdns(blocking_client, "example.com")

        with pytest.raises(EgressBlockedError):
            await fetch_robtex_pdns(blocking_client, "example.com")

        with pytest.raises(EgressBlockedError):
            await fetch_otx_pdns(blocking_client, "example.com", "fake_key")

        with pytest.raises(EgressBlockedError):
            await fetch_passive_ptr(blocking_client, "93.184.216.34")

        with pytest.raises(EgressBlockedError):
            await fetch_wayback_cdx(blocking_client, "example.com")

        with pytest.raises(EgressBlockedError):
            await fetch_anubis_subdomains(blocking_client, "example.com")
