"""Machines, memoria de pasos, copiloto (puntuación/recomendación/explicación), gestión y entregables."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp import Client
from mcp.types import TextContent

from maltego_mcp.graph.memory import MemoryGraphStore
from maltego_mcp.maltego.mtgx import GRAPH_MEMBER, SIDECAR_MEMBER, compute_layout, read_mtgx
from maltego_mcp.server import create_server
from maltego_mcp.service import OsintService
from maltego_mcp.transforms.builtin import new_http_client
from maltego_mcp.transforms.catalog import TransformCatalog
from tests.test_builtin import Router

EXPECTED_TOOLS = {
    "osint_list_entity_types",
    "osint_list_transforms",
    "osint_manage_case",
    "osint_list_cases",
    "osint_get_case_summary",
    "osint_upsert_entity",
    "osint_manage_entity",
    "osint_get_entity",
    "osint_search_entities",
    "osint_link_entities",
    "osint_get_neighbors",
    "osint_find_paths",
    "osint_run_transform",
    "osint_expand_entity",
    "osint_run_machine",
    "osint_investigate",
    "osint_suggest_next_steps",
    "osint_get_timeline",
    "osint_export_case",
    "osint_import_graph",
}


@pytest.fixture
def svc(tmp_path: Path, catalog: TransformCatalog) -> OsintService:
    s = OsintService(
        MemoryGraphStore(tmp_path / "g.json"), catalog.with_builtins(), tmp_path / "exports", tmp_path / "imports"
    )
    s.env = {}  # sin claves: los proveedores deben omitirse e informarse
    s._http = new_http_client(transport=httpx.MockTransport(Router()))
    return s


async def call(svc: OsintService, tool: str, args: dict[str, Any], expect_error: bool = False) -> str:
    async with Client(create_server(service=svc)) as client:
        result = await client.call_tool(tool, args)
    block = result.content[0]
    assert isinstance(block, TextContent)
    assert bool(result.is_error) == expect_error, block.text
    return block.text


async def js(svc: OsintService, tool: str, args: dict[str, Any]) -> Any:
    return json.loads(await call(svc, tool, {**args, "response_format": "json"}))


async def test_exactamente_las_20_tools(svc: OsintService) -> None:
    async with Client(create_server(service=svc)) as client:
        tools = (await client.list_tools()).tools
    assert {t.name for t in tools} == EXPECTED_TOOLS
    destructive = {t.name for t in tools if t.annotations and t.annotations.destructive_hint}
    assert destructive == {"osint_manage_case", "osint_manage_entity"}


async def test_domain_recon_por_etapas_y_proveedores_omitidos(svc: OsintService) -> None:
    r = await js(
        svc,
        "osint_run_machine",
        {"case_id": "dr", "entity_type": "auto", "value": "example.com", "machine": "DomainRecon", "reason": "prueba"},
    )
    by_stage = {(s["stage"], s["transform"]) for s in r["steps"]}
    assert (1, "DomainToWhois") in by_stage and (2, "DNSToIP") in by_stage and (3, "IPToAS") in by_stage
    assert set(r["unavailable"]) == {"VTDomainToSubdomains", "SecurityTrailsSubdomains", "ShodanDomainToSubdomains"}
    found = {(e.maltego_type, e.value) for e in (await svc.search("dr", "", "", 100, 0)).items}
    assert {
        ("maltego.AS", "15133"),
        ("maltego.Netblock", "93.184.216.0/24"),
        ("maltego.DNSName", "dev.example.com"),
        ("maltego.IPv4Address", "93.184.216.35"),
        ("maltego.Organization", "RESERVED-IANA"),
    } <= found
    # En la etapa 2 DNSToIP no se repite sobre example.com (ya procesado en la etapa 1)
    timeline = await js(svc, "osint_get_timeline", {"case_id": "dr"})
    dns_inputs = [s["input_id"] for s in timeline["items"] if s["action"] == "DNSToIP"]
    assert len(dns_inputs) == len(set(dns_inputs))
    assert timeline["items"][-1]["kind"] == "machine" and timeline["items"][-1]["reason"] == "prueba"


async def test_rondas_y_presupuesto(svc: OsintService) -> None:
    one = await js(
        svc,
        "osint_run_machine",
        {
            "case_id": "r1",
            "entity_type": "maltego.EmailAddress",
            "value": "ana@example.com",
            "transforms": ["EmailToDomain"],
        },
    )
    assert one["rounds"] == 1 and one["new_entities"] == 1
    tiny = await js(
        svc,
        "osint_run_machine",
        {
            "case_id": "r2",
            "entity_type": "maltego.Domain",
            "value": "example.com",
            "machine": "DomainRecon",
            "max_total_entities": 4,
        },
    )
    assert tiny["stopped_by_budget"] is True
    assert (await svc.case_summary("r2", 0)).entity_count <= 4
    deep = await js(
        svc,
        "osint_run_machine",
        {
            "case_id": "r3",
            "entity_type": "maltego.EmailAddress",
            "value": "jdoe@example.com",
            "machine": "PersonalFootprint",
            "max_rounds": 2,
        },
    )
    assert deep["rounds"] >= 1
    assert "HIBPEmailToBreaches" in deep["unavailable"]
    assert await call(
        svc,
        "osint_run_machine",
        {"case_id": "r4", "entity_type": "maltego.Domain", "value": "a.com", "machine": "EmailRecon"},
        expect_error=True,
    )
    assert "Indica machine o transforms" in await call(
        svc,
        "osint_run_machine",
        {
            "case_id": "r4",
            "entity_type": "maltego.Domain",
            "value": "a.com",
            "machine": "DomainRecon",
            "transforms": ["DNSToIP"],
        },
        expect_error=True,
    )
    assert "no existe" in await call(
        svc,
        "osint_run_machine",
        {"case_id": "r4", "entity_type": "maltego.Domain", "value": "a.com", "machine": "Nope"},
        expect_error=True,
    )


async def test_memoria_explicacion_y_sondeo(svc: OsintService) -> None:
    await call(
        svc,
        "osint_run_transform",
        {
            "case_id": "m1",
            "transform": "DNSToIP",
            "entity_type": "maltego.Domain",
            "value": "example.com",
            "reason": "ver hosting",
        },
    )
    t1 = await js(svc, "osint_get_timeline", {"case_id": "m1"})
    last = t1["last_seq"]
    assert [s["action"] for s in t1["items"]][-1] == "DNSToIP" and t1["items"][-1]["reason"] == "ver hosting"
    assert (await js(svc, "osint_get_timeline", {"case_id": "m1", "since_seq": last}))["count"] == 0
    await call(
        svc,
        "osint_run_transform",
        {"case_id": "m1", "transform": "IPToAS", "entity_type": "maltego.IPv4Address", "value": "93.184.216.34"},
    )
    new = await js(svc, "osint_get_timeline", {"case_id": "m1", "since_seq": last})
    assert [s["action"] for s in new["items"]] == ["IPToAS"]
    ip = (await svc.search("m1", "93.184.216.34", "", 1, 0)).items[0]
    info = await js(svc, "osint_get_entity", {"case_id": "m1", "entity_id": ip.id})
    assert [s["action"] for s in info["discovered_by"]] == ["DNSToIP"]
    assert [s["action"] for s in info["used_as_input"]] == ["IPToAS"]
    assert "IPToAS" not in info["pending_transforms"] and "IPToNetblock" in info["pending_transforms"]
    assert 0 <= info["score"]["priority"] <= 1
    md = await call(svc, "osint_get_entity", {"case_id": "m1", "entity_id": ip.id})
    assert "Descubierta por" in md and "Prioridad" in md


async def test_siguiente_mejor_accion_y_aprendizaje(svc: OsintService) -> None:
    await call(
        svc,
        "osint_run_transform",
        {"case_id": "n1", "transform": "DNSToIP", "entity_type": "maltego.Domain", "value": "example.com"},
    )
    acts = await js(svc, "osint_suggest_next_steps", {"case_id": "n1", "limit": 50, "include_stats": True})
    pairs = {(a["transform"], a["value"]) for a in acts["actions"]}
    assert ("DNSToIP", "example.com") not in pairs  # ya ejecutado
    assert ("IPToAS", "93.184.216.34") in pairs and ("DomainToWhois", "example.com") in pairs
    assert not any(a["transform"].startswith(("VT", "Shodan")) for a in acts["actions"])  # sin clave
    assert acts["transform_stats"]["DNSToIP"]["runs"] == 1
    scores = [a["score"] for a in acts["actions"]]
    assert scores == sorted(scores, reverse=True)
    again = await js(svc, "osint_suggest_next_steps", {"case_id": "n1", "limit": 50})
    assert again["actions"] == acts["actions"]  # determinista


async def test_investigate_en_una_llamada(svc: OsintService) -> None:
    r = await js(svc, "osint_investigate", {"value": "jdoe@example.com"})
    assert r["case_id"].startswith("inv-jdoe-example-com-") and r["strategy"] == "EmailRecon"
    assert r["maltego_type"] == "maltego.EmailAddress" and r["entity_count"] >= 3 and r["top"]
    md = await call(svc, "osint_investigate", {"value": "93.184.216.34", "case_id": "ip"})
    assert "InfrastructureRecon" in md and "Siguientes pasos recomendados" in md
    phrase = await js(svc, "osint_investigate", {"value": "texto libre", "case_id": "fr"})
    assert phrase["strategy"] == "expand_entity" and phrase["notes"]


async def test_gestion_de_casos_y_entidades(svc: OsintService) -> None:
    await call(svc, "osint_manage_case", {"case_id": "a1", "description": "origen"})
    d = (
        await js(
            svc,
            "osint_upsert_entity",
            {
                "case_id": "a1",
                "entity_type": "auto",
                "value": "a.com",
                "notes": "sospechoso",
                "properties": ["x=1", "y=2"],
            },
        )
    )["entity"]
    i = (await js(svc, "osint_upsert_entity", {"case_id": "a1", "entity_type": "auto", "value": "1.1.1.1"}))["entity"]
    assert d["notes"] == "sospechoso"
    await call(
        svc,
        "osint_link_entities",
        {"case_id": "a1", "source_id": d["id"], "target_id": i["id"], "edge_label": "resolves_to"},
    )
    up = await call(
        svc,
        "osint_manage_entity",
        {
            "case_id": "a1",
            "entity_id": d["id"],
            "confidence": 0.9,
            "notes": "confirmado",
            "properties": ["z=3"],
            "remove_properties": ["x"],
        },
    )
    assert "2 propiedades" in up
    e = (await js(svc, "osint_get_entity", {"case_id": "a1", "entity_id": d["id"]}))["entity"]
    assert (e["confidence"], e["notes"], e["properties"]) == (0.9, "confirmado", {"y": "2", "z": "3"})
    # fusión de casos
    await call(svc, "osint_upsert_entity", {"case_id": "b1", "entity_type": "auto", "value": "b.com"})
    merged = await call(svc, "osint_manage_case", {"case_id": "b1", "action": "merge", "source_case": "a1"})
    assert "2 entidades nuevas, 1 relaciones" in merged
    assert (await svc.case_summary("b1", 0)).entity_count == 3
    # desvincular y borrar
    assert "eliminada" in await call(
        svc,
        "osint_link_entities",
        {"case_id": "a1", "source_id": d["id"], "target_id": i["id"], "edge_label": "resolves_to", "action": "unlink"},
    )
    assert "No existía" in await call(
        svc,
        "osint_link_entities",
        {"case_id": "a1", "source_id": d["id"], "target_id": i["id"], "edge_label": "resolves_to", "action": "unlink"},
    )
    assert "borrada" in await call(
        svc, "osint_manage_entity", {"case_id": "a1", "entity_id": i["id"], "action": "delete"}
    )
    assert "confirm" in await call(svc, "osint_manage_case", {"case_id": "a1", "action": "delete"}, expect_error=True)
    assert "borrado (1 entidades" in await call(
        svc, "osint_manage_case", {"case_id": "a1", "action": "delete", "confirm": "a1"}
    )
    assert "no existe" in await call(svc, "osint_get_case_summary", {"case_id": "a1"}, expect_error=True)
    assert (await svc.case_summary("b1", 0)).entity_count == 3  # la copia fusionada sigue


async def test_busqueda_por_prioridad(svc: OsintService) -> None:
    await call(
        svc,
        "osint_run_transform",
        {"case_id": "p1", "transform": "DomainToNS", "entity_type": "maltego.Domain", "value": "example.com"},
    )
    r = await js(svc, "osint_search_entities", {"case_id": "p1", "sort": "priority"})
    scores = await svc.scores("p1")
    prios = [scores[e["id"]].priority for e in r["items"]]
    assert prios == sorted(prios, reverse=True) and len(prios) == 3
    assert "case_id" in await call(svc, "osint_search_entities", {"sort": "priority"}, expect_error=True)


async def test_informes_layouts_y_memoria_en_mtgx(svc: OsintService, tmp_path: Path) -> None:
    await call(
        svc,
        "osint_run_machine",
        {"case_id": "x1", "entity_type": "maltego.Domain", "value": "example.com", "machine": "DomainRecon"},
    )
    for fmt, ext in (("report_md", ".md"), ("report_html", ".html")):
        await call(svc, "osint_export_case", {"case_id": "x1", "format": fmt})
        report = next((tmp_path / "exports").glob(f"*{ext}")).read_text(encoding="utf-8")
        assert "Entidades prioritarias" in report and "Cronología" in report
    html_text = next((tmp_path / "exports").glob("*.html")).read_text(encoding="utf-8")
    assert "<script" not in html_text and "Content-Security-Policy" in html_text
    inline = await call(svc, "osint_export_case", {"case_id": "x1", "format": "json", "inline": True})
    assert "# Informe del caso `x1`" in inline
    positions = {}
    for layout in ("hierarchical", "radial", "force"):
        await call(svc, "osint_export_case", {"case_id": "x1", "format": "mtgx", "layout": layout})
    files = sorted((tmp_path / "exports").glob("*.mtgx"))
    assert len(files) == 3
    for f in files:
        with zipfile.ZipFile(f) as zf:
            assert SIDECAR_MEMBER in zf.namelist()
            positions[f.name] = zf.read(GRAPH_MEMBER).count(b"<mtg:Position")
    assert len(set(positions.values())) == 1  # todas las entidades tienen posición en los tres layouts
    # la memoria viaja dentro del .mtgx y se recupera al importarlo en otro caso
    (tmp_path / "imports").mkdir()
    (tmp_path / "imports" / "x.mtgx").write_bytes(files[0].read_bytes())
    text = await call(svc, "osint_import_graph", {"case_id": "x2", "file_name": "x.mtgx"})
    steps_original = len(await svc.timeline("x1", 0, 1000))
    assert f"{steps_original} pasos de memoria" in text
    assert read_mtgx(files[0].read_bytes()).sidecar["case_id"] == "x1"


def test_layouts_deterministas_y_distintos() -> None:
    from maltego_mcp.domain.records import EdgeRecord, EntityRecord

    ents = [EntityRecord(f"n{i}", "c", "x", "maltego.Phrase", f"v{i}") for i in range(12)]
    edges = [EdgeRecord(f"e{i}", "c", "r", "n0", f"n{i}") for i in range(1, 12)]
    layouts = {name: compute_layout(ents, edges, name) for name in ("hierarchical", "radial", "force")}  # type: ignore[arg-type]
    assert all(len(p) == 12 for p in layouts.values())
    assert layouts["radial"] != layouts["hierarchical"] != layouts["force"]
    assert compute_layout(ents, edges, "force") == layouts["force"]  # determinista
    radial = layouts["radial"]
    center = radial["n0"]
    dists = {round(((x - center[0]) ** 2 + (y - center[1]) ** 2) ** 0.5) for n, (x, y) in radial.items() if n != "n0"}
    assert len(dists) == 1  # anillo alrededor del pivote


async def test_inventario_y_estado_de_servidores(svc: OsintService) -> None:
    inv = await js(svc, "osint_list_transforms", {"check_servers": True})
    assert inv["providers"]["shodan"] is False
    assert inv["servers"]["dead"].startswith("sin conexión") and inv["servers"]["local-trx"].startswith("responde")
    names = {t["name"]: t for t in inv["transforms"]}
    assert names["ShodanIPToServices"]["available"] is False and names["DNSToIP"]["available"] is True
    dns = await js(svc, "osint_list_transforms", {"category": "dns", "include_machines": False})
    assert {t["category"] for t in dns["transforms"]} == {"dns"} and dns["machines"] == []
    svc.env = {"SHODAN_API_KEY": "x"}
    assert (await js(svc, "osint_list_transforms", {}))["providers"]["shodan"] is True


async def test_ontologia_por_categoria(svc: OsintService) -> None:
    r = await js(svc, "osint_list_entity_types", {"category": "cripto"})
    assert {t["maltego_type"] for t in r["items"]} == {
        "maltego.CryptocurrencyAddress",
        "maltego.CryptocurrencyTransaction",
    }
    port = (await js(svc, "osint_upsert_entity", {"case_id": "o1", "entity_type": "maltego.Port", "value": "443/tcp"}))[
        "entity"
    ]
    assert port["value"] == "443"
    assert "puerto" in await call(
        svc,
        "osint_upsert_entity",
        {"case_id": "o1", "entity_type": "maltego.Port", "value": "99999"},
        expect_error=True,
    )


def test_mtgx_sidecar_corrupto_no_rompe() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(GRAPH_MEMBER, b'<graphml xmlns="http://graphml.graphdrawing.org/xmlns"><graph/></graphml>')
        zf.writestr(SIDECAR_MEMBER, b"{no json")
    assert read_mtgx(buf.getvalue()).sidecar == {}


async def test_reimportar_no_duplica_memoria_y_presupuesto_minimo(svc: OsintService, tmp_path: Path) -> None:
    await call(
        svc,
        "osint_run_transform",
        {"case_id": "ri", "transform": "DNSToIP", "entity_type": "maltego.Domain", "value": "example.com"},
    )
    await call(svc, "osint_export_case", {"case_id": "ri", "format": "mtgx"})
    (tmp_path / "imports").mkdir()
    (tmp_path / "imports" / "ri.mtgx").write_bytes(next((tmp_path / "exports").glob("*.mtgx")).read_bytes())
    first = await call(svc, "osint_import_graph", {"case_id": "dst", "file_name": "ri.mtgx"})
    second = await call(svc, "osint_import_graph", {"case_id": "dst", "file_name": "ri.mtgx"})
    assert "1 pasos de memoria" in first and "0 pasos de memoria" in second
    r = await js(
        svc,
        "osint_run_machine",
        {
            "case_id": "b1x",
            "entity_type": "maltego.Domain",
            "value": "example.com",
            "machine": "DomainRecon",
            "max_total_entities": 1,
        },
    )
    assert r["stopped_by_budget"] is True and r["new_entities"] == 0


async def test_coercion_auto_y_nuevas_machines(svc: OsintService) -> None:
    tr = await js(
        svc,
        "osint_run_transform",
        {"case_id": "co1", "transform": "AliasToProfiles", "entity_type": "auto", "value": "jdoe", "save": False},
    )
    assert tr["input"]["maltego_type"] == "maltego.Alias" and len(tr["results"]) == 3
    mc = await js(
        svc,
        "osint_run_machine",
        {"case_id": "co2", "entity_type": "auto", "value": "jdoe", "machine": "PersonalFootprint"},
    )
    assert mc["root"]["maltego_type"] == "maltego.Alias" and mc["new_entities"] >= 3
    asn = await js(svc, "osint_investigate", {"value": "AS15133", "case_id": "co3"})
    assert asn["strategy"] == "ASNToNetblocks" and asn["entity_count"] >= 3
    threat = await js(svc, "osint_investigate", {"value": "ab" * 32, "case_id": "co4"})
    assert threat["strategy"] == "ThreatSweep" and threat["entity_count"] >= 3
