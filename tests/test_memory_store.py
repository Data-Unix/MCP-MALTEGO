from pathlib import Path

import pytest

from maltego_mcp.errors import BackendError, InvalidInput, NotFound
from maltego_mcp.graph.memory import MemoryGraphStore
from maltego_mcp.service import OsintService
from maltego_mcp.transforms.catalog import TransformCatalog


@pytest.fixture
def svc(tmp_path: Path) -> OsintService:
    return OsintService(MemoryGraphStore(tmp_path / "g.json"), TransformCatalog(), tmp_path / "exp")


async def test_upsert_es_idempotente_y_fusiona(svc: OsintService) -> None:
    a, created = await svc.upsert_entity("c1", "maltego.Domain", "Example.com", 0.3, "whois", ["registrar=X"])
    assert created
    b, created = await svc.upsert_entity("c1", "maltego.Domain", "example.COM.", 0.9, "dns", ["ns=ns1"])
    assert not created
    assert b.id == a.id
    assert b.confidence == 0.9
    assert b.sources == ["whois", "dns"]
    assert b.properties == {"registrar": "X", "ns": "ns1"}
    assert b.first_seen == a.first_seen


async def test_persistencia_en_fichero(tmp_path: Path) -> None:
    path = tmp_path / "g.json"
    svc = OsintService(MemoryGraphStore(path), TransformCatalog(), tmp_path)
    await svc.create_case("c1", "desc")
    d, _ = await svc.upsert_entity("c1", "maltego.Domain", "a.com", 0.5, "m", [])
    i, _ = await svc.upsert_entity("c1", "maltego.IPv4Address", "1.1.1.1", 0.5, "m", [])
    await svc.link("c1", d.id, i.id, "resolves_to", "m", 0.7)
    reloaded = OsintService(MemoryGraphStore(path), TransformCatalog(), tmp_path)
    s = await reloaded.case_summary("c1", 5)
    assert (s.entity_count, s.edge_count, s.case.description) == (2, 1, "desc")


def test_fichero_corrupto_da_error_claro(tmp_path: Path) -> None:
    p = tmp_path / "g.json"
    p.write_text("{no json", encoding="utf-8")
    with pytest.raises(BackendError, match="No se pudo leer"):
        MemoryGraphStore(p)


async def test_vecinos_caminos_y_resumen(svc: OsintService) -> None:
    ids = {}
    for t, v in [
        ("maltego.Domain", "a.com"),
        ("maltego.IPv4Address", "1.1.1.1"),
        ("maltego.Domain", "b.com"),
        ("maltego.EmailAddress", "x@b.com"),
    ]:
        e, _ = await svc.upsert_entity("c1", t, v, 0.5, "m", [])
        ids[v] = e.id
    await svc.link("c1", ids["a.com"], ids["1.1.1.1"], "resolves_to", "m", 0.9)
    await svc.link("c1", ids["b.com"], ids["1.1.1.1"], "resolves_to", "m", 0.5)
    await svc.link("c1", ids["x@b.com"], ids["b.com"], "email_domain", "m", 0.5)

    out = await svc.neighbors("c1", ids["1.1.1.1"], "", "in", 10)
    assert {n.entity.value for n in out} == {"a.com", "b.com"}
    assert out[0].entity.value == "a.com"  # mayor confianza primero
    assert await svc.neighbors("c1", ids["1.1.1.1"], "", "out", 10) == []
    only = await svc.neighbors("c1", ids["b.com"], "email_domain", "both", 10)
    assert [n.direction for n in only] == ["in"]

    paths = await svc.find_paths("c1", ids["a.com"], ids["x@b.com"], 3, 5)
    assert paths == [[ids["a.com"], ids["1.1.1.1"], ids["b.com"], ids["x@b.com"]]]
    assert await svc.find_paths("c1", ids["a.com"], ids["x@b.com"], 2, 5) == []

    s = await svc.case_summary("c1", 2)
    assert s.entity_count == 4 and s.edge_count == 3
    assert s.by_type == {"maltego.Domain": 2, "maltego.IPv4Address": 1, "maltego.EmailAddress": 1}
    assert s.top_connected[0][0].value in {"1.1.1.1", "b.com"} and s.top_connected[0][1] == 2


async def test_busqueda_paginada_y_entre_casos(svc: OsintService) -> None:
    for i in range(25):
        await svc.upsert_entity("c1", "maltego.Domain", f"site{i:02d}.example.com", 0.5, "m", [])
    await svc.upsert_entity("c2", "maltego.Domain", "site00.example.com", 0.5, "m", [])
    p1 = await svc.search("c1", "SITE", "", 10, 0)
    assert (p1.total, len(p1.items), p1.has_more, p1.next_offset) == (25, 10, True, 10)
    p3 = await svc.search("c1", "site", "maltego.Domain", 10, 20)
    assert (len(p3.items), p3.has_more, p3.next_offset) == (5, False, None)
    cross = await svc.search("", "site00", "", 10, 0)
    assert {e.case_id for e in cross.items} == {"c1", "c2"}
    assert (await svc.search("c1", "zzz", "", 10, 0)).total == 0


async def test_errores_accionables(svc: OsintService) -> None:
    with pytest.raises(NotFound, match="osint_create_case"):
        await svc.case_summary("no-existe", 5)
    d, _ = await svc.upsert_entity("c1", "maltego.Domain", "a.com", 0.5, "m", [])
    with pytest.raises(NotFound, match="osint_search_entities"):
        await svc.get_entity("c1", "domain-" + "0" * 32)
    with pytest.raises(NotFound):
        await svc.link("c1", d.id, "domain-" + "0" * 32, "x", "m", 0.5)
    with pytest.raises(InvalidInput, match="bucles"):
        await svc.link("c1", d.id, d.id, "x", "m", 0.5)
    with pytest.raises(InvalidInput, match="clave=valor"):
        await svc.upsert_entity("c1", "maltego.Domain", "a.com", 0.5, "m", ["sin-igual"])
    with pytest.raises(NotFound):
        await svc.neighbors("c1", "domain-" + "0" * 32, "", "both", 5)


async def test_confianza_se_acota(svc: OsintService) -> None:
    e, _ = await svc.upsert_entity("c1", "maltego.Domain", "a.com", 7.0, "m", [])
    assert e.confidence == 1.0


async def test_caminos_no_explotan_en_grafo_denso(svc: OsintService) -> None:
    ids = []
    for i in range(12):
        e, _ = await svc.upsert_entity("c1", "maltego.Phrase", f"n{i}", 0.5, "m", [])
        ids.append(e.id)
    for a in ids:
        for b in ids:
            if a < b:
                await svc.link("c1", a, b, "rel", "m", 0.5)
    paths = await svc.find_paths("c1", ids[0], ids[1], 4, 20)
    assert len(paths) == 20


async def test_varios_procesos_comparten_el_fichero_sin_perder_datos(tmp_path: Path) -> None:
    """Dos instancias (como dos agentes en Orca) escriben alternadamente en el mismo fichero."""
    path = tmp_path / "shared.json"
    a = OsintService(MemoryGraphStore(path), TransformCatalog(), tmp_path)
    b = OsintService(MemoryGraphStore(path), TransformCatalog(), tmp_path)
    for i in range(5):
        await a.upsert_entity("c1", "maltego.Domain", f"a{i}.com", 0.5, "agente-a", [])
        await b.upsert_entity("c1", "maltego.Domain", f"b{i}.com", 0.5, "agente-b", [])
    assert (await a.search("c1", "", "", 50, 0)).total == 10  # a ve lo que escribió b
    fresh = OsintService(MemoryGraphStore(path), TransformCatalog(), tmp_path)
    assert (await fresh.case_summary("c1", 0)).entity_count == 10


def test_fichero_con_claves_inesperadas(tmp_path: Path) -> None:
    p = tmp_path / "g.json"
    p.write_text('{"cases": [{"case_id": "c1", "nueva_clave": 1}]}', encoding="utf-8")
    with pytest.raises(BackendError, match="MALTEGO_MCP_DATA_FILE"):
        MemoryGraphStore(p)
