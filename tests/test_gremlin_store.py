"""Backend Gremlin con un ejecutor simulado: plantillas constantes, bindings y parseo de GraphSON."""

from __future__ import annotations

from enum import Enum
from typing import Any

import pytest

from maltego_mcp.errors import BackendError, NotFound
from maltego_mcp.graph import gremlin as G
from maltego_mcp.graph.gremlin import GremlinGraphStore, GremlinPythonExecutor
from maltego_mcp.service import OsintService
from maltego_mcp.transforms.catalog import TransformCatalog

EVIL = "x') ; g.V().drop() ; ('"


class T(Enum):  # imita gremlin_python.process.traversal.T
    id = 1
    label = 2


class FakeGraph:
    """Ejecutor que interpreta solo las plantillas conocidas sobre un diccionario."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.v: dict[tuple[str, str], dict[str, Any]] = {}
        self.e: dict[str, dict[str, Any]] = {}

    def vm(self, props: dict[str, Any]) -> dict[Any, Any]:
        out: dict[Any, Any] = {T.id: props["id"], T.label: props["label"]}
        out.update({k: [v] for k, v in props.items() if k not in ("id", "label")})
        return out

    async def __call__(self, q: str, b: dict[str, Any]) -> list[Any]:
        self.calls.append((q, b))
        if q == G.Q_GET_VERTEX:
            p = self.v.get((b["pk"], b["vid"]))
            return [self.vm(p)] if p else []
        if q == G.Q_ADD_CASE:
            self.v[(b["pk"], b["vid"])] = {
                "id": b["vid"],
                "label": "case",
                "pk": b["pk"],
                "case_id": b["pk"],
                "description": b["description"],
                "created": b["now"],
                "updated": b["now"],
            }
            return []
        if q in (G.Q_TOUCH_CASE, G.Q_UPDATE_CASE):
            self.v[(b["pk"], b["vid"])].update({k: b[k] for k in ("description", "now") if k in b})
            return []
        if q == G.Q_ADD_ENTITY:
            if (b["pk"], b["vid"]) in self.v:
                raise G.ConflictError("409")
            props = {k: v for k, v in b.items() if k not in ("vid", "vlabel", "val")}
            props.update(id=b["vid"], case_id=b["pk"], label=b["vlabel"], value=b["val"])
            self.v[(b["pk"], b["vid"])] = props
            return []
        if q == G.Q_UPDATE_ENTITY:
            self.v[(b["pk"], b["vid"])].update({k: v for k, v in b.items() if k not in ("vid", "pk")})
            return []
        if q == G.Q_GET_EDGE:
            p = self.e.get(b["eid"])
            return [self.vm(p)] if p else []
        if q == G.Q_ADD_EDGE:
            if b["eid"] in self.e:
                raise G.ConflictError("409")
            self.e[b["eid"]] = {
                "id": b["eid"],
                "label": b["elabel"],
                "case_id": b["pk"],
                "out_id": b["out_id"],
                "in_id": b["in_id"],
                "confidence": b["confidence"],
                "sources_json": b["sources_json"],
                "props_json": b.get("props_json", "{}"),
                "first_seen": b["first_seen"],
                "last_seen": b["last_seen"],
            }
            return []
        if q == G.Q_UPDATE_EDGE:
            self.e[b["eid"]].update(
                confidence=b["confidence"],
                sources_json=b["sources_json"],
                props_json=b.get("props_json", "{}"),
            )
            return []
        if q.startswith("g.V()") and q.endswith(".count()") and "value_lc" in q:
            return [len(self._search(q, b))]
        if q.startswith("g.V()") and ".range(lo, hi)" in q:
            return [self.vm(p) for p in self._search(q, b)[b["lo"] : b["hi"]]]
        if q in G.Q_NEIGHBORS.values():
            out = ".outE(" in q
            rows = []
            for e in self.e.values():
                if (out and e["out_id"] == b["vid"]) or (not out and e["in_id"] == b["vid"]):
                    if "elabel" in b and e["label"] != b["elabel"]:
                        continue
                    other = e["in_id"] if out else e["out_id"]
                    rows.append({"e": self.vm(e), "v": self.vm(self.v[(b["pk"], other)])})
            return rows[: b["n"]]
        if q == G.Q_LIST_CASES:
            return [self.vm(p) for p in self.v.values() if p["label"] == "case"]
        if q == G.Q_COUNT_BY_TYPE:
            counts: dict[str, int] = {}
            for p in self.v.values():
                if p["pk"] == b["pk"] and "value_lc" in p:
                    counts[p["maltego_type"]] = counts.get(p["maltego_type"], 0) + 1
            return [counts]
        if q == G.Q_COUNT_EDGES:
            return [sum(1 for e in self.e.values() if e["case_id"] == b["pk"])]
        if q == G.Q_DEGREES:
            return [
                {
                    "v": self.vm(p),
                    "degree": sum(1 for e in self.e.values() if p["id"] in (e["out_id"], e["in_id"])),
                }
                for p in self.v.values()
                if p["pk"] == b["pk"] and "value_lc" in p
            ]
        if q == G.Q_PATHS:
            return [[b["src"], b["dst"]]]
        if q == G.Q_ADD_STEP:
            props = {
                "id": b["vid"],
                "label": "step",
                "pk": b["pk"],
                "case_id": b["pk"],
                "seq": b["seq"],
                "timestamp": b["ts"],
                "kind": b["kind"],
                "action": b["step_action"],
                "input_id": b["input_id"],
                "input_value": b["input_value"],
                "reason": b["reason"],
                "outputs_json": b["outputs_json"],
                "new_entities": b["new_entities"],
                "error": b["err"],
                "duration_ms": b["duration_ms"],
            }
            self.v[(b["pk"], b["vid"])] = props
            return []
        if q == G.Q_LIST_STEPS:
            return [
                self.vm(p)
                for p in self.v.values()
                if p["label"] == "step" and p["pk"] == b["pk"] and p["seq"] > b["since"]
            ]
        if q == G.Q_LIST_ALL_STEPS:
            return [self.vm(p) for p in self.v.values() if p["label"] == "step"]
        if q == G.Q_COUNT_BOTH_EDGES:
            return [sum(1 for e in self.e.values() if b["vid"] in (e["out_id"], e["in_id"]))]
        if q == G.Q_DROP_VERTEX:
            self.v.pop((b["pk"], b["vid"]), None)
            self.e = {k: e for k, e in self.e.items() if b["vid"] not in (e["out_id"], e["in_id"])}
            return []
        if q == G.Q_COUNT_EDGE:
            return [int(b["eid"] in self.e)]
        if q == G.Q_DROP_EDGE:
            self.e.pop(b["eid"], None)
            return []
        if q == G.Q_DROP_CASE:
            self.v = {k: p for k, p in self.v.items() if p["pk"] != b["pk"]}
            self.e = {k: e for k, e in self.e.items() if e["case_id"] != b["pk"]}
            return []
        raise AssertionError(f"consulta no esperada: {q}")

    def _search(self, q: str, b: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            p
            for p in self.v.values()
            if "value_lc" in p
            and ("pk" not in b or p["pk"] == b["pk"])
            and ("q" not in b or b["q"] in p["value_lc"])
            and ("maltego_type" not in b or p["maltego_type"] == b["maltego_type"])
        ]


@pytest.fixture
def fake() -> FakeGraph:
    return FakeGraph()


@pytest.fixture
def svc(fake: FakeGraph, tmp_path: Any) -> OsintService:
    return OsintService(GremlinGraphStore(fake), TransformCatalog(), tmp_path)


async def test_flujo_completo_y_ningun_valor_en_la_consulta(svc: OsintService, fake: FakeGraph) -> None:
    await svc.create_case("c1", EVIL)
    d, created = await svc.upsert_entity("c1", "maltego.Phrase", EVIL, 0.4, EVIL, [f"k={EVIL}"])
    assert created
    d2, created = await svc.upsert_entity("c1", "maltego.Phrase", EVIL, 0.8, "otra", [])
    assert not created and d2.confidence == 0.8 and d2.sources == [EVIL, "otra"]
    ip, _ = await svc.upsert_entity("c1", "maltego.IPv4Address", "1.1.1.1", 0.5, "m", [])
    _, created = await svc.link("c1", d.id, ip.id, "resolves_to", "m", 0.6)
    assert created
    _, created = await svc.link("c1", d.id, ip.id, "resolves_to", "m", 0.9)
    assert not created
    page = await svc.search("c1", "G.V()", "maltego.Phrase", 10, 0)
    assert page.total == 1 and page.items[0].value == EVIL
    assert page.items[0].properties == {"k": EVIL}
    nb = await svc.neighbors("c1", ip.id, "resolves_to", "both", 5)
    assert [(n.direction, n.entity.id, n.edge.confidence) for n in nb] == [("in", d.id, 0.9)]
    s = await svc.case_summary("c1", 3)
    assert (s.entity_count, s.edge_count) == (2, 1)
    assert s.case.description == EVIL
    assert [c.case_id for c in (await svc.list_cases(10, 0)).items] == ["c1"]
    assert await svc.find_paths("c1", d.id, ip.id, 3, 5) == [[d.id, ip.id]]

    templates = {v for k, v in vars(G).items() if k.startswith("Q_") and isinstance(v, str)}
    templates |= set(G.Q_NEIGHBORS.values())
    for query, bindings in fake.calls:
        assert EVIL not in query, query  # los datos solo viajan en bindings
        assert "1.1.1.1" not in query
        base = query.removesuffix(".count()").removesuffix(".range(lo, hi).valueMap(true)")
        assert query in templates or base in {G._search_query(a, b, c) for a in (0, 1) for b in (0, 1) for c in (0, 1)}
        assert all(isinstance(k, str) and k.isidentifier() for k in bindings)
        assert not (G.RESERVED_BINDINGS & bindings.keys()), (query, bindings)


async def test_errores_de_existencia(svc: OsintService) -> None:
    with pytest.raises(NotFound, match="no existe"):
        await svc.case_summary("c9", 3)
    await svc.create_case("c1", "")
    with pytest.raises(NotFound):
        await svc.get_entity("c1", "domain-" + "0" * 32)
    with pytest.raises(NotFound):
        await svc.find_paths("c1", "domain-" + "0" * 32, "domain-" + "1" * 32, 2, 2)


class _Err(Exception):
    def __init__(self, attrs: dict[str, Any]) -> None:
        super().__init__("err")
        self.status_attributes = attrs


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self.rows = rows
        self.status_attributes = {"x-ms-total-request-charge": 3.2}

    def all(self) -> _Result:
        return self

    def result(self, timeout: float | None = None) -> list[Any]:
        return self.rows


class _Client:
    def __init__(self, failures: list[Exception]) -> None:
        self.failures = failures
        self.calls = 0

    def submit(self, q: str, b: dict[str, Any]) -> _Result:
        self.calls += 1
        if self.failures:
            raise self.failures.pop(0)
        return _Result([42])

    def close(self) -> None:
        pass


def _executor(client: _Client) -> GremlinPythonExecutor:
    ex = GremlinPythonExecutor("wss://x:443/", "/dbs/d/colls/g", "k", max_retries=2)
    ex._client = client
    return ex


async def test_reintenta_429_respetando_retry_after() -> None:
    client = _Client([_Err({"x-ms-status-code": 429, "x-ms-retry-after-ms": "5"})] * 2)
    assert await _executor(client)("g.V().count()", {}) == [42]
    assert client.calls == 3


async def test_429_persistente_da_error_accionable() -> None:
    client = _Client([_Err({"x-ms-status-code": 429, "x-ms-retry-after-ms": "1"})] * 5)
    with pytest.raises(BackendError, match="429"):
        await _executor(client)("g.V().count()", {})


async def test_error_de_conexion_y_de_servidor() -> None:
    with pytest.raises(BackendError, match="GREMLIN_ENDPOINT"):
        await _executor(_Client([ConnectionError("down")]))("q", {})
    with pytest.raises(BackendError, match="estado 400"):
        await _executor(_Client([_Err({"x-ms-status-code": 400})]))("q", {})


async def test_alta_concurrente_se_fusiona_en_vez_de_fallar(svc: OsintService, fake: FakeGraph) -> None:
    """Simula que otra petición crea la entidad entre la lectura y el addV (409 en Cosmos)."""
    await svc.create_case("c1", "")
    original = fake.__call__
    created_behind = False

    async def racing(q: str, b: dict[str, Any]) -> list[Any]:
        nonlocal created_behind
        if q == G.Q_ADD_ENTITY and not created_behind:
            created_behind = True
            await original(q, {**b, "confidence": 0.2, "sources_json": '["otro"]'})
        return await original(q, b)

    store = GremlinGraphStore(racing)
    ent = svc.build_entity("c1", "maltego.Domain", "a.com", 0.9, "yo")
    merged, created = await store.upsert_entity(ent)
    assert created is False
    assert merged.confidence == 0.9 and merged.sources == ["otro", "yo"]


async def test_ejecutor_rechaza_bindings_reservados() -> None:
    with pytest.raises(BackendError, match="reservados"):
        await _executor(_Client([]))("g.V(label)", {"label": "x"})


async def test_409_se_traduce_a_conflicto() -> None:
    with pytest.raises(G.ConflictError):
        await _executor(_Client([_Err({"x-ms-status-code": 409})]))("q", {})


async def test_crud_y_memoria_en_gremlin(svc: OsintService, fake: FakeGraph) -> None:
    await svc.create_case("g1", "")
    d, _ = await svc.upsert_entity("g1", "maltego.Domain", "a.com", 0.5, "m", [], "nota")
    i, _ = await svc.upsert_entity("g1", "maltego.IPv4Address", "1.1.1.1", 0.5, "m", [])
    await svc.link("g1", d.id, i.id, "resolves_to", "m", 0.5)
    up = await svc.update_entity("g1", d.id, 0.9, "otra", ["k=v"], [])
    assert (up.confidence, up.notes, up.properties) == (0.9, "otra", {"k": "v"})
    assert (await svc.get_entity("g1", d.id)).notes == "otra"
    steps = await svc.timeline("g1", 0, 50)
    assert [s.action for s in steps][-1] == "update_entity" and steps == sorted(steps, key=lambda s: s.seq)
    assert await svc.timeline("g1", steps[-1].seq, 50) == []
    assert await svc.unlink("g1", d.id, i.id, "resolves_to") is True
    assert await svc.unlink("g1", d.id, i.id, "resolves_to") is False
    await svc.link("g1", d.id, i.id, "resolves_to", "m", 0.5)
    assert await svc.delete_entity("g1", i.id) == 1
    with pytest.raises(NotFound):
        await svc.delete_entity("g1", i.id)
    assert (await svc.learning()) == {}
    assert await svc.delete_case("g1", "g1") == (1, 0)
    with pytest.raises(NotFound):
        await svc.case_summary("g1", 0)
    for query, bindings in fake.calls:
        assert not (G.RESERVED_BINDINGS & bindings.keys()), query
