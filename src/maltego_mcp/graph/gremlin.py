"""Backend Azure Cosmos DB for Apache Gremlin.

- Solo consultas de texto con bindings (Cosmos no soporta bytecode). Ningún dato de usuario se
  concatena en la consulta: las plantillas son constantes y los valores van en `bindings`.
- Partición: propiedad `pk` = case_id. Los vértices de caso tienen label `case`.
- Reintentos ante 429 (RequestRateTooLarge) respetando `x-ms-retry-after-ms`.

ESTADO: sintaxis basada en la documentación de Cosmos DB Gremlin; validar contra una cuenta real
antes de producción (ver docs/USO.md).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import replace
from typing import Any

from maltego_mcp.domain.records import (
    CaseRecord,
    EdgeRecord,
    EntityRecord,
    StepRecord,
    merge_edge,
    merge_entity,
    utc_now,
)
from maltego_mcp.errors import BackendError, NotFound
from maltego_mcp.graph.base import CaseSummary, Direction, Neighbor, Page

logger = logging.getLogger(__name__)

Executor = Callable[[str, dict[str, Any]], Awaitable[list[Any]]]
# Gremlin Server rechaza bindings con nombres de tokens T (id, key, label, value).
RESERVED_BINDINGS = frozenset({"id", "key", "label", "value"})


class ConflictError(BackendError):
    """El elemento ya existe (409): otra petición concurrente lo creó."""


MAX_CASES_SCAN = 500

# ----------------------------------------------------------------------------------------------
# Plantillas constantes. Variables: solo nombres de binding.
# ----------------------------------------------------------------------------------------------
Q_GET_VERTEX = "g.V(vid).has('pk', pk).valueMap(true)"
Q_ADD_CASE = (
    "g.addV('case').property('id', vid).property('pk', pk).property('case_id', pk)"
    ".property('description', description).property('created', now).property('updated', now)"
)
Q_UPDATE_CASE = "g.V(vid).has('pk', pk).property('description', description).property('updated', now)"
Q_TOUCH_CASE = "g.V(vid).has('pk', pk).property('updated', now)"
Q_LIST_CASES = "g.V().hasLabel('case').limit(max_cases).valueMap(true)"
Q_ADD_ENTITY = (
    "g.addV(vlabel).property('id', vid).property('pk', pk).property('case_id', pk)"
    ".property('maltego_type', maltego_type).property('value', val).property('value_lc', value_lc)"
    ".property('confidence', confidence).property('sources_json', sources_json)"
    ".property('props_json', props_json).property('first_seen', first_seen).property('last_seen', last_seen)"
    ".property('notes', notes)"
)
Q_UPDATE_ENTITY = (
    "g.V(vid).has('pk', pk).property('confidence', confidence).property('sources_json', sources_json)"
    ".property('props_json', props_json).property('last_seen', last_seen).property('notes', notes)"
)
Q_GET_EDGE = "g.V(out_id).has('pk', pk).outE(elabel).hasId(eid).valueMap(true)"
Q_ADD_EDGE = (
    "g.V(out_id).has('pk', pk).addE(elabel).to(g.V(in_id).has('pk', pk)).property('id', eid)"
    ".property('case_id', pk).property('out_id', out_id).property('in_id', in_id)"
    ".property('confidence', confidence).property('sources_json', sources_json)"
    ".property('props_json', props_json).property('first_seen', first_seen).property('last_seen', last_seen)"
)
Q_UPDATE_EDGE = (
    "g.V(out_id).has('pk', pk).outE(elabel).hasId(eid).property('confidence', confidence)"
    ".property('sources_json', sources_json).property('props_json', props_json).property('last_seen', last_seen)"
)
Q_NEIGHBORS = {
    (
        "out",
        False,
    ): "g.V(vid).has('pk', pk).outE().limit(n).project('e', 'v').by(valueMap(true)).by(inV().valueMap(true))",
    (
        "out",
        True,
    ): "g.V(vid).has('pk', pk).outE(elabel).limit(n).project('e', 'v').by(valueMap(true)).by(inV().valueMap(true))",
    (
        "in",
        False,
    ): "g.V(vid).has('pk', pk).inE().limit(n).project('e', 'v').by(valueMap(true)).by(outV().valueMap(true))",
    (
        "in",
        True,
    ): "g.V(vid).has('pk', pk).inE(elabel).limit(n).project('e', 'v').by(valueMap(true)).by(outV().valueMap(true))",
}
Q_PATHS = (
    "g.V(src).has('pk', pk).repeat(both().simplePath()).until(hasId(dst).or().loops().is(gte(max_depth)))"
    ".hasId(dst).path().by('id').limit(n)"
)
Q_COUNT_BY_TYPE = "g.V().has('pk', pk).has('value_lc').groupCount().by('maltego_type')"
Q_COUNT_EDGES = "g.V().has('pk', pk).outE().count()"
# Sin order() en servidor (sintaxis de orden distinta entre versiones): se ordena en Python.
Q_DEGREES = (
    "g.V().has('pk', pk).has('value_lc').limit(scan).project('v', 'degree').by(valueMap(true)).by(bothE().count())"
)
MAX_DEGREE_SCAN = 2000
Q_COUNT_BOTH_EDGES = "g.V(vid).has('pk', pk).bothE().count()"
Q_DROP_VERTEX = "g.V(vid).has('pk', pk).drop()"
Q_COUNT_EDGE = "g.E(eid).has('case_id', pk).count()"
Q_DROP_EDGE = "g.E(eid).has('case_id', pk).drop()"
Q_DROP_CASE = "g.V().has('pk', pk).drop()"
Q_ADD_STEP = (
    "g.addV('step').property('id', vid).property('pk', pk).property('case_id', pk).property('seq', seq)"
    ".property('timestamp', ts).property('kind', kind).property('action', step_action)"
    ".property('input_id', input_id).property('input_value', input_value).property('reason', reason)"
    ".property('outputs_json', outputs_json).property('new_entities', new_entities).property('error', err)"
    ".property('duration_ms', duration_ms)"
)
Q_LIST_STEPS = "g.V().has('pk', pk).hasLabel('step').has('seq', gt(since)).limit(scan).valueMap(true)"
Q_LIST_ALL_STEPS = "g.V().hasLabel('step').limit(scan).valueMap(true)"
MAX_STEPS_SCAN = 5000
Q_EXPORT_VERTICES = "g.V().has('pk', pk).has('value_lc').limit(n).valueMap(true)"
Q_EXPORT_EDGES = "g.V().has('pk', pk).outE().limit(n).valueMap(true)"


def _search_query(with_case: bool, with_text: bool, with_type: bool) -> str:
    q = "g.V()"
    if with_case:
        q += ".has('pk', pk)"
    q += ".has('value_lc', containing(q))" if with_text else ".has('value_lc')"
    if with_type:
        q += ".has('maltego_type', maltego_type)"
    return q


def case_vertex_id(case_id: str) -> str:
    return f"case-{case_id}"


# ----------------------------------------------------------------------------------------------
# Conversión de resultados GraphSON (valueMap(true)) a registros.
# ----------------------------------------------------------------------------------------------
def _key(k: Any) -> str:
    name = getattr(k, "name", None)  # gremlin_python T.id / T.label
    return str(name if name is not None else k)


def _flat(vm: dict[Any, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in vm.items():
        out[_key(k)] = v[0] if isinstance(v, list) and v else v
    return out


def _json_list(text: Any) -> list[str]:
    try:
        data = json.loads(text) if text else []
    except (TypeError, json.JSONDecodeError):
        return []
    return [str(x) for x in data] if isinstance(data, list) else []


def _json_dict(text: Any) -> dict[str, str]:
    try:
        data = json.loads(text) if text else {}
    except (TypeError, json.JSONDecodeError):
        return {}
    return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}


def entity_from_vm(vm: dict[Any, Any]) -> EntityRecord:
    d = _flat(vm)
    return EntityRecord(
        id=str(d["id"]),
        case_id=str(d.get("case_id") or d.get("pk", "")),
        label=str(d.get("label", "")),
        maltego_type=str(d.get("maltego_type", "")),
        value=str(d.get("value", "")),
        confidence=float(d.get("confidence", 0.5)),
        sources=_json_list(d.get("sources_json")),
        properties=_json_dict(d.get("props_json")),
        first_seen=str(d.get("first_seen", "")),
        last_seen=str(d.get("last_seen", "")),
        notes=str(d.get("notes", "")),
    )


def step_from_vm(vm: dict[Any, Any]) -> StepRecord:
    d = _flat(vm)
    return StepRecord(
        seq=int(d.get("seq", 0)),
        case_id=str(d.get("case_id") or d.get("pk", "")),
        timestamp=str(d.get("timestamp", "")),
        kind=str(d.get("kind", "")),
        action=str(d.get("action", "")),
        input_id=str(d.get("input_id", "")),
        input_value=str(d.get("input_value", "")),
        reason=str(d.get("reason", "")),
        outputs=_json_list(d.get("outputs_json")),
        new_entities=int(d.get("new_entities", 0)),
        error=str(d.get("error", "")),
        duration_ms=int(d.get("duration_ms", 0)),
    )


def edge_from_vm(vm: dict[Any, Any]) -> EdgeRecord:
    d = _flat(vm)
    return EdgeRecord(
        id=str(d["id"]),
        case_id=str(d.get("case_id", "")),
        label=str(d.get("label", "")),
        out_id=str(d.get("out_id", "")),
        in_id=str(d.get("in_id", "")),
        confidence=float(d.get("confidence", 0.5)),
        sources=_json_list(d.get("sources_json")),
        first_seen=str(d.get("first_seen", "")),
        last_seen=str(d.get("last_seen", "")),
        properties=_json_dict(d.get("props_json")),
    )


def case_from_vm(vm: dict[Any, Any]) -> CaseRecord:
    d = _flat(vm)
    return CaseRecord(
        case_id=str(d.get("case_id") or d.get("pk", "")),
        description=str(d.get("description", "")),
        created=str(d.get("created", "")),
        updated=str(d.get("updated", "")),
        version=int(d.get("version", 1)),
        parent_case_id=str(d.get("parent_case_id", "")),
    )


class GremlinGraphStore:
    def __init__(self, executor: Executor, close: Callable[[], Awaitable[None]] | None = None) -> None:
        self._run = executor
        self._close = close

    # ---------- casos ----------
    async def get_case(self, case_id: str) -> CaseRecord | None:
        rows = await self._run(Q_GET_VERTEX, {"vid": case_vertex_id(case_id), "pk": case_id})
        return case_from_vm(rows[0]) if rows else None

    async def ensure_case(
        self, case_id: str, description: str = "", parent_case_id: str = ""
    ) -> tuple[CaseRecord, bool]:
        existing = await self.get_case(case_id)
        now = utc_now()
        b = {"vid": case_vertex_id(case_id), "pk": case_id, "description": description, "now": now}
        if existing is None:
            await self._run(Q_ADD_CASE, b)
            return CaseRecord(case_id, description, now, now, 1, parent_case_id), True
        if description and description != existing.description:
            await self._run(Q_UPDATE_CASE, b)
            existing.description, existing.updated = description, now
        return existing, False

    async def list_cases(self, limit: int, offset: int) -> Page[CaseRecord]:
        rows = await self._run(Q_LIST_CASES, {"max_cases": MAX_CASES_SCAN})
        cases = sorted((case_from_vm(r) for r in rows), key=lambda c: c.updated, reverse=True)
        return Page(cases[offset : offset + limit], len(cases), offset, limit)

    async def _require_case(self, case_id: str) -> None:
        if await self.get_case(case_id) is None:
            raise NotFound(f"El caso '{case_id}' no existe. Créalo con osint_create_case o revisa osint_list_cases.")

    async def _touch_case(self, case_id: str) -> None:
        await self._run(Q_TOUCH_CASE, {"vid": case_vertex_id(case_id), "pk": case_id, "now": utc_now()})

    # ---------- entidades ----------
    async def get_entity(self, case_id: str, entity_id: str) -> EntityRecord | None:
        rows = await self._run(Q_GET_VERTEX, {"vid": entity_id, "pk": case_id})
        if not rows:
            return None
        ent = entity_from_vm(rows[0])
        return ent if ent.label not in ("case", "step") else None

    async def upsert_entity(self, entity: EntityRecord) -> tuple[EntityRecord, bool]:
        await self._require_case(entity.case_id)
        return await self._upsert_entity(entity, retry_on_conflict=True)

    async def _upsert_entity(self, entity: EntityRecord, retry_on_conflict: bool) -> tuple[EntityRecord, bool]:
        existing = await self.get_entity(entity.case_id, entity.id)
        merged = merge_entity(existing, entity)
        b = {
            "vid": merged.id,
            "pk": merged.case_id,
            "vlabel": merged.label,
            "maltego_type": merged.maltego_type,
            "val": merged.value,
            "value_lc": merged.value.lower(),
            "confidence": merged.confidence,
            "sources_json": json.dumps(merged.sources, ensure_ascii=False),
            "props_json": json.dumps(merged.properties, ensure_ascii=False),
            "first_seen": merged.first_seen,
            "last_seen": merged.last_seen,
            "notes": merged.notes,
        }
        if existing is None:
            try:
                await self._run(Q_ADD_ENTITY, b)
            except ConflictError:  # creada en paralelo: se fusiona con la versión ya guardada
                if not retry_on_conflict:
                    raise
                return await self._upsert_entity(entity, retry_on_conflict=False)
        else:
            await self._run(
                Q_UPDATE_ENTITY,
                {k: b[k] for k in ("vid", "pk", "confidence", "sources_json", "props_json", "last_seen", "notes")},
            )
        await self._touch_case(entity.case_id)
        return merged, existing is None

    async def search_entities(
        self, case_id: str, query: str, maltego_type: str, limit: int, offset: int
    ) -> Page[EntityRecord]:
        if case_id:
            await self._require_case(case_id)
        base = _search_query(bool(case_id), bool(query), bool(maltego_type))
        b: dict[str, Any] = {}
        if case_id:
            b["pk"] = case_id
        if query:
            b["q"] = query.lower()
        if maltego_type:
            b["maltego_type"] = maltego_type
        total_rows = await self._run(base + ".count()", b)
        total = int(total_rows[0]) if total_rows else 0
        rows = await self._run(base + ".range(lo, hi).valueMap(true)", {**b, "lo": offset, "hi": offset + limit})
        return Page([entity_from_vm(r) for r in rows], total, offset, limit)

    # ---------- aristas ----------
    async def upsert_edge(self, edge: EdgeRecord) -> tuple[EdgeRecord, bool]:
        await self._require_case(edge.case_id)
        for eid in (edge.out_id, edge.in_id):
            if await self.get_entity(edge.case_id, eid) is None:
                raise NotFound(f"La entidad '{eid}' no existe en el caso '{edge.case_id}'.")
        return await self._upsert_edge(edge, retry_on_conflict=True)

    async def _upsert_edge(self, edge: EdgeRecord, retry_on_conflict: bool) -> tuple[EdgeRecord, bool]:
        key = {"out_id": edge.out_id, "pk": edge.case_id, "elabel": edge.label, "eid": edge.id}
        rows = await self._run(Q_GET_EDGE, key)
        existing = edge_from_vm(rows[0]) if rows else None
        merged = merge_edge(existing, edge)
        b = {
            **key,
            "in_id": merged.in_id,
            "confidence": merged.confidence,
            "sources_json": json.dumps(merged.sources, ensure_ascii=False),
            "props_json": json.dumps(merged.properties, ensure_ascii=False),
            "first_seen": merged.first_seen,
            "last_seen": merged.last_seen,
        }
        if existing is None:
            try:
                await self._run(Q_ADD_EDGE, b)
            except ConflictError:
                if not retry_on_conflict:
                    raise
                return await self._upsert_edge(edge, retry_on_conflict=False)
        else:
            await self._run(
                Q_UPDATE_EDGE,
                {
                    k: b[k]
                    for k in ("out_id", "pk", "elabel", "eid", "confidence", "sources_json", "props_json", "last_seen")
                },
            )
        await self._touch_case(edge.case_id)
        return merged, existing is None

    async def upsert_many(self, entities: list[EntityRecord], edges: list[EdgeRecord]) -> tuple[int, int]:
        created = saved = 0
        for entity in entities:
            created += (await self.upsert_entity(entity))[1]
        for edge in edges:
            try:
                await self.upsert_edge(edge)
                saved += 1
            except NotFound:
                continue
        return created, saved

    async def neighbors(
        self, case_id: str, entity_id: str, edge_label: str, direction: Direction, limit: int
    ) -> list[Neighbor]:
        if await self.get_entity(case_id, entity_id) is None:
            await self._require_case(case_id)
            raise NotFound(f"La entidad '{entity_id}' no existe en el caso '{case_id}'.")
        dirs: list[Direction] = ["out", "in"] if direction == "both" else [direction]
        result: list[Neighbor] = []
        for d in dirs:
            b: dict[str, Any] = {"vid": entity_id, "pk": case_id, "n": limit}
            if edge_label:
                b["elabel"] = edge_label
            rows = await self._run(Q_NEIGHBORS[(d, bool(edge_label))], b)
            for row in rows:
                result.append(Neighbor(edge_from_vm(row["e"]), entity_from_vm(row["v"]), "out" if d == "out" else "in"))
        result.sort(key=lambda n: (-n.edge.confidence, n.entity.value))
        return result[:limit]

    async def find_paths(
        self, case_id: str, source_id: str, target_id: str, max_depth: int, limit: int
    ) -> list[list[str]]:
        for eid in (source_id, target_id):
            if await self.get_entity(case_id, eid) is None:
                await self._require_case(case_id)
                raise NotFound(f"La entidad '{eid}' no existe en el caso '{case_id}'.")
        rows = await self._run(
            Q_PATHS, {"src": source_id, "dst": target_id, "pk": case_id, "max_depth": max_depth, "n": limit}
        )
        paths: list[list[str]] = []
        for row in rows:
            objects: list[Any] = list(getattr(row, "objects", None) or row)
            paths.append([str(x) for x in objects])
        return paths

    async def case_summary(self, case_id: str, top: int) -> CaseSummary:
        case = await self.get_case(case_id)
        if case is None:
            raise NotFound(f"El caso '{case_id}' no existe. Revisa osint_list_cases.")
        by_type_rows = await self._run(Q_COUNT_BY_TYPE, {"pk": case_id})
        by_type = {str(k): int(v) for k, v in (by_type_rows[0] if by_type_rows else {}).items()}
        edges = await self._run(Q_COUNT_EDGES, {"pk": case_id})
        rows = await self._run(Q_DEGREES, {"pk": case_id, "scan": MAX_DEGREE_SCAN}) if top else []
        degrees = sorted(((entity_from_vm(r["v"]), int(r["degree"])) for r in rows), key=lambda x: -x[1])
        top_connected = [d for d in degrees if d[1] > 0][:top]
        return CaseSummary(case, sum(by_type.values()), int(edges[0]) if edges else 0, by_type, top_connected)

    async def export_case(self, case_id: str, max_items: int) -> tuple[list[EntityRecord], list[EdgeRecord]]:
        await self._require_case(case_id)
        vs = [entity_from_vm(r) for r in await self._run(Q_EXPORT_VERTICES, {"pk": case_id, "n": max_items})]
        kept = {e.id for e in vs}
        es = [edge_from_vm(r) for r in await self._run(Q_EXPORT_EDGES, {"pk": case_id, "n": max_items})]
        return vs, [e for e in es if e.out_id in kept and e.in_id in kept]

    async def replace_entity(self, entity: EntityRecord) -> EntityRecord:
        if await self.get_entity(entity.case_id, entity.id) is None:
            await self._require_case(entity.case_id)
            raise NotFound(f"La entidad '{entity.id}' no existe en el caso '{entity.case_id}'.")
        bindings = {
            "vid": entity.id,
            "pk": entity.case_id,
            "confidence": entity.confidence,
            "sources_json": json.dumps(entity.sources, ensure_ascii=False),
            "props_json": json.dumps(entity.properties, ensure_ascii=False),
            "last_seen": entity.last_seen,
            "notes": entity.notes,
        }
        await self._run(Q_UPDATE_ENTITY, bindings)
        await self._touch_case(entity.case_id)
        return entity

    async def delete_entity(self, case_id: str, entity_id: str) -> int:
        if await self.get_entity(case_id, entity_id) is None:
            await self._require_case(case_id)
            raise NotFound(f"La entidad '{entity_id}' no existe en el caso '{case_id}'.")
        rows = await self._run(Q_COUNT_BOTH_EDGES, {"vid": entity_id, "pk": case_id})
        await self._run(Q_DROP_VERTEX, {"vid": entity_id, "pk": case_id})
        await self._touch_case(case_id)
        return int(rows[0]) if rows else 0

    async def delete_edge(self, case_id: str, edge_id: str) -> bool:
        await self._require_case(case_id)
        rows = await self._run(Q_COUNT_EDGE, {"eid": edge_id, "pk": case_id})
        if not rows or int(rows[0]) == 0:
            return False
        await self._run(Q_DROP_EDGE, {"eid": edge_id, "pk": case_id})
        await self._touch_case(case_id)
        return True

    async def delete_case(self, case_id: str) -> tuple[int, int]:
        summary = await self.case_summary(case_id, 0)
        await self._run(Q_DROP_CASE, {"pk": case_id})
        return summary.entity_count, summary.edge_count

    async def append_step(self, step: StepRecord) -> StepRecord:
        seq = time.time_ns() // 1000  # microsegundos: creciente sin contar (evita carreras entre procesos)
        stored = replace(step, seq=seq)
        bindings = {
            "vid": f"step-{seq}",
            "pk": step.case_id,
            "seq": seq,
            "ts": step.timestamp,
            "kind": step.kind,
            "step_action": step.action,
            "input_id": step.input_id,
            "input_value": step.input_value,
            "reason": step.reason,
            "outputs_json": json.dumps(step.outputs),
            "new_entities": step.new_entities,
            "err": step.error,
            "duration_ms": step.duration_ms,
        }
        await self._run(Q_ADD_STEP, bindings)
        return stored

    async def append_steps(self, steps: list[StepRecord]) -> int:
        for step in steps:
            await self.append_step(step)
        return len(steps)

    async def list_steps(self, case_id: str, since_seq: int, limit: int) -> list[StepRecord]:
        if case_id:
            await self._require_case(case_id)
            rows = await self._run(Q_LIST_STEPS, {"pk": case_id, "since": since_seq, "scan": MAX_STEPS_SCAN})
            return sorted((step_from_vm(r) for r in rows), key=lambda x: x.seq)[:limit]
        rows = await self._run(Q_LIST_ALL_STEPS, {"scan": MAX_STEPS_SCAN})
        return sorted((step_from_vm(r) for r in rows), key=lambda x: x.seq)[-limit:]

    async def close(self) -> None:
        if self._close:
            await self._close()


# ----------------------------------------------------------------------------------------------
# Ejecutor real con gremlinpython (dependencia opcional: `uv sync --extra gremlin`).
# ----------------------------------------------------------------------------------------------
class GremlinPythonExecutor:
    """Envía consultas de texto con bindings usando GraphSON v2 (requisito de Cosmos DB)."""

    def __init__(
        self, endpoint: str, username: str, password: str, max_retries: int = 5, timeout_s: float = 30.0
    ) -> None:
        self._endpoint = endpoint
        self._username = username
        self._password = password
        self._max_retries = max_retries
        self._timeout_s = timeout_s
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                from gremlin_python.driver import client, serializer
            except ImportError as exc:
                raise BackendError(
                    "Falta la dependencia gremlinpython. Instálala con `uv sync --extra gremlin`."
                ) from exc
            self._client = client.Client(
                self._endpoint,
                "g",
                username=self._username,
                password=self._password,
                message_serializer=serializer.GraphSONSerializersV2d0(),
            )
        return self._client

    def _submit(self, query: str, bindings: dict[str, Any]) -> list[Any]:
        result = self._get_client().submit(query, bindings)
        rows = result.all().result(timeout=self._timeout_s)
        attrs = getattr(result, "status_attributes", None) or {}
        if "x-ms-total-request-charge" in attrs:
            logger.debug("RU consumidas: %s", attrs["x-ms-total-request-charge"])
        return list(rows)

    async def __call__(self, query: str, bindings: dict[str, Any]) -> list[Any]:
        reserved = RESERVED_BINDINGS & bindings.keys()
        if reserved:
            raise BackendError(f"Error interno: bindings reservados {sorted(reserved)}.")
        attempt = 0
        while True:
            try:
                return await asyncio.to_thread(self._submit, query, bindings)
            except BackendError:
                raise
            except Exception as exc:
                status, retry_ms = _error_status(exc)
                if status == 429 and attempt < self._max_retries:
                    attempt += 1
                    delay = (retry_ms or 100 * 2**attempt) / 1000
                    logger.warning("Cosmos 429; reintento %d en %.2fs", attempt, delay)
                    await asyncio.sleep(delay)
                    continue
                logger.error("Error Gremlin (estado %s): %s", status, exc.__class__.__name__)
                if status == 409:
                    raise ConflictError("El elemento ya existe en el grafo.") from exc
                if status == 429:
                    raise BackendError(
                        "Cosmos DB está limitando peticiones (429). Reduce limit o reintenta en unos segundos."
                    ) from exc
                if status is None:
                    raise BackendError(
                        "No se pudo conectar con el grafo Gremlin. Revisa GREMLIN_ENDPOINT y las credenciales."
                    ) from exc
                raise BackendError(
                    f"El grafo devolvió un error (estado {status}). Revisa los logs del servidor."
                ) from exc

    async def close(self) -> None:
        if self._client is not None:
            await asyncio.to_thread(self._client.close)
            self._client = None


def _error_status(exc: Exception) -> tuple[int | None, int | None]:
    attrs = getattr(exc, "status_attributes", None) or {}
    raw = attrs.get("x-ms-status-code") or getattr(exc, "status_code", None)
    try:
        status = int(raw) if raw is not None else None
    except (TypeError, ValueError):
        status = None
    retry = attrs.get("x-ms-retry-after-ms")
    try:
        retry_ms = int(float(retry)) if retry is not None else None
    except (TypeError, ValueError):
        retry_ms = None
    return status, retry_ms
