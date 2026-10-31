"""Backend en memoria, con persistencia opcional en un fichero JSON.

Pensado para desarrollo local, pruebas y uso sin Azure. Mismo contrato que el backend Gremlin.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
from collections import Counter, deque
from dataclasses import replace
from pathlib import Path
from typing import Any

from maltego_mcp.domain.records import (
    CaseRecord,
    EdgeRecord,
    EntityRecord,
    merge_edge,
    merge_entity,
    utc_now,
)
from maltego_mcp.errors import BackendError, NotFound
from maltego_mcp.graph.base import CaseSummary, Direction, Neighbor, Page

logger = logging.getLogger(__name__)
SCHEMA_VERSION = 1
MAX_PATH_EXPANSIONS = 50_000  # protege CPU/memoria en grafos densos


class MemoryGraphStore:
    def __init__(self, data_file: Path | None = None) -> None:
        self._data_file = data_file
        self._lock = asyncio.Lock()
        self._cases: dict[str, CaseRecord] = {}
        self._entities: dict[str, dict[str, EntityRecord]] = {}
        self._edges: dict[str, dict[str, EdgeRecord]] = {}
        if data_file and data_file.exists():
            self._load(data_file)

    # ---------- persistencia ----------
    def _load(self, path: Path) -> None:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BackendError(f"No se pudo leer el fichero de datos {path.name}: {exc.__class__.__name__}.") from exc
        for c in raw.get("cases", []):
            case = CaseRecord(**c)
            self._cases[case.case_id] = case
            self._entities.setdefault(case.case_id, {})
            self._edges.setdefault(case.case_id, {})
        for e in raw.get("entities", []):
            ent = EntityRecord(**e)
            self._entities.setdefault(ent.case_id, {})[ent.id] = ent
        for e in raw.get("edges", []):
            edge = EdgeRecord(**e)
            self._edges.setdefault(edge.case_id, {})[edge.id] = edge
        logger.info("Grafo cargado desde %s (%d casos)", path, len(self._cases))

    def _save(self) -> None:
        if not self._data_file:
            return
        payload: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "cases": [c.to_dict() for c in self._cases.values()],
            "entities": [e.to_dict() for d in self._entities.values() for e in d.values()],
            "edges": [e.to_dict() for d in self._edges.values() for e in d.values()],
        }
        self._data_file.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self._data_file.parent, prefix=".graph-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False)
            os.replace(tmp, self._data_file)
        except OSError as exc:
            Path(tmp).unlink(missing_ok=True)
            raise BackendError(f"No se pudo guardar el grafo: {exc.__class__.__name__}.") from exc

    # ---------- casos ----------
    async def ensure_case(self, case_id: str, description: str = "") -> tuple[CaseRecord, bool]:
        async with self._lock:
            existing = self._cases.get(case_id)
            now = utc_now()
            if existing:
                if description and description != existing.description:
                    existing = replace(existing, description=description, updated=now)
                    self._cases[case_id] = existing
                    self._save()
                return existing, False
            case = CaseRecord(case_id=case_id, description=description, created=now, updated=now)
            self._cases[case_id] = case
            self._entities.setdefault(case_id, {})
            self._edges.setdefault(case_id, {})
            self._save()
            return case, True

    async def get_case(self, case_id: str) -> CaseRecord | None:
        return self._cases.get(case_id)

    async def list_cases(self, limit: int, offset: int) -> Page[CaseRecord]:
        cases = sorted(self._cases.values(), key=lambda c: c.updated, reverse=True)
        return Page(cases[offset : offset + limit], len(cases), offset, limit)

    def _require_case(self, case_id: str) -> None:
        if case_id not in self._cases:
            raise NotFound(f"El caso '{case_id}' no existe. Créalo con osint_create_case o revisa osint_list_cases.")

    # ---------- entidades ----------
    async def upsert_entity(self, entity: EntityRecord) -> tuple[EntityRecord, bool]:
        async with self._lock:
            self._require_case(entity.case_id)
            bucket = self._entities[entity.case_id]
            existing = bucket.get(entity.id)
            merged = merge_entity(existing, entity)
            bucket[entity.id] = merged
            self._touch_case(entity.case_id)
            self._save()
            return merged, existing is None

    async def get_entity(self, case_id: str, entity_id: str) -> EntityRecord | None:
        return self._entities.get(case_id, {}).get(entity_id)

    async def search_entities(
        self, case_id: str, query: str, maltego_type: str, limit: int, offset: int
    ) -> Page[EntityRecord]:
        if case_id:
            self._require_case(case_id)
            pools = [self._entities.get(case_id, {})]
        else:
            pools = list(self._entities.values())
        q = query.lower()
        t = maltego_type.lower()
        hits = [
            e
            for pool in pools
            for e in pool.values()
            if (not q or q in e.value.lower()) and (not t or e.maltego_type.lower() == t)
        ]
        hits.sort(key=lambda e: (e.case_id, e.value))
        return Page(hits[offset : offset + limit], len(hits), offset, limit)

    # ---------- aristas ----------
    async def upsert_edge(self, edge: EdgeRecord) -> tuple[EdgeRecord, bool]:
        async with self._lock:
            self._require_case(edge.case_id)
            ents = self._entities[edge.case_id]
            for eid in (edge.out_id, edge.in_id):
                if eid not in ents:
                    raise NotFound(f"La entidad '{eid}' no existe en el caso '{edge.case_id}'.")
            bucket = self._edges[edge.case_id]
            existing = bucket.get(edge.id)
            merged = merge_edge(existing, edge)
            bucket[edge.id] = merged
            self._touch_case(edge.case_id)
            self._save()
            return merged, existing is None

    async def neighbors(
        self, case_id: str, entity_id: str, edge_label: str, direction: Direction, limit: int
    ) -> list[Neighbor]:
        self._require_case(case_id)
        ents = self._entities[case_id]
        if entity_id not in ents:
            raise NotFound(f"La entidad '{entity_id}' no existe en el caso '{case_id}'.")
        result: list[Neighbor] = []
        for edge in self._edges[case_id].values():
            if edge_label and edge.label != edge_label:
                continue
            if direction in ("out", "both") and edge.out_id == entity_id:
                result.append(Neighbor(edge, ents[edge.in_id], "out"))
            elif direction in ("in", "both") and edge.in_id == entity_id:
                result.append(Neighbor(edge, ents[edge.out_id], "in"))
        result.sort(key=lambda n: (-n.edge.confidence, n.entity.value))
        return result[:limit]

    async def find_paths(
        self, case_id: str, source_id: str, target_id: str, max_depth: int, limit: int
    ) -> list[list[str]]:
        self._require_case(case_id)
        ents = self._entities[case_id]
        for eid in (source_id, target_id):
            if eid not in ents:
                raise NotFound(f"La entidad '{eid}' no existe en el caso '{case_id}'.")
        adjacency: dict[str, set[str]] = {}
        for edge in self._edges[case_id].values():
            adjacency.setdefault(edge.out_id, set()).add(edge.in_id)
            adjacency.setdefault(edge.in_id, set()).add(edge.out_id)
        paths: list[list[str]] = []
        queue: deque[list[str]] = deque([[source_id]])
        expansions = 0
        while queue and len(paths) < limit and expansions < MAX_PATH_EXPANSIONS:
            path = queue.popleft()
            expansions += 1
            if path[-1] == target_id and len(path) > 1:
                paths.append(path)
                continue
            if len(path) > max_depth:
                continue
            for nxt in sorted(adjacency.get(path[-1], ())):
                if nxt not in path:
                    queue.append([*path, nxt])
        return paths

    async def case_summary(self, case_id: str, top: int) -> CaseSummary:
        self._require_case(case_id)
        ents = self._entities[case_id]
        edges = self._edges[case_id]
        degree: Counter[str] = Counter()
        for edge in edges.values():
            degree[edge.out_id] += 1
            degree[edge.in_id] += 1
        by_type = Counter(e.maltego_type for e in ents.values())
        top_connected = [(ents[eid], n) for eid, n in degree.most_common(top)]
        return CaseSummary(self._cases[case_id], len(ents), len(edges), dict(by_type), top_connected)

    async def export_case(self, case_id: str, max_items: int) -> tuple[list[EntityRecord], list[EdgeRecord]]:
        self._require_case(case_id)
        ents = list(self._entities[case_id].values())[:max_items]
        kept = {e.id for e in ents}
        edges = [e for e in self._edges[case_id].values() if e.out_id in kept and e.in_id in kept][:max_items]
        return ents, edges

    def _touch_case(self, case_id: str) -> None:
        case = self._cases[case_id]
        self._cases[case_id] = replace(case, updated=utc_now())

    async def close(self) -> None:
        return None
