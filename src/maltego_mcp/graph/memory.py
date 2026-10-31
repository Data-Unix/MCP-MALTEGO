"""Backend en memoria, con persistencia opcional en un fichero JSON.

Pensado para desarrollo local, pruebas y uso sin Azure. Mismo contrato que el backend Gremlin.
Varios procesos (p. ej. varios agentes en Orca) pueden compartir el fichero: cada escritura toma un
bloqueo de fichero, recarga si otro proceso lo cambió, aplica el cambio y guarda.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import sys
import tempfile
import threading
from collections import Counter, deque
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path
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
SCHEMA_VERSION = 1
MAX_PATH_EXPANSIONS = 50_000  # protege CPU/memoria en grafos densos


class MemoryGraphStore:
    def __init__(self, data_file: Path | None = None) -> None:
        self._data_file = data_file
        self._lock = asyncio.Lock()
        self._cases: dict[str, CaseRecord] = {}
        self._entities: dict[str, dict[str, EntityRecord]] = {}
        self._edges: dict[str, dict[str, EdgeRecord]] = {}
        self._steps: dict[str, list[StepRecord]] = {}
        self._loaded_mtime: tuple[int, int, int] | None = None
        # Protege el estado frente al hilo de escritura (asyncio.to_thread) y lecturas concurrentes.
        self._sync_lock = threading.RLock()
        self._reload_if_changed()

    # ---------- persistencia ----------
    def _mtime(self) -> tuple[int, int, int] | None:
        """Huella del fichero. Cada guardado crea un inodo nuevo (os.replace), así que la huella cambia
        aunque el sistema de ficheros tenga poca resolución de fechas."""
        try:
            st = self._data_file.stat() if self._data_file else None
        except FileNotFoundError:
            return None
        return (st.st_ino, st.st_mtime_ns, st.st_size) if st else None

    def _reload_if_changed(self) -> None:
        """Recarga el fichero si otro proceso lo modificó desde la última lectura/escritura."""
        with self._sync_lock:
            mtime = self._mtime()
            if self._data_file is None or mtime is None or mtime == self._loaded_mtime:
                return
            self._load(self._data_file)
            self._loaded_mtime = mtime

    def _load(self, path: Path) -> None:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            cases = {c["case_id"]: CaseRecord(**c) for c in raw.get("cases", [])}
            entities = [EntityRecord(**e) for e in raw.get("entities", [])]
            edges = [EdgeRecord(**e) for e in raw.get("edges", [])]
            steps = [StepRecord(**x) for x in raw.get("steps", [])]
        except (OSError, json.JSONDecodeError, TypeError, KeyError, AttributeError) as exc:
            raise BackendError(
                f"No se pudo leer el fichero de datos {path.name} ({exc.__class__.__name__}). "
                "Revísalo o apunta MALTEGO_MCP_DATA_FILE a otro fichero."
            ) from exc
        self._cases = cases
        self._entities = {cid: {} for cid in cases}
        self._edges = {cid: {} for cid in cases}
        for ent in entities:
            self._entities.setdefault(ent.case_id, {})[ent.id] = ent
        for edge in edges:
            self._edges.setdefault(edge.case_id, {})[edge.id] = edge
        self._steps = {}
        for step in sorted(steps, key=lambda x: x.seq):
            self._steps.setdefault(step.case_id, []).append(step)
        logger.info("Grafo cargado desde %s (%d casos)", path, len(self._cases))

    @contextlib.contextmanager
    def _file_lock(self) -> Iterator[None]:
        """Bloqueo exclusivo entre procesos sobre <data_file>.lock (POSIX y Windows)."""
        if self._data_file is None:
            yield
            return
        self._data_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self._data_file.with_suffix(self._data_file.suffix + ".lock"), "a+b") as fh:
            if sys.platform == "win32":  # pragma: no cover - solo Windows
                import msvcrt

                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(fh, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(fh, fcntl.LOCK_UN)

    def _write_sync[T](self, mutate: Callable[[], T]) -> T:
        with self._file_lock(), self._sync_lock:
            self._reload_if_changed()
            result = mutate()
            self._save()
            return result

    async def _write[T](self, mutate: Callable[[], T]) -> T:
        """Serializa escrituras en el proceso y ejecuta la E/S de fichero fuera del bucle de eventos."""
        async with self._lock:
            if self._data_file is None:
                return mutate()
            return await asyncio.to_thread(self._write_sync, mutate)

    def _read(self) -> None:
        self._reload_if_changed()

    def _save(self) -> None:
        if not self._data_file:
            return
        payload: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "cases": [c.to_dict() for c in self._cases.values()],
            "entities": [e.to_dict() for d in self._entities.values() for e in d.values()],
            "edges": [e.to_dict() for d in self._edges.values() for e in d.values()],
            "steps": [x.to_dict() for lst in self._steps.values() for x in lst],
        }
        self._data_file.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self._data_file.parent, prefix=".graph-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False)
            os.replace(tmp, self._data_file)
            self._loaded_mtime = self._mtime()
        except OSError as exc:
            Path(tmp).unlink(missing_ok=True)
            raise BackendError(f"No se pudo guardar el grafo: {exc.__class__.__name__}.") from exc

    # ---------- casos ----------
    async def ensure_case(self, case_id: str, description: str = "") -> tuple[CaseRecord, bool]:
        self._read()
        existing = self._cases.get(case_id)
        if existing and (not description or description == existing.description):
            return existing, False  # sin cambios: no se escribe

        def mutate() -> tuple[CaseRecord, bool]:
            now = utc_now()
            current = self._cases.get(case_id)
            if current:
                if description and description != current.description:
                    current = replace(current, description=description, updated=now)
                    self._cases[case_id] = current
                return current, False
            case = CaseRecord(case_id=case_id, description=description, created=now, updated=now)
            self._cases[case_id] = case
            self._entities.setdefault(case_id, {})
            self._edges.setdefault(case_id, {})
            return case, True

        return await self._write(mutate)

    async def get_case(self, case_id: str) -> CaseRecord | None:
        self._read()
        return self._cases.get(case_id)

    async def list_cases(self, limit: int, offset: int) -> Page[CaseRecord]:
        self._read()
        cases = sorted(self._cases.values(), key=lambda c: c.updated, reverse=True)
        return Page(cases[offset : offset + limit], len(cases), offset, limit)

    def _require_case(self, case_id: str) -> None:
        if case_id not in self._cases:
            raise NotFound(f"El caso '{case_id}' no existe. Créalo con osint_create_case o revisa osint_list_cases.")

    # ---------- entidades ----------
    async def upsert_entity(self, entity: EntityRecord) -> tuple[EntityRecord, bool]:
        def mutate() -> tuple[EntityRecord, bool]:
            self._require_case(entity.case_id)
            bucket = self._entities[entity.case_id]
            existing = bucket.get(entity.id)
            merged = merge_entity(existing, entity)
            bucket[entity.id] = merged
            self._touch_case(entity.case_id)
            return merged, existing is None

        return await self._write(mutate)

    async def get_entity(self, case_id: str, entity_id: str) -> EntityRecord | None:
        self._read()
        return self._entities.get(case_id, {}).get(entity_id)

    async def search_entities(
        self, case_id: str, query: str, maltego_type: str, limit: int, offset: int
    ) -> Page[EntityRecord]:
        self._read()
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
        def mutate() -> tuple[EdgeRecord, bool]:
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
            return merged, existing is None

        return await self._write(mutate)

    async def upsert_many(self, entities: list[EntityRecord], edges: list[EdgeRecord]) -> tuple[int, int]:
        """Una sola escritura del fichero para todo el lote."""

        def mutate() -> tuple[int, int]:
            created = saved = 0
            for entity in entities:
                self._require_case(entity.case_id)
                bucket = self._entities[entity.case_id]
                existing = bucket.get(entity.id)
                bucket[entity.id] = merge_entity(existing, entity)
                created += existing is None
            for edge in edges:
                ents = self._entities.get(edge.case_id, {})
                if edge.out_id not in ents or edge.in_id not in ents:
                    continue
                bucket_e = self._edges[edge.case_id]
                bucket_e[edge.id] = merge_edge(bucket_e.get(edge.id), edge)
                saved += 1
            for case_id in {e.case_id for e in entities} | {e.case_id for e in edges}:
                if case_id in self._cases:
                    self._touch_case(case_id)
            return created, saved

        return await self._write(mutate)

    async def neighbors(
        self, case_id: str, entity_id: str, edge_label: str, direction: Direction, limit: int
    ) -> list[Neighbor]:
        self._read()
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
        self._read()
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
        self._read()
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
        self._read()
        self._require_case(case_id)
        ents = list(self._entities[case_id].values())[:max_items]
        kept = {e.id for e in ents}
        edges = [e for e in self._edges[case_id].values() if e.out_id in kept and e.in_id in kept][:max_items]
        return ents, edges

    def _touch_case(self, case_id: str) -> None:
        case = self._cases[case_id]
        self._cases[case_id] = replace(case, updated=utc_now())

    async def replace_entity(self, entity: EntityRecord) -> EntityRecord:
        def mutate() -> EntityRecord:
            self._require_case(entity.case_id)
            if entity.id not in self._entities[entity.case_id]:
                raise NotFound(f"La entidad '{entity.id}' no existe en el caso '{entity.case_id}'.")
            self._entities[entity.case_id][entity.id] = entity
            self._touch_case(entity.case_id)
            return entity

        return await self._write(mutate)

    async def delete_entity(self, case_id: str, entity_id: str) -> int:
        def mutate() -> int:
            self._require_case(case_id)
            if self._entities[case_id].pop(entity_id, None) is None:
                raise NotFound(f"La entidad '{entity_id}' no existe en el caso '{case_id}'.")
            edges = self._edges[case_id]
            gone = [k for k, e in edges.items() if entity_id in (e.out_id, e.in_id)]
            for k in gone:
                del edges[k]
            self._touch_case(case_id)
            return len(gone)

        return await self._write(mutate)

    async def delete_edge(self, case_id: str, edge_id: str) -> bool:
        def mutate() -> bool:
            self._require_case(case_id)
            removed = self._edges[case_id].pop(edge_id, None) is not None
            if removed:
                self._touch_case(case_id)
            return removed

        return await self._write(mutate)

    async def delete_case(self, case_id: str) -> tuple[int, int]:
        def mutate() -> tuple[int, int]:
            self._require_case(case_id)
            counts = (len(self._entities.pop(case_id, {})), len(self._edges.pop(case_id, {})))
            self._steps.pop(case_id, None)
            del self._cases[case_id]
            return counts

        return await self._write(mutate)

    async def append_step(self, step: StepRecord) -> StepRecord:
        def mutate() -> StepRecord:
            steps = self._steps.setdefault(step.case_id, [])
            stored = replace(step, seq=(steps[-1].seq + 1) if steps else 1)
            steps.append(stored)
            return stored

        return await self._write(mutate)

    async def list_steps(self, case_id: str, since_seq: int, limit: int) -> list[StepRecord]:
        self._read()
        if case_id:
            self._require_case(case_id)
            pool = self._steps.get(case_id, [])
        else:
            pool = sorted((x for lst in self._steps.values() for x in lst), key=lambda x: (x.timestamp, x.seq))
        return [x for x in pool if x.seq > since_seq or not case_id][:limit] if case_id else pool[-limit:]

    async def close(self) -> None:
        return None
