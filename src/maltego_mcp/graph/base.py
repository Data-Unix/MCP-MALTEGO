"""Contrato común de los backends del grafo."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Protocol

from maltego_mcp.domain.records import CaseRecord, EdgeRecord, EntityRecord, StepRecord

Direction = Literal["out", "in", "both"]


@dataclass(slots=True)
class Page[T]:
    items: list[T]
    total: int
    offset: int
    limit: int

    @property
    def has_more(self) -> bool:
        return self.offset + len(self.items) < self.total

    @property
    def next_offset(self) -> int | None:
        return self.offset + len(self.items) if self.has_more else None


@dataclass(slots=True)
class Neighbor:
    edge: EdgeRecord
    entity: EntityRecord
    direction: Literal["out", "in"]


@dataclass(slots=True)
class CaseSummary:
    case: CaseRecord
    entity_count: int
    edge_count: int
    by_type: dict[str, int] = field(default_factory=dict)
    top_connected: list[tuple[EntityRecord, int]] = field(default_factory=list)


class GraphStore(Protocol):
    """Operaciones que necesitan las tools. Todas acotadas en tamaño."""

    async def ensure_case(self, case_id: str, description: str = "") -> tuple[CaseRecord, bool]: ...

    async def get_case(self, case_id: str) -> CaseRecord | None: ...

    async def list_cases(self, limit: int, offset: int) -> Page[CaseRecord]: ...

    async def upsert_entity(self, entity: EntityRecord) -> tuple[EntityRecord, bool]: ...

    async def get_entity(self, case_id: str, entity_id: str) -> EntityRecord | None: ...

    async def search_entities(
        self, case_id: str, query: str, maltego_type: str, limit: int, offset: int
    ) -> Page[EntityRecord]: ...

    async def upsert_edge(self, edge: EdgeRecord) -> tuple[EdgeRecord, bool]: ...

    async def upsert_many(self, entities: list[EntityRecord], edges: list[EdgeRecord]) -> tuple[int, int]:
        """Inserta/fusiona en bloque (importaciones). Devuelve (entidades nuevas, relaciones guardadas)."""
        ...

    async def neighbors(
        self, case_id: str, entity_id: str, edge_label: str, direction: Direction, limit: int
    ) -> list[Neighbor]: ...

    async def find_paths(
        self, case_id: str, source_id: str, target_id: str, max_depth: int, limit: int
    ) -> list[list[str]]: ...

    async def case_summary(self, case_id: str, top: int) -> CaseSummary: ...

    async def export_case(self, case_id: str, max_items: int) -> tuple[list[EntityRecord], list[EdgeRecord]]: ...

    async def replace_entity(self, entity: EntityRecord) -> EntityRecord:
        """Sustituye la entidad tal cual (edición explícita: propiedades, notas, confianza)."""
        ...

    async def delete_entity(self, case_id: str, entity_id: str) -> int:
        """Borra la entidad y sus relaciones. Devuelve el número de relaciones borradas."""
        ...

    async def delete_edge(self, case_id: str, edge_id: str) -> bool: ...

    async def delete_case(self, case_id: str) -> tuple[int, int]:
        """Borra el caso con sus entidades, relaciones y pasos. Devuelve (entidades, relaciones)."""
        ...

    async def append_step(self, step: StepRecord) -> StepRecord:
        """Añade un paso a la memoria del caso; asigna seq creciente."""
        ...

    async def list_steps(self, case_id: str, since_seq: int, limit: int) -> list[StepRecord]:
        """Pasos del caso (case_id vacío = todos los casos) con seq > since_seq, en orden."""
        ...

    async def close(self) -> None: ...
