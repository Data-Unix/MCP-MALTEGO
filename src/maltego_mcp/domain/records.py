"""Registros del grafo (vértices y aristas) y reglas de fusión al reinsertar."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

MAX_PROPERTIES = 50
MAX_PROPERTY_LEN = 2000
MAX_SOURCES = 50


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def clamp_confidence(value: float) -> float:
    return round(min(1.0, max(0.0, float(value))), 3)


def clean_properties(props: dict[str, str]) -> dict[str, str]:
    """Limita número y tamaño de propiedades adicionales (datos no confiables)."""
    cleaned: dict[str, str] = {}
    for key, value in list(props.items())[:MAX_PROPERTIES]:
        k = str(key).strip()[:120]
        if k:
            cleaned[k] = str(value)[:MAX_PROPERTY_LEN]
    return cleaned


@dataclass(slots=True)
class EntityRecord:
    id: str
    case_id: str
    label: str
    maltego_type: str
    value: str
    confidence: float = 0.5
    sources: list[str] = field(default_factory=list)
    properties: dict[str, str] = field(default_factory=dict)
    first_seen: str = ""
    last_seen: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "case_id": self.case_id,
            "label": self.label,
            "maltego_type": self.maltego_type,
            "value": self.value,
            "confidence": self.confidence,
            "sources": list(self.sources),
            "properties": dict(self.properties),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass(slots=True)
class EdgeRecord:
    id: str
    case_id: str
    label: str
    out_id: str
    in_id: str
    confidence: float = 0.5
    sources: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "case_id": self.case_id,
            "label": self.label,
            "out_id": self.out_id,
            "in_id": self.in_id,
            "confidence": self.confidence,
            "sources": list(self.sources),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass(slots=True)
class CaseRecord:
    case_id: str
    description: str = ""
    created: str = ""
    updated: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "description": self.description,
            "created": self.created,
            "updated": self.updated,
        }


def _merge_sources(old: list[str], new: list[str]) -> list[str]:
    merged = list(dict.fromkeys([*old, *new]))
    return merged[-MAX_SOURCES:]


def merge_entity(existing: EntityRecord | None, incoming: EntityRecord) -> EntityRecord:
    """Fusiona una reinserción: conserva first_seen, sube confianza al máximo y une fuentes."""
    if existing is None:
        return incoming
    props = {**existing.properties, **incoming.properties}
    return replace(
        existing,
        confidence=max(existing.confidence, incoming.confidence),
        sources=_merge_sources(existing.sources, incoming.sources),
        properties=clean_properties(props),
        last_seen=incoming.last_seen or existing.last_seen,
    )


def merge_edge(existing: EdgeRecord | None, incoming: EdgeRecord) -> EdgeRecord:
    if existing is None:
        return incoming
    return replace(
        existing,
        confidence=max(existing.confidence, incoming.confidence),
        sources=_merge_sources(existing.sources, incoming.sources),
        last_seen=incoming.last_seen or existing.last_seen,
    )
