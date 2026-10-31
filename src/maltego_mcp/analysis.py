"""Copiloto determinista: puntuación de entidades, siguiente mejor acción, procedencia y aprendizaje.

Todo se calcula a partir del grafo y de la memoria de pasos (sin aleatoriedad ni LLM), así que las mismas
entradas dan siempre el mismo resultado y cada puntuación se puede explicar.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from maltego_mcp.domain.records import EdgeRecord, EntityRecord, StepRecord
from maltego_mcp.transforms.catalog import TransformSpec

# Fiabilidad por tipo de fuente (0-1). Lo manual del analista y los proveedores comerciales pesan más.
SOURCE_RELIABILITY = {"manual": 0.8, "maltego": 0.8, "provider": 0.75, "transform": 0.6, "import": 0.5}
WEIGHTS = {"confidence": 0.35, "reliability": 0.2, "linkage": 0.3, "novelty": 0.15}


@dataclass(frozen=True, slots=True)
class EntityScore:
    entity: EntityRecord
    confidence: float
    reliability: float
    linkage: float
    novelty: float
    degree: int

    @property
    def priority(self) -> float:
        return round(
            WEIGHTS["confidence"] * self.confidence
            + WEIGHTS["reliability"] * self.reliability
            + WEIGHTS["linkage"] * self.linkage
            + WEIGHTS["novelty"] * self.novelty,
            3,
        )

    def rationale(self) -> str:
        return (
            f"confianza {self.confidence:.2f}·{WEIGHTS['confidence']} + fiabilidad de fuentes {self.reliability:.2f}·"
            f"{WEIGHTS['reliability']} + conexiones {self.degree} ({self.linkage:.2f})·{WEIGHTS['linkage']} + "
            f"novedad {self.novelty:.2f}·{WEIGHTS['novelty']} = {self.priority:.2f}"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "entity_id": self.entity.id,
            "value": self.entity.value,
            "maltego_type": self.entity.maltego_type,
            "priority": self.priority,
            "confidence": self.confidence,
            "reliability": self.reliability,
            "linkage": self.linkage,
            "novelty": self.novelty,
            "degree": self.degree,
        }


def _source_kind(source: str, provider_transforms: set[str]) -> str:
    if source.startswith("transform:"):
        return "provider" if source.split(":", 1)[1].lower() in provider_transforms else "transform"
    if source.startswith("import:"):
        return "import"
    return source if source in SOURCE_RELIABILITY else "manual"


def score_entities(
    entities: list[EntityRecord], edges: list[EdgeRecord], provider_transforms: set[str] | None = None
) -> dict[str, EntityScore]:
    providers = {p.lower() for p in (provider_transforms or set())}
    degree: Counter[str] = Counter()
    for edge in edges:
        degree[edge.out_id] += 1
        degree[edge.in_id] += 1
    order = sorted(entities, key=lambda e: (e.first_seen, e.id))
    n = max(1, len(order) - 1)
    novelty = {e.id: (i / n if len(order) > 1 else 1.0) for i, e in enumerate(order)}
    scores: dict[str, EntityScore] = {}
    for e in entities:
        kinds = [_source_kind(s, providers) for s in e.sources] or ["manual"]
        reliability = sum(SOURCE_RELIABILITY[k] for k in kinds) / len(kinds)
        reliability = min(1.0, reliability + 0.05 * (len(set(e.sources)) - 1))  # corroboración por varias fuentes
        d = degree[e.id]
        scores[e.id] = EntityScore(
            e, e.confidence, round(reliability, 3), round(d / (d + 3), 3), round(novelty[e.id], 3), d
        )
    return scores


@dataclass(slots=True)
class TransformStats:
    runs: int = 0
    errors: int = 0
    new_entities: int = 0
    total_ms: int = 0

    @property
    def avg_yield(self) -> float:
        ok = self.runs - self.errors
        return self.new_entities / ok if ok else 0.0

    @property
    def error_rate(self) -> float:
        return self.errors / self.runs if self.runs else 0.0


def learning_stats(steps: list[StepRecord]) -> dict[str, TransformStats]:
    """Rendimiento histórico de cada transform (todas las investigaciones registradas)."""
    stats: dict[str, TransformStats] = defaultdict(TransformStats)
    for s in steps:
        if s.kind != "transform":
            continue
        st = stats[s.action]
        st.runs += 1
        st.errors += bool(s.error)
        st.new_entities += s.new_entities
        st.total_ms += s.duration_ms
    return dict(stats)


@dataclass(frozen=True, slots=True)
class Action:
    transform: str
    entity: EntityRecord
    score: float
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "transform": self.transform,
            "entity_id": self.entity.id,
            "value": self.entity.value,
            "maltego_type": self.entity.maltego_type,
            "score": self.score,
            "reason": self.reason,
        }


def next_best_actions(
    scores: dict[str, EntityScore],
    steps: list[StepRecord],
    specs: list[TransformSpec],
    env: dict[str, str],
    history: dict[str, TransformStats],
    limit: int,
) -> list[Action]:
    """Pivotes más valiosos: entidad prioritaria x transform aplicable aún no ejecutado x rendimiento esperado."""
    done = {(s.action.lower(), s.input_id) for s in steps if s.kind == "transform"}
    actions: list[Action] = []
    for sc in sorted(scores.values(), key=lambda x: -x.priority)[:50]:
        for spec in specs:
            if not spec.input_types or not spec.accepts(sc.entity.maltego_type) or not spec.available(env):
                continue
            if (spec.name.lower(), sc.entity.id) in done:
                continue
            st = history.get(spec.name)
            expected = 1.0 if st is None or st.runs < 2 else min(3.0, 0.3 + st.avg_yield)  # optimista sin historial
            penalty = 1.0 - 0.5 * (st.error_rate if st else 0.0)
            score = round(sc.priority * expected * penalty, 3)
            hist = (
                f"rinde {st.avg_yield:.1f} nuevas/ejecución en {st.runs} ejecuciones"
                if st and st.runs
                else "sin historial"
            )
            actions.append(
                Action(
                    spec.name,
                    sc.entity,
                    score,
                    f"prioridad de la entidad {sc.priority:.2f}; {spec.name} {hist}; aún no ejecutado",
                )
            )
    actions.sort(key=lambda a: (-a.score, a.entity.value, a.transform))
    return actions[:limit]


@dataclass(slots=True)
class Explanation:
    entity: EntityRecord
    score: EntityScore | None
    discovered_by: list[StepRecord] = field(default_factory=list)
    used_as_input: list[StepRecord] = field(default_factory=list)
    pending_transforms: list[str] = field(default_factory=list)


def explain(
    entity: EntityRecord,
    scores: dict[str, EntityScore],
    steps: list[StepRecord],
    specs: list[TransformSpec],
    env: dict[str, str],
) -> Explanation:
    discovered = [s for s in steps if s.kind == "transform" and entity.id in s.outputs]
    used = [s for s in steps if s.kind == "transform" and s.input_id == entity.id]
    ran = {s.action.lower() for s in used}
    pending = [
        sp.name
        for sp in specs
        if sp.input_types and sp.accepts(entity.maltego_type) and sp.available(env) and sp.name.lower() not in ran
    ]
    return Explanation(entity, scores.get(entity.id), discovered, used, pending)
