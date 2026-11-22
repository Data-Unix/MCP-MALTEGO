"""Copiloto determinista: puntuación de entidades, siguiente mejor acción, procedencia y aprendizaje.

Todo se calcula a partir del grafo y de la memoria de pasos (sin aleatoriedad ni LLM), así que las mismas
entradas dan siempre el mismo resultado y cada puntuación se puede explicar.
"""

from __future__ import annotations

import datetime
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
    only_passive: bool = False,
) -> list[Action]:
    """Pivotes más valiosos: entidad prioritaria x transform aplicable aún no ejecutado x rendimiento esperado."""
    done = {(s.action.lower(), s.input_id) for s in steps if s.kind == "transform"}
    actions: list[Action] = []
    for sc in sorted(scores.values(), key=lambda x: -x.priority)[:50]:
        for spec in specs:
            if only_passive and not spec.is_passive:
                continue
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
    validity: ValidityAssessment | None = None


def explain(
    entity: EntityRecord,
    scores: dict[str, EntityScore],
    steps: list[StepRecord],
    specs: list[TransformSpec],
    env: dict[str, str],
    only_passive: bool = False,
) -> Explanation:
    discovered = [s for s in steps if s.kind == "transform" and entity.id in s.outputs]
    used = [s for s in steps if s.kind == "transform" and s.input_id == entity.id]
    ran = {s.action.lower() for s in used}
    pending = [
        sp.name
        for sp in specs
        if sp.input_types
        and sp.accepts(entity.maltego_type)
        and sp.available(env)
        and (not only_passive or sp.is_passive)
        and sp.name.lower() not in ran
    ]
    validity = compute_entity_validity(entity)
    return Explanation(entity, scores.get(entity.id), discovered, used, pending, validity=validity)


def indirect_pivots_for_entity(entity: EntityRecord) -> list[str]:
    """Generador de pivotes indirectos fuera de la caja ('¿Quién más habla de esto?') según el tipo (M3)."""
    mtype = entity.maltego_type
    val = entity.value
    pivots: list[str] = []
    if mtype in ("maltego.Domain", "maltego.DNSName"):
        pivots.extend(
            [
                f"Capturas históricas en Wayback/Common Crawl/Arquivo.pt para '{val}' (páginas borradas, robots.txt)",
                f"Búsqueda de certificados Certificate Transparency por Organización (crt.sh O=) vinculados a '{val}'",
                f"Historial pasivo pDNS y AnubisDB para detectar subdominios dados de baja o previos de '{val}'",
                f"Dorking de huellas compartidas (ID de Google Analytics, Adsense, tags) de '{val}' en otros dominios",
                f"Referencias y commits en repositorios de código público (GitHub/GitLab) mencionando '{val}'",
            ]
        )
    elif mtype in ("maltego.IPv4Address", "maltego.IPv6Address"):
        pivots.extend(
            [
                f"Consultar en RIPEstat prefijos BGP históricos y ASN anunciante para {val}",
                f"Consultar Shodan InternetDB e ipapi.is para servicios cacheados, CVEs y banderas de hosting de {val}",
                f"Búsqueda de resoluciones DNS pasivas (PTR históricos) vinculadas a {val}",
            ]
        )
    elif mtype == "maltego.EmailAddress":
        pivots.extend(
            [
                f"Verificar exposición en brechas históricas públicas (HIBP, XposedOrNot) para '{val}'",
                f"Buscar perfil público en Gravatar para el hash de '{val}' sin interactuar",
                "Menciones del correo en commits públicos y repositorios de código",
            ]
        )
    elif mtype in ("maltego.Company", "maltego.Organization"):
        pivots.extend(
            [
                f"Consultar actos y administradores en BORME (OpenMercantil) y validación VIES IVA para '{val}'",
                f"Consultar árbol societario internacional (LEI, matriz directa y última) en GLEIF para '{val}'",
                f"Revisar ofertas de empleo públicas que revelen tecnologías, sedes y dependencias de '{val}'",
                f"Buscar certificados SSL/TLS con campo O='{val}' para descubrir activos no vinculados al dominio",
            ]
        )
    elif mtype in ("maltego.Person", "maltego.Alias"):
        pivots.extend(
            [
                f"Cruzar cargos societarios vigentes e históricos en BORME (OpenMercantil) para '{val}'",
                f"Buscar presencia pasiva en plataformas de código (GitHub, GitLab, Keybase) para '{val}'",
                f"Buscar presencia en comunidades técnicas y foros (Reddit, Lobsters, Hacker News) para '{val}'",
                f"Verificar clave pública PGP y pruebas criptográficas en Keybase para '{val}'",
            ]
        )
    else:
        pivots.append(f"Buscar referencias cruzadas y menciones secundarias de '{val}' en fuentes de terceros")
    return pivots


# -------------------------------------------------------------------------------------- Vigencia F5 (§4.4)
@dataclass(frozen=True, slots=True)
class EvidenceItem:
    cluster: str
    source: str
    family: str
    observed_date: str
    days_ago: int
    score: float
    is_recent: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "cluster": self.cluster,
            "source": self.source,
            "family": self.family,
            "observed_date": self.observed_date,
            "days_ago": self.days_ago,
            "score": round(self.score, 2),
            "is_recent": self.is_recent,
        }


@dataclass(frozen=True, slots=True)
class ValidityAssessment:
    status: str  # OBSERVADO_RECIENTE | HISTORICO | MENCIONADO_SIN_FECHA
    score: int  # 0 a 100
    evidences: tuple[EvidenceItem, ...]
    independent_clusters_count: int
    recent_clusters_count: int
    rationale: str

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "score": self.score,
            "evidences": [e.to_dict() for e in self.evidences],
            "independent_clusters_count": self.independent_clusters_count,
            "recent_clusters_count": self.recent_clusters_count,
            "rationale": self.rationale,
        }


def _parse_ts_days_ago(ts_str: str, now: datetime.datetime) -> tuple[str, int] | None:
    """Parsea una marca temporal heterogénea y calcula los días transcurridos."""
    if not ts_str:
        return None
    from maltego_mcp.transforms.pdns import normalize_iso_utc

    norm = normalize_iso_utc(ts_str)
    if not norm:
        return None
    try:
        clean = norm.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.UTC)
        delta = (now - dt).total_seconds() / 86400.0
        days = max(0, int(delta))
        return norm, days
    except Exception:
        return None


def compute_entity_validity(entity: EntityRecord, now: datetime.datetime | None = None) -> ValidityAssessment:
    """Calcula la vigencia objetiva de una entidad (§4.4) sin tocar el objetivo.

    Estados:
    - OBSERVADO_RECIENTE: >= 2 clústeres independientes con observación reciente.
    - HISTORICO: solo registros con fechas antiguas (>30 d pDNS, >90 d CT).
    - MENCIONADO_SIN_FECHA: mencionado únicamente en fuentes/agregadores sin fecha.

    Reglas obligatorias:
    - Decaimiento por semivida f = 2^(-Δ/H).
    - Máximo por clúster de independencia (las copias de una misma fuente no inflan la puntuación).
    - NUNCA se califica de 'muerto' un activo, solo 'sin evidencia reciente' o 'HISTORICO'.
    """
    if now is None:
        now = datetime.datetime.now(datetime.UTC)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=datetime.UTC)

    props = entity.properties
    evidences_list: list[EvidenceItem] = []

    # Extraer indicios de pDNS / Registros / CT / Archivos
    for k, v in props.items():
        k_clean = k.replace("__", ".")
        if not v:
            continue
        # Registros mercantiles / oficiales (BORME, GLEIF, VIES)
        if "registry.last_seen" in k_clean:
            parsed = _parse_ts_days_ago(v, now)
            if parsed:
                iso_ts, days = parsed
                cluster = (
                    props.get("independence_cluster") or props.get("independence.cluster") or "registry_openmercantil"
                )
                source = props.get("source") or props.get("source_family") or "registry"
                h = 180.0
                score = 35.0 * (2.0 ** (-days / h))
                is_recent = days <= 180
                evidences_list.append(
                    EvidenceItem(
                        cluster=cluster,
                        source=source,
                        family="registry",
                        observed_date=iso_ts,
                        days_ago=days,
                        score=score,
                        is_recent=is_recent,
                    )
                )

        # pDNS last_seen
        elif "last_seen" in k_clean or "lastseen" in k_clean:
            parsed = _parse_ts_days_ago(v, now)
            if parsed:
                iso_ts, days = parsed
                cluster = (
                    props.get("pdns.independence_cluster")
                    or props.get("pdns__independence_cluster")
                    or (
                        props.get("independence_cluster")
                        if "ct" not in (props.get("independence_cluster") or "")
                        else None
                    )
                    or "pdns_sensor_mnemonic"
                )
                source = props.get("pdns.source") or props.get("pdns__source") or "pdns"
                # Semivida H = 30 días, peso base = 40
                h = 30.0
                score = 40.0 * (2.0 ** (-days / h))
                is_recent = days <= 30
                evidences_list.append(
                    EvidenceItem(
                        cluster=cluster,
                        source=source,
                        family="pdns",
                        observed_date=iso_ts,
                        days_ago=days,
                        score=score,
                        is_recent=is_recent,
                    )
                )

        # CT not_before
        elif "not_before" in k_clean or "notbefore" in k_clean:
            parsed = _parse_ts_days_ago(v, now)
            if parsed:
                iso_ts, days = parsed
                cluster = (
                    props.get("ct.independence_cluster")
                    or props.get("ct__independence_cluster")
                    or (
                        props.get("independence_cluster")
                        if "pdns" not in (props.get("independence_cluster") or "")
                        else None
                    )
                    or "ct_crtsh"
                )
                source = props.get("ct.source") or props.get("ct__source") or "crt.sh"
                is_canary = props.get("possible_canary") == "true"
                is_wildcard = entity.value.startswith("*.")
                h = 90.0
                score = 35.0 * (2.0 ** (-days / h))
                is_recent = (days <= 90) and not is_canary and not is_wildcard
                evidences_list.append(
                    EvidenceItem(
                        cluster=cluster,
                        source=source,
                        family="ct",
                        observed_date=iso_ts,
                        days_ago=days,
                        score=score,
                        is_recent=is_recent,
                    )
                )

        # Archivos históricos (Wayback / Arquivo.pt)
        elif "archive.timestamp" in k_clean or "archive__timestamp" in k_clean:
            parsed = _parse_ts_days_ago(v, now)
            if parsed:
                iso_ts, days = parsed
                cluster = (
                    props.get("archive.independence_cluster")
                    or props.get("archive__independence_cluster")
                    or "archive_wayback"
                )
                source = props.get("archive.source") or props.get("archive__source") or "archive"
                h = 180.0
                score = 25.0 * (2.0 ** (-days / h))
                is_recent = days <= 60
                evidences_list.append(
                    EvidenceItem(
                        cluster=cluster,
                        source=source,
                        family="archive",
                        observed_date=iso_ts,
                        days_ago=days,
                        score=score,
                        is_recent=is_recent,
                    )
                )

    # Si no hay indicios con fecha, comprobar si tiene cluster o fuente de agregador sin fecha
    if not evidences_list:
        cluster = props.get("independence_cluster") or props.get("independence.cluster") or ""
        source = props.get("pdns.source") or props.get("pdns__source") or ""
        if cluster or source:
            evidences_list.append(
                EvidenceItem(
                    cluster=cluster or "aggregator_generic",
                    source=source or "aggregator",
                    family="aggregator",
                    observed_date="",
                    days_ago=-1,
                    score=12.0,
                    is_recent=False,
                )
            )

    # Agrupar por clúster de independencia: tomar el máximo de cada clúster
    by_cluster: dict[str, list[EvidenceItem]] = {}
    for ev in evidences_list:
        by_cluster.setdefault(ev.cluster, []).append(ev)

    total_score_raw = 0.0
    recent_clusters = 0
    for _cl_name, items in by_cluster.items():
        max_score = max(it.score for it in items)
        total_score_raw += max_score
        if any(it.is_recent for it in items):
            recent_clusters += 1

    independent_clusters_count = len(by_cluster)
    final_score = min(100, max(5, round(total_score_raw))) if evidences_list else 0

    # Clasificación estricta según §4.4
    has_dates = any(ev.observed_date for ev in evidences_list)
    if recent_clusters >= 2:
        status = "OBSERVADO_RECIENTE"
        rationale = (
            f"Activo confirmado por telemetría reciente ({recent_clusters} clústeres independientes "
            f"observados en ventana activa). Puntuación explicable: {final_score}/100."
        )
    elif has_dates:
        status = "HISTORICO"
        min_days = min(ev.days_ago for ev in evidences_list if ev.days_ago >= 0)
        rationale = (
            f"Sin evidencia reciente: última observación registrada hace {min_days} días. "
            f"Puntuación explicable: {final_score}/100."
        )
    else:
        status = "MENCIONADO_SIN_FECHA"
        rationale = (
            "Mencionado exclusivamente en agregadores o fuentes secundarias sin marca temporal confirmada. "
            f"Puntuación base: {final_score}/100."
        )

    return ValidityAssessment(
        status=status,
        score=final_score,
        evidences=tuple(evidences_list),
        independent_clusters_count=independent_clusters_count,
        recent_clusters_count=recent_clusters,
        rationale=rationale,
    )
