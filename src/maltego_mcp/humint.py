"""Motores analíticos HUMINT/SOCMINT: conducta, correlación de pseudónimos, cronología del sujeto y relaciones.

Todas las inferencias conductuales o psicométricas incluyen `humint.epistemic_status="hypothesis"` y citan
explícitamente la evidencia observada en el grafo para distinguir hechos técnicos de hipótesis analíticas.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from maltego_mcp.domain.records import EdgeRecord, EntityRecord

IDENTITY_TYPES = frozenset(
    {
        "maltego.alias",
        "humint.alias",
        "maltego.person",
        "maltego.affiliation",
        "maltego.affiliationtwitter",
        "maltego.emailaddress",
    }
)

_LEET_MAP = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_TOKEN_RE = re.compile(r"[a-zA-Z0-9_áéíóúñÁÉÍÓÚÑ+-]{2,}")
_HANDLE_ORG_RE = re.compile(r"@([A-Za-z0-9_.-]{2,40})")
_ISO_DATE_RE = re.compile(r"\b(19\d\d|20\d\d)-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])(?:[T\s](\d\d:\d\d(?::\d\d)?Z?))?")

TEMPORAL_PROP_KEYS: tuple[tuple[str, str], ...] = (
    ("whois.created", "Registro WHOIS (creación)"),
    ("whois.expires", "Expiración WHOIS"),
    ("breach.date", "Exposición en filtración (breach)"),
    ("github.created_at", "Alta de cuenta en GitHub"),
    ("github.updated_at", "Última actividad en GitHub"),
    ("otx.created", "Publicación de pulso OTX"),
    ("vt.last_resolved", "Resolución DNS pasiva (VirusTotal)"),
    ("crypto.time", "Transacción en blockchain"),
    ("cert.not_before", "Emisión de certificado SSL/TLS"),
    ("humint.timestamp", "Evento conductual / check-in HUMINT"),
)


@dataclass(slots=True)
class BehaviorTraitItem:
    maltego_type: str
    value: str
    edge_label: str
    weight: int = 75
    properties: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class BehaviorAnalysis:
    subject_value: str
    sentiment: str
    communication_style: str
    opsec_level: str
    ocean_summary: str
    active_window: str
    summary_note: str
    traits: list[BehaviorTraitItem] = field(default_factory=list)
    subject_properties: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class IdentityOverlap:
    source_id: str
    source_value: str
    target_id: str
    target_value: str
    probability: float
    handle_similarity: float
    metadata_similarity: float
    stylometry_similarity: float
    graph_jaccard: float
    same_individual: bool
    evidence: list[str] = field(default_factory=list)
    edge_created: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "source_value": self.source_value,
            "target_id": self.target_id,
            "target_value": self.target_value,
            "probability": self.probability,
            "handle_similarity": self.handle_similarity,
            "metadata_similarity": self.metadata_similarity,
            "stylometry_similarity": self.stylometry_similarity,
            "graph_jaccard": self.graph_jaccard,
            "same_individual": self.same_individual,
            "evidence": list(self.evidence),
            "edge_created": self.edge_created,
        }


@dataclass(slots=True)
class SubjectTimelineEvent:
    timestamp: str
    category: str
    event: str
    entity_id: str
    entity_type: str
    entity_value: str
    source_property: str

    def to_dict(self) -> dict[str, str]:
        return {
            "timestamp": self.timestamp,
            "category": self.category,
            "event": self.event,
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "entity_value": self.entity_value,
            "source_property": self.source_property,
        }


@dataclass(slots=True)
class TimelineAnomaly:
    kind: str
    severity: str
    description: str
    entities: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "description": self.description,
            "entities": list(self.entities),
        }


@dataclass(slots=True)
class SubjectTimeline:
    case_id: str
    subject_id: str
    events: list[SubjectTimelineEvent] = field(default_factory=list)
    anomalies: list[TimelineAnomaly] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": "subject",
            "case_id": self.case_id,
            "subject_id": self.subject_id,
            "count": len(self.events),
            "events": [e.to_dict() for e in self.events],
            "anomalies": [a.to_dict() for a in self.anomalies],
        }


# --------------------------------------------------------------------------- 1. Análisis conductual
def analyze_subject_behavior(
    value: str,
    properties: dict[str, str],
    notes: str = "",
    neighbor_values: list[tuple[str, str, dict[str, str]]] | None = None,
) -> BehaviorAnalysis:
    """Analiza textos, metadatos y vecindario de un sujeto para inferir rasgos HUMINT auditables."""
    neighbors = neighbor_values or []
    corpus_parts = [
        value,
        notes,
        properties.get("bio", ""),
        properties.get("github.bio", ""),
        properties.get("gravatar.bio", ""),
        properties.get("posts", ""),
        properties.get("status", ""),
        properties.get("description", ""),
    ]
    for _, nval, nprops in neighbors:
        corpus_parts.append(nval)
        for k in ("bio", "github.bio", "notes", "description", "location", "github.location"):
            if nprops.get(k):
                corpus_parts.append(nprops[k])
    corpus = " ".join(p for p in corpus_parts if p).strip()
    lower = corpus.lower()

    # 1. Sentimiento y estilo comunicativo
    hostile_terms = ("exploit", "attack", "pwn", "breach", "leak", "ddos", "ransom", "fud", "bypass", "hostil", "odio")
    tech_terms = (
        "python",
        "rust",
        "linux",
        "kernel",
        "security",
        "osint",
        "cti",
        "soc",
        "devops",
        "cloud",
        "github",
        "git",
        "crypto",
        "api",
    )
    collab_terms = ("open source", "community", "team", "contributor", "maintainer", "mentor", "research", "comunidad")
    opsec_terms = ("pgp", "gpg", "tor", "monero", "xmrig", "protonmail", "simplelogin", "anon", "opsec", "nostr")

    hostile_hits = [w for w in hostile_terms if w in lower]
    tech_hits = [w for w in tech_terms if w in lower]
    collab_hits = [w for w in collab_terms if w in lower]
    opsec_hits = [w for w in opsec_terms if w in lower]

    try:
        repos = int(properties.get("github.public_repos", "0") or "0")
    except ValueError:
        repos = 0
    try:
        followers = int(properties.get("github.followers", "0") or "0")
    except ValueError:
        followers = 0

    if hostile_hits:
        sentiment = "confrontacional/ofensivo"
    elif collab_hits or followers >= 20:
        sentiment = "colaborativo/constructivo"
    else:
        sentiment = "neutro/operativo"

    if tech_hits or repos > 0:
        style = "técnico-analítico"
    elif len(corpus) > 160:
        style = "narrativo-expresivo"
    else:
        style = "conciso-fragmentario"

    if opsec_hits or ("+" in value and "@" in value):
        opsec_level = "alto (uso de alias compartimentados / herramientas de privacidad)"
    elif properties.get("github.name") or properties.get("location") or properties.get("github.location"):
        opsec_level = "bajo-medio (exposición de atributos reales y ubicación)"
    else:
        opsec_level = "medio (superficie pública acotada)"

    # 2. Indicadores proxy OCEAN (siempre marcados como hipótesis)
    openness = "alta" if (len(tech_hits) >= 2 or repos >= 5) else "media"
    conscientiousness = "alta" if (opsec_hits or repos >= 10) else "media"
    extraversion = "alta" if (followers >= 25 or len(collab_hits) >= 1) else "moderada-reservada"
    ocean_summary = f"Apertura={openness}, Responsabilidad={conscientiousness}, Extraversión={extraversion}"

    # 3. Ventana horaria / ubicación
    location = (
        properties.get("location")
        or properties.get("github.location")
        or properties.get("gravatar.location")
        or next(
            (nval for ntype, nval, _ in neighbors if ntype.lower() in ("maltego.location", "humint.locationhistory")),
            "",
        )
    )
    tz = properties.get("timezone") or properties.get("utc_offset") or ""
    if not tz and location:
        loc_l = location.lower()
        if any(x in loc_l for x in ("madrid", "spain", "españa", "berlin", "paris", "cet")):
            tz = "UTC+1/UTC+2 (Europa Central)"
        elif any(x in loc_l for x in ("london", "uk", "lisbon", "dublin", "utc")):
            tz = "UTC+0/UTC+1"
        elif any(x in loc_l for x in ("new york", "est", "toronto", "miami", "washington")):
            tz = "UTC-5 (US Eastern)"
        elif any(x in loc_l for x in ("san francisco", "california", "seattle", "pst")):
            tz = "UTC-8 (US Pacific)"
    active_window = tz or "No determinada (sin marcas horarias suficientes)"

    traits: list[BehaviorTraitItem] = []
    # Rasgo técnico / cognitivo
    ev_tech = ", ".join(tech_hits[:4]) or (f"{repos} repos públicos" if repos else f"valor '{value[:40]}'")
    traits.append(
        BehaviorTraitItem(
            maltego_type="humint.PsychologicalTrait",
            value=f"[Hipótesis] Estilo {style} ({ocean_summary})",
            edge_label="exhibits_trait",
            weight=75,
            properties={
                "humint.trait": f"[Hipótesis] Estilo {style} ({ocean_summary})",
                "humint.dimension": "OCEAN_Proxy",
                "humint.sentiment": sentiment,
                "humint.style": style,
                "humint.evidence": ev_tech[:200],
                "humint.epistemic_status": "hypothesis",
            },
        )
    )
    # Rasgo OPSEC / postura operacional
    ev_opsec = ", ".join(opsec_hits[:4]) or ("atributos públicos visibles" if location else "huella mínima")
    traits.append(
        BehaviorTraitItem(
            maltego_type="humint.PsychologicalTrait",
            value=f"[Hipótesis] Postura OPSEC: {opsec_level.split(' (')[0]}",
            edge_label="exhibits_trait",
            weight=70,
            properties={
                "humint.trait": f"[Hipótesis] Postura OPSEC: {opsec_level.split(' (')[0]}",
                "humint.dimension": "OPSEC_Posture",
                "humint.opsec": opsec_level,
                "humint.evidence": ev_opsec[:200],
                "humint.epistemic_status": "hypothesis",
            },
        )
    )
    if hostile_hits:
        traits.append(
            BehaviorTraitItem(
                maltego_type="humint.PsychologicalTrait",
                value=f"[Hipótesis] Interés en vectores ofensivos ({', '.join(hostile_hits[:3])})",
                edge_label="exhibits_trait",
                weight=82,
                properties={
                    "humint.trait": f"[Hipótesis] Interés en vectores ofensivos ({', '.join(hostile_hits[:3])})",
                    "humint.dimension": "Threat_Interest",
                    "humint.risk": "high",
                    "humint.evidence": ", ".join(hostile_hits[:5]),
                    "humint.epistemic_status": "hypothesis",
                },
            )
        )

    if location:
        loc_val = f"{location} ({tz})" if tz and tz not in location else location
        traits.append(
            BehaviorTraitItem(
                maltego_type="humint.LocationHistory",
                value=loc_val[:160],
                edge_label=" frequented_location",
                weight=80,
                properties={
                    "humint.location": loc_val[:160],
                    "humint.timezone": tz or "unknown",
                    "humint.evidence": "metadatos de perfil/vecindario",
                    "humint.epistemic_status": "observed" if properties.get("location") else "hypothesis",
                },
            )
        )

    orgs: set[str] = set()
    for k in ("company", "github.company", "organization", "humint.organization"):
        if properties.get(k):
            orgs.add(properties[k].strip().lstrip("@"))
    for m in _HANDLE_ORG_RE.findall(properties.get("bio", "") + " " + properties.get("github.bio", "")):
        orgs.add(m)
    for org in sorted(o for o in orgs if len(o) >= 2)[:3]:
        traits.append(
            BehaviorTraitItem(
                maltego_type="humint.Organization",
                value=org,
                edge_label="affiliated_with",
                weight=78,
                properties={
                    "humint.organization": org,
                    "humint.evidence": "filiación declarada en perfil/bio",
                    "humint.epistemic_status": "observed",
                },
            )
        )

    summary_note = (
        f"[Hipótesis analítica HUMINT] Sujeto '{value}': estilo {style}, sentimiento {sentiment}, "
        f"OPSEC {opsec_level}. Indicadores OCEAN: {ocean_summary}. Ventana/zona: {active_window}."
    )
    subj_props = {
        "humint.sentiment": sentiment,
        "humint.style": style,
        "humint.opsec": opsec_level,
        "humint.ocean_summary": ocean_summary,
        "humint.active_window": active_window,
        "humint.epistemic_status": "hypothesis",
    }
    if hostile_hits:
        subj_props["humint.risk"] = "high"
    return BehaviorAnalysis(
        subject_value=value,
        sentiment=sentiment,
        communication_style=style,
        opsec_level=opsec_level,
        ocean_summary=ocean_summary,
        active_window=active_window,
        summary_note=summary_note,
        traits=traits,
        subject_properties=subj_props,
    )


# --------------------------------------------------------------------------- 2. Correlación de pseudónimos
def _clean_handle(value: str) -> str:
    base = value.strip().lower().lstrip("@")
    if "@" in base:
        base = base.split("@", 1)[0]
    if " (" in base:
        base = base.split(" (", 1)[0]
    return base.split("+", 1)[0]


def _stem_handle(handle: str) -> str:
    norm = handle.translate(_LEET_MAP)
    norm = re.sub(r"[._\-]+", "", norm)
    stripped = re.sub(r"\d+$", "", norm)
    return stripped if len(stripped) >= 3 else norm


def _jaro_winkler(s1: str, s2: str) -> float:
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if not len1 or not len2:
        return 0.0
    match_dist = max(len1, len2) // 2 - 1
    if match_dist < 0:
        match_dist = 0
    s1_matches = [False] * len1
    s2_matches = [False] * len2
    matches = 0
    for i in range(len1):
        start = max(0, i - match_dist)
        end = min(i + match_dist + 1, len2)
        for j in range(start, end):
            if not s2_matches[j] and s1[i] == s2[j]:
                s1_matches[i] = s2_matches[j] = True
                matches += 1
                break
    if not matches:
        return 0.0
    k = 0
    transpositions = 0
    for i in range(len1):
        if s1_matches[i]:
            while not s2_matches[k]:
                k += 1
            if s1[i] != s2[k]:
                transpositions += 1
            k += 1
    jaro = (matches / len1 + matches / len2 + (matches - transpositions / 2) / matches) / 3.0
    prefix = 0
    for c1, c2 in zip(s1[:4], s2[:4], strict=False):
        if c1 == c2:
            prefix += 1
        else:
            break
    return min(1.0, jaro + prefix * 0.1 * (1.0 - jaro))


def _char_ngrams(text: str, n: int = 3) -> set[str]:
    cleaned = re.sub(r"\s+", " ", text.lower().strip())
    if len(cleaned) < n:
        return {cleaned} if cleaned else set()
    return {cleaned[i : i + n] for i in range(len(cleaned) - n + 1)}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def calculate_identity_overlap(
    entity_a: EntityRecord,
    entity_b: EntityRecord,
    entities_by_id: dict[str, EntityRecord],
    edges: list[EdgeRecord],
    threshold: float = 0.85,
) -> IdentityOverlap:
    """Calcula la probabilidad matemática [0-1] de que dos perfiles/alias correspondan al mismo individuo."""
    evidence: list[str] = []

    # 1. Similitud morfológica del alias / handle
    h1, h2 = _clean_handle(entity_a.value), _clean_handle(entity_b.value)
    stem1, stem2 = _stem_handle(h1), _stem_handle(h2)
    jw_raw = _jaro_winkler(h1, h2)
    jw_stem = _jaro_winkler(stem1, stem2)
    handle_sim = round(max(jw_raw, jw_stem * 0.96), 3)
    if handle_sim >= 0.8:
        evidence.append(f"raíz léxica de alias muy similar ('{h1}' ~ '{h2}', score={handle_sim:.2f})")

    # 2. Solapamiento de metadatos directos (nombre, ubicación, avatar, dominio, empresa)
    meta_matches = 0.0
    meta_checks = 0.0
    pa, pb = entity_a.properties, entity_b.properties
    meta_pairs = (
        ("nombre", ("person.fullname", "github.name", "gravatar.display_name", "name", "display_name")),
        ("ubicación", ("location", "github.location", "gravatar.location", "humint.location")),
        ("organización", ("company", "github.company", "organization", "humint.organization")),
        ("email", ("email", "github.email", "public_email")),
        ("web/blog", ("blog", "github.blog", "website", "url")),
        ("avatar/hash", ("gravatar.hash", "avatar_hash")),
        ("zona horaria", ("timezone", "humint.timezone", "humint.active_window")),
    )
    for label_name, keys in meta_pairs:
        va = next((pa[k].strip().lower() for k in keys if pa.get(k, "").strip()), "")
        vb = next((pb[k].strip().lower() for k in keys if pb.get(k, "").strip()), "")
        if va and vb:
            meta_checks += 1.0
            sim = _jaro_winkler(va.lstrip("@"), vb.lstrip("@"))
            if sim >= 0.85:
                meta_matches += sim
                evidence.append(f"coincidencia en {label_name} ('{va}' ~ '{vb}')")
    meta_sim = round(meta_matches / meta_checks, 3) if meta_checks > 0 else 0.0

    # 3. Estilometría básica y huella temporal (biografías, notas, tokens)
    text_a = " ".join(filter(None, [entity_a.notes, pa.get("bio", ""), pa.get("github.bio", ""), pa.get("posts", "")]))
    text_b = " ".join(filter(None, [entity_b.notes, pb.get("bio", ""), pb.get("github.bio", ""), pb.get("posts", "")]))
    if text_a and text_b:
        tok_a = {m.lower() for m in _TOKEN_RE.findall(text_a)}
        tok_b = {m.lower() for m in _TOKEN_RE.findall(text_b)}
        stylo_sim = round(0.5 * _jaccard(tok_a, tok_b) + 0.5 * _jaccard(_char_ngrams(text_a), _char_ngrams(text_b)), 3)
        if stylo_sim >= 0.45:
            evidence.append(f"solapamiento estilométrico en bio/notas (score={stylo_sim:.2f})")
    else:
        stylo_sim = 0.0

    # 4. Vecindario en el grafo (1 salto y 2 saltos)
    adj: dict[str, set[str]] = {}
    for ed in edges:
        if ed.label == "humint_highly_likely_same_individual":
            continue
        adj.setdefault(ed.out_id, set()).add(ed.in_id)
        adj.setdefault(ed.in_id, set()).add(ed.out_id)
    nb1_a = adj.get(entity_a.id, set()) - {entity_b.id}
    nb1_b = adj.get(entity_b.id, set()) - {entity_a.id}
    shared_1hop = nb1_a & nb1_b
    nb2_a = set(nb1_a)
    for n in nb1_a:
        nb2_a |= adj.get(n, set())
    nb2_b = set(nb1_b)
    for n in nb1_b:
        nb2_b |= adj.get(n, set())
    nb2_a -= {entity_a.id, entity_b.id}
    nb2_b -= {entity_a.id, entity_b.id}
    shared_2hop = nb2_a & nb2_b

    if shared_1hop:
        names = [entities_by_id[x].value for x in list(shared_1hop)[:3] if x in entities_by_id]
        graph_sim = min(1.0, round(0.65 + 0.15 * len(shared_1hop) + 0.2 * _jaccard(nb1_a, nb1_b), 3))
        evidence.append(f"{len(shared_1hop)} vecino(s) directo(s) compartido(s) ({', '.join(names)})")
    elif shared_2hop:
        names = [entities_by_id[x].value for x in list(shared_2hop)[:3] if x in entities_by_id]
        graph_sim = min(0.85, round(0.45 + 0.12 * len(shared_2hop) + 0.2 * _jaccard(nb2_a, nb2_b), 3))
        evidence.append(f"{len(shared_2hop)} nodo(s) compartido(s) a 2 saltos ({', '.join(names)})")
    else:
        graph_sim = 0.0

    # Combinación ponderada adaptativa según las señales disponibles
    weights: list[tuple[float, float]] = [(handle_sim, 0.35)]
    if meta_checks > 0:
        weights.append((meta_sim, 0.35))
    if text_a and text_b:
        weights.append((stylo_sim, 0.15))
    if nb1_a or nb1_b:
        weights.append((graph_sim, 0.35))

    total_w = sum(w for _, w in weights) or 1.0
    base_prob = sum(score * w for score, w in weights) / total_w
    # Bonificación por corroboración convergente (p. ej. handle muy similar + metadatos o grafo compartido)
    corroboration_bonus = 0.0
    strong_signals = sum(1 for s in (handle_sim >= 0.82, meta_sim >= 0.8, stylo_sim >= 0.5, graph_sim >= 0.6) if s)
    if strong_signals >= 2:
        corroboration_bonus = 0.12 * (strong_signals - 1)
    probability = round(min(0.99, max(0.0, base_prob + corroboration_bonus)), 3)
    same = probability >= threshold

    return IdentityOverlap(
        source_id=entity_a.id,
        source_value=entity_a.value,
        target_id=entity_b.id,
        target_value=entity_b.value,
        probability=probability,
        handle_similarity=handle_sim,
        metadata_similarity=meta_sim,
        stylometry_similarity=stylo_sim,
        graph_jaccard=graph_sim,
        same_individual=same,
        evidence=evidence or ["sin señales convergentes fuertes"],
    )


# --------------------------------------------------------------------------- 3. Cronología del sujeto y de-confliction
def _normalize_timestamp(raw: str) -> str:
    text = raw.strip()
    if not text:
        return ""
    if text.isdigit() and 9 <= len(text) <= 13:
        ts = int(text)
        if len(text) > 10:
            ts //= 1000
        try:
            return datetime.fromtimestamp(ts, UTC).replace(microsecond=0).isoformat()
        except (ValueError, OSError):
            return ""
    m = _ISO_DATE_RE.search(text)
    if m:
        date_part = f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
        time_part = m.group(4) or "00:00:00Z"
        if len(time_part) == 5:
            time_part += ":00Z"
        elif not time_part.endswith("Z"):
            time_part += "Z"
        return f"{date_part}T{time_part}"
    return ""


def build_subject_timeline(
    case_id: str,
    entities: list[EntityRecord],
    edges: list[EdgeRecord],
    subject_id: str = "",
    limit: int = 100,
) -> SubjectTimeline:
    """Construye la cronología vital/técnica del sujeto y detecta anomalías temporales (de-confliction)."""
    by_id = {e.id: e for e in entities}
    if subject_id and subject_id in by_id:
        # Filtra al sujeto y su componente / vecindario a 2 saltos
        adj: dict[str, set[str]] = {}
        for ed in edges:
            adj.setdefault(ed.out_id, set()).add(ed.in_id)
            adj.setdefault(ed.in_id, set()).add(ed.out_id)
        keep = {subject_id} | adj.get(subject_id, set())
        for n in list(keep):
            keep |= adj.get(n, set())
        pool = [e for e in entities if e.id in keep]
    else:
        pool = list(entities)

    events: list[SubjectTimelineEvent] = []
    domain_creations: list[tuple[str, EntityRecord]] = []
    breach_dates: list[tuple[str, EntityRecord]] = []
    account_creations: list[tuple[str, EntityRecord]] = []
    timezones: dict[str, list[EntityRecord]] = {}

    for ent in pool:
        for prop_key, label_desc in TEMPORAL_PROP_KEYS:
            raw_val = ent.properties.get(prop_key, "")
            norm_ts = _normalize_timestamp(raw_val)
            if norm_ts:
                cat = prop_key.split(".", 1)[0]
                events.append(
                    SubjectTimelineEvent(
                        timestamp=norm_ts,
                        category=cat,
                        event=f"{label_desc}: {ent.value}",
                        entity_id=ent.id,
                        entity_type=ent.maltego_type,
                        entity_value=ent.value,
                        source_property=prop_key,
                    )
                )
                if prop_key == "whois.created":
                    domain_creations.append((norm_ts, ent))
                elif prop_key == "breach.date":
                    breach_dates.append((norm_ts, ent))
                elif prop_key in ("github.created_at", "humint.timestamp"):
                    account_creations.append((norm_ts, ent))

        # Si la entidad no tenía propiedades temporales explícitas pero sí first_seen en el grafo
        if not any(ent.properties.get(k) for k, _ in TEMPORAL_PROP_KEYS) and ent.first_seen:
            norm_first = _normalize_timestamp(ent.first_seen)
            if norm_first:
                events.append(
                    SubjectTimelineEvent(
                        timestamp=norm_first,
                        category="observacion",
                        event=f"Primera observación en el caso ({ent.maltego_type})",
                        entity_id=ent.id,
                        entity_type=ent.maltego_type,
                        entity_value=ent.value,
                        source_property="first_seen",
                    )
                )

        tz = (
            ent.properties.get("humint.timezone")
            or ent.properties.get("timezone")
            or ent.properties.get("humint.active_window")
            or ""
        )
        if tz and not tz.startswith("No determinada"):
            timezones.setdefault(tz, []).append(ent)

    events.sort(key=lambda x: (x.timestamp, x.entity_value))
    anomalies: list[TimelineAnomaly] = []

    # Anomalía 1: Conflicto de zonas horarias / ubicaciones incompatibles
    if len(timezones) >= 2:
        tz_list = sorted(timezones.keys())
        involved = [e.id for lst in timezones.values() for e in lst]
        anomalies.append(
            TimelineAnomaly(
                kind="timezone_conflict",
                severity="media",
                description=(
                    f"Múltiples zonas horarias o ventanas de actividad distintas detectadas ({', '.join(tz_list)}): "
                    "posible uso de VPN/OPSEC, viaje o cuenta compartida por varios operadores."
                ),
                entities=list(dict.fromkeys(involved))[:10],
            )
        )

    # Anomalía 2: Paradoja cronológica (cuenta/perfil anterior al registro WHOIS del dominio asociado)
    for d_ts, d_ent in domain_creations:
        for a_ts, a_ent in account_creations:
            a_haystack = (a_ent.value + " " + " ".join(a_ent.properties.values())).lower()
            if a_ts < d_ts and d_ent.value.lower() in a_haystack:
                anomalies.append(
                    TimelineAnomaly(
                        kind="chronology_paradox",
                        severity="alta",
                        description=(
                            f"La entidad '{a_ent.value}' ({a_ts[:10]}) es anterior a la fecha de creación WHOIS "
                            f"de '{d_ent.value}' ({d_ts[:10]})."
                        ),
                        entities=[a_ent.id, d_ent.id],
                    )
                )

    # Anomalía 3: Pivote / rotación de identidad posterior a filtración (post-breach pivot)
    for b_ts, b_ent in breach_dates:
        for a_ts, a_ent in account_creations + domain_creations:
            if a_ts > b_ts and a_ent.id != b_ent.id:
                anomalies.append(
                    TimelineAnomaly(
                        kind="post_breach_pivot",
                        severity="media",
                        description=(
                            f"Actividad o alta posterior a filtración: '{a_ent.value}' ({a_ts[:10]}) "
                            f"aparece después de la filtración '{b_ent.value}' ({b_ts[:10]})."
                        ),
                        entities=[b_ent.id, a_ent.id],
                    )
                )
                break

    return SubjectTimeline(case_id=case_id, subject_id=subject_id, events=events[:limit], anomalies=anomalies)


# --------------------------------------------------------------------------- 4. Relaciones ponderadas
def infer_relationship_attributes(
    source: EntityRecord,
    target: EntityRecord,
    edges: list[EdgeRecord],
    explicit_role: str = "",
    explicit_sentiment: str = "",
    explicit_weight: int = 1,
) -> dict[str, str]:
    """Determina o infiere rol, sentimiento y peso de una relación HUMINT."""
    out_deg: dict[str, int] = {}
    in_deg: dict[str, int] = {}
    adj: dict[str, set[str]] = {}
    for ed in edges:
        out_deg[ed.out_id] = out_deg.get(ed.out_id, 0) + 1
        in_deg[ed.in_id] = in_deg.get(ed.in_id, 0) + 1
        adj.setdefault(ed.out_id, set()).add(ed.in_id)
        adj.setdefault(ed.in_id, set()).add(ed.out_id)

    src_nb = adj.get(source.id, set())
    dst_nb = adj.get(target.id, set())
    shared = len(src_nb & dst_nb)

    role = explicit_role
    if not role:
        if len(src_nb) >= 3 and len(dst_nb) >= 3 and shared == 0:
            role = "intermediario"
        elif out_deg.get(source.id, 0) > out_deg.get(target.id, 0) + 1:
            role = "lider"
        elif target.maltego_type.lower() in ("maltego.organization", "maltego.company", "humint.organization"):
            role = "operador"
        else:
            role = "colaborador"

    sentiment = explicit_sentiment
    if not sentiment:
        notes_combined = (source.notes + " " + target.notes).lower()
        if any(w in notes_combined for w in ("hostil", "ataque", "rival", "amenaza", "conflicto")):
            sentiment = "hostil"
        elif shared >= 2:
            sentiment = "estrecho"
        elif any(
            t.maltego_type.lower() in ("maltego.company", "maltego.organization", "humint.organization")
            for t in (source, target)
        ):
            sentiment = "profesional"
        else:
            sentiment = "transaccional"

    weight = explicit_weight if explicit_weight > 1 else min(100, max(10, 25 + shared * 20 + len(src_nb) * 5))
    is_hyp = any(
        e.maltego_type.lower() == "humint.psychologicaltrait"
        or e.properties.get("humint.epistemic_status") == "hypothesis"
        or e.value.startswith("[Hipótesis]")
        for e in (source, target)
    )
    status = "hypothesis" if is_hyp or not (explicit_role and explicit_sentiment) else "observed"
    return {
        "humint.role": role,
        "humint.sentiment": sentiment,
        "humint.weight": str(weight),
        "humint.shared_neighbors": str(shared),
        "humint.epistemic_status": status,
    }

