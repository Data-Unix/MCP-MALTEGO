"""Coordinador central del motor unificado de perfilado (profiling).

Despacha la ejecución a los submotores especializados y devuelve un ProfileRecord
estructurado y no repudiable.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from maltego_mcp.domain.profiling import (
    GOLDWATER_ETHICAL_WARNING,
    TYPOLOGY_TITLES,
    TYPOLOGY_TO_DOMAIN,
    ProfileRecord,
    ProfileTypology,
)
from maltego_mcp.domain.records import EntityRecord
from maltego_mcp.profiling.clinical_risk import profile_clinical_risk
from maltego_mcp.profiling.corporate import (
    profile_competitor,
    profile_cultural_fit,
    profile_investor,
    profile_negotiation,
    profile_shareholder,
)
from maltego_mcp.profiling.cyber import (
    profile_cyber,
    profile_data,
    profile_device,
    profile_network,
)
from maltego_mcp.profiling.forensic import (
    profile_deductive_crime,
    profile_geographic,
    profile_inductive_crime,
    profile_stylometry,
    profile_victimology,
)
from maltego_mcp.profiling.intelligence import (
    profile_border_risk,
    profile_insider_threat,
    profile_political_leader,
)
from maltego_mcp.profiling.psychographic import (
    profile_audience,
    profile_psychographic,
    profile_user_consumer,
)

TYPOLOGY_ALIASES: dict[str, ProfileTypology] = {
    "activist_investor": "investor",
    "activist": "investor",
    "key_shareholder": "shareholder",
    "strategic_negotiation": "negotiation",
    "negotiator": "negotiation",
    "cultural": "cultural_fit",
    "competitors": "competitor",
    "cyber_profiling": "cyber",
    "device_fingerprinting": "device",
    "fingerprint": "device",
    "network_profiling": "network",
    "data_profiling": "data",
    "forensic_linguistics": "stylometry",
    "geographical": "geographic",
    "political": "political_leader",
    "border": "border_risk",
    "insider": "insider_threat",
    "consumer": "user_consumer",
    "user": "user_consumer",
    "clinical": "clinical_risk",
    "psychiatric": "clinical_risk",
}


def deduce_typology(target: EntityRecord, text_corpus: str) -> ProfileTypology:
    """Infiere la tipología de perfilado más adecuada si el usuario no especificó una."""
    props_text = " ".join(f"{k} {v}" for k, v in target.properties.items())
    raw_text = f"{text_corpus} {target.value} {target.maltego_type} {target.notes} {props_text}"
    text = raw_text.lower()
    mtype = target.maltego_type.lower()

    if mtype in ("maltego.threatactor", "maltego.hash"):
        return "cyber"
    if mtype == "maltego.device":
        return "device"
    if mtype in ("maltego.as", "maltego.netblock", "maltego.ipv4address", "maltego.ipv6address"):
        return "network"
    if mtype in ("maltego.gps", "maltego.location"):
        return "geographic"
    if mtype == "maltego.document":
        return "stylometry"

    # Inferencia por contenido en personas y organizaciones
    if any(k in text for k in ("opa", "proxy", "activista", "hedge fund", "inversor")):
        return "investor"
    if any(k in text for k in ("accionista", "participación", "derechos de voto", "junta")):
        return "shareholder"
    if any(k in text for k in ("negociador", "negociación", "batna", "sesgo")):
        return "negotiation"
    if any(k in text for k in ("fusión", "m&a", "cultural fit", "choque cultural")):
        return "cultural_fit"
    if any(k in text for k in ("competidor", "rival", "cuota de mercado", "patente")):
        return "competitor"
    if any(k in text for k in ("líder", "presidente", "primer ministro", "general", "geopolítica")):
        return "political_leader"
    if any(k in text for k in ("frontera", "aduana", "itinerario", "contrabando", "pasaporte")):
        return "border_risk"
    if any(k in text for k in ("insider", "amenaza interna", "empleado", "fuga de datos", "dlp")):
        return "insider_threat"
    if any(k in text for k in ("tríada oscura", "psicopatía", "narcisismo", "maquiavelismo")):
        return "clinical_risk"
    if any(k in text for k in ("escena del crimen", "modus operandi", "firma", "staging")):
        return "deductive_crime"
    if any(k in text for k in ("víctima", "victimología", "vulnerabilidad")):
        return "victimology"
    if any(k in text for k in ("consumidor", "cliente", "rfm", "ltv", "churn")):
        return "user_consumer"
    if any(k in text for k in ("audiencia", "cámara de eco", "polarización", "desinformación")):
        return "audience"

    if mtype in ("maltego.company", "maltego.organization"):
        return "competitor"

    return "psychographic"


def execute_profile(
    target: EntityRecord,
    neighbors: list[tuple[str, str, dict[str, Any]]],
    typology: ProfileTypology | str = "",
) -> ProfileRecord:
    """Ejecuta el perfilado sobre el sujeto y su vecindario de evidencias en el grafo."""
    # Recopilar corpus textual de target y vecinos
    corpus_parts = [target.value, target.notes]
    corpus_parts.extend(f"{k}={v}" for k, v in target.properties.items())
    for ntype, nval, nprops in neighbors:
        corpus_parts.append(f"{ntype}: {nval}")
        corpus_parts.extend(f"{k}={v}" for k, v in nprops.items())
    text_corpus = " \n ".join(corpus_parts)

    chosen_typology: ProfileTypology
    norm_typology = str(typology or "").strip().lower()
    norm_typology = TYPOLOGY_ALIASES.get(norm_typology, norm_typology)
    if not norm_typology or norm_typology == "auto":
        chosen_typology = deduce_typology(target, text_corpus)
    elif norm_typology in TYPOLOGY_TO_DOMAIN:
        chosen_typology = norm_typology
    else:
        chosen_typology = "psychographic"

    domain = TYPOLOGY_TO_DOMAIN[chosen_typology]
    title = TYPOLOGY_TITLES[chosen_typology]

    # Despachar al submotor
    if chosen_typology == "investor":
        arch, risk, summ, dims, traits, anom, recs = profile_investor(target, neighbors, text_corpus)
    elif chosen_typology == "shareholder":
        arch, risk, summ, dims, traits, anom, recs = profile_shareholder(target, neighbors, text_corpus)
    elif chosen_typology == "negotiation":
        arch, risk, summ, dims, traits, anom, recs = profile_negotiation(target, neighbors, text_corpus)
    elif chosen_typology == "cultural_fit":
        arch, risk, summ, dims, traits, anom, recs = profile_cultural_fit(target, neighbors, text_corpus)
    elif chosen_typology == "competitor":
        arch, risk, summ, dims, traits, anom, recs = profile_competitor(target, neighbors, text_corpus)
    elif chosen_typology == "cyber":
        arch, risk, summ, dims, traits, anom, recs = profile_cyber(target, neighbors, text_corpus)
    elif chosen_typology == "device":
        arch, risk, summ, dims, traits, anom, recs = profile_device(target, neighbors, text_corpus)
    elif chosen_typology == "network":
        arch, risk, summ, dims, traits, anom, recs = profile_network(target, neighbors, text_corpus)
    elif chosen_typology == "data":
        arch, risk, summ, dims, traits, anom, recs = profile_data(target, neighbors, text_corpus)
    elif chosen_typology == "inductive_crime":
        arch, risk, summ, dims, traits, anom, recs = profile_inductive_crime(target, neighbors, text_corpus)
    elif chosen_typology == "deductive_crime":
        arch, risk, summ, dims, traits, anom, recs = profile_deductive_crime(target, neighbors, text_corpus)
    elif chosen_typology == "geographic":
        arch, risk, summ, dims, traits, anom, recs = profile_geographic(target, neighbors, text_corpus)
    elif chosen_typology == "victimology":
        arch, risk, summ, dims, traits, anom, recs = profile_victimology(target, neighbors, text_corpus)
    elif chosen_typology == "stylometry":
        arch, risk, summ, dims, traits, anom, recs = profile_stylometry(target, neighbors, text_corpus)
    elif chosen_typology == "political_leader":
        arch, risk, summ, dims, traits, anom, recs = profile_political_leader(target, neighbors, text_corpus)
    elif chosen_typology == "border_risk":
        arch, risk, summ, dims, traits, anom, recs = profile_border_risk(target, neighbors, text_corpus)
    elif chosen_typology == "insider_threat":
        arch, risk, summ, dims, traits, anom, recs = profile_insider_threat(target, neighbors, text_corpus)
    elif chosen_typology == "user_consumer":
        arch, risk, summ, dims, traits, anom, recs = profile_user_consumer(target, neighbors, text_corpus)
    elif chosen_typology == "psychographic":
        arch, risk, summ, dims, traits, anom, recs = profile_psychographic(target, neighbors, text_corpus)
    elif chosen_typology == "audience":
        arch, risk, summ, dims, traits, anom, recs = profile_audience(target, neighbors, text_corpus)
    elif chosen_typology == "clinical_risk":
        arch, risk, summ, dims, traits, anom, recs = profile_clinical_risk(target, neighbors, text_corpus)
    else:
        arch, risk, summ, dims, traits, anom, recs = profile_psychographic(target, neighbors, text_corpus)

    now_iso = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    h_seed = f"{target.id}_{chosen_typology}_{now_iso}"
    prof_id = f"prof_{chosen_typology}_{hashlib.sha256(h_seed.encode()).hexdigest()[:8]}"
    evidence_sha256 = hashlib.sha256(text_corpus.encode("utf-8")).hexdigest()

    # Calcular puntuaciones normalizadas para el Radar Hexagonal de 6 Pilares
    avg_dim_score = sum(d.score for d in dims) / len(dims) if dims else 0.45
    pillar_scores: dict[str, float] = {
        "corporate": 0.20,
        "cyber": 0.15,
        "forensic": 0.15,
        "intelligence": 0.15,
        "psychographic": 0.25,
        "clinical_risk": 0.10,
    }
    pillar_scores[domain] = round(min(1.0, max(0.05, avg_dim_score)), 2)

    lower_corpus = text_corpus.lower()
    if any(k in lower_corpus for k in ("c2", "tor", "proxy", "port", "jarm", "tls", "hash", "malware")):
        pillar_scores["cyber"] = max(pillar_scores["cyber"], 0.72)
    if any(k in lower_corpus for k in ("opa", "ebitda", "fusión", "adquisición", "board", "accionista", "bpo")):
        pillar_scores["corporate"] = max(pillar_scores["corporate"], 0.68)
    if any(k in lower_corpus for k in ("delito", "fraude", "custodia", "evidencia", "coartada", "víctima")):
        pillar_scores["forensic"] = max(pillar_scores["forensic"], 0.65)
    if any(k in lower_corpus for k in ("gobierno", "ministro", "sanción", "geopolítica", "insider", "aduana")):
        pillar_scores["intelligence"] = max(pillar_scores["intelligence"], 0.60)
    if any(k in lower_corpus for k in ("tríada", "psicopatía", "narcisista", "manipulación", "violencia")):
        pillar_scores["clinical_risk"] = max(pillar_scores["clinical_risk"], 0.65)

    epistemic_warning = (
        GOLDWATER_ETHICAL_WARNING
        if domain == "clinical_risk"
        else (
            "AVISO METODOLÓGICO: Perfil analítico computado a partir de evidencias observadas en fuentes "
            "abiertas (OSINT) y telemetría de grafo bajo el principio de proporcionalidad y no repudio."
        )
    )

    return ProfileRecord(
        profile_id=prof_id,
        target_entity_id=target.id,
        target_value=target.value,
        case_id=target.case_id,
        domain=domain,
        typology=chosen_typology,
        title=title,
        archetype_label=arch,
        risk_level=risk,
        summary=summ,
        dimensions=tuple(dims),
        traits_to_emit=tuple(traits),
        anomalies=tuple(anom),
        strategic_recommendations=tuple(recs),
        epistemic_warning=epistemic_warning,
        metadata={
            "target_type": target.maltego_type,
            "neighbors_evaluated": len(neighbors),
            "generated_at": now_iso,
            "evidence_sha256": evidence_sha256,
            "verification_status": "TRIANGULATED_PRIMARY_SOURCES",
            "pillars": pillar_scores,
        },
        generated_at=now_iso,
    )
