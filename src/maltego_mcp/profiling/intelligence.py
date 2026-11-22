"""Submotor de perfilado de Inteligencia, Seguridad Nacional y Amenazas Internas.

Tipologías cubiertas:
- political_leader: Perfilado Político de Líderes Extranjeros (LTA / Operational Code)
- border_risk: Perfilado de Riesgo Fronterizo y Aduanero
- insider_threat: Perfilado de Amenaza Interna (CERT Critical Pathway)
"""

from __future__ import annotations

from typing import Any

from maltego_mcp.domain.profiling import (
    ProfileDimension,
    ProfilingTraitNode,
    RiskLevel,
)
from maltego_mcp.domain.records import EntityRecord


def profile_political_leader(
    target: EntityRecord,
    neighbors: list[tuple[str, str, dict[str, Any]]],
    text_corpus: str,
) -> tuple[str, RiskLevel, str, list[ProfileDimension], list[ProfilingTraitNode], list[str], list[str]]:
    text = text_corpus.lower()

    # Leadership Trait Analysis (Margaret Hermann) & Operational Code (Leites/George)
    power_terms = ("poder", "fuerza", "militar", "victoria", "enemigo", "control", "orden", "soberanía", "amenaza")
    coop_terms = ("paz", "acuerdo", "tratado", "diplomacia", "consenso", "diálogo", "cooperación")

    power_count = sum(1 for t in power_terms if t in text)
    coop_count = sum(1 for t in coop_terms if t in text)

    need_for_power = min(1.0, 0.4 + 0.1 * power_count)
    worldview = "Conflictivo / Hobbesiano (Suma Cero)" if power_count >= coop_count else "Cooperativo / Multilateral"
    archetype = "Líder Asertivo de Dominio / Suma Cero" if need_for_power > 0.65 else "Líder Pragmático / Negociador"
    risk: RiskLevel = "HIGH" if need_for_power > 0.7 else "MEDIUM"

    dimensions = [
        ProfileDimension(
            name="Necesidad de Poder y Control (LTA Hermann)",
            score=round(need_for_power, 2),
            confidence=0.80,
            epistemic_status="inference",
            notes="Medición cuantitativa de retórica de dominio y centralización de mando.",
        ),
        ProfileDimension(
            name="Visión Filosófica del Mundo (Operational Code)",
            score=0.85 if "Conflictivo" in worldview else 0.40,
            confidence=0.75,
            epistemic_status="inference",
            notes=f"Percepción del entorno geopolítico: {worldview}.",
        ),
    ]

    traits = [
        ProfilingTraitNode(
            maltego_type="maltego.Phrase",
            value=f"Perfil Político: {archetype}",
            edge_label="Classified_Under_LTA_Framework",
            properties={"profiling.lta_power": str(need_for_power), "profiling.worldview": worldview},
            visual_color="#e11d48" if risk == "HIGH" else "#00f5ff",
            visual_weight=85,
        ),
        ProfilingTraitNode(
            maltego_type="maltego.Phrase",
            value=f"Premisa Operacional: {worldview}",
            edge_label="Operational_Code_Premise",
            properties={"profiling.worldview": worldview},
            visual_color="#818cf8",
            visual_weight=75,
        ),
    ]

    anomalies = []
    if need_for_power > 0.75 and "Conflictivo" in worldview:
        anomalies.append(
            "Alerta de escalada: Alta reactividad hostil ante sanciones o ultimátums sin vía de escape honorable."
        )

    recs = [
        "Presentar alternativas donde el líder pueda proclamar una victoria simbólica interna.",
        "Evitar la humillación pública en foros multilaterales que detone represalias asimétricas.",
    ]
    summary = (
        f"Líder político tipificado como '{archetype}', "
        f"con necesidad de poder del {need_for_power * 100:.0f} % y visión '{worldview}'."
    )
    return archetype, risk, summary, dimensions, traits, anomalies, recs


def profile_border_risk(
    target: EntityRecord,
    neighbors: list[tuple[str, str, dict[str, Any]]],
    text_corpus: str,
) -> tuple[str, RiskLevel, str, list[ProfileDimension], list[ProfilingTraitNode], list[str], list[str]]:
    text = text_corpus.lower()

    # Itinerarios anómalos y pasaporte
    suspicious_route = any(
        k in text for k in ("triangulación", "escala sospechosa", "sin equipaje", "última hora", "efectivo", "tráfico")
    )
    sanction_match = any(k in text for k in ("sanción", "ofac", "alerta roja", "interpol", "requisitoria", "aduanas"))

    risk_score = 0.90 if sanction_match else 0.75 if suspicious_route else 0.25
    risk: RiskLevel = "CRITICAL" if sanction_match else "HIGH" if suspicious_route else "LOW"
    archetype = "Pasajero/Carga de Alto Riesgo Fronterizo" if risk_score > 0.6 else "Tránsito Transfronterizo Estándar"

    dimensions = [
        ProfileDimension(
            name="Índice de Riesgo Aduanero y Fronterizo",
            score=round(risk_score, 2),
            confidence=0.85,
            epistemic_status="fact" if sanction_match else "inference",
            notes="Evaluación no lineal de itinerarios, modalidades de pago y registros de alerta.",
        )
    ]

    traits = [
        ProfilingTraitNode(
            maltego_type="maltego.Phrase",
            value=f"Perfil Fronterizo: {archetype}",
            edge_label="Assessed_Border_Risk",
            properties={"profiling.risk_score": str(risk_score)},
            visual_color="#e11d48" if risk in ("CRITICAL", "HIGH") else "#10b981",
            visual_weight=80,
        )
    ]

    anomalies = []
    if sanction_match:
        anomalies.append(
            "Coincidencia crítica: Identificador vinculado a listas oficiales de sanciones o requisitorias."
        )

    recs = [
        "Activar inspección secundaria física de equipaje y comprobación biométrica.",
        "Verificar trazabilidad de fondos utilizados en la adquisición del pasaje.",
    ]
    summary = f"Perfil de frontera: '{archetype}' con índice de riesgo del {risk_score * 100:.0f} %."
    return archetype, risk, summary, dimensions, traits, anomalies, recs


def profile_insider_threat(
    target: EntityRecord,
    neighbors: list[tuple[str, str, dict[str, Any]]],
    text_corpus: str,
) -> tuple[str, RiskLevel, str, list[ProfileDimension], list[ProfilingTraitNode], list[str], list[str]]:
    text = text_corpus.lower()

    # Modelo The Critical Pathway to Insider Threat (CERT / CMU)
    personal_stressor = any(k in text for k in ("deuda", "adicción", "problema personal", "embargo", "divorcio"))
    work_stressor = any(
        k in text
        for k in ("despido", "degradación", "resentimiento", "queja", "evaluación negativa", "sanción laboral")
    )
    tech_violation = any(
        k in text for k in ("usb", "descarga masiva", "fuera de horario", "acceso denegado", "vpn no autorizada", "dlp")
    )

    pathway_stages = sum(1 for s in (personal_stressor, work_stressor, tech_violation) if s)
    risk_score = 0.90 if pathway_stages >= 2 else 0.65 if pathway_stages == 1 else 0.20
    risk: RiskLevel = "CRITICAL" if pathway_stages >= 2 and tech_violation else "HIGH" if pathway_stages >= 1 else "LOW"
    archetype = (
        "Amenaza Interna Activa (Etapa Crítica CERT)"
        if pathway_stages >= 2
        else "Empleado con Estresores Observados"
        if pathway_stages == 1
        else "Perfil Interno Fidedigno"
    )

    dimensions = [
        ProfileDimension(
            name="Índice de Progresión CERT (Critical Pathway)",
            score=round(risk_score, 2),
            confidence=0.85,
            epistemic_status="inference",
            notes=(
                f"Estresores personales: {personal_stressor}, laborales: {work_stressor}, "
                f"violaciones técnicas: {tech_violation}."
            ),
        )
    ]

    traits = [
        ProfilingTraitNode(
            maltego_type="maltego.Phrase",
            value=f"Amenaza Interna: {archetype}",
            edge_label="Monitored_Under_Insider_Threat_Model",
            properties={"profiling.pathway_stages": str(pathway_stages), "profiling.risk": str(risk_score)},
            visual_color="#e11d48" if risk in ("CRITICAL", "HIGH") else "#10b981",
            visual_weight=85,
        )
    ]

    anomalies = []
    if tech_violation and work_stressor:
        anomalies.append(
            "Riesgo inminente: Coincidencia de resentimiento laboral declarado con descargas masivas no autorizadas."
        )

    recs = [
        "Restringir de forma inmediata los privilegios de acceso a carpetas de I+D y repositorios estratégicos.",
        "Iniciar auditoría forense discreta de los registros de actividad en endpoints (EDR/DLP).",
    ]
    summary = (
        f"Evaluación de amenaza interna: '{archetype}' con puntuación CERT del {risk_score * 100:.0f} % "
        f"y {pathway_stages}/3 fases recorridas."
    )
    return archetype, risk, summary, dimensions, traits, anomalies, recs
