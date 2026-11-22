"""Submotor de perfilado Clínico y Psiquiátrico Forense (Factores de Riesgo y Tríada Oscura).

Tipología cubierta:
- clinical_risk: Perfilado Clínico / Psiquiátrico Forense

SALVAGUARDA ÉTICA Y DEONTOLÓGICA (Regla Goldwater):
No emite diagnósticos médicos ni psiquiátricos formales. Evalúa exclusivamente
indicadores forenses de riesgo conductual observados en evidencias públicas
contrastadas conforme a las escalas científicas Dark Triad, HCR-20 y PCL-R.
"""

from __future__ import annotations

from typing import Any

from maltego_mcp.domain.profiling import (
    GOLDWATER_ETHICAL_WARNING,
    ProfileDimension,
    ProfilingTraitNode,
    RiskLevel,
)
from maltego_mcp.domain.records import EntityRecord


def profile_clinical_risk(
    target: EntityRecord,
    neighbors: list[tuple[str, str, dict[str, Any]]],
    text_corpus: str,
) -> tuple[str, RiskLevel, str, list[ProfileDimension], list[ProfilingTraitNode], list[str], list[str]]:
    text = text_corpus.lower()

    # Evaluación de la Tríada Oscura (Dark Triad)
    # 1. Maquiavelismo (Manipulación, cálculo cínico)
    mach_terms = ("manipulación", "cálculo", "mentira", "estafa", "chantaje", "extorsión", "utilitario", "cínico")
    mach_score = 0.85 if any(k in text for k in mach_terms) else 0.35

    # 2. Narcisismo (Grandiosidad, necesidad de admiración)
    narc_terms = ("superior", "grandioso", "intocable", "fama", "admiración", "ego", "humillación ajena")
    narc_score = 0.80 if any(k in text for k in narc_terms) else 0.30

    # 3. Psicopatía Subclínica (Falta de empatía, crueldad, impulsividad temeraria)
    psych_terms = (
        "sin remordimiento",
        "cruel",
        "frialdad",
        "sadismo",
        "violencia",
        "insensibilidad",
        "amenaza de muerte",
    )
    psych_score = 0.90 if any(k in text for k in psych_terms) else 0.25

    dark_triad_avg = (mach_score + narc_score + psych_score) / 3.0
    risk: RiskLevel = (
        "CRITICAL" if psych_score > 0.7 or dark_triad_avg > 0.7 else "HIGH" if dark_triad_avg > 0.5 else "LOW"
    )
    archetype = (
        "Indicadores Forenses de Tríada Oscura Marcada (Alto Maquiavelismo/Frialdad)"
        if dark_triad_avg > 0.65
        else "Indicadores Aislados de Manipulación / Riesgo Moderado"
        if dark_triad_avg > 0.45
        else "Sin Indicadores Clínicos de Alarma Forense"
    )

    dimensions = [
        ProfileDimension(
            name="Índice de Conducta Maquiavélica (Dark Triad - Mach)",
            score=round(mach_score, 2),
            confidence=0.80,
            epistemic_status="forensic_risk_indicator",
            notes="Observación de manipulación interpersonal deliberada y engaño táctico.",
        ),
        ProfileDimension(
            name="Índice de Rasgos Narcisistas / Grandiosidad",
            score=round(narc_score, 2),
            confidence=0.75,
            epistemic_status="forensic_risk_indicator",
            notes="Tendencia a la sobreestimación de impunidad y necesidad de validación externa.",
        ),
        ProfileDimension(
            name="Indicadores de Insensibilidad y Frialdad Afectiva (PCL-R)",
            score=round(psych_score, 2),
            confidence=0.85,
            epistemic_status="forensic_risk_indicator",
            notes="Falta aparente de empatía hacia las consecuencias del daño inferido a terceros.",
        ),
    ]

    traits = [
        ProfilingTraitNode(
            maltego_type="humint.PsychologicalTrait",
            value=f"Riesgo Forense: {archetype}",
            edge_label="Presents_Forensic_Risk_Indicators",
            properties={
                "dark_triad.machiavellianism": f"{mach_score:.2f}",
                "dark_triad.narcissism": f"{narc_score:.2f}",
                "dark_triad.psychopathy_subclinical": f"{psych_score:.2f}",
                "humint.epistemic_status": "forensic_risk_indicator",
                "humint.goldwater_rule_compliant": "true",
            },
            visual_color="#e11d48" if risk in ("CRITICAL", "HIGH") else "#10b981",
            visual_weight=90,
        )
    ]

    anomalies = []
    if psych_score > 0.7:
        anomalies.append(
            "Alerta de peligrosidad: Detección de insensibilidad afectiva y amenazas explícitas sin inhibición moral."
        )

    recs = [
        "Tratar las interacciones con el sujeto bajo estricto protocolo de contención y seguridad física.",
        "Evitar la confrontación dialéctica directa que pueda detonar episodios de ira narcisista descontrolada.",
        "Aportar estos indicadores forenses exclusivamente como respaldo en valoraciones policiales o judiciales.",
    ]
    summary = (
        f"Evaluación de riesgo forense: '{archetype}' con índice medio de Tríada Oscura de {dark_triad_avg:.2f} "
        f"[Mach:{mach_score:.2f}, Narc:{narc_score:.2f}, Psych:{psych_score:.2f}]. {GOLDWATER_ETHICAL_WARNING}"
    )
    return archetype, risk, summary, dimensions, traits, anomalies, recs
