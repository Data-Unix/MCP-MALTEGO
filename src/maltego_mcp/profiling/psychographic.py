"""Submotor de perfilado Social, Psicográfico y de Audiencias.

Tipologías cubiertas:
- user_consumer: Perfilado de Consumidor / Usuario (Matriz RFM)
- psychographic: Perfilado Psicográfico (OCEAN / Big Five Kosinski)
- audience: Perfilado de Audiencia y Cámaras de Eco (Audience Profiling)
"""

from __future__ import annotations

from typing import Any

from maltego_mcp.domain.profiling import (
    ProfileDimension,
    ProfilingTraitNode,
    RiskLevel,
)
from maltego_mcp.domain.records import EntityRecord


def profile_user_consumer(
    target: EntityRecord,
    neighbors: list[tuple[str, str, dict[str, Any]]],
    text_corpus: str,
) -> tuple[str, RiskLevel, str, list[ProfileDimension], list[ProfilingTraitNode], list[str], list[str]]:
    text = text_corpus.lower()

    # Análisis RFM (Recencia, Frecuencia, Valor Monetario)
    high_value = any(
        k in text
        for k in ("premium", "recurrente", "vip", "alto valor", "frecuente", "suscripción anual", "compra recurrente")
    )
    churn_risk = any(k in text for k in ("inactivo", "cancelación", "abandono", "reclamación", "queja", "baja"))

    ltv_score = 0.85 if high_value else 0.45
    churn_score = 0.80 if churn_risk else 0.25
    archetype = (
        "Cliente VIP de Alto Valor (High LTV)"
        if high_value
        else "Cliente Oportunista / En Riesgo de Baja"
        if churn_risk
        else "Usuario Estándar Activo"
    )
    risk: RiskLevel = "HIGH" if churn_risk and high_value else "LOW"

    dimensions = [
        ProfileDimension(
            name="Valor del Ciclo de Vida (Lifetime Value - LTV)",
            score=round(ltv_score, 2),
            confidence=0.80,
            epistemic_status="inference",
            notes="Estimación basada en volumen y frecuencia transaccional observada.",
        ),
        ProfileDimension(
            name="Riesgo de Abandono (Churn Risk)",
            score=round(churn_score, 2),
            confidence=0.75,
            epistemic_status="inference",
            notes="Tendencia a la inactividad o insatisfacción comunicada.",
        ),
    ]

    traits = [
        ProfilingTraitNode(
            maltego_type="maltego.Phrase",
            value=f"Segmento Consumidor: {archetype}",
            edge_label="Classified_Under_RFM_Segment",
            properties={"profiling.ltv": str(ltv_score), "profiling.churn": str(churn_score)},
            visual_color="#00f5ff" if high_value else "#f59e0b",
            visual_weight=75,
        )
    ]

    anomalies = []
    if high_value and churn_risk:
        anomalies.append(
            "Fuga crítica de valor: Cliente de segmento superior con indicios de insatisfacción o desvinculación."
        )

    recs = [
        "Desplegar protocolo de fidelización personalizada antes del cierre del ciclo de suscripción.",
        "Monitorear si el abandono coincide con ofertas agresivas de un competidor directo.",
    ]
    summary = (
        f"Perfil de consumidor: '{archetype}' con LTV del {ltv_score * 100:.0f} % "
        f"y riesgo de churn del {churn_score * 100:.0f} %."
    )
    return archetype, risk, summary, dimensions, traits, anomalies, recs


def profile_psychographic(
    target: EntityRecord,
    neighbors: list[tuple[str, str, dict[str, Any]]],
    text_corpus: str,
) -> tuple[str, RiskLevel, str, list[ProfileDimension], list[ProfilingTraitNode], list[str], list[str]]:
    text = text_corpus.lower()

    # Mapeo OCEAN / Big Five (Kosinski / Cambridge Analytica methodology)
    openness = (
        0.85
        if any(k in text for k in ("innovación", "arte", "filosofía", "curiosidad", "tecnología", "diseño", "ciencia"))
        else 0.45
    )
    conscientiousness = (
        0.85
        if any(k in text for k in ("organizado", "disciplina", "metódico", "riguroso", "plan", "orden", "preciso"))
        else 0.45
    )
    extraversion = (
        0.80
        if any(k in text for k in ("líder", "social", "orador", "redes", "comunidad", "amigos", "entusiasmo"))
        else 0.40
    )
    agreeableness = (
        0.80
        if any(k in text for k in ("solidario", "ayuda", "equipo", "confianza", "empático", "colaborativo"))
        else 0.35
    )
    neuroticism = (
        0.80
        if any(k in text for k in ("ansiedad", "estrés", "ira", "preocupación", "miedo", "conflicto", "inseguro"))
        else 0.30
    )

    archetype = (
        "Personalidad Analítica y Disciplinada (Alta C, Alta O)"
        if conscientiousness > 0.7 and openness > 0.7
        else "Personalidad Asertiva y Comunicativa (Alta E, Baja N)"
        if extraversion > 0.7 and neuroticism < 0.5
        else "Perfil Conductual Equilibrado"
    )
    risk: RiskLevel = "HIGH" if neuroticism > 0.7 else "LOW"

    dimensions = [
        ProfileDimension(
            name="Apertura a la Experiencia (O - Openness)",
            score=round(openness, 2),
            confidence=0.80,
            epistemic_status="inference",
            notes="Curiosidad intelectual e interés por novedades conceptuales.",
        ),
        ProfileDimension(
            name="Responsabilidad y Metodología (C - Conscientiousness)",
            score=round(conscientiousness, 2),
            confidence=0.80,
            epistemic_status="inference",
            notes="Autodisciplina, atención al detalle y perseverancia en objetivos.",
        ),
        ProfileDimension(
            name="Extraversión y Asertividad (E - Extraversion)",
            score=round(extraversion, 2),
            confidence=0.75,
            epistemic_status="inference",
            notes="Orientación hacia la acción grupal y el protagonismo social.",
        ),
        ProfileDimension(
            name="Amabilidad y Cooperación (A - Agreeableness)",
            score=round(agreeableness, 2),
            confidence=0.75,
            epistemic_status="inference",
            notes="Disposición a confiar y colaborar frente a la postura competitiva.",
        ),
        ProfileDimension(
            name="Inestabilidad Emocional / Reactividad (N - Neuroticism)",
            score=round(neuroticism, 2),
            confidence=0.80,
            epistemic_status="inference",
            notes="Sensibilidad a la frustración y respuesta al estrés prolongado.",
        ),
    ]

    p1 = f"O:{openness:.2f} C:{conscientiousness:.2f}"
    p2 = f"E:{extraversion:.2f} A:{agreeableness:.2f} N:{neuroticism:.2f}"
    ocean_str = f"{p1} {p2}"
    traits = [
        ProfilingTraitNode(
            maltego_type="humint.PsychologicalTrait",
            value=f"Perfil OCEAN: {archetype} ({ocean_str})",
            edge_label="Exhibits_Psychographic_Profile",
            properties={
                "ocean.openness": f"{openness:.2f}",
                "ocean.conscientiousness": f"{conscientiousness:.2f}",
                "ocean.extraversion": f"{extraversion:.2f}",
                "ocean.agreeableness": f"{agreeableness:.2f}",
                "ocean.neuroticism": f"{neuroticism:.2f}",
            },
            visual_color="#818cf8",
            visual_weight=80,
        )
    ]

    anomalies = []
    if neuroticism > 0.75:
        anomalies.append(
            "Vulnerabilidad reactiva: Alta probabilidad de toma de decisiones precipitada bajo presión temporal."
        )

    recs = [
        "Adaptar el encuadre comunicativo: apelar a datos y estructura lógica si Conscientiousness es alta.",
        "Evitar mensajes antagónicos directos si Neuroticism es elevado para no provocar bloqueo defensivo.",
    ]
    summary = f"Perfil psicográfico OCEAN: '{archetype}' [{ocean_str}]."
    return archetype, risk, summary, dimensions, traits, anomalies, recs


def profile_audience(
    target: EntityRecord,
    neighbors: list[tuple[str, str, dict[str, Any]]],
    text_corpus: str,
) -> tuple[str, RiskLevel, str, list[ProfileDimension], list[ProfilingTraitNode], list[str], list[str]]:
    text = text_corpus.lower()

    # Cámaras de eco y polarización
    polarized = any(
        k in text
        for k in ("polarizado", "cámara de eco", "radical", "boicot", "ataque coordinado", "bulo", "desinformación")
    )
    polarization_score = 0.85 if polarized else 0.35
    risk: RiskLevel = "HIGH" if polarized else "LOW"
    archetype = "Comunidad Cerrada / Cámara de Eco Polarizada" if polarized else "Audiencia Abierta y Multidireccional"

    dimensions = [
        ProfileDimension(
            name="Índice de Polarización y Resonancia de Grupo",
            score=round(polarization_score, 2),
            confidence=0.80,
            epistemic_status="inference",
            notes="Tendencia a amplificar narrativas homogéneas y rechazo de discursos contrarios.",
        )
    ]

    traits = [
        ProfilingTraitNode(
            maltego_type="maltego.Phrase",
            value=f"Estructura de Audiencia: {archetype}",
            edge_label="Forms_Audience_Cluster",
            properties={"profiling.polarization": str(polarization_score)},
            visual_color="#f59e0b" if polarized else "#10b981",
            visual_weight=75,
        )
    ]

    anomalies = []
    if polarized:
        anomalies.append(
            "Riesgo de astroturfing: Elevado volumen de réplicas sincrónicas compatible con amplificación coordinada."
        )

    recs = [
        "Identificar nodos puente (intermediación de Betweenness) que conecten la comunidad con redes externas.",
        "Diseñar contranarrativas neutras basadas en hechos contrastados para reducir la resonancia afectiva.",
    ]
    summary = f"Perfil de audiencia: '{archetype}' con índice de polarización del {polarization_score * 100:.0f} %."
    return archetype, risk, summary, dimensions, traits, anomalies, recs
