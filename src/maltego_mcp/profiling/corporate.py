"""Submotor de perfilado Corporativo, Financiero y de M&A.

Tipologías cubiertas:
- investor: Inversores Activistas / Atacantes
- shareholder: Accionistas Clave
- negotiation: Negociación Estratégica
- cultural_fit: Idoneidad Cultural (Cultural Fit)
- competitor: Competidores (Competitor Profiling)
"""

from __future__ import annotations

from typing import Any

from maltego_mcp.domain.profiling import (
    ProfileDimension,
    ProfilingTraitNode,
    RiskLevel,
)
from maltego_mcp.domain.records import EntityRecord


def profile_investor(
    target: EntityRecord,
    neighbors: list[tuple[str, str, dict[str, Any]]],
    text_corpus: str,
) -> tuple[str, RiskLevel, str, list[ProfileDimension], list[ProfilingTraitNode], list[str], list[str]]:
    text = text_corpus.lower()

    # 1. Medir agresividad mediática y campañas históricas
    hostile_terms = ("hostil", "opa", "proxy", "carta", "demanda", "activista", "destitución", "hedge fund", "short")
    hostile_matches = [t for t in hostile_terms if t in text]
    media_aggression = min(1.0, 0.2 + 0.15 * len(hostile_matches))

    # 2. Capacidad de fuego y límites de apalancamiento
    has_high_aum = any(k in text for k in ("aum", "millones", "billones", "fondo soberano", "liquidez", "capital"))
    capital_strength = 0.85 if has_high_aum else 0.55

    # 3. Holding horizon y estrategia de salida
    quick_exit = any(
        k in text for k in ("troceo", "liquidación", "desmantelamiento", "greenmail", "corto plazo", "desinversión")
    )
    exit_speed = 0.80 if quick_exit else 0.40

    risk: RiskLevel = (
        "CRITICAL" if media_aggression > 0.7 or quick_exit else "HIGH" if media_aggression > 0.4 else "MEDIUM"
    )
    archetype = "Inversor Activista Agresivo (Proxy Fighter)" if quick_exit else "Fondo Táctico de Presión de Consejo"

    dimensions = [
        ProfileDimension(
            name="Agresividad Mediática y Litigiosa",
            score=round(media_aggression, 2),
            confidence=0.85,
            epistemic_status="inference",
            evidence_entities=tuple(n[1] for n in neighbors[:4]),
            notes=f"Evidencia de términos hostiles observados: {', '.join(hostile_matches) or 'Ninguno explícito'}",
        ),
        ProfileDimension(
            name="Potencia de Fuego Financiera (AUM / Liquidez)",
            score=round(capital_strength, 2),
            confidence=0.75,
            epistemic_status="inference",
            notes="Capacidad estimada de adquisición de paquetes accionariales significativos.",
        ),
        ProfileDimension(
            name="Urgencia de Salida / Horizonte de Tenencia",
            score=round(exit_speed, 2),
            confidence=0.80,
            epistemic_status="inference",
            notes="Propensión a desinversión acelerada mediante plusvalía forzada o troceo de filiales.",
        ),
    ]

    traits = [
        ProfilingTraitNode(
            maltego_type="maltego.Phrase",
            value=f"Perfil Inversor: {archetype}",
            edge_label="Classified_As_Investor_Archetype",
            properties={"profiling.archetype": archetype, "profiling.aggression": str(round(media_aggression, 2))},
            visual_color="#e11d48" if risk in ("CRITICAL", "HIGH") else "#f59e0b",
            visual_weight=85,
        ),
        ProfilingTraitNode(
            maltego_type="maltego.Phrase",
            value=(
                "Estrategia Prevista: "
                f"{'Desmantelamiento/Venta Rápida' if quick_exit else 'Reforma de Consejo y Dividendos'}"
            ),
            edge_label="Anticipated_Exit_Strategy",
            properties={"profiling.strategy": "hostile_takeover" if quick_exit else "board_pressure"},
            visual_color="#00f5ff",
            visual_weight=75,
        ),
    ]

    anomalies = []
    if media_aggression > 0.6 and capital_strength < 0.5:
        anomalies.append(
            "Asimetría: Alta agresividad mediática con capital propio limitado (posible campaña sindicada opaca)."
        )

    recs = [
        "Monitorear declaraciones de participaciones significativas (13D / Formulario CNMV) con antelación.",
        "Reforzar el poison pill y el diálogo proactivo con inversores institucionales neutrales.",
        "Auditar pactos parasociales y sindicaciones de voto del núcleo duro de accionistas.",
    ]
    exit_desc = "inmediato/agresivo" if quick_exit else "estratégico medio"
    summary = (
        f"El sujeto {target.value} presenta un perfil de '{archetype}' con índice de agresividad "
        f"del {media_aggression * 100:.1f} % y horizonte de desinversión {exit_desc}."
    )
    return archetype, risk, summary, dimensions, traits, anomalies, recs


def profile_shareholder(
    target: EntityRecord,
    neighbors: list[tuple[str, str, dict[str, Any]]],
    text_corpus: str,
) -> tuple[str, RiskLevel, str, list[ProfileDimension], list[ProfilingTraitNode], list[str], list[str]]:
    text = text_corpus.lower()

    # Lealtad institucional vs propensión a venta
    debt_terms = ("deuda", "pago", "herencia", "sucesión", "embargo", "necesidad", "liquidez", "divorcio")
    debt_detected = any(k in text for k in debt_terms)

    loyal_terms = ("fundador", "familia", "histórico", "compromiso", "permanencia", "presidente", "fiel")
    loyalty_score = 0.85 if any(k in text for k in loyal_terms) else 0.40
    liquidity_vulnerability = 0.85 if debt_detected else 0.30

    risk: RiskLevel = "HIGH" if liquidity_vulnerability > 0.70 else "MEDIUM"
    archetype = (
        "Accionista Vulnerable a Oferta en Efectivo"
        if liquidity_vulnerability > 0.6
        else "Accionista Núcleo Duro / Leal"
    )

    dimensions = [
        ProfileDimension(
            name="Coeficiente de Lealtad al Equipo Gestor",
            score=round(loyalty_score, 2),
            confidence=0.80,
            epistemic_status="inference",
            notes="Alineación histórica con las propuestas del Consejo de Administración.",
        ),
        ProfileDimension(
            name="Sensibilidad al Precio y Vulnerabilidad de Liquidez",
            score=round(liquidity_vulnerability, 2),
            confidence=0.75,
            epistemic_status="inference",
            notes="Indicio de compromisos financieros o sucesorios que propician la aceptación de primas en efectivo.",
        ),
    ]

    traits = [
        ProfilingTraitNode(
            maltego_type="maltego.Phrase",
            value=f"Perfil Accionarial: {archetype}",
            edge_label="Classified_As_Shareholder_Archetype",
            properties={
                "profiling.loyalty": str(loyalty_score),
                "profiling.vulnerability": str(liquidity_vulnerability),
            },
            visual_color="#e11d48" if liquidity_vulnerability > 0.6 else "#10b981",
            visual_weight=80,
        )
    ]

    anomalies = []
    if debt_detected:
        anomalies.append("Alerta patrimonial: Registros revelan compromisos de pasivo o sucesión familiar inminente.")

    recs = [
        "Establecer pactos de sindicación de voto con derecho de adquisición preferente.",
        "Garantizar la política de retribución al accionista o diseñar alternativas de liquidez interna.",
    ]
    summary = (
        f"Accionista '{archetype}' con lealtad estimada en {loyalty_score * 100:.1f} % y vulnerabilidad "
        f"a ofertas en efectivo del {liquidity_vulnerability * 100:.1f} %."
    )
    return archetype, risk, summary, dimensions, traits, anomalies, recs


def profile_negotiation(
    target: EntityRecord,
    neighbors: list[tuple[str, str, dict[str, Any]]],
    text_corpus: str,
) -> tuple[str, RiskLevel, str, list[ProfileDimension], list[ProfilingTraitNode], list[str], list[str]]:
    text = text_corpus.lower()

    # Sesgos cognitivos: Aversión a la pérdida, anclaje, exceso de confianza
    loss_aversion = (
        0.85 if any(k in text for k in ("seguridad", "riesgo cero", "garantías", "penalización", "blindaje")) else 0.45
    )
    overconfidence = (
        0.80
        if any(k in text for k in ("infalible", "exclusivo", "líder indiscutible", "no negociable", "victoria"))
        else 0.40
    )
    batna_strength = (
        0.75
        if any(k in text for k in ("alternativas", "múltiples ofertas", "competidor interesado", "respaldo"))
        else 0.35
    )

    style = "Transaccional / Posicional Rígido" if overconfidence > 0.6 else "Colaborativo / Basado en Principios"
    risk: RiskLevel = "HIGH" if overconfidence > 0.7 and loss_aversion > 0.7 else "MEDIUM"

    dimensions = [
        ProfileDimension(
            name="Sesgo de Aversión a la Pérdida (Kahneman)",
            score=round(loss_aversion, 2),
            confidence=0.80,
            epistemic_status="inference",
            notes="Tendencia a sobrevalorar la protección ante contingencias frente a la ganancia futura.",
        ),
        ProfileDimension(
            name="Exceso de Confianza y Anclaje Táctico",
            score=round(overconfidence, 2),
            confidence=0.75,
            epistemic_status="inference",
            notes="Rigidez en posiciones iniciales y resistencia a ceder sin compensación simétrica.",
        ),
        ProfileDimension(
            name="Solidez Relativa de su BATNA",
            score=round(batna_strength, 2),
            confidence=0.70,
            epistemic_status="inference",
            notes="Existencia percibida de opciones viables fuera de la mesa de negociación.",
        ),
    ]

    traits = [
        ProfilingTraitNode(
            maltego_type="maltego.Phrase",
            value=f"Estilo Negociador: {style}",
            edge_label="Exhibits_Negotiation_Style",
            properties={"profiling.style": style, "profiling.batna": str(batna_strength)},
            visual_color="#a855f7",
            visual_weight=75,
        )
    ]

    anomalies = []
    if loss_aversion > 0.8:
        anomalies.append("Disparador crítico: Alta sensibilidad a penalizaciones contractuales o plazos forzados.")

    recs = [
        "Enmarcar la propuesta destacando la mitigación de riesgos y salvaguardas (framing anti-pérdida).",
        "Ofrecer concesiones simbólicas de alto valor percibido para su ego sin coste estructural.",
    ]
    batna_desc = "robusto" if batna_strength > 0.6 else "vulnerable"
    summary = (
        f"Negociador con estilo '{style}', marcado por aversión a la pérdida ({loss_aversion * 100:.0f}%) "
        f"y BATNA {batna_desc}."
    )
    return style, risk, summary, dimensions, traits, anomalies, recs


def profile_cultural_fit(
    target: EntityRecord,
    neighbors: list[tuple[str, str, dict[str, Any]]],
    text_corpus: str,
) -> tuple[str, RiskLevel, str, list[ProfileDimension], list[ProfilingTraitNode], list[str], list[str]]:
    text = text_corpus.lower()

    # Fricción de gobernanza y rotación
    turnover_terms = ("rotación", "fuga", "huelga", "descontento", "baja", "sindicato", "conflicto laboral")
    turnover_risk = 0.80 if any(k in text for k in turnover_terms) else 0.35

    hierarchical = any(k in text for k in ("militar", "vertical", "estricto", "autoritario", "control centralizado"))
    friction_index = min(1.0, 0.3 + (0.3 if turnover_risk > 0.5 else 0.0) + (0.3 if hierarchical else 0.0))

    risk: RiskLevel = "HIGH" if friction_index > 0.65 else "MEDIUM" if friction_index > 0.4 else "LOW"
    archetype = "Cultura Vertical / Alto Riesgo de Fricción M&A" if hierarchical else "Cultura Orgánica / Integrable"

    dimensions = [
        ProfileDimension(
            name="Índice de Fricción Cultural Post-Fusión",
            score=round(friction_index, 2),
            confidence=0.75,
            epistemic_status="inference",
            notes="Estimación de choque entre estilos directivos y normativas operativas.",
        ),
        ProfileDimension(
            name="Riesgo de Fuga de Talento Clave (Brain Drain)",
            score=round(turnover_risk, 2),
            confidence=0.70,
            epistemic_status="inference",
            notes="Vulnerabilidad de pérdida de mandos medios técnicos y comerciales tras la compra.",
        ),
    ]

    traits = [
        ProfilingTraitNode(
            maltego_type="maltego.Phrase",
            value=f"Cultura Organizacional: {archetype}",
            edge_label="Characterized_By_Cultural_Model",
            properties={"profiling.friction_index": str(friction_index)},
            visual_color="#f59e0b" if risk == "HIGH" else "#10b981",
            visual_weight=70,
        )
    ]

    anomalies = []
    if turnover_risk > 0.7:
        anomalies.append(
            "Alerta de retención: Se detectan precedentes de descontento sindical o rotación en mandos clave."
        )

    recs = [
        "Planificar paquetes de retención (golden handcuffs) para el 20 % superior de especialistas clave.",
        "Establecer un comité paritario de integración cultural durante los primeros 100 días de la transacción.",
    ]
    summary = (
        f"Entidad evaluada con índice de fricción cultural del {friction_index * 100:.1f} % y perfil '{archetype}'."
    )
    return archetype, risk, summary, dimensions, traits, anomalies, recs


def profile_competitor(
    target: EntityRecord,
    neighbors: list[tuple[str, str, dict[str, Any]]],
    text_corpus: str,
) -> tuple[str, RiskLevel, str, list[ProfileDimension], list[ProfilingTraitNode], list[str], list[str]]:
    text = text_corpus.lower()

    # Agilidad vs Rigidez operativa
    agile_terms = ("patente", "innovación", "rápido", "expansión", "saas", "disrupción", "cloud")
    agility_score = 0.85 if sum(1 for t in agile_terms if t in text) >= 2 else 0.45

    cost_rigidity = (
        0.75
        if any(k in text for k in ("fábrica", "instalación fija", "deuda alta", "costes fijos", "pesado"))
        else 0.35
    )
    threat_level: RiskLevel = "HIGH" if agility_score > 0.7 else "MEDIUM"
    archetype = "Competidor Ágil / Innovador Ofensivo" if agility_score > 0.6 else "Competidor Tradicional de Escala"

    dimensions = [
        ProfileDimension(
            name="Velocidad de Reacción en Mercado (Time-to-Market)",
            score=round(agility_score, 2),
            confidence=0.80,
            epistemic_status="inference",
            notes="Capacidad demostrada para lanzar contracampañas o desarrollos tecnológicos.",
        ),
        ProfileDimension(
            name="Rigidez Financiera y Estructura de Costes",
            score=round(cost_rigidity, 2),
            confidence=0.75,
            epistemic_status="inference",
            notes="Sensibilidad a guerras de precios prolongadas o encarecimiento del crédito.",
        ),
    ]

    traits = [
        ProfilingTraitNode(
            maltego_type="maltego.Phrase",
            value=f"Perfil Competitivo: {archetype}",
            edge_label="Classified_As_Competitor_Archetype",
            properties={"profiling.agility": str(agility_score), "profiling.rigidity": str(cost_rigidity)},
            visual_color="#e11d48" if threat_level == "HIGH" else "#00f5ff",
            visual_weight=80,
        )
    ]

    anomalies = []
    if agility_score > 0.7 and cost_rigidity < 0.4:
        anomalies.append("Amenaza asimétrica: Alta agilidad tecnológica combinada con estructura de costes liviana.")

    recs = [
        "Anticipar barreras de entrada mediante patentes en sus líneas adyacentes de I+D.",
        "Explotar sus puntos ciegos geográficos o nichos desatendidos por su modelo de negocio.",
    ]
    summary = (
        f"Competidor catalogado como '{archetype}', con agilidad de mercado del {agility_score * 100:.0f} % "
        f"y rigidez de costes del {cost_rigidity * 100:.0f} %."
    )
    return archetype, threat_level, summary, dimensions, traits, anomalies, recs
