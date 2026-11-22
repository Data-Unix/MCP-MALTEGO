"""Ontología y modelos de datos para el módulo unificado de perfilado (profiling).

Cubre 21 tipologías de perfilado organizadas en 6 pilares operativos:
1. Corporativo, Financiero y M&A
2. Técnico, Cibernético y Telemetría CTI
3. Criminológico y Forense
4. Inteligencia, Seguridad Nacional y Amenazas Internas
5. Social, Psicográfico y Audiencias
6. Clínico y Psiquiátrico Forense
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

ProfilingDomain = Literal[
    "corporate",
    "cyber",
    "forensic",
    "intelligence",
    "psychographic",
    "clinical_risk",
]

ProfileTypology = Literal[
    "investor",
    "shareholder",
    "negotiation",
    "cultural_fit",
    "competitor",
    "cyber",
    "device",
    "network",
    "data",
    "inductive_crime",
    "deductive_crime",
    "geographic",
    "victimology",
    "stylometry",
    "political_leader",
    "border_risk",
    "insider_threat",
    "user_consumer",
    "psychographic",
    "audience",
    "clinical_risk",
]

RiskLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]

TYPOLOGY_TO_DOMAIN: dict[ProfileTypology, ProfilingDomain] = {
    "investor": "corporate",
    "shareholder": "corporate",
    "negotiation": "corporate",
    "cultural_fit": "corporate",
    "competitor": "corporate",
    "cyber": "cyber",
    "device": "cyber",
    "network": "cyber",
    "data": "cyber",
    "inductive_crime": "forensic",
    "deductive_crime": "forensic",
    "geographic": "forensic",
    "victimology": "forensic",
    "stylometry": "forensic",
    "political_leader": "intelligence",
    "border_risk": "intelligence",
    "insider_threat": "intelligence",
    "user_consumer": "psychographic",
    "psychographic": "psychographic",
    "audience": "psychographic",
    "clinical_risk": "clinical_risk",
}

TYPOLOGY_TITLES: dict[ProfileTypology, str] = {
    "investor": "Perfilado de Inversores Activistas / Atacantes",
    "shareholder": "Perfilado de Accionistas Clave",
    "negotiation": "Perfilado de Negociación Estratégica",
    "cultural_fit": "Perfilado de Idoneidad Cultural (Cultural Fit M&A)",
    "competitor": "Perfilado de Competidores (Competitor Profiling)",
    "cyber": "Perfilado Cibernético y Atribución (Cyber Profiling)",
    "device": "Perfilado de Dispositivos y Huella Digital (Device Fingerprinting)",
    "network": "Perfilado de Redes y Línea Base de Tráfico (Network Profiling)",
    "data": "Perfilado de Datos e Integridad Forense (Data Profiling)",
    "inductive_crime": "Perfilación Criminal Inductiva (Actuarial / Estadística)",
    "deductive_crime": "Perfilación Criminal Deductiva (BEA / MO vs Firma)",
    "geographic": "Perfilado Geográfico (Modelo CGT Rossmo / Canter)",
    "victimology": "Perfilado de la Víctima (Victimología Forense)",
    "stylometry": "Lingüística Forense y Perfilado Estilométrico (Burrows Delta)",
    "political_leader": "Perfilado Político de Líderes Extranjeros (LTA / OpCode)",
    "border_risk": "Perfilado de Riesgo Fronterizo y Aduanero",
    "insider_threat": "Perfilado de Amenaza Interna (CERT Critical Pathway)",
    "user_consumer": "Perfilado de Consumidor / Usuario (Matriz RFM)",
    "psychographic": "Perfilado Psicográfico (OCEAN / Big Five Kosinski)",
    "audience": "Perfilado de Audiencia y Cámaras de Eco (Audience Profiling)",
    "clinical_risk": "Perfilado Clínico / Psiquiátrico Forense (Tríada Oscura / HCR-20)",
}

GOLDWATER_ETHICAL_WARNING = (
    "AVISO LEGAL Y DEONTOLÓGICO: Conforme al principio de rigor pericial y salvaguarda de no repudio "
    "(Regla Goldwater), este análisis no constituye un diagnóstico médico o psiquiátrico formal. "
    "Todos los hallazgos representan indicadores forenses de riesgo conductual e inferencias analíticas "
    "contrastadas exclusivamente sobre evidencias y fuentes abiertas disponibles en el expediente."
)


@dataclass(frozen=True, slots=True)
class ProfileDimension:
    name: str
    score: float
    confidence: float
    epistemic_status: str
    evidence_entities: tuple[str, ...] = ()
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ProfilingTraitNode:
    maltego_type: str
    value: str
    edge_label: str
    properties: dict[str, str] = field(default_factory=dict)
    visual_color: str = "#818cf8"
    visual_weight: int = 70

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ProfileRecord:
    profile_id: str
    target_entity_id: str
    target_value: str
    case_id: str
    domain: ProfilingDomain
    typology: ProfileTypology
    title: str
    archetype_label: str
    risk_level: RiskLevel
    summary: str
    dimensions: tuple[ProfileDimension, ...]
    traits_to_emit: tuple[ProfilingTraitNode, ...]
    anomalies: tuple[str, ...]
    strategic_recommendations: tuple[str, ...]
    epistemic_warning: str
    metadata: dict[str, Any] = field(default_factory=dict)
    generated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["pillars"] = self.metadata.get("pillars", {})
        data["evidence_sha256"] = self.metadata.get("evidence_sha256", "")
        data["verification_status"] = self.metadata.get("verification_status", "TRIANGULATED_PRIMARY_SOURCES")
        return data
