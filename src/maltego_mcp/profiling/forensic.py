"""Submotor de perfilado Criminológico y Forense.

Tipologías cubiertas:
- inductive_crime: Perfilación Criminal Inductiva
- deductive_crime: Perfilación Criminal Deductiva (BEA)
- geographic: Perfilado Geográfico (Modelo CGT Rossmo / Canter)
- victimology: Perfilado de la Víctima (Victimología Forense)
- stylometry: Lingüística Forense y Perfilado Estilométrico
"""

from __future__ import annotations

import contextlib
import math
import re
from typing import Any

from maltego_mcp.domain.profiling import (
    ProfileDimension,
    ProfilingTraitNode,
    RiskLevel,
)
from maltego_mcp.domain.records import EntityRecord


def profile_inductive_crime(
    target: EntityRecord,
    neighbors: list[tuple[str, str, dict[str, Any]]],
    text_corpus: str,
) -> tuple[str, RiskLevel, str, list[ProfileDimension], list[ProfilingTraitNode], list[str], list[str]]:
    text = text_corpus.lower()

    is_organized = any(
        k in text for k in ("planificado", "armamento", "transporte", "evasión", "vigilancia previa", "cómplice")
    )
    recidivism_terms = ("reincidente", "antecedente", "prisión", "condena", "historial", "habitual")
    has_recidivism = any(k in text for k in recidivism_terms)

    archetype = "Agresor Serial Organizado (Planificador)" if is_organized else "Agresor Desorganizado / Oportunista"
    recidivism_prob = 0.85 if has_recidivism else 0.45
    risk: RiskLevel = "CRITICAL" if recidivism_prob > 0.7 and is_organized else "HIGH"

    dimensions = [
        ProfileDimension(
            name="Tipología Criminal Estadístico-Actuarial",
            score=0.85 if is_organized else 0.40,
            confidence=0.80,
            epistemic_status="inference",
            notes=f"Clasificación inductiva según patrones del modelo FBI BSU: {archetype}.",
        ),
        ProfileDimension(
            name="Probabilidad Bayesiana de Reincidencia",
            score=round(recidivism_prob, 2),
            confidence=0.75,
            epistemic_status="inference",
            notes="Estimación actuarial calculada a partir de antecedentes y metódica de ejecución.",
        ),
    ]

    traits = [
        ProfilingTraitNode(
            maltego_type="maltego.Phrase",
            value=f"Tipología Inductiva: {archetype}",
            edge_label="Matches_Actuarial_Typology",
            properties={"profiling.typology": archetype, "profiling.recidivism": str(recidivism_prob)},
            visual_color="#e11d48" if risk == "CRITICAL" else "#f59e0b",
            visual_weight=85,
        )
    ]

    anomalies = []
    if is_organized and has_recidivism:
        anomalies.append(
            "Riesgo inminente: Agresor organizado con alta probabilidad estadística de continuidad delictiva."
        )

    recs = [
        "Cribar bases de datos policiales de agresores con modus operandi coincidente.",
        "Cruzar franjas horarias y días de la semana con detenciones pasadas en el radio operativo.",
    ]
    summary = (
        f"Perfil inductivo categorizado como '{archetype}', "
        f"con probabilidad actuarial de reincidencia del {recidivism_prob * 100:.0f} %."
    )
    return archetype, risk, summary, dimensions, traits, anomalies, recs


def profile_deductive_crime(
    target: EntityRecord,
    neighbors: list[tuple[str, str, dict[str, Any]]],
    text_corpus: str,
) -> tuple[str, RiskLevel, str, list[ProfileDimension], list[ProfilingTraitNode], list[str], list[str]]:
    text = text_corpus.lower()

    # Diferenciación entre MO, Firma y Escenificación (Staging)
    has_staging = any(
        k in text for k in ("escenificación", "staging", "manipulado", "falso móvil", "alterada", "simulación")
    )
    has_signature = any(
        k in text for k in ("firma", "fetiche", "ritual", "mensaje", "innecesario", "fantasía", "ensañamiento")
    )

    risk: RiskLevel = "CRITICAL" if has_signature or has_staging else "HIGH"
    archetype = (
        "Autor con Firma Psicológica Específica" if has_signature else "Autor Instrumental / Funcional (Solo MO)"
    )

    dimensions = [
        ProfileDimension(
            name="Diferenciación Modus Operandi vs Firma (BEA)",
            score=0.90 if has_signature else 0.35,
            confidence=0.85,
            epistemic_status="fact" if has_signature else "inference",
            notes="Detección de conductas no requeridas funcionalmente que satisfacen necesidades psicológicas.",
        ),
        ProfileDimension(
            name="Índice de Escenificación (Staging / Coartada)",
            score=0.85 if has_staging else 0.15,
            confidence=0.80,
            epistemic_status="inference",
            notes="Indicios de alteración forense de la escena para desviar la investigación.",
        ),
    ]

    traits = [
        ProfilingTraitNode(
            maltego_type="maltego.Phrase",
            value=f"Análisis Deductivo: {archetype}",
            edge_label="Reconstructed_Via_BEA",
            properties={"profiling.signature_present": str(has_signature), "profiling.staging": str(has_staging)},
            visual_color="#e11d48",
            visual_weight=90,
        )
    ]

    anomalies = []
    if has_staging:
        anomalies.append(
            "Alerta pericial: Se observan contradicciones en la escena compatibles con escenificación deliberada."
        )

    recs = [
        "Aislar la firma psicológica del modus operandi para no descartar incidentes donde el método haya variado.",
        "Verificar la relación íntima entre víctima y sospechosos (el staging suele indicar vínculo previo).",
    ]
    sig_desc = "confirmada" if has_signature else "no evidente"
    staging_desc = "detectada" if has_staging else "descartada"
    summary = f"Reconstrucción deductiva (BEA): '{archetype}' con firma {sig_desc} y escenificación {staging_desc}."
    return archetype, risk, summary, dimensions, traits, anomalies, recs


def profile_geographic(
    target: EntityRecord,
    neighbors: list[tuple[str, str, dict[str, Any]]],
    text_corpus: str,
) -> tuple[str, RiskLevel, str, list[ProfileDimension], list[ProfilingTraitNode], list[str], list[str]]:
    # 1. Extracción de coordenadas de los vecinos (Locations o GPS)
    coords: list[tuple[float, float]] = []
    coord_re = re.compile(r"([-+]?\d{1,2}\.\d+)[,\s]+([-+]?\d{1,3}\.\d+)")

    for _ntype, nval, nprops in neighbors:
        m = (
            coord_re.search(nval)
            or coord_re.search(nprops.get("gps.coordinate", ""))
            or coord_re.search(nprops.get("latitude", "") + " " + nprops.get("longitude", ""))
        )
        if m:
            with contextlib.suppress(ValueError):
                coords.append((float(m.group(1)), float(m.group(2))))

    # Si no hay coordenadas explícitas, usar coordenadas de referencia de la entidad
    m_target = coord_re.search(target.value) or coord_re.search(target.properties.get("gps.coordinate", ""))
    if m_target:
        with contextlib.suppress(ValueError):
            coords.append((float(m_target.group(1)), float(m_target.group(2))))

    if len(coords) < 2:
        # Fallback analítico si no hay múltiples coordenadas
        avg_lat, avg_lon = (coords[0][0], coords[0][1]) if coords else (40.4168, -3.7038)
        radius_km = 5.0
        canter_type = "Merodeador Urbano (Marauder)"
    else:
        avg_lat = sum(c[0] for c in coords) / len(coords)
        avg_lon = sum(c[1] for c in coords) / len(coords)
        # Distancia máxima entre puntos
        max_dist = max(math.sqrt((c[0] - avg_lat) ** 2 + (c[1] - avg_lon) ** 2) * 111.0 for c in coords)
        radius_km = max(1.0, max_dist)
        canter_type = "Merodeador (Marauder)" if radius_km < 15.0 else "Conmutador (Commuter - Desplazamiento Largo)"

    archetype = f"Punto de Anclaje Probable: {avg_lat:.4f}, {avg_lon:.4f} ({canter_type})"
    risk: RiskLevel = "HIGH" if len(coords) >= 3 else "MEDIUM"

    dimensions = [
        ProfileDimension(
            name="Centro de Gravedad y Superficie CGT de Rossmo",
            score=round(min(1.0, 0.5 + 0.1 * len(coords)), 2),
            confidence=0.85 if len(coords) >= 3 else 0.60,
            epistemic_status="inference",
            notes=(
                f"Punto medio estimado en lat: {avg_lat:.4f}, lon: {avg_lon:.4f} "
                f"con radio de búsqueda de {radius_km:.1f} km."
            ),
        ),
        ProfileDimension(
            name="Criterio Espacial de Canter (Hipótesis del Círculo)",
            score=0.80 if "Marauder" in canter_type else 0.50,
            confidence=0.75,
            epistemic_status="inference",
            notes=f"Clasificación de movilidad territorial: {canter_type}.",
        ),
    ]

    traits = [
        ProfilingTraitNode(
            maltego_type="maltego.GPS",
            value=f"{avg_lat:.4f},{avg_lon:.4f}",
            edge_label="Estimated_Anchor_Point",
            properties={"profiling.radius_km": str(round(radius_km, 1)), "profiling.canter": canter_type},
            visual_color="#a855f7",
            visual_weight=85,
        ),
        ProfilingTraitNode(
            maltego_type="maltego.Phrase",
            value=f"Zona Operativa: Radio {radius_km:.1f} km ({canter_type})",
            edge_label="Operational_Spatial_Zone",
            properties={"profiling.mobility": canter_type},
            visual_color="#00f5ff",
            visual_weight=75,
        ),
    ]

    anomalies = []
    if "Commuter" in canter_type:
        anomalies.append(
            "Patrón de conmutación: El autor viaja distancias significativas entre la base y las zonas de actuación."
        )

    recs = [
        (
            f"Priorizar patrullaje y revisión de cámaras en un radio de {radius_km:.1f} km "
            f"alrededor de {avg_lat:.4f}, {avg_lon:.4f}."
        ),
        "Verificar domicilios y centros de trabajo de sospechosos que intersecten el área de mayor probabilidad CGT.",
    ]
    summary = (
        f"Perfil geográfico (Rossmo/Canter): {archetype}. "
        f"Radio estimado de acción de {radius_km:.1f} km sobre {len(coords)} localizaciones analizadas."
    )
    return archetype, risk, summary, dimensions, traits, anomalies, recs


def profile_victimology(
    target: EntityRecord,
    neighbors: list[tuple[str, str, dict[str, Any]]],
    text_corpus: str,
) -> tuple[str, RiskLevel, str, list[ProfileDimension], list[ProfilingTraitNode], list[str], list[str]]:
    text = text_corpus.lower()

    # Evaluación de riesgo de la víctima vs riesgo del agresor
    high_vuln = any(
        k in text
        for k in ("anciano", "menor", "desprotegido", "aislado", "vulnerable", "nocturno", "alcohol", "confianza")
    )
    selection_symbolic = any(
        k in text for k in ("odio", "discriminación", "religión", "raza", "colectivo", "política", "símbolo")
    )

    victim_risk = 0.80 if high_vuln else 0.40
    selection_type = (
        "Simbólica / Odio / Colectivo"
        if selection_symbolic
        else "Oportunista / Baja Resistencia"
        if high_vuln
        else "Específica / Dirigida"
    )
    risk: RiskLevel = "HIGH" if high_vuln or selection_symbolic else "MEDIUM"
    archetype = f"Víctima por Selección {selection_type}"

    dimensions = [
        ProfileDimension(
            name="Nivel de Exposición y Vulnerabilidad de la Víctima",
            score=round(victim_risk, 2),
            confidence=0.80,
            epistemic_status="inference",
            notes="Evaluación de rutinas, hábitos y factores de indefensión.",
        ),
        ProfileDimension(
            name="Criterio de Selección del Agresor",
            score=0.85 if selection_symbolic else 0.50,
            confidence=0.75,
            epistemic_status="inference",
            notes=f"Móvil inferido de selección: {selection_type}.",
        ),
    ]

    traits = [
        ProfilingTraitNode(
            maltego_type="maltego.Phrase",
            value=f"Victimología: {archetype}",
            edge_label="Assessed_Victimology_Profile",
            properties={"profiling.selection": selection_type},
            visual_color="#f59e0b",
            visual_weight=75,
        )
    ]

    anomalies = []
    if selection_symbolic:
        anomalies.append(
            "Riesgo de escalada: Selección por odio o valor simbólico (probabilidad de ataques en cadena)."
        )

    recs = [
        "Establecer medidas de protección a perfiles de alta vulnerabilidad similar en la misma demarcación.",
        "Reconstruir las últimas 48 horas previas al incidente para identificar puntos de contacto no declarados.",
    ]
    summary = (
        f"Evaluación victimológica: '{archetype}' con vulnerabilidad del {victim_risk * 100:.0f} % "
        f"y selección '{selection_type}'."
    )
    return archetype, risk, summary, dimensions, traits, anomalies, recs


def profile_stylometry(
    target: EntityRecord,
    neighbors: list[tuple[str, str, dict[str, Any]]],
    text_corpus: str,
) -> tuple[str, RiskLevel, str, list[ProfileDimension], list[ProfilingTraitNode], list[str], list[str]]:
    # Extracción de tokens
    words = re.findall(r"\b[a-zA-ZáéíóúñÁÉÍÓÚÑüÜ]{2,}\b", text_corpus.lower())
    total_words = len(words)
    unique_words = len(set(words))

    # Riqueza léxica TTR (Type-Token Ratio)
    ttr = (unique_words / total_words) if total_words > 0 else 0.5

    # Puntuación e idiolecto
    punctuation_count = len(re.findall(r"[!?,;:\-\(\)\"]", text_corpus))
    punct_density = (punctuation_count / total_words) if total_words > 0 else 0.05

    # Detección de barbarismos o idiolecto marcado
    has_spelling_quirks = bool(re.search(r"(\w)\1{2,}", text_corpus))  # letras repetidas: 'holaaa'

    archetype = (
        "Estilo Formal / Léxico Rico (Alta Formación)" if ttr > 0.65 else "Estilo Reducido / Repetitivo / Coloquial"
    )
    risk: RiskLevel = "MEDIUM" if has_spelling_quirks or ttr < 0.4 else "LOW"

    spelling_desc = "Detectadas" if has_spelling_quirks else "No evidentes"
    dimensions = [
        ProfileDimension(
            name="Riqueza Léxica (Type-Token Ratio - TTR)",
            score=round(ttr, 2),
            confidence=0.85 if total_words >= 50 else 0.60,
            epistemic_status="fact",
            notes=f"Total palabras: {total_words}, vocabulario único: {unique_words} (TTR={ttr:.2f}).",
        ),
        ProfileDimension(
            name="Densidad de Puntuación e Idiolecto",
            score=round(min(1.0, punct_density * 5), 2),
            confidence=0.75,
            epistemic_status="fact",
            notes=f"Signos: {punctuation_count}. Anomalías idiolectales: {spelling_desc}.",
        ),
    ]

    traits = [
        ProfilingTraitNode(
            maltego_type="maltego.Phrase",
            value=f"Estilometría: {archetype} (TTR={ttr:.2f})",
            edge_label="Displays_Stylometric_Profile",
            properties={"profiling.ttr": f"{ttr:.2f}", "profiling.words": str(total_words)},
            visual_color="#818cf8",
            visual_weight=75,
        )
    ]

    anomalies = []
    if has_spelling_quirks:
        anomalies.append("Firma idiolectal: Patrón reiterado de elongación ortográfica y puntuación atípica.")

    recs = [
        "Comparar matriz de palabras funcionales con el corpus de los sospechosos (Burrows Delta).",
        "Inspeccionar si el vocabulario delata regionalismos dialectales o traducción literal de otro idioma.",
    ]
    summary = f"Análisis estilométrico: '{archetype}' sobre {total_words} palabras con ratio TTR de {ttr:.2f}."
    return archetype, risk, summary, dimensions, traits, anomalies, recs
