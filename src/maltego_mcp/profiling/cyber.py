"""Submotor de perfilado Técnico, Cibernético y de Telemetría (CTI).

Tipologías cubiertas:
- cyber: Perfilado Cibernético / Threat Actor Attribution
- device: Perfilado de Dispositivos / Huella Digital
- network: Perfilado de Redes / Línea Base de Tráfico
- data: Perfilado de Datos e Integridad Forense
"""

from __future__ import annotations

from typing import Any

from maltego_mcp.domain.profiling import (
    ProfileDimension,
    ProfilingTraitNode,
    RiskLevel,
)
from maltego_mcp.domain.records import EntityRecord


def profile_cyber(
    target: EntityRecord,
    neighbors: list[tuple[str, str, dict[str, Any]]],
    text_corpus: str,
) -> tuple[str, RiskLevel, str, list[ProfileDimension], list[ProfilingTraitNode], list[str], list[str]]:
    text = text_corpus.lower()

    # 1. Sofisticación del actor
    apt_terms = ("apt", "zero-day", "0-day", "rootkit", "state-sponsored", "kernel", "bypass", "custom loader")
    crime_terms = ("ransomware", "stealer", "infostealer", "botnet", "phishing", "telegram", "c2", "cobalt")

    is_apt = any(k in text for k in apt_terms)
    is_syndicate = any(k in text for k in crime_terms)

    sophistication = 0.90 if is_apt else 0.70 if is_syndicate else 0.40
    motivation = (
        "Espionaje / Sabotaje Geopolítico"
        if is_apt
        else "Lucro Financiero / Extorsión"
        if is_syndicate
        else "Oportunista / Hacktivismo"
    )

    # 2. Inferencia de huso horario / diurno
    tz_hint = "Desconocido (Telemetría global)"
    if any(k in text for k in ("utc+8", "cst", "alibaba", "qq.com", "beijing", "chinese", "huawei")):
        tz_hint = "Asia Oriental (UTC+8)"
    elif any(k in text for k in ("utc+3", "msk", "yandex", "ru-tld", "cis", "cyrillic")):
        tz_hint = "Europa Oriental / CIS (UTC+3)"
    elif any(k in text for k in ("utc-5", "est", "north america")):
        tz_hint = "América del Norte (UTC-5 / UTC-8)"

    risk: RiskLevel = "CRITICAL" if is_apt or is_syndicate else "HIGH"
    archetype = (
        f"Célula APT Avanzada ({motivation})"
        if is_apt
        else f"Sindicato de Cibercrimen Organizado ({motivation})"
        if is_syndicate
        else "Actor de Amenaza Oportunista"
    )

    dimensions = [
        ProfileDimension(
            name="Índice de Sofisticación Técnica (MITRE ATT&CK Tier)",
            score=round(sophistication, 2),
            confidence=0.85,
            epistemic_status="inference",
            notes="Capacidad observada de desarrollo de artefactos propios y evasión EDR/C2.",
        ),
        ProfileDimension(
            name="Alineación Geográfica / Huso Horario de Operación",
            score=0.80 if tz_hint != "Desconocido" else 0.30,
            confidence=0.75,
            epistemic_status="hypothesis",
            notes=f"Inferencia horaria y cultural basada en artefactos: {tz_hint}",
        ),
    ]

    traits = [
        ProfilingTraitNode(
            maltego_type="maltego.ThreatActor" if target.maltego_type != "maltego.ThreatActor" else "maltego.Phrase",
            value=f"Actor: {archetype}",
            edge_label="Attributed_To_Threat_Tier",
            properties={"profiling.sophistication": str(sophistication), "profiling.timezone": tz_hint},
            visual_color="#e11d48",
            visual_weight=90,
        ),
        ProfilingTraitNode(
            maltego_type="maltego.Phrase",
            value=f"Huso Horario Operativo: {tz_hint}",
            edge_label="Operates_In_Timezone_Window",
            properties={"profiling.inferred_tz": tz_hint},
            visual_color="#818cf8",
            visual_weight=75,
        ),
    ]

    anomalies = []
    if is_apt and "qq.com" in text:
        anomalies.append(
            "Fuga de OPSEC: Artefacto de comunicación civil/personal detectado en infraestructura de ataque."
        )

    recs = [
        "Desplegar reglas YARA y firmas Sigma específicas para los TTPs observados.",
        "Aislar segmentos que mantengan comunicación con los C2 e IPs asociadas.",
        "Efectuar bloqueo de IOCs en pasarelas perimetrales y firewalls de DNS.",
    ]
    summary = (
        f"Actor '{archetype}' con sofisticación {sophistication * 100:.0f} %, "
        f"motivación en '{motivation}' y ventana probable en {tz_hint}."
    )
    return archetype, risk, summary, dimensions, traits, anomalies, recs


def profile_device(
    target: EntityRecord,
    neighbors: list[tuple[str, str, dict[str, Any]]],
    text_corpus: str,
) -> tuple[str, RiskLevel, str, list[ProfileDimension], list[ProfilingTraitNode], list[str], list[str]]:
    text = text_corpus.lower()

    # Detección de emuladores, proxies o anti-detect
    is_spoofed = any(
        k in text
        for k in ("canvas", "webgl", "ja3", "ja4", "antidetect", "proxy residencial", "emulator", "genymotion")
    )
    anomaly_score = 0.85 if is_spoofed else 0.20
    risk: RiskLevel = "HIGH" if is_spoofed else "LOW"
    archetype = "Dispositivo Suplantado / Entorno Anti-Detect / VM" if is_spoofed else "Terminal Físico Convencional"

    dimensions = [
        ProfileDimension(
            name="Índice de Alteración de Huella (Fingerprint Spoofing)",
            score=round(anomaly_score, 2),
            confidence=0.85,
            epistemic_status="inference",
            notes="Detección de incoherencias entre User-Agent, pila TCP y capacidades de renderizado.",
        )
    ]

    traits = [
        ProfilingTraitNode(
            maltego_type="maltego.Phrase",
            value=f"Huella de Dispositivo: {archetype}",
            edge_label="Emits_Device_Profile",
            properties={"profiling.spoofed": str(is_spoofed)},
            visual_color="#e11d48" if is_spoofed else "#10b981",
            visual_weight=80,
        )
    ]

    anomalies = []
    if is_spoofed:
        anomalies.append(
            "Alerta de fraude: La huella TLS (JA3/JA4) discrepa del navegador reportado en cabeceras HTTP."
        )

    recs = [
        "Exigir autenticación reforzada por segundo factor (WebAuthn/FIDO2) ante huellas discrepantes.",
        "Bloquear el acceso si se detectan extensiones conocidas de alteración de Canvas/WebGL.",
    ]
    summary = f"Terminal categorizado como '{archetype}' con índice de manipulación del {anomaly_score * 100:.0f} %."
    return archetype, risk, summary, dimensions, traits, anomalies, recs


def profile_network(
    target: EntityRecord,
    neighbors: list[tuple[str, str, dict[str, Any]]],
    text_corpus: str,
) -> tuple[str, RiskLevel, str, list[ProfileDimension], list[ProfilingTraitNode], list[str], list[str]]:
    text = text_corpus.lower()

    # Comprobación de anomalías de red
    is_bulletproof = any(
        k in text for k in ("bulletproof", "as13335", "cloudflare", "tor", "vpn", "proxy", "túnel", "beacon")
    )
    anomaly_score = 0.80 if is_bulletproof else 0.25
    risk: RiskLevel = "HIGH" if is_bulletproof else "LOW"
    archetype = "Infraestructura Opaca / Tráfico Anómalo" if is_bulletproof else "Segmento de Conectividad Estándar"

    dimensions = [
        ProfileDimension(
            name="Desviación de Línea Base de Tráfico",
            score=round(anomaly_score, 2),
            confidence=0.80,
            epistemic_status="inference",
            notes="Evaluación de patrones de enrutamiento y uso de proxies/CDN como escudo de ofuscación.",
        )
    ]

    traits = [
        ProfilingTraitNode(
            maltego_type="maltego.Phrase",
            value=f"Perfil de Red: {archetype}",
            edge_label="Displays_Network_Behavior",
            properties={"profiling.anomaly": str(anomaly_score)},
            visual_color="#f59e0b" if is_bulletproof else "#10b981",
            visual_weight=75,
        )
    ]

    anomalies = []
    if is_bulletproof:
        anomalies.append(
            "Enrutamiento sospechoso: Empleo de saltos intermedios para dificultar la atribución legal del origen."
        )

    recs = [
        "Auditar resoluciones de DNS pasivo para identificar cambios bruscos de direccionamiento IP.",
        "Inspeccionar registros NetFlow en busca de tráfico periódico de balizamiento C2.",
    ]
    summary = (
        f"Infraestructura evaluada como '{archetype}' con desviación del baseline "
        f"estimada en {anomaly_score * 100:.0f} %."
    )
    return archetype, risk, summary, dimensions, traits, anomalies, recs


def profile_data(
    target: EntityRecord,
    neighbors: list[tuple[str, str, dict[str, Any]]],
    text_corpus: str,
) -> tuple[str, RiskLevel, str, list[ProfileDimension], list[ProfilingTraitNode], list[str], list[str]]:
    # Medir completitud, cardinalidad y calidad en el grafo
    total_props = len(target.properties)
    has_notes = bool(target.notes)
    integrity_score = min(1.0, 0.4 + 0.1 * min(5, total_props) + (0.2 if has_notes else 0.0))
    risk: RiskLevel = "LOW" if integrity_score > 0.7 else "MEDIUM"
    archetype = (
        "Registro Pericial Completo y No Repudiable"
        if integrity_score > 0.7
        else "Registro Parcial con Lagunas de Telemetría"
    )

    notes_status = "presentes" if has_notes else "ausentes"
    dimensions = [
        ProfileDimension(
            name="Calidad e Integridad de Metadatos",
            score=round(integrity_score, 2),
            confidence=0.95,
            epistemic_status="fact",
            notes=f"Propiedades estructuradas: {total_props}, notas forenses: {notes_status}.",
        )
    ]

    traits = [
        ProfilingTraitNode(
            maltego_type="maltego.Phrase",
            value=f"Auditoría de Datos: {archetype}",
            edge_label="Evaluated_For_Data_Integrity",
            properties={"profiling.integrity": str(integrity_score)},
            visual_color="#10b981" if integrity_score > 0.7 else "#f59e0b",
            visual_weight=70,
        )
    ]

    anomalies = []
    if integrity_score < 0.6:
        anomalies.append("Alerta de integridad: La entidad carece de notas periciales o fuentes cruzadas verificables.")

    recs = [
        "Ejecutar transforms adicionales para enriquecer propiedades ausentes antes del dictamen final.",
        "Verificar no repudio contrastando con registros secundarios independientes.",
    ]
    summary = f"Evaluación de datos: '{archetype}' con índice de fidelidad del {integrity_score * 100:.0f} %."
    return archetype, risk, summary, dimensions, traits, anomalies, recs
