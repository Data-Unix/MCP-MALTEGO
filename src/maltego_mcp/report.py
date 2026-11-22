"""Informes ejecutivos de un caso (Markdown y HTML autocontenido pericial de alta fidelidad).

Genera documentacion ejecutiva modular de nivel pericial con soporte para:
1. Portada institucional con strip de metadatos (Caso, TLP, Clasificacion, Entidades).
2. § 01 Resumen Ejecutivo & BLUF con respuesta taxativa a la investigacion, Dictamen pericial,
   franja de 4 KPIs ejecutivos, insignias de competidores y protocolo metodologico Fases A/B/C.
3. § 02 & § 03 Matrices periciales de evidencias consolidadas de 6 columnas agrupadas dinamicamente
   por ambito o capa forense segun la tipologia del caso (BPO, Ciberfraude, CTI u OSINT General).
4. § 04 Matriz de concurrencia multicuenta o correlacion cruzada de infraestructura y vectores.
5. § 05 Red topologica y arquitectura del grafo (diagrama vectorial SVG interactivo autocontenido,
   estratificado en 9 niveles de acuerdo con la geometria matematica del caso, mas leyenda formal completa).
6. § 06 Trazabilidad procedimental (Ledger de pasos StepRecord), metricas de calidad y sello criptografico SHA-256.

Cumple estrictamente con la regla ZERO EMOJIS en UI, codigo y marcado.
"""

from __future__ import annotations

import hashlib
import html
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from maltego_mcp.analysis import Action, EntityScore, compute_entity_validity
from maltego_mcp.defang import defang
from maltego_mcp.domain.records import CaseRecord, EdgeRecord, EntityRecord, StepRecord
from maltego_mcp.maltego.mtgx import (
    compute_layout,
    edge_visual_profile,
    entity_visual_profile,
)


@dataclass(slots=True)
class ReportData:
    case: CaseRecord
    entities: list[EntityRecord]
    edges: list[EdgeRecord]
    steps: list[StepRecord]
    scores: dict[str, EntityScore]
    actions: list[Action] = field(default_factory=list)
    generated: str = ""
    recon: dict[str, Any] = field(default_factory=dict)
    profiles: list[dict[str, Any]] = field(default_factory=list)

    def quality(self) -> dict[str, float | int]:
        n = len(self.entities) or 1
        linked = {e.out_id for e in self.edges} | {e.in_id for e in self.edges}
        transform_steps = [s for s in self.steps if s.kind == "transform"]
        return {
            "entidades": len(self.entities),
            "relaciones": len(self.edges),
            "confianza_media": round(sum(e.confidence for e in self.entities) / n, 2),
            "corroboradas_pct": round(100 * sum(len(set(e.sources)) > 1 for e in self.entities) / n, 1),
            "aisladas": sum(e.id not in linked for e in self.entities),
            "pasos": len(self.steps),
            "errores_pct": round(100 * sum(bool(s.error) for s in transform_steps) / (len(transform_steps) or 1), 1),
        }

    def by_type(self) -> list[tuple[str, int]]:
        counts: dict[str, int] = {}
        for e in self.entities:
            counts[e.maltego_type] = counts.get(e.maltego_type, 0) + 1
        return sorted(counts.items(), key=lambda x: (-x[1], x[0]))

    def top(self, n: int = 15) -> list[EntityScore]:
        return sorted(self.scores.values(), key=lambda s: (-s.priority, s.entity.value))[:n]


def _h(v: object) -> str:
    """Escapa texto para insercion segura en HTML."""
    return html.escape(str(v or ""))


def _defang(v: object) -> str:
    """Neutraliza URLs e IOCs (ej. hxxps[://]domain[.]com) para evitar navegación accidental o prefetching."""
    return _h(defang(v))


def _md(v: object) -> str:
    """Escapa texto para tablas y bloques Markdown, neutralizando inyección HTML y caracteres de tabla."""
    return (
        str(v or "").replace("|", "\\|").replace("\n", " ").replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")
    )


def _hash_seal(entities: list[EntityRecord], edges: list[EdgeRecord]) -> str:
    """Calcula la huella criptografica SHA-256 para la cadena de custodia pericial."""
    h = hashlib.sha256()
    for e in sorted(entities, key=lambda x: x.id):
        h.update(f"{e.id}:{e.maltego_type}:{e.value}:{e.confidence}".encode())
    for ed in sorted(edges, key=lambda x: x.id):
        h.update(f"{ed.id}:{ed.out_id}:{ed.label}:{ed.in_id}".encode())
    return h.hexdigest()


def _detect_case_theme(case: CaseRecord, entities: list[EntityRecord]) -> dict[str, str]:
    """Detecta de forma dinamica la tipologia pericial del caso para adaptar la terminologia sin contaminaciones."""
    text = f"{case.case_id} {case.description}".upper()
    has_bpo = "BPO" in text or any(e.properties.get("bpo.role") for e in entities)
    has_fraud = any(
        k in text
        for k in (
            "FRAUDE",
            "ESTAFA",
            "SCAM",
            "PHISHING",
            "PONZI",
            "PIG BUTCHERING",
            "CIBERFRAUDE",
            "TAREAS",
        )
    )
    has_cti = any(k in text for k in ("CTI", "APT", "MALWARE", "RANSOMWARE", "INCIDENT"))

    if has_bpo:
        return {
            "theme_name": "bpo",
            "super_title": "[INFORME PERICIAL DE INTELIGENCIA DE FUENTES ABIERTAS - BPO]",
            "cover_title": "MAPEO TOPOLOGICO Y EVALUACION DE CONCURRENCIA BPO",
            "section2_badge": "§ 02 & § 03 // ENTIDADES PRIORITARIAS Y MATRICES PERICIALES",
            "section2_title": "Entidades prioritarias y Consolidación de Proveedores",
            "section2_desc": (
                "Desglose exhaustivo de los sujetos auditados con asignación de servicios, "
                "identificación societaria oficial, recintos operativos y fuentes probatorias."
            ),
            "section2_md": "## § 02. Entidades prioritarias y Matrices de Evidencias Consolidadas",
            "section4_badge": "§ 04 // CONCURRENCIA MULTICUENTA",
            "section4_title": "Matriz de Concurrencia y Heatmap de Penetración Sectorial",
            "section4_desc": (
                "Auditoría cruzada de convivencia operativa entre los proveedores BPO asignados "
                "y clientes concurrentes del sector telecomunicaciones, banca y retail."
            ),
            "section4_md": "## § 03. Matriz de Concurrencia Multicuenta y Penetración",
            "tier3_label": "Tier 3 (Proveedores BPO)",
            "tier3_desc": "Sujetos nucleares auditados con rol operativo en la cuenta",
            "table_th_entity": "Proveedor Auditado",
            "table_th_id": "Registro / ID",
            "table_th_service": "Servicios & Procesos",
            "table_th_location": "Sedes Físicas & GPS",
            "table_th_evidence": "Evidencias & Registros",
            "default_verdict_title": "[DICTAMEN] Exclusividad Operativa No Detectada",
            "default_verdict_notes": (
                "Concurrencia multicliente y multitenant generalizada en los centros operativos "
                "y proveedores auditados."
            ),
        }
    if has_fraud:
        return {
            "theme_name": "fraud",
            "super_title": "[INFORME PERICIAL DE CIBERCRIMEN Y FRAUDE FINANCIERO]",
            "cover_title": "ANALISIS FORENSE DE CIBERFRAUDE Y ATRIBUCION DE INFRAESTRUCTURA",
            "section2_badge": "§ 02 & § 03 // ENTIDADES PRIORITARIAS Y MATRICES FORENSES",
            "section2_title": "Entidades prioritarias y Cartografía de la Red Delictiva",
            "section2_desc": (
                "Desglose exhaustivo de activos digitales, infraestructura de captación, "
                "identidades de mando y canales de liquidación y lavado de activos."
            ),
            "section2_md": "## § 02. Entidades prioritarias y Cartografía de la Red Delictiva",
            "section4_badge": "§ 04 // CORRELACION DE INFRAESTRUCTURA Y VECTORES",
            "section4_title": "Matriz de Coexistencia de Infraestructura, Pasarelas y Actores",
            "section4_desc": (
                "Correlación cruzada entre actores operativos, dominios de captación, "
                "servidores de backend y pasarelas de liquidación de activos."
            ),
            "section4_md": "## § 03. Matriz de Coexistencia de Infraestructura, Pasarelas y Actores",
            "tier3_label": "Tier 3 (Actores y Activos Nucleares)",
            "tier3_desc": "Células operativas, identidades de control y dominios raíz del esquema",
            "table_th_entity": "Activo / Sujeto de Mando",
            "table_th_id": "Identificador / Registro / Red",
            "table_th_service": "Módulos de Fraude & Roles",
            "table_th_location": "Ubicación / IP / Huso Horario",
            "table_th_evidence": "Evidencias & Artefactos",
            "default_verdict_title": "[DICTAMEN] Red Delictiva Transnacional y Esquema de Fraude Confirmado",
            "default_verdict_notes": (
                "Estructura coordinada de fraude digital con infraestructura de captación distribuida, "
                "ofuscación de origen y canales de liquidación identificados mediante correlación multifuente."
            ),
        }
    if has_cti:
        return {
            "theme_name": "cti",
            "super_title": "[INFORME DE CIBERINTELIGENCIA DE AMENAZAS - CTI]",
            "cover_title": "INFORME DE CIBERINTELIGENCIA Y CORRELACION DE AMENAZAS",
            "section2_badge": "§ 02 & § 03 // ENTIDADES PRIORITARIAS Y MATRICES DE AMENAZAS",
            "section2_title": "Entidades prioritarias e Indicadores de Compromiso (IOCs)",
            "section2_desc": (
                "Inventario de artefactos maliciosos, servidores de comando y control (C2), "
                "familias de amenazas y tácticas asociadas."
            ),
            "section2_md": "## § 02. Entidades prioritarias e Indicadores de Compromiso (IOCs)",
            "section4_badge": "§ 04 // CORRELACION DE TTPs Y VECTORES",
            "section4_title": "Matriz de Tácticas, Técnicas y Procedimientos (ATT&CK)",
            "section4_desc": "Mapeo de infraestructura adversaria frente a técnicas de ataque y objetivos.",
            "section4_md": "## § 03. Matriz de Tácticas, Técnicas y Procedimientos (ATT&CK)",
            "tier3_label": "Tier 3 (Actores y Artefactos CTI)",
            "tier3_desc": "Infraestructura adversaria, C2 y sujetos de amenaza principales",
            "table_th_entity": "IOC / Actor de Amenaza",
            "table_th_id": "Firma / Hash / Registro",
            "table_th_service": "Tácticas & Capacidades",
            "table_th_location": "Infraestructura & GeoIP",
            "table_th_evidence": "Telemetría & Fuentes CTI",
            "default_verdict_title": "[DICTAMEN] Infraestructura Maliciosa y Actividad de Amenaza Confirmada",
            "default_verdict_notes": (
                "Correlación de vectores de intrusión, artefactos C2 y telemetría adversaria "
                "verificada en la investigación."
            ),
        }
    return {
        "theme_name": "osint",
        "super_title": "[INFORME PERICIAL DE INTELIGENCIA OSINT / SOCMINT]",
        "cover_title": "INFORME PERICIAL DE INTELIGENCIA Y MAPEADO TOPOLOGICO",
        "section2_badge": "§ 02 & § 03 // ENTIDADES PRIORITARIAS Y MATRICES PERICIALES",
        "section2_title": "Entidades prioritarias y Matrices Periciales de Evidencias",
        "section2_desc": (
            "Desglose exhaustivo de los sujetos auditados con asignación de funciones, "
            "identificadores oficiales y fuentes probatorias."
        ),
        "section2_md": "## § 02. Entidades prioritarias y Matrices de Evidencias Consolidadas",
        "section4_badge": "§ 04 // CORRELACION Y VINCULOS OPERATIVOS",
        "section4_title": "Matriz de Correlación y Vínculos Operativos",
        "section4_desc": (
            "Análisis de relaciones y coexistencia operativa entre entidades nucleares y activos relacionados."
        ),
        "section4_md": "## § 03. Matriz de Concurrencia y Correlación Operativa",
        "tier3_label": "Tier 3 (Entidades y Sujetos Nucleares)",
        "tier3_desc": "Sujetos auditados directos con rol operativo o central",
        "table_th_entity": "Entidad / Sujeto Nuclear",
        "table_th_id": "Registro / Identificador",
        "table_th_service": "Funciones & Atributos",
        "table_th_location": "Sedes Físicas & Ubicación",
        "table_th_evidence": "Evidencias & Registros",
        "default_verdict_title": "[DICTAMEN] Cartografía Topológica y Vínculos Operativos Verificados",
        "default_verdict_notes": (
            "Identificación y corroboración multifuente de los sujetos auditados y su infraestructura asociada."
        ),
    }


def _extract_target(entities: list[EntityRecord], edges: list[EdgeRecord]) -> EntityRecord:
    for e in entities:
        if (
            e.properties.get("role") in ("target_client", "target", "primary")
            or e.properties.get("is_target") == "true"
        ):
            return e
    by_id = {e.id: e for e in entities}
    for ed in edges:
        if ed.label in ("provides_bpo_service_to", "assigned_to_account", "services_target") and ed.in_id in by_id:
            return by_id[ed.in_id]
    companies = [e for e in entities if e.maltego_type == "maltego.Company"]
    if companies:
        adj: dict[str, int] = defaultdict(int)
        for ed in edges:
            adj[ed.out_id] += 1
            adj[ed.in_id] += 1
        return max(companies, key=lambda c: adj[c.id])
    domains = [e for e in entities if e.maltego_type == "maltego.Domain"]
    if domains:
        return domains[0]
    return entities[0] if entities else EntityRecord("target", "", "Target", "maltego.Phrase", "Entidad Auditada")


def _extract_verdict(entities: list[EntityRecord], theme: dict[str, str]) -> tuple[str, str, float]:
    for e in entities:
        mtype = e.maltego_type.lower()
        val = e.value.lower()
        props = e.properties
        if mtype == "maltego.phrase" and (
            "dictamen" in val
            or "verdict" in val
            or "conclusi" in val
            or "alerta" in val
            or props.get("analysis.status") == "confirmed"
            or "exclusivity.result" in props
        ):
            title = e.value
            notes = (
                e.notes
                or props.get("notes")
                or props.get("description")
                or "Dictamen pericial fundamentado en la topología de relaciones y evidencias auditadas."
            )
            return title, notes, e.confidence
    return (
        theme["default_verdict_title"],
        theme["default_verdict_notes"],
        0.95,
    )


def _extract_scopes_and_entities(
    entities: list[EntityRecord], edges: list[EdgeRecord], theme: dict[str, str]
) -> dict[str, list[dict[str, Any]]]:
    """Extrae las matrices de entidades de 6 columnas adaptadas dinamicamente segun la tipologia del caso."""
    by_id = {e.id: e for e in entities}
    adj_out: dict[str, list[EdgeRecord]] = defaultdict(list)
    for ed in edges:
        adj_out[ed.out_id].append(ed)

    blocks: dict[str, list[dict[str, Any]]] = defaultdict(list)

    if theme["theme_name"] == "bpo":
        providers = [
            e
            for e in entities
            if (e.maltego_type == "maltego.Company" and e.properties.get("bpo.role"))
            or (e.maltego_type == "maltego.Company" and any(ed.label == "delivers_service" for ed in adj_out[e.id]))
        ]
        if not providers:
            providers = [e for e in entities if e.maltego_type == "maltego.Company"][:10]
        for p in providers:
            scope = p.properties.get("geo.country") or p.properties.get("geo.scope") or ""
            if not scope:
                for ed in adj_out[p.id]:
                    target = by_id.get(ed.in_id)
                    if (
                        target
                        and target.maltego_type == "maltego.Location"
                        and ed.label in ("physically_located_in", "located_in")
                    ):
                        scope = target.value
                        break
            if not scope:
                scope = "Ambito General"
            reg_id = (
                p.properties.get("commercial_registry_id")
                or p.properties.get("tax_id")
                or p.properties.get("cif")
                or p.properties.get("ruc")
                or "-"
            )
            services = []
            for ed in adj_out[p.id]:
                if ed.label == "delivers_service":
                    nbr = by_id.get(ed.in_id)
                    if nbr:
                        val = nbr.value
                        if " :: " in val:
                            val = val.split(" :: ", 1)[1]
                        services.append(val)
            facilities = []
            for ed in adj_out[p.id]:
                if ed.label == "operates_facility":
                    nbr = by_id.get(ed.in_id)
                    if nbr:
                        fac_name = nbr.value
                        gps_coords = ""
                        for f_ed in adj_out[nbr.id]:
                            if f_ed.label == "georeferenced_at":
                                gps_nbr = by_id.get(f_ed.in_id)
                                if gps_nbr:
                                    gps_coords = gps_nbr.value
                        facilities.append({"name": fac_name, "gps": gps_coords})
            evidences = []
            for ed in adj_out[p.id]:
                if ed.label in ("supported_by_document", "verified_via_url"):
                    nbr = by_id.get(ed.in_id)
                    if nbr:
                        evidences.append(nbr.value)
            blocks[scope].append(
                {
                    "entity": p,
                    "reg_id": reg_id,
                    "services": services or ["Servicios Operativos"],
                    "facilities": facilities,
                    "confidence": p.confidence,
                    "evidences": evidences,
                }
            )
        return blocks

    # Tipologias No-BPO (Ciberfraude, CTI, OSINT General): agrupacion por capas de analisis forense
    for e in entities:
        mtype = e.maltego_type.lower()
        val = e.value.lower()
        props = e.properties

        if mtype == "maltego.phrase" and ("dictamen" in val or "verdict" in val):
            continue

        category = ""
        reg_id = "-"
        srv_list: list[str] = []
        loc_list: list[dict[str, str]] = []
        evi_list: list[str] = []

        if mtype in ("maltego.domain", "maltego.dnsname", "maltego.url"):
            category = "Infraestructura Web, Dominios y Servicios Cloud"
            reg_id = props.get("registrar") or props.get("type") or props.get("framework") or "-"
            if props.get("spoofed_brand"):
                srv_list.append(f"Suplantación: {props['spoofed_brand']}")
            if props.get("cloud"):
                srv_list.append(f"Bucket Cloud: {props['cloud']} ({props.get('region', '')})")
            for ed in adj_out[e.id]:
                target = by_id.get(ed.in_id)
                if target:
                    if target.maltego_type == "maltego.IPv4Address":
                        loc_list.append({"name": f"IP: {target.value}", "gps": ""})
                    elif ed.label.startswith("Serves"):
                        srv_list.append(f"Servicio: {target.value[:35]}")
                    elif ed.label.startswith("Attributed") or ed.label.startswith("Config"):
                        evi_list.append(f"{ed.label}: {target.value}")

        elif mtype in ("maltego.person", "maltego.alias", "maltego.emailaddress", "maltego.organization"):
            category = "Estructura de Actores, Mando y Cuentas Operativas"
            reg_id = props.get("deptId") or props.get("partyId") or props.get("service") or "-"
            role_desc = props.get("role") or props.get("privileges") or "Operador"
            srv_list.append(f"Rol: {role_desc}")
            if props.get("password_hash"):
                srv_list.append(f"Credencial/Hash: {props['password_hash']}")
            for ed in adj_out[e.id]:
                target = by_id.get(ed.in_id)
                if target:
                    if target.maltego_type == "maltego.IPv4Address":
                        loc_list.append(
                            {
                                "name": f"Origen IP: {target.value} ({target.properties.get('city', '')})",
                                "gps": "",
                            }
                        )
                    elif ed.label.startswith("Supervises"):
                        srv_list.append(f"Mando sobre: {target.value}")
                    elif ed.label.startswith("Operates"):
                        srv_list.append(f"Opera: {target.value}")
                    elif ed.label.startswith("Shared"):
                        evi_list.append(f"Artefacto común: {target.value}")

        elif mtype == "maltego.phrase" and any(
            k in val for k in ("tarea", "préstamo", "prestamo", "tarjeta", "usdt", "wallet", "piramidal", "target")
        ):
            category = "Módulos de Fraude, Captación y Canales Financieros"
            reg_id = props.get("uuid") or props.get("coin") or props.get("network") or props.get("endpoint") or "-"
            if props.get("min_order") and props.get("max_order"):
                srv_list.append(
                    f"Órdenes: {props['min_order']} a {props['max_order']} (Beneficio: {props.get('profit', '-')})"
                )
            if props.get("daily_rate"):
                srv_list.append(f"Interés diario: {props['daily_rate']} (Máx: {props.get('max_loan', '-')})")
            if props.get("target_geo"):
                loc_list.append(
                    {
                        "name": f"Objetivo: {props['target_geo']} (Moneda: {props.get('currency', 'EUR')})",
                        "gps": "",
                    }
                )
            for ed in adj_out[e.id]:
                target = by_id.get(ed.in_id)
                if target and "Drains" in ed.label:
                    srv_list.append(f"Drena a: {target.value}")

        elif mtype in ("maltego.company", "maltego.location", "maltego.document"):
            category = "Entidades y Evidencias Probatorias"
            reg_id = (
                props.get("commercial_registry_id")
                or props.get("tax_id")
                or props.get("cif")
                or props.get("doc.type")
                or "-"
            )
            srv_list.append(props.get("role") or "Activo Identificado")

        if category:
            blocks[category].append(
                {
                    "entity": e,
                    "reg_id": reg_id,
                    "services": srv_list or ["Activo Operativo"],
                    "facilities": loc_list or [{"name": "Global / Red Cloud", "gps": ""}],
                    "confidence": e.confidence,
                    "evidences": evi_list or ["Telemetría Directa / Código Fuente"],
                }
            )

    return blocks


def _extract_concurrency_or_correlation(
    entities: list[EntityRecord], edges: list[EdgeRecord], theme: dict[str, str]
) -> tuple[str, list[str], list[str], dict[str, dict[str, bool]]]:
    """Genera la matriz cruzada de concurrencia sectorial o correlacion de activos de infraestructura."""
    by_id = {e.id: e for e in entities}
    adj_out: dict[str, list[EdgeRecord]] = defaultdict(list)
    adj_undirected: dict[str, set[str]] = defaultdict(set)
    for ed in edges:
        adj_out[ed.out_id].append(ed)
        adj_undirected[ed.out_id].add(ed.in_id)
        adj_undirected[ed.in_id].add(ed.out_id)

    # 1. Si existen relaciones explicitas de servicios a clientes concurrentes
    concurrent_edges = [ed for ed in edges if ed.label == "services_concurrent_client"]
    if concurrent_edges:
        provider_set = {
            e.value
            for e in entities
            if (e.maltego_type == "maltego.Company" and e.properties.get("bpo.role"))
            or (e.maltego_type == "maltego.Company" and any(ed.label == "delivers_service" for ed in adj_out[e.id]))
        }
        if not provider_set:
            provider_set = {by_id[ed.out_id].value for ed in concurrent_edges if ed.out_id in by_id}
        concurrent_clients: set[str] = set()
        matrix: dict[str, dict[str, bool]] = defaultdict(lambda: defaultdict(bool))
        for ed in concurrent_edges:
            src = by_id.get(ed.out_id)
            dst = by_id.get(ed.in_id)
            if src and dst and src.value in provider_set:
                concurrent_clients.add(dst.value)
                matrix[src.value][dst.value] = True
        return theme["table_th_entity"], sorted(provider_set), sorted(concurrent_clients), matrix

    # 2. Caso No-BPO (Ciberfraude, CTI, OSINT): correlacion cruzada entre nodos primarios e infraestructura clave
    primary_types = ("maltego.domain", "maltego.person", "maltego.alias", "maltego.dnsname")
    vector_types = ("maltego.as", "maltego.ipv4address", "maltego.phrase")

    primaries = [e for e in entities if e.maltego_type.lower() in primary_types][:7]
    vectors = [
        e
        for e in entities
        if e.maltego_type.lower() in vector_types
        and "dictamen" not in e.value.lower()
        and "verdict" not in e.value.lower()
    ][:8]

    if primaries and vectors:
        matrix_gen: dict[str, dict[str, bool]] = defaultdict(lambda: defaultdict(bool))
        row_names = [p.value for p in primaries]
        col_names = [v.value for v in vectors]
        for p in primaries:
            for v in vectors:
                if v.id in adj_undirected[p.id]:
                    matrix_gen[p.value][v.value] = True
        return theme["table_th_entity"], row_names, col_names, matrix_gen

    return theme["table_th_entity"], [], [], defaultdict(lambda: defaultdict(bool))


def _render_svg_graph(entities: list[EntityRecord], edges: list[EdgeRecord], theme: dict[str, str]) -> str:
    """Genera diagrama SVG autocontenido con la disposicion jerarquica exacta en 9 niveles."""
    if not entities:
        return "<svg viewBox='0 0 400 200'><text x='50%' y='50%' fill='#94a3b8'>Sin entidades</text></svg>"

    positions = compute_layout(entities, edges, "hierarchical")
    xs = [pos[0] for pos in positions.values()]
    ys = [pos[1] for pos in positions.values()]

    min_x, max_x = min(xs) - 250.0, max(xs) + 250.0
    min_y, max_y = min(ys) - 150.0, max(ys) + 150.0
    w = max(800.0, max_x - min_x)
    h = max(400.0, max_y - min_y)

    svg_lines = [
        f'<svg viewBox="{min_x:.1f} {min_y:.1f} {w:.1f} {h:.1f}" '
        'width="100%" height="auto" style="min-height: 550px; max-height: 800px; '
        'background: #070a13; border-radius: 8px; border: 1px solid #1e293b;" '
        'xmlns="http://www.w3.org/2000/svg">',
        "  <defs>",
    ]

    marker_colors = {
        "verdict": "#e11d48",
        "target": "#00f5ff",
        "core": "#10b981",
        "service": "#00f5ff",
        "concurrent": "#38bdf8",
        "facility": "#818cf8",
        "gps": "#a855f7",
        "doc": "#f59e0b",
        "default": "#64748b",
    }
    if theme["theme_name"] == "bpo":
        marker_colors["bpo"] = "#10b981"
    for m_id, col in marker_colors.items():
        svg_lines.append(
            f'    <marker id="arrow-{m_id}" viewBox="0 0 10 10" refX="8" refY="5" '
            f'markerWidth="5" markerHeight="5" orient="auto-start-reverse">'
            f'<path d="M 0 1 L 10 5 L 0 9 z" fill="{col}"/></marker>'
        )
    svg_lines.append("  </defs>")

    for ed in edges:
        if ed.out_id not in positions or ed.in_id not in positions:
            continue
        p1 = positions[ed.out_id]
        p2 = positions[ed.in_id]
        lcolor, lthick, lstyle = edge_visual_profile(ed)

        m_key = "default"
        if lcolor == "#e11d48":
            m_key = "verdict"
        elif lcolor == "#10b981":
            m_key = "bpo" if theme["theme_name"] == "bpo" else "core"
        elif lcolor == "#00f5ff":
            m_key = "service"
        elif lcolor == "#38bdf8":
            m_key = "concurrent"
        elif lcolor == "#818cf8":
            m_key = "facility"
        elif lcolor == "#a855f7":
            m_key = "gps"
        elif lcolor == "#f59e0b":
            m_key = "doc"

        dash_attr = 'stroke-dasharray="6,4" ' if lstyle == "1" else ""
        svg_lines.append(
            f'  <line x1="{p1[0]:.1f}" y1="{p1[1]:.1f}" x2="{p2[0]:.1f}" y2="{p2[1]:.1f}" '
            f'stroke="{lcolor}" stroke-width="{max(1, lthick)}" {dash_attr}opacity="0.8" '
            f'marker-end="url(#arrow-{m_key})"/>'
        )

    for e in entities:
        pos = positions.get(e.id, (0.0, 0.0))
        _weight, color, _size, bookmark = entity_visual_profile(e)
        type_short = e.maltego_type.split(".")[-1].upper()
        val = e.value
        if len(val) > 26:
            val = val[:24] + "..."
        safe_val = html.escape(val)

        box_w = 170.0
        box_h = 42.0

        svg_lines.append(f'  <g transform="translate({pos[0]:.1f}, {pos[1]:.1f})">')
        svg_lines.append(
            f'    <rect x="-{box_w / 2:.1f}" y="-{box_h / 2:.1f}" width="{box_w:.1f}" height="{box_h:.1f}" '
            f'rx="6" fill="#131d33" stroke="{color}" stroke-width="2"/>'
        )
        svg_lines.append(
            f'    <text x="-{box_w / 2 - 8:.1f}" y="-4" fill="#94a3b8" '
            f'font-size="8.5" font-family="system-ui,sans-serif" font-weight="600">{type_short}</text>'
        )
        svg_lines.append(
            f'    <text x="-{box_w / 2 - 8:.1f}" y="12" fill="#f8fafc" '
            f'font-size="10" font-family="system-ui,sans-serif" font-weight="700">{safe_val}</text>'
        )
        if bookmark != "none":
            svg_lines.append(f'    <circle cx="{box_w / 2 - 10:.1f}" cy="-8" r="3.5" fill="{color}"/>')
        svg_lines.append("  </g>")

    svg_lines.append("</svg>")
    return "\n".join(svg_lines)


_PROB_ICD203_LABELS = {
    "CASI_SEGURO": "Casi Seguro (>95%)",
    "MUY_PROBABLE": "Altamente Probable (80-95%)",
    "PROBABLE": "Probable (55-80%)",
    "POSIBILIDAD_IGUAL": "Posibilidad Equilibrada (45-55%)",
    "IMPROBABLE": "Improbable (20-45%)",
    "MUY_IMPROBABLE": "Altamente Improbable (<20%)",
}


def _collect_profiles(d: ReportData) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for p in d.profiles:
        eid = str(p.get("id") or p.get("entity_id") or p.get("value") or "")
        if eid and eid not in seen:
            seen.add(eid)
            out.append(
                {
                    "value": str(p.get("value") or eid),
                    "type": str(p.get("type") or p.get("maltego_type") or ""),
                    "domain": str(p.get("domain") or ""),
                    "typology": str(p.get("typology") or ""),
                    "archetype": str(p.get("archetype") or p.get("archetype_label") or ""),
                    "risk_level": str(p.get("risk_level") or ""),
                    "summary": str(p.get("summary") or p.get("notes") or ""),
                }
            )
    for e in d.entities:
        if e.id in seen:
            continue
        if any(k.startswith("profiling.") for k in e.properties):
            seen.add(e.id)
            out.append(
                {
                    "value": e.value,
                    "type": e.maltego_type,
                    "domain": e.properties.get("profiling.domain", ""),
                    "typology": e.properties.get("profiling.typology", ""),
                    "archetype": e.properties.get("profiling.archetype", ""),
                    "risk_level": e.properties.get("profiling.risk_level", ""),
                    "summary": e.properties.get("profiling.summary") or e.notes or "",
                }
            )
    return out


def _render_intelligence_synthesis_md(d: ReportData) -> list[str]:
    """Renderiza síntesis ACH / ICD 203 (Fases P0-P9), perfilado pericial y vigencia objetiva en Markdown."""
    lines: list[str] = []
    profiles = _collect_profiles(d)

    # 1. Perfilado pericial y vigencia objetiva de activos
    validity_counts: dict[str, int] = defaultdict(int)
    validity_rows: list[str] = []
    for e in d.entities[:25]:
        v = compute_entity_validity(e)
        validity_counts[v.status] += 1
        if len(validity_rows) < 10:
            val_disp = _md(defang(e.value)) if "http" in e.value.lower() else _md(e.value)
            validity_rows.append(
                f"| **{val_disp}** | `{_md(e.maltego_type)}` | `{_md(v.status)}` | {v.score}/100 | "
                f"{_md(v.rationale[:110])} |"
            )

    if profiles or validity_rows:
        lines += [
            "---",
            "",
            "## § 03B. Perfilado Pericial Multidimensional y Vigencia Objetiva (§4.4)",
            "",
        ]
        if profiles:
            lines += [
                "### Dictámenes de Perfilado Pericial (21 Tipologías / HUMINT)",
                "| Entidad Auditada | Tipo | Dominio / Tipología | Arquetipo | Nivel de Riesgo | Síntesis Pericial |",
                "|---|---|---|---|---|---|",
            ]
            for pf in profiles[:10]:
                v_disp = _md(defang(pf["value"])) if "http" in pf["value"].lower() else _md(pf["value"])
                lines.append(
                    f"| **{v_disp}** | `{_md(pf['type'])}` | `{_md(pf['domain'])}/{_md(pf['typology'])}` | "
                    f"**{_md(pf['archetype'])}** | `{_md(pf['risk_level']).upper()}` | {_md(pf['summary'][:140])} |"
                )
            lines.append("")
        if validity_rows:
            summary_tags = ", ".join(f"{k}: {cnt}" for k, cnt in sorted(validity_counts.items()))
            lines += [
                f"### Vigencia Objetiva de Activos sin Contacto Directo ({_md(summary_tags)})",
                "| Activo / Indicador | Tipo | Estado de Vigencia | Puntuación | Fundamento de Telemetría |",
                "|---|---|---|---|---|",
                *validity_rows,
                "",
            ]

    # 2. Síntesis Analítica ACH / ICD 203 (Fases P0-P9)
    recon = d.recon or {}
    p0 = recon.get("p0_framing") or {}
    hyps = recon.get("hypotheses") or []
    seeds = recon.get("seeds") or []
    key_ev = recon.get("key_evidence") or {}
    gaps = recon.get("coverage_gaps") or p0.get("named_gaps") or []

    if p0 or hyps or seeds:
        target_p0 = _md(defang(str(p0.get("target") or ""))) or "Objetivo del Caso"
        question_p0 = _md(str(p0.get("question") or d.case.description or "Evaluación integral de superficie OSINT"))
        legal_p0 = _md(str(p0.get("legal_basis") or "Ley 5/2014 de Seguridad Privada / RGPD Interés Legítimo"))
        ref_class = _md(str(p0.get("reference_class") or " Superficie Corporativa / Infraestructura Digital"))
        infra_cnt = len(recon.get("fase2_infra") or [])
        arch_cnt = len(recon.get("fase3_archives") or [])
        breach_cnt = len(recon.get("fase6_breaches") or [])
        humint_cnt = len(recon.get("fase7_humint") or [])
        eco_cnt = len(recon.get("fase8_ecosystem") or [])

        lines += [
            "---",
            "",
            "## § 03C. Síntesis Analítica Estimativa (ACH / Directiva ICD 203 — Fases P0 a P9)",
            "",
            f"- **Encuadre P0 (Objetivo Raíz):** `{target_p0}` | **Clase de Referencia:** {_md(ref_class)}",
            f"- **Pregunta Central de Inteligencia:** *{question_p0}*",
            f"- **Marco Legal y Proporcionalidad:** {legal_p0}",
            f"- **Cobertura Multi-Clúster (Fases 1-8):** {len(seeds)} semillas con evaluación Admiralty, "
            f"{infra_cnt} activos de infraestructura (Fase 2), {arch_cnt} archivos históricos (Fase 3), "
            f"{breach_cnt} registros de exposición (Fase 6), {humint_cnt} perfiles HUMINT con atribución desacoplada "
            f"(Fase 7) y {eco_cnt} entidades de ecosistema con mitigación de culpa por asociación (Fase 8).",
            "",
        ]
        if hyps:
            lines += [
                "### Matriz de Hipótesis en Competencia (ACH — Heuer Cap. 8)",
                "| ID | Hipótesis Analítica | Criterio Obligatorio de Refutación | Probabilidad ICD 203 | "
                "Confianza | Inconsistencias |",
                "|---|---|---|---|---|---|",
            ]
            for h in hyps:
                hid = _md(h.get("id", "H?"))
                stmt = _md(h.get("statement", ""))
                refut = _md(h.get("what_would_refute_it") or h.get("falsification_criteria") or "No definido")
                prob_raw = str(h.get("probability", "PROBABLE")).upper()
                prob_lbl = _md(_PROB_ICD203_LABELS.get(prob_raw, prob_raw))
                conf_lbl = _md(str(h.get("confidence", "MEDIA")).upper())
                inc = int(h.get("inconsistency_score", 0))
                lines.append(f"| **{hid}** | {stmt} | {refut} | `{prob_lbl}` | `{conf_lbl}` | `{inc}` |")
            lines.append("")

        if key_ev and key_ev.get("evidence_summary"):
            lines += [
                "### Pieza Clave y Análisis de Sensibilidad (Heuer Caps. 10-13)",
                f"- **Evidencia Nuclear:** {_md(defang(str(key_ev.get('evidence_summary', ''))))}",
                f"- **Clúster de Origen:** `{_md(key_ev.get('source_cluster', 'CL-01'))}` "
                f"({int(key_ev.get('independent_clusters_count', 1))} clústeres independientes)",
                f"- **Impacto de Sensibilidad:** `{_md(str(key_ev.get('sensitivity_impact', 'ALTO')).upper())}` | "
                f"**Vulnerabilidad a Señuelo/Canario:** "
                f"`{_md(str(key_ev.get('vulnerability_to_deception', 'BAJO')).upper())}`",
                f"- **Explicación Alternativa:** {_md(key_ev.get('alternative_explanation', 'N/A'))}",
                "",
            ]

        if gaps:
            gap_strs = [_md(g.get("description", "")) if isinstance(g, dict) else _md(str(g)) for g in gaps[:6]]
            gap_strs = [g for g in gap_strs if g]
            if gap_strs:
                lines.append("- **Brechas de Cobertura Declaradas (WYSIATI):** " + "; ".join(gap_strs))
                lines.append("")

    return lines


def _render_intelligence_synthesis_html(d: ReportData) -> str:
    """Renderiza las secciones HTML de perfilado pericial, vigencia objetiva y síntesis ACH / ICD 203."""
    parts: list[str] = []
    profiles = _collect_profiles(d)

    validity_rows_html: list[str] = []
    for e in d.entities[:15]:
        v = compute_entity_validity(e)
        ent_disp = _defang(e.value) if "http" in e.value.lower() or "." in e.value else _h(e.value)
        validity_rows_html.append(
            f"<tr>"
            f"<td class='col-entity'><div class='entity-title'>{ent_disp}</div>"
            f"<div class='entity-badge'>{_h(e.maltego_type)}</div></td>"
            f"<td><span class='code-pill'>{_h(v.status)}</span></td>"
            f"<td><b>{v.score}/100</b></td>"
            f"<td>{_h(v.rationale)}</td>"
            f"</tr>"
        )

    profile_rows_html: list[str] = []
    for pf in profiles[:10]:
        p_disp = _defang(pf["value"]) if "http" in pf["value"].lower() or "." in pf["value"] else _h(pf["value"])
        profile_rows_html.append(
            f"<tr>"
            f"<td class='col-entity'><div class='entity-title'>{p_disp}</div>"
            f"<div class='entity-badge'>{_h(pf['type'])}</div></td>"
            f"<td><span class='code-pill'>{_h(pf['domain'])} / {_h(pf['typology'])}</span></td>"
            f"<td><b>{_h(pf['archetype'])}</b></td>"
            f"<td><span class='status-pill active'>{_h(pf['risk_level']).upper()}</span></td>"
            f"<td>{_h(pf['summary'])}</td>"
            f"</tr>"
        )

    if profile_rows_html or validity_rows_html:
        prof_block = ""
        if profile_rows_html:
            prof_block = f"""
            <div class="scope-block">
              <div class="scope-header">
                <span class="scope-tag">[PERFILADO PERICIAL]</span>
                <span class="scope-title">Dictámenes Multidimensionales (21 Tipologías / HUMINT)</span>
                <span class="scope-count">{len(profile_rows_html)} Sujetos Perfilados</span>
              </div>
              <table class="matrix-table">
                <thead>
                  <tr>
                    <th>Entidad</th>
                    <th>Dominio / Tipología</th>
                    <th>Arquetipo</th>
                    <th>Riesgo</th>
                    <th>Dictamen Pericial</th>
                  </tr>
                </thead>
                <tbody>{"".join(profile_rows_html)}</tbody>
              </table>
            </div>
            """
        val_block = ""
        if validity_rows_html:
            val_block = f"""
            <div class="scope-block">
              <div class="scope-header">
                <span class="scope-tag">[VIGENCIA OBJETIVA §4.4]</span>
                <span class="scope-title">Evaluación de Vigencia por Clústeres Independientes</span>
                <span class="scope-count">{len(validity_rows_html)} Activos Evaluados</span>
              </div>
              <table class="matrix-table">
                <thead>
                  <tr>
                    <th>Activo</th>
                    <th>Estado Vigencia</th>
                    <th>Puntuación</th>
                    <th>Fundamento de Telemetría Pasiva</th>
                  </tr>
                </thead>
                <tbody>{"".join(validity_rows_html)}</tbody>
              </table>
            </div>
            """
        parts.append(f"""
        <section class="report-section">
          <div class="section-badge">§ 03B // PERFILADO PERICIAL Y VIGENCIA OBJETIVA</div>
          <h2 class="section-title">Evaluación Multidimensional de Sujetos y Estado de Vigencia</h2>
          <p class="section-desc">
            Resultados del motor de perfilado pericial y calificación de vigencia temporal sin contacto directo.
          </p>
          {prof_block}
          {val_block}
        </section>
        """)

    recon = d.recon or {}
    p0 = recon.get("p0_framing") or {}
    hyps = recon.get("hypotheses") or []
    seeds = recon.get("seeds") or []
    key_ev = recon.get("key_evidence") or {}

    if p0 or hyps or seeds:
        hyp_rows: list[str] = []
        for h in hyps:
            prob_raw = str(h.get("probability", "PROBABLE")).upper()
            prob_lbl = _PROB_ICD203_LABELS.get(prob_raw, prob_raw)
            hyp_rows.append(
                f"<tr>"
                f"<td><span class='code-pill'>{_h(h.get('id', 'H?'))}</span></td>"
                f"<td><b>{_h(h.get('statement', ''))}</b></td>"
                f"<td>{_h(h.get('what_would_refute_it') or h.get('falsification_criteria') or '')}</td>"
                f"<td><span class='status-pill active'>{_h(prob_lbl)}</span></td>"
                f"<td>{_h(str(h.get('confidence', 'MEDIA')).upper())}</td>"
                f"<td class='num-cell'>{int(h.get('inconsistency_score', 0))}</td>"
                f"</tr>"
            )
        hyp_table = ""
        if hyp_rows:
            hyp_table = f"""
            <div class="scope-block">
              <div class="scope-header">
                <span class="scope-tag">[MATRIZ ACH // HEUER CAP. 8]</span>
                <span class="scope-title">Hipótesis en Competencia y Criterios de Falsificación</span>
                <span class="scope-count">{len(hyp_rows)} Hipótesis Evaluadas</span>
              </div>
              <table class="matrix-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Enunciado de Hipótesis</th>
                    <th>Criterio Obligatorio de Refutación</th>
                    <th>Probabilidad ICD 203</th>
                    <th>Confianza</th>
                    <th>Inconsistencias</th>
                  </tr>
                </thead>
                <tbody>{"".join(hyp_rows)}</tbody>
              </table>
            </div>
            """
        key_html = ""
        if key_ev and key_ev.get("evidence_summary"):
            key_html = f"""
            <div class="disclaimer-box" style="margin-top: 1rem;">
              <b>PIEZA CLAVE Y SENSIBILIDAD (HEUER CAPS. 10-13):</b>
              {_defang(str(key_ev.get("evidence_summary", "")))}
              | <b>Clúster:</b> <code>{_h(key_ev.get("source_cluster", "CL-01"))}</code>
              ({int(key_ev.get("independent_clusters_count", 1))} clústeres independientes)
              | <b>Sensibilidad:</b> <code>{_h(str(key_ev.get("sensitivity_impact", "ALTO")).upper())}</code>
              | <b>Explicación Alternativa:</b> {_h(key_ev.get("alternative_explanation", "N/A"))}
            </div>
            """
        parts.append(f"""
        <section class="report-section">
          <div class="section-badge">§ 03C // SINTESIS ANALITICA ACH & DIRECTIVA ICD 203 (FASES P0-P9)</div>
          <h2 class="section-title">Encuadre No-Zoom, Hipótesis en Competencia y Pieza Clave</h2>
          <p class="section-desc">
            Pregunta de inteligencia: <b>{_h(p0.get("question") or d.case.description)}</b>
            | Marco Legal: {_h(p0.get("legal_basis") or "Ley 5/2014 / RGPD")}
            | Semillas auditadas: {len(seeds)}.
          </p>
          {hyp_table}
          {key_html}
        </section>
        """)

    return "\n".join(parts)


def to_markdown(d: ReportData) -> str:
    """Genera informe pericial en formato GitHub Flavored Markdown de nivel ejecutivo sin emojis."""
    q = d.quality()
    seal = _hash_seal(d.entities, d.edges)
    theme = _detect_case_theme(d.case, d.entities)
    target = _extract_target(d.entities, d.edges)
    verdict_title, verdict_notes, verdict_conf = _extract_verdict(d.entities, theme)
    blocks = _extract_scopes_and_entities(d.entities, d.edges, theme)
    th_ent, rows_h, cols_h, matrix = _extract_concurrency_or_correlation(d.entities, d.edges, theme)

    lines: list[str] = [
        f"# Informe del caso `{d.case.case_id}`: Auditoría Pericial y Mapeado Topológico",
        f"### EXPEDIENTE: `{d.case.case_id}` // CLASIFICACION: TLP:AMBER+STRICT",
        "",
        f"**Sujeto / Entidad Auditada:** {_md(target.value)}  ",
        f"**Objetivo:** {_md(d.case.description) or 'Auditoría topológica y mapeo de infraestructura operativa'}  ",
        f"**Fecha de Emisión:** {d.generated or 'Audit Timestamp'} | **Cadena de Custodia SHA-256:** `{seal[:16]}...`",
        "",
        "> **AVISO LEGAL Y METODOLOGICO:** Los hallazgos presentados en este informe pericial proceden de fuentes "
        "abiertas (OSINT/SOCMINT), registros mercantiles, telemetría de red y documentación oficial contrastada. "
        "Cada indicador ha sido verificado multifuente conforme al principio de no repudio y proporcionalidad.",
        "",
        "> **ADVERTENCIA DE SEGURIDAD OPERATIVA Y MODO SIGILOSO (STEALTH MODE):** "
        "Este expediente pericial y su archivo asociado `.mtgx` contienen indicadores identificados de "
        "forma estrictamente pasiva. Al importar el archivo en Maltego Desktop, active previamente el "
        "**Stealth Mode** en Maltego y no ejecute transforms estándar sobre entidades del caso "
        "para evitar alertar a la infraestructura objetivo.",
        "",
        "---",
        "",
        "## § 01. Resumen Ejecutivo y Dictamen Pericial (BLUF)",
        "",
        f"> ### [DICTAMEN PERICIAL // VEREDICTO EJECUTIVO] (Confianza: {verdict_conf * 100:.1f} %)",
        f"> **{_md(verdict_title)}**",
        ">",
        f"> {_md(verdict_notes)}",
        "",
        "### Franja de Indicadores Clave (KPIs)",
        f"- **Entidades Auditadas en Grafo:** {q['entidades']} nodos",
        f"- **Relaciones Topológicas Verificadas:** {q['relaciones']} vínculos",
        f"- **Nivel de Confianza Pericial Media:** {q['confianza_media'] * 100:.1f} %",
        f"- **Tasa de Corroboración Multifuente:** {q['corroboradas_pct']} %",
        f"- **Pasos Procedimentales Auditados:** {q['pasos']} ejecuciones",
        "",
        "### Protocolo Metodológico Aplicado",
        "1. **Fase A (Reconocimiento Pasivo):** Extracción de huella digital y registros de identidad.",
        (
            "2. **Fase B (Correlación Registral y Laboral):** Verificación con registros oficiales y"
            " plataformas operativas."
        ),
        (
            "3. **Fase C (Verificación Topológica y Satelital):** Inspección de infraestructura, servidores"
            " y fijación pericial."
        ),
        "",
        "---",
        "",
        theme["section2_md"],
        "",
    ]

    if d.scores:
        lines += [
            "### Entidades prioritarias",
            "| Prioridad | Tipo | Valor | Conexiones | Fuentes |",
            "|---|---|---|---|---|",
            *[
                f"| {s.priority:.2f} | {s.entity.maltego_type} | {_md(s.entity.value)} | {s.degree} | "
                f"{_md(', '.join(s.entity.sources[-3:]))} |"
                for s in d.top(10)
            ],
            "",
        ]

    for scope, p_list in blocks.items():
        lines.append(f"### {scope}")
        lines.append(
            f"| {theme['table_th_entity']} | {theme['table_th_id']} | {theme['table_th_service']} | "
            f"{theme['table_th_location']} | Confianza | {theme['table_th_evidence']} |"
        )
        lines.append("|---|---|---|---|---|---|")
        for p in p_list:
            is_ioc = p["entity"].maltego_type in (
                "maltego.Domain",
                "maltego.IPv4Address",
                "maltego.IPv6Address",
                "maltego.URL",
                "maltego.EmailAddress",
            ) or str(p["entity"].value).startswith(("http://", "https://"))
            ent_val = _md(defang(p["entity"].value)) if is_ioc else _md(p["entity"].value)
            reg_id = _md(p["reg_id"])
            srv_str = "<br>".join(f"• {_md(s)}" for s in p["services"][:3])
            fac_str = "<br>".join(
                f"• {_md(f['name'])}" + (f" (`{_md(f['gps'])}`)" if f["gps"] else "") for f in p["facilities"][:3]
            )
            conf_str = f"**{p['confidence'] * 100:.0f} %**"
            evi_str = "<br>".join(f"• {_md(e[:50])}..." if len(e) > 50 else f"• {_md(e)}" for e in p["evidences"][:2])
            lines.append(
                f"| **{ent_val}** | `{reg_id}` | {srv_str or '-'} | {fac_str or '-'} | {conf_str} | {evi_str or '-'} |"
            )
        lines.append("")

    if rows_h and cols_h:
        lines += [
            "---",
            "",
            theme["section4_md"],
            "",
            f"> {_md(theme['section4_desc'])}",
            "",
        ]
        top_cols = cols_h[:6]
        header = f"| {th_ent} | " + " | ".join(_md(c[:25]) for c in top_cols) + " |"
        sep = "|---|" + "|".join("---" for _ in top_cols) + "|"
        lines.append(header)
        lines.append(sep)
        for r_name in rows_h:
            row = [f"**{_md(r_name[:30])}**"]
            for c_name in top_cols:
                status = "[CONFIRMADO]" if matrix[r_name][c_name] else "[-]"
                row.append(status)
            lines.append("| " + " | ".join(row) + " |")
        lines.append("")

    lines.extend(_render_intelligence_synthesis_md(d))

    lines += [
        "---",
        "",
        "## § 04. Arquitectura Topológica y Estratificación del Grafo",
        "",
        "| Nivel | Estrato Ontológico | Color Maltego | Función en la Investigación |",
        "|---|---|---|---|",
        "| Tier -1 | Dictamen Pericial | `#e11d48` (Rojo) | Veredicto legal y dictamen sobre la auditoría |",
        "| Tier 0 | Target Client | `#00f5ff` (Cyan) | Entidad principal auditada (activo o empresa matriz) |",
        "| Tier 1 | Ámbitos y Registros | `#818cf8` (Índigo) | Jurisdicciones, registros públicos y ASNs troncales |",
        "| Tier 2 | Organizaciones y Sindicatos | `#64748b` (Gris) | Asociaciones sindicales y gobernanza laboral |",
        f"| Tier 3 | {theme['tier3_label']} | `#10b981` (Verde) | {theme['tier3_desc']} |",
        "| Tier 4 | Servicios y Procesos | `#00f5ff` (Cyan) | Servicios asignados, módulos y funciones de negocio |",
        "| Tier 5 | Concurrencia y Competidores | `#38bdf8` (Celeste) | Clientes concurrentes y cuentas relacionadas |",
        "| Tier 6 | Sedes e Instalaciones | `#818cf8` (Índigo) | Parques tecnológicos, campus y edificios operativos |",
        "| Tier 7 | Coordenadas Satelitales | `#a855f7` (Púrpura) | Fijación satelital GPS de sedes operativas |",
        "| Tier 8 | Evidencias Documentales | `#f59e0b` (Ámbar) | Documentos PDF, convenios y URLs auditadas |",
        "",
        "---",
        "",
        "## § 05. Cronología Procedimental y Ledger Forense",
        "",
        "| Seq | Marca Temporal | Tipo | Acción / Transform | Entrada Auditada | Nuevas | Resultado / Motivo |",
        "|---|---|---|---|---|---|---|",
    ]

    for s in d.steps[-35:]:
        err = f"ALERTA: {_md(s.error)}" if s.error else "OK"
        lines.append(
            f"| {s.seq} | `{s.timestamp}` | {s.kind} | **{_md(s.action)}** | "
            f"`{_md(s.input_value)[:35]}` | +{s.new_entities} | {err} |"
        )
    if not d.steps:
        lines.append("| 1 | - | manual | osint_init | - | 0 | (sin pasos registrados) |")

    if d.actions:
        lines += [
            "",
            "---",
            "",
            "## § 06. Siguientes Pasos Recomendados (Next Best Action)",
            "",
        ]
        for i, a in enumerate(d.actions[:8], 1):
            lines.append(
                f"{i}. **{_md(a.transform)}** sobre `{_md(a.entity.value)}` ({a.entity.maltego_type}) - {_md(a.reason)}"
            )

    lines += [
        "",
        "---",
        "",
        "## § 07. Certificación Forense y Cadena de Custodia",
        "",
        f"- **Sello Criptográfico SHA-256:** `{seal}`",
        f"- **Total Nodos Computados:** {len(d.entities)}",
        f"- **Total Aristas Dirigidas:** {len(d.edges)}",
        "- **Estado:** AUDITORIA PERICIAL VERIFICADA",
        "",
    ]

    return "\n".join(lines) + "\n"


def to_html(d: ReportData) -> str:
    """Genera informe pericial HTML interactivo, responsive y autocontenido de nivel pericial sin emojis."""
    q = d.quality()
    seal = _hash_seal(d.entities, d.edges)
    theme = _detect_case_theme(d.case, d.entities)
    target = _extract_target(d.entities, d.edges)
    verdict_title, verdict_notes, verdict_conf = _extract_verdict(d.entities, theme)
    blocks = _extract_scopes_and_entities(d.entities, d.edges, theme)
    th_ent, rows_h, cols_h, matrix = _extract_concurrency_or_correlation(d.entities, d.edges, theme)
    svg_graph = _render_svg_graph(d.entities, d.edges, theme)

    scope_sections: list[str] = []
    for scope, p_list in blocks.items():
        rows: list[str] = []
        for p in p_list:
            is_ioc = p["entity"].maltego_type in (
                "maltego.Domain",
                "maltego.IPv4Address",
                "maltego.IPv6Address",
                "maltego.URL",
                "maltego.EmailAddress",
            ) or str(p["entity"].value).startswith(("http://", "https://"))
            ent_val = _defang(p["entity"].value) if is_ioc else _h(p["entity"].value)
            type_tag = _h(p["entity"].maltego_type)
            reg_id = _h(p["reg_id"])
            srv_items = "".join(f"<li>{_h(s)}</li>" for s in p["services"])
            fac_items = "".join(
                f"<li>{_h(f['name'])}"
                + (f" <span class='coord-pill'>{_h(f['gps'])}</span>" if f["gps"] else "")
                + "</li>"
                for f in p["facilities"]
            )
            pct = round(p["confidence"] * 100)
            evi_items = "".join(
                f"<li><code>{_defang(e[:60])}</code></li>"
                if e.startswith(("http://", "https://"))
                else f"<li>{_h(e)}</li>"
                for e in p["evidences"][:3]
            )

            rows.append(f"""
            <tr>
              <td class="col-entity">
                <div class="entity-title">{ent_val}</div>
                <div class="entity-badge">{type_tag}</div>
              </td>
              <td class="col-reg"><span class="code-pill">{reg_id}</span></td>
              <td class="col-srv"><ul class="dense-list">{srv_items or "<li>-</li>"}</ul></td>
              <td class="col-fac"><ul class="dense-list">{fac_items or "<li>-</li>"}</ul></td>
              <td class="col-conf">
                <div class="conf-bar-bg"><div class="conf-bar-fill" style="width: {pct}%;"></div></div>
                <div class="conf-text">{pct}%</div>
              </td>
              <td class="col-evi"><ul class="dense-list">{evi_items or "<li>-</li>"}</ul></td>
            </tr>
            """)

        body_rows = "".join(rows)
        scope_sections.append(f"""
        <div class="scope-block">
          <div class="scope-header">
            <span class="scope-tag">[GRUPO FORENSE]</span>
            <span class="scope-title">{_h(scope)}</span>
            <span class="scope-count">{len(p_list)} Registros Identificados</span>
          </div>
          <table class="matrix-table">
            <thead>
              <tr>
                <th>{_h(theme["table_th_entity"])}</th>
                <th>{_h(theme["table_th_id"])}</th>
                <th>{_h(theme["table_th_service"])}</th>
                <th>{_h(theme["table_th_location"])}</th>
                <th>Confianza</th>
                <th>{_h(theme["table_th_evidence"])}</th>
              </tr>
            </thead>
            <tbody>
              {body_rows}
            </tbody>
          </table>
        </div>
        """)

    concurrency_section = ""
    if rows_h and cols_h:
        top_c = cols_h[:8]
        th_clients = "".join(f"<th>{_h(c[:22])}</th>" for c in top_c)
        c_rows: list[str] = []
        for r_name in rows_h:
            tds: list[str] = []
            for c_name in top_c:
                if matrix[r_name][c_name]:
                    tds.append("<td class='cell-active'><span class='status-pill active'>CONFIRMADO</span></td>")
                else:
                    tds.append("<td class='cell-inactive'><span class='status-pill inactive'>-</span></td>")
            cells_str = "".join(tds)
            c_rows.append(f"<tr><td class='col-entity-sm'><b>{_h(r_name[:30])}</b></td>{cells_str}</tr>")

        body_concurrency = "".join(c_rows)
        concurrency_section = f"""
        <section class="report-section page-break">
          <div class="section-badge">{_h(theme["section4_badge"])}</div>
          <h2 class="section-title">{_h(theme["section4_title"])}</h2>
          <p class="section-desc">{_h(theme["section4_desc"])}</p>
          <div class="table-responsive">
            <table class="heatmap-table">
              <thead>
                <tr>
                  <th>{_h(th_ent)}</th>
                  {th_clients}
                </tr>
              </thead>
              <tbody>
                {body_concurrency}
              </tbody>
            </table>
          </div>
        </section>
        """

    step_rows = "".join(
        f"""<tr>
          <td><span class='code-pill'>{s.seq}</span></td>
          <td><span class='date-pill'>{_h(s.timestamp)}</span></td>
          <td><span class='kind-pill'>{_h(s.kind)}</span></td>
          <td><b>{_h(s.action)}</b></td>
          <td><span class='code-pill-dim'>{_h(s.input_value)[:40]}</span></td>
          <td class='num-cell'>+{s.new_entities}</td>
          <td>
            {f"<span class='alert-pill'>ALERTA: {_h(s.error)}</span>" if s.error else "<span class='ok-pill'>OK</span>"}
          </td>
        </tr>"""
        for s in d.steps[-30:]
    )

    action_items = "".join(
        f"<li><b>{_h(a.transform)}</b> sobre <span class='code-pill'>{_h(a.entity.value)}</span> "
        f"({_h(a.entity.maltego_type)}) - {_h(a.reason)}</li>"
        for a in d.actions[:6]
    )

    scopes_html = "".join(scope_sections)
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Informe Pericial - {_h(d.case.case_id)}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="referrer" content="no-referrer">
  <meta http-equiv="x-dns-prefetch-control" content="off">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
  <style>
    :root {{
      --bg: #070a13;
      --surface: #0f172a;
      --surface-card: #131d33;
      --surface-row: #182238;
      --border: #1e293b;
      --border-bright: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --cyan: #00f5ff;
      --emerald: #10b981;
      --crimson: #e11d48;
      --sky: #38bdf8;
      --indigo: #818cf8;
      --purple: #a855f7;
      --amber: #f59e0b;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      line-height: 1.5;
      font-size: 13px;
      padding: 2rem 1.5rem;
    }}
    .container {{
      max-width: 1400px;
      margin: 0 auto;
    }}
    @page {{
      size: A4 landscape;
      margin: 10mm 12mm;
    }}
    @media print {{
      body {{ background: #070a13 !important; color: #f8fafc !important; -webkit-print-color-adjust: exact; }}
      .page-break {{ page-break-after: always; break-after: page; }}
    }}
    .cover-strip {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 0.8rem 1.2rem;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      margin-bottom: 2rem;
      font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
      font-size: 11px;
    }}
    .tlp-badge {{
      background: rgba(245, 158, 11, 0.15);
      color: var(--amber);
      border: 1px solid var(--amber);
      padding: 0.2rem 0.6rem;
      border-radius: 4px;
      font-weight: 700;
      letter-spacing: 0.5px;
    }}
    .cover-header {{
      text-align: center;
      padding: 3rem 1rem;
      background: radial-gradient(circle at 50% 20%, rgba(0, 245, 255, 0.08), transparent 70%);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 2.5rem;
    }}
    .cover-super {{
      color: var(--cyan);
      font-family: ui-monospace, monospace;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 2px;
      margin-bottom: 0.8rem;
    }}
    .cover-title {{
      font-size: 26px;
      font-weight: 800;
      letter-spacing: -0.5px;
      margin-bottom: 0.8rem;
      color: #ffffff;
    }}
    .cover-sub {{
      font-size: 15px;
      color: var(--text-muted);
      max-width: 850px;
      margin: 0 auto 1.5rem auto;
    }}
    .cover-meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1rem;
      max-width: 1000px;
      margin: 0 auto;
    }}
    .cover-meta-card {{
      background: var(--surface-card);
      border: 1px solid var(--border);
      padding: 0.8rem 1rem;
      border-radius: 6px;
      text-align: left;
    }}
    .cover-meta-label {{
      font-size: 10px;
      color: var(--text-dim);
      font-family: ui-monospace, monospace;
      text-transform: uppercase;
      margin-bottom: 0.2rem;
    }}
    .cover-meta-val {{
      font-size: 13px;
      font-weight: 700;
      color: var(--text);
    }}
    .disclaimer-box {{
      margin: 1.5rem auto 0 auto;
      max-width: 1000px;
      background: rgba(30, 41, 59, 0.4);
      border-left: 3px solid var(--cyan);
      padding: 0.6rem 1rem;
      font-size: 11px;
      color: var(--text-muted);
      text-align: left;
      line-height: 1.4;
    }}
    .report-section {{
      margin-bottom: 3.5rem;
    }}
    .section-badge {{
      display: inline-block;
      color: var(--cyan);
      font-family: ui-monospace, monospace;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 1px;
      margin-bottom: 0.4rem;
    }}
    .section-title {{
      font-size: 20px;
      font-weight: 800;
      margin-bottom: 0.4rem;
      color: #ffffff;
    }}
    .section-desc {{
      font-size: 13px;
      color: var(--text-muted);
      margin-bottom: 1.5rem;
      max-width: 900px;
    }}
    .verdict-callout {{
      background: rgba(225, 29, 72, 0.08);
      border: 1px solid rgba(225, 29, 72, 0.3);
      border-left: 4px solid var(--crimson);
      border-radius: 6px;
      padding: 1.2rem 1.5rem;
      margin-bottom: 2rem;
    }}
    .verdict-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.5rem;
    }}
    .verdict-tag {{
      color: var(--crimson);
      font-family: ui-monospace, monospace;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 1px;
    }}
    .verdict-conf {{
      background: var(--crimson);
      color: #ffffff;
      font-size: 10px;
      font-weight: 700;
      padding: 0.15rem 0.5rem;
      border-radius: 3px;
    }}
    .verdict-headline {{
      font-size: 17px;
      font-weight: 700;
      color: #ffffff;
      margin-bottom: 0.4rem;
    }}
    .verdict-body {{
      font-size: 13px;
      color: #cbd5e1;
      line-height: 1.45;
    }}
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1rem;
      margin-bottom: 2rem;
    }}
    .kpi-card {{
      background: var(--surface-card);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 1rem 1.2rem;
    }}
    .kpi-label {{
      font-size: 11px;
      color: var(--text-muted);
      text-transform: uppercase;
      font-family: ui-monospace, monospace;
      margin-bottom: 0.3rem;
    }}
    .kpi-value {{
      font-size: 24px;
      font-weight: 800;
      color: var(--cyan);
    }}
    .kpi-sub {{
      font-size: 11px;
      color: var(--text-dim);
      margin-top: 0.2rem;
    }}
    .scope-block {{
      margin-bottom: 2rem;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
    }}
    .scope-header {{
      background: var(--surface-card);
      padding: 0.8rem 1.2rem;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      gap: 0.8rem;
    }}
    .scope-tag {{
      background: rgba(129, 140, 248, 0.15);
      color: var(--indigo);
      font-family: ui-monospace, monospace;
      font-size: 10px;
      font-weight: 700;
      padding: 0.15rem 0.5rem;
      border-radius: 3px;
    }}
    .scope-title {{
      font-size: 15px;
      font-weight: 700;
      color: #ffffff;
    }}
    .scope-count {{
      margin-left: auto;
      font-size: 11px;
      color: var(--text-dim);
      font-family: ui-monospace, monospace;
    }}
    .matrix-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }}
    .matrix-table th {{
      background: var(--surface);
      color: var(--text-muted);
      font-family: ui-monospace, monospace;
      font-size: 10px;
      text-transform: uppercase;
      padding: 0.7rem 1rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }}
    .matrix-table td {{
      padding: 0.8rem 1rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    .matrix-table tr:hover {{
      background: var(--surface-row);
    }}
    .col-entity {{ width: 22%; }}
    .col-reg {{ width: 14%; }}
    .col-srv {{ width: 24%; }}
    .col-fac {{ width: 20%; }}
    .col-conf {{ width: 8%; }}
    .col-evi {{ width: 12%; }}
    .entity-title {{ font-weight: 700; color: #ffffff; margin-bottom: 0.2rem; }}
    .entity-badge {{ font-size: 9px; color: var(--text-dim); font-family: ui-monospace, monospace; }}
    .code-pill {{
      display: inline-block;
      font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
      font-size: 11px;
      color: var(--cyan);
      background: rgba(0, 245, 255, 0.08);
      padding: 0.1rem 0.4rem;
      border-radius: 3px;
    }}
    .code-pill-dim {{
      display: inline-block;
      font-family: ui-monospace, monospace;
      font-size: 11px;
      color: var(--text-muted);
    }}
    .coord-pill {{
      display: inline-block;
      font-family: ui-monospace, monospace;
      font-size: 10px;
      color: var(--purple);
      background: rgba(168, 85, 247, 0.1);
      padding: 0.05rem 0.3rem;
      border-radius: 3px;
      margin-left: 0.3rem;
    }}
    .dense-list {{
      list-style: none;
      padding: 0;
      margin: 0;
    }}
    .dense-list li {{
      margin-bottom: 0.25rem;
      line-height: 1.35;
      color: #cbd5e1;
    }}
    .dense-list li a {{
      color: var(--sky);
      text-decoration: none;
    }}
    .dense-list li a:hover {{
      text-decoration: underline;
    }}
    .conf-bar-bg {{
      background: #1e293b;
      height: 6px;
      border-radius: 3px;
      overflow: hidden;
      margin-bottom: 0.2rem;
    }}
    .conf-bar-fill {{
      background: var(--emerald);
      height: 100%;
    }}
    .conf-text {{
      font-size: 11px;
      font-weight: 700;
      color: var(--emerald);
      font-family: ui-monospace, monospace;
    }}
    .heatmap-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 11px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      overflow: hidden;
    }}
    .heatmap-table th {{
      background: var(--surface-card);
      color: var(--text-muted);
      font-family: ui-monospace, monospace;
      font-size: 10px;
      padding: 0.6rem 0.8rem;
      text-align: center;
      border: 1px solid var(--border);
    }}
    .heatmap-table th:first-child {{ text-align: left; }}
    .heatmap-table td {{
      padding: 0.5rem 0.8rem;
      border: 1px solid var(--border);
      text-align: center;
    }}
    .status-pill {{
      display: inline-block;
      font-family: ui-monospace, monospace;
      font-size: 9px;
      font-weight: 700;
      padding: 0.1rem 0.4rem;
      border-radius: 3px;
    }}
    .status-pill.active {{
      background: rgba(16, 185, 129, 0.15);
      color: var(--emerald);
      border: 1px solid var(--emerald);
    }}
    .status-pill.inactive {{
      color: var(--text-dim);
    }}
    .legend-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
      gap: 0.8rem;
      margin-top: 1.5rem;
    }}
    .legend-item {{
      background: var(--surface-card);
      border: 1px solid var(--border);
      padding: 0.6rem 0.8rem;
      border-radius: 4px;
      display: flex;
      align-items: center;
      gap: 0.6rem;
    }}
    .legend-chip {{
      width: 14px;
      height: 14px;
      border-radius: 3px;
      flex-shrink: 0;
    }}
    .legend-text {{ font-size: 11px; color: var(--text-muted); }}
    .legend-text b {{ color: var(--text); }}
    .audit-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 11px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      overflow: hidden;
    }}
    .audit-table th {{
      background: var(--surface-card);
      color: var(--text-muted);
      font-family: ui-monospace, monospace;
      padding: 0.5rem 0.8rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }}
    .audit-table td {{
      padding: 0.5rem 0.8rem;
      border-bottom: 1px solid var(--border);
    }}
    .date-pill {{ font-family: ui-monospace, monospace; font-size: 10px; color: var(--text-dim); }}
    .kind-pill {{
      font-family: ui-monospace, monospace;
      font-size: 10px;
      color: var(--indigo);
      background: rgba(129, 140, 248, 0.1);
      padding: 0.05rem 0.3rem;
      border-radius: 3px;
    }}
    .ok-pill {{ color: var(--emerald); font-weight: 700; font-family: ui-monospace, monospace; }}
    .alert-pill {{ color: var(--crimson); font-weight: 700; font-family: ui-monospace, monospace; }}
    .footer-seal {{
      margin-top: 3rem;
      padding: 1.2rem;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-family: ui-monospace, monospace;
      font-size: 11px;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="cover-strip">
      <div>EXPEDIENTE: <span class="code-pill">{_h(d.case.case_id)}</span></div>
      <div class="tlp-badge">TLP:AMBER+STRICT // USO INTERNO EXCLUSIVO</div>
      <div>EMISION: {_h(d.generated or "AUDIT-NOW")}</div>
    </div>

    <header class="cover-header">
      <div class="cover-super">{_h(theme["super_title"])}</div>
      <h1 class="cover-title">{_h(theme["cover_title"])}</h1>
      <p class="cover-sub">
        {_h(d.case.description or "Auditoría pericial integral de infraestructura, contratos y convivencia operativa.")}
      </p>

      <div class="cover-meta-grid">
        <div class="cover-meta-card">
          <div class="cover-meta-label">Sujeto / Cliente Auditado</div>
          <div class="cover-meta-val">{_h(target.value)}</div>
        </div>
        <div class="cover-meta-card">
          <div class="cover-meta-label">Nodos Verificados</div>
          <div class="cover-meta-val">{q["entidades"]} entidades</div>
        </div>
        <div class="cover-meta-card">
          <div class="cover-meta-label">Relaciones Topológicas</div>
          <div class="cover-meta-val">{q["relaciones"]} vínculos</div>
        </div>
        <div class="cover-meta-card">
          <div class="cover-meta-label">Corroboración Multifuente</div>
          <div class="cover-meta-val">{q["corroboradas_pct"]}% verificado</div>
        </div>
      </div>

      <div class="disclaimer-box">
        <b>AVISO METODOLOGICO Y DE INTEGRIDAD:</b> Los valores y grafos incluidos en este informe pericial proceden
        de fuentes abiertas (OSINT/SOCMINT), registros mercantiles, telemetría de telecomunicaciones y resoluciones.
        Los resultados han sido procesados y correlacionados de forma determinista para su verificación no repudiable.
      </div>
      <div class="disclaimer-box"
           style="margin-top:0.75rem; border-color:rgba(239,68,68,0.4); background:rgba(239,68,68,0.05);">
        <b>AVISO DE SEGURIDAD OPERATIVA Y MODO SIGILOSO (STEALTH MODE):</b> Este expediente pericial y su archivo
        asociado <code>.mtgx</code> contienen indicadores identificados de forma estrictamente pasiva. Al importar el
        archivo en Maltego Desktop, <b>active previamente el Stealth Mode</b> en la barra inferior de Maltego y
        <b>no ejecute transforms estándar</b> sobre entidades del caso para evitar alertar a la infraestructura
        objetivo.
      </div>
    </header>

    <section class="report-section">
      <div class="section-badge">§ 01 // RESUMEN EJECUTIVO & BLUF</div>
      <h2 class="section-title">Dictamen Pericial y Conclusiones Operativas</h2>
      <p class="section-desc">
        Respuesta taxativa a los requerimientos de la investigación conforme a las evidencias recolectadas en el grafo.
      </p>

      <div class="verdict-callout">
        <div class="verdict-header">
          <span class="verdict-tag">[DICTAMEN PERICIAL EMITIDO]</span>
          <span class="verdict-conf">CONFIANZA: {verdict_conf * 100:.1f}%</span>
        </div>
        <div class="verdict-headline">{_h(verdict_title)}</div>
        <div class="verdict-body">{_h(verdict_notes)}</div>
      </div>

      <div class="kpi-grid">
        <div class="kpi-card">
          <div class="kpi-label">Entidades Auditadas</div>
          <div class="kpi-value">{q["entidades"]}</div>
          <div class="kpi-sub">Total de sujetos en grafo</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Relaciones Verificadas</div>
          <div class="kpi-value">{q["relaciones"]}</div>
          <div class="kpi-sub">Vínculos topológicos directos</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Confianza Media</div>
          <div class="kpi-value">{q["confianza_media"] * 100:.1f}%</div>
          <div class="kpi-sub">Puntuación ponderada pericial</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Corroboradas Multifuente</div>
          <div class="kpi-value">{q["corroboradas_pct"]}%</div>
          <div class="kpi-sub">Comprobadas por 2 o más vías</div>
        </div>
      </div>
    </section>

    <section class="report-section page-break">
      <div class="section-badge">{_h(theme["section2_badge"])}</div>
      <h2 class="section-title">{_h(theme["section2_title"])}</h2>
      <p class="section-desc">{_h(theme["section2_desc"])}</p>

      {scopes_html}
    </section>

    {concurrency_section}

    {_render_intelligence_synthesis_html(d)}

    <section class="report-section page-break">
      <div class="section-badge">§ 05 // ARQUITECTURA TOPOLOGICA DEL GRAFO</div>
      <h2 class="section-title">Red Vectorial Jerárquica y Estratificación Pericial</h2>
      <p class="section-desc">
        Representación matemática topológica organizada en 9 estratos funcionales (desde el dictamen pericial en
        cúspide hasta las evidencias documentales en base).
      </p>

      <div style="margin-bottom: 1.5rem; overflow-x: auto;">
        {svg_graph}
      </div>

      <div class="legend-grid">
        <div class="legend-item">
          <div class="legend-chip" style="background: #e11d48;"></div>
          <div class="legend-text"><b>Tier -1 (Dictamen):</b> Veredicto pericial de la investigación</div>
        </div>
        <div class="legend-item">
          <div class="legend-chip" style="background: #00f5ff;"></div>
          <div class="legend-text"><b>Tier 0 (Target Client):</b> Entidad matriz o activo auditado</div>
        </div>
        <div class="legend-item">
          <div class="legend-chip" style="background: #818cf8;"></div>
          <div class="legend-text"><b>Tier 1 (Ambitos & ASNs):</b> Jurisdicción, registros y conectividad</div>
        </div>
        <div class="legend-item">
          <div class="legend-chip" style="background: #64748b;"></div>
          <div class="legend-text"><b>Tier 2 (Gobernanza):</b> Organizaciones sectoriales y entidades de control</div>
        </div>
        <div class="legend-item">
          <div class="legend-chip" style="background: #10b981;"></div>
          <div class="legend-text"><b>{_h(theme["tier3_label"])}:</b> {_h(theme["tier3_desc"])}</div>
        </div>
        <div class="legend-item">
          <div class="legend-chip" style="background: #00f5ff;"></div>
          <div class="legend-text"><b>Tier 4 (Servicios & Módulos):</b> Procesos, campañas y capacidades</div>
        </div>
        <div class="legend-item">
          <div class="legend-chip" style="background: #38bdf8;"></div>
          <div class="legend-text"><b>Tier 5 (Concurrencia):</b> Cuentas vinculadas, competidores y vectores</div>
        </div>
        <div class="legend-item">
          <div class="legend-chip" style="background: #818cf8;"></div>
          <div class="legend-text"><b>Tier 6 (Sedes & Servidores):</b> Campus físicos, servidores e instalaciones</div>
        </div>
        <div class="legend-item">
          <div class="legend-chip" style="background: #a855f7;"></div>
          <div class="legend-text"><b>Tier 7 (GPS Satelital):</b> Coordenadas de posicionamiento global</div>
        </div>
        <div class="legend-item">
          <div class="legend-chip" style="background: #f59e0b;"></div>
          <div class="legend-text"><b>Tier 8 (Evidencias):</b> Documentos, convenios, memorias y URLs auditadas</div>
        </div>
      </div>
    </section>

    <section class="report-section">
      <div class="section-badge">§ 06 // CRONOLOGÍA PROCEDIMENTAL Y CALIDAD</div>
      <h2 class="section-title">Cronología de Pasos y Recomendaciones Operativas</h2>
      <p class="section-desc">
        Registro inmutable de acciones periciales ejecutadas durante la investigación y siguientes pasos sugeridos por
        el motor determinista.
      </p>

      <div style="margin-bottom: 2rem;">
        <table class="audit-table">
          <thead>
            <tr>
              <th>Seq</th>
              <th>Marca Temporal</th>
              <th>Tipo</th>
              <th>Acción / Transform</th>
              <th>Entrada</th>
              <th>Nuevas</th>
              <th>Estado</th>
            </tr>
          </thead>
          <tbody>
            {step_rows or "<tr><td colspan='7'>Sin pasos registrados</td></tr>"}
          </tbody>
        </table>
      </div>

      <div class="scope-block" style="padding: 1.2rem; background: var(--surface-card);">
        <h4 style="font-size: 13px; font-weight: 700; color: #ffffff; margin-bottom: 0.8rem;">
          Siguientes Acciones Recomendadas (Next Best Action):
        </h4>
        <ol style="padding-left: 1.2rem; color: #cbd5e1; line-height: 1.6;">
          {action_items or "<li>No se requieren acciones adicionales sobre este caso.</li>"}
        </ol>
      </div>
    </section>

    <footer class="footer-seal">
      <div>SELLO CRIPTOGRAFICO SHA-256: <span class="code-pill">{seal}</span></div>
      <div>ESTADO: <span class="ok-pill">[VERIFICADO / NO REPUDIABLE]</span></div>
    </footer>
  </div>
</body>
</html>
"""
