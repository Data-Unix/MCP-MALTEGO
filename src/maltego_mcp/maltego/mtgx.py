"""Lectura y escritura de grafos de Maltego (.mtgx).

Un .mtgx es un ZIP cuyo miembro principal es `Graphs/Graph1.graphml`: GraphML con nodos que llevan un
`mtg:MaltegoEntity` (tipo + propiedades) y aristas con un `mtg:MaltegoLink`. La estructura sigue la de
las exportaciones de Maltego tal como la reproducen dos implementaciones de la comunidad
(lidless-labs/maltego-mcp y SulimanAbdulrazzaq/maltego-mcp).

La lectura trata el fichero como no confiable: límites de tamaño, número de miembros y defusedxml.
"""

from __future__ import annotations

import io
import json
import math
import zipfile
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Literal
from xml.etree.ElementTree import Element, SubElement, register_namespace, tostring

import defusedxml.ElementTree as SafeET
from defusedxml import DefusedXmlException

from maltego_mcp.domain.entity_types import resolve_entity_type
from maltego_mcp.domain.records import EdgeRecord, EntityRecord
from maltego_mcp.errors import InvalidInput

GRAPHML_NS = "http://graphml.graphdrawing.org/xmlns"
MTG_NS = "http://maltego.paterva.com/xml/mtgx"
YFILES_NS = "http://www.yworks.com/xml/graphml"
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"
GRAPH_MEMBER = "Graphs/Graph1.graphml"
LINK_LABEL_PROP = "maltego.link.manual.type"
LINK_LABEL_FALLBACKS = (LINK_LABEL_PROP, "maltego.link.label", "maltego.link.transform.display-name")

MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
MAX_GRAPHML_BYTES = 50 * 1024 * 1024
MAX_MEMBERS = 2000
MAX_ENTITIES = 20_000
MAX_LINKS = 50_000
MAX_SIDECAR_BYTES = 10 * 1024 * 1024

# Tipos cuyo valor visible en Maltego no es la propiedad principal (p. ej. URL muestra short-title).
DISPLAY_PROPERTY = {"maltego.url": "short-title", "maltego.document": "title"}


def main_property_for(maltego_type: str) -> str:
    """Propiedad principal del tipo (ontología importada, estándar o convención properties.<nombre>)."""
    try:
        return resolve_entity_type(maltego_type).main_property
    except InvalidInput:
        return f"properties.{maltego_type.rsplit('.', 1)[-1].lower()}"


def _q(ns: str, tag: str) -> str:
    return f"{{{ns}}}{tag}"


def _prop(parent: Element, name: str, display: str, value: str, ptype: str = "string") -> None:
    p = SubElement(
        parent,
        _q(MTG_NS, "Property"),
        name=name,
        displayName=display,
        type=ptype,
        nullable="true",
        hidden="false",
        readonly="false",
    )
    SubElement(p, _q(MTG_NS, "Value")).text = value


Layout = Literal["hierarchical", "radial", "force"]
SIDECAR_MEMBER = "maltego_mcp/investigation.json"
MAX_FORCE_NODES = 1500


def _adjacency(entities: list[EntityRecord], edges: list[EdgeRecord]) -> dict[str, set[str]]:
    adj: dict[str, set[str]] = {e.id: set() for e in entities}
    for ed in edges:
        if ed.out_id in adj and ed.in_id in adj and ed.out_id != ed.in_id:
            adj[ed.out_id].add(ed.in_id)
            adj[ed.in_id].add(ed.out_id)
    return adj


def _components(adj: dict[str, set[str]]) -> list[dict[int, list[str]]]:
    """BFS por componente desde su nodo más conectado: lista de {nivel: nodos}."""
    seen: set[str] = set()
    comps: list[dict[int, list[str]]] = []
    for root in sorted(adj, key=lambda n: (-len(adj[n]), n)):
        if root in seen:
            continue
        levels: dict[int, list[str]] = {}
        seen.add(root)
        queue: deque[tuple[str, int]] = deque([(root, 0)])
        while queue:
            node, depth = queue.popleft()
            levels.setdefault(depth, []).append(node)
            for nxt in sorted(adj[node]):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append((nxt, depth + 1))
        comps.append(levels)
    return comps


def _hierarchical(adj: dict[str, set[str]]) -> dict[str, tuple[float, float]]:
    positions: dict[str, tuple[float, float]] = {}
    x_offset = 0.0
    for levels in _components(adj):
        max_level_len = max(len(v) for v in levels.values()) if levels else 1
        width = max_level_len
        y_step = max(300.0, min(1200.0, max_level_len * 22.0))
        for depth, nodes in levels.items():
            for i, node in enumerate(nodes):
                positions[node] = (x_offset + (i - (len(nodes) - 1) / 2) * 180.0, depth * y_step)
        x_offset += width * 180.0 + 300.0
    return positions


def _radial(adj: dict[str, set[str]]) -> dict[str, tuple[float, float]]:
    positions: dict[str, tuple[float, float]] = {}
    x_offset = 0.0
    for levels in _components(adj):
        radius_max = 0.0
        for depth, nodes in levels.items():
            radius = depth * 220.0
            radius_max = max(radius_max, radius)
            for i, node in enumerate(nodes):
                angle = 2 * math.pi * i / max(1, len(nodes))
                positions[node] = (radius * math.cos(angle), radius * math.sin(angle))
        for node in [n for lvl in levels.values() for n in lvl]:
            x, y = positions[node]
            positions[node] = (x + x_offset + radius_max, y)
        x_offset += 2 * radius_max + 400.0
    return positions


def _force(adj: dict[str, set[str]], iterations: int = 150) -> dict[str, tuple[float, float]]:
    """Fruchterman-Reingold determinista (parte del layout radial); en grafos muy grandes, jerárquico."""
    nodes = sorted(adj)
    if len(nodes) > MAX_FORCE_NODES:
        return _hierarchical(adj)
    pos = {n: list(p) for n, p in _radial(adj).items()}
    area = max(1.0, len(nodes)) * 40000.0
    k = math.sqrt(area / max(1, len(nodes)))
    temp = math.sqrt(area) / 10
    for _ in range(iterations):
        disp = {n: [0.0, 0.0] for n in nodes}
        for i, a in enumerate(nodes):
            for b in nodes[i + 1 :]:
                dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
                dist = math.hypot(dx, dy) or 0.01
                force = k * k / dist
                disp[a][0] += dx / dist * force
                disp[a][1] += dy / dist * force
                disp[b][0] -= dx / dist * force
                disp[b][1] -= dy / dist * force
        for a in nodes:
            for b in adj[a]:
                if a < b:
                    dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
                    dist = math.hypot(dx, dy) or 0.01
                    force = dist * dist / k
                    disp[a][0] -= dx / dist * force
                    disp[a][1] -= dy / dist * force
                    disp[b][0] += dx / dist * force
                    disp[b][1] += dy / dist * force
        for n in nodes:
            d = math.hypot(*disp[n]) or 0.01
            step = min(d, temp)
            pos[n][0] += disp[n][0] / d * step
            pos[n][1] += disp[n][1] / d * step
        temp *= 0.95
    return {n: (p[0], p[1]) for n, p in pos.items()}


def compute_layout(
    entities: list[EntityRecord], edges: list[EdgeRecord], layout: Layout = "hierarchical"
) -> dict[str, tuple[float, float]]:
    adj = _adjacency(entities, edges)
    if layout == "radial":
        return _radial(adj)
    if layout == "force":
        return _force(adj)
    return _hierarchical(adj)


def entity_visual_profile(entity: EntityRecord, degree: int = 0) -> tuple[int, str, str, str]:
    """Calcula (weight 1-100, color hex, size tier, bookmark) para renderizado visual en .mtgx."""
    props = entity.properties
    raw_w = props.get("visual.weight") or props.get("mcp.visual.weight") or ""
    try:
        weight = max(1, min(100, int(float(raw_w)))) if raw_w else 0
    except ValueError:
        weight = 0
    if not weight:
        threat_bonus = 0
        if (
            int(props.get("vt.malicious", "0") or "0") > 0
            or int(props.get("otx.pulse_count", "0") or "0") > 0
            or props.get("breach.name")
            or props.get("breach.count")
            or props.get("humint.risk") == "high"
            or entity.value.startswith(("[CVE]", "[Malware]", "[Breach]", "[PwnedPassword]"))
        ):
            threat_bonus = 35
        weight = max(1, min(100, round(entity.confidence * 55 + min(degree, 6) * 5 + threat_bonus)))

    color = props.get("visual.color") or props.get("mcp.visual.color") or ""
    size = props.get("visual.size") or props.get("mcp.visual.size") or ""
    bookmark = props.get("visual.bookmark") or props.get("mcp.visual.bookmark") or ""
    is_threat = (
        int(props.get("vt.malicious", "0") or "0") > 0
        or int(props.get("otx.pulse_count", "0") or "0") > 0
        or bool(props.get("breach.name") or props.get("breach.count"))
        or props.get("humint.risk") == "high"
        or entity.value.startswith(("[CVE]", "[Malware]", "[Breach]", "[PwnedPassword]"))
    )
    if not color:
        if is_threat:
            color = "#e11d48"
        elif weight >= 75:
            color = "#f59e0b"
        elif entity.maltego_type.lower().startswith("humint.") or props.get("humint.epistemic_status") == "hypothesis":
            color = "#8b5cf6"
        elif weight >= 50:
            color = "#10b981"
        else:
            color = "#64748b"
    if not size:
        if is_threat or weight >= 85:
            size = "xl"
        elif weight >= 65:
            size = "large"
        elif weight >= 35:
            size = "normal"
        else:
            size = "small"
    if not bookmark:
        bookmark = "red" if is_threat else ("orange" if weight >= 75 else ("purple" if color == "#8b5cf6" else "none"))
    return weight, color, size, bookmark


def edge_visual_profile(edge: EdgeRecord) -> tuple[str, int, str]:
    """Calcula (color hex, grosor 1-5, estilo '0' sólido / '1' discontinuo) para MaltegoLink."""
    props = edge.properties
    color = props.get("maltego.link.color") or props.get("mcp.link.color") or ""
    raw_thick = (
        props.get("maltego.link.thickness") or props.get("mcp.link.thickness") or props.get("humint.weight") or ""
    )
    sentiment = props.get("humint.sentiment", "")
    role = props.get("humint.role", "")
    if not color:
        if edge.label == "humint_highly_likely_same_individual" or sentiment == "hostil":
            color = "#e11d48"
        elif sentiment in ("estrecho", "familiar") or role in ("lider", "reclutador"):
            color = "#f59e0b"
        elif role in ("intermediario", "operador") or sentiment == "profesional":
            color = "#3b82f6"
        elif edge.confidence >= 0.85:
            color = "#10b981"
        else:
            color = "#64748b"
    try:
        val = int(float(raw_thick))
        thickness = max(1, min(5, val if val <= 5 else (2 + min(3, val // 25))))
    except ValueError:
        thickness = (
            4
            if edge.label == "humint_highly_likely_same_individual"
            else (3 if edge.confidence >= 0.8 else (2 if edge.confidence >= 0.5 else 1))
        )
    style = props.get("maltego.link.style") or (
        "1"
        if props.get("humint.epistemic_status") == "hypothesis" or edge.label == "humint_highly_likely_same_individual"
        else "0"
    )
    return color, thickness, style


def write_mtgx(
    entities: list[EntityRecord],
    edges: list[EdgeRecord],
    layout: Layout = "hierarchical",
    sidecar: dict[str, Any] | None = None,
) -> bytes:
    """Escribe el .mtgx. `sidecar` (memoria de la investigación) viaja en un fichero aparte que Maltego ignora."""
    # Solo prefijos con nombre: los elementos GraphML van sin calificar bajo un xmlns literal en la raíz, así no se
    # altera el espacio de nombres por defecto global de ElementTree.
    register_namespace("mtg", MTG_NS)
    register_namespace("y", YFILES_NS)
    register_namespace("xsi", XSI_NS)
    root = Element("graphml", {"xmlns": GRAPHML_NS})
    for attrs in (
        {"for": "graphml", "id": "d0", "yfiles.type": "resources"},
        {"for": "port", "id": "d1", "yfiles.type": "portgraphics"},
        {"for": "port", "id": "d2", "yfiles.type": "portgeometry"},
        {"for": "port", "id": "d3", "yfiles.type": "portuserdata"},
        {"attr.name": "MaltegoEntity", "for": "node", "id": "d4"},
        {"for": "node", "id": "d5", "yfiles.type": "nodegraphics"},
        {"attr.name": "MaltegoLink", "for": "edge", "id": "d6"},
        {"for": "edge", "id": "d7", "yfiles.type": "edgegraphics"},
    ):
        SubElement(root, "key", attrs)
    graph = SubElement(root, "graph", id="G", edgedefault="directed")
    adj = _adjacency(entities, edges)
    positions = compute_layout(entities, edges, layout)
    ids = {e.id for e in entities}
    for e in entities:
        weight, vcolor, vsize, vbookmark = entity_visual_profile(e, len(adj.get(e.id, ())))
        node = SubElement(graph, "node", id=e.id)
        data = SubElement(node, "data", key="d4")
        ment = SubElement(data, _q(MTG_NS, "MaltegoEntity"), type=e.maltego_type)
        props = SubElement(ment, _q(MTG_NS, "Properties"))
        main = main_property_for(e.maltego_type)
        _prop(props, main, main, e.value)
        display = DISPLAY_PROPERTY.get(e.maltego_type.lower())
        if display:
            _prop(props, display, display, e.properties.get(display, e.value))
        for k, v in e.properties.items():
            if k not in (main, display):
                _prop(props, k, k, v)
        _prop(props, "maltego.calculated.weight", "Weight", str(weight), "int")
        _prop(props, "mcp.confidence", "Confianza (MCP)", str(e.confidence))
        _prop(props, "mcp.sources", "Fuentes (MCP)", "; ".join(e.sources))
        _prop(props, "mcp.visual.weight", "Peso visual (MCP)", str(weight), "int")
        _prop(props, "mcp.visual.color", "Color visual (MCP)", vcolor)
        _prop(props, "mcp.visual.size", "Tamaño visual (MCP)", vsize)
        _prop(props, "mcp.visual.bookmark", "Marcador visual (MCP)", vbookmark)
        if e.notes:
            SubElement(ment, _q(MTG_NS, "Notes")).text = e.notes
        g = SubElement(node, "data", key="d5")
        renderer = SubElement(g, _q(MTG_NS, "EntityRenderer"))
        raw_x = e.properties.get("mcp.pos.x") or e.properties.get("pos.x")
        raw_y = e.properties.get("mcp.pos.y") or e.properties.get("pos.y")
        if raw_x is not None and raw_y is not None:
            try:
                x, y = float(raw_x), float(raw_y)
            except ValueError:
                x, y = positions.get(e.id, (0.0, 0.0))
        else:
            x, y = positions.get(e.id, (0.0, 0.0))
        SubElement(renderer, _q(MTG_NS, "Position"), x=f"{x:.1f}", y=f"{y:.1f}")
        SubElement(
            renderer,
            _q(MTG_NS, "Style"),
            color=vcolor,
            size=vsize,
            weight=str(weight),
            bookmark=vbookmark,
        )
    for ed in edges:
        if ed.out_id not in ids or ed.in_id not in ids:
            continue
        lcolor, lthick, lstyle = edge_visual_profile(ed)
        edge = SubElement(graph, "edge", id=ed.id, source=ed.out_id, target=ed.in_id)
        data = SubElement(edge, "data", key="d6")
        link = SubElement(data, _q(MTG_NS, "MaltegoLink"), type="maltego.link.manual-link")
        props = SubElement(link, _q(MTG_NS, "Properties"))
        _prop(props, "maltego.link.show-label", "Show Label", "1", "int")
        _prop(props, LINK_LABEL_PROP, "Label", ed.label)
        _prop(props, "maltego.link.color", "Color", lcolor)
        _prop(props, "maltego.link.thickness", "Thickness", str(lthick), "int")
        _prop(props, "maltego.link.style", "Style", lstyle, "int")
        _prop(props, "mcp.confidence", "Confianza (MCP)", str(ed.confidence))
        for k, v in ed.properties.items():
            if k not in (
                "maltego.link.show-label",
                LINK_LABEL_PROP,
                "maltego.link.color",
                "maltego.link.thickness",
                "maltego.link.style",
            ):
                _prop(props, k, k, v)
        lrend = SubElement(SubElement(edge, "data", key="d7"), _q(MTG_NS, "LinkRenderer"))
        SubElement(lrend, _q(MTG_NS, "Style"), color=lcolor, thickness=str(lthick), style=lstyle)
    SubElement(root, "data", key="d0")
    xml = tostring(root, encoding="utf-8", xml_declaration=True)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(GRAPH_MEMBER, xml)
        zf.writestr("version.properties", "maltego.graph.version=1.3\n")
        if sidecar is not None:
            zf.writestr(SIDECAR_MEMBER, json.dumps(sidecar, ensure_ascii=False))
    return buf.getvalue()


@dataclass(slots=True)
class ImportedEntity:
    key: str
    maltego_type: str
    value: str
    properties: dict[str, str] = field(default_factory=dict)
    confidence: float = 0.5


@dataclass(slots=True)
class ImportedLink:
    source: str
    target: str
    label: str
    confidence: float = 0.5
    properties: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class ImportedGraph:
    entities: list[ImportedEntity] = field(default_factory=list)
    links: list[ImportedLink] = field(default_factory=list)
    skipped: int = 0
    sidecar: dict[str, Any] = field(default_factory=dict)


def read_mtgx(payload: bytes) -> ImportedGraph:
    if len(payload) > MAX_ARCHIVE_BYTES:
        raise InvalidInput("El .mtgx supera 20 MB.")
    try:
        zf = zipfile.ZipFile(io.BytesIO(payload))
    except zipfile.BadZipFile as exc:
        raise InvalidInput("El fichero no es un .mtgx válido (no es un ZIP).") from exc
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            raise InvalidInput("El .mtgx tiene demasiados ficheros internos.")
        graph_infos = [i for i in infos if i.filename.startswith("Graphs/") and i.filename.endswith(".graphml")]
        if not graph_infos:
            raise InvalidInput("El .mtgx no contiene Graphs/*.graphml.")
        info = next((i for i in graph_infos if i.filename == GRAPH_MEMBER), graph_infos[0])
        if info.file_size > MAX_GRAPHML_BYTES:
            raise InvalidInput("El grafo del .mtgx es demasiado grande (>50 MB descomprimido).")
        with zf.open(info) as fh:
            xml = fh.read(MAX_GRAPHML_BYTES + 1)
        if len(xml) > MAX_GRAPHML_BYTES:
            raise InvalidInput("El grafo del .mtgx es demasiado grande (>50 MB descomprimido).")
        sidecar: dict[str, Any] = {}
        side = next((i for i in infos if i.filename == SIDECAR_MEMBER), None)
        if side is not None and side.file_size <= MAX_SIDECAR_BYTES:
            try:
                loaded = json.loads(zf.read(side).decode("utf-8"))
                sidecar = loaded if isinstance(loaded, dict) else {}
            except (ValueError, UnicodeDecodeError):
                sidecar = {}
    graph = parse_graphml(xml)
    graph.sidecar = sidecar
    return graph


def parse_graphml(xml: bytes) -> ImportedGraph:
    try:
        root = SafeET.fromstring(xml)
    except (DefusedXmlException, SafeET.ParseError) as exc:
        raise InvalidInput("El GraphML del .mtgx es inválido o inseguro.") from exc
    out = ImportedGraph()
    for node in root.iter(_q(GRAPHML_NS, "node")):
        ment = node.find(f".//{_q(MTG_NS, 'MaltegoEntity')}")
        node_id = node.get("id")
        if ment is None or not node_id:
            out.skipped += 1
            continue
        if len(out.entities) >= MAX_ENTITIES:
            raise InvalidInput(f"El grafo supera {MAX_ENTITIES} entidades.")
        mtype = (ment.get("type") or "maltego.Phrase").strip()
        props: dict[str, str] = {}
        for p in ment.iter(_q(MTG_NS, "Property")):
            name = (p.get("name") or "").strip()
            val = p.find(_q(MTG_NS, "Value"))
            if name and val is not None and val.text:
                props[name] = val.text.strip()
        main = main_property_for(mtype)
        value = props.pop(main, "") or (props.pop(next(iter(props))) if props else "")
        try:
            confidence = float(props.get("mcp.confidence", 0.5))
        except ValueError:
            confidence = 0.5
        props = {k: v for k, v in props.items() if not k.startswith("mcp.") and k != "maltego.calculated.weight"}
        if not value:
            out.skipped += 1
            continue
        out.entities.append(ImportedEntity(node_id, mtype, value, props, confidence))
    keys = {e.key for e in out.entities}
    for edge in root.iter(_q(GRAPHML_NS, "edge")):
        src, dst = edge.get("source"), edge.get("target")
        if not src or not dst or src not in keys or dst not in keys:
            continue
        if len(out.links) >= MAX_LINKS:
            raise InvalidInput(f"El grafo supera {MAX_LINKS} enlaces.")
        label = ""
        edge_props: dict[str, str] = {}
        for p in edge.iter(_q(MTG_NS, "Property")):
            pname = (p.get("name") or "").strip()
            val = p.find(_q(MTG_NS, "Value"))
            if val is not None and val.text and val.text.strip():
                text_val = val.text.strip()
                if pname in LINK_LABEL_FALLBACKS and not label:
                    label = text_val
                elif pname:
                    edge_props[pname] = text_val
        try:
            e_conf = float(edge_props.pop("mcp.confidence", 0.5))
        except ValueError:
            e_conf = 0.5
        edge_props = {
            k: v
            for k, v in edge_props.items()
            if not k.startswith("mcp.")
            and k
            not in (
                "maltego.link.show-label",
                "maltego.link.color",
                "maltego.link.thickness",
                "maltego.link.style",
                *LINK_LABEL_FALLBACKS,
            )
        }
        out.links.append(ImportedLink(src, dst, label, e_conf, edge_props))
    return out
