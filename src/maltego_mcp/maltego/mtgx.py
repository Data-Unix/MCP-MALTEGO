"""Lectura y escritura de grafos de Maltego (.mtgx).

Un .mtgx es un ZIP cuyo miembro principal es `Graphs/Graph1.graphml`: GraphML con nodos que llevan un
`mtg:MaltegoEntity` (tipo + propiedades) y aristas con un `mtg:MaltegoLink`. La estructura sigue la de
las exportaciones de Maltego tal como la reproducen dos implementaciones de la comunidad
(lidless-labs/maltego-mcp y SulimanAbdulrazzaq/maltego-mcp).

La lectura trata el fichero como no confiable: límites de tamaño, número de miembros y defusedxml.
"""

from __future__ import annotations

import io
import zipfile
from collections import deque
from dataclasses import dataclass, field
from xml.etree.ElementTree import Element, SubElement, register_namespace, tostring

import defusedxml.ElementTree as SafeET
from defusedxml import DefusedXmlException

from maltego_mcp.domain.entity_types import ENTITY_TYPES
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

_MAIN_PROPERTY = {e.maltego_type.lower(): e.main_property for e in ENTITY_TYPES}
# Tipos cuyo valor visible en Maltego no es la propiedad principal (p. ej. URL muestra short-title).
DISPLAY_PROPERTY = {"maltego.url": "short-title", "maltego.document": "title"}


def main_property_for(maltego_type: str) -> str:
    """Propiedad principal del tipo. Para tipos propios, la convención de Maltego: properties.<nombre>."""
    known = _MAIN_PROPERTY.get(maltego_type.lower())
    return known or f"properties.{maltego_type.rsplit('.', 1)[-1].lower()}"


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


def _layout(entities: list[EntityRecord], edges: list[EdgeRecord]) -> dict[str, tuple[float, float]]:
    """Disposición por niveles (BFS desde la entidad más conectada de cada componente)."""
    adj: dict[str, set[str]] = {e.id: set() for e in entities}
    for ed in edges:
        if ed.out_id in adj and ed.in_id in adj:
            adj[ed.out_id].add(ed.in_id)
            adj[ed.in_id].add(ed.out_id)
    positions: dict[str, tuple[float, float]] = {}
    x_offset = 0.0
    for root in sorted(adj, key=lambda n: (-len(adj[n]), n)):
        if root in positions:
            continue
        levels: dict[int, list[str]] = {}
        seen = {root}
        queue: deque[tuple[str, int]] = deque([(root, 0)])
        while queue:
            node, depth = queue.popleft()
            levels.setdefault(depth, []).append(node)
            for nxt in sorted(adj[node]):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append((nxt, depth + 1))
        width = max(len(v) for v in levels.values())
        for depth, nodes in levels.items():
            for i, node in enumerate(nodes):
                positions[node] = (x_offset + (i - len(nodes) / 2) * 180.0, depth * 200.0)
        x_offset += width * 180.0 + 300.0
    return positions


def write_mtgx(entities: list[EntityRecord], edges: list[EdgeRecord]) -> bytes:
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
    positions = _layout(entities, edges)
    ids = {e.id for e in entities}
    for e in entities:
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
        _prop(props, "mcp.confidence", "Confianza (MCP)", str(e.confidence))
        _prop(props, "mcp.sources", "Fuentes (MCP)", "; ".join(e.sources))
        g = SubElement(node, "data", key="d5")
        renderer = SubElement(g, _q(MTG_NS, "EntityRenderer"))
        x, y = positions.get(e.id, (0.0, 0.0))
        SubElement(renderer, _q(MTG_NS, "Position"), x=f"{x:.1f}", y=f"{y:.1f}")
    for ed in edges:
        if ed.out_id not in ids or ed.in_id not in ids:
            continue
        edge = SubElement(graph, "edge", id=ed.id, source=ed.out_id, target=ed.in_id)
        data = SubElement(edge, "data", key="d6")
        link = SubElement(data, _q(MTG_NS, "MaltegoLink"), type="maltego.link.manual-link")
        props = SubElement(link, _q(MTG_NS, "Properties"))
        _prop(props, "maltego.link.show-label", "Show Label", "1", "int")
        _prop(props, LINK_LABEL_PROP, "Label", ed.label)
        SubElement(SubElement(edge, "data", key="d7"), _q(MTG_NS, "LinkRenderer"))
    SubElement(root, "data", key="d0")
    xml = tostring(root, encoding="utf-8", xml_declaration=True)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(GRAPH_MEMBER, xml)
        zf.writestr("version.properties", "maltego.graph.version=1.3\n")
    return buf.getvalue()


@dataclass(slots=True)
class ImportedEntity:
    key: str
    maltego_type: str
    value: str
    properties: dict[str, str] = field(default_factory=dict)
    confidence: float = 0.5


@dataclass(frozen=True, slots=True)
class ImportedLink:
    source: str
    target: str
    label: str
    confidence: float = 0.5


@dataclass(slots=True)
class ImportedGraph:
    entities: list[ImportedEntity] = field(default_factory=list)
    links: list[ImportedLink] = field(default_factory=list)
    skipped: int = 0


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
    return parse_graphml(xml)


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
        props = {k: v for k, v in props.items() if not k.startswith("mcp.")}
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
        for p in edge.iter(_q(MTG_NS, "Property")):
            if p.get("name") in LINK_LABEL_FALLBACKS:
                val = p.find(_q(MTG_NS, "Value"))
                if val is not None and val.text and val.text.strip():
                    label = val.text.strip()
                    break
        out.links.append(ImportedLink(src, dst, label))
    return out
