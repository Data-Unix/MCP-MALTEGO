"""Casos de uso del MCP: normalizan entradas, coordinan grafo y transforms."""

from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from xml.etree.ElementTree import Element, SubElement, tostring

from maltego_mcp.domain.detect import resolve_type_for_value
from maltego_mcp.domain.entity_types import resolve_entity_type
from maltego_mcp.domain.normalize import (
    edge_id,
    entity_id,
    normalize_edge_label,
    normalize_value,
    validate_case_id,
    validate_entity_id,
)
from maltego_mcp.domain.records import (
    CaseRecord,
    EdgeRecord,
    EntityRecord,
    clamp_confidence,
    clean_properties,
    utc_now,
)
from maltego_mcp.errors import InvalidInput, MaltegoMcpError, NotFound, TransformError
from maltego_mcp.graph.base import CaseSummary, Direction, GraphStore, Neighbor, Page
from maltego_mcp.maltego.mtgx import ImportedEntity, ImportedGraph, read_mtgx, write_mtgx
from maltego_mcp.transforms.catalog import TransformCatalog, TransformSpec
from maltego_mcp.transforms.client import run_remote_transform
from maltego_mcp.transforms.protocol import TransformResponse

logger = logging.getLogger(__name__)
ExportFormat = Literal["json", "graphml", "csv", "mtgx"]
IMPORT_SUFFIXES = (".mtgx", ".csv")
MAX_IMPORT_BYTES = 20 * 1024 * 1024
CSV_HEADER = ["source_type", "source_value", "relation", "target_type", "target_value", "confidence"]
MAX_EXPORT_ITEMS = 10_000
CHAIN_CONCURRENCY = 4


def parse_properties(items: list[str]) -> dict[str, str]:
    props: dict[str, str] = {}
    for item in items:
        key, sep, value = item.partition("=")
        if not sep or not key.strip():
            raise InvalidInput(f"Propiedad '{item[:80]}' inválida: usa el formato clave=valor.")
        props[key.strip()] = value.strip()
    return clean_properties(props)


@dataclass(slots=True)
class TransformOutcome:
    entity: EntityRecord
    edge_label: str
    created: bool


@dataclass(slots=True)
class TransformRun:
    transform: str
    input: EntityRecord
    results: list[TransformOutcome] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    messages: list[tuple[str, str]] = field(default_factory=list)
    truncated: bool = False
    saved: bool = True


@dataclass(slots=True)
class ChainStep:
    transform: str
    inputs: int = 0
    outputs: int = 0
    new_entities: int = 0
    errors: list[str] = field(default_factory=list)
    skipped_inputs: int = 0


@dataclass(slots=True)
class ImportResult:
    path: Path
    entities: int = 0
    new_entities: int = 0
    links: int = 0
    skipped: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ExpandResult:
    entity: EntityRecord
    runs: list[TransformRun] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    not_run: list[str] = field(default_factory=list)


class OsintService:
    def __init__(
        self, store: GraphStore, catalog: TransformCatalog, export_dir: Path, import_dir: Path | None = None
    ) -> None:
        self.store = store
        self.catalog = catalog
        self.export_dir = export_dir
        self.import_dir = import_dir or export_dir.parent / "imports"

    # ---------- casos ----------
    async def create_case(self, case_id: str, description: str) -> tuple[CaseRecord, bool]:
        return await self.store.ensure_case(validate_case_id(case_id), description.strip()[:500])

    async def list_cases(self, limit: int, offset: int) -> Page[CaseRecord]:
        return await self.store.list_cases(limit, offset)

    async def case_summary(self, case_id: str, top: int) -> CaseSummary:
        return await self.store.case_summary(validate_case_id(case_id), top)

    # ---------- entidades ----------
    def build_entity(
        self,
        case_id: str,
        entity_type: str,
        value: str,
        confidence: float,
        source: str,
        properties: dict[str, str] | None = None,
    ) -> EntityRecord:
        etype = resolve_type_for_value(entity_type, value)
        norm = normalize_value(etype, value)
        now = utc_now()
        return EntityRecord(
            id=entity_id(etype, norm),
            case_id=case_id,
            label=etype.graph_label,
            maltego_type=etype.maltego_type,
            value=norm,
            confidence=clamp_confidence(confidence),
            sources=[source.strip()[:120] or "manual"],
            properties=properties or {},
            first_seen=now,
            last_seen=now,
        )

    async def upsert_entity(
        self,
        case_id: str,
        entity_type: str,
        value: str,
        confidence: float,
        source: str,
        properties: list[str],
    ) -> tuple[EntityRecord, bool]:
        cid = validate_case_id(case_id)
        entity = self.build_entity(cid, entity_type, value, confidence, source, parse_properties(properties))
        await self.store.ensure_case(cid)
        return await self.store.upsert_entity(entity)

    async def get_entity(self, case_id: str, eid: str) -> EntityRecord:
        cid, eid = validate_case_id(case_id), validate_entity_id(eid)
        ent = await self.store.get_entity(cid, eid)
        if ent is None:
            raise NotFound(f"La entidad '{eid}' no existe en el caso '{cid}'. Búscala con osint_search_entities.")
        return ent

    async def search(self, case_id: str, query: str, entity_type: str, limit: int, offset: int) -> Page[EntityRecord]:
        cid = validate_case_id(case_id) if case_id.strip() else ""
        mtype = resolve_entity_type(entity_type).maltego_type if entity_type.strip() else ""
        return await self.store.search_entities(cid, query.strip()[:200], mtype, limit, offset)

    # ---------- relaciones ----------
    async def link(
        self, case_id: str, source_id: str, target_id: str, label: str, source: str, confidence: float
    ) -> tuple[EdgeRecord, bool]:
        cid = validate_case_id(case_id)
        out_id, in_id = validate_entity_id(source_id), validate_entity_id(target_id)
        if out_id == in_id:
            raise InvalidInput("source_id y target_id son la misma entidad; no se crean bucles.")
        lbl = normalize_edge_label(label)
        now = utc_now()
        edge = EdgeRecord(
            id=edge_id(cid, out_id, lbl, in_id),
            case_id=cid,
            label=lbl,
            out_id=out_id,
            in_id=in_id,
            confidence=clamp_confidence(confidence),
            sources=[source.strip()[:120] or "manual"],
            first_seen=now,
            last_seen=now,
        )
        return await self.store.upsert_edge(edge)

    async def neighbors(
        self, case_id: str, eid: str, edge_label: str, direction: Direction, limit: int
    ) -> list[Neighbor]:
        lbl = normalize_edge_label(edge_label) if edge_label.strip() else ""
        return await self.store.neighbors(validate_case_id(case_id), validate_entity_id(eid), lbl, direction, limit)

    async def find_paths(self, case_id: str, src: str, dst: str, max_depth: int, limit: int) -> list[list[str]]:
        s, d = validate_entity_id(src), validate_entity_id(dst)
        if s == d:
            raise InvalidInput("source_id y target_id son la misma entidad.")
        return await self.store.find_paths(validate_case_id(case_id), s, d, max_depth, limit)

    # ---------- transforms ----------
    def list_transforms(self, entity_type: str) -> list[TransformSpec]:
        specs = sorted(self.catalog.transforms.values(), key=lambda s: s.name.lower())
        if entity_type.strip():
            mtype = resolve_entity_type(entity_type).maltego_type
            specs = [s for s in specs if s.accepts(mtype)]
        return specs

    async def run_transform(
        self,
        case_id: str,
        transform: str,
        entity_type: str,
        value: str,
        properties: list[str],
        soft_limit: int,
        save: bool,
    ) -> TransformRun:
        cid = validate_case_id(case_id) if case_id.strip() else ""
        if save and not cid:
            raise InvalidInput("Para guardar resultados (save=true) indica case_id, o usa save=false.")
        spec = self.catalog.get(transform)
        source_entity = self.build_entity(cid, entity_type, value, 1.0, "manual", parse_properties(properties))
        if not spec.accepts(source_entity.maltego_type):
            raise InvalidInput(
                f"El transform '{spec.name}' no acepta {source_entity.maltego_type}; "
                f"acepta: {', '.join(spec.input_types)}."
            )
        if save:
            await self.store.ensure_case(cid)
            source_entity, _ = await self.store.upsert_entity(source_entity)
        return await self._run_on_entity(spec, source_entity, soft_limit, save)

    async def _fetch(self, spec: TransformSpec, source: EntityRecord, soft_limit: int) -> TransformResponse:
        response = await run_remote_transform(
            spec, source.maltego_type, source.value, source.properties, soft_limit=soft_limit
        )
        if response.exceptions:
            raise TransformError(
                f"El transform '{spec.name}' devolvió un error: " + " | ".join(x[:300] for x in response.exceptions)
            )
        return response

    async def _run_on_entity(
        self, spec: TransformSpec, source: EntityRecord, soft_limit: int, save: bool
    ) -> TransformRun:
        return await self._ingest(spec, source, await self._fetch(spec, source, soft_limit), save)

    async def _ingest(
        self, spec: TransformSpec, source: EntityRecord, response: TransformResponse, save: bool
    ) -> TransformRun:
        run = TransformRun(spec.name, source, messages=response.messages[:20], truncated=response.truncated, saved=save)
        origin = f"transform:{spec.name}"
        for item in response.entities:
            try:
                entity = self.build_entity(
                    source.case_id,
                    item.entity_type,
                    item.value,
                    item.weight / 100,
                    origin,
                    clean_properties(item.properties),
                )
            except InvalidInput as exc:
                run.skipped.append(f"{item.entity_type} '{item.value[:60]}': {exc}")
                continue
            try:
                label = normalize_edge_label(item.link_label or spec.name)
            except InvalidInput:
                label = "transform_result"
            created = False
            if save:
                entity, created = await self.store.upsert_entity(entity)
                out_id, in_id = (entity.id, source.id) if item.reversed_link else (source.id, entity.id)
                if out_id != in_id:
                    now = utc_now()
                    await self.store.upsert_edge(
                        EdgeRecord(
                            id=edge_id(source.case_id, out_id, label, in_id),
                            case_id=source.case_id,
                            label=label,
                            out_id=out_id,
                            in_id=in_id,
                            confidence=entity.confidence,
                            sources=[origin],
                            first_seen=now,
                            last_seen=now,
                        )
                    )
            run.results.append(TransformOutcome(entity, label, created))
        return run

    async def expand_entity(self, case_id: str, eid: str, max_transforms: int, soft_limit: int) -> ExpandResult:
        """Ejecuta sobre una entidad del caso todos los transforms del catálogo que la aceptan."""
        cid, eid = validate_case_id(case_id), validate_entity_id(eid)
        entity = await self.store.get_entity(cid, eid)
        if entity is None:
            raise NotFound(f"La entidad '{eid}' no existe en el caso '{cid}'. Búscala con osint_search_entities.")
        specs = [
            s
            for s in sorted(self.catalog.transforms.values(), key=lambda s: s.name.lower())
            if s.input_types and s.accepts(entity.maltego_type)
        ]
        if not specs:
            raise InvalidInput(
                f"No hay transforms en el catálogo que acepten {entity.maltego_type}. Revisa osint_list_transforms."
            )
        result = ExpandResult(entity, not_run=[s.name for s in specs[max_transforms:]])
        sem = asyncio.Semaphore(CHAIN_CONCURRENCY)

        async def fetch(spec: TransformSpec) -> TransformResponse | str:
            async with sem:
                try:
                    return await self._fetch(spec, entity, soft_limit)
                except MaltegoMcpError as exc:
                    return f"{spec.name}: {exc}"

        chosen = specs[:max_transforms]
        responses = await asyncio.gather(*(fetch(s) for s in chosen))
        for spec, response in zip(chosen, responses, strict=True):
            if isinstance(response, str):
                result.errors.append(response)
                continue
            try:
                result.runs.append(await self._ingest(spec, entity, response, save=True))
            except MaltegoMcpError as exc:
                result.errors.append(f"{spec.name}: {exc}")
        return result

    async def run_chain(
        self,
        case_id: str,
        entity_type: str,
        value: str,
        transforms: list[str],
        max_inputs_per_step: int,
        max_total_entities: int,
        soft_limit: int,
    ) -> tuple[EntityRecord, list[ChainStep], bool]:
        cid = validate_case_id(case_id)
        if not transforms:
            raise InvalidInput("transforms no puede estar vacío: indica al menos un transform del catálogo.")
        specs = [self.catalog.get(t) for t in transforms]
        await self.store.ensure_case(cid)
        root, _ = await self.store.upsert_entity(self.build_entity(cid, entity_type, value, 1.0, "manual"))
        frontier: list[EntityRecord] = [root]
        seen: set[str] = {root.id}
        steps: list[ChainStep] = []
        stopped = False
        sem = asyncio.Semaphore(CHAIN_CONCURRENCY)

        async def fetch(spec: TransformSpec, ent: EntityRecord, limit: int) -> TransformResponse | str:
            async with sem:
                try:
                    return await self._fetch(spec, ent, limit)
                except MaltegoMcpError as exc:
                    return f"{ent.value[:60]}: {exc}"

        for spec in specs:
            remaining = max_total_entities - len(seen)
            if remaining <= 0:
                stopped = True
                break
            step = ChainStep(spec.name)
            steps.append(step)
            accepted = [e for e in frontier if spec.accepts(e.maltego_type)]
            candidates = accepted[: min(max_inputs_per_step, remaining)]
            step.skipped_inputs = len(frontier) - len(candidates)
            step.inputs = len(candidates)
            # Las consultas se lanzan en paralelo; el guardado es secuencial y respeta el presupuesto.
            responses = await asyncio.gather(*(fetch(spec, e, min(soft_limit, remaining)) for e in candidates))
            next_frontier: list[EntityRecord] = []
            for ent, response in zip(candidates, responses, strict=True):
                if isinstance(response, str):
                    step.errors.append(response)
                    continue
                remaining = max_total_entities - len(seen)
                if remaining <= 0:
                    stopped = True
                    break
                response.entities = response.entities[:remaining]
                try:
                    run = await self._ingest(spec, ent, response, save=True)
                except MaltegoMcpError as exc:
                    step.errors.append(f"{ent.value[:60]}: {exc}")
                    continue
                for res in run.results:
                    step.outputs += 1
                    if res.entity.id not in seen:
                        seen.add(res.entity.id)
                        step.new_entities += 1
                        next_frontier.append(res.entity)
            frontier = next_frontier
            if len(seen) >= max_total_entities:
                stopped = True
            if stopped or not frontier:
                break
        return root, steps, stopped

    # ---------- exportación ----------
    async def export_case(self, case_id: str, fmt: ExportFormat) -> tuple[Path, int, int]:
        cid = validate_case_id(case_id)
        entities, edges = await self.store.export_case(cid, MAX_EXPORT_ITEMS)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
        self.export_dir.mkdir(parents=True, exist_ok=True)
        path = self.export_dir / f"{cid}-{stamp}-{secrets.token_hex(3)}.{fmt}"
        if fmt == "json":
            content = json.dumps(
                {
                    "case_id": cid,
                    "entities": [e.to_dict() for e in entities],
                    "edges": [e.to_dict() for e in edges],
                },
                ensure_ascii=False,
                indent=2,
            ).encode()
        elif fmt == "graphml":
            content = _to_graphml(entities, edges)
        elif fmt == "mtgx":
            content = write_mtgx(entities, edges)
        else:
            content = _to_csv(entities, edges).encode("utf-8-sig")
        path.write_bytes(content)
        return path, len(entities), len(edges)

    def resolve_import_path(self, file_name: str) -> Path:
        """Solo se importan ficheros de la carpeta de importación o de exportación (sin rutas arbitrarias)."""
        name = file_name.strip().strip('"')
        if not name:
            raise InvalidInput("Indica file_name (p. ej. caso.mtgx).")
        allowed = [self.import_dir.resolve(), self.export_dir.resolve()]
        candidate = Path(name)
        options = [candidate] if candidate.is_absolute() else [d / name for d in allowed]
        for option in options:
            resolved = option.resolve()
            if any(resolved.is_relative_to(d) for d in allowed) and resolved.is_file():
                if resolved.suffix.lower() not in IMPORT_SUFFIXES:
                    raise InvalidInput("Formato no soportado: usa un fichero .mtgx (Maltego) o .csv.")
                return resolved
        available = sorted(
            p.name for d in allowed if d.is_dir() for p in d.iterdir() if p.suffix.lower() in IMPORT_SUFFIXES
        )[:20]
        raise NotFound(
            f"No encuentro '{name[:120]}' en {self.import_dir}. Copia ahí el fichero exportado desde Maltego. "
            f"Disponibles: {', '.join(available) or 'ninguno'}."
        )

    async def import_graph(self, case_id: str, file_name: str) -> ImportResult:
        cid = validate_case_id(case_id)
        path = self.resolve_import_path(file_name)
        if path.stat().st_size > MAX_IMPORT_BYTES:
            raise InvalidInput("El fichero supera 20 MB.")
        data = path.read_bytes()
        graph = read_mtgx(data) if path.suffix.lower() == ".mtgx" else _read_csv(data)
        await self.store.ensure_case(cid)
        result = ImportResult(path)
        origin = f"import:{path.name}"[:120]
        ids: dict[str, str] = {}
        for item in graph.entities:
            try:
                entity = self.build_entity(
                    cid, item.maltego_type, item.value, 0.5, origin, clean_properties(item.properties)
                )
            except InvalidInput as exc:
                result.skipped.append(f"{item.maltego_type} '{item.value[:60]}': {exc}")
                continue
            entity, created = await self.store.upsert_entity(entity)
            ids[item.key] = entity.id
            result.entities += 1
            result.new_entities += int(created)
        for src, dst, label in graph.links:
            if src not in ids or dst not in ids or ids[src] == ids[dst]:
                continue
            try:
                lbl = normalize_edge_label(label) if label else "related_to"
            except InvalidInput:
                lbl = "related_to"
            await self.link(cid, ids[src], ids[dst], lbl, origin, 0.5)
            result.links += 1
        if graph.skipped:
            result.skipped.append(f"{graph.skipped} nodos sin tipo o sin valor")
        return result


def _read_csv(data: bytes) -> ImportedGraph:
    """CSV con cabecera source_type,source_value,relation,target_type,target_value[,confidence]."""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InvalidInput("El CSV debe estar en UTF-8.") from exc
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or not {"source_type", "source_value"} <= set(reader.fieldnames):
        raise InvalidInput(f"Cabecera CSV no reconocida; usa: {','.join(CSV_HEADER)}.")
    graph = ImportedGraph()
    keys: dict[tuple[str, str], str] = {}

    def key_for(etype: str, value: str) -> str:
        k = (etype.strip(), value.strip().lstrip("'"))
        if k not in keys:
            keys[k] = f"n{len(keys)}"
            graph.entities.append(ImportedEntity(keys[k], k[0] or "auto", k[1]))
        return keys[k]

    for row in reader:
        if not (row.get("source_value") or "").strip():
            graph.skipped += 1
            continue
        a = key_for(row.get("source_type") or "", row["source_value"])
        if (row.get("target_value") or "").strip():
            b = key_for(row.get("target_type") or "", row["target_value"])
            graph.links.append((a, b, (row.get("relation") or "").strip()))
    return graph


def _to_graphml(entities: list[EntityRecord], edges: list[EdgeRecord]) -> bytes:
    root = Element("graphml", xmlns="http://graphml.graphdrawing.org/xmlns")
    keys = [
        ("maltego_type", "node"),
        ("value", "node"),
        ("confidence", "node"),
        ("sources", "node"),
        ("label", "edge"),
        ("confidence", "edge"),
    ]
    for name, scope in keys:
        SubElement(root, "key", {"id": f"{scope}_{name}", "for": scope, "attr.name": name, "attr.type": "string"})
    graph = SubElement(root, "graph", id="G", edgedefault="directed")
    for e in entities:
        node = SubElement(graph, "node", id=e.id)
        for name, val in (
            ("maltego_type", e.maltego_type),
            ("value", e.value),
            ("confidence", str(e.confidence)),
            ("sources", ";".join(e.sources)),
        ):
            SubElement(node, "data", key=f"node_{name}").text = val
    for ed in edges:
        el = SubElement(graph, "edge", id=ed.id, source=ed.out_id, target=ed.in_id)
        SubElement(el, "data", key="edge_label").text = ed.label
        SubElement(el, "data", key="edge_confidence").text = str(ed.confidence)
    return bytes(tostring(root, encoding="utf-8", xml_declaration=True))


def _to_csv(entities: list[EntityRecord], edges: list[EdgeRecord]) -> str:
    """Una fila por relación (origen -> destino), apta para 'Import Graph from Table' de Maltego.

    Las entidades sin relaciones se incluyen con las columnas de destino vacías.
    """
    by_id = {e.id: e for e in entities}
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_HEADER)
    linked: set[str] = set()
    for ed in edges:
        a, b = by_id.get(ed.out_id), by_id.get(ed.in_id)
        if a and b:
            linked.update((a.id, b.id))
            writer.writerow(
                [
                    a.maltego_type,
                    _csv_safe(a.value),
                    ed.label,
                    b.maltego_type,
                    _csv_safe(b.value),
                    ed.confidence,
                ]
            )
    for e in entities:
        if e.id not in linked:
            writer.writerow([e.maltego_type, _csv_safe(e.value), "", "", "", e.confidence])
    return buf.getvalue()


def _csv_safe(value: str) -> str:
    """Evita inyección de fórmulas al abrir el CSV en Excel/LibreOffice."""
    if value[:1] in ("=", "@", "\t", "\r"):
        return "'" + value
    if value[:1] in ("+", "-") and not value[1:].replace(" ", "").isdigit():  # +34600... es un teléfono
        return "'" + value
    return value
