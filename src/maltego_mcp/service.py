"""Casos de uso del MCP: normalizan entradas, coordinan grafo y transforms."""

from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import logging
import os
import re
import secrets
import time
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from xml.etree.ElementTree import Element, SubElement, tostring

import httpx

from maltego_mcp.accounts import (
    SockPuppetPersona,
    generate_sockpuppet_persona,
    load_account_pool,
    save_persona_to_accounts_toml,
)
from maltego_mcp.analysis import (
    Action,
    EntityScore,
    Explanation,
    TransformStats,
    explain,
    learning_stats,
    next_best_actions,
    score_entities,
)
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
    MAX_NOTES_LEN,
    MAX_STEP_OUTPUTS,
    CaseRecord,
    EdgeRecord,
    EntityRecord,
    StepRecord,
    clamp_confidence,
    clean_properties,
    merge_entity,
    utc_now,
)
from maltego_mcp.errors import InvalidInput, MaltegoMcpError, NotFound, TransformError
from maltego_mcp.graph.base import CaseSummary, Direction, GraphStore, Neighbor, Page
from maltego_mcp.humint import (
    IDENTITY_TYPES,
    BehaviorAnalysis,
    IdentityOverlap,
    SubjectTimeline,
    analyze_subject_behavior,
    build_subject_timeline,
    calculate_identity_overlap,
    infer_relationship_attributes,
)
from maltego_mcp.machines import Machine, custom_machine
from maltego_mcp.maltego.mtgx import (
    ImportedEntity,
    ImportedGraph,
    ImportedLink,
    Layout,
    entity_visual_profile,
    read_mtgx,
    write_mtgx,
)
from maltego_mcp.report import ReportData, to_html, to_markdown
from maltego_mcp.transforms.builtin import PROVIDER_KEYS, BuiltinContext, new_http_client
from maltego_mcp.transforms.catalog import TransformCatalog, TransformServer, TransformSpec
from maltego_mcp.transforms.client import run_remote_transform
from maltego_mcp.transforms.protocol import TransformResponse

logger = logging.getLogger(__name__)
ExportFormat = Literal["json", "graphml", "csv", "mtgx", "report_md", "report_html"]
MAX_SIDECAR_STEPS = 5000
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
    round: int = 1
    stage: int = 1
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
    steps: int = 0
    skipped: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ExpandResult:
    entity: EntityRecord
    runs: list[TransformRun] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    not_run: list[str] = field(default_factory=list)
    unavailable: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Inventory:
    transforms: list[TransformSpec]
    machines: list[Machine]
    providers: dict[str, bool]
    servers: dict[str, str]
    accounts: list[dict[str, object]] = field(default_factory=list)


async def _probe_server(server: TransformServer) -> str:
    """Comprueba que un servidor TRX/iTDS responde (GET a la raíz)."""
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            resp = await client.get(server.url.rstrip("/") + "/")
    except httpx.HTTPError as exc:
        return f"sin conexión ({exc.__class__.__name__})"
    return f"responde (HTTP {resp.status_code})"


@dataclass(slots=True)
class InvestigationResult:
    case_id: str
    maltego_type: str
    strategy: str
    machine_result: MachineResult | None = None
    expand_result: ExpandResult | None = None
    summary: CaseSummary | None = None
    actions: list[Action] = field(default_factory=list)
    top: list[EntityScore] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _auto_case_id(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:40] or "caso"
    return validate_case_id(f"inv-{slug}-{datetime.now(UTC).strftime('%Y%m%d')}")


@dataclass(slots=True)
class MachineResult:
    root: EntityRecord
    machine: str
    steps: list[ChainStep] = field(default_factory=list)
    rounds: int = 0
    stopped_by_budget: bool = False
    unavailable: set[str] = field(default_factory=set)
    missing: set[str] = field(default_factory=set)

    @property
    def new_entities(self) -> int:
        return sum(s.new_entities for s in self.steps)


class OsintService:
    def __init__(
        self, store: GraphStore, catalog: TransformCatalog, export_dir: Path, import_dir: Path | None = None
    ) -> None:
        self.store = store
        self.catalog = catalog
        self.export_dir = export_dir
        self.import_dir = import_dir or export_dir.parent / "imports"
        self.env: dict[str, str] = dict(os.environ)
        self._http: httpx.AsyncClient | None = None

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
        notes: str = "",
    ) -> tuple[EntityRecord, bool]:
        cid = validate_case_id(case_id)
        entity = self.build_entity(cid, entity_type, value, confidence, source, parse_properties(properties))
        if notes.strip():
            entity = replace(entity, notes=notes.strip()[:MAX_NOTES_LEN])
        await self.store.ensure_case(cid)
        stored, created = await self.store.upsert_entity(entity)
        if created:
            await self.record_step(
                cid, "manual", f"upsert:{source.strip()[:60] or 'manual'}", stored, outputs=[stored.id], new_entities=1
            )
        return stored, created

    async def get_entity(self, case_id: str, eid: str) -> EntityRecord:
        cid, eid = validate_case_id(case_id), validate_entity_id(eid)
        ent = await self.store.get_entity(cid, eid)
        if ent is None:
            raise NotFound(f"La entidad '{eid}' no existe en el caso '{cid}'. Búscala con osint_search_entities.")
        return ent

    async def search(
        self, case_id: str, query: str, entity_type: str, limit: int, offset: int, sort: str = "value"
    ) -> Page[EntityRecord]:
        cid = validate_case_id(case_id) if case_id.strip() else ""
        mtype = resolve_entity_type(entity_type).maltego_type if entity_type.strip() else ""
        if sort != "priority":
            return await self.store.search_entities(cid, query.strip()[:200], mtype, limit, offset)
        if not cid:
            raise InvalidInput("sort=priority necesita case_id (la puntuación es relativa a un caso).")
        page = await self.store.search_entities(cid, query.strip()[:200], mtype, MAX_EXPORT_ITEMS, 0)
        scores = await self.scores(cid)
        ranked = sorted(page.items, key=lambda e: (-(scores[e.id].priority if e.id in scores else 0), e.value))
        return Page(ranked[offset : offset + limit], len(ranked), offset, limit)

    # ---------- relaciones ----------
    async def link(
        self,
        case_id: str,
        source_id: str,
        target_id: str,
        label: str,
        source: str,
        confidence: float,
        properties: list[str] | None = None,
        role: str = "",
        sentiment: str = "",
        weight: int = 1,
    ) -> tuple[EdgeRecord, bool]:
        cid = validate_case_id(case_id)
        out_id, in_id = validate_entity_id(source_id), validate_entity_id(target_id)
        if out_id == in_id:
            raise InvalidInput("source_id y target_id son la misma entidad; no se crean bucles.")
        lbl = normalize_edge_label(label)
        props = parse_properties(properties or [])
        if role.strip():
            props["humint.role"] = role.strip()
        if sentiment.strip():
            props["humint.sentiment"] = sentiment.strip()
        if weight > 1:
            props["humint.weight"] = str(weight)
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
            properties=clean_properties(props),
        )
        return await self.store.upsert_edge(edge)

    async def analyze_relationship(
        self,
        case_id: str,
        source_id: str,
        target_id: str,
        label: str = "related_to",
        source: str = "humint",
        confidence: float = 0.7,
        role: str = "",
        sentiment: str = "",
        weight: int = 1,
        properties: list[str] | None = None,
    ) -> tuple[EdgeRecord, bool]:
        cid = validate_case_id(case_id)
        src_ent = await self.get_entity(cid, source_id)
        dst_ent = await self.get_entity(cid, target_id)
        if src_ent.id == dst_ent.id:
            raise InvalidInput("source_id y target_id son la misma entidad; no se crean bucles.")
        _, edges = await self.store.export_case(cid, MAX_EXPORT_ITEMS)
        inferred = infer_relationship_attributes(src_ent, dst_ent, edges, role.strip(), sentiment.strip(), weight)
        extra = [f"{k}={v}" for k, v in inferred.items()] + list(properties or [])
        lbl = normalize_edge_label(label or f"humint_{inferred['humint.role']}")
        edge, created = await self.link(cid, src_ent.id, dst_ent.id, lbl, source, confidence, extra)
        await self.record_step(cid, "manual", f"analyze_relationship:{lbl}", src_ent, outputs=[dst_ent.id])
        return edge, created

    async def correlate_identities(
        self,
        case_id: str,
        source_id: str,
        target_id: str = "",
        threshold: float = 0.85,
        auto_link: bool = True,
    ) -> list[IdentityOverlap]:
        cid = validate_case_id(case_id)
        src_ent = await self.get_entity(cid, source_id)
        entities, edges = await self.store.export_case(cid, MAX_EXPORT_ITEMS)
        by_id = {e.id: e for e in entities}
        if target_id.strip():
            dst_ent = await self.get_entity(cid, target_id)
            if dst_ent.id == src_ent.id:
                raise InvalidInput("source_id y target_id son la misma entidad.")
            candidates = [dst_ent]
        else:
            candidates = [
                e
                for e in entities
                if e.id != src_ent.id and (e.maltego_type.lower() in IDENTITY_TYPES or e.label in ("alias", "person"))
            ]
            if not candidates:
                candidates = [e for e in entities if e.id != src_ent.id]

        results: list[IdentityOverlap] = []
        for cand in candidates:
            ov = calculate_identity_overlap(src_ent, cand, by_id, edges, threshold=threshold)
            if ov.same_individual and auto_link:
                props = [
                    f"humint.overlap_score={ov.probability}",
                    f"humint.handle_similarity={ov.handle_similarity}",
                    f"humint.metadata_similarity={ov.metadata_similarity}",
                    f"humint.stylometry_similarity={ov.stylometry_similarity}",
                    f"humint.graph_jaccard={ov.graph_jaccard}",
                    "humint.epistemic_status=hypothesis",
                    "maltego.link.manual.type=humint.HighlyLikelySameIndividual",
                ]
                await self.link(
                    cid,
                    src_ent.id,
                    cand.id,
                    "humint_highly_likely_same_individual",
                    "humint:correlate",
                    ov.probability,
                    props,
                )
                ov.edge_created = True
            results.append(ov)
        results.sort(key=lambda x: (-x.probability, x.target_value))
        await self.record_step(
            cid,
            "manual",
            "correlate_identities",
            src_ent,
            outputs=[r.target_id for r in results if r.same_individual],
        )
        return results

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
    def list_transforms(self, entity_type: str, category: str = "") -> list[TransformSpec]:
        specs = sorted(self.catalog.transforms.values(), key=lambda s: (s.category, s.name.lower()))
        if entity_type.strip():
            mtype = resolve_entity_type(entity_type).maltego_type
            specs = [s for s in specs if s.accepts(mtype)]
        if category.strip():
            specs = [s for s in specs if s.category.lower().startswith(category.strip().lower())]
        return specs

    async def inventory(self, entity_type: str, category: str, check_servers: bool) -> Inventory:
        machines = sorted(self.catalog.machines.machines.values(), key=lambda m: m.name)
        if entity_type.strip():
            mtype = resolve_entity_type(entity_type).maltego_type
            machines = [m for m in machines if m.accepts(mtype)]
        providers = {name: all(self.env.get(v, "").strip() for v in keys) for name, keys in PROVIDER_KEYS.items()}
        servers: dict[str, str] = {}
        remote = {s.server.name: s.server for s in self.catalog.transforms.values() if s.builtin is None}
        for name, server in remote.items():
            servers[name] = await _probe_server(server) if check_servers else server.url
        home_raw = (self.env.get("MALTEGO_MCP_HOME") or os.environ.get("MALTEGO_MCP_HOME") or "").strip()
        home_dir = Path(home_raw) if home_raw else self.export_dir.parent
        accounts = load_account_pool(home_dir, self.env).summary()
        return Inventory(self.list_transforms(entity_type, category), machines, providers, servers, accounts)

    def _coerce_auto_entity(
        self,
        entity: EntityRecord,
        entity_type: str,
        value: str,
        accepted_types: tuple[str, ...],
        properties: dict[str, str] | None = None,
    ) -> EntityRecord:
        if (
            entity_type.strip().lower() not in ("", "auto")
            or entity.maltego_type != "maltego.Phrase"
            or not accepted_types
            or entity.maltego_type.lower() in {t.lower() for t in accepted_types}
        ):
            return entity
        for candidate in accepted_types:
            try:
                return self.build_entity(entity.case_id, candidate, value, entity.confidence, "manual", properties)
            except InvalidInput:
                continue
        return entity

    async def run_transform(
        self,
        case_id: str,
        transform: str,
        entity_type: str,
        value: str,
        properties: list[str],
        soft_limit: int,
        save: bool,
        reason: str = "",
    ) -> TransformRun:
        cid = validate_case_id(case_id) if case_id.strip() else ""
        if save and not cid:
            raise InvalidInput("Para guardar resultados (save=true) indica case_id, o usa save=false.")
        spec = self.catalog.get(transform)
        props = parse_properties(properties)
        source_entity = self._coerce_auto_entity(
            self.build_entity(cid, entity_type, value, 1.0, "manual", props),
            entity_type,
            value,
            spec.input_types,
            props,
        )
        if not spec.accepts(source_entity.maltego_type):
            raise InvalidInput(
                f"El transform '{spec.name}' no acepta {source_entity.maltego_type}; "
                f"acepta: {', '.join(spec.input_types)}."
            )
        if save:
            await self.store.ensure_case(cid)
            source_entity, _ = await self.store.upsert_entity(source_entity)
        return await self._execute(spec, source_entity, soft_limit, save, reason)

    def _builtin_ctx(self) -> BuiltinContext:
        if self._http is None or self._http.is_closed:
            self._http = new_http_client()
        return BuiltinContext(self._http, self.env)

    async def _fetch(self, spec: TransformSpec, source: EntityRecord, soft_limit: int) -> TransformResponse:
        if spec.builtin is not None:
            if not spec.available(self.env):
                raise TransformError(
                    f"El transform '{spec.name}' necesita {', '.join(spec.requires)} (clave de API del proveedor)."
                )
            response = await spec.builtin.handler(
                self._builtin_ctx(), source.maltego_type, source.value, source.properties, soft_limit
            )
        else:
            response = await run_remote_transform(
                spec, source.maltego_type, source.value, source.properties, soft_limit=soft_limit
            )
        if response.exceptions:
            raise TransformError(
                f"El transform '{spec.name}' devolvió un error: " + " | ".join(x[:300] for x in response.exceptions)
            )
        return response

    async def _execute(
        self,
        spec: TransformSpec,
        source: EntityRecord,
        soft_limit: int,
        save: bool,
        reason: str = "",
        response: TransformResponse | None = None,
        fetch_error: str = "",
        started: float | None = None,
    ) -> TransformRun:
        """Consulta (o usa la respuesta ya obtenida), guarda los resultados y registra el paso en la memoria."""
        start = started if started is not None else time.perf_counter()
        error = fetch_error
        run = TransformRun(spec.name, source, saved=save)
        if not error:
            try:
                response = response or await self._fetch(spec, source, soft_limit)
                run = await self._ingest(spec, source, response, save)
            except MaltegoMcpError as exc:
                error = str(exc)
        if save and source.case_id:
            await self.record_step(
                source.case_id,
                "transform",
                spec.name,
                source,
                reason,
                outputs=[r.entity.id for r in run.results],
                new_entities=sum(r.created for r in run.results),
                error=error,
                duration_ms=int((time.perf_counter() - start) * 1000),
            )
        if error:
            raise TransformError(error)
        return run

    async def record_step(
        self,
        case_id: str,
        kind: str,
        action: str,
        source: EntityRecord | None = None,
        reason: str = "",
        outputs: list[str] | None = None,
        new_entities: int = 0,
        error: str = "",
        duration_ms: int = 0,
    ) -> StepRecord:
        return await self.store.append_step(
            StepRecord(
                seq=0,
                case_id=case_id,
                timestamp=utc_now(),
                kind=kind,
                action=action,
                input_id=source.id if source else "",
                input_value=source.value[:300] if source else "",
                reason=reason.strip()[:500],
                outputs=(outputs or [])[:MAX_STEP_OUTPUTS],
                new_entities=new_entities,
                error=error[:500],
                duration_ms=duration_ms,
            )
        )

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

    async def _run_many(
        self,
        pairs: list[tuple[TransformSpec, EntityRecord]],
        soft_limit: int,
        reason: str,
        budget: list[int] | None = None,
    ) -> list[TransformRun | str]:
        """Consulta en paralelo (acotado) y guarda en serie respetando el presupuesto de entidades nuevas."""
        sem = asyncio.Semaphore(CHAIN_CONCURRENCY)

        async def fetch(spec: TransformSpec, ent: EntityRecord) -> tuple[TransformResponse | None, str, float]:
            async with sem:
                start = time.perf_counter()
                try:
                    return await self._fetch(spec, ent, soft_limit), "", start
                except MaltegoMcpError as exc:
                    return None, str(exc), start

        fetched = await asyncio.gather(*(fetch(s, e) for s, e in pairs))
        out: list[TransformRun | str] = []
        for (spec, ent), (response, error, start) in zip(pairs, fetched, strict=True):
            if budget is not None and response is not None:
                if budget[0] <= 0:
                    out.append(f"{spec.name} sobre {ent.value[:60]}: omitido por presupuesto")
                    continue
                response.entities = response.entities[: budget[0]]
            try:
                run = await self._execute(
                    spec, ent, soft_limit, True, reason, response=response, fetch_error=error, started=start
                )
            except MaltegoMcpError as exc:
                out.append(f"{spec.name} sobre {ent.value[:60]}: {exc}")
                continue
            if budget is not None:
                budget[0] -= sum(r.created for r in run.results)
            out.append(run)
        return out

    async def expand_entity(
        self, case_id: str, eid: str, max_transforms: int, soft_limit: int, reason: str = ""
    ) -> ExpandResult:
        """Ejecuta sobre una entidad del caso todos los transforms disponibles que declaran su tipo."""
        cid, eid = validate_case_id(case_id), validate_entity_id(eid)
        entity = await self.store.get_entity(cid, eid)
        if entity is None:
            raise NotFound(f"La entidad '{eid}' no existe en el caso '{cid}'. Búscala con osint_search_entities.")
        candidates = [
            s
            for s in sorted(self.catalog.transforms.values(), key=lambda s: s.name.lower())
            if s.input_types and s.accepts(entity.maltego_type)
        ]
        specs = [s for s in candidates if s.available(self.env)]
        if not specs:
            raise InvalidInput(
                f"No hay transforms disponibles que acepten {entity.maltego_type}. Revisa osint_list_transforms."
            )
        result = ExpandResult(
            entity,
            not_run=[s.name for s in specs[max_transforms:]],
            unavailable=[s.name for s in candidates if not s.available(self.env)],
        )
        for item in await self._run_many([(s, entity) for s in specs[:max_transforms]], soft_limit, reason):
            if isinstance(item, str):
                result.errors.append(item)
            else:
                result.runs.append(item)
        return result

    async def run_machine(
        self,
        case_id: str,
        entity_type: str,
        value: str,
        machine: str,
        transforms: list[str],
        max_rounds: int,
        max_inputs_per_step: int,
        max_total_entities: int,
        soft_limit: int,
        reason: str = "",
    ) -> MachineResult:
        cid = validate_case_id(case_id)
        if machine.strip() and transforms:
            raise InvalidInput("Indica machine o transforms, no ambos.")
        if machine.strip():
            definition = self.catalog.machines.get(machine.strip())
        else:
            definition = custom_machine(transforms)
            for name in transforms:
                self.catalog.get(name)  # valida nombres antes de empezar
        await self.store.ensure_case(cid)
        built = self._coerce_auto_entity(
            self.build_entity(cid, entity_type, value, 1.0, "manual"),
            entity_type,
            value,
            definition.input_types,
        )
        root, _ = await self.store.upsert_entity(built)
        if not definition.accepts(root.maltego_type):
            types = ", ".join(definition.input_types)
            raise InvalidInput(f"La machine '{definition.name}' no acepta {root.maltego_type}; acepta: {types}.")
        start = time.perf_counter()
        result = MachineResult(root, definition.name)
        budget = [max_total_entities - 1]  # la entidad inicial cuenta dentro del total
        result.stopped_by_budget = budget[0] <= 0
        processed: set[tuple[str, str]] = set()
        frontier: list[EntityRecord] = [root]
        known: set[str] = {root.id}
        for round_no in range(1, max(1, max_rounds) + 1):
            round_found: list[EntityRecord] = []
            previous_stage: list[EntityRecord] = frontier
            for stage_no, stage in enumerate(definition.stages, 1):
                pool = frontier + round_found if definition.accumulate else previous_stage
                stage_found_start = len(round_found)
                for name in stage:
                    spec = self.catalog.transforms.get(name.lower())
                    if spec is None:
                        result.missing.add(name)
                        continue
                    if not spec.available(self.env):
                        result.unavailable.add(name)
                        continue
                    step = ChainStep(spec.name, round_no, stage_no)
                    accepted = [
                        ent for ent in pool if spec.accepts(ent.maltego_type) and (spec.name, ent.id) not in processed
                    ]
                    chosen = accepted[:max_inputs_per_step] if budget[0] > 0 else []
                    step.inputs, step.skipped_inputs = len(chosen), len(accepted) - len(chosen)
                    if not chosen:
                        continue
                    result.steps.append(step)
                    processed.update((spec.name, ent.id) for ent in chosen)
                    for item in await self._run_many(
                        [(spec, ent) for ent in chosen],
                        min(soft_limit, budget[0]),
                        reason or f"machine {definition.name}",
                        budget,
                    ):
                        if isinstance(item, str):
                            step.errors.append(item)
                            continue
                        for res in item.results:
                            step.outputs += 1
                            if res.entity.id not in known:
                                known.add(res.entity.id)
                                step.new_entities += 1
                                round_found.append(res.entity)
                    if budget[0] <= 0:
                        result.stopped_by_budget = True
                previous_stage = round_found[stage_found_start:]
                if not definition.accumulate and not previous_stage:
                    break
            frontier = round_found
            result.rounds = round_no
            if not frontier or budget[0] <= 0:
                break
        await self.record_step(
            cid,
            "machine",
            definition.name,
            root,
            reason,
            outputs=sorted(known - {root.id}),
            new_entities=sum(s.new_entities for s in result.steps),
            duration_ms=int((time.perf_counter() - start) * 1000),
        )
        return result

    # ---------- gestión de casos y entidades ----------
    async def delete_case(self, case_id: str, confirm: str) -> tuple[int, int]:
        cid = validate_case_id(case_id)
        if confirm.strip().lower() != cid:
            raise InvalidInput(f"Para borrar el caso escribe su id en confirm (confirm='{cid}'). No se puede deshacer.")
        return await self.store.delete_case(cid)

    async def merge_cases(self, target_case: str, source_case: str, expected_version: int = 0) -> tuple[int, int]:
        """Fusiona las entidades, relaciones y memoria de source_case (o 'all' para sub-casos) en target_case."""
        tgt = validate_case_id(target_case)
        await self.store.ensure_case(tgt)
        tgt_case = await self.store.get_case(tgt)
        if expected_version > 0 and tgt_case is not None and tgt_case.version != expected_version:
            raise InvalidInput(
                f"Conflicto de versión optimista en '{tgt}': la versión actual es {tgt_case.version} "
                f"(esperada {expected_version}). Recarga el estado del caso antes de fusionar."
            )
        if source_case.strip().lower() in ("*", "all"):
            all_cases = (await self.store.list_cases(500, 0)).items
            sources = [
                c.case_id
                for c in all_cases
                if c.case_id != tgt and (c.parent_case_id == tgt or c.case_id.startswith(f"{tgt}--"))
            ]
            if not sources:
                raise InvalidInput(f"No hay sub-casos derivados de '{tgt}' para fusionar.")
        else:
            src = validate_case_id(source_case)
            if tgt == src:
                raise InvalidInput("Los casos origen y destino son el mismo.")
            sources = [src]

        total_created = total_linked = 0
        existing_steps = await self.store.list_steps(tgt, 0, MAX_SIDECAR_STEPS)
        seen_step_keys = {(s.kind, s.action, s.input_id, s.reason) for s in existing_steps}
        for src in sources:
            entities, edges = await self.store.export_case(src, MAX_EXPORT_ITEMS)
            moved_e = [replace(e, case_id=tgt) for e in entities]
            moved_l = [replace(e, case_id=tgt, id=edge_id(tgt, e.out_id, e.label, e.in_id)) for e in edges]
            created, linked = await self.store.upsert_many(moved_e, moved_l)
            total_created += created
            total_linked += linked
            new_steps: list[StepRecord] = []
            for step in await self.store.list_steps(src, 0, MAX_SIDECAR_STEPS):
                tagged_reason = f"[fusionado de {src}] {step.reason}"[:500]
                key = (step.kind, step.action, step.input_id, tagged_reason)
                if key not in seen_step_keys:
                    seen_step_keys.add(key)
                    new_steps.append(replace(step, case_id=tgt, reason=tagged_reason))
            if new_steps:
                await self.store.append_steps(new_steps)
            await self.record_step(tgt, "manual", f"merge:{src}", new_entities=created)
        return total_created, total_linked

    async def fork_case(
        self, case_id: str, sub_roles: list[str] | None = None, description: str = ""
    ) -> list[dict[str, object]]:
        """Divide/delega un caso principal en sub-casos virtuales por rol para enjambres multi-agente."""
        cid = validate_case_id(case_id)
        parent, _ = await self.store.ensure_case(cid, description.strip()[:500])
        entities, edges = await self.store.export_case(cid, MAX_EXPORT_ITEMS)
        roles = [r.strip().lower() for r in (sub_roles or ["infra", "humint"]) if r.strip()]
        if not roles:
            roles = ["infra", "humint"]

        infra_cats = {"infraestructura", "artefacto", "cripto"}
        humint_cats = {"identidad", "social", "humint", "organizacion"}
        delegated: list[dict[str, object]] = []

        for raw_role in roles[:10]:
            slug = re.sub(r"[^a-z0-9_-]+", "-", raw_role).strip("-")[:18] or "sub"
            sub_id = validate_case_id(f"{cid[:42]}--{slug}")
            role_desc = f"Sub-caso [{slug}] delegado de {cid}" + (f": {description[:200]}" if description else "")
            sub_case, _ = await self.store.ensure_case(sub_id, role_desc, parent_case_id=cid)

            if slug in ("infra", "net", "red", "network", "cti"):
                filtered = [e for e in entities if resolve_entity_type(e.maltego_type).category in infra_cats]
            elif slug in ("humint", "socmint", "id", "identity", "identidad", "persona", "social"):
                filtered = [e for e in entities if resolve_entity_type(e.maltego_type).category in humint_cats]
            else:
                filtered = list(entities)
            seeds = filtered or list(entities)
            seed_ids = {e.id for e in seeds}
            sub_ents = [replace(e, case_id=sub_id) for e in seeds]
            sub_edges = [
                replace(ed, case_id=sub_id, id=edge_id(sub_id, ed.out_id, ed.label, ed.in_id))
                for ed in edges
                if ed.out_id in seed_ids and ed.in_id in seed_ids
            ]
            created, linked = await self.store.upsert_many(sub_ents, sub_edges) if sub_ents else (0, 0)
            await self.record_step(
                cid, "manual", f"fork:{sub_id}", reason=f"delegación multi-agente ({slug})", new_entities=created
            )
            delegated.append(
                {
                    "sub_case_id": sub_case.case_id,
                    "parent_case_id": cid,
                    "parent_version": parent.version,
                    "role": slug,
                    "seeded_entities": len(sub_ents),
                    "seeded_edges": linked,
                }
            )
        return delegated

    async def update_entity(
        self,
        case_id: str,
        eid: str,
        confidence: float,
        notes: str,
        properties: list[str],
        remove_properties: list[str],
        reason: str = "",
    ) -> EntityRecord:
        entity = await self.get_entity(case_id, eid)
        props = {k: v for k, v in entity.properties.items() if k not in set(remove_properties)}
        props.update(parse_properties(properties))
        updated = replace(
            entity,
            confidence=clamp_confidence(confidence) if confidence >= 0 else entity.confidence,
            notes=notes.strip()[:MAX_NOTES_LEN] if notes else entity.notes,
            properties=clean_properties(props),
            last_seen=utc_now(),
        )
        stored = await self.store.replace_entity(updated)
        await self.record_step(stored.case_id, "manual", "update_entity", stored, reason)
        return stored

    async def set_visual_style(
        self,
        case_id: str,
        eid: str,
        visual_weight: int = -1,
        visual_color: str = "",
        visual_size: str = "",
        reason: str = "",
    ) -> EntityRecord:
        """Configura o calcula automáticamente las propiedades visuales de un nodo para .mtgx."""
        entity = await self.get_entity(case_id, eid)
        nbs = await self.neighbors(entity.case_id, entity.id, "", "both", 100)
        auto_w, auto_c, auto_s, auto_b = entity_visual_profile(entity, len(nbs))
        w = visual_weight if visual_weight >= 0 else auto_w
        c = visual_color.strip() or auto_c
        s = visual_size.strip() or auto_s
        props = [
            f"visual.weight={w}",
            f"visual.color={c}",
            f"visual.size={s}",
            f"visual.bookmark={auto_b}",
        ]
        return await self.update_entity(case_id, eid, -1, "", props, [], reason or "set_visual_style")

    async def analyze_entity_behavior(
        self, case_id: str, eid: str, reason: str = ""
    ) -> tuple[EntityRecord, BehaviorAnalysis, list[EntityRecord]]:
        """Ejecuta el análisis conductual HUMINT enriquecido con el vecindario de la entidad en el caso."""
        entity = await self.get_entity(case_id, eid)
        nbs = await self.neighbors(entity.case_id, entity.id, "", "both", 50)
        nb_tuples = [(n.entity.maltego_type, n.entity.value, n.entity.properties) for n in nbs]
        analysis = analyze_subject_behavior(entity.value, entity.properties, entity.notes, nb_tuples)
        merged_notes = (
            f"{entity.notes}\n{analysis.summary_note}".strip()
            if entity.notes and analysis.summary_note not in entity.notes
            else (entity.notes or analysis.summary_note)
        )
        updated = await self.update_entity(
            entity.case_id,
            entity.id,
            -1,
            merged_notes,
            [f"{k}={v}" for k, v in analysis.subject_properties.items()],
            [],
            reason or "humint_analyze_behavior",
        )
        emitted: list[EntityRecord] = []
        for t in analysis.traits:
            child, _ = await self.upsert_entity(
                entity.case_id,
                t.maltego_type,
                t.value,
                t.weight / 100,
                "humint:AnalyzeSubjectBehavior",
                [f"{k}={v}" for k, v in t.properties.items()],
            )
            await self.link(
                entity.case_id,
                entity.id,
                child.id,
                t.edge_label.strip(),
                "humint:AnalyzeSubjectBehavior",
                t.weight / 100,
                ["humint.epistemic_status=hypothesis"],
            )
            emitted.append(child)
        return updated, analysis, emitted

    async def generate_persona_entity(
        self,
        case_id: str,
        seed_or_eid: str,
        properties: list[str],
        notes: str = "",
        reason: str = "",
    ) -> tuple[EntityRecord, SockPuppetPersona, Path | None]:
        """Genera un kit operativo de Sock Puppet (humint.Alias) en el caso y opcionalmente en accounts.toml."""
        cid = validate_case_id(case_id)
        props = parse_properties(properties)
        role = props.get("role", "security_researcher")
        region = props.get("region", "EU")
        site = props.get("site", props.get("target_site", ""))
        save_toml = props.get("save", "").strip().lower() in {"1", "true", "yes", "si", "sí"}
        persona = generate_sockpuppet_persona(
            role=role,
            region=region,
            target_site=site,
            seed=props.get("seed", seed_or_eid),
        )
        ent_props = [
            f"platform={site or 'multi'}",
            f"display_name={persona.display_name}",
            f"humint.role={persona.role}",
            f"humint.region={persona.region}",
            f"humint.timezone={persona.timezone}",
            f"humint.pgp_key_id={persona.pgp_key_id_hint}",
            "humint.sockpuppet=true",
        ]
        summary_note = (
            notes.strip()
            or f"[Sock Puppet Operativo] {persona.display_name} ({persona.role}, {persona.region}). Bio: {persona.bio}"
        )
        stored, _ = await self.upsert_entity(
            cid,
            "humint.Alias",
            persona.handle,
            0.95,
            "sockpuppet_generator",
            ent_props,
            summary_note,
        )
        saved_path: Path | None = None
        if save_toml:
            home_raw = (self.env.get("MALTEGO_MCP_HOME") or os.environ.get("MALTEGO_MCP_HOME") or "").strip()
            home_dir = Path(home_raw) if home_raw else self.export_dir.parent
            saved_path = save_persona_to_accounts_toml(home_dir, persona)
        await self.record_step(cid, "manual", "generate_persona", stored, reason or "sockpuppet_kit", [stored.id], 1)
        return stored, persona, saved_path

    async def delete_entity(self, case_id: str, eid: str, reason: str = "") -> int:
        entity = await self.get_entity(case_id, eid)
        removed = await self.store.delete_entity(entity.case_id, entity.id)
        await self.record_step(entity.case_id, "manual", "delete_entity", entity, reason)
        return removed

    async def unlink(self, case_id: str, source_id: str, target_id: str, label: str) -> bool:
        cid = validate_case_id(case_id)
        out_id, in_id = validate_entity_id(source_id), validate_entity_id(target_id)
        return await self.store.delete_edge(cid, edge_id(cid, out_id, normalize_edge_label(label), in_id))

    # ---------- análisis ----------
    def _provider_transforms(self) -> set[str]:
        return {s.name.lower() for s in self.catalog.transforms.values() if s.category.startswith("proveedor")}

    async def _case_state(self, case_id: str) -> tuple[list[EntityRecord], list[EdgeRecord], list[StepRecord]]:
        cid = validate_case_id(case_id)
        entities, edges = await self.store.export_case(cid, MAX_EXPORT_ITEMS)
        steps = await self.store.list_steps(cid, 0, MAX_SIDECAR_STEPS)
        return entities, edges, steps

    async def scores(self, case_id: str) -> dict[str, EntityScore]:
        entities, edges, _ = await self._case_state(case_id)
        return score_entities(entities, edges, self._provider_transforms())

    async def learning(self) -> dict[str, TransformStats]:
        return learning_stats(await self.store.list_steps("", 0, 20_000))

    async def suggest(self, case_id: str, limit: int) -> tuple[list[Action], dict[str, EntityScore]]:
        entities, edges, steps = await self._case_state(case_id)
        scores = score_entities(entities, edges, self._provider_transforms())
        specs = list(self.catalog.transforms.values())
        return next_best_actions(scores, steps, specs, self.env, await self.learning(), limit), scores

    async def explain_entity(self, case_id: str, eid: str) -> Explanation:
        entity = await self.get_entity(case_id, eid)
        entities, edges, steps = await self._case_state(entity.case_id)
        scores = score_entities(entities, edges, self._provider_transforms())
        return explain(entity, scores, steps, list(self.catalog.transforms.values()), self.env)

    async def timeline(self, case_id: str, since_seq: int, limit: int) -> list[StepRecord]:
        return await self.store.list_steps(validate_case_id(case_id), since_seq, limit)

    async def subject_timeline(self, case_id: str, entity_id: str = "", limit: int = 100) -> SubjectTimeline:
        cid = validate_case_id(case_id)
        eid = validate_entity_id(entity_id) if entity_id.strip() else ""
        if eid:
            await self.get_entity(cid, eid)
        entities, edges = await self.store.export_case(cid, MAX_EXPORT_ITEMS)
        return build_subject_timeline(cid, entities, edges, subject_id=eid, limit=limit)

    async def report_data(self, case_id: str, include_actions: bool = True) -> ReportData:
        cid = validate_case_id(case_id)
        case = await self.store.get_case(cid)
        if case is None:
            raise NotFound(f"El caso '{cid}' no existe. Revisa osint_list_cases.")
        entities, edges, steps = await self._case_state(cid)
        scores = score_entities(entities, edges, self._provider_transforms())
        actions: list[Action] = []
        if include_actions:  # recomendaciones: requieren el historial global (más caro)
            specs = list(self.catalog.transforms.values())
            actions = next_best_actions(scores, steps, specs, self.env, await self.learning(), 10)
        return ReportData(case, entities, edges, steps, scores, actions, utc_now())

    # ---------- investigación en una llamada ----------
    async def investigate(
        self,
        value: str,
        case_id: str,
        entity_type: str,
        machine: str,
        max_rounds: int,
        max_total_entities: int,
        reason: str = "",
    ) -> InvestigationResult:
        etype = resolve_type_for_value(entity_type, value)
        norm = normalize_value(etype, value)
        cid = validate_case_id(case_id) if case_id.strip() else _auto_case_id(norm)
        await self.store.ensure_case(cid, f"Investigación de {norm[:200]}")
        chosen = (
            self.catalog.machines.get(machine)
            if machine.strip()
            else self.catalog.machines.for_type(etype.maltego_type)
        )
        result = InvestigationResult(cid, etype.maltego_type, chosen.name if chosen else "expand_entity")
        if chosen is not None:
            result.machine_result = await self.run_machine(
                cid,
                etype.maltego_type,
                norm,
                chosen.name,
                [],
                max_rounds,
                10,
                max_total_entities,
                25,
                reason or "investigate",
            )
        else:
            root, _ = await self.store.upsert_entity(self.build_entity(cid, etype.maltego_type, norm, 1.0, "manual"))
            try:
                result.expand_result = await self.expand_entity(cid, root.id, 10, 25, reason or "investigate")
            except InvalidInput as exc:
                result.notes.append(str(exc))
        result.summary = await self.store.case_summary(cid, 5)
        result.actions, scores = await self.suggest(cid, 5)
        result.top = sorted(scores.values(), key=lambda s: -s.priority)[:8]
        await self.record_step(
            cid, "investigate", result.strategy, reason=reason, new_entities=result.summary.entity_count
        )
        return result

    # ---------- exportación ----------
    async def export_case(
        self, case_id: str, fmt: ExportFormat, layout: Layout = "hierarchical"
    ) -> tuple[Path, int, int]:
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
            steps = await self.store.list_steps(cid, 0, MAX_SIDECAR_STEPS)
            sidecar = {"format": "maltego-mcp/1", "case_id": cid, "steps": [x.to_dict() for x in steps]}
            content = write_mtgx(entities, edges, layout, sidecar)
        elif fmt in ("report_md", "report_html"):
            data = await self.report_data(cid)
            content = (to_markdown(data) if fmt == "report_md" else to_html(data)).encode("utf-8")
            path = path.with_suffix(".md" if fmt == "report_md" else ".html")
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
        records: dict[str, EntityRecord] = {}
        for item in graph.entities:
            try:
                entity = self.build_entity(
                    cid, item.maltego_type, item.value, item.confidence, origin, clean_properties(item.properties)
                )
            except InvalidInput as exc:
                result.skipped.append(f"{item.maltego_type} '{item.value[:60]}': {exc}")
                continue
            ids[item.key] = entity.id
            records[entity.id] = merge_entity(records.get(entity.id), entity)
        now = utc_now()
        edges: dict[str, EdgeRecord] = {}
        for link in graph.links:
            out_id, in_id = ids.get(link.source), ids.get(link.target)
            if not out_id or not in_id or out_id == in_id:
                continue
            try:
                lbl = normalize_edge_label(link.label) if link.label else "related_to"
            except InvalidInput:
                lbl = "related_to"
            eid = edge_id(cid, out_id, lbl, in_id)
            edges[eid] = EdgeRecord(
                eid,
                cid,
                lbl,
                out_id,
                in_id,
                clamp_confidence(link.confidence),
                [origin],
                now,
                now,
                clean_properties(link.properties),
            )
        result.new_entities, result.links = await self.store.upsert_many(list(records.values()), list(edges.values()))
        result.entities = len(records)
        # La memoria del .mtgx solo se añade la primera vez que se importa ese mismo fichero en el caso.
        digest = hashlib.sha256(data).hexdigest()[:16]
        marker = f"{path.name}#{digest}"
        already = any(
            x.kind == "import" and x.action.endswith(f"#{digest}")
            for x in await self.store.list_steps(cid, 0, MAX_SIDECAR_STEPS)
        )
        if not already:
            imported: list[StepRecord] = []
            for raw in list(graph.sidecar.get("steps", []))[:MAX_SIDECAR_STEPS]:
                try:
                    imported.append(StepRecord(**{**raw, "case_id": cid}))
                except TypeError:
                    continue
            await self.store.append_steps(imported)
            result.steps = len(imported)
        await self.record_step(cid, "import", marker, new_entities=result.new_entities)
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

    def key_for(etype: str, value: str, confidence: float) -> str:
        k = (etype.strip(), value.strip().lstrip("'"))
        if k not in keys:
            keys[k] = f"n{len(keys)}"
            graph.entities.append(ImportedEntity(keys[k], k[0] or "auto", k[1], confidence=confidence))
        return keys[k]

    for row in reader:
        if not (row.get("source_value") or "").strip():
            graph.skipped += 1
            continue
        try:
            confidence = float(row.get("confidence") or 0.5)
        except ValueError:
            confidence = 0.5
        has_target = bool((row.get("target_value") or "").strip())
        # En filas de relación la confianza es la del enlace; en filas sueltas, la de la entidad.
        a = key_for(row.get("source_type") or "", row["source_value"], 0.5 if has_target else confidence)
        if has_target:
            b = key_for(row.get("target_type") or "", row["target_value"], 0.5)
            graph.links.append(ImportedLink(a, b, (row.get("relation") or "").strip(), confidence))
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
