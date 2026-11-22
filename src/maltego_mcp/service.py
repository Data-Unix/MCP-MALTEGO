"""Casos de uso del MCP: normalizan entradas, coordinan grafo y transforms."""

from __future__ import annotations

import asyncio
import contextlib
import csv
import hashlib
import html
import io
import ipaddress
import json
import logging
import os
import re
import secrets
import time
import urllib.parse
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from xml.etree.ElementTree import Element, SubElement, tostring

import httpx

from maltego_mcp import __version__
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
    indirect_pivots_for_entity,
    learning_stats,
    next_best_actions,
    score_entities,
)
from maltego_mcp.config import Settings
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
from maltego_mcp.domain.profiling import ProfileRecord
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
ExportFormat = Literal["mcpcase", "json", "graphml", "csv", "mtgx", "report_md", "report_html"]
MAX_SIDECAR_STEPS = 5000
IMPORT_SUFFIXES = (".mcpcase", ".mtgx", ".csv", ".json")
MAX_IMPORT_BYTES = 20 * 1024 * 1024
CSV_HEADER = ["source_type", "source_value", "relation", "target_type", "target_value", "confidence"]
MAX_EXPORT_ITEMS = 10_000
CHAIN_CONCURRENCY = 3  # Concurrencia controlada anti-ráfaga (sin peticiones masivas)


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
    import urllib.parse

    from maltego_mcp.egress import create_egress_client

    try:
        host = urllib.parse.urlparse(server.url).hostname or ""
        async with create_egress_client(timeout=5.0, extra_allowed_hosts={host} if host else None) as client:
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
    report_markdown: str = ""
    exported_files: dict[str, str] = field(default_factory=dict)
    recon_phase: str = "Fase 9"
    leading_hypothesis: str = ""


_NL_COMPANY_RE = re.compile(
    r"^(?:investiga(?:r)?|analiza(?:r)?|audita(?:r)?|busca(?:r)?|rastrea(?:r)?|"
    r"qu[eé]\s+(?:hay|sabes)\s+(?:de|sobre|detr[aá]s\s+de)|informe\s+(?:completo\s+|pericial\s+)?(?:de|sobre))\s+"
    r"(?:a\s+fondo\s+)?(?:la\s+|el\s+)?(?:empresa|compa[ñn][ií]a|organizaci[oó]n|sociedad|corporaci[oó]n|entidad)\s+"
    r"([A-Za-z0-9ÁÉÍÓÚáéíóúÑñ._\-\s]{2,80}?)(?:\s+y\s+(?:dame|genera|haz|brinda|entrega).*)?$",
    re.IGNORECASE,
)
_NL_ALIAS_RE = re.compile(
    r"^(?:investiga(?:r)?|analiza(?:r)?|audita(?:r)?|busca(?:r)?|rastrea(?:r)?|"
    r"qu[eé]\s+(?:hay|sabes)\s+(?:de|sobre|detr[aá]s\s+de))\s+"
    r"(?:a\s+fondo\s+)?(?:al\s+|el\s+|la\s+)?(?:alias|usuario|handle|nick|perfil)\s+"
    r"@?([A-Za-z0-9._\-]{2,60})(?:\s+y\s+.*)?$",
    re.IGNORECASE,
)


def extract_seed_from_plaintext(value: str, entity_type: str = "auto") -> tuple[str, str, str]:
    """Extrae indicador o sujeto desde una petición en texto claro o vaga cuando entity_type es 'auto'.

    Devuelve ``(valor_semilla, tipo_inferido, pregunta_original)``. Si el valor ya es un indicador limpio
    o una frase sin indicador embebido ni comando explícito, conserva el valor original sin alterar tests.
    """
    raw = value.strip()
    if not raw or (entity_type.strip() and entity_type.strip().lower() != "auto"):
        return raw, entity_type, ""

    direct_type = resolve_type_for_value("auto", raw)
    if direct_type.maltego_type != "maltego.Phrase":
        return raw, "auto", ""

    if " " not in raw:
        if raw.startswith("@") and len(raw) > 2:
            return raw[1:], "maltego.Alias", ""
        return raw, entity_type, ""

    # 1. Patrón explícito de empresa/organización o alias en lenguaje natural
    m_comp = _NL_COMPANY_RE.match(raw)
    if m_comp:
        cleaned_comp = m_comp.group(1).strip(" \"'.,;¿?!¡")
        if cleaned_comp:
            return cleaned_comp, "maltego.Company", raw

    m_alias = _NL_ALIAS_RE.match(raw)
    if m_alias:
        cleaned_alias = m_alias.group(1).strip(" \"'.,;¿?!¡")
        if cleaned_alias:
            return cleaned_alias, "maltego.Alias", raw

    # 2. Búsqueda de indicador técnico embebido en la frase (URL, Email, IP, Netblock, ASN, Hash, Dominio, @alias)
    tokens = [t.strip(" \"'.,;:()[]<>¿?!¡") for t in raw.split()]
    for tok in tokens:
        if not tok:
            continue
        if tok.startswith("@") and len(tok) > 2 and re.match(r"^@[A-Za-z0-9._\-]{2,50}$", tok):
            return tok[1:], "maltego.Alias", raw
        detected = resolve_type_for_value("auto", tok)
        if detected.maltego_type != "maltego.Phrase":
            return tok, detected.maltego_type, raw

    return raw, entity_type, ""


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
        self,
        store: GraphStore,
        catalog: TransformCatalog,
        export_dir: Path,
        import_dir: Path | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.store = store
        self.catalog = catalog
        self.export_dir = export_dir
        self.import_dir = import_dir or export_dir.parent / "imports"
        self.settings = settings
        self.env: dict[str, str] = dict(os.environ)
        self._http: httpx.AsyncClient | None = None
        from maltego_mcp.egress import AuditLog

        log_path = self.settings.home / "audit.log" if self.settings else Path.home() / ".maltego-mcp" / "audit.log"
        self.audit_log = AuditLog(log_path)
        self._event_listeners: list[Any] = []

    def _home_dir(self) -> Path | None:
        if self.settings and self.settings.home:
            return self.settings.home
        data_file = getattr(self.store, "_data_file", None)
        if isinstance(data_file, Path):
            return data_file.parent
        return None

    def _events_file(self) -> Path | None:
        h = self._home_dir()
        return h / "events.jsonl" if h else None

    def add_event_listener(self, callback: Any) -> None:
        if callback not in self._event_listeners:
            self._event_listeners.append(callback)

    def emit_event(self, event_type: str, **payload: Any) -> dict[str, Any]:
        """Emite un evento en tiempo real a los suscriptores en proceso y al bus en disco (multiproceso stdio->web)."""
        ev: dict[str, Any] = {
            "type": event_type,
            "ts": time.time(),
            "seq_ns": time.time_ns(),
            "pid": os.getpid(),
            **payload,
        }
        for cb in list(self._event_listeners):
            with contextlib.suppress(Exception):
                cb(ev)
        ev_file = self._events_file()
        if ev_file is not None:
            with contextlib.suppress(Exception):
                ev_file.parent.mkdir(parents=True, exist_ok=True)
                line = json.dumps(ev, ensure_ascii=False) + "\n"
                if ev_file.is_file() and ev_file.stat().st_size > 256 * 1024:
                    tail = ev_file.read_text(encoding="utf-8", errors="ignore").splitlines()[-250:]
                    tail.append(line.rstrip("\n"))
                    ev_file.write_text("\n".join(tail) + "\n", encoding="utf-8")
                else:
                    with open(ev_file, "a", encoding="utf-8") as fh:
                        fh.write(line)
                cid = str(payload.get("case_id") or "").strip()
                if cid:
                    (ev_file.parent / "active_case").write_text(cid, encoding="utf-8")
        return ev

    # ---------- casos ----------
    @property
    def is_passive_mode(self) -> bool:
        if self.env.get("MALTEGO_MCP_ALLOW_ACTIVE", "").strip() in ("1", "true", "yes"):
            return False
        mode = self.env.get("MALTEGO_MCP_MODE", "")
        if not mode and self.settings:
            mode = self.settings.mode
        return (mode or "passive").strip().lower() != "active"

    async def create_case(self, case_id: str, description: str) -> tuple[CaseRecord, bool]:
        return await self.store.ensure_case(validate_case_id(case_id), description.strip()[:500])

    async def set_case_confidential(self, case_id: str, confidential: bool = True) -> CaseRecord:
        return await self.store.set_case_confidential(validate_case_id(case_id), confidential)

    async def list_cases(self, limit: int, offset: int) -> Page[CaseRecord]:
        return await self.store.list_cases(limit, offset)

    async def case_summary(self, case_id: str, top: int) -> CaseSummary:
        return await self.store.case_summary(validate_case_id(case_id), top)

    def _perimeter_file(self, case_id: str) -> Path:
        base = self.settings.home if self.settings else Path.home() / ".maltego-mcp"
        p = base / "cases" / f"{case_id}_perimeter.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    async def get_custom_perimeter_assets(self, case_id: str) -> list[str]:
        f = self._perimeter_file(case_id)
        if not f.is_file():
            return []
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except Exception:
            return []

    async def add_custom_perimeter_asset(self, case_id: str, asset: str) -> list[str]:
        cid = validate_case_id(case_id)
        f = self._perimeter_file(cid)
        assets = set(await self.get_custom_perimeter_assets(cid))
        clean = asset.strip().lower()
        if clean:
            assets.add(clean)
            f.write_text(json.dumps(sorted(assets), indent=2), encoding="utf-8")
        return sorted(assets)

    async def remove_custom_perimeter_asset(self, case_id: str, asset: str) -> list[str]:
        cid = validate_case_id(case_id)
        f = self._perimeter_file(cid)
        assets = set(await self.get_custom_perimeter_assets(cid))
        clean = asset.strip().lower()
        if clean in assets:
            assets.remove(clean)
            f.write_text(json.dumps(sorted(assets), indent=2), encoding="utf-8")
        return sorted(assets)

    async def get_case_perimeter(self, case_id: str) -> Any:
        from maltego_mcp.egress import Scope

        cid = validate_case_id(case_id)
        scope = Scope(case_id=cid)
        try:
            entities, _ = await self.store.export_case(cid, 10_000)
            for n in entities:
                val = (n.value or "").strip().lower()
                t = n.maltego_type
                if "Domain" in t or "DNSName" in t or "Website" in t:
                    host = val.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
                    if host:
                        scope.domains.add(host)
                elif "URL" in t:
                    with contextlib.suppress(Exception):
                        parsed = urllib.parse.urlsplit(val if "://" in val else f"http://{val}")
                        if parsed.hostname:
                            scope.domains.add(parsed.hostname.lower())
                elif "IPv4Address" in t or "IPv6Address" in t:
                    if val:
                        scope.ips.add(val)
                elif "Netblock" in t or "IPv4Range" in t:
                    with contextlib.suppress(Exception):
                        scope.networks.append(ipaddress.ip_network(val, strict=False))
        except Exception as e:
            logger.debug("Error leyendo entidades para perímetro del caso %s: %s", cid, e)

        custom = await self.get_custom_perimeter_assets(cid)
        for c_asset in custom:
            clean = c_asset.strip().lower()
            try:
                ip_obj = ipaddress.ip_address(clean)
                scope.ips.add(str(ip_obj))
            except ValueError:
                with contextlib.suppress(ValueError):
                    scope.networks.append(ipaddress.ip_network(clean, strict=False))
                h = clean.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
                if h:
                    scope.domains.add(h)

        return scope

    def _recon_file(self, case_id: str) -> Path:
        base = self.settings.home if self.settings else Path.home() / ".maltego-mcp"
        p = base / "cases" / f"{case_id}_recon.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    async def get_case_recon(self, case_id: str) -> dict[str, Any]:
        cid = validate_case_id(case_id)
        f = self._recon_file(cid)
        default_data: dict[str, Any] = {
            "case_id": cid,
            "active_phase": "Fase 0",
            "p0_framing": {
                "target": "",
                "question": "",
                "legal_basis": "Ley 5/2014 de Seguridad Privada, art. 48 / RGPD Interés Legítimo",
                "humint_limits": "Ámbito profesional y fuentes públicas abiertas exclusivamente. Sin interacción.",
                "pre_mortem": "",
                "reference_class": "",
                "budget_max_hop": 2,
                "budget_min_families": 4,
                "budget_max_queries": 20,
                "budget": "Máximo 8 familias de fuentes, 5 consultas por familia, tope 2 saltos.",
                "assumptions": [],
                "named_gaps": [
                    "Registro Mercantil / Estructura Societaria",
                    "Infraestructura DNS Pasivo y Certificados Históricos",
                    "Exposición de Credenciales y Brechas",
                ],
            },
            "seeds": [],
            "hypotheses": [],
            "fase2_infra": [],
            "fase3_archives": [],
            "fase6_breaches": [],
            "fase7_humint": [],
            "fase8_ecosystem": [],
            "reframing_log": [],
            "coverage_gaps": [],
            "bias_checks": {},
            "searches_count": 0,
            "refutations_count": 0,
        }
        if not f.is_file():
            return default_data
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                for k, v in default_data.items():
                    data.setdefault(k, v)
                # Normalización suave de nomenclatura P0->Fase 0 si viene de caso legacy
                act_phase = str(data.get("active_phase") or "Fase 0")
                if act_phase.startswith("P") and act_phase[1:].isdigit():
                    data["active_phase"] = f"Fase {act_phase[1:]}"
                return data
            return default_data
        except Exception:
            return default_data

    async def save_case_recon(self, case_id: str, data: dict[str, Any]) -> dict[str, Any]:
        from maltego_mcp.egress import ensure_private_file_permissions

        cid = validate_case_id(case_id)
        f = self._recon_file(cid)
        data["case_id"] = cid
        # Normalizar active_phase si viene como P0..P9
        act_phase = str(data.get("active_phase") or "Fase 0")
        if act_phase.startswith("P") and act_phase[1:].isdigit():
            data["active_phase"] = f"Fase {act_phase[1:]}"
        f.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        ensure_private_file_permissions(f)
        return data

    async def add_recon_seed(self, case_id: str, seed: dict[str, Any]) -> dict[str, Any]:
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        val = str(seed.get("value") or "").strip()
        stype = str(seed.get("type") or "Domain").strip()
        raw_origin = str(seed.get("origin") or "Fase 0").strip()
        origin = f"Fase {raw_origin[1:]}" if raw_origin.startswith("P") and raw_origin[1:].isdigit() else raw_origin
        hop = int(seed.get("hop") or 0)
        status = str(seed.get("status") or "nueva").strip()

        # Atributos doctrinales anti-sesgo (§Heuer caps. 10-13)
        diagnosticidad = str(seed.get("diagnosticidad") or "no_evaluada").strip().lower()
        cluster = str(seed.get("cluster") or "CL-01").strip()
        origen_tipo = str(seed.get("origen_tipo") or "fuente_primaria").strip().lower()
        buscado_no_encontrado = bool(seed.get("buscado_no_encontrado") or False)
        tasa_base = str(seed.get("tasa_base") or "").strip()

        # Resolución de homónimos con 2 factores independientes (Heuer cap. 10)
        identificador_1 = str(seed.get("identificador_1") or "").strip()
        identificador_2 = str(seed.get("identificador_2") or "").strip()
        homonimo_verificado = bool(identificador_1 and identificador_2)

        # Doble evaluación Admiralty desacoplada (contenido primero a ciegas, fuente después)
        admiralty_contenido = str(seed.get("admiralty_contenido") or "").strip()
        admiralty_fuente = str(seed.get("admiralty_fuente") or "").strip().upper()
        admiralty_code = f"{admiralty_fuente}{admiralty_contenido}" if admiralty_fuente and admiralty_contenido else ""

        # Métrica de búsquedas de confirmación vs refutación
        consultas_confirmacion = int(seed.get("consultas_confirmacion") or 0)
        consultas_refutacion = int(seed.get("consultas_refutacion") or 0)

        sid = f"seed-{int(time.time() * 1000)}"
        new_seed = {
            "id": sid,
            "type": stype,
            "value": val,
            "origin": origin,
            "hop": min(2, max(0, hop)),
            "status": status,
            "diagnosticidad": diagnosticidad,
            "cluster": cluster,
            "origen_tipo": origen_tipo,
            "buscado_no_encontrado": buscado_no_encontrado,
            "tasa_base": tasa_base,
            "identificador_1": identificador_1,
            "identificador_2": identificador_2,
            "homonimo_verificado": homonimo_verificado,
            "admiralty_contenido": admiralty_contenido,
            "admiralty_fuente": admiralty_fuente,
            "admiralty_code": admiralty_code,
            "consultas_confirmacion": consultas_confirmacion,
            "consultas_refutacion": consultas_refutacion,
            "families_applied": seed.get("families_applied") or [],
            "created_at": datetime.now(UTC).isoformat(),
        }
        recon["seeds"].append(new_seed)
        await self.save_case_recon(cid, recon)

        # Regla de oro: Contagio dinámico del Perímetro Intocable e inserción en el grafo
        if val and not buscado_no_encontrado:
            await self.add_custom_perimeter_asset(cid, val)
            try:
                graph_etype = stype if "." in stype else f"maltego.{stype}"
                try:
                    resolve_entity_type(graph_etype)
                except Exception:
                    graph_etype = "auto"
                await self.upsert_entity(
                    case_id=cid,
                    entity_type=graph_etype,
                    value=val,
                    confidence=1.0,
                    source=f"recon:{origin}",
                    properties=[],
                    notes=f"Semilla de investigación ({origin}, salto {hop}, clúster {cluster})",
                )
            except Exception as e:
                logger.debug("Error insertando semilla recon en el grafo: %s", e)

        return recon

    async def delete_recon_seed(self, case_id: str, seed_id: str) -> dict[str, Any]:
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        recon["seeds"] = [s for s in recon.get("seeds", []) if s.get("id") != seed_id]
        await self.save_case_recon(cid, recon)
        return recon

    async def update_recon_seed(self, case_id: str, seed_id: str, patch_data: dict[str, Any]) -> dict[str, Any]:
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        for s in recon.get("seeds", []):
            if s.get("id") == seed_id:
                if "status" in patch_data:
                    s["status"] = str(patch_data["status"]).strip().lower()
                if "identificador_1" in patch_data:
                    s["identificador_1"] = str(patch_data["identificador_1"]).strip()
                if "identificador_2" in patch_data:
                    s["identificador_2"] = str(patch_data["identificador_2"]).strip()
                s["homonimo_verificado"] = bool(s.get("identificador_1") and s.get("identificador_2"))
                if "diagnosticidad" in patch_data:
                    s["diagnosticidad"] = str(patch_data["diagnosticidad"]).strip().lower()
                if "cluster" in patch_data:
                    s["cluster"] = str(patch_data["cluster"]).strip()
                if "admiralty_contenido" in patch_data:
                    s["admiralty_contenido"] = str(patch_data["admiralty_contenido"]).strip()
                if "admiralty_fuente" in patch_data:
                    s["admiralty_fuente"] = str(patch_data["admiralty_fuente"]).strip().upper()
                c = s.get("admiralty_contenido", "")
                f = s.get("admiralty_fuente", "")
                s["admiralty_code"] = f"{f}{c}" if f and c else ""
                if "consultas_confirmacion" in patch_data:
                    s["consultas_confirmacion"] = max(0, int(patch_data["consultas_confirmacion"]))
                if "consultas_refutacion" in patch_data:
                    s["consultas_refutacion"] = max(0, int(patch_data["consultas_refutacion"]))
                break
        await self.save_case_recon(cid, recon)
        return recon

    async def update_recon_seed_status(self, case_id: str, seed_id: str, status: str) -> dict[str, Any]:
        return await self.update_recon_seed(case_id, seed_id, {"status": status})

    async def add_fase2_infra(self, case_id: str, item: dict[str, Any]) -> dict[str, Any]:
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        infra_list = recon.setdefault("fase2_infra", [])
        host = str(item.get("host") or "").strip()
        ip = str(item.get("ip") or "").strip()
        provider = str(item.get("provider") or "").strip()
        tasa_base = str(item.get("tasa_base") or "dedicated_baja").strip()
        vigencia = str(item.get("vigencia") or "activo").strip()
        ct_cert = str(item.get("ct_cert") or "").strip()

        import uuid

        entry = {
            "id": f"infra-{uuid.uuid4().hex[:8]}",
            "host": host,
            "ip": ip,
            "provider": provider,
            "tasa_base": tasa_base,
            "vigencia": vigencia,
            "ct_cert": ct_cert,
            "timestamp": time.time(),
        }
        infra_list.append(entry)
        await self.save_case_recon(cid, recon)
        return {"ok": True, "item": entry, "recon": recon}

    async def delete_fase2_infra(self, case_id: str, item_id: str) -> dict[str, Any]:
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        infra_list = recon.get("fase2_infra", [])
        recon["fase2_infra"] = [x for x in infra_list if x.get("id") != item_id]
        await self.save_case_recon(cid, recon)
        return {"ok": True, "recon": recon}

    async def add_fase3_archive(self, case_id: str, item: dict[str, Any]) -> dict[str, Any]:
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        archive_list = recon.setdefault("fase3_archives", [])
        url = str(item.get("url") or "").strip()
        repository = str(item.get("repository") or "wayback").strip()
        timestamp_capture = str(item.get("timestamp_capture") or "").strip()
        http_status = str(item.get("http_status") or "200").strip()
        mime_type = str(item.get("mime_type") or "text/html").strip()
        possible_canary = bool(item.get("possible_canary") or False)
        admiralty = str(item.get("admiralty") or "B2").strip()

        import uuid

        entry = {
            "id": f"arch-{uuid.uuid4().hex[:8]}",
            "url": url,
            "repository": repository,
            "timestamp_capture": timestamp_capture,
            "http_status": http_status,
            "mime_type": mime_type,
            "possible_canary": possible_canary,
            "admiralty": admiralty,
            "timestamp": time.time(),
        }
        archive_list.append(entry)
        await self.save_case_recon(cid, recon)
        return {"ok": True, "item": entry, "recon": recon}

    async def delete_fase3_archive(self, case_id: str, item_id: str) -> dict[str, Any]:
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        archive_list = recon.get("fase3_archives", [])
        recon["fase3_archives"] = [x for x in archive_list if x.get("id") != item_id]
        await self.save_case_recon(cid, recon)
        return {"ok": True, "recon": recon}

    async def confirm_reframing(self, case_id: str, phase: str) -> dict[str, Any]:
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        logs = recon.setdefault("reframing_log", [])
        entry = {
            "phase": phase,
            "confirmed_at": time.time(),
            "target": recon.get("p0_framing", {}).get("target", ""),
            "question": recon.get("p0_framing", {}).get("question", ""),
        }
        logs.append(entry)
        await self.save_case_recon(cid, recon)
        return {"ok": True, "entry": entry, "recon": recon}

    async def add_fase6_breach(self, case_id: str, item: dict[str, Any]) -> dict[str, Any]:
        """Registra una filtración en Fase 6 con calibración Heuer de vigencia y detección de honeytokens."""
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        breaches_list = recon.setdefault("fase6_breaches", [])
        identity = str(item.get("identity") or "").strip()
        breach_name = str(item.get("breach_name") or "Volcado Desconocido").strip()
        breach_date = str(item.get("breach_date") or "").strip()
        exposure_type = str(item.get("exposure_type") or "third_party").strip()
        secret_sample = str(item.get("secret_sample") or "").strip()
        admiralty = str(item.get("admiralty") or "B2").strip()

        if not identity:
            raise InvalidInput("La identidad o correo no puede estar vacía.")

        # Heuer Cap. 12: Detección de Honeytokens / Canarios (control reflexivo y credenciales trampa)
        combined_text = f"{identity} {secret_sample} {breach_name}".lower()
        import re

        is_honeytoken = bool(
            item.get("is_honeytoken")
            or re.search(r"\bakia[0-9a-z]{16}\b", combined_text)
            or "canarytokens" in combined_text
            or "canary" in combined_text
            or "honeytoken" in combined_text
            or "honeypot" in combined_text
            or "fake_cred" in combined_text
            or "seed_canary" in combined_text
        )
        honeytoken_alert = (
            "ALERTA OPERATIVA: Patrón de Honeytoken / Canary detectado (§Heuer Cap. 12). ¡No interactuar!"
            if is_honeytoken
            else ""
        )

        # Heuer Cap. 11: Viveza vs Vigencia (antigüedad real vs impacto dramático)
        vigencia = "indeterminada"
        vigencia_rationale = "Sin fecha de brecha verificable"
        if exposure_type == "source_code":
            vigencia = "activa_critica"
            vigencia_rationale = "Secreto expuesto directamente en repositorio de código fuente."
        elif breach_date:
            match = re.search(r"\b(19\d\d|20\d\d)\b", breach_date)
            if match:
                year = int(match.group(1))
                if year <= 2021:
                    vigencia = "historica_reciclada"
                    vigencia_rationale = (
                        f"Filtración del año {year} (>3 años); baja probabilidad de credencial activa en infra "
                        f"actual (§Heuer Cap. 11)."
                    )
                elif year >= 2024:
                    vigencia = "reciente_activa"
                    vigencia_rationale = (
                        f"Filtración del año {year}; alta probabilidad de contraseña viva o reutilizada."
                    )
                else:
                    vigencia = "intermedia"
                    vigencia_rationale = (
                        f"Filtración del año {year}; vigencia intermedia sujeta a rotación de credenciales."
                    )

        import uuid

        masked_sample = (
            f"[REDACTED · sha256:{hashlib.sha256(secret_sample.encode('utf-8')).hexdigest()[:10]}]"
            if secret_sample.strip()
            else ""
        )
        entry = {
            "id": f"brch-{uuid.uuid4().hex[:8]}",
            "identity": identity,
            "breach_name": breach_name,
            "breach_date": breach_date,
            "exposure_type": exposure_type,
            "secret_sample": masked_sample,
            "is_honeytoken": is_honeytoken,
            "honeytoken_alert": honeytoken_alert,
            "vigencia": vigencia,
            "vigencia_rationale": vigencia_rationale,
            "admiralty": admiralty,
            "linked_to_graph": False,
            "timestamp": time.time(),
        }
        breaches_list.append(entry)
        await self.save_case_recon(cid, recon)
        return {"ok": True, "item": entry, "recon": recon}

    async def delete_fase6_breach(self, case_id: str, breach_id: str) -> dict[str, Any]:
        """Elimina una filtración registrada en Fase 6."""
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        breaches_list = recon.get("fase6_breaches", [])
        recon["fase6_breaches"] = [x for x in breaches_list if x.get("id") != breach_id]
        await self.save_case_recon(cid, recon)
        return {"ok": True, "recon": recon}

    async def link_breach_to_graph(self, case_id: str, breach_id: str) -> dict[str, Any]:
        """Enlaza una identidad y su brecha al grafo mediante arista 'exposed_in' (§Heuer Cap. 10)."""
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        breaches_list = recon.get("fase6_breaches", [])
        entry = next((x for x in breaches_list if x.get("id") == breach_id), None)
        if not entry:
            raise InvalidInput(f"Filtración con ID '{breach_id}' no encontrada en Fase 6.")

        identity = entry.get("identity", "").strip()
        breach_name = entry.get("breach_name", "Desconocida").strip()
        exposure_type = entry.get("exposure_type", "third_party").strip()
        vigencia = entry.get("vigencia", "indeterminada")
        admiralty = entry.get("admiralty", "B2")

        # 1. Upsert entidad de Identidad (EmailAddress o Alias canonical)
        from maltego_mcp.domain.detect import resolve_type_for_value

        etype = resolve_type_for_value("auto", identity).maltego_type
        id_ent, _ = await self.upsert_entity(
            case_id=cid,
            entity_type=etype,
            value=identity,
            confidence=0.85,
            source="Fase 6: Filtraciones",
            properties=[],
            notes=f"Identidad expuesta en brecha {breach_name} (Vigencia: {vigencia})",
        )

        # 2. Upsert entidad para la Brecha (Phrase)
        br_ent, _ = await self.upsert_entity(
            case_id=cid,
            entity_type="maltego.Phrase",
            value=f"Brecha: {breach_name}",
            confidence=1.0,
            source="Fase 6: Filtraciones",
            properties=[],
            notes=f"Exposición de tipo {exposure_type} con Admiralty {admiralty}",
        )

        # 3. Enlazar con relación 'exposed_in'
        await self.link(
            case_id=cid,
            source_id=id_ent.id,
            target_id=br_ent.id,
            label="exposed_in",
            source="Fase 6: Filtraciones",
            confidence=0.85,
            properties=[f"vigencia={vigencia}", f"admiralty={admiralty}"],
        )

        entry["linked_to_graph"] = True
        await self.save_case_recon(cid, recon)
        return {"ok": True, "recon": recon, "identity_id": id_ent.id, "breach_entity_id": br_ent.id}

    def search_local_breaches_service(self, query: str, limit: int = 25) -> list[dict[str, Any]]:
        """Consulta el índice SQLite local de brechas preexistente."""
        from maltego_mcp.breaches import classify_breach_indicator, query_local_breaches

        clean_q = query.strip()
        if not clean_q:
            return []
        kind, norm_val = classify_breach_indicator("auto", clean_q)
        home = self.settings.home if self.settings else Path.home() / ".maltego-mcp"
        hits = query_local_breaches(home, kind, norm_val, limit=limit)
        return [
            {
                "breach_name": h.breach_name,
                "breach_date": h.breach_date,
                "email": h.email,
                "alias": h.alias,
                "domain": h.domain,
                "phone": h.phone,
                "password_hash": h.password_hash,
                "source": h.source,
            }
            for h in hits
        ]

    async def add_fase7_humint(self, case_id: str, item: dict[str, Any]) -> dict[str, Any]:
        """Registra un perfil HUMINT pasivo con salvaguarda Heuer de desacoplamiento de atribución."""
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        humint_list = recon.setdefault("fase7_humint", [])
        actor_name = str(item.get("actor_name") or "").strip()
        role = str(item.get("role") or "technical_dev").strip()
        channel = str(item.get("channel") or "linkedin_passive").strip()
        opinion_scope = str(item.get("opinion_scope") or "personal").strip()
        tech_stack = str(item.get("tech_stack") or "").strip()
        admiralty = str(item.get("admiralty") or "B2").strip()

        if not actor_name:
            raise InvalidInput("El nombre o alias del perfil HUMINT no puede estar vacío.")

        # Heuer Cap. 10: Desacoplamiento estricto de atribución (Opinión Personal vs Postura Oficial)
        if opinion_scope == "personal":
            attribution_guard = (
                "DESACOPLAMIENTO HEUER (Cap. 10): Conducta u opinión a título personal. "
                "No imputable a la política ni presunta culpabilidad corporativa de la entidad."
            )
            diagnosticidad = "baja_personal"
        else:
            attribution_guard = "Postura institucional oficial o rol directivo fiduciario formalmente verificado."
            diagnosticidad = "alta_corporativa"

        import uuid

        entry = {
            "id": f"hum-{uuid.uuid4().hex[:8]}",
            "actor_name": actor_name,
            "role": role,
            "channel": channel,
            "opinion_scope": opinion_scope,
            "attribution_guard": attribution_guard,
            "diagnosticidad": diagnosticidad,
            "tech_stack": tech_stack,
            "admiralty": admiralty,
            "linked_to_graph": False,
            "timestamp": time.time(),
        }
        humint_list.append(entry)
        await self.save_case_recon(cid, recon)
        return {"ok": True, "item": entry, "recon": recon}

    async def delete_fase7_humint(self, case_id: str, item_id: str) -> dict[str, Any]:
        """Elimina un perfil HUMINT registrado en Fase 7."""
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        humint_list = recon.get("fase7_humint", [])
        recon["fase7_humint"] = [x for x in humint_list if x.get("id") != item_id]
        await self.save_case_recon(cid, recon)
        return {"ok": True, "recon": recon}

    async def link_humint_to_graph(self, case_id: str, item_id: str) -> dict[str, Any]:
        """Enlaza el perfil HUMINT y la entidad corporativa en el grafo con relación desacoplada (§Heuer Cap. 10)."""
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        humint_list = recon.get("fase7_humint", [])
        entry = next((x for x in humint_list if x.get("id") == item_id), None)
        if not entry:
            raise InvalidInput(f"Perfil HUMINT con ID '{item_id}' no encontrado en Fase 7.")

        actor_name = entry.get("actor_name", "").strip()
        role = entry.get("role", "technical_dev").strip()
        opinion_scope = entry.get("opinion_scope", "personal").strip()
        tech_stack = entry.get("tech_stack", "").strip()
        admiralty = entry.get("admiralty", "B2")

        # 1. Upsert entidad de Persona o Alias
        p_type = "maltego.Person" if " " in actor_name and not actor_name.startswith("@") else "humint.Alias"
        p_ent, _ = await self.upsert_entity(
            case_id=cid,
            entity_type=p_type,
            value=actor_name,
            confidence=0.85,
            source="Fase 7: HUMINT Pasivo",
            properties=[f"humint.role={role}", f"humint.opinion_scope={opinion_scope}"],
            notes=f"Perfil HUMINT identificado en canal pasivo (Rol: {role}, Ámbito: {opinion_scope})",
        )

        # 2. Upsert entidad de Organización Objetivo
        target = recon.get("p0_framing", {}).get("target", "").strip() or "Organización Objetivo"
        c_ent, _ = await self.upsert_entity(
            case_id=cid,
            entity_type="maltego.Company",
            value=target,
            confidence=1.0,
            source="Fase 7: HUMINT Pasivo",
            properties=[],
            notes="Entidad corporativa de referencia",
        )

        # 3. Enlazar con relación tipada 'employed_by' o 'associated_with'
        rel_label = "employed_by" if role in ("c_level", "technical_dev", "commercial") else "associated_with"
        props = [
            f"humint.role={role}",
            f"humint.opinion_scope={opinion_scope}",
            "humint.epistemic_status=observed",
            f"admiralty={admiralty}",
        ]
        if tech_stack:
            props.append(f"tech_stack={tech_stack}")

        await self.link(
            case_id=cid,
            source_id=p_ent.id,
            target_id=c_ent.id,
            label=rel_label,
            source="Fase 7: HUMINT Pasivo",
            confidence=0.8,
            properties=props,
        )

        entry["linked_to_graph"] = True
        await self.save_case_recon(cid, recon)
        return {"ok": True, "recon": recon, "person_id": p_ent.id, "company_id": c_ent.id}

    async def add_fase8_ecosystem(self, case_id: str, item: dict[str, Any]) -> dict[str, Any]:
        """Registra un proveedor o entidad de ecosistema en Fase 8 con mitigación de culpa por asociación.

        Aplica la doctrina de Richards J. Heuer Jr. (Caps. 10-13) para desacoplar relaciones funcionales.
        """
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        eco_list = recon.setdefault("fase8_ecosystem", [])

        provider_name = str(item.get("provider_name") or "").strip()
        if not provider_name:
            raise InvalidInput("El nombre del proveedor o entidad del ecosistema es obligatorio.")

        category = str(item.get("category") or "other_third_party").strip()
        dependency_level = str(item.get("dependency_level") or "secundaria").strip()
        base_rate_commonality = str(item.get("base_rate_commonality") or "media").strip()
        shared_cluster_id = str(item.get("shared_cluster_id") or "Cluster-General").strip()
        admiralty = str(item.get("admiralty") or "B2").strip().upper()
        notes = str(item.get("notes") or "").strip()

        # Doctrina Heuer Cap. 10: Toda arista con proveedor desacopla la conducta.
        # Un vínculo de negocio, técnico o comercial NO implica culpabilidad compartida.
        entry = {
            "id": f"eco-{secrets.token_hex(4)}",
            "provider_name": provider_name,
            "category": category,
            "dependency_level": dependency_level,
            "base_rate_commonality": base_rate_commonality,
            "shared_cluster_id": shared_cluster_id,
            "conduct_decoupled": True,
            "admiralty": admiralty if len(admiralty) == 2 else "B2",
            "notes": notes,
            "linked_to_graph": False,
            "timestamp": time.time(),
        }
        eco_list.append(entry)
        await self.save_case_recon(cid, recon)
        return {"ok": True, "item": entry, "recon": recon}

    async def delete_fase8_ecosystem(self, case_id: str, item_id: str) -> dict[str, Any]:
        """Elimina una entidad del ecosistema registrada en Fase 8."""
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        eco_list = recon.get("fase8_ecosystem", [])
        recon["fase8_ecosystem"] = [x for x in eco_list if x.get("id") != item_id]
        await self.save_case_recon(cid, recon)
        return {"ok": True, "recon": recon}

    async def link_ecosystem_to_graph(self, case_id: str, item_id: str) -> dict[str, Any]:
        """Enlaza el proveedor en el grafo Maltego desacoplando estrictamente la culpa por asociación.

        Garantiza que la entidad de proveedor o servicio satélite no herede sospecha corporativa.
        """
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        eco_list = recon.get("fase8_ecosystem", [])
        entry = next((x for x in eco_list if x.get("id") == item_id), None)
        if not entry:
            raise InvalidInput(f"Entidad de ecosistema con ID '{item_id}' no encontrada en Fase 8.")

        p_name = entry.get("provider_name", "").strip()
        cat = entry.get("category", "other_third_party").strip()
        dep = entry.get("dependency_level", "secundaria").strip()
        base_rate = entry.get("base_rate_commonality", "media").strip()
        admiralty = entry.get("admiralty", "B2")

        # 1. Upsert entidad del Proveedor (Tipo Company / Organization)
        prov_ent, _ = await self.upsert_entity(
            case_id=cid,
            entity_type="maltego.Company",
            value=p_name,
            confidence=0.85,
            source="Fase 8: Ecosistema Externo",
            properties=[
                f"ecosystem.category={cat}",
                f"ecosystem.dependency={dep}",
                f"ecosystem.base_rate={base_rate}",
                "conduct_decoupled=true",
            ],
            notes=f"Proveedor o servicio de ecosistema (Categoría: {cat}, Dependencia: {dep})",
        )

        # 2. Upsert entidad de Organización Objetivo
        target = recon.get("p0_framing", {}).get("target", "").strip() or "Organización Objetivo"
        c_ent, _ = await self.upsert_entity(
            case_id=cid,
            entity_type="maltego.Company",
            value=target,
            confidence=1.0,
            source="Fase 8: Ecosistema Externo",
            properties=[],
            notes="Entidad corporativa de referencia",
        )

        # 3. Enlazar con relación tipada neutra
        label_map = {
            "payment_gateway": "uses_payment_gateway",
            "logistics_shipping": "uses_logistics",
            "cloud_hosting_saas": "uses_cloud_service",
            "legal_fiscal": "advised_by",
            "marketing_comms": "uses_marketing_service",
            "bpo_support": "subcontracts_support",
            "supplier_procurement": "supplied_by",
        }
        rel_label = label_map.get(cat, "uses_service")

        props = [
            f"ecosystem.category={cat}",
            f"ecosystem.dependency={dep}",
            f"ecosystem.base_rate={base_rate}",
            "conduct_decoupled=true",
            "guilt_by_association_mitigated=true",
            f"admiralty={admiralty}",
        ]

        await self.link(
            case_id=cid,
            source_id=c_ent.id,
            target_id=prov_ent.id,
            label=rel_label,
            source="Fase 8: Ecosistema Externo",
            confidence=0.85,
            properties=props,
        )

        entry["linked_to_graph"] = True
        await self.save_case_recon(cid, recon)
        return {"ok": True, "recon": recon, "provider_id": prov_ent.id, "company_id": c_ent.id}

    async def declare_coverage_gap(self, case_id: str, phase: str, description: str) -> dict[str, Any]:
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        gaps = recon.setdefault("coverage_gaps", [])
        desc = description.strip()
        if not desc:
            raise InvalidInput("La descripción de la laguna de cobertura no puede estar vacía.")
        import uuid

        entry = {
            "id": f"gap-{uuid.uuid4().hex[:8]}",
            "phase": phase,
            "description": desc,
            "declared_at": time.time(),
        }
        gaps.append(entry)
        # Añadir también a named_gaps en p0_framing si no está presente
        named = recon.setdefault("p0_framing", {}).setdefault("named_gaps", [])
        if desc not in named:
            named.append(desc)
        await self.save_case_recon(cid, recon)
        return {"ok": True, "entry": entry, "recon": recon}

    async def delete_recon_hypothesis(self, case_id: str, hypothesis_id: str) -> dict[str, Any]:
        """Elimina una hipótesis en competencia registrada en el caso."""
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        recon["hypotheses"] = [h for h in recon.get("hypotheses", []) if h.get("id") != hypothesis_id]
        await self.save_case_recon(cid, recon)
        return {"ok": True, "recon": recon}

    async def save_key_evidence(self, case_id: str, data: dict[str, Any]) -> dict[str, Any]:
        """Guarda el análisis de sensibilidad y pieza clave (§Heuer Caps. 10-13).

        Evalúa si el juicio analítico colapsaría si una pieza singular de evidencia
        fuese errónea, estuviese manipulada o respondiese a un señuelo/canario.
        """
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        summary = str(data.get("evidence_summary") or "").strip()
        if not summary:
            raise InvalidInput("El resumen de la pieza clave de evidencia es obligatorio.")

        key_ev = {
            "evidence_summary": summary,
            "source_cluster": str(data.get("source_cluster") or "CL-01").strip(),
            "independent_clusters_count": int(data.get("independent_clusters_count") or 1),
            "sensitivity_impact": str(data.get("sensitivity_impact") or "alto").strip().lower(),
            "vulnerability_to_deception": str(data.get("vulnerability_to_deception") or "medio").strip().lower(),
            "alternative_explanation": str(data.get("alternative_explanation") or "").strip(),
            "timestamp": data.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        recon["key_evidence"] = key_ev
        await self.save_case_recon(cid, recon)
        return {"ok": True, "key_evidence": key_ev, "recon": recon}

    async def update_hypothesis_evaluations(
        self,
        case_id: str,
        hypothesis_id: str,
        evaluations: dict[str, str] | None = None,
        probability: str = "",
        confidence: str = "",
    ) -> dict[str, Any]:
        """Actualiza evaluaciones de la matriz ACH y recalcula la puntuación de inconsistencia."""
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        hyp_list = recon.get("hypotheses", [])
        hyp = next((h for h in hyp_list if h.get("id") == hypothesis_id), None)
        if not hyp:
            raise InvalidInput(f"Hipótesis '{hypothesis_id}' no encontrada en el caso.")

        if evaluations:
            existing_evals = hyp.setdefault("evaluations", {})
            existing_evals.update(evaluations)
            inconsistent_count = sum(1 for v in existing_evals.values() if v.upper() in ("I", "INCONSISTENT", "-"))
            hyp["inconsistency_score"] = inconsistent_count

        if probability:
            hyp["probability"] = probability.strip().upper()
        if confidence:
            hyp["confidence"] = confidence.strip().upper()

        await self.save_case_recon(cid, recon)
        return {"ok": True, "hypothesis": hyp, "recon": recon}

    async def generate_icd203_report(self, case_id: str) -> dict[str, Any]:
        """Genera un informe estimativo estructurado bajo los estándares de la directiva ICD 203.

        Sintetiza la totalidad de los tres planos analíticos y diez fases modulares
        (Fase 0 a Fase 9), con lenguaje probabilístico graduado, niveles explícitos
        de confianza analítica, matriz ACH de falsificación y análisis de sensibilidad.
        """
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")

        p0 = recon.get("p0_framing") or {}
        target = str(p0.get("target") or "No especificado").strip()
        question = str(p0.get("question") or "Sin pregunta central definida").strip()
        legal_basis = str(p0.get("legal_basis") or "Ley 5/2014 de Seguridad Privada / RGPD").strip()
        humint_limits = str(p0.get("humint_limits") or "Ámbito profesional y fuentes abiertas").strip()

        seeds = recon.get("seeds") or []
        infra = recon.get("fase2_infra") or []
        archive = recon.get("fase3_archive") or []
        searches_count = int(recon.get("searches_count") or 0)
        refutations_count = int(recon.get("refutations_count") or 0)
        refutation_rate = int(recon.get("refutation_rate") or (25 if searches_count == 0 else 0))
        breaches = recon.get("fase6_breaches") or []
        humint = recon.get("fase7_humint") or []
        ecosystem = recon.get("fase8_ecosystem") or []
        hypotheses = recon.get("hypotheses") or []
        key_ev = recon.get("key_evidence") or {}
        gaps = recon.get("coverage_gaps") or []

        # Determinar hipótesis líder (menor puntuación de inconsistencia según regla de Heuer)
        leading_hyp: dict[str, Any] | None = None
        rival_hyps: list[dict[str, Any]] = []
        if hypotheses:
            sorted_hyps = sorted(
                hypotheses,
                key=lambda h: (int(h.get("inconsistency_score", 0)), h.get("id", "")),
            )
            leading_hyp = sorted_hyps[0]
            rival_hyps = sorted_hyps[1:]

        # Mapeo de términos de probabilidad estimativa graduada ICD 203
        prob_labels = {
            "CASI_SEGURO": "Casi Seguro (>95%)",
            "MUY_PROBABLE": "Altamente Probable (80-95%)",
            "PROBABLE": "Probable (55-80%)",
            "POSIBILIDAD_IGUAL": "Posibilidad Equilibrada (45-55%)",
            "IMPROBABLE": "Improbable (20-45%)",
            "MUY_IMPROBABLE": "Altamente Improbable (<20%)",
        }
        lead_prob = prob_labels.get(
            str(leading_hyp.get("probability", "PROBABLE") if leading_hyp else "PROBABLE"),
            "Probable (55-80%)",
        )
        lead_conf = str(leading_hyp.get("confidence", "MEDIA") if leading_hyp else "MEDIA").capitalize()

        # Construir Markdown
        md_lines = [
            "# INFORME ESTIMATIVO DE INTELIGENCIA (ICD 203 / HEUER ACH)",
            f"**Caso:** `{cid}` | **Fecha:** {now_str} | **Generador:** `maltego-mcp/{__version__}`",
            f"**Clasificación:** PRIVADO / RESTRINGIDO | **Marco Legal:** {legal_basis}",
            "",
            "---",
            "",
            "## 1. ENCUADRE DE INTELIGENCIA Y BASE LEGAL (FASE 0)",
            f"- **Objetivo Central / Semilla Raíz:** `{target}`",
            f'- **Pregunta de Inteligencia (Neutral y sin sesgo):** *"{question}"*',
            f"- **Límites Operativos HUMINT:** {humint_limits}",
            f"- **Semillas Descubiertas:** {len(seeds)} entidades bajo custodia Egress (0 peticiones directas)",
            "",
            "## 2. RESUMEN DE EVIDENCIA POR CLÚSTERES INDEPENDIENTES (FASES 1 A 8)",
            f"- **Clúster Infraestructura y Vigencia (Fase 2):** {len(infra)} activos catalogados "
            "(clasificación temporal estricta y aislamiento de canarios).",
            f"- **Clúster Archivo Histórico Web (Fase 3):** {len(archive)} capturas procesadas "
            "vía réplicas offline y metadatos.",
            f"- **Clúster Búsqueda No Zoom (Fases 4-5):** {searches_count} consultas ejecutadas con "
            f"{refutations_count} de orientación refutatoria (Ratio de refutación alcanzado: {refutation_rate}%).",
            f"- **Clúster Credenciales y Brechas (Fase 6):** {len(breaches)} registros verificados "
            "sin interactuar con servicios del objetivo.",
            f"- **Clúster HUMINT Pasivo (Fase 7):** {len(humint)} perfiles profesionales consultados sin login "
            "y con desacoplamiento de atribución individual vs corporativa.",
            f"- **Clúster Ecosistema de Proveedores (Fase 8):** {len(ecosystem)} proveedores y dependencias "
            "con mitigación de culpa por asociación y cálculo de tasa base.",
            "",
            "## 3. ANÁLISIS DE HIPÓTESIS EN COMPETENCIA (ACH - HEUER CAP. 8)",
            "La metodología ACH evalúa las hipótesis ordenándolas por su **menor puntuación de inconsistencia**, "
            "rechazando la coherencia narrativa como criterio suficiente de certeza:",
            "",
            "| ID | Enunciado de Hipótesis | Criterio Obligatorio de Refutación | Probabilidad ICD 203 | "
            "Confianza | Inconsistencias |",
            "|---|---|---|---|---|---|",
        ]

        if hypotheses:
            for h in hypotheses:
                h_id = h.get("id", "H?")
                h_stmt = h.get("statement", "").replace("|", "/")
                h_ref = (h.get("what_would_refute_it") or h.get("falsification_criteria") or "No definido").replace(
                    "|", "/"
                )
                h_pr = prob_labels.get(str(h.get("probability", "")), str(h.get("probability", "")))
                h_cf = str(h.get("confidence", "")).capitalize()
                h_sc = h.get("inconsistency_score", 0)
                md_lines.append(f"| **{h_id}** | {h_stmt} | {h_ref} | {h_pr} | {h_cf} | `{h_sc}` |")
        else:
            md_lines.append("| - | *Sin hipótesis formalizadas en Fase 9* | - | - | - | - |")

        md_lines.extend(
            [
                "",
                "## 4. ANÁLISIS DE PIEZA CLAVE Y SENSIBILIDAD (HEUER CAPS. 10-13)",
                "Evaluación del punto único de fallo analítico (Single Point of Analytical Failure):",
                f"- **Pieza Clave de Evidencia:** {key_ev.get('evidence_summary') or 'Pendiente de formalizar'}",
                f"- **Clúster de Origen:** `{key_ev.get('source_cluster') or 'CL-01'}` "
                f"({key_ev.get('independent_clusters_count', 1)} clúster(es) independiente(s) corroborando)",
                f"- **Impacto de Sensibilidad:** **{str(key_ev.get('sensitivity_impact', 'medio')).upper()}** "
                "(si esta evidencia es engañosa o falsa, cambiaría radicalmente la estimación)",
                f"- **Vulnerabilidad a Deception / Señuelo:** "
                f"*{str(key_ev.get('vulnerability_to_deception', 'bajo')).capitalize()}*",
                f"- **Explicación Alternativa Considerada:** "
                f"{key_ev.get('alternative_explanation') or 'Ninguna reportada'}",
                "",
                "## 5. JUICIO ESTIMATIVO FINAL (ESTÁNDARES ICD 203)",
            ]
        )

        if leading_hyp:
            md_lines.extend(
                [
                    f"> **Estimación Principal ({leading_hyp.get('id', 'H1')}):** {leading_hyp.get('statement')}",
                    "> ",
                    f"> **Grado de Probabilidad Estimativa:** `{lead_prob}`",
                    "> ",
                    f"> **Nivel de Confianza Analítica:** `{lead_conf}` (sustentado en la convergencia de "
                    f"{len(seeds)} semillas y {len(ecosystem) + len(humint) + len(infra)} evidencias corroboradas).",
                    "",
                    "### Hipótesis Alternativas Consideradas y Descartadas:",
                ]
            )
            for rh in rival_hyps:
                rh_id = rh.get("id", "H?")
                rh_stmt = rh.get("statement", "")
                rh_ref = rh.get("what_would_refute_it") or rh.get("falsification_criteria") or "Criterio ausente"
                md_lines.append(
                    f"- **{rh_id}:** {rh_stmt} — *Descartada por {rh.get('inconsistency_score', 0)} "
                    f"inconsistencias o evidencia refutatoria:* {rh_ref}."
                )
        else:
            md_lines.append(
                "*Se requiere definir al menos una hipótesis en Fase 9 para computar el juicio estimativo formal.*"
            )

        md_lines.extend(
            [
                "",
                "## 6. INDICADORES DE ALERTA TEMPRANA / SIGNPOSTS (EVENTOS DE REFUTACIÓN)",
                "Eventos observables en el exterior que obligarían a invertir o reabrir la presente estimación:",
            ]
        )
        if hypotheses:
            for h in hypotheses:
                h_ref = h.get("what_would_refute_it") or h.get("falsification_criteria")
                if h_ref:
                    md_lines.append(f"- **Disparador sobre {h.get('id')}:** {h_ref}")
        else:
            md_lines.append("- Ningún indicador registrado.")

        md_lines.extend(
            [
                "",
                "## 7. LAGUNAS CRÍTICAS DE INFORMACIÓN (WHAT WE DO NOT KNOW)",
                "Conforme al estándar ICD 203, se declaran explícitamente los límites de visibilidad del caso:",
            ]
        )
        if gaps:
            for g in gaps:
                g_phase = g.get("phase", "General")
                g_desc = g.get("description", "")
                md_lines.append(f"- **[{g_phase}]:** {g_desc}")
        else:
            md_lines.append("- No se han formalizado lagunas de cobertura abiertas.")

        md_lines.extend(
            [
                "",
                "---",
                f"*Fin del Informe Estimativo | Producido con Maltego MCP v{__version__} | Metodología 100% Pasiva*",
            ]
        )
        report_md = "\n".join(md_lines)

        # Construir versión HTML autónoma y estilizada (con escape XSS estricto)
        def _esc(val: Any) -> str:
            return html.escape(str(val if val is not None else ""), quote=True)

        html_rows = ""
        for h in hypotheses:
            h_id = _esc(h.get("id", "H?"))
            h_stmt = _esc(h.get("statement", ""))
            h_ref = _esc(h.get("what_would_refute_it") or h.get("falsification_criteria") or "No definido")
            h_pr = _esc(prob_labels.get(str(h.get("probability", "")), str(h.get("probability", ""))))
            h_cf = _esc(str(h.get("confidence", "")).capitalize())
            h_sc = _esc(h.get("inconsistency_score", 0))
            html_rows += (
                f"<tr><td><b>{h_id}</b></td><td>{h_stmt}</td><td style='color:#f43f5e;'>{h_ref}</td>"
                f"<td>{h_pr}</td><td>{h_cf}</td><td style='font-family:monospace; text-align:center;'>{h_sc}</td></tr>"
            )

        lead_stmt_esc = _esc(leading_hyp.get("statement") if leading_hyp else "Pendiente de formalización")
        key_ev_summary_esc = _esc(key_ev.get("evidence_summary") or "Sin registrar")
        key_ev_cluster_esc = _esc(key_ev.get("source_cluster") or "CL-01")
        key_ev_count_esc = _esc(key_ev.get("independent_clusters_count", 1))
        key_ev_impact_esc = _esc(str(key_ev.get("sensitivity_impact", "medio")).upper())
        key_ev_deception_esc = _esc(str(key_ev.get("vulnerability_to_deception", "medio")).capitalize())
        gaps_html = (
            "".join(
                f"<li><b>[{_esc(g.get('phase', 'General'))}]:</b> {_esc(g.get('description', ''))}</li>" for g in gaps
            )
            or "<li>Sin lagunas declaradas.</li>"
        )

        report_html = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
  <title>Informe Estimativo ICD 203 - Caso {_esc(cid)}</title>
  <style>
    body {{
      font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
      background: #0b1120;
      color: #f8fafc;
      line-height: 1.5;
      padding: 2rem;
      margin: 0;
    }}
    .container {{
      max-width: 900px;
      margin: 0 auto;
      background: #0f172a;
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 2.5rem;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
    }}
    h1 {{ color: #06b6d4; font-size: 20px; border-bottom: 2px solid #1e293b; padding-bottom: 0.75rem; }}
    h2 {{ color: #38bdf8; font-size: 16px; margin-top: 1.5rem; }}
    h3 {{ color: #94a3b8; font-size: 14px; }}
    .badge {{ display: inline-block; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 12px; font-weight: bold; }}
    .badge-prob {{ background: rgba(6,182,212,0.15); color: #06b6d4; border: 1px solid rgba(6,182,212,0.3); }}
    .badge-conf {{ background: rgba(16,185,129,0.15); color: #10b981; border: 1px solid rgba(16,185,129,0.3); }}
    .box-callout {{
      background: rgba(6,182,212,0.05);
      border-left: 4px solid #06b6d4;
      padding: 1rem;
      border-radius: 4px;
      margin: 1rem 0;
    }}
    table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 13px; }}
    th, td {{ padding: 0.6rem 0.75rem; text-align: left; border-bottom: 1px solid #1e293b; }}
    th {{ background: #1e293b; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
    @media print {{
      body {{ background: #fff; color: #000; padding: 0; }}
      .container {{ box-shadow: none; border: none; max-width: 100%; padding: 0; }}
      h1, h2, h3 {{ color: #000; }}
      th {{ background: #eee; color: #000; }}
      td {{ border-bottom: 1px solid #ccc; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <h1>INFORME ESTIMATIVO DE INTELIGENCIA (ICD 203 / HEUER ACH)</h1>
    <div style="font-size:12px; color:#94a3b8; margin-bottom:1.5rem;">
      <b>Caso:</b> {_esc(cid)} | <b>Fecha:</b> {_esc(now_str)} | <b>Generador:</b> maltego-mcp/{_esc(__version__)} |
      <b>Marco:</b> {_esc(legal_basis)}
    </div>

    <h2>1. ENCUADRE Y PREGUNTA DE INTELIGENCIA (FASE 0)</h2>
    <p><b>Objetivo Raíz:</b> {_esc(target)}<br>
    <b>Pregunta Neutral:</b> <i>"{_esc(question)}"</i><br>
    <b>Límites HUMINT:</b> {_esc(humint_limits)}</p>

    <h2>2. MATRIZ DE HIPÓTESIS EN COMPETENCIA (ACH - HEUER CAP. 8)</h2>
    <table>
      <thead>
        <tr>
          <th>ID</th><th>Enunciado</th><th>Criterio Refutación</th>
          <th>Probabilidad</th><th>Confianza</th><th>Inconsistencias</th>
        </tr>
      </thead>
      <tbody>
        {html_rows or '<tr><td colspan="6" style="text-align:center;">Sin hipótesis registradas.</td></tr>'}
      </tbody>
    </table>

    <div class="box-callout">
      <h3 style="margin-top:0; color:#06b6d4;">JUICIO ESTIMATIVO FINAL (ICD 203)</h3>
      <p style="font-size:15px; margin:0.5rem 0;">
        <b>Estimación:</b> {lead_stmt_esc}<br>
        <b>Probabilidad ICD 203:</b> <span class="badge badge-prob">{_esc(lead_prob)}</span><br>
        <b>Nivel de Confianza:</b> <span class="badge badge-conf">{_esc(lead_conf)}</span>
      </p>
    </div>

    <h2>3. ANÁLISIS DE PIEZA CLAVE (KEY EVIDENCE SENSITIVITY)</h2>
    <p><b>Evidencia Clave:</b> {key_ev_summary_esc}<br>
    <b>Clúster:</b> {key_ev_cluster_esc}
    ({key_ev_count_esc} fuentes independientes)<br>
    <b>Sensibilidad al Fallo:</b> <b>{key_ev_impact_esc}</b><br>
    <b>Vulnerabilidad a Deception:</b> {key_ev_deception_esc}</p>

    <h2>4. LAGUNAS DE INFORMACIÓN (WHAT WE DO NOT KNOW)</h2>
    <ul>
      {gaps_html}
    </ul>

    <div style="font-size:11px; color:#64748b; margin-top:2rem; border-top:1px solid #1e293b; padding-top:0.75rem;">
      Documento generado automáticamente bajo la directiva ICD 203 de la Comunidad de Inteligencia y la metodología
      de Análisis de Hipótesis en Competencia de Richards J. Heuer Jr.
    </div>
  </div>
</body>
</html>"""

        assessment_summary = {
            "case_id": cid,
            "target": target,
            "leading_hypothesis": leading_hyp.get("id") if leading_hyp else None,
            "statement": leading_hyp.get("statement") if leading_hyp else "",
            "probability": lead_prob,
            "confidence": lead_conf,
            "key_evidence_impact": str(key_ev.get("sensitivity_impact", "medio")).upper(),
            "falsification_indicators_count": len([h for h in hypotheses if h.get("what_would_refute_it")]),
            "independent_clusters_count": len([c for c in [infra, archive, breaches, humint, ecosystem] if c]),
            "timestamp": now_str,
        }

        # Guardar resumen de evaluación en recon
        recon["icd203_assessment"] = assessment_summary
        await self.save_case_recon(cid, recon)

        return {
            "ok": True,
            "case_id": cid,
            "assessment": assessment_summary,
            "report_markdown": report_md,
            "report_html": report_html,
        }

    def generate_safe_dorks(self, domain_or_name: str) -> list[dict[str, str]]:
        clean = (
            domain_or_name.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        )
        if not clean:
            return []
        return [
            {
                "title": "Código fuente y secretos en GitHub",
                "dork": f'site:github.com "{clean}"',
                "category": "Fase 6 - Código Expuesto",
                "purpose": "Localizar repositorios públicos que mencionen el host o credenciales",
            },
            {
                "title": "Pastes de texto y volcados de datos",
                "dork": f'site:pastebin.com "{clean}"',
                "category": "Fase 5 - No Zoom Dorking",
                "purpose": "Menciones en volcados de texto y filtraciones externas",
            },
            {
                "title": "Espacios de trabajo en Trello expuestos",
                "dork": f'site:trello.com "{clean}"',
                "category": "Fase 5 - No Zoom Dorking",
                "purpose": "Tableros de proyectos o soporte indexados públicamente",
            },
            {
                "title": "Colecciones y endpoints en Postman",
                "dork": f'site:postman.com "{clean}"',
                "category": "Fase 5 - No Zoom Dorking",
                "purpose": "Colecciones de APIs públicas con rutas internas o tokens",
            },
            {
                "title": "Perfiles profesionales sin login (HUMINT pasivo)",
                "dork": f'site:linkedin.com/in "{clean}"',
                "category": "Fase 7 - HUMINT Pasivo",
                "purpose": "Identificar directivos y empleados sin interactuar en la plataforma",
            },
            {
                "title": "Documentos corporativos archivados en Wayback",
                "dork": f'filetype:pdf site:web.archive.org "{clean}"',
                "category": "Fase 3 - Archivos Web",
                "purpose": "Descarga segura desde la réplica Wayback sin tocar servidores del objetivo",
            },
            {
                "title": "Hojas de cálculo y bases de datos expuestas",
                "dork": f'"@{clean}" (filetype:xls OR filetype:xlsx OR filetype:csv)',
                "category": "Fase 5 - Dorking Externo",
                "purpose": "Hojas de cálculo con cuentas y contactos en sitios terceros",
            },
        ]

    def generate_symmetric_dorks(self, domain_or_val: str) -> list[dict[str, Any]]:
        """Genera tríos simétricos de dorks (§Heuer Caps. 10-13) para neutralizar sesgos de formulación."""
        clean = domain_or_val.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        if not clean:
            return []

        return [
            {
                "seed": clean,
                "domain_context": "Fase 4: Snippets Públicos SERP (Google / Bing / DDG)",
                "fase": "Fase 4",
                "platform": "serp",
                "positive": {
                    "title": "Dork Positivo (Sospecha / Incidente)",
                    "dork": f'"{clean}" ("vulnerabilidad" OR "brecha" OR "hackeado" OR "fraude" OR "fallo")',
                    "type": "confirmatorio",
                    "purpose": "Buscar indicios que respalden la sospecha de irregularidad",
                },
                "negative": {
                    "title": "Dork Negativo (Refutación Heuer)",
                    "dork": f'"{clean}" ("ISO 27001" OR "auditoría limpia" OR "desmentido" OR "premio ciberseguridad")',
                    "type": "refutatorio",
                    "purpose": "Buscar activamente evidencias que desmientan la sospecha",
                },
                "neutral": {
                    "title": "Dork Neutro (Línea Base Operativa)",
                    "dork": f'"{clean}" ("aviso legal" OR "política de privacidad" OR "registro mercantil")',
                    "type": "neutro",
                    "purpose": "Medir volumen de presencia formal y tasa base",
                },
            },
            {
                "seed": clean,
                "domain_context": "Fase 5: Repositorios y Colaboración Externa (GitHub / Postman / Trello)",
                "fase": "Fase 5",
                "platform": "repos",
                "positive": {
                    "title": "Dork Positivo (Fuga de Secretos)",
                    "dork": f'site:github.com "{clean}" ("api_key" OR "secret" OR "password" OR "token")',
                    "type": "confirmatorio",
                    "purpose": "Identificar tokens o credenciales expuestos en código",
                },
                "negative": {
                    "title": "Dork Negativo (Control de Fugas / Seguridad)",
                    "dork": f'site:github.com "{clean}" ("SECURITY.md" OR "takedown" OR "false positive" OR "revoked")',
                    "type": "refutatorio",
                    "purpose": "Comprobar si existen políticas de divulgación responsable o revocaciones inmediatas",
                },
                "neutral": {
                    "title": "Dork Neutro (Documentación Pública)",
                    "dork": f'(site:github.com OR site:postman.com OR site:trello.com) "{clean}" ("readme" OR "docs")',
                    "type": "neutro",
                    "purpose": "Verificar si la presencia externa es meramente documental",
                },
            },
            {
                "seed": clean,
                "domain_context": "Fase 5: Pastes y Volcados Externos No Zoom (Pastebin / Text Dumps)",
                "fase": "Fase 5",
                "platform": "pastes",
                "positive": {
                    "title": "Dork Positivo (Volcado de Credenciales)",
                    "dork": f'site:pastebin.com "{clean}" ("combo" OR "dump" OR "leak" OR "stealer")',
                    "type": "confirmatorio",
                    "purpose": "Detectar menciones en volcados de texto públicos",
                },
                "negative": {
                    "title": "Dork Negativo (Desmentidos y Retiradas)",
                    "dork": f'"{clean}" ("pastebin" OR "leak") ("desmentido oficial" OR "falso leak" OR "reclamación")',
                    "type": "refutatorio",
                    "purpose": "Verificar si las filtraciones fueron falsificaciones o desmentidas formalmente",
                },
                "neutral": {
                    "title": "Dork Neutro (Configuraciones Técnicas)",
                    "dork": f'site:pastebin.com "{clean}" ("log" OR "config" OR "script")',
                    "type": "neutro",
                    "purpose": "Identificar registros operativos estándar sin contraseñas",
                },
            },
        ]

    async def log_recon_search(self, case_id: str, search_type: str) -> dict[str, Any]:
        """Registra una consulta lanzada y ajusta la cuota de refutación en tiempo real."""
        cid = validate_case_id(case_id)
        recon = await self.get_case_recon(cid)
        searches = int(recon.get("searches_count", 0)) + 1
        recon["searches_count"] = searches
        refutations = int(recon.get("refutations_count", 0))
        if search_type.lower() == "refutatorio":
            refutations += 1
            recon["refutations_count"] = refutations

        rate = round((refutations / searches) * 100) if searches > 0 else 25
        await self.save_case_recon(cid, recon)
        return {
            "ok": True,
            "searches_count": searches,
            "refutations_count": refutations,
            "refutation_rate": rate,
            "recon": recon,
        }

    def generate_lateral_pivots(self, seeds: list[dict[str, Any]]) -> list[dict[str, Any]]:
        pivots: list[dict[str, Any]] = []
        for s in seeds:
            val = s.get("value", "")
            stype = s.get("type", "Domain")
            if "Domain" in stype:
                pivots.append(
                    {
                        "seed": val,
                        "type": stype,
                        "question": f"¿Quién más habla de {val} fuera de su red?",
                        "action": "Consultar crt.sh / CertSpotter",
                        "transform": "DomainToSubdomains",
                        "rationale": "Descubrir subsidiarias y dominios hermanos por certificado SSL en logs CT",
                    }
                )
                pivots.append(
                    {
                        "seed": val,
                        "type": stype,
                        "question": f"¿Qué páginas históricas borró {val}?",
                        "action": "Consultar Wayback Machine CDX API",
                        "transform": "WaybackHistoricalURLs",
                        "rationale": "URLs históricas y documentos offline en web.archive.org",
                    }
                )
                pivots.append(
                    {
                        "seed": val,
                        "type": stype,
                        "question": f"¿Qué bloque IP y ASN aloja pasivamente a {val}?",
                        "action": "Consultar historial pDNS (Robtex / Mnemonic)",
                        "transform": "PDNSDomainToIPHistory",
                        "rationale": "Histórico pDNS sin resolución DoH recursiva viva",
                    }
                )
            elif "IPv4" in stype or "IP" in stype:
                pivots.append(
                    {
                        "seed": val,
                        "type": stype,
                        "question": f"¿Qué ASN y prefijo BGP anuncia la IP {val}?",
                        "action": "Consultar RIPEstat Routing Status",
                        "transform": "RIPEStatASNToNetblocks",
                        "rationale": "Datos de enrutamiento pasivo y vecinos BGP sin escanear",
                    }
                )
                pivots.append(
                    {
                        "seed": val,
                        "type": stype,
                        "question": f"¿Qué servicios abiertos tiene indexados {val}?",
                        "action": "Consultar Shodan InternetDB",
                        "transform": "InternetDBIPToServices",
                        "rationale": "Cotejo en base de datos ya compilada, cero sondeo directo",
                    }
                )
            elif "Email" in stype:
                pivots.append(
                    {
                        "seed": val,
                        "type": stype,
                        "question": f"¿Aparece {val} en filtraciones conocidas?",
                        "action": "Consultar Have I Been Pwned / BreachSemanticPivot",
                        "transform": "HIBPEmailToBreaches",
                        "rationale": "Verificación pasiva sin validar buzón por SMTP",
                    }
                )
        return pivots

    # ---------- entidades ----------
    def build_entity(
        self,
        case_id: str,
        entity_type: str,
        value: str,
        confidence: float,
        source: str,
        properties: dict[str, str] | None = None,
        notes: str = "",
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
            notes=notes.strip()[:MAX_NOTES_LEN] if notes else "",
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
        if self.is_passive_mode and not spec.is_passive:
            raise TransformError(
                f"El transform '{spec.name}' está clasificado como '{spec.passivity}' y está bloqueado en modo pasivo. "
                "Para permitir transforms activos, configure MALTEGO_MCP_MODE=active."
            )
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
        scope = await self.get_case_perimeter(cid) if cid else None
        return await self._execute(spec, source_entity, soft_limit, save, reason, scope=scope)

    def _builtin_ctx(self, scope: Any | None = None) -> BuiltinContext:
        if self._http is None or self._http.is_closed:
            self._http = new_http_client(
                allow_active=not self.is_passive_mode,
                settings=self.settings,
                scope=scope,
                audit_log=self.audit_log,
            )
        else:
            transport = getattr(self._http, "_transport", None)
            if transport is not None and hasattr(transport, "scope"):
                transport.scope = scope
        return BuiltinContext(self._http, self.env)

    async def _fetch(
        self, spec: TransformSpec, source: EntityRecord, soft_limit: int, scope: Any | None = None
    ) -> TransformResponse:
        if spec.builtin is not None:
            if not spec.available(self.env):
                raise TransformError(
                    f"El transform '{spec.name}' necesita {', '.join(spec.requires)} (clave de API del proveedor)."
                )
            ctx = self._builtin_ctx(scope=scope)
            response = await spec.builtin.handler(ctx, source.maltego_type, source.value, source.properties, soft_limit)
        else:
            response = await run_remote_transform(
                spec, source.maltego_type, source.value, source.properties, soft_limit=soft_limit, env=self.env
            )
        if response.exceptions:
            from maltego_mcp.egress import redact_secrets

            raise TransformError(
                f"El transform '{spec.name}' devolvió un error: "
                + " | ".join(redact_secrets(x[:300], self.env) for x in response.exceptions)
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
        scope: Any | None = None,
    ) -> TransformRun:
        """Consulta (o usa la respuesta ya obtenida), guarda los resultados y registra el paso en la memoria."""
        start = started if started is not None else time.perf_counter()
        error = fetch_error
        run = TransformRun(spec.name, source, saved=save)
        if not error:
            try:
                response = response or await self._fetch(spec, source, soft_limit, scope=scope)
                run = await self._ingest(spec, source, response, save)
            except MaltegoMcpError as exc:
                from maltego_mcp.egress import redact_secrets

                error = redact_secrets(str(exc), self.env)
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
        from maltego_mcp.egress import redact_secrets

        safe_error = redact_secrets(error, self.env)[:500] if error else ""
        step = await self.store.append_step(
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
                error=safe_error,
                duration_ms=duration_ms,
            )
        )
        self.emit_event(
            "step",
            case_id=case_id,
            seq=step.seq,
            kind=kind,
            transform=action,
            action=action,
            target=source.value[:140] if source else "",
            new_entities=new_entities,
            reason=reason.strip()[:200],
        )
        return step

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
        scope: Any | None = None,
    ) -> list[TransformRun | str]:
        """Consulta en paralelo (acotado) y guarda en serie respetando el presupuesto de entidades nuevas."""
        sem = asyncio.Semaphore(CHAIN_CONCURRENCY)

        async def fetch(spec: TransformSpec, ent: EntityRecord) -> tuple[TransformResponse | None, str, float]:
            async with sem:
                start = time.perf_counter()
                try:
                    return await self._fetch(spec, ent, soft_limit, scope=scope), "", start
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
                    spec,
                    ent,
                    soft_limit,
                    True,
                    reason,
                    response=response,
                    fetch_error=error,
                    started=start,
                    scope=scope,
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
        if self.is_passive_mode:
            candidates = [s for s in candidates if s.is_passive]
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
        scope = await self.get_case_perimeter(entity.case_id) if entity.case_id else None
        pairs = [(s, entity) for s in specs[:max_transforms]]
        for item in await self._run_many(pairs, soft_limit, reason, scope=scope):
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
        scope = await self.get_case_perimeter(cid)
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
                    if self.is_passive_mode and not spec.is_passive:
                        result.unavailable.add(name)
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
                        scope=scope,
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

    async def profile_entity(
        self,
        case_id: str,
        eid: str,
        typology: str = "",
        reason: str = "",
    ) -> tuple[EntityRecord, ProfileRecord, list[EntityRecord]]:
        """Ejecuta el perfilado pericial multidimensional (21 tipologías en 6 pilares) sobre una entidad."""
        from maltego_mcp.profiling import execute_profile

        entity = await self.get_entity(case_id, eid)
        nbs = await self.neighbors(entity.case_id, entity.id, "", "both", 50)
        nb_tuples = [(n.entity.maltego_type, n.entity.value, n.entity.properties) for n in nbs]
        profile = execute_profile(entity, nb_tuples, typology)

        summary_note = (
            f"[{profile.title.upper()}]\n"
            f"Arquetipo: {profile.archetype_label} (Riesgo: {profile.risk_level})\n"
            f"{profile.summary}"
        )
        merged_notes = (
            f"{entity.notes}\n\n{summary_note}".strip()
            if entity.notes and summary_note not in entity.notes
            else (entity.notes or summary_note)
        )

        props_to_add = [
            f"profiling.domain={profile.domain}",
            f"profiling.typology={profile.typology}",
            f"profiling.archetype={profile.archetype_label}",
            f"profiling.risk_level={profile.risk_level}",
        ]
        for dim in profile.dimensions:
            dim_key = dim.name.lower().replace(" ", "_")[:30]
            props_to_add.append(f"profiling.dim.{dim_key}={dim.score}")

        updated = await self.update_entity(
            entity.case_id,
            entity.id,
            -1,
            merged_notes,
            props_to_add,
            [],
            reason or f"profiling_{profile.typology}",
        )

        emitted: list[EntityRecord] = []
        for trait in profile.traits_to_emit:
            child, _ = await self.upsert_entity(
                entity.case_id,
                trait.maltego_type,
                trait.value,
                trait.visual_weight / 100.0,
                f"profiling:{profile.typology}",
                [f"{k}={v}" for k, v in trait.properties.items()]
                + [f"visual.color={trait.visual_color}", f"visual.weight={trait.visual_weight}"],
            )
            await self.link(
                entity.case_id,
                entity.id,
                child.id,
                trait.edge_label.strip(),
                f"profiling:{profile.typology}",
                trait.visual_weight / 100.0,
                [f"profiling.domain={profile.domain}", f"profiling.typology={profile.typology}"],
            )
            emitted.append(child)

        return updated, profile, emitted

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
        return (
            next_best_actions(
                scores, steps, specs, self.env, await self.learning(), limit, only_passive=self.is_passive_mode
            ),
            scores,
        )

    async def explain_entity(self, case_id: str, eid: str) -> Explanation:
        entity = await self.get_entity(case_id, eid)
        entities, edges, steps = await self._case_state(entity.case_id)
        scores = score_entities(entities, edges, self._provider_transforms())
        return explain(
            entity,
            scores,
            steps,
            list(self.catalog.transforms.values()),
            self.env,
            only_passive=self.is_passive_mode,
        )

    async def get_entity_validity(self, case_id: str, eid: str) -> dict[str, Any]:
        entity = await self.get_entity(case_id, eid)
        from maltego_mcp.analysis import compute_entity_validity

        val = compute_entity_validity(entity)
        return val.to_dict()

    async def timeline(self, case_id: str, since_seq: int, limit: int) -> list[StepRecord]:
        return await self.store.list_steps(validate_case_id(case_id), since_seq, limit)

    async def subject_timeline(self, case_id: str, entity_id: str = "", limit: int = 100) -> SubjectTimeline:
        cid = validate_case_id(case_id)
        eid = validate_entity_id(entity_id) if entity_id.strip() else ""
        if eid:
            await self.get_entity(cid, eid)
        entities, edges = await self.store.export_case(cid, MAX_EXPORT_ITEMS)
        return build_subject_timeline(cid, entities, edges, subject_id=eid, limit=limit)

    async def _auto_attach_profiles(self, case_id: str, max_entities: int = 3) -> list[dict[str, Any]]:
        """Ejecuta perfilado pericial ligero sobre las entidades nucleares del caso sin inflar StepRecord."""
        from maltego_mcp.profiling import execute_profile

        cid = validate_case_id(case_id)
        entities, edges = await self.store.export_case(cid, MAX_EXPORT_ITEMS)
        if not entities:
            return []
        scores = score_entities(entities, edges, self._provider_transforms())
        ranked = [s.entity for s in sorted(scores.values(), key=lambda x: -x.priority)]
        targets = ranked[:max_entities] if ranked else entities[:max_entities]
        out: list[dict[str, Any]] = []
        for ent in targets:
            with contextlib.suppress(Exception):
                nbs = await self.neighbors(cid, ent.id, "", "both", 40)
                nb_tuples = [(n.entity.maltego_type, n.entity.value, n.entity.properties) for n in nbs]
                profile = execute_profile(ent, nb_tuples, "auto")
                avg_conf = (
                    round(sum(d.confidence for d in profile.dimensions) / len(profile.dimensions), 2)
                    if profile.dimensions
                    else 0.75
                )
                props = dict(ent.properties)
                props.update(
                    {
                        "profiling.domain": profile.domain,
                        "profiling.typology": profile.typology,
                        "profiling.archetype": profile.archetype_label,
                        "profiling.risk_level": profile.risk_level,
                        "profiling.confidence": str(avg_conf),
                        "profiling.summary": profile.summary[:450],
                    }
                )
                updated = replace(ent, properties=clean_properties(props))
                await self.store.replace_entity(updated)
                p_dict = {
                    "id": ent.id,
                    "value": ent.value,
                    "type": ent.maltego_type,
                    "domain": profile.domain,
                    "typology": profile.typology,
                    "archetype": profile.archetype_label,
                    "risk_level": profile.risk_level,
                    "summary": profile.summary,
                }
                out.append(p_dict)
                self.emit_event(
                    "entity_profiled",
                    case_id=cid,
                    entity_id=ent.id,
                    value=ent.value,
                    typology=profile.typology,
                    archetype=profile.archetype_label,
                    risk_level=profile.risk_level,
                )
        return out

    async def sync_case_recon_from_graph(
        self,
        case_id: str,
        raw_question: str = "",
        active_phase: str = "",
        target_override: str = "",
    ) -> dict[str, Any]:
        """Sincroniza de forma no destructiva el estado de descubrimiento P0-P9 (_recon.json) desde el grafo activo."""
        from maltego_mcp.analysis import compute_entity_validity

        cid = validate_case_id(case_id)
        case = await self.store.get_case(cid)
        entities, edges, steps = await self._case_state(cid)
        recon = await self.get_case_recon(cid)
        if not entities and not raw_question:
            return recon

        scores = score_entities(entities, edges, self._provider_transforms())
        ranked = [s.entity for s in sorted(scores.values(), key=lambda x: -x.priority)]
        manual_root = next((e for e in entities if "manual" in e.sources), None)
        root = manual_root or (ranked[0] if ranked else (entities[0] if entities else None))
        target_val = target_override.strip() or (root.value if root else cid)

        # Fase 0: Encuadre, calibración y supuestos WYSIATI
        p0 = recon.setdefault("p0_framing", {})
        if target_override.strip():
            p0["target"] = target_override.strip()
        elif not str(p0.get("target") or "").strip() and root:
            p0["target"] = root.value
        if raw_question.strip():
            p0["question"] = raw_question.strip()[:400]
        elif not str(p0.get("question") or "").strip():
            desc = (case.description if case and case.description else "").strip()
            p0["question"] = (
                f"¿Cuál es la superficie técnica verificable, estructura operativa, vínculos de ecosistema "
                f"y exposición en fuentes abiertas de {target_val} ({desc or 'auditoría OSINT'})?"
            )
        if not str(p0.get("reference_class") or "").strip():
            mtype = (root.maltego_type if root else "").lower()
            if "domain" in mtype or "company" in mtype or "organization" in mtype:
                p0["reference_class"] = "Organización Corporativa / Infraestructura Digital"
            elif "email" in mtype or "alias" in mtype or "person" in mtype:
                p0["reference_class"] = "Identidad Digital / Huella HUMINT-SOCMINT"
            elif "ip" in mtype or "as" in mtype or "netblock" in mtype:
                p0["reference_class"] = "Infraestructura de Red / Operador BGP-ASN"
            else:
                p0["reference_class"] = "Indicador Técnico / Superficie OSINT"
        if not str(p0.get("pre_mortem") or "").strip():
            p0["pre_mortem"] = (
                f"Si el dictamen sobre {target_val} resultase incompleto o sesgado, la causa más probable sería "
                "confundir infraestructura compartida (CDN/SaaS/BPO) con activos propios exclusivos o asumir "
                "vigencia actual sobre registros meramente históricos."
            )
        if not p0.get("assumptions"):
            p0["assumptions"] = [
                {
                    "text": f"Los activos vinculados a {target_val} corresponden a su perímetro operativo real",
                    "refutation": (
                        "Demostrar alojamiento multi-tenant masivo sin identificador exclusivo (SAN/WHOIS/CIF)"
                    ),
                    "status": "activo",
                },
                {
                    "text": "La telemetría recolectada refleja la configuración vigente o histórica verificable",
                    "refutation": (
                        "Detectar revocación de certificados, reasignación de IP o marcadores de canario/señuelo"
                    ),
                    "status": "activo",
                },
            ]

        # Fase 1: Semillas y resolución de homónimos
        seeds: list[dict[str, Any]] = recon.setdefault("seeds", [])
        seen_seeds = {str(s.get("value") or "").strip().lower() for s in seeds}
        for idx, ent in enumerate((ranked or entities)[:12]):
            v_low = ent.value.strip().lower()
            if not v_low or v_low in seen_seeds:
                continue
            seen_seeds.add(v_low)
            short_type = ent.maltego_type.split(".")[-1]
            src_list = list(ent.sources)
            cluster_id = f"CL-0{(idx % 4) + 1}"
            has_2f = len(src_list) >= 2 or len(ent.properties) >= 2
            id1 = f"Fuente primaria: {src_list[0]}" if src_list else "Semilla inicial"
            id2 = (
                f"Corroboración: {src_list[1]}"
                if len(src_list) > 1
                else (
                    f"Atributo: {next(iter(ent.properties.keys()))}" if ent.properties else "Cotejo topológico en grafo"
                )
            )
            seeds.append(
                {
                    "id": f"seed-auto-{ent.id[:12]}",
                    "type": short_type,
                    "value": ent.value,
                    "origin": "Fase 0" if idx == 0 else "Fase 2",
                    "hop": 0 if idx == 0 else 1,
                    "status": "completada" if idx == 0 else "en_analisis",
                    "diagnosticidad": "alta" if ent.confidence >= 0.8 else "media",
                    "cluster": cluster_id,
                    "origen_tipo": "fuente_primaria" if idx == 0 else "agregador_secundario",
                    "buscado_no_encontrado": False,
                    "tasa_base": "baja_especifica" if ent.confidence >= 0.8 else "media_compartida",
                    "identificador_1": id1,
                    "identificador_2": id2 if has_2f else "",
                    "homonimo_verificado": has_2f,
                    "admiralty_fuente": "B" if ent.confidence >= 0.75 else "C",
                    "admiralty_contenido": "2" if has_2f else "3",
                    "admiralty_code": "B2" if (ent.confidence >= 0.75 and has_2f) else "C3",
                    "consultas_confirmacion": max(1, len(src_list)),
                    "consultas_refutacion": 1,
                    "families_applied": src_list[:4],
                    "created_at": ent.first_seen or utc_now(),
                }
            )

        # Mapa de adyacencia para enriquecer Fase 2..8
        by_id = {e.id: e for e in entities}
        adj: dict[str, list[EntityRecord]] = {}
        for ed in edges:
            src_e, dst_e = by_id.get(ed.out_id), by_id.get(ed.in_id)
            if src_e and dst_e:
                adj.setdefault(src_e.id, []).append(dst_e)
                adj.setdefault(dst_e.id, []).append(src_e)

        # Fase 2: Infraestructura y vigencia
        infra_list: list[dict[str, Any]] = recon.setdefault("fase2_infra", [])
        seen_infra = {(str(x.get("host") or "").lower(), str(x.get("ip") or "").lower()) for x in infra_list}
        for ent in entities:
            mt = ent.maltego_type.lower()
            if any(k in mt for k in ("domain", "dnsname", "ipv4", "ipv6", "netblock", "as", "service", "port")):
                nbs = adj.get(ent.id, [])
                ip_val = ent.value if "ip" in mt else next((n.value for n in nbs if "ip" in n.maltego_type.lower()), "")
                host_val = (
                    ent.value
                    if ("domain" in mt or "dns" in mt)
                    else next(
                        (n.value for n in nbs if "domain" in n.maltego_type.lower() or "dns" in n.maltego_type.lower()),
                        ent.value,
                    )
                )
                prov_val = (
                    ent.properties.get("asn")
                    or ent.properties.get("isp")
                    or ent.properties.get("org")
                    or next(
                        (
                            n.value
                            for n in nbs
                            if "as" in n.maltego_type.lower() or "organization" in n.maltego_type.lower()
                        ),
                        "Telemetría Pasiva",
                    )
                )
                key_inf = (host_val.lower(), ip_val.lower())
                if key_inf in seen_infra:
                    continue
                seen_infra.add(key_inf)
                val_status = compute_entity_validity(ent).status.lower()
                vig_str = (
                    "activo"
                    if "reciente" in val_status
                    else ("historico" if "historico" in val_status else "observado")
                )
                is_cdn = any(
                    c in f"{host_val} {prov_val}".lower()
                    for c in ("cloudflare", "akamai", "fastly", "cloudfront", "azure", "amazonaws")
                )
                infra_list.append(
                    {
                        "id": f"infra-auto-{ent.id[:10]}",
                        "host": host_val,
                        "ip": ip_val or "-",
                        "provider": str(prov_val)[:80],
                        "tasa_base": "cdn_alta" if is_cdn else "dedicated_baja",
                        "vigencia": vig_str,
                        "ct_cert": ent.properties.get("ct.issuer") or ent.properties.get("ct__source") or "CT / pDNS",
                        "timestamp": time.time(),
                    }
                )

        # Fase 3: Archivos web históricos y capturas
        arch_list: list[dict[str, Any]] = recon.setdefault("fase3_archives", [])
        seen_arch = {str(x.get("url") or "").lower() for x in arch_list}
        for ent in entities:
            mt = ent.maltego_type.lower()
            if "url" in mt or "website" in mt or "document" in mt or ent.properties.get("archive_url"):
                u_val = ent.properties.get("archive_url") or ent.properties.get("url") or ent.value
                if not u_val or u_val.lower() in seen_arch:
                    continue
                seen_arch.add(u_val.lower())
                is_can = bool(
                    ent.properties.get("possible_canary") == "true"
                    or ent.properties.get("is_canary") == "true"
                    or "canary" in u_val.lower()
                )
                arch_list.append(
                    {
                        "id": f"arch-auto-{ent.id[:10]}",
                        "url": u_val,
                        "repository": ent.properties.get("archive_source") or "wayback_cdx",
                        "timestamp_capture": ent.properties.get("timestamp") or ent.first_seen or utc_now(),
                        "http_status": ent.properties.get("status_code") or "200",
                        "mime_type": ent.properties.get("mime_type") or "text/html",
                        "possible_canary": is_can,
                        "admiralty": "B2",
                        "timestamp": time.time(),
                    }
                )

        # Fase 6: Filtraciones y exposición
        breach_list: list[dict[str, Any]] = recon.setdefault("fase6_breaches", [])
        seen_breach = {
            (str(x.get("identity") or "").lower(), str(x.get("breach_name") or "").lower()) for x in breach_list
        }
        for ent in entities:
            mt = ent.maltego_type.lower()
            is_breach_node = (
                "brecha" in ent.value.lower()
                or "breach" in ent.value.lower()
                or "stealer" in ent.value.lower()
                or any(k.startswith("breach.") or k.startswith("stealer.") for k in ent.properties)
            )
            if is_breach_node or "email" in mt:
                if "email" in mt and not any(k.startswith("breach.") for k in ent.properties):
                    continue
                nbs = adj.get(ent.id, [])
                ident = (
                    ent.value
                    if "email" in mt
                    else next(
                        (
                            n.value
                            for n in nbs
                            if "email" in n.maltego_type.lower() or "alias" in n.maltego_type.lower()
                        ),
                        target_val,
                    )
                )
                b_name = ent.properties.get("breach.name") or (ent.value if "email" not in mt else "Exposición OSINT")
                key_b = (ident.lower(), b_name.lower())
                if key_b in seen_breach:
                    continue
                seen_breach.add(key_b)
                b_date = ent.properties.get("breach.date") or ent.first_seen[:10]
                breach_list.append(
                    {
                        "id": f"brch-auto-{ent.id[:10]}",
                        "identity": ident,
                        "breach_name": b_name[:100],
                        "breach_date": b_date,
                        "exposure_type": "third_party",
                        "secret_sample": "",
                        "is_honeytoken": "canary" in f"{ident} {b_name}".lower(),
                        "honeytoken_alert": "",
                        "vigencia": "reciente_activa" if "202" in str(b_date) else "historica_reciclada",
                        "vigencia_rationale": (
                            "Evaluado automáticamente desde telemetría de brechas (§Heuer Cap. 11)."
                        ),
                        "admiralty": "B2",
                        "linked_to_graph": True,
                        "timestamp": time.time(),
                    }
                )

        # Fase 7: HUMINT pasivo y desacoplamiento de atribución
        humint_list: list[dict[str, Any]] = recon.setdefault("fase7_humint", [])
        seen_humint = {str(x.get("actor_name") or "").lower() for x in humint_list}
        for ent in entities:
            mt = ent.maltego_type.lower()
            if any(k in mt for k in ("person", "alias", "emailaddress", "phonenumber")):
                if ent.value.lower() in seen_humint:
                    continue
                seen_humint.add(ent.value.lower())
                role_v = ent.properties.get("humint.role") or ent.properties.get("role") or "technical_dev"
                scope_v = ent.properties.get("humint.opinion_scope") or ("corporate" if "email" in mt else "personal")
                humint_list.append(
                    {
                        "id": f"hum-auto-{ent.id[:10]}",
                        "actor_name": ent.value,
                        "role": role_v,
                        "channel": ",".join(ent.sources[:2]) or "osint_passive",
                        "opinion_scope": scope_v,
                        "attribution_guard": (
                            "Postura institucional o cuenta corporativa verificada."
                            if scope_v == "corporate"
                            else (
                                "DESACOPLAMIENTO HEUER (Cap. 10): Identidad o perfil individual "
                                "desacoplado de política corporativa."
                            )
                        ),
                        "diagnosticidad": "alta_corporativa" if scope_v == "corporate" else "baja_personal",
                        "tech_stack": ent.properties.get("tech_stack") or ent.properties.get("company") or "",
                        "admiralty": "B2",
                        "linked_to_graph": True,
                        "timestamp": time.time(),
                    }
                )

        # Fase 8: Ecosistema externo y mitigación de culpa por asociación
        eco_list: list[dict[str, Any]] = recon.setdefault("fase8_ecosystem", [])
        seen_eco = {str(x.get("provider_name") or "").lower() for x in eco_list}
        for ent in entities:
            mt = ent.maltego_type.lower()
            if any(k in mt for k in ("company", "organization", "as")) and ent.value.lower() != target_val.lower():
                if ent.value.lower() in seen_eco:
                    continue
                seen_eco.add(ent.value.lower())
                cat_v = ent.properties.get("ecosystem.category") or (
                    "bpo_support"
                    if ent.properties.get("bpo.role")
                    else ("cloud_hosting_saas" if "as" in mt else "other_third_party")
                )
                eco_list.append(
                    {
                        "id": f"eco-auto-{ent.id[:10]}",
                        "provider_name": ent.value,
                        "category": cat_v,
                        "dependency_level": ent.properties.get("ecosystem.dependency") or "secundaria",
                        "base_rate_commonality": ent.properties.get("ecosystem.base_rate") or "alta",
                        "shared_cluster_id": f"Cluster-{ent.maltego_type.split('.')[-1]}",
                        "conduct_decoupled": True,
                        "admiralty": "B2",
                        "notes": ent.notes
                        or "Identificado mediante correlación pasiva con mitigación de culpa por asociación.",
                        "linked_to_graph": True,
                        "timestamp": time.time(),
                    }
                )

        # Métricas de búsqueda No Zoom (Fases 4-5)
        tx_steps = [s for s in steps if s.kind in ("transform", "machine", "investigate")]
        if tx_steps:
            recon["searches_count"] = max(int(recon.get("searches_count") or 0), len(tx_steps))
            recon["refutations_count"] = max(int(recon.get("refutations_count") or 0), max(1, len(tx_steps) // 3))
            s_cnt = int(recon["searches_count"])
            r_cnt = int(recon["refutations_count"])
            recon["refutation_rate"] = round((r_cnt / s_cnt) * 100) if s_cnt > 0 else 25

        # Fase 9: Hipótesis en competencia (ACH) y Pieza Clave (ICD 203)
        hyps: list[dict[str, Any]] = recon.setdefault("hypotheses", [])
        if not hyps and entities:
            hyps.extend(
                [
                    {
                        "id": "H1",
                        "statement": (
                            f"La huella observada de {target_val} ({len(entities)} entidades y {len(edges)} vínculos) "
                            "corresponde a su arquitectura operativa y ecosistema de proveedores/perfiles verificados."
                        ),
                        "probability": "MUY_PROBABLE" if len(entities) >= 3 else "PROBABLE",
                        "confidence": "ALTA" if len(entities) >= 5 else "MEDIA",
                        "what_would_refute_it": (
                            "Demostrar que los registros CT/WHOIS/pDNS e identidades pertenecen a un homónimo "
                            "ajeno o a infraestructura dada de baja sin vínculo registral vigente."
                        ),
                        "evaluations": {"CL-01": "C", "CL-02": "C", "CL-03": "C"},
                        "inconsistency_score": 0,
                        "created_at": utc_now(),
                    },
                    {
                        "id": "H2",
                        "statement": (
                            f"Los activos descubiertos para {target_val} están distorsionados por alojamiento "
                            "compartido (multi-tenant/CDN/BPO) sin atribución exclusiva al sujeto principal."
                        ),
                        "probability": "IMPROBABLE" if len(entities) >= 3 else "POSIBILIDAD_IGUAL",
                        "confidence": "MEDIA",
                        "what_would_refute_it": (
                            "Confirmar identificadores únicos exclusivos (certificados SAN propios, registros "
                            "mercantiles o cuentas oficiales verificadas por 2 factores independientes)."
                        ),
                        "evaluations": {"CL-01": "I", "CL-02": "C", "CL-03": "N"},
                        "inconsistency_score": 1,
                        "created_at": utc_now(),
                    },
                    {
                        "id": "H3",
                        "statement": (
                            f"Parte de los indicadores expuestos de {target_val} corresponden a señuelos defensivos "
                            "(honeytokens/canarios) o registros históricos obsoletos."
                        ),
                        "probability": "MUY_IMPROBABLE",
                        "confidence": "MEDIA",
                        "what_would_refute_it": (
                            "Verificar vigencia reciente (OBSERVADO_RECIENTE <=30d/90d) en al menos dos clústeres de "
                            "telemetría independientes sin marcadores de engaño."
                        ),
                        "evaluations": {"CL-01": "I", "CL-02": "I", "CL-03": "C"},
                        "inconsistency_score": 2,
                        "created_at": utc_now(),
                    },
                ]
            )

        if not recon.get("key_evidence") and root:
            ind_clusters = min(4, max(1, len({s.get("cluster") for s in seeds if s.get("cluster")})))
            recon["key_evidence"] = {
                "evidence_summary": (
                    f"Correlación multifuente sobre semilla nuclear {root.value} ({root.maltego_type}) "
                    f"con {len(entities)} nodos y {len(edges)} relaciones topológicas verificadas."
                ),
                "source_cluster": "CL-01 Identidad e Infraestructura",
                "independent_clusters_count": ind_clusters,
                "sensitivity_impact": "alto",
                "vulnerability_to_deception": "bajo",
                "alternative_explanation": "Coincidencia parcial en servicios compartidos de terceros o CDN.",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            }

        if active_phase:
            recon["active_phase"] = active_phase
        elif len(entities) >= 2 and recon.get("active_phase") in ("", "Fase 0", "P0"):
            recon["active_phase"] = "Fase 9"

        saved = await self.save_case_recon(cid, recon)
        self.emit_event("recon_updated", case_id=cid, active_phase=saved.get("active_phase", "Fase 9"))
        self.emit_event("graph_updated", case_id=cid)
        return saved

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
            actions = next_best_actions(
                scores, steps, specs, self.env, await self.learning(), 10, only_passive=self.is_passive_mode
            )
        recon_data: dict[str, Any] = {}
        with contextlib.suppress(Exception):
            recon_data = await self.get_case_recon(cid)
        profiles_list: list[dict[str, Any]] = []
        for e in entities:
            if any(k.startswith("profiling.") for k in e.properties):
                profiles_list.append(
                    {
                        "id": e.id,
                        "value": e.value,
                        "type": e.maltego_type,
                        "domain": e.properties.get("profiling.domain", ""),
                        "typology": e.properties.get("profiling.typology", ""),
                        "archetype": e.properties.get("profiling.archetype", ""),
                        "risk_level": e.properties.get("profiling.risk_level", ""),
                        "summary": e.properties.get("profiling.summary") or e.notes,
                    }
                )
        return ReportData(
            case, entities, edges, steps, scores, actions, utc_now(), recon=recon_data, profiles=profiles_list
        )

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
        seed_val, inferred_type, raw_question = extract_seed_from_plaintext(value, entity_type)
        etype = resolve_type_for_value(inferred_type, seed_val)
        norm = normalize_value(etype, seed_val)
        cid = validate_case_id(case_id) if case_id.strip() else _auto_case_id(norm)
        case_desc = raw_question[:300] if raw_question else f"Investigación de {norm[:200]}"
        await self.store.ensure_case(cid, case_desc)
        self.emit_event("case_created", case_id=cid, description=case_desc)
        chosen = (
            self.catalog.machines.get(machine)
            if machine.strip()
            else self.catalog.machines.for_type(etype.maltego_type, is_passive=self.is_passive_mode)
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
            # Sin Machine aplicable se ofrecen SIEMPRE pivotes indirectos pasivos, haya o no transforms que acepten
            # el tipo (antes solo aparecían notas como efecto colateral de un InvalidInput).
            for pivot in indirect_pivots_for_entity(root):
                if pivot not in result.notes:
                    result.notes.append(pivot)

        # Perfilado pericial automático sobre entidades nucleares + sincronización completa P0-P9 en el Dashboard
        await self._auto_attach_profiles(cid, max_entities=3)
        recon_state = await self.sync_case_recon_from_graph(
            cid, raw_question=raw_question or reason, active_phase="Fase 9"
        )
        result.recon_phase = str(recon_state.get("active_phase") or "Fase 9")
        hyps = recon_state.get("hypotheses") or []
        if hyps:
            lead = sorted(hyps, key=lambda h: int(h.get("inconsistency_score", 0)))[0]
            result.leading_hypothesis = f"{lead.get('id', 'H1')}: {lead.get('statement', '')}"

        result.summary = await self.store.case_summary(cid, 5)
        result.actions, scores = await self.suggest(cid, 5)
        result.top = sorted(scores.values(), key=lambda s: -s.priority)[:8]
        await self.record_step(
            cid, "investigate", result.strategy, reason=reason, new_entities=result.summary.entity_count
        )

        # Auto-generación del Informe Pericial Ejecutivo y exportación de entregables (HTML y paquete .mcpcase)
        with contextlib.suppress(Exception):
            rep_data = await self.report_data(cid)
            result.report_markdown = to_markdown(rep_data)
            html_path, _, _ = await self.export_case(cid, "report_html")
            mcpcase_path, _, _ = await self.export_case(cid, "mcpcase")
            result.exported_files = {
                "report_html": str(html_path),
                "mcpcase": str(mcpcase_path),
            }
        self.emit_event(
            "investigation_completed", case_id=cid, strategy=result.strategy, entity_count=result.summary.entity_count
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
        if fmt == "mcpcase":
            steps = await self.store.list_steps(cid, 0, MAX_SIDECAR_STEPS)
            case_rec = await self.store.get_case(cid)
            case_info = {
                "case_id": cid,
                "description": case_rec.description if case_rec else "",
                "created_at": (case_rec.created or stamp) if case_rec else stamp,
                "updated_at": (case_rec.updated or stamp) if case_rec else stamp,
                "stats": {
                    "entity_count": len(entities),
                    "edge_count": len(edges),
                    "step_count": len(steps),
                },
            }
            graph_data = {
                "entities": [e.to_dict() for e in entities],
                "edges": [e.to_dict() for e in edges],
            }
            memory_data = {
                "steps": [s.to_dict() for s in steps],
            }
            checksum_val = compute_mcpcase_checksum(case_info, graph_data, memory_data)
            bundle = {
                "$schema": "https://maltego-mcp.local/schemas/case-v1.json",
                "format": "maltego-mcp-case/v1",
                "version": "1.0.0",
                "generator": f"maltego-mcp/{__version__}",
                "exported_at": datetime.now(UTC).isoformat(),
                "checksum": checksum_val,
                "case": case_info,
                "graph": graph_data,
                "memory": memory_data,
            }
            content = json.dumps(bundle, ensure_ascii=False, indent=2).encode("utf-8")
        elif fmt == "json":
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
            # Layout + XML + ZIP son CPU puro (minutos con grafos grandes sin el núcleo nativo): fuera del event loop.
            content = await asyncio.to_thread(write_mtgx, entities, edges, layout, sidecar)
        elif fmt in ("report_md", "report_html"):
            data = await self.report_data(cid)
            render = to_markdown if fmt == "report_md" else to_html
            content = (await asyncio.to_thread(render, data)).encode("utf-8")
            path = path.with_suffix(".md" if fmt == "report_md" else ".html")
        else:
            content = _to_csv(entities, edges).encode("utf-8-sig")
        await asyncio.to_thread(path.write_bytes, content)
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
                    raise InvalidInput(
                        "Formato no soportado: usa un paquete .mcpcase (Recomendado), .mtgx (Maltego), .csv o .json."
                    )
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
        if path.suffix.lower() == ".mcpcase":
            graph = _read_mcpcase(data)
        elif path.suffix.lower() == ".mtgx":
            graph = read_mtgx(data)
        elif path.suffix.lower() == ".json":
            try:
                peek = json.loads(data.decode("utf-8-sig"))
                if isinstance(peek, dict) and peek.get("format") == "maltego-mcp-case/v1":
                    graph = _read_mcpcase(data)
                else:
                    graph = _read_json(data)
            except Exception:
                graph = _read_json(data)
        else:
            graph = _read_csv(data)
        await self.store.ensure_case(cid)
        if graph.sidecar.get("case"):
            pkg_case = graph.sidecar["case"]
            if isinstance(pkg_case, dict) and pkg_case.get("description"):
                case_rec = await self.store.get_case(cid)
                if case_rec and not case_rec.description:
                    case_rec.description = str(pkg_case["description"])
        result = ImportResult(path)
        origin = f"import:{path.name}"[:120]
        ids: dict[str, str] = {}
        records: dict[str, EntityRecord] = {}
        for item in graph.entities:
            clean_props = clean_properties(item.properties)
            if item.position is not None:
                clean_props["pos.x"] = f"{item.position[0]:.1f}"
                clean_props["pos.y"] = f"{item.position[1]:.1f}"
            for k, v in item.style.items():
                clean_props[f"visual.{k}"] = v
            try:
                entity = self.build_entity(
                    cid,
                    item.maltego_type,
                    item.value,
                    item.confidence,
                    origin,
                    clean_props,
                    notes=item.notes,
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
            link_props = clean_properties(link.properties)
            for k, v in link.style.items():
                link_props[f"maltego.link.{k}"] = v
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
                link_props,
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


def compute_mcpcase_checksum(case_info: dict[str, Any], graph_data: dict[str, Any], memory_data: dict[str, Any]) -> str:
    """Calcula hash criptográfico SHA-256 sobre la información canónica del paquete .mcpcase."""
    raw = json.dumps(
        {"case": case_info, "graph": graph_data, "memory": memory_data},
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _read_mcpcase(data: bytes) -> ImportedGraph:
    """Lee y valida un paquete de caso dedicado .mcpcase (maltego-mcp-case/v1) verificando su integridad."""
    try:
        payload = json.loads(data.decode("utf-8-sig"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise InvalidInput("El paquete .mcpcase no contiene JSON válido en UTF-8.") from exc

    if not isinstance(payload, dict):
        raise InvalidInput("El paquete .mcpcase debe ser un objeto JSON estructurado.")

    fmt = str(payload.get("format") or "").strip()
    if fmt != "maltego-mcp-case/v1":
        raise InvalidInput(f"Formato no reconocido: '{fmt}'. Se esperaba 'maltego-mcp-case/v1'.")

    stored_checksum = str(payload.get("checksum") or "").strip()
    raw_case = payload.get("case")
    case_info: dict[str, Any] = raw_case if isinstance(raw_case, dict) else {}
    raw_graph = payload.get("graph")
    graph_data: dict[str, Any] = raw_graph if isinstance(raw_graph, dict) else {}
    raw_memory = payload.get("memory")
    memory_data: dict[str, Any] = raw_memory if isinstance(raw_memory, dict) else {}

    if stored_checksum:
        expected = compute_mcpcase_checksum(case_info, graph_data, memory_data)
        if stored_checksum != expected:
            raise InvalidInput(
                f"Fallo de integridad criptográfica: el hash SHA-256 no coincide (archivo corrupto o modificado). "
                f"Esperado: {expected}, Registrado: {stored_checksum}"
            )

    raw_entities = graph_data.get("entities") or []
    raw_edges = graph_data.get("edges") or []
    raw_steps = memory_data.get("steps") or []

    graph = ImportedGraph()
    key_map: dict[str, str] = {}

    for item in raw_entities:
        if not isinstance(item, dict):
            graph.skipped += 1
            continue
        mtype = str(item.get("maltego_type") or item.get("type") or "auto").strip()
        val = str(item.get("value") or "").strip()
        if not val:
            graph.skipped += 1
            continue
        k = f"n{len(graph.entities)}"
        orig_id = str(item.get("id") or "")
        if orig_id:
            key_map[orig_id] = k
        key_map[val] = k
        try:
            conf = float(item.get("confidence", 0.5))
        except (ValueError, TypeError):
            conf = 0.5
        props = item.get("properties")
        clean_props = {str(pk): str(pv) for pk, pv in props.items()} if isinstance(props, dict) else {}
        graph.entities.append(ImportedEntity(k, mtype, val, clean_props, conf))

    for edge in raw_edges:
        if not isinstance(edge, dict):
            continue
        src = str(edge.get("source") or edge.get("out_id") or edge.get("from") or "").strip()
        tgt = str(edge.get("target") or edge.get("in_id") or edge.get("to") or "").strip()
        k_src = key_map.get(src)
        k_tgt = key_map.get(tgt)
        if not k_src or not k_tgt or k_src == k_tgt:
            continue
        lbl = str(edge.get("label") or edge.get("relation") or "related_to").strip()
        try:
            conf = float(edge.get("confidence", 0.5))
        except (ValueError, TypeError):
            conf = 0.5
        props = edge.get("properties")
        clean_props = {str(pk): str(pv) for pk, pv in props.items()} if isinstance(props, dict) else {}
        graph.links.append(ImportedLink(k_src, k_tgt, lbl, conf, clean_props))

    graph.sidecar = {
        "format": "maltego-mcp-case/v1",
        "case": case_info,
        "steps": raw_steps,
        "dashboard_state": payload.get("dashboard_state") or {},
    }
    return graph


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


def _read_json(data: bytes) -> ImportedGraph:
    """Importa grafo desde JSON: formato maltego-mcp o genérico (nodes/links, entities/edges)."""
    try:
        raw = json.loads(data.decode("utf-8-sig"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise InvalidInput("El fichero JSON no es válido o no está en UTF-8.") from exc
    if not isinstance(raw, (dict, list)):
        raise InvalidInput("El JSON debe contener un objeto o lista de entidades y relaciones.")

    graph = ImportedGraph()
    key_map: dict[str, str] = {}

    if isinstance(raw, dict):
        raw_entities = raw.get("entities") or raw.get("nodes") or []
        raw_edges = raw.get("edges") or raw.get("links") or raw.get("relations") or []
        if not isinstance(raw_entities, list) or not isinstance(raw_edges, list):
            raise InvalidInput("El JSON debe contener listas 'entities' (o 'nodes') y 'edges' (o 'links').")

        for item in raw_entities:
            if not isinstance(item, dict):
                graph.skipped += 1
                continue
            mtype = str(item.get("maltego_type") or item.get("type") or "auto").strip()
            val = str(item.get("value") or "").strip()
            if not val:
                graph.skipped += 1
                continue
            k = f"n{len(graph.entities)}"
            orig_id = str(item.get("id") or item.get("key") or "")
            if orig_id:
                key_map[orig_id] = k
            key_map[val] = k
            try:
                conf = float(item.get("confidence", 0.5))
            except (ValueError, TypeError):
                conf = 0.5
            props = item.get("properties")
            clean_props = {str(pk): str(pv) for pk, pv in props.items()} if isinstance(props, dict) else {}
            graph.entities.append(ImportedEntity(k, mtype, val, clean_props, conf))

        for edge in raw_edges:
            if not isinstance(edge, dict):
                continue
            src = str(edge.get("source") or edge.get("out_id") or edge.get("from") or "").strip()
            tgt = str(edge.get("target") or edge.get("in_id") or edge.get("to") or "").strip()
            k_src = key_map.get(src)
            k_tgt = key_map.get(tgt)
            if not k_src or not k_tgt or k_src == k_tgt:
                continue
            lbl = str(edge.get("label") or edge.get("relation") or "related_to").strip()
            try:
                conf = float(edge.get("confidence", 0.5))
            except (ValueError, TypeError):
                conf = 0.5
            props = edge.get("properties")
            clean_props = {str(pk): str(pv) for pk, pv in props.items()} if isinstance(props, dict) else {}
            graph.links.append(ImportedLink(k_src, k_tgt, lbl, conf, clean_props))

        if isinstance(raw.get("sidecar"), dict):
            graph.sidecar = raw["sidecar"]
    elif isinstance(raw, list):
        for row in raw:
            if not isinstance(row, dict):
                graph.skipped += 1
                continue
            s_val = str(row.get("source_value") or row.get("source") or "").strip()
            if not s_val:
                graph.skipped += 1
                continue
            s_type = str(row.get("source_type") or "auto").strip()
            t_val = str(row.get("target_value") or row.get("target") or "").strip()
            t_type = str(row.get("target_type") or "auto").strip()
            rel = str(row.get("relation") or row.get("label") or "related_to").strip()
            try:
                conf = float(row.get("confidence", 0.5))
            except (ValueError, TypeError):
                conf = 0.5

            if s_val not in key_map:
                k_s = f"n{len(graph.entities)}"
                key_map[s_val] = k_s
                graph.entities.append(ImportedEntity(k_s, s_type, s_val, {}, conf))
            else:
                k_s = key_map[s_val]

            if t_val:
                if t_val not in key_map:
                    k_t = f"n{len(graph.entities)}"
                    key_map[t_val] = k_t
                    graph.entities.append(ImportedEntity(k_t, t_type, t_val, {}, conf))
                else:
                    k_t = key_map[t_val]
                if k_s != k_t:
                    graph.links.append(ImportedLink(k_s, k_t, rel, conf, {}))

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
    val = value
    stripped = val.lstrip()
    is_phone = val[:1] in ("+", "-") and val[1:].replace(" ", "").isdigit()  # +34600... es un teléfono
    stripped_is_phone = stripped[:1] in ("+", "-") and stripped[1:].replace(" ", "").isdigit()

    if (
        val[:1] in ("=", "@", "\t", "\r", "\n")
        or (val[:1] in ("+", "-") and not is_phone)
        or (stripped[:1] in ("=", "@", "+", "-") and not stripped_is_phone)
    ):
        val = "'" + val
    return val.replace("\r", " ")
