"""Las 20 tools MCP. Finas: validan formato, llaman al servicio y formatean (markdown legible o JSON).

Agrupación (≤ 20 tools para que Gemini y otros clientes las manejen bien; las variantes van en `action`):
  Catálogo:      osint_list_entity_types, osint_list_transforms
  Casos:         osint_manage_case, osint_list_cases, osint_get_case_summary
  Entidades:     osint_upsert_entity, osint_manage_entity, osint_get_entity, osint_search_entities
  Relaciones:    osint_link_entities, osint_get_neighbors, osint_find_paths
  Transforms:    osint_run_transform, osint_expand_entity, osint_run_machine
  Copiloto:      osint_investigate, osint_suggest_next_steps, osint_get_timeline
  Intercambio:   osint_export_case, osint_import_graph
"""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from typing import Annotated, Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from maltego_mcp.analysis import Action, EntityScore
from maltego_mcp.domain.entity_types import all_entity_types
from maltego_mcp.errors import InvalidInput, MaltegoMcpError
from maltego_mcp.format import (
    UNTRUSTED_NOTE,
    cell,
    code,
    code_cell,
    entities_table,
    entity_line,
    pagination_line,
    safe,
    to_json,
)
from maltego_mcp.report import to_markdown
from maltego_mcp.service import MachineResult, OsintService

ResponseFormat = Literal["markdown", "json"]
READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)
WRITE_IDEMPOTENT = ToolAnnotations(
    read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False
)
DESTRUCTIVE = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=False)
OPEN_WORLD = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True)

CaseId = Annotated[str, Field(description="Id del caso: 2-63 caracteres a-z, 0-9, '-' o '_' (ej.: caso-2026-001).")]
EntityId = Annotated[str, Field(description="Id de entidad devuelto por otra tool (ej.: domain-3f2a...).")]
EntityType = Annotated[
    str,
    Field(
        description='Tipo Maltego (ver osint_list_entity_types), p. ej. maltego.Domain, propio (acme.Ticket) o "auto" '
        "para detectarlo por el valor (correo, URL, IP, rango, hash, AS, teléfono, dominio o frase)."
    ),
]
Fmt = Annotated[ResponseFormat, Field(description='"markdown" (por defecto, legible) o "json" (estructurado).')]
Limit = Annotated[int, Field(ge=1, le=100, description="Máximo de resultados (1-100).")]
Offset = Annotated[int, Field(ge=0, le=100_000, description="Desplazamiento para paginar.")]
Confidence = Annotated[float, Field(ge=0, le=1, description="Confianza 0-1 en el dato.")]
Props = Annotated[
    list[str], Field(default_factory=list, max_length=50, description='Propiedades adicionales "clave=valor".')
]
Reason = Annotated[str, Field(max_length=500, description="Por qué se hace (queda en la memoria del caso).")]
SoftLimit = Annotated[int, Field(ge=1, le=256, description="Máximo de resultados por transform.")]


def tool_errors[**P, R](fn: Callable[P, Awaitable[R]]) -> Callable[P, Awaitable[R]]:
    """Convierte errores esperados en ToolError (isError=true con mensaje accionable)."""

    @functools.wraps(fn)
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return await fn(*args, **kwargs)
        except MaltegoMcpError as exc:
            raise ToolError(str(exc)) from exc

    return wrapper


def _page(page, items: list[dict[str, object]], offset: int) -> str:  # type: ignore[no-untyped-def]
    return to_json(
        {
            "total": page.total,
            "count": len(page.items),
            "offset": offset,
            "has_more": page.has_more,
            "next_offset": page.next_offset,
            "items": items,
        }
    )


def _actions_md(actions: list[Action]) -> str:
    if not actions:
        return "Sin acciones pendientes: todos los transforms disponibles ya se ejecutaron sobre las entidades clave."
    rows = ["| # | transform | sobre | tipo | id | puntuación | motivo |", "|---|---|---|---|---|---|---|"]
    rows += [
        f"| {i} | {a.transform} | {code_cell(a.entity.value)} | {a.entity.maltego_type} | `{a.entity.id}` | "
        f"{a.score} | {cell(a.reason, 160)} |"
        for i, a in enumerate(actions, 1)
    ]
    return "\n".join(rows)


def _scores_md(top: list[EntityScore]) -> str:
    rows = ["| prioridad | tipo | valor | conexiones | id |", "|---|---|---|---|---|"]
    rows += [
        f"| {s.priority:.2f} | {s.entity.maltego_type} | {code_cell(s.entity.value)} | {s.degree} | `{s.entity.id}` |"
        for s in top
    ]
    return "\n".join(rows)


def _machine_md(r: MachineResult) -> str:
    rows = [
        f"**{r.machine}** sobre {code(r.root.value)} (`{r.root.id}`) en el caso `{r.root.case_id}`: "
        f"{r.new_entities} entidades nuevas en {r.rounds} ronda(s)",
        "| ronda | etapa | transform | entradas | omitidas | resultados | nuevas | errores |",
        "|---|---|---|---|---|---|---|---|",
    ]
    rows += [
        f"| {s.round} | {s.stage} | {s.transform} | {s.inputs} | {s.skipped_inputs} | {s.outputs} | "
        f"{s.new_entities} | {len(s.errors)} |"
        for s in r.steps
    ]
    errors = [e for s in r.steps for e in s.errors][:8]
    if errors:
        rows.append("\nErrores: " + "; ".join(safe(e, 200) for e in errors))
    if r.unavailable:
        rows.append("\nOmitidos por falta de API key: " + ", ".join(sorted(r.unavailable)))
    if r.missing:
        rows.append("\nNo existen en el catálogo: " + ", ".join(sorted(r.missing)))
    if r.stopped_by_budget:
        rows.append("\nParada al agotar max_total_entities.")
    return "\n".join(rows)


def _machine_json(r: MachineResult) -> dict[str, object]:
    return {
        "machine": r.machine,
        "root": r.root.to_dict(),
        "rounds": r.rounds,
        "new_entities": r.new_entities,
        "stopped_by_budget": r.stopped_by_budget,
        "unavailable": sorted(r.unavailable),
        "missing": sorted(r.missing),
        "steps": [
            {
                "round": s.round,
                "stage": s.stage,
                "transform": s.transform,
                "inputs": s.inputs,
                "skipped_inputs": s.skipped_inputs,
                "outputs": s.outputs,
                "new_entities": s.new_entities,
                "errors": s.errors,
            }
            for s in r.steps
        ],
    }


def register_tools(mcp: MCPServer, svc: OsintService) -> None:
    # =============================================================================== catálogo
    @mcp.tool(
        name="osint_list_entity_types",
        title="Ontología de entidades Maltego",
        description=(
            "Lista los tipos de entidad soportados (estándar de Maltego e importados de tu Maltego) por categoría, "
            "con su propiedad principal. El valor de maltego_type es el entity_type que usan las demás tools."
        ),
        annotations=READ_ONLY,
        structured_output=False,
    )
    @tool_errors
    async def osint_list_entity_types(
        category: Annotated[str, Field(description="Filtra por categoría (infraestructura, identidad...).")] = "",
        response_format: Fmt = "markdown",
    ) -> str:
        types = [t for t in all_entity_types() if not category.strip() or t.category == category.strip().lower()]
        if response_format == "json":
            return to_json({"count": len(types), "items": [t.to_dict() for t in types]})
        rows = ["| categoría | tipo (entity_type) | propiedad principal | ejemplo | origen |", "|---|---|---|---|---|"]
        rows += [
            f"| {t.category} | {t.maltego_type} | {t.main_property} | {cell(t.example, 60)} | {t.origin} |"
            for t in types
        ]
        rows.append(
            '\nTambién se aceptan tipos propios prefijo.Nombre y "auto". Para conceptos no nativos usa '
            'maltego.Phrase con prefijo de categoría, p. ej. "[T1566] Phishing" o "[TheHive] Caso 42".'
        )
        return "\n".join(rows)

    @mcp.tool(
        name="osint_list_transforms",
        title="Transforms, Machines y proveedores",
        description=(
            "Inventario: transforms (integrados sin API key, de proveedores con API key y de tus servidores "
            "TRX/iTDS) filtrables por tipo de entrada o categoría, Machines disponibles y estado de cada proveedor "
            "y servidor (check_servers=true comprueba la conexión)."
        ),
        annotations=READ_ONLY,
        structured_output=False,
    )
    @tool_errors
    async def osint_list_transforms(
        entity_type: Annotated[str, Field(description="Filtra por tipo de entrada; vacío = todos.")] = "",
        category: Annotated[str, Field(description="Filtra por categoría: dns, whois, proveedor:shodan...")] = "",
        include_machines: Annotated[bool, Field(description="Incluir la lista de Machines.")] = True,
        check_servers: Annotated[bool, Field(description="Comprobar conexión con servidores TRX/iTDS.")] = False,
        response_format: Fmt = "markdown",
    ) -> str:
        inv = await svc.inventory(entity_type, category, check_servers)
        if response_format == "json":
            return to_json(
                {
                    "transforms": [
                        {
                            "name": s.name,
                            "category": s.category,
                            "origin": s.origin,
                            "input_types": list(s.input_types),
                            "output_types": list(s.output_types),
                            "available": s.available(svc.env),
                            "requires": list(s.requires),
                            "description": s.description,
                        }
                        for s in inv.transforms
                    ],
                    "machines": [
                        {
                            "name": m.name,
                            "input_types": list(m.input_types),
                            "description": m.description,
                            "stages": [list(x) for x in m.stages],
                            "origin": m.origin,
                        }
                        for m in (inv.machines if include_machines else [])
                    ],
                    "providers": inv.providers,
                    "servers": inv.servers,
                }
            )
        rows = ["| transform | categoría | acepta | produce | disponible |", "|---|---|---|---|---|"]
        rows += [
            f"| {s.name} | {s.category} | {', '.join(t.split('.')[-1] for t in s.input_types) or 'cualquiera'} | "
            f"{', '.join(t.split('.')[-1] for t in s.output_types) or '?'} | "
            f"{'sí' if s.available(svc.env) else 'falta ' + ', '.join(s.requires)} |"
            for s in inv.transforms
        ]
        if not inv.transforms:
            rows = ["No hay transforms para ese filtro."]
        if include_machines and inv.machines:
            rows += ["\n**Machines**", "| machine | acepta | descripción |", "|---|---|---|"]
            rows += [
                f"| {m.name} | {', '.join(t.split('.')[-1] for t in m.input_types) or 'cualquiera'} | "
                f"{cell(m.description, 200)} |"
                for m in inv.machines
            ]
        rows.append(
            "\n**Proveedores:** "
            + ", ".join(f"{p} ({'configurado' if ok else 'sin clave'})" for p, ok in sorted(inv.providers.items()))
        )
        if inv.servers:
            rows.append("**Servidores TRX/iTDS:** " + ", ".join(f"{n}: {st}" for n, st in sorted(inv.servers.items())))
        return "\n".join(rows)

    # =============================================================================== casos
    @mcp.tool(
        name="osint_manage_case",
        title="Gestionar caso",
        description=(
            "Crea o actualiza un caso (action=create), fusiona otro caso dentro de este (action=merge, "
            "source_case) o lo borra con todo su contenido (action=delete, confirm=<case_id>; irreversible)."
        ),
        annotations=DESTRUCTIVE,
        structured_output=False,
    )
    @tool_errors
    async def osint_manage_case(
        case_id: CaseId,
        action: Annotated[
            Literal["create", "merge", "delete"], Field(description="create, merge o delete.")
        ] = "create",
        description: Annotated[str, Field(max_length=500, description="Objetivo del caso (create).")] = "",
        source_case: Annotated[str, Field(description="Caso a fusionar en case_id (merge).")] = "",
        confirm: Annotated[str, Field(description="Repite el case_id para confirmar delete.")] = "",
    ) -> str:
        if action == "delete":
            ents, edges = await svc.delete_case(case_id, confirm)
            return f"Caso `{case_id.strip().lower()}` borrado ({ents} entidades, {edges} relaciones)."
        if action == "merge":
            if not source_case.strip():
                raise InvalidInput("Indica source_case para fusionar.")
            created, linked = await svc.merge_cases(case_id, source_case)
            return (
                f"Fusionado `{source_case.strip().lower()}` en `{case_id.strip().lower()}`: {created} entidades "
                f"nuevas, {linked} relaciones. El caso origen se conserva."
            )
        case, created = await svc.create_case(case_id, description)
        state = "creado" if created else "ya existía"
        return f"Caso `{case.case_id}` {state}. Descripción: {safe(case.description) or '—'}"

    @mcp.tool(
        name="osint_list_cases",
        title="Listar casos",
        description="Lista los casos de investigación, del más reciente al más antiguo, con paginación.",
        annotations=READ_ONLY,
        structured_output=False,
    )
    @tool_errors
    async def osint_list_cases(limit: Limit = 20, offset: Offset = 0, response_format: Fmt = "markdown") -> str:
        page = await svc.list_cases(limit, offset)
        if response_format == "json":
            return _page(page, [c.to_dict() for c in page.items], offset)
        if not page.items:
            return "No hay casos. Crea uno con osint_manage_case o usa osint_investigate."
        rows = ["| case_id | descripción | actualizado |", "|---|---|---|"]
        rows += [f"| `{c.case_id}` | {cell(c.description, 120)} | {c.updated} |" for c in page.items]
        rows.append(pagination_line(page.total, offset, len(page.items), page.next_offset))
        return "\n".join(rows)

    @mcp.tool(
        name="osint_get_case_summary",
        title="Resumen y calidad de un caso",
        description=(
            "Resume un caso: recuentos por tipo, entidades prioritarias (puntuación explicable de confianza, "
            "fiabilidad de fuentes, conexiones y novedad), entidades aisladas e índices de calidad."
        ),
        annotations=READ_ONLY,
        structured_output=False,
    )
    @tool_errors
    async def osint_get_case_summary(
        case_id: CaseId,
        top: Annotated[int, Field(ge=0, le=50, description="Cuántas entidades prioritarias mostrar.")] = 10,
        response_format: Fmt = "markdown",
    ) -> str:
        data = await svc.report_data(case_id, include_actions=False)
        ranked = data.top(top)
        if response_format == "json":
            return to_json(
                {
                    "case": data.case.to_dict(),
                    "quality": data.quality(),
                    "by_type": dict(data.by_type()),
                    "top": [s.to_dict() for s in ranked],
                }
            )
        q = data.quality()
        lines = [
            f"## Caso `{data.case.case_id}`",
            safe(data.case.description) or "Sin descripción",
            f"- Entidades: {q['entidades']} · Relaciones: {q['relaciones']} · Pasos: {q['pasos']}",
            f"- Calidad: confianza media {q['confianza_media']}, {q['corroboradas_pct']} % corroboradas, "
            f"{q['aisladas']} aisladas, {q['errores_pct']} % transforms con error",
            "- Por tipo: " + ", ".join(f"{t}: {n}" for t, n in data.by_type()),
        ]
        if ranked:
            lines += ["\n**Entidades prioritarias**", _scores_md(ranked), UNTRUSTED_NOTE]
        return "\n".join(lines)

    # =============================================================================== entidades
    @mcp.tool(
        name="osint_upsert_entity",
        title="Crear o fusionar entidad",
        description=(
            "Guarda una entidad en un caso (lo crea si no existe). Normaliza el valor y devuelve su entity_id "
            "determinista. Reinsertar fusiona fuentes y propiedades. Úsala también para volcar al grafo datos de "
            "otros MCP (MISP, ATT&CK, TheHive...) con source=<origen>."
        ),
        annotations=WRITE_IDEMPOTENT,
        structured_output=False,
    )
    @tool_errors
    async def osint_upsert_entity(
        case_id: CaseId,
        entity_type: EntityType,
        value: Annotated[str, Field(max_length=2048, description="Valor de la entidad (ej.: example.com).")],
        properties: Props,
        confidence: Confidence = 0.5,
        source: Annotated[
            str, Field(max_length=120, description="Origen del dato (manual, misp, attack...).")
        ] = "manual",
        notes: Annotated[str, Field(max_length=4000, description="Notas del analista.")] = "",
        response_format: Fmt = "markdown",
    ) -> str:
        ent, created = await svc.upsert_entity(case_id, entity_type, value, confidence, source, properties, notes)
        if response_format == "json":
            return to_json({"created": created, "entity": ent.to_dict()})
        return f"Entidad {'creada' if created else 'actualizada'}: {entity_line(ent)}"

    @mcp.tool(
        name="osint_manage_entity",
        title="Editar o borrar entidad",
        description=(
            "action=update cambia confianza (confidence>=0), notas, propiedades (properties clave=valor) o quita "
            "propiedades (remove_properties). action=delete borra la entidad y sus relaciones (irreversible)."
        ),
        annotations=DESTRUCTIVE,
        structured_output=False,
    )
    @tool_errors
    async def osint_manage_entity(
        case_id: CaseId,
        entity_id: EntityId,
        properties: Props,
        remove_properties: Annotated[
            list[str], Field(default_factory=list, max_length=50, description="Nombres de propiedades a quitar.")
        ],
        action: Annotated[Literal["update", "delete"], Field(description="update o delete.")] = "update",
        confidence: Annotated[float, Field(ge=-1, le=1, description="Nueva confianza 0-1; -1 = no cambiar.")] = -1,
        notes: Annotated[str, Field(max_length=4000, description="Notas (sustituyen a las actuales).")] = "",
        reason: Reason = "",
    ) -> str:
        if action == "delete":
            removed = await svc.delete_entity(case_id, entity_id, reason)
            return f"Entidad `{entity_id}` borrada junto con {removed} relaciones."
        ent = await svc.update_entity(case_id, entity_id, confidence, notes, properties, remove_properties, reason)
        return f"Entidad actualizada: {entity_line(ent)}; {len(ent.properties)} propiedades."

    @mcp.tool(
        name="osint_get_entity",
        title="Detalle y explicación de una entidad",
        description=(
            "Devuelve una entidad con propiedades, notas, fuentes, puntuación explicada, qué paso la descubrió "
            "(procedencia), qué transforms se ejecutaron sobre ella y cuáles quedan pendientes."
        ),
        annotations=READ_ONLY,
        structured_output=False,
    )
    @tool_errors
    async def osint_get_entity(case_id: CaseId, entity_id: EntityId, response_format: Fmt = "markdown") -> str:
        x = await svc.explain_entity(case_id, entity_id)
        e = x.entity
        if response_format == "json":
            return to_json(
                {
                    "entity": e.to_dict(),
                    "score": x.score.to_dict() if x.score else None,
                    "discovered_by": [s.to_dict() for s in x.discovered_by],
                    "used_as_input": [s.to_dict() for s in x.used_as_input],
                    "pending_transforms": x.pending_transforms,
                }
            )
        lines = [
            f"## {code(e.value)}",
            f"- Tipo: {e.maltego_type} · id `{e.id}` · confianza {e.confidence}",
            f"- Fuentes: {safe(', '.join(e.sources), 300)}",
            f"- Visto: {e.first_seen} → {e.last_seen}",
        ]
        if x.score:
            lines.append(f"- Prioridad: {x.score.rationale()}")
        if e.notes:
            lines.append(f"- Notas: {code(e.notes, 600)}")
        if e.properties:
            lines.append("- Propiedades:")
            lines += [f"  - {safe(k, 60)}: {code(v, 300)}" for k, v in list(e.properties.items())[:50]]
        if x.discovered_by:
            lines.append(
                "- Descubierta por: "
                + "; ".join(f"#{s.seq} {s.action} sobre {code(s.input_value, 80)}" for s in x.discovered_by[:10])
            )
        if x.used_as_input:
            lines.append(
                "- Transforms ya ejecutados sobre ella: " + ", ".join(sorted({s.action for s in x.used_as_input}))
            )
        if x.pending_transforms:
            lines.append("- Transforms pendientes: " + ", ".join(x.pending_transforms))
        lines.append(UNTRUSTED_NOTE)
        return "\n".join(lines)

    @mcp.tool(
        name="osint_search_entities",
        title="Buscar y ordenar entidades",
        description=(
            "Busca entidades por texto contenido en el valor y/o tipo, en un caso o en todos (case_id vacío: "
            "correlación entre casos). sort=priority ordena por puntuación (requiere case_id)."
        ),
        annotations=READ_ONLY,
        structured_output=False,
    )
    @tool_errors
    async def osint_search_entities(
        query: Annotated[str, Field(max_length=200, description="Texto a buscar; vacío = todas.")] = "",
        entity_type: Annotated[str, Field(description="Filtra por tipo Maltego; vacío = todos.")] = "",
        case_id: Annotated[str, Field(description="Caso donde buscar; vacío = todos los casos.")] = "",
        sort: Annotated[Literal["value", "priority"], Field(description="value o priority.")] = "value",
        limit: Limit = 20,
        offset: Offset = 0,
        response_format: Fmt = "markdown",
    ) -> str:
        page = await svc.search(case_id, query, entity_type, limit, offset, sort)
        if response_format == "json":
            return _page(page, [e.to_dict() for e in page.items], offset)
        if not page.items:
            return "Sin resultados. Prueba con un texto más corto, sin entity_type o con case_id vacío."
        table = entities_table(page.items)
        if not case_id.strip():
            table += "\n\nCasos: " + ", ".join(sorted({f"`{e.case_id}`" for e in page.items}))
        return "\n".join(
            [table, pagination_line(page.total, offset, len(page.items), page.next_offset), UNTRUSTED_NOTE]
        )

    # =============================================================================== relaciones
    @mcp.tool(
        name="osint_link_entities",
        title="Relacionar o desrelacionar entidades",
        description="action=link crea/refuerza la relación dirigida source -> target; action=unlink la elimina.",
        annotations=WRITE_IDEMPOTENT,
        structured_output=False,
    )
    @tool_errors
    async def osint_link_entities(
        case_id: CaseId,
        source_id: EntityId,
        target_id: EntityId,
        edge_label: Annotated[str, Field(max_length=63, description="Tipo de relación (ej.: resolves_to, owns).")],
        action: Annotated[Literal["link", "unlink"], Field(description="link o unlink.")] = "link",
        confidence: Confidence = 0.5,
        source: Annotated[str, Field(max_length=120, description="Origen de la relación.")] = "manual",
    ) -> str:
        if action == "unlink":
            ok = await svc.unlink(case_id, source_id, target_id, edge_label)
            return "Relación eliminada." if ok else "No existía esa relación (revisa edge_label y la dirección)."
        edge, created = await svc.link(case_id, source_id, target_id, edge_label, source, confidence)
        return (
            f"Relación {'creada' if created else 'actualizada'}: `{edge.out_id}` -[{edge.label}]-> `{edge.in_id}` "
            f"(confianza {edge.confidence})"
        )

    @mcp.tool(
        name="osint_get_neighbors",
        title="Vecinos de una entidad",
        description="Lista las entidades relacionadas con una entidad, con el tipo y la dirección de cada relación.",
        annotations=READ_ONLY,
        structured_output=False,
    )
    @tool_errors
    async def osint_get_neighbors(
        case_id: CaseId,
        entity_id: EntityId,
        edge_label: Annotated[str, Field(description="Filtra por tipo de relación; vacío = todas.")] = "",
        direction: Annotated[Literal["out", "in", "both"], Field(description="out, in o both.")] = "both",
        limit: Limit = 25,
        response_format: Fmt = "markdown",
    ) -> str:
        items = await svc.neighbors(case_id, entity_id, edge_label, direction, limit)
        if response_format == "json":
            return to_json(
                {
                    "count": len(items),
                    "items": [
                        {"direction": n.direction, "edge": n.edge.to_dict(), "entity": n.entity.to_dict()}
                        for n in items
                    ],
                }
            )
        if not items:
            return "La entidad no tiene relaciones" + (f" de tipo {safe(edge_label)}" if edge_label else "") + "."
        rows = ["| dirección | relación | entidad | tipo | id |", "|---|---|---|---|---|"]
        rows += [
            f"| {'→' if n.direction == 'out' else '←'} | {n.edge.label} | {code_cell(n.entity.value)} | "
            f"{n.entity.maltego_type} | `{n.entity.id}` |"
            for n in items
        ]
        rows.append(UNTRUSTED_NOTE)
        return "\n".join(rows)

    @mcp.tool(
        name="osint_find_paths",
        title="Caminos entre dos entidades",
        description="Encuentra caminos (sin ciclos, en cualquier dirección, el más corto primero) entre dos entidades.",
        annotations=READ_ONLY,
        structured_output=False,
    )
    @tool_errors
    async def osint_find_paths(
        case_id: CaseId,
        source_id: EntityId,
        target_id: EntityId,
        max_depth: Annotated[int, Field(ge=1, le=6, description="Máximo de saltos (1-6).")] = 3,
        limit: Annotated[int, Field(ge=1, le=20, description="Máximo de caminos (1-20).")] = 5,
        response_format: Fmt = "markdown",
    ) -> str:
        paths = await svc.find_paths(case_id, source_id, target_id, max_depth, limit)
        if response_format == "json":
            return to_json({"count": len(paths), "paths": paths})
        if not paths:
            return f"No hay caminos de hasta {max_depth} saltos. Prueba con max_depth mayor (máx. 6)."
        return "\n".join(f"{i}. " + " → ".join(f"`{p}`" for p in path) for i, path in enumerate(paths, 1))

    # =============================================================================== transforms
    @mcp.tool(
        name="osint_run_transform",
        title="Ejecutar un transform",
        description=(
            "Ejecuta un transform (integrado, de proveedor o de tus servidores TRX/iTDS) sobre una entidad. Con "
            "save=true guarda entidad, resultados, relaciones y el paso en la memoria del caso."
        ),
        annotations=OPEN_WORLD,
        structured_output=False,
    )
    @tool_errors
    async def osint_run_transform(
        transform: Annotated[str, Field(description="Nombre del transform (ver osint_list_transforms).")],
        entity_type: EntityType,
        value: Annotated[str, Field(max_length=2048, description="Valor de la entidad de entrada.")],
        properties: Props,
        case_id: Annotated[str, Field(description="Caso donde guardar (obligatorio si save=true).")] = "",
        save: Annotated[bool, Field(description="Guardar en el grafo del caso.")] = True,
        soft_limit: SoftLimit = 12,
        reason: Reason = "",
        response_format: Fmt = "markdown",
    ) -> str:
        run = await svc.run_transform(case_id, transform, entity_type, value, properties, soft_limit, save, reason)
        if response_format == "json":
            return to_json(
                {
                    "transform": run.transform,
                    "input": run.input.to_dict(),
                    "saved": run.saved,
                    "truncated": run.truncated,
                    "results": [
                        {"edge_label": r.edge_label, "created": r.created, "entity": r.entity.to_dict()}
                        for r in run.results
                    ],
                    "skipped": run.skipped,
                    "messages": [{"type": t, "text": m} for t, m in run.messages],
                }
            )
        lines = [
            f"**{run.transform}** sobre {code(run.input.value)} ({run.input.maltego_type}): "
            f"{len(run.results)} resultados" + (" (guardados)" if run.saved else " (no guardados)")
        ]
        if run.results:
            rows = ["| relación | tipo | valor | id | nueva |", "|---|---|---|---|---|"]
            rows += [
                f"| {r.edge_label} | {r.entity.maltego_type} | {code_cell(r.entity.value)} | `{r.entity.id}` | "
                f"{'sí' if r.created else 'no'} |"
                for r in run.results
            ]
            lines.append("\n".join(rows))
        if run.truncated:
            lines.append("Resultados truncados: sube soft_limit si necesitas más.")
        if run.skipped:
            lines.append("Descartados: " + "; ".join(safe(s, 160) for s in run.skipped[:10]))
        if run.messages:
            lines.append("Mensajes: " + "; ".join(f"[{t}] {code(m, 200)}" for t, m in run.messages[:10]))
        lines.append(UNTRUSTED_NOTE)
        return "\n\n".join(lines)

    @mcp.tool(
        name="osint_expand_entity",
        title="Expandir entidad (Run All)",
        description=(
            "Ejecuta sobre una entidad del caso todos los transforms disponibles que declaran su tipo (como "
            "'Run All' en Maltego) y guarda los resultados. Indica los que faltan por API key."
        ),
        annotations=OPEN_WORLD,
        structured_output=False,
    )
    @tool_errors
    async def osint_expand_entity(
        case_id: CaseId,
        entity_id: EntityId,
        max_transforms: Annotated[int, Field(ge=1, le=30, description="Máximo de transforms a ejecutar.")] = 15,
        soft_limit: SoftLimit = 12,
        reason: Reason = "",
        response_format: Fmt = "markdown",
    ) -> str:
        r = await svc.expand_entity(case_id, entity_id, max_transforms, soft_limit, reason)
        if response_format == "json":
            return to_json(
                {
                    "entity": r.entity.to_dict(),
                    "runs": [
                        {
                            "transform": run.transform,
                            "results": [
                                {"edge_label": x.edge_label, "created": x.created, "entity": x.entity.to_dict()}
                                for x in run.results
                            ],
                        }
                        for run in r.runs
                    ],
                    "errors": r.errors,
                    "not_run": r.not_run,
                    "unavailable": r.unavailable,
                }
            )
        rows = [
            f"Expansión de {code(r.entity.value)} ({r.entity.maltego_type}) con {len(r.runs)} transforms",
            "| transform | relación | tipo | valor | id | nueva |",
            "|---|---|---|---|---|---|",
        ]
        for run in r.runs:
            rows += [
                f"| {run.transform} | {x.edge_label} | {x.entity.maltego_type} | {code_cell(x.entity.value)} | "
                f"`{x.entity.id}` | {'sí' if x.created else 'no'} |"
                for x in run.results
            ]
        if r.errors:
            rows.append("\nErrores: " + "; ".join(safe(e, 200) for e in r.errors[:10]))
        if r.not_run:
            rows.append("\nNo ejecutados (sube max_transforms): " + ", ".join(r.not_run))
        if r.unavailable:
            rows.append("\nSin API key: " + ", ".join(r.unavailable))
        rows.append(UNTRUSTED_NOTE)
        return "\n".join(rows)

    @mcp.tool(
        name="osint_run_machine",
        title="Ejecutar Machine",
        description=(
            "Ejecuta una Machine (DomainRecon, InfrastructureRecon, EmailRecon, CompanyFootprint, "
            "PersonalFootprint, URLRecon, ThreatSweep, ASNToNetblocks o las de tu catálogo) o una cadena propia "
            "(transforms en orden). max_rounds repite la expansión sobre lo nuevo; los presupuestos limitan coste."
        ),
        annotations=OPEN_WORLD,
        structured_output=False,
    )
    @tool_errors
    async def osint_run_machine(
        case_id: CaseId,
        entity_type: EntityType,
        value: Annotated[str, Field(max_length=2048, description="Valor de la entidad inicial.")],
        transforms: Annotated[
            list[str], Field(default_factory=list, max_length=20, description="Cadena propia (si no usas machine).")
        ],
        machine: Annotated[str, Field(description="Nombre de la Machine (ver osint_list_transforms).")] = "",
        max_rounds: Annotated[int, Field(ge=1, le=5, description="Rondas de expansión recursiva.")] = 1,
        max_inputs_per_step: Annotated[int, Field(ge=1, le=50, description="Máximo de entidades por transform.")] = 10,
        max_total_entities: Annotated[int, Field(ge=1, le=1000, description="Para al alcanzar este total.")] = 150,
        soft_limit: SoftLimit = 25,
        reason: Reason = "",
        response_format: Fmt = "markdown",
    ) -> str:
        r = await svc.run_machine(
            case_id,
            entity_type,
            value,
            machine,
            transforms,
            max_rounds,
            max_inputs_per_step,
            max_total_entities,
            soft_limit,
            reason,
        )
        if response_format == "json":
            return to_json(_machine_json(r))
        return _machine_md(r) + "\n\nSiguiente: osint_suggest_next_steps u osint_get_case_summary."

    # =============================================================================== copiloto
    @mcp.tool(
        name="osint_investigate",
        title="Investigar en una llamada",
        description=(
            "Punto de entrada: detecta el tipo del valor, crea el caso (o usa case_id), ejecuta la Machine adecuada "
            "(o expand_entity), puntúa entidades, propone los siguientes pasos y devuelve un informe en línea."
        ),
        annotations=OPEN_WORLD,
        structured_output=False,
    )
    @tool_errors
    async def osint_investigate(
        value: Annotated[str, Field(max_length=2048, description="Dato inicial: dominio, IP, correo, URL, alias...")],
        case_id: Annotated[str, Field(description="Caso; vacío = se crea inv-<valor>-<fecha>.")] = "",
        entity_type: EntityType = "auto",
        machine: Annotated[str, Field(description="Forzar Machine; vacío = automática por tipo.")] = "",
        max_rounds: Annotated[int, Field(ge=1, le=3, description="Rondas de expansión.")] = 1,
        max_total_entities: Annotated[int, Field(ge=1, le=500, description="Presupuesto de entidades.")] = 120,
        reason: Reason = "",
        response_format: Fmt = "markdown",
    ) -> str:
        r = await svc.investigate(value, case_id, entity_type, machine, max_rounds, max_total_entities, reason)
        if response_format == "json":
            return to_json(
                {
                    "case_id": r.case_id,
                    "maltego_type": r.maltego_type,
                    "strategy": r.strategy,
                    "machine": _machine_json(r.machine_result) if r.machine_result else None,
                    "entity_count": r.summary.entity_count if r.summary else 0,
                    "edge_count": r.summary.edge_count if r.summary else 0,
                    "top": [s.to_dict() for s in r.top],
                    "next_actions": [a.to_dict() for a in r.actions],
                    "notes": r.notes,
                }
            )
        parts = [f"# Investigación `{r.case_id}`", f"Tipo detectado: {r.maltego_type} · estrategia: {r.strategy}"]
        if r.machine_result:
            parts.append(_machine_md(r.machine_result))
        if r.expand_result:
            parts.append(
                f"expand_entity: {sum(len(x.results) for x in r.expand_result.runs)} resultados, "
                f"{len(r.expand_result.errors)} errores"
            )
        parts += r.notes
        if r.summary:
            parts.append(f"**Grafo:** {r.summary.entity_count} entidades, {r.summary.edge_count} relaciones")
        if r.top:
            parts += ["**Entidades prioritarias**", _scores_md(r.top)]
        parts += [
            "**Siguientes pasos recomendados**",
            _actions_md(r.actions),
            UNTRUSTED_NOTE,
            "Más: osint_export_case (mtgx para Maltego, report_md/report_html para informe).",
        ]
        return "\n\n".join(parts)

    @mcp.tool(
        name="osint_suggest_next_steps",
        title="Siguiente mejor acción",
        description=(
            "Recomienda de forma determinista y explicada los pivotes más valiosos: entidad prioritaria x transform "
            "aplicable aún no ejecutado x rendimiento histórico del transform (aprendizaje por resultados)."
        ),
        annotations=READ_ONLY,
        structured_output=False,
    )
    @tool_errors
    async def osint_suggest_next_steps(
        case_id: CaseId,
        limit: Annotated[int, Field(ge=1, le=50, description="Cuántas acciones devolver.")] = 10,
        include_stats: Annotated[bool, Field(description="Incluir rendimiento histórico de transforms.")] = False,
        response_format: Fmt = "markdown",
    ) -> str:
        actions, _ = await svc.suggest(case_id, limit)
        stats = await svc.learning() if include_stats else {}
        if response_format == "json":
            return to_json(
                {
                    "actions": [a.to_dict() for a in actions],
                    "transform_stats": {
                        k: {"runs": v.runs, "errors": v.errors, "avg_new": round(v.avg_yield, 2)}
                        for k, v in stats.items()
                    },
                }
            )
        out = [_actions_md(actions)]
        if stats:
            out += [
                "\n**Rendimiento histórico**",
                "| transform | ejecuciones | errores | nuevas/ejecución |",
                "|---|---|---|---|",
            ]
            out += [
                f"| {k} | {v.runs} | {v.errors} | {v.avg_yield:.1f} |"
                for k, v in sorted(stats.items(), key=lambda kv: -kv[1].avg_yield)
            ]
        return "\n".join(out)

    @mcp.tool(
        name="osint_get_timeline",
        title="Memoria y cronología del caso",
        description=(
            "Memoria procedimental del caso: cada paso (qué, sobre qué, por qué, resultado, duración, errores) en "
            "orden. Para seguir hallazgos en vivo, consulta periódicamente con since_seq = último seq recibido."
        ),
        annotations=READ_ONLY,
        structured_output=False,
    )
    @tool_errors
    async def osint_get_timeline(
        case_id: CaseId,
        since_seq: Annotated[
            int, Field(ge=0, description="Solo pasos posteriores a este seq (sondeo incremental).")
        ] = 0,
        limit: Annotated[int, Field(ge=1, le=500, description="Máximo de pasos.")] = 100,
        response_format: Fmt = "markdown",
    ) -> str:
        steps = await svc.timeline(case_id, since_seq, limit)
        last = steps[-1].seq if steps else since_seq
        if response_format == "json":
            return to_json({"count": len(steps), "last_seq": last, "items": [s.to_dict() for s in steps]})
        if not steps:
            return f"Sin pasos nuevos después de seq {since_seq}."
        rows = ["| seq | hora | tipo | acción | sobre | nuevas | error | motivo |", "|---|---|---|---|---|---|---|---|"]
        rows += [
            f"| {s.seq} | {s.timestamp} | {s.kind} | {cell(s.action, 60)} | {code_cell(s.input_value, 60)} | "
            f"{s.new_entities} | {cell(s.error, 80)} | {cell(s.reason, 80)} |"
            for s in steps
        ]
        rows.append(f"\nÚltimo seq: {last} (úsalo como since_seq para recibir solo lo nuevo).")
        return "\n".join(rows)

    # =============================================================================== intercambio
    @mcp.tool(
        name="osint_export_case",
        title="Exportar caso o informe",
        description=(
            "Exporta a fichero: mtgx (grafo nativo de Maltego con layout hierarchical/radial/force y la memoria de la "
            "investigación dentro), json, graphml (SIEM/SOAR, Gephi), csv, report_md o report_html (informe "
            "ejecutivo). inline=true devuelve además el informe Markdown en la respuesta."
        ),
        annotations=ToolAnnotations(
            read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False
        ),
        structured_output=False,
    )
    @tool_errors
    async def osint_export_case(
        case_id: CaseId,
        format: Annotated[
            Literal["mtgx", "json", "graphml", "csv", "report_md", "report_html"],
            Field(description="mtgx, json, graphml, csv, report_md o report_html."),
        ] = "mtgx",
        layout: Annotated[
            Literal["hierarchical", "radial", "force"], Field(description="Disposición del .mtgx.")
        ] = "hierarchical",
        inline: Annotated[bool, Field(description="Incluir el informe Markdown en la respuesta.")] = False,
    ) -> str:
        path, n_ent, n_edges = await svc.export_case(case_id, format, layout)
        msg = f"Exportado {n_ent} entidades y {n_edges} relaciones a `{path}`."
        if inline:
            msg += "\n\n" + to_markdown(await svc.report_data(case_id))
        return msg

    @mcp.tool(
        name="osint_import_graph",
        title="Importar grafo de Maltego o CSV",
        description=(
            "Importa (fusiona) en un caso un grafo .mtgx guardado en Maltego —con su memoria si la trae— o un CSV "
            "(source_type,source_value,relation,target_type,target_value,confidence). El fichero debe estar en "
            "~/.maltego-mcp/imports o exports."
        ),
        annotations=WRITE_IDEMPOTENT,
        structured_output=False,
    )
    @tool_errors
    async def osint_import_graph(
        case_id: CaseId,
        file_name: Annotated[str, Field(max_length=300, description="Nombre del fichero, p. ej. caso.mtgx.")],
    ) -> str:
        r = await svc.import_graph(case_id, file_name)
        lines = [
            f"Importado `{r.path.name}`: {r.entities} entidades ({r.new_entities} nuevas), {r.links} relaciones"
            f" y {r.steps} pasos de memoria en el caso `{case_id.strip().lower()}`."
        ]
        if r.skipped:
            lines.append("Descartados: " + "; ".join(safe(x, 160) for x in r.skipped[:10]))
        return "\n".join(lines)
