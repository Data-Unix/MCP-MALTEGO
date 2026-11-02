"""maltegoctl: consola para terminal y CI/CD, sin interfaz gráfica.

maltegoctl inspect GRAFO.mtgx [--json]        valida un .mtgx: estructura, límites, tipos, enlaces, memoria
maltegoctl lookup TRANSFORM VALOR [--type T]   ejecuta un transform y muestra el resultado (no guarda nada)
maltegoctl transforms [--type T]               lista transforms y Machines con su disponibilidad
maltegoctl import-entities CONFIG.mtz          importa la ontología de tu Maltego (Entities/*.entity)
maltegoctl export CASO [--format F] [--layout L]
maltegoctl mtz [--output RUTA]                 genera el .mtz de transforms locales para Maltego
"""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import sys
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

import defusedxml.ElementTree as SafeET
from defusedxml import DefusedXmlException

from maltego_mcp.config import ONTOLOGY_FILE, Settings
from maltego_mcp.domain.entity_types import CUSTOM_TYPE_RE, all_entity_types, resolve_entity_type
from maltego_mcp.errors import InvalidInput, MaltegoMcpError
from maltego_mcp.maltego.mtgx import (
    GRAPH_MEMBER,
    GRAPHML_NS,
    MAX_ARCHIVE_BYTES,
    MAX_ENTITIES,
    MAX_GRAPHML_BYTES,
    MAX_LINKS,
    MTG_NS,
    read_mtgx,
)

MAX_ENTITY_FILES = 5000
MAX_ENTITY_FILE_BYTES = 1024 * 1024


# ------------------------------------------------------------------------------------------ inspect
def inspect_mtgx(payload: bytes) -> dict[str, Any]:
    """Informe de validez de un .mtgx (no modifica nada)."""
    report: dict[str, Any] = {"valid": False, "errors": [], "warnings": [], "size_bytes": len(payload)}
    try:
        graph = read_mtgx(payload)  # aplica primero todos los límites (tamaño, nº de ficheros, descompresión)
    except InvalidInput as exc:
        report["errors"].append(str(exc))
        return report
    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        names = zf.namelist()
        report["members"] = len(names)
        if GRAPH_MEMBER not in names:
            report["warnings"].append(f"No existe {GRAPH_MEMBER}; se usó el primer Graphs/*.graphml.")
        member = next((n for n in names if n.startswith("Graphs/") and n.endswith(".graphml")), GRAPH_MEMBER)
        with zf.open(member) as fh:
            xml = fh.read(MAX_GRAPHML_BYTES + 1)
    try:
        root = SafeET.fromstring(xml)
    except (DefusedXmlException, SafeET.ParseError) as exc:
        report["errors"].append(f"GraphML inválido: {exc.__class__.__name__}.")
        return report
    nodes = list(root.iter(f"{{{GRAPHML_NS}}}node"))
    positions = sum(1 for n in nodes if n.find(f".//{{{MTG_NS}}}Position") is not None)
    types = Counter(e.maltego_type for e in graph.entities)
    unknown = [t for t in types if _is_unknown_type(t)]
    report.update(
        {
            "entities": len(graph.entities),
            "links": len(graph.links),
            "skipped_nodes": graph.skipped,
            "by_type": dict(types.most_common()),
            "positions": positions,
            "memory_steps": len(graph.sidecar.get("steps", [])),
        }
    )
    if positions < len(nodes):
        report["warnings"].append(f"{len(nodes) - positions} nodos sin posición: Maltego los recolocará al abrir.")
    if unknown:
        report["warnings"].append(
            "Tipos no estándar (importa tu ontología si son tuyos): " + ", ".join(sorted(unknown))
        )
    if graph.skipped:
        report["warnings"].append(f"{graph.skipped} nodos sin tipo o sin valor.")
    if len(payload) > MAX_ARCHIVE_BYTES or len(graph.entities) > MAX_ENTITIES or len(graph.links) > MAX_LINKS:
        report["warnings"].append("Supera los límites de importación de MCP Maltego.")
    report["valid"] = not report["errors"]
    return report


def _is_unknown_type(maltego_type: str) -> bool:
    try:
        return resolve_entity_type(maltego_type).graph_label == "custom"
    except InvalidInput:
        return True


# ------------------------------------------------------------------------------------------ ontología
def parse_entity_definitions(mtz_bytes: bytes) -> list[dict[str, str]]:
    """Lee Entities/*.entity de un .mtz exportado desde Maltego (Import | Export > Export Config)."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(mtz_bytes))
    except zipfile.BadZipFile as exc:
        raise InvalidInput("El fichero no es un .mtz (ZIP) válido.") from exc
    out: list[dict[str, str]] = []
    with zf:
        entity_files = [
            i for i in zf.infolist() if i.filename.lower().endswith(".entity") and i.file_size <= MAX_ENTITY_FILE_BYTES
        ][:MAX_ENTITY_FILES]
        if not entity_files:
            raise InvalidInput(
                "El .mtz no contiene entidades (Entities/*.entity). Exporta la configuración con "
                "las entidades seleccionadas."
            )
        for info in entity_files:
            try:
                with zf.open(info) as fh:
                    root = SafeET.fromstring(fh.read(MAX_ENTITY_FILE_BYTES + 1))
            except (DefusedXmlException, SafeET.ParseError):
                continue
            ent = root if root.tag.endswith("MaltegoEntity") else root.find(".//MaltegoEntity")
            if ent is None:
                continue
            type_id = (ent.get("id") or "").strip()
            props = ent.find("Properties")
            main = (props.get("value") if props is not None else "") or ""
            if not main and props is not None:
                first = props.find(".//Field")
                main = first.get("name", "") if first is not None else ""
            if CUSTOM_TYPE_RE.match(type_id) and main:
                out.append(
                    {
                        "maltego_type": type_id,
                        "main_property": main.strip(),
                        "description": (ent.get("displayName") or type_id).strip()[:200],
                        "category": (ent.get("category") or "").strip()[:60],
                    }
                )
    return out


def write_ontology(definitions: list[dict[str, str]], home: Path) -> Path:
    home.mkdir(parents=True, exist_ok=True)
    path = home / ONTOLOGY_FILE
    path.write_text(
        json.dumps({"format": "maltego-mcp-entities/1", "entity_types": definitions}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return path


# ------------------------------------------------------------------------------------------ comandos
def _print_table(rows: list[list[str]]) -> None:
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    for r in rows:
        print("  ".join(c.ljust(w) for c, w in zip(r, widths, strict=True)))


async def _lookup(transform: str, value: str, entity_type: str) -> int:
    from maltego_mcp.server import build_service

    svc = build_service(Settings.from_env())
    run = await svc.run_transform("", transform, entity_type, value, [], 50, False)
    rows = [["TIPO", "VALOR", "RELACIÓN"]] + [
        [r.entity.maltego_type, r.entity.value, r.edge_label] for r in run.results
    ]
    _print_table(rows)
    for kind, text in run.messages:
        print(f"[{kind}] {text}", file=sys.stderr)
    return 0


def _transforms(entity_type: str) -> int:
    from maltego_mcp.server import build_service

    svc = build_service(Settings.from_env())
    rows = [["TRANSFORM", "CATEGORÍA", "DISPONIBLE"]] + [
        [s.name, s.category, "sí" if s.available(svc.env) else "falta " + ",".join(s.requires)]
        for s in svc.list_transforms(entity_type)
    ]
    _print_table(rows)
    print("\nMachines: " + ", ".join(sorted(m.name for m in svc.catalog.machines.machines.values())))
    return 0


async def _export(case_id: str, fmt: str, layout: str) -> int:
    from maltego_mcp.server import build_service

    svc = build_service(Settings.from_env())
    path, n, m = await svc.export_case(case_id, fmt, layout)  # type: ignore[arg-type]
    print(f"{path} ({n} entidades, {m} relaciones)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="maltegoctl", description="Consola de MCP Maltego")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("inspect", help="Valida un .mtgx")
    p.add_argument("file", type=Path)
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("lookup", help="Ejecuta un transform sin guardar")
    p.add_argument("transform")
    p.add_argument("value")
    p.add_argument("--type", default="auto")
    p = sub.add_parser("transforms", help="Lista transforms y Machines")
    p.add_argument("--type", default="")
    p = sub.add_parser("import-entities", help="Importa la ontología de tu Maltego desde un .mtz")
    p.add_argument("file", type=Path)
    p = sub.add_parser(
        "index-breaches",
        help="Indexa un fichero local de filtraciones (.csv, .tsv, .jsonl, .txt) en SQLite",
    )
    p.add_argument("file", type=Path)
    p = sub.add_parser(
        "sync-cti",
        help="Sincroniza fuentes CTI activas (ONLINE/VALID) desde fastfire/deepdarkCTI y purga las OFFLINE/EXPIRED",
    )
    p.add_argument("--force", action="store_true", help="Fuerza la descarga aunque la caché sea reciente")
    p = sub.add_parser(
        "dashboard",
        help="Inicia el panel web interactivo en 127.0.0.1 y lo abre en el navegador",
    )
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--no-browser", action="store_true", help="No abrir automáticamente el navegador")
    p = sub.add_parser(
        "accounts",
        help="Gestiona cuentas de redes sociales y Sock Puppets (~/.maltego-mcp/accounts.toml)",
    )
    p.add_argument("action", nargs="?", default="list", choices=["list", "generate-persona"])
    p.add_argument("--role", default="security_researcher")
    p.add_argument("--region", default="EU")
    p.add_argument("--site", default="")
    p.add_argument("--seed", default="")
    p.add_argument("--save", action="store_true", help="Añade la plantilla del Sock Puppet a accounts.toml")
    p = sub.add_parser("export", help="Exporta un caso")
    p.add_argument("case_id")
    p.add_argument("--format", default="mtgx", choices=["mtgx", "json", "graphml", "csv", "report_md", "report_html"])
    p.add_argument("--layout", default="hierarchical", choices=["hierarchical", "radial", "force"])
    p = sub.add_parser("mtz", help="Genera el .mtz de transforms locales para Maltego")
    p.add_argument("--output", type=Path, default=None)
    p.add_argument("--repo", type=Path, default=Path.cwd())
    p.add_argument("--uv", default="")
    ns = parser.parse_args(argv)
    try:
        if ns.command == "inspect":
            report = inspect_mtgx(ns.file.read_bytes())
            if ns.json:
                print(json.dumps(report, ensure_ascii=False, indent=2))
            else:
                print(f"{'VÁLIDO' if report['valid'] else 'INVÁLIDO'}: {ns.file.name}")
                for key in ("entities", "links", "positions", "memory_steps", "members", "size_bytes"):
                    if key in report:
                        print(f"  {key}: {report[key]}")
                for t, n in report.get("by_type", {}).items():
                    print(f"  {t}: {n}")
                for w in report["warnings"]:
                    print(f"  aviso: {w}")
                for e in report["errors"]:
                    print(f"  error: {e}")
            return 0 if report["valid"] else 1
        if ns.command == "lookup":
            return asyncio.run(_lookup(ns.transform, ns.value, ns.type))
        if ns.command == "transforms":
            return _transforms(ns.type)
        if ns.command == "import-entities":
            defs = parse_entity_definitions(ns.file.read_bytes())
            path = write_ontology(defs, Settings.from_env().home)
            print(f"Importados {len(defs)} tipos de entidad en {path}. Reinicia los agentes para cargarlos.")
            total = len(all_entity_types())
            print(f"(Tipos estándar disponibles antes de importar: {total})", file=sys.stderr)
            return 0
        if ns.command == "index-breaches":
            from maltego_mcp.breaches import BREACH_DB_NAME, index_breach_file

            db_path = Settings.from_env().home / BREACH_DB_NAME
            count = index_breach_file(db_path, ns.file)
            print(f"Indexados {count} registros de filtraciones en {db_path}.")
            return 0
        if ns.command == "sync-cti":
            import httpx

            from maltego_mcp.cti_feeds import CTISyncSummary, sync_deepdark_cti

            async def _run_sync() -> CTISyncSummary:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    return await sync_deepdark_cti(Settings.from_env().home, client, force=bool(ns.force))

            res = asyncio.run(_run_sync())
            print(
                f"Sincronización DeepDarkCTI ({res['db_path']}): "
                f"{res['active_rows']} fuentes ACTIVAS (ONLINE/VALID), "
                f"{res['purged_rows']} purgadas/actualizadas."
            )
            return 0
        if ns.command == "dashboard":
            import webbrowser

            import uvicorn

            from maltego_mcp.server import _uvicorn_log_config, build_service, create_server
            from maltego_mcp.web_app import attach_dashboard_routes

            settings = Settings.from_env()
            server = create_server(settings)
            app = server.streamable_http_app(stateless_http=True, json_response=True, host=ns.host)
            svc = getattr(server, "_service", None) or build_service(settings)
            attach_dashboard_routes(app, svc, settings)

            url = f"http://{ns.host}:{ns.port}/"
            print(f"Panel web MCP Maltego activo en: {url}")
            print(f"Transporte MCP Streamable HTTP en: http://{ns.host}:{ns.port}/mcp")
            if not ns.no_browser:
                import contextlib

                with contextlib.suppress(Exception):
                    webbrowser.open(url)
            try:
                uvicorn.run(
                    app,
                    host=ns.host,
                    port=ns.port,
                    log_level="info",
                    log_config=_uvicorn_log_config(),
                )
            except OSError as exc:
                print(
                    f"Error: no se pudo iniciar el panel en {ns.host}:{ns.port} ({exc}). "
                    f"Prueba con otro puerto mediante --port (ej. maltegoctl dashboard --port {ns.port + 1}).",
                    file=sys.stderr,
                )
                return 1
            return 0
        if ns.command == "accounts":
            from maltego_mcp.accounts import (
                ensure_accounts_template,
                generate_sockpuppet_persona,
                load_account_pool,
                save_persona_to_accounts_toml,
            )

            home = Settings.from_env().home
            tpl = ensure_accounts_template(home)
            if ns.action == "generate-persona":
                persona = generate_sockpuppet_persona(
                    role=ns.role,
                    region=ns.region,
                    target_site=ns.site,
                    seed=ns.seed,
                )
                print(json.dumps(persona.to_dict(), ensure_ascii=False, indent=2))
                if ns.save:
                    saved = save_persona_to_accounts_toml(home, persona)
                    print(f"\nPlantilla añadida en {saved}", file=sys.stderr)
                return 0
            pool = load_account_pool(home)
            items = pool.summary()
            if not items:
                print(
                    f"Sin cuentas activas configuradas. Edita {tpl} o usa "
                    "'maltegoctl accounts generate-persona --save'."
                )
                return 0
            rows = [["PLATAFORMA", "CUENTA", "SITIO", "ESTADO", "SECRETO"]] + [
                [
                    str(a["platform"]),
                    str(a["username"]),
                    str(a["site"] or "-"),
                    "disponible" if a["available"] else "cooldown",
                    str(a["secret_preview"]),
                ]
                for a in items
            ]
            _print_table(rows)
            return 0
        if ns.command == "export":
            return asyncio.run(_export(ns.case_id, ns.format, ns.layout))
        from maltego_mcp.maltego.bridge import main as bridge_main

        args = ["mtz", "--repo", str(ns.repo)] + (["--output", str(ns.output)] if ns.output else [])
        bridge_main(args + (["--uv", ns.uv] if ns.uv else []))
        return 0
    except (MaltegoMcpError, OSError) as exc:
        print(f"maltegoctl: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
