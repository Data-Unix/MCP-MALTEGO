"""Puente con Maltego Desktop mediante transforms locales (sin servidor, válido en Maltego CE).

Uso:
  maltego-mcp-bridge mtz [--output RUTA] [--uv RUTA_A_UV]   # genera el .mtz para importar en Maltego
  maltego-mcp-bridge local <transform> <valor> [props]       # lo invoca Maltego, no a mano

Transforms que aparecen en Maltego (set "MCP Maltego"):
  - MCP · Listar casos        (Phrase)        -> una Phrase por caso
  - MCP · Abrir caso          (Phrase=case_id) -> fija el caso actual y trae sus entidades
  - MCP · Vecinos en el caso  (cada tipo)     -> relaciones guardadas por los agentes
  - MCP · Guardar en el caso  (cada tipo)     -> guarda la entidad para que los agentes la vean

Los .mtz se generan con el SDK oficial (maltego_trx.decorator_registry.TransformRegistry).
"""

from __future__ import annotations

import argparse
import asyncio
import shutil
import sys
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from maltego_trx.decorator_registry import TransformRegistry, TransformSet
from maltego_trx.maltego import UIM_INFORM, UIM_PARTIAL, MaltegoMsg, MaltegoTransform
from maltego_trx.utils import name_to_path

from maltego_mcp.config import Settings
from maltego_mcp.domain.entity_types import ENTITY_TYPES
from maltego_mcp.domain.normalize import validate_case_id
from maltego_mcp.domain.records import EntityRecord
from maltego_mcp.errors import MaltegoMcpError
from maltego_mcp.maltego.mtgx import DISPLAY_PROPERTY, main_property_for
from maltego_mcp.service import OsintService

TRANSFORM_SET = TransformSet("MCP Maltego", "Puente entre Maltego y el grafo compartido de los agentes (MCP)")
MAX_ENTITIES_OUT = 256
CURRENT_CASE_FILE = "current_case"


@dataclass(frozen=True, slots=True)
class BridgeTransform:
    class_name: str
    kind: str  # list_cases | open_case | neighbors | save
    input_entity: str
    display_name: str
    description: str

    @property
    def name(self) -> str:
        return str(name_to_path(self.class_name))


def _type_suffix(maltego_type: str) -> str:
    return maltego_type.split(".", 1)[-1].replace(".", "")


def bridge_transforms() -> list[BridgeTransform]:
    out = [
        BridgeTransform(
            "MCPListCases",
            "list_cases",
            "maltego.Phrase",
            "MCP · Listar casos",
            "Lista los casos del grafo compartido del MCP.",
        ),
        BridgeTransform(
            "MCPOpenCase",
            "open_case",
            "maltego.Phrase",
            "MCP · Abrir caso",
            "Usa el valor de la frase como case_id, lo fija como caso actual y trae sus entidades.",
        ),
    ]
    for et in ENTITY_TYPES:
        suffix = _type_suffix(et.maltego_type)
        out.append(
            BridgeTransform(
                f"MCPNeighbors_{suffix}",
                "neighbors",
                et.maltego_type,
                "MCP · Vecinos en el caso",
                "Relaciones de esta entidad en el caso actual del MCP.",
            )
        )
        out.append(
            BridgeTransform(
                f"MCPSave_{suffix}",
                "save",
                et.maltego_type,
                "MCP · Guardar en el caso",
                "Guarda esta entidad en el caso actual del MCP para que los agentes la usen.",
            )
        )
    return out


BY_NAME: dict[str, BridgeTransform] = {t.name: t for t in bridge_transforms()}


# ------------------------------------------------------------------------------------- ejecución
def _current_case_path(settings: Settings) -> Path:
    return settings.home / CURRENT_CASE_FILE


def read_current_case(settings: Settings) -> str:
    try:
        return validate_case_id(_current_case_path(settings).read_text(encoding="utf-8").strip())
    except (FileNotFoundError, MaltegoMcpError):
        return ""


def _emit(response: MaltegoTransform, e: EntityRecord, link_label: str = "", reverse: bool = False) -> None:
    ent = response.addEntity(e.maltego_type, e.value)
    if e.maltego_type.lower() in DISPLAY_PROPERTY:  # URL/Document: el valor real va en su propiedad principal
        ent.addProperty(main_property_for(e.maltego_type), main_property_for(e.maltego_type), "strict", e.value)
    ent.addProperty("mcp.entity_id", "MCP id", "loose", e.id)
    ent.addProperty("mcp.case", "MCP caso", "loose", e.case_id)
    ent.addProperty("mcp.confidence", "MCP confianza", "loose", str(e.confidence))
    ent.addProperty("mcp.sources", "MCP fuentes", "loose", "; ".join(e.sources[-5:]))
    for k, v in list(e.properties.items())[:20]:
        ent.addProperty(k, k, "loose", v)
    ent.setWeight(max(1, int(e.confidence * 100)))
    if link_label:
        ent.setLinkLabel(link_label)
    if reverse:
        ent.reverseLink()


async def _run(
    t: BridgeTransform, msg: MaltegoMsg, svc: OsintService, settings: Settings, response: MaltegoTransform
) -> None:
    limit = max(1, min(int(msg.Slider or 100), MAX_ENTITIES_OUT))
    if t.kind == "list_cases":
        cases = await svc.list_cases(limit, 0)
        for case in cases.items:
            response.addEntity("maltego.Phrase", case.case_id).setLinkLabel("caso MCP")
        response.addUIMessage(f"{cases.total} casos en el MCP.", UIM_INFORM)
        return
    if t.kind == "open_case":
        case_id = validate_case_id(msg.Value)
        summary = await svc.case_summary(case_id, 0)
        settings.home.mkdir(parents=True, exist_ok=True)
        _current_case_path(settings).write_text(case_id, encoding="utf-8")
        page = await svc.search(case_id, "", "", limit, 0)
        for e in page.items:
            _emit(response, e, "en el caso")
        response.addUIMessage(
            f"Caso actual: {case_id} ({summary.entity_count} entidades, {summary.edge_count} relaciones; "
            f"mostradas {len(page.items)}). Usa 'MCP · Vecinos en el caso' para expandir.",
            UIM_INFORM,
        )
        return
    # El caso viaja en la propia entidad (mcp.case) si vino del MCP; si no, se usa el caso actual.
    case_id = _case_from_entity(msg) or read_current_case(settings)
    if not case_id:
        response.addUIMessage(
            "No hay caso actual: ejecuta 'MCP · Abrir caso' sobre una frase con el id del caso.", UIM_PARTIAL
        )
        return
    value = _entity_value(t.input_entity, msg)
    if t.kind == "neighbors":
        entity = svc.build_entity(case_id, t.input_entity, value, 0.5, "maltego")
        if await svc.store.get_entity(case_id, entity.id) is None:
            response.addUIMessage(
                f"'{value}' no está en el caso {case_id}. Usa 'MCP · Guardar en el caso'.", UIM_PARTIAL
            )
            return
        for n in await svc.neighbors(case_id, entity.id, "", "both", limit):
            _emit(response, n.entity, n.edge.label, reverse=n.direction == "in")
        return
    skip = {main_property_for(t.input_entity), DISPLAY_PROPERTY.get(t.input_entity.lower(), "")}
    props = {k: str(v) for k, v in (msg.Properties or {}).items() if v and k not in skip and not k.startswith("mcp.")}
    ent, created = await svc.upsert_entity(
        case_id, t.input_entity, value, 0.7, "maltego", [f"{k}={v}" for k, v in list(props.items())[:50]]
    )
    response.addUIMessage(
        f"{'Guardada' if created else 'Actualizada'} en el caso {case_id}: {ent.value} ({ent.maltego_type}).",
        UIM_INFORM,
    )


def _entity_value(maltego_type: str, msg: MaltegoMsg) -> str:
    """Valor real de la entidad: para URL/Document Maltego muestra un título y la URL va en una propiedad."""
    if maltego_type.lower() in DISPLAY_PROPERTY:
        real = (msg.Properties or {}).get(main_property_for(maltego_type))
        if real:
            return str(real)
    return str(msg.Value)


def _case_from_entity(msg: MaltegoMsg) -> str:
    try:
        return validate_case_id(str((msg.Properties or {}).get("mcp.case", "")))
    except MaltegoMcpError:
        return ""


def run_local(
    name: str,
    local_args: list[str],
    settings: Settings | None = None,
    service_factory: Callable[[Settings], OsintService] | None = None,
) -> str:
    """Ejecuta un transform local y devuelve el XML de respuesta (lo que Maltego lee por stdout)."""
    response = MaltegoTransform()
    t = BY_NAME.get(name.lower())
    if t is None:
        response.addUIMessage(f"Transform desconocido: {name}. Regenera el .mtz.", UIM_PARTIAL)
        return str(response.returnOutput())
    try:
        settings = settings or Settings.from_env()
        from maltego_mcp.server import build_service  # import diferido: evita ciclo

        svc = (service_factory or build_service)(settings)
        msg = MaltegoMsg(LocalArgs=local_args)
        coro: Coroutine[Any, Any, None] = _run(t, msg, svc, settings, response)
        asyncio.run(coro)
    except MaltegoMcpError as exc:
        response.addUIMessage(str(exc), UIM_PARTIAL)
    except Exception as exc:  # cualquier fallo inesperado se muestra en Maltego sin traza
        response.addUIMessage(f"Error interno del puente MCP ({exc.__class__.__name__}).", UIM_PARTIAL)
    return str(response.returnOutput())


# ------------------------------------------------------------------------------------- .mtz
def build_registry() -> TransformRegistry:
    registry = TransformRegistry(owner="MCP Maltego", author="MCP Maltego", host_url="http://localhost", seed_ids=[])
    for t in bridge_transforms():
        cls = type(t.class_name, (), {})
        registry.register_transform(
            display_name=t.display_name,
            input_entity=t.input_entity,
            description=t.description,
            transform_set=TRANSFORM_SET,
        )(cls)
    return registry


def write_mtz(output: Path, repo_dir: Path, uv_command: str) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    build_registry().write_local_mtz(
        mtz_path=str(output),
        working_dir=str(repo_dir),
        command=uv_command,
        params="run --quiet maltego-mcp-bridge",
        debug=False,
    )
    return output


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="maltego-mcp-bridge", description="Puente MCP <-> Maltego Desktop")
    sub = parser.add_subparsers(dest="command", required=True)
    mtz = sub.add_parser("mtz", help="Genera el .mtz con los transforms locales para importar en Maltego")
    mtz.add_argument("--output", type=Path, default=None)
    mtz.add_argument("--repo", type=Path, default=Path.cwd(), help="Carpeta del repo (por defecto, la actual)")
    mtz.add_argument("--uv", default=shutil.which("uv") or "uv", help="Ruta completa de uv")
    local = sub.add_parser("local", help="Lo invoca Maltego")
    local.add_argument("transform")
    local.add_argument("args", nargs=argparse.REMAINDER)
    ns = parser.parse_args(argv)
    if ns.command == "mtz":
        settings = Settings.from_env()
        repo = ns.repo.resolve()
        if not (repo / "pyproject.toml").exists():
            parser.error(f"{repo} no parece la carpeta del repo (falta pyproject.toml). Usa --repo.")
        out = write_mtz(ns.output or settings.home / "maltego-mcp-local.mtz", repo, ns.uv)
        print(f"Generado {out} con {len(BY_NAME)} transforms locales.", file=sys.stderr)
        print(f"Importa en Maltego: Import | Export > Import Config > {out}", file=sys.stderr)
        return
    # Bytes UTF-8 con declaración: en Windows la salida por tubería usaría la página de códigos ANSI y fallaría
    # con valores no latinos.
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n' + run_local(ns.transform, ns.args)
    sys.stdout.buffer.write(xml.encode("utf-8"))
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
