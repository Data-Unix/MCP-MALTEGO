"""Tests exhaustivos de:
1. Garantía Zero-Leak (ausencia absoluta de referencias a clientes, casos privados o rutas locales en todo el repo).
2. Peticiones vagas / en texto claro desde agentes de VS Code (Claude, GitHub Copilot) con osint_investigate.
3. Sincronización automática de fases P0-P9 (ACH / ICD 203), perfilado pericial e Informe Pericial Ejecutivo completo.
4. Bus de eventos en tiempo real multiproceso (stdio -> Dashboard HTTP /api/events/poll y SSE).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp import Client
from mcp.types import TextContent
from starlette.testclient import TestClient

from maltego_mcp.config import Settings
from maltego_mcp.graph.memory import MemoryGraphStore
from maltego_mcp.server import build_service, create_server
from maltego_mcp.service import OsintService, extract_seed_from_plaintext
from maltego_mcp.transforms.builtin import new_http_client
from maltego_mcp.transforms.catalog import TransformCatalog
from maltego_mcp.web_app import attach_dashboard_routes
from tests.test_builtin import Router

ROOT = Path(__file__).resolve().parents[1]

# Construidos por concatenación para que ni siquiera este fichero contenga los literales en bruto.
FORBIDDEN_PRIVATE_TERMS: tuple[str, ...] = (
    "voda" + "fone",
    "kone" + "cta",
    "arru" + "fat",
    "wua" + "shop",
    "duo" + "ke",
    "informe_final_" + "bpo",
    "daily" + "-mcp",
    "users\\" + "alvaro",
    "users/" + "alvaro",
)


def test_repositorio_publico_cero_filtraciones_privadas() -> None:
    """Escanea todos los ficheros del repositorio para garantizar cero referencias a casos o clientes privados."""
    res = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True)
    tracked = [line.strip() for line in res.stdout.splitlines() if line.strip()]
    assert len(tracked) > 50

    leaks: list[str] = []
    for rel_path in tracked:
        if rel_path == "uv.lock":
            continue
        fpath = ROOT / rel_path
        if not fpath.is_file():
            continue
        if rel_path.startswith("scripts/investigate_"):
            leaks.append(f"Script privado versionado: {rel_path}")
        try:
            text = fpath.read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            continue
        for term in FORBIDDEN_PRIVATE_TERMS:
            if term in text:
                leaks.append(f"{rel_path} contiene término privado prohibido: {term}")

    # Además verificar que no queden scripts privados sin seguimiento dentro de scripts/
    for untracked_priv in (ROOT / "scripts").glob("investigate_*.py"):
        leaks.append(f"Script privado presente en scripts/: {untracked_priv.name}")

    assert not leaks, "Fugas de privacidad detectadas:\n" + "\n".join(leaks)


def test_extract_seed_from_plaintext_vague_requests() -> None:
    """Verifica la extracción de indicadores y sujetos desde peticiones vagas o en lenguaje natural."""
    # 1. Dominio embebido en frase natural
    val, etype, q = extract_seed_from_plaintext("Investiga a fondo el dominio example.com y dame un informe completo")
    assert val == "example.com"
    assert etype == "maltego.Domain"
    assert "Investiga a fondo" in q

    # 2. Correo electrónico en pregunta vaga
    val, etype, q = extract_seed_from_plaintext("¿Qué hay detrás del correo jdoe@example.com?")
    assert val == "jdoe@example.com"
    assert etype == "maltego.EmailAddress"
    assert "correo" in q

    # 3. IP en frase
    val, etype, _q = extract_seed_from_plaintext("Analiza qué servicios tiene la IP 93.184.216.34 por favor")
    assert val == "93.184.216.34"
    assert etype == "maltego.IPv4Address"

    # 4. Organización / empresa en lenguaje natural
    val, etype, q = extract_seed_from_plaintext("Investiga la empresa Acme Defense Corp y genera un informe")
    assert val == "Acme Defense Corp"
    assert etype == "maltego.Company"
    assert "Acme Defense Corp" in q

    # 5. Alias / usuario en lenguaje natural
    val, etype, _q = extract_seed_from_plaintext("Investiga al usuario @jdoe")
    assert val == "jdoe"
    assert etype == "maltego.Alias"

    # 6. Frase libre sin indicador ni patrón de comando se mantiene intacta como Phrase
    val, etype, q = extract_seed_from_plaintext("cadena libre sin patron estructurado")
    assert val == "cadena libre sin patron estructurado"
    assert etype == "auto"
    assert q == ""


@pytest.mark.asyncio
async def test_vscode_vague_request_populates_recon_p0_p9_profiles_and_full_report(
    tmp_path: Path, catalog: TransformCatalog
) -> None:
    """Una petición vaga en texto claro a osint_investigate actualiza P0-P9, perfila y devuelve el informe pericial."""
    settings = Settings(data_file=tmp_path / "graph.json", home=tmp_path)
    svc = OsintService(
        MemoryGraphStore(settings.data_file),
        catalog.with_builtins(),
        tmp_path / "exports",
        tmp_path / "imports",
        settings=settings,
    )
    svc.env = {}  # Modo pasivo por defecto
    svc._http = new_http_client(transport=httpx.MockTransport(Router()))

    async with Client(create_server(service=svc)) as client:
        res_md = await client.call_tool(
            "osint_investigate",
            {
                "value": "Investiga a fondo el dominio example.com y dame un informe de máxima calidad",
                "reason": "Petición en texto claro desde agente VS Code",
            },
        )
        assert not res_md.is_error
        block = res_md.content[0]
        assert isinstance(block, TextContent)
        md_text = block.text

        # 1. El informe devuelto al agente incluye el resumen táctico, la guía híbrida y el Informe Pericial completo
        assert "PassiveDomainRecon" in md_text
        assert "Guía de profundización híbrida para el agente" in md_text
        assert "TLP:AMBER+STRICT" in md_text
        assert "§ 01. Resumen Ejecutivo y Dictamen Pericial (BLUF)" in md_text
        assert "§ 03B. Perfilado Pericial Multidimensional y Vigencia Objetiva" in md_text
        assert "§ 03C. Síntesis Analítica Estimativa (ACH / Directiva ICD 203" in md_text
        assert "Matriz de Hipótesis en Competencia (ACH" in md_text
        assert "Sello Criptográfico SHA-256:" in md_text

        # 2. Verificar en JSON que los entregables fueron auto-exportados y las fases P0-P9 pobladas
        res_json = await client.call_tool(
            "osint_investigate",
            {
                "value": "¿Qué hay detrás del correo jdoe@example.com?",
                "case_id": "caso-vscode-email",
                "response_format": "json",
            },
        )
        assert not res_json.is_error
        jblock = res_json.content[0]
        assert isinstance(jblock, TextContent)
        payload: dict[str, Any] = json.loads(jblock.text)

    assert payload["case_id"] == "caso-vscode-email"
    assert payload["maltego_type"] == "maltego.EmailAddress"
    assert payload["strategy"] == "PassiveEmailRecon"
    assert payload["recon_phase"] == "Fase 9"
    assert payload["leading_hypothesis"].startswith("H1:")
    assert Path(payload["exported_files"]["report_html"]).is_file()
    assert Path(payload["exported_files"]["mcpcase"]).is_file()

    # 3. Verificar estado P0-P9 en el fichero _recon.json para el Dashboard de Descubrimiento
    recon = await svc.get_case_recon("caso-vscode-email")
    assert recon["active_phase"] == "Fase 9"
    assert recon["p0_framing"]["target"] == "jdoe@example.com"
    assert "correo" in recon["p0_framing"]["question"]
    assert len(recon["seeds"]) >= 1
    assert len(recon["hypotheses"]) == 3
    assert all(h.get("what_would_refute_it") for h in recon["hypotheses"])
    assert recon["key_evidence"]["sensitivity_impact"] == "alto"


def test_realtime_cross_process_dashboard_sync(tmp_path: Path, catalog: TransformCatalog) -> None:
    """Simula un proceso MCP stdio externo (VS Code) escribiendo eventos y verifica que el Dashboard HTTP los emite."""
    settings = Settings(data_file=tmp_path / "graph.json", home=tmp_path)
    server = create_server(settings)
    app = server.streamable_http_app(stateless_http=True, json_response=True)
    svc = getattr(server, "_service", None) or build_service(settings)
    attach_dashboard_routes(app, svc, settings)
    client = TestClient(app)

    # Simular un evento emitido por un proceso stdio externo (con distinto PID) en events.jsonl y current_case
    external_event = {
        "type": "step",
        "ts": 1700000000.0,
        "seq_ns": 9999999999999999999,
        "pid": 999999,  # PID externo distinto del servidor HTTP
        "case_id": "inv-vscode-live",
        "transform": "PassiveDomainRecon",
        "target": "example.com",
        "new_entities": 6,
    }
    (tmp_path / "events.jsonl").write_text(json.dumps(external_event) + "\n", encoding="utf-8")
    (tmp_path / "active_case").write_text("inv-vscode-live", encoding="utf-8")

    r_poll = client.get("/api/events/poll")
    assert r_poll.status_code == 200
    data = r_poll.json()
    assert data["ok"] is True
    assert data["active_case"] == "inv-vscode-live"
    assert data["count"] >= 1
    assert any(ev["type"] == "step" and ev["case_id"] == "inv-vscode-live" for ev in data["events"])


@pytest.mark.asyncio
async def test_active_non_intrusive_mode_enables_active_transforms_and_blocks_intrusive_scans(
    tmp_path: Path, catalog: TransformCatalog
) -> None:
    """En modo activo no intrusivo se habilitan todos los transforms activos de lectura y se bloquean escaneos."""
    from maltego_mcp.egress import EgressPolicy
    from maltego_mcp.service import CHAIN_CONCURRENCY

    assert CHAIN_CONCURRENCY <= 3, "La concurrencia debe estar acotada para evitar peticiones masivas."

    policy = EgressPolicy(allow_active=True)
    # 1. Lecturas GET en VirusTotal permitidas en modo activo
    ok_vt, _ = policy.validate_request("GET", "https://www.virustotal.com/api/v3/domains/example.com")
    assert ok_vt is True

    # 2. Peticiones intrusivas (POST / analyse en VT, escaneos en Shodan/urlscan/Censys) siguen bloqueadas
    ok_vt_post, _ = policy.validate_request("POST", "https://www.virustotal.com/api/v3/files")
    assert ok_vt_post is False
    ok_vt_analyse, _ = policy.validate_request("GET", "https://www.virustotal.com/api/v3/urls/123/analyse")
    assert ok_vt_analyse is False
    ok_shodan_scan, _ = policy.validate_request("POST", "https://api.shodan.io/shodan/scan")
    assert ok_shodan_scan is False

    # 3. Una petición en lenguaje natural sobre una empresa con modo activo ejecuta CompanyFootprint sin errores
    settings = Settings(data_file=tmp_path / "g_act.json", home=tmp_path, mode="active")
    svc = OsintService(
        MemoryGraphStore(settings.data_file),
        catalog.with_builtins(),
        tmp_path / "exports",
        tmp_path / "imports",
        settings=settings,
    )
    svc.env = {"MALTEGO_MCP_ALLOW_ACTIVE": "1", "MALTEGO_MCP_MODE": "active", "VIRUSTOTAL_API_KEY": "vt_key_test"}
    svc._http = new_http_client(transport=httpx.MockTransport(Router()), allow_active=True)

    async with Client(create_server(service=svc)) as client:
        res_comp = await client.call_tool(
            "osint_investigate",
            {
                "value": "Investiga la empresa Acme Defense Corp y genera un informe",
                "case_id": "caso-empresa-activa",
                "response_format": "json",
            },
        )
        assert not res_comp.is_error
        block = res_comp.content[0]
        assert isinstance(block, TextContent)
        comp_data = json.loads(block.text)
        assert comp_data["maltego_type"] == "maltego.Company"
        assert comp_data["strategy"] == "CompanyFootprint"
