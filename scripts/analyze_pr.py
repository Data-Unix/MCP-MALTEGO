"""Script de evaluación de seguridad, análisis de impacto (blast radius) y gobernanza de PRs.

Diseñado para ejecutarse de forma no privilegiada en GitHub Actions (evento `pull_request`)
o localmente antes de proponer cambios al repositorio MCP Maltego.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Capas arquitectónicas y sus pesos de riesgo base
LAYERS_CONFIG = {
    "core": {
        "paths": [
            "src/maltego_mcp/tools.py",
            "src/maltego_mcp/server.py",
            "src/maltego_mcp/compat.py",
            "src/maltego_mcp/service.py",
            "src/maltego_mcp/transforms/protocol.py",
        ],
        "risk": "ALTO",
        "desc": "Núcleo del protocolo MCP, registro de herramientas y contratos",
    },
    "graph": {
        "paths": ["src/maltego_mcp/graph/", "src/maltego_mcp/domain/"],
        "risk": "MEDIO",
        "desc": "Almacenamiento de grafos (memoria / Gremlin) y entidades deterministas",
    },
    "transforms": {
        "paths": ["src/maltego_mcp/transforms/"],
        "risk": "MEDIO",
        "desc": "Catálogo y ejecución de transformadas OSINT integradas / TRX",
    },
    "web": {
        "paths": ["src/maltego_mcp/web/", "src/maltego_mcp/web_app.py"],
        "risk": "MEDIO",
        "desc": "Web Dashboard interactivo, visualizador Canvas y endpoints REST",
    },
    "agents": {
        "paths": [".agents/", ".claude/", ".gemini/", ".github/agents/", ".codex/", ".qwen/"],
        "risk": "MEDIO",
        "desc": "Definición y sincronización de subagentes y skills OSINT",
    },
    "ci": {
        "paths": [".github/workflows/", ".github/CODEOWNERS", "dependabot.yml"],
        "risk": "ALTO",
        "desc": "Automatizaciones de CI/CD, seguridad y gobernanza de rama",
    },
    "deps": {
        "paths": ["pyproject.toml", "package.json", "uv.lock"],
        "risk": "MEDIO",
        "desc": "Dependencias externas y configuración de empaquetado",
    },
    "docs": {
        "paths": ["docs/", "README.md", "README.es.md", "PLAN.md", "AGENTS.md", "CONTRIBUTING.md", "SECURITY.md"],
        "risk": "BAJO",
        "desc": "Documentación y guías del proyecto",
    },
}

DANGEROUS_FUNCTIONS = {"eval", "exec", "compile", "__import__"}
DANGEROUS_OS_CALLS = {"system", "popen", "spawn", "spawnl", "spawnv", "execl", "execv"}


@dataclass
class SecurityFinding:
    severity: str  # CRITICA, ALTA, MEDIA, BAJA
    file: str
    line: int
    message: str


@dataclass
class AnalysisReport:
    base_ref: str
    changed_files: list[str] = field(default_factory=list)
    affected_layers: dict[str, list[str]] = field(default_factory=dict)
    security_findings: list[SecurityFinding] = field(default_factory=list)
    mcp_tools_count: int | None = None
    tools_rule_violated: bool = False
    new_dependencies: list[str] = field(default_factory=list)
    overall_risk: str = "BAJO"
    recommendation: str = ""

    def calculate_overall_risk(self) -> None:
        if self.tools_rule_violated or any(f.severity == "CRITICA" for f in self.security_findings):
            self.overall_risk = "CRITICO"
            self.recommendation = "⛔ RECHAZAR O BLOQUEAR MERGE: Violación crítica de seguridad o contrato MCP"
        elif (
            any(f.severity == "ALTA" for f in self.security_findings)
            or "core" in self.affected_layers
            or "ci" in self.affected_layers
        ):
            self.overall_risk = "ALTO"
            self.recommendation = "⚠️ REVISIÓN PROFUNDA OBLIGATORIA: Cambios en el núcleo o infraestructura de CI"
        elif any(f.severity == "MEDIA" for f in self.security_findings) or len(self.affected_layers) > 2:
            self.overall_risk = "MEDIO"
            self.recommendation = "🔍 REVISIÓN ESTÁNDAR: Requiere validación de tests y aprobación manual de @Data-Unix"
        else:
            self.overall_risk = "BAJO"
            self.recommendation = "✅ LISTO PARA REVISIÓN: Cambios de bajo impacto, apto para aprobación de @Data-Unix"


class ASTSecurityScanner(ast.NodeVisitor):
    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.findings: list[SecurityFinding] = []

    def visit_Call(self, node: ast.Call) -> None:
        # 1. Detección de funciones globales peligrosas: eval, exec, compile, __import__
        if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_FUNCTIONS:
            self.findings.append(
                SecurityFinding(
                    severity="CRITICA",
                    file=self.filepath,
                    line=node.lineno,
                    message=f"Uso prohibido de la primitiva insegura '{node.func.id}()'",
                )
            )

        # 2. Detección de os.system, os.popen, os.spawn*
        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "os" and node.func.attr in DANGEROUS_OS_CALLS:
                self.findings.append(
                    SecurityFinding(
                        severity="CRITICA",
                        file=self.filepath,
                        line=node.lineno,
                        message=f"Ejecución de shell insegura mediante 'os.{node.func.attr}()'",
                    )
                )
            elif node.func.value.id in {"subprocess", "asyncio"}:
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.findings.append(
                            SecurityFinding(
                                severity="CRITICA",
                                file=self.filepath,
                                line=node.lineno,
                                message="Invocación de subproceso con 'shell=True' (riesgo de inyección de comandos)",
                            )
                        )

        # 3. Detección de reflexiones dunder sospechosas (__subclasses__, __globals__)
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"__subclasses__", "__globals__"}:
            self.findings.append(
                SecurityFinding(
                    severity="ALTA",
                    file=self.filepath,
                    line=node.lineno,
                    message=f"Acceso por reflexión dunder potencialmente malicioso '{node.func.attr}'",
                )
            )

        self.generic_visit(node)


def scan_file_security(path: Path, rel_path: str) -> list[SecurityFinding]:
    """Escanea un fichero Python utilizando AST en busca de patrones inseguros."""
    if not path.is_file() or not path.name.endswith(".py"):
        return []

    try:
        content = path.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(path))
        scanner = ASTSecurityScanner(rel_path)
        scanner.visit(tree)
        return scanner.findings
    except SyntaxError as exc:
        return [
            SecurityFinding(
                severity="ALTA",
                file=rel_path,
                line=exc.lineno or 1,
                message=f"Error de sintaxis de Python en el fichero modificado: {exc.msg}",
            )
        ]
    except Exception as exc:
        return [
            SecurityFinding(
                severity="MEDIA",
                file=rel_path,
                line=1,
                message=f"No se pudo parsear el archivo para análisis de seguridad: {exc}",
            )
        ]


def count_mcp_tools(tools_file: Path) -> int | None:
    """Cuenta el número exacto de herramientas registradas en tools.py."""
    if not tools_file.is_file():
        return None
    try:
        content = tools_file.read_text(encoding="utf-8")
        matches = re.findall(r"@(mcp|server)\.tool\(", content)
        return len(matches)
    except Exception:
        return None


def get_git_changed_files(base_ref: str) -> list[str]:
    """Obtiene la lista de ficheros modificados respecto a la rama base."""
    # 1. Intento contra el merge-base de git
    for ref_spec in [f"{base_ref}...HEAD", base_ref, "HEAD~1"]:
        try:
            r = subprocess.run(
                ["git", "diff", "--name-only", ref_spec],
                capture_output=True,
                text=True,
                check=False,
                cwd=ROOT,
            )
            if r.returncode == 0:
                files = [line.strip().replace("\\", "/") for line in r.stdout.splitlines() if line.strip()]
                if files:
                    return files
        except Exception:
            pass

    # 2. Respaldo por estado del árbol de trabajo (git status)
    try:
        r = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=False,
            cwd=ROOT,
        )
        if r.returncode == 0:
            files = []
            for line in r.stdout.splitlines():
                parts = line.strip().split(maxsplit=1)
                if len(parts) == 2:
                    files.append(parts[1].replace("\\", "/"))
            return files
    except Exception:
        pass

    return []


def classify_blast_radius(files: list[str]) -> dict[str, list[str]]:
    """Clasifica los ficheros en capas de arquitectura de Maltego MCP."""
    affected: dict[str, list[str]] = {}
    for f in files:
        matched = False
        for layer, conf in LAYERS_CONFIG.items():
            for p in conf["paths"]:
                if f.startswith(p) or f == p:
                    affected.setdefault(layer, []).append(f)
                    matched = True
                    break
        if not matched:
            affected.setdefault("otros", []).append(f)
    return affected


def analyze_pr(base_ref: str = "main", explicit_files: list[str] | None = None) -> AnalysisReport:
    """Ejecuta el análisis completo de la PR."""
    changed_files = explicit_files if explicit_files is not None else get_git_changed_files(base_ref)
    report = AnalysisReport(base_ref=base_ref, changed_files=changed_files)

    # 1. Blast Radius por capas
    report.affected_layers = classify_blast_radius(changed_files)

    # 2. Escaneo AST de seguridad sobre ficheros Python
    for f in changed_files:
        p = ROOT / f
        if p.exists() and f.endswith(".py"):
            findings = scan_file_security(p, f)
            report.security_findings.extend(findings)

    # 3. Verificación de regla de 20 tools MCP
    tools_file = ROOT / "src/maltego_mcp/tools.py"
    if "src/maltego_mcp/tools.py" in changed_files or tools_file.exists():
        count = count_mcp_tools(tools_file)
        report.mcp_tools_count = count
        if count is not None and count != 20:
            report.tools_rule_violated = True
            report.security_findings.append(
                SecurityFinding(
                    severity="CRITICA",
                    file="src/maltego_mcp/tools.py",
                    line=1,
                    message=f"Regla violada: existen {count} tools MCP (debe ser exactamente 20).",
                )
            )

    # 4. Cálculo final de riesgo y recomendación
    report.calculate_overall_risk()
    return report


def format_markdown_report(report: AnalysisReport) -> str:
    """Genera el informe ejecutivo en Markdown listo para comentar en GitHub PR."""
    md: list[str] = []
    icon = {"BAJO": "🟢", "MEDIO": "🟡", "ALTO": "🔴", "CRITICO": "⛔"}.get(report.overall_risk, "⚪")

    md.append(f"## {icon} Evaluación Automatizada de PR · MCP Maltego Governance")
    md.append("")
    md.append(f"> **Dictamen para @Data-Unix**: {report.recommendation}")
    md.append("")
    md.append("| Indicador | Estado | Detalle |")
    md.append("| :--- | :---: | :--- |")
    md.append(f"| **Nivel de Riesgo Global** | **`{report.overall_risk}`** | Basado en AST y capas afectadas |")
    md.append(f"| **Ficheros Modificados** | `{len(report.changed_files)}` | Rama base: `{report.base_ref}` |")

    tools_status = "✅ 20 / 20" if not report.tools_rule_violated else f"❌ {report.mcp_tools_count} (Límite violado)"
    md.append(f"| **Límite de Tools MCP** | `{tools_status}` | Contrato de portabilidad multi-LLM |")
    sec_count = len(report.security_findings)
    sec_status = "✅ Sin alertas críticas" if not report.security_findings else f"⚠️ {sec_count} hallazgos"
    md.append(f"| **Auditoría de Seguridad AST** | `{sec_status}` | Anti-eval, SSRF y shell injection |")
    md.append("")

    # Tabla de Blast Radius
    md.append("### 🗺️ Impacto Arquitectónico (Blast Radius)")
    if not report.affected_layers:
        md.append("_No se detectaron ficheros modificados en el análisis._")
    else:
        md.append("| Capa Afectada | Riesgo Base | Descripción | Ficheros |")
        md.append("| :--- | :---: | :--- | :--- |")
        for layer, flist in report.affected_layers.items():
            conf = LAYERS_CONFIG.get(layer, {"risk": "BAJO", "desc": "Otros archivos auxiliares"})
            f_display = ", ".join(f"`{Path(x).name}`" for x in flist[:3])
            if len(flist) > 3:
                f_display += f" _(+{len(flist) - 3} más)_"
            md.append(f"| **`{layer.upper()}`** | `{conf['risk']}` | {conf['desc']} | {f_display} |")
    md.append("")

    # Tabla de Hallazgos de Seguridad si existen
    if report.security_findings:
        md.append("### 🛡️ Hallazgos de Seguridad e Integridad")
        md.append("| Gravedad | Archivo | Línea | Mensaje |")
        md.append("| :---: | :--- | :---: | :--- |")
        for f in report.security_findings:
            sev_icon = {"CRITICA": "⛔", "ALTA": "🔴", "MEDIA": "🟡", "BAJA": "🔹"}.get(f.severity, "•")
            md.append(f"| {sev_icon} `{f.severity}` | `{f.file}` | `{f.line}` | {f.message} |")
        md.append("")

    md.append("---")
    md.append(
        "_Gobernanza MCP Maltego: Ningún cambio puede ser fusionado sin la aprobación expresa y manual "
        "del mantenedor principal (@Data-Unix)._"
    )
    return "\n".join(md)


def main() -> int:
    # Asegurar soporte UTF-8 en consolas Windows
    if hasattr(sys.stdout, "reconfigure"):
        with contextlib.suppress(Exception):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="Evalúa PRs para MCP Maltego (seguridad y blast radius).")
    parser.add_argument("--base", default="main", help="Rama base de comparación (por defecto: main)")
    parser.add_argument("--files", nargs="*", default=None, help="Lista explícita de ficheros a analizar")
    parser.add_argument("--output", help="Ruta donde escribir el informe en Markdown")
    parser.add_argument("--json", action="store_true", help="Salida en formato JSON plano")
    parser.add_argument(
        "--fail-on-critical", action="store_true", help="Devuelve código de salida 1 si el riesgo es CRÍTICO"
    )
    args = parser.parse_args()

    report = analyze_pr(base_ref=args.base, explicit_files=args.files)

    if args.json:
        data = {
            "base_ref": report.base_ref,
            "overall_risk": report.overall_risk,
            "recommendation": report.recommendation,
            "tools_count": report.mcp_tools_count,
            "tools_rule_violated": report.tools_rule_violated,
            "affected_layers": report.affected_layers,
            "security_findings": [
                {"severity": f.severity, "file": f.file, "line": f.line, "message": f.message}
                for f in report.security_findings
            ],
        }
        output_str = json.dumps(data, indent=2)
    else:
        output_str = format_markdown_report(report)

    if args.output:
        Path(args.output).write_text(output_str, encoding="utf-8")
        print(f"Informe escrito exitosamente en: {args.output}")
    else:
        print(output_str)

    if args.fail_on_critical and report.overall_risk == "CRITICO":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
