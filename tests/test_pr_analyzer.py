"""Tests exhaustivos para el evaluador estático de PRs y análisis de seguridad AST."""

from __future__ import annotations

from pathlib import Path

from scripts.analyze_pr import (
    AnalysisReport,
    classify_blast_radius,
    format_markdown_report,
    scan_file_security,
)


def test_ast_scanner_detects_eval_and_exec(tmp_path: Path) -> None:
    bad_file = tmp_path / "bad.py"
    bad_file.write_text("x = eval('2 + 2')\nexec('import os')", encoding="utf-8")

    findings = scan_file_security(bad_file, "bad.py")
    severities = [f.severity for f in findings]
    messages = " ".join(f.message for f in findings)

    assert "CRITICA" in severities
    assert "eval()" in messages
    assert "exec()" in messages


def test_ast_scanner_detects_shell_injection(tmp_path: Path) -> None:
    bad_file = tmp_path / "shell_bad.py"
    bad_file.write_text(
        "import os\nimport subprocess\nos.system('dir')\nsubprocess.run('cmd', shell=True)", encoding="utf-8"
    )

    findings = scan_file_security(bad_file, "shell_bad.py")
    messages = " ".join(f.message for f in findings)

    assert "os.system()" in messages
    assert "shell=True" in messages


def test_ast_scanner_passes_safe_code(tmp_path: Path) -> None:
    safe_file = tmp_path / "safe.py"
    safe_file.write_text(
        "def calculate_stats(a: int, b: int) -> int:\n    return a + b\n",
        encoding="utf-8",
    )

    findings = scan_file_security(safe_file, "safe.py")
    assert findings == []


def test_classify_blast_radius() -> None:
    files = [
        "src/maltego_mcp/tools.py",
        "src/maltego_mcp/transforms/builtin.py",
        "src/maltego_mcp/web/dashboard.js",
        "docs/USO.md",
    ]
    layers = classify_blast_radius(files)
    assert "core" in layers
    assert "transforms" in layers
    assert "web" in layers
    assert "docs" in layers


def test_report_formatting_and_risk() -> None:
    report = AnalysisReport(base_ref="main", changed_files=["src/maltego_mcp/tools.py"])
    report.mcp_tools_count = 20
    report.tools_rule_violated = False
    report.calculate_overall_risk()

    md = format_markdown_report(report)
    assert "MCP Maltego Governance" in md
    assert "@Data-Unix" in md
    assert "20 / 20" in md

