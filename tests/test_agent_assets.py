"""Agentes y skills: fuente única en .agents/ y copias por herramienta sincronizadas y con formato válido."""

import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENTS = sorted(p.stem for p in (ROOT / ".agents" / "agents").glob("*.md"))
SKILLS = sorted(p.name for p in (ROOT / ".agents" / "skills").iterdir() if p.is_dir())


def _front(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---\n"), path
    head = text[4:].split("\n---\n", 1)[0]
    return {k.strip(): v.strip() for k, _, v in (line.partition(":") for line in head.splitlines()) if k.strip()}


def test_copias_sincronizadas() -> None:
    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "sync_agents.py"), "--check"], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stderr


def test_formatos_por_herramienta() -> None:
    assert len(AGENTS) >= 5 and len(SKILLS) >= 5
    for name in AGENTS:
        for path in (
            ROOT / ".claude/agents" / f"{name}.md",
            ROOT / ".gemini/agents" / f"{name}.md",
            ROOT / ".qwen/agents" / f"{name}.md",
            ROOT / ".github/agents" / f"{name}.agent.md",
        ):
            meta = _front(path)
            assert meta["name"] == name and meta["description"].strip('"'), path
        codex = tomllib.loads((ROOT / ".codex/agents" / f"{name}.toml").read_text(encoding="utf-8"))
        assert codex["name"] == name and codex["description"] and codex["developer_instructions"].strip()
    for name in SKILLS:
        for base in (".agents/skills", ".claude/skills"):
            meta = _front(ROOT / base / name / "SKILL.md")
            assert meta["name"] == name and 0 < len(meta["description"]) <= 1024


def test_no_quedan_agentes_genericos_iniciales() -> None:
    for old in ("azure-infra-engineer", "cloud-architect", "data-engineer", "python-pro", "threat-modeling-expert"):
        assert not (ROOT / ".claude/agents" / f"{old}.md").exists()
    for old in ("mcp-builder", "async-python-patterns", "python-resilience", "python-testing-patterns"):
        assert not (ROOT / ".claude/skills" / old).exists()


def test_analista_osint_sin_shell_ni_edicion() -> None:
    claude = _front(ROOT / ".claude/agents/osint-analyst.md")["tools"]
    assert "Bash" not in claude and "Edit" not in claude and "mcp__maltego__osint_investigate" in claude
    copilot = _front(ROOT / ".github/agents/osint-analyst.agent.md")["tools"]
    assert "execute" not in copilot and "maltego/*" in copilot
    gemini = _front(ROOT / ".gemini/agents/osint-analyst.md")["tools"]
    assert "run_shell_command" not in gemini and "read_file" in gemini and "mcp_*" in gemini


def test_no_escribe_a_traves_de_enlaces(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import importlib.util

    spec = importlib.util.spec_from_file_location("sync_agents", ROOT / "scripts" / "sync_agents.py")
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    monkeypatch.setitem(sys.modules, "sync_agents", mod)  # necesario para sus dataclasses
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    outside = tmp_path / "fuera.md"
    outside.write_text("no tocar", encoding="utf-8")
    link = ROOT / ".claude" / "agents" / "zz-enlace.md"
    import pytest

    try:
        link.symlink_to(outside)
    except OSError as exc:  # Windows sin modo desarrollador ni privilegio SeCreateSymbolicLink
        pytest.skip(f"el sistema no permite crear enlaces simbólicos: {exc}")
    try:
        with pytest.raises(SystemExit, match="fuera"):
            mod.main([])
        assert outside.read_text(encoding="utf-8") == "no tocar"
    finally:
        link.unlink()


def test_skills_y_agentes_solo_citan_elementos_reales() -> None:
    import re

    from maltego_mcp.machines import BUILTIN_MACHINES
    from maltego_mcp.transforms.builtin import BUILTIN_TRANSFORMS

    sys.path.insert(0, str(ROOT / "tests"))
    from test_copilot import EXPECTED_TOOLS

    machines = {m.name for m in BUILTIN_MACHINES}
    transforms = {b.name for b in BUILTIN_TRANSFORMS}
    texts = [p.read_text(encoding="utf-8") for p in (ROOT / ".agents").rglob("*.md")]
    for text in texts:
        for tool in re.findall(r"\bosint_[a-z_]+", text):
            assert tool in EXPECTED_TOOLS, tool
        for m in re.findall(r'machine="([A-Za-z]+)"', text):
            assert m in machines, m
        for name in re.findall(r"`([A-Z][A-Za-z0-9]+(?:To|Context|Subdomains|Services)[A-Za-z0-9]*)`", text):
            assert name in transforms, name
    for m in ("CompanyFootprint", "PersonalFootprint", "EmailRecon", "DomainRecon", "InfrastructureRecon"):
        assert any(m in t for t in texts), m
