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
