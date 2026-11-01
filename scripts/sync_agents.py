"""Sincroniza agentes y skills desde la fuente única `.agents/` al formato de cada herramienta.

Fuente única (edita solo aquí):
  .agents/agents/<nombre>.md          frontmatter: name, description, tools (read, search, edit, shell, mcp)
  .agents/skills/<nombre>/SKILL.md    estándar agentskills.io (lo leen Codex, Gemini, Copilot y Cursor tal cual)

Destinos generados (no editar a mano):
  .claude/agents/<n>.md               Claude Code (subagentes)
  .claude/skills/<n>/                 Claude Code (skills; no lee .agents/skills)
  .gemini/agents/<n>.md               Gemini CLI (subagentes)
  .qwen/agents/<n>.md                 Qwen Code (subagentes; formato tipo Gemini, sin verificar en docs oficiales)
  .github/agents/<n>.agent.md         GitHub Copilot (agentes personalizados)
  .codex/agents/<n>.toml              Codex (subagentes)

Uso:  uv run python scripts/sync_agents.py          # regenera
      uv run python scripts/sync_agents.py --check  # falla si algo está desincronizado (CI)
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC_AGENTS = ROOT / ".agents" / "agents"
SRC_SKILLS = ROOT / ".agents" / "skills"
MARKER = "GENERADO por scripts/sync_agents.py desde .agents/ — no editar a mano"
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

CLAUDE_TOOLS = {"read": ["Read"], "search": ["Grep", "Glob"], "edit": ["Edit", "Write"], "shell": ["Bash"]}
COPILOT_TOOLS = {"read": ["read"], "search": ["search"], "edit": ["edit"], "shell": ["execute"]}


@dataclass(frozen=True)
class Agent:
    name: str
    description: str
    tools: tuple[str, ...]
    body: str


def parse_frontmatter(text: str, source: Path) -> tuple[dict[str, str], str]:
    if not text.startswith("---\n"):
        raise SystemExit(f"{source}: el frontmatter debe empezar en la línea 1 con ---")
    head, sep, body = text[4:].partition("\n---\n")
    if not sep:
        raise SystemExit(f"{source}: frontmatter sin cierre ---")
    meta: dict[str, str] = {}
    for line in head.splitlines():
        key, _, value = line.partition(":")
        if key.strip():
            meta[key.strip()] = value.strip()
    return meta, body.strip() + "\n"


def load_agents() -> list[Agent]:
    agents = []
    for path in sorted(SRC_AGENTS.glob("*.md")):
        meta, body = parse_frontmatter(path.read_text(encoding="utf-8"), path)
        name = meta.get("name", "")
        if name != path.stem or not NAME_RE.match(name):
            raise SystemExit(f"{path}: name debe coincidir con el fichero y ser minúsculas-con-guiones")
        if not meta.get("description"):
            raise SystemExit(f"{path}: falta description")
        tools = tuple(t.strip() for t in meta.get("tools", "").split(",") if t.strip())
        unknown = set(tools) - {"read", "search", "edit", "shell", "mcp"}
        if unknown:
            raise SystemExit(f"{path}: tools desconocidas {sorted(unknown)}")
        agents.append(Agent(name, meta["description"], tools, body))
    return agents


def check_skills() -> list[Path]:
    skills = []
    for d in sorted(p for p in SRC_SKILLS.iterdir() if p.is_dir()):
        meta, _ = parse_frontmatter((d / "SKILL.md").read_text(encoding="utf-8"), d / "SKILL.md")
        if meta.get("name") != d.name or not NAME_RE.match(d.name) or len(d.name) > 64:
            raise SystemExit(f"{d}: name debe coincidir con la carpeta (agentskills.io)")
        if not 0 < len(meta.get("description", "")) <= 1024:
            raise SystemExit(f"{d}: description obligatoria (1-1024 caracteres)")
        skills.append(d)
    return skills


def _yaml_str(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _md(front: list[str], body: str) -> str:
    return "---\n" + "\n".join(front) + "\n---\n" + f"<!-- {MARKER} -->\n\n" + body


def render(agents: list[Agent]) -> dict[Path, str]:
    out: dict[Path, str] = {}
    for a in agents:
        desc = _yaml_str(a.description)
        # Claude Code: sin `tools` hereda todas (incluidas las MCP), necesario para el analista.
        claude = [f"name: {a.name}", f"description: {desc}"]
        if "mcp" not in a.tools:
            claude.append("tools: " + ", ".join(t for k in a.tools for t in CLAUDE_TOOLS[k]))
        claude.append("model: inherit")
        out[ROOT / ".claude" / "agents" / f"{a.name}.md"] = _md(claude, a.body)
        out[ROOT / ".gemini" / "agents" / f"{a.name}.md"] = _md(
            [f"name: {a.name}", f"description: {desc}", "kind: local"], a.body
        )
        out[ROOT / ".qwen" / "agents" / f"{a.name}.md"] = _md([f"name: {a.name}", f"description: {desc}"], a.body)
        copilot = [f"name: {a.name}", f"description: {desc}"]
        if "mcp" not in a.tools:
            names = [t for k in a.tools for t in COPILOT_TOOLS[k]]
            copilot.append("tools: [" + ", ".join(_yaml_str(n) for n in names) + "]")
        out[ROOT / ".github" / "agents" / f"{a.name}.agent.md"] = _md(copilot, a.body)
        instructions = a.body.replace("'''", "' ' '")
        out[ROOT / ".codex" / "agents" / f"{a.name}.toml"] = (
            f"# {MARKER}\n"
            f"name = {_yaml_str(a.name)}\n"
            f"description = {_yaml_str(a.description)}\n"
            f"developer_instructions = '''\n{instructions}'''\n"
        )
    return out


def skill_files(skills: list[Path]) -> dict[Path, bytes]:
    out: dict[Path, bytes] = {}
    for d in skills:
        for f in sorted(p for p in d.rglob("*") if p.is_file()):
            out[ROOT / ".claude" / "skills" / d.name / f.relative_to(d)] = f.read_bytes()
    return out


def generated_dirs() -> list[Path]:
    return [
        ROOT / ".claude" / "agents",
        ROOT / ".gemini" / "agents",
        ROOT / ".qwen" / "agents",
        ROOT / ".github" / "agents",
        ROOT / ".codex" / "agents",
        ROOT / ".claude" / "skills",
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="Solo comprobar (para CI)")
    ns = parser.parse_args(argv)
    texts = render(load_agents())
    blobs = skill_files(check_skills())
    expected: dict[Path, bytes] = {**{p: t.encode("utf-8") for p, t in texts.items()}, **blobs}
    existing = {p for d in generated_dirs() if d.exists() for p in d.rglob("*") if p.is_file()}
    stale = sorted(existing - set(expected))
    changed = sorted(p for p, data in expected.items() if not p.exists() or p.read_bytes() != data)
    if ns.check:
        for p in changed + stale:
            print(f"desincronizado: {p.relative_to(ROOT)}", file=sys.stderr)
        if changed or stale:
            print("Ejecuta: uv run python scripts/sync_agents.py", file=sys.stderr)
            return 1
        print(f"OK: {len(texts)} ficheros de agentes y {len(blobs)} de skills sincronizados")
        return 0
    for p in stale:
        p.unlink()
    for d in generated_dirs():
        for sub in sorted((x for x in d.rglob("*") if x.is_dir()), reverse=True) if d.exists() else []:
            if not any(sub.iterdir()):
                sub.rmdir()
    for p, data in expected.items():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    print(f"Generados {len(texts)} ficheros de agentes y {len(blobs)} de skills; eliminados {len(stale)} obsoletos")
    return 0


if __name__ == "__main__":
    sys.exit(main())
