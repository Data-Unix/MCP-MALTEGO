"""Los ficheros de proyecto que leen los agentes deben apuntar al mismo servidor y ser válidos."""

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _json(rel: str) -> dict:  # type: ignore[type-arg]
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def test_todos_los_agentes_registran_maltego() -> None:
    for rel in (".mcp.json", ".gemini/settings.json", ".qwen/settings.json", ".cursor/mcp.json"):
        server = _json(rel)["mcpServers"]["maltego"]
        assert server["command"] == "uv", rel
        assert server["args"][0] == "run" and server["args"][-1] == "maltego-mcp", rel
    oc = _json("opencode.json")["mcp"]["maltego"]
    assert oc["type"] == "local" and oc["command"][-1] == "maltego-mcp"
    codex = tomllib.loads((ROOT / ".codex/config.toml").read_text(encoding="utf-8"))
    assert codex["mcp_servers"]["maltego"]["args"][-1] == "maltego-mcp"


def test_el_script_existe_en_pyproject() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "maltego-mcp" in project["project"]["scripts"]
