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
        assert server["env"]["MALTEGO_MCP_ALLOW_ACTIVE"] == "1", rel
        assert server["env"]["MALTEGO_MCP_MODE"] == "active", rel
    vscode_srv = _json(".vscode/mcp.json")["servers"]["maltego"]
    assert vscode_srv["command"] == "uv" and vscode_srv["args"][-1] == "maltego-mcp"
    assert vscode_srv["env"]["MALTEGO_MCP_ALLOW_ACTIVE"] == "1"
    oc = _json("opencode.json")["mcp"]["maltego"]
    assert oc["type"] == "local" and oc["command"][-1] == "maltego-mcp"
    assert oc["environment"]["MALTEGO_MCP_ALLOW_ACTIVE"] == "1"
    codex = tomllib.loads((ROOT / ".codex/config.toml").read_text(encoding="utf-8"))
    assert codex["mcp_servers"]["maltego"]["args"][-1] == "maltego-mcp"
    assert codex["mcp_servers"]["maltego"]["env"]["MALTEGO_MCP_ALLOW_ACTIVE"] == "1"


def test_el_script_existe_en_pyproject() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "maltego-mcp" in project["project"]["scripts"]
