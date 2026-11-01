"""La versión es la misma en todos los artefactos publicables."""

import json
import tomllib
from pathlib import Path

from maltego_mcp import __version__

ROOT = Path(__file__).resolve().parents[1]


def test_version_unica() -> None:
    pkg = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    server = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    py = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    assert pkg["version"] == py == __version__ == server["version"] == server["packages"][0]["version"]
    assert f"## [{__version__}]" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


def test_paquete_npm_incluye_lo_necesario() -> None:
    pkg = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    for needed in ("bin/", "src/maltego_mcp/", "pyproject.toml", "uv.lock"):
        assert needed in pkg["files"], needed
    assert pkg["bin"]["mcp-maltego"] == "bin/mcp-maltego.js"
    assert (ROOT / pkg["bin"]["mcp-maltego"]).read_text(encoding="utf-8").startswith("#!/usr/bin/env node")
