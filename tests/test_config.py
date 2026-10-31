from pathlib import Path

import pytest

from maltego_mcp.config import Settings
from maltego_mcp.errors import ConfigError
from maltego_mcp.server import build_store, main


def test_valores_por_defecto() -> None:
    s = Settings.from_env({})
    assert s.backend == "memory"
    assert s.data_file == Path("data/graph.json")


def test_sin_persistencia() -> None:
    assert Settings.from_env({"MALTEGO_MCP_DATA_FILE": "none"}).data_file is None


def test_backend_invalido() -> None:
    with pytest.raises(ConfigError, match="memory"):
        Settings.from_env({"MALTEGO_MCP_BACKEND": "neo4j"})


def test_gremlin_requiere_credenciales() -> None:
    with pytest.raises(ConfigError, match="GREMLIN_ENDPOINT"):
        Settings.from_env({"MALTEGO_MCP_BACKEND": "gremlin", "GREMLIN_ENDPOINT": "wss://x"})
    s = Settings.from_env(
        {
            "MALTEGO_MCP_BACKEND": "gremlin",
            "GREMLIN_ENDPOINT": "wss://x:443/",
            "GREMLIN_USERNAME": "/dbs/d/colls/g",
            "GREMLIN_PASSWORD": "k",
        }
    )
    store = build_store(s)  # no conecta hasta la primera consulta
    assert type(store).__name__ == "GremlinGraphStore"


def test_main_sale_con_error_de_configuracion(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MALTEGO_MCP_BACKEND", "bogus")
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2
    assert "error de configuración" in capsys.readouterr().err
