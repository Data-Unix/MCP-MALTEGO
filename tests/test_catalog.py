from pathlib import Path

import pytest

from maltego_mcp.errors import ConfigError, InvalidInput
from maltego_mcp.transforms.catalog import load_catalog

ROOT = Path(__file__).resolve().parents[1]


def write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "t.toml"
    p.write_text(text, encoding="utf-8")
    return p


def test_catalogo_de_ejemplo_es_valido() -> None:
    cat = load_catalog(ROOT / "config" / "transforms.example.toml")
    spec = cat.get("emailtodomain")  # búsqueda sin distinguir mayúsculas
    assert spec.name == "EmailToDomain"
    assert spec.path == "emailtodomain"  # convención maltego-trx
    assert spec.run_url == "http://127.0.0.1:8080/run/emailtodomain/"
    assert spec.accepts("maltego.EmailAddress") and not spec.accepts("maltego.Domain")


def test_sin_catalogo() -> None:
    assert load_catalog(None).transforms == {}


def test_transform_desconocido_lista_disponibles() -> None:
    cat = load_catalog(ROOT / "config" / "transforms.example.toml")
    with pytest.raises(InvalidInput, match="Disponibles: DomainToIP"):
        cat.get("nope")


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("[[servers]]\nname='a'\nurl='ftp://x'\n", "URL inválida"),
        ("[[servers]]\nname='a b'\nurl='http://x'\n", "nombre inválido"),
        ("[[transforms]]\nname='T'\nserver='nope'\n", "no está declarado"),
        (
            "[[servers]]\nname='a'\nurl='http://x'\n[[transforms]]\nname='T'\nserver='a'\npath='../x'\n",
            "path inválido",
        ),
        (
            "[[servers]]\nname='a'\nurl='http://x'\n[[transforms]]\nname='T'\nserver='a'\n"
            "[[transforms]]\nname='t'\nserver='a'\n",
            "duplicado",
        ),
        ("esto no es toml = = ", "TOML inválido"),
    ],
)
def test_catalogos_invalidos(tmp_path: Path, text: str, fragment: str) -> None:
    with pytest.raises(ConfigError, match=fragment):
        load_catalog(write(tmp_path, text))


def test_fichero_inexistente(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="No existe"):
        load_catalog(tmp_path / "nope.toml")


def test_api_key_por_variable_de_entorno(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cat = load_catalog(
        write(
            tmp_path,
            "[[servers]]\nname='a'\nurl='http://x'\napi_key_env='K'\n[[transforms]]\nname='T'\nserver='a'\n",
        )
    )
    with pytest.raises(ConfigError, match="K"):
        cat.get("T").server.headers()
    monkeypatch.setenv("K", "s3cr3t")
    assert cat.get("T").server.headers() == {"Authorization": "Bearer s3cr3t"}


def test_machines_propias_en_el_catalogo(tmp_path: Path) -> None:
    text = (
        (ROOT / "config" / "transforms.example.toml").read_text(encoding="utf-8")
        + """
[[machines]]
name = "MiRecon"
description = "DNS y luego AS"
input_types = ["maltego.Domain"]
stages = [["DNSToIP"], ["IPToAS"]]
rounds = 2
"""
    )
    cat = load_catalog(write(tmp_path, text))
    m = cat.machines.get("mirecon")
    assert (m.stages, m.default_rounds, m.origin) == ((("DNSToIP",), ("IPToAS",)), 2, "catálogo")
    assert m.accepts("maltego.Domain") and not m.accepts("maltego.URL")
    assert cat.machines.get("DomainRecon").origin == "predefinida"
    assert cat.machines.for_type("maltego.IPv4Address").name == "InfrastructureRecon"
    assert cat.machines.for_type("maltego.Phrase") is None
    with pytest.raises(InvalidInput, match="Disponibles"):
        cat.machines.get("nope")


@pytest.mark.parametrize(
    ("block", "fragment"),
    [
        ('[[machines]]\nname = "x y"\nstages = [["A"]]\n', "nombre inválido"),
        ('[[machines]]\nname = "Vacia"\nstages = []\n', "stages"),
    ],
)
def test_machines_invalidas(tmp_path: Path, block: str, fragment: str) -> None:
    with pytest.raises(ConfigError, match=fragment):
        load_catalog(write(tmp_path, block))
