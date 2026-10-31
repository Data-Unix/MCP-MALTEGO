"""maltegoctl: inspección de .mtgx, ontología importada, consultas y exportación por terminal."""

import io
import json
import zipfile
from pathlib import Path

import pytest

from maltego_mcp.cli import inspect_mtgx, main, parse_entity_definitions
from maltego_mcp.domain.entity_types import load_imported_types, register_imported_types, resolve_entity_type
from maltego_mcp.domain.records import EdgeRecord, EntityRecord
from maltego_mcp.errors import InvalidInput
from maltego_mcp.maltego.mtgx import GRAPH_MEMBER, write_mtgx

ENTITY_XML = b"""<MaltegoEntity id="acme.Employee" displayName="Empleado" category="ACME" allowedRoot="true">
  <Properties value="employee.id" displayValue="employee.name">
    <Fields><Field name="employee.id" type="string" displayName="Id"/>
    <Field name="employee.name" type="string"/></Fields>
  </Properties>
</MaltegoEntity>"""
DOMAIN_XML = b"""<MaltegoEntity id="maltego.Domain" displayName="Domain"><Properties value="fqdn"><Fields>
<Field name="fqdn" type="string"/></Fields></Properties></MaltegoEntity>"""
NOVALUE_XML = b"""<MaltegoEntity id="acme.Badge"><Properties><Fields><Field name="badge.code" type="string"/>
</Fields></Properties></MaltegoEntity>"""


def mtz(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for k, v in files.items():
            zf.writestr(k, v)
    return buf.getvalue()


@pytest.fixture(autouse=True)
def _reset_ontology():  # type: ignore[no-untyped-def]
    yield
    register_imported_types([])


def test_importa_ontologia_de_maltego(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = mtz(
        {
            "Entities/acme.Employee.entity": ENTITY_XML,
            "Entities/maltego.Domain.entity": DOMAIN_XML,
            "Entities/acme.Badge.entity": NOVALUE_XML,
            "Entities/roto.entity": b"<no",
            "otro.txt": b"x",
        }
    )
    defs = parse_entity_definitions(data)
    assert {d["maltego_type"]: d["main_property"] for d in defs} == {
        "acme.Employee": "employee.id",
        "maltego.Domain": "fqdn",
        "acme.Badge": "badge.code",
    }
    (tmp_path / "cfg.mtz").write_bytes(data)
    monkeypatch.setenv("MALTEGO_MCP_HOME", str(tmp_path / "home"))
    assert main(["import-entities", str(tmp_path / "cfg.mtz")]) == 0
    assert load_imported_types(tmp_path / "home" / "entities.json") == 3
    emp = resolve_entity_type("acme.employee")
    assert (emp.main_property, emp.origin, emp.description) == ("employee.id", "importado", "Empleado")
    dom = resolve_entity_type("maltego.Domain")  # importado conserva normalizador y etiqueta estándar
    assert (dom.graph_label, dom.normalizer) == ("domain", "domain")


def test_ontologia_invalida(tmp_path: Path) -> None:
    with pytest.raises(InvalidInput, match="ZIP"):
        parse_entity_definitions(b"nada")
    with pytest.raises(InvalidInput, match="no contiene entidades"):
        parse_entity_definitions(mtz({"a.txt": b"x"}))
    (tmp_path / "bad.json").write_text("{", encoding="utf-8")
    assert load_imported_types(tmp_path / "bad.json") == 0
    assert load_imported_types(tmp_path / "noexiste.json") == 0


def test_inspect(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    ents = [
        EntityRecord("a", "c", "domain", "maltego.Domain", "a.com"),
        EntityRecord("b", "c", "custom", "acme.Raro", "x"),
    ]
    good = write_mtgx(ents, [EdgeRecord("e", "c", "rel", "a", "b")], sidecar={"steps": [{"seq": 1}]})
    rep = inspect_mtgx(good)
    assert rep["valid"] and rep["entities"] == 2 and rep["links"] == 1 and rep["memory_steps"] == 1
    assert rep["positions"] == 2 and any("acme.Raro" in w for w in rep["warnings"])
    assert inspect_mtgx(b"basura")["valid"] is False
    nopos = mtz(
        {
            GRAPH_MEMBER: b'<graphml xmlns="http://graphml.graphdrawing.org/xmlns" '
            b'xmlns:mtg="http://maltego.paterva.com/xml/mtgx"><graph><node id="n">'
            b'<data><mtg:MaltegoEntity type="maltego.Phrase"><mtg:Properties>'
            b'<mtg:Property name="text"><mtg:Value>hola</mtg:Value></mtg:Property>'
            b"</mtg:Properties></mtg:MaltegoEntity></data></node></graph></graphml>"
        }
    )
    assert any("sin posición" in w for w in inspect_mtgx(nopos)["warnings"])
    (tmp_path / "g.mtgx").write_bytes(good)
    assert main(["inspect", str(tmp_path / "g.mtgx")]) == 0
    assert "VÁLIDO" in capsys.readouterr().out
    assert main(["inspect", str(tmp_path / "g.mtgx"), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["entities"] == 2
    (tmp_path / "x.mtgx").write_bytes(b"no")
    assert main(["inspect", str(tmp_path / "x.mtgx")]) == 1
    assert main(["inspect", str(tmp_path / "noexiste.mtgx")]) == 2


def test_lookup_transforms_export_y_mtz(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MALTEGO_MCP_HOME", str(tmp_path))
    assert main(["lookup", "EmailToDomain", "Ana@Example.org"]) == 0
    assert "maltego.Domain  example.org" in capsys.readouterr().out
    assert main(["lookup", "Nope", "x"]) == 2
    assert main(["transforms", "--type", "maltego.EmailAddress"]) == 0
    out = capsys.readouterr().out
    assert "EmailToDomain" in out and "DNSToIP" not in out and "Machines:" in out
    assert main(["export", "inexistente"]) == 2
    repo = Path(__file__).resolve().parents[1]
    assert main(["mtz", "--repo", str(repo), "--output", str(tmp_path / "b.mtz"), "--uv", "uv"]) == 0
    assert zipfile.is_zipfile(tmp_path / "b.mtz")


def test_inspect_rechaza_zip_bomb() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(GRAPH_MEMBER, b"<graphml>" + b" " * (60 * 1024 * 1024) + b"</graphml>")
    rep = inspect_mtgx(buf.getvalue())
    assert rep["valid"] is False and "demasiado grande" in rep["errors"][0]


def test_logs_de_httpx_nunca_en_debug() -> None:
    import logging

    from maltego_mcp.server import configure_logging

    configure_logging("DEBUG")
    assert logging.getLogger("httpx").level == logging.WARNING
    configure_logging("INFO")
