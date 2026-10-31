import io
import zipfile

import pytest

from maltego_mcp.domain.records import EdgeRecord, EntityRecord
from maltego_mcp.errors import InvalidInput
from maltego_mcp.maltego.mtgx import GRAPH_MEMBER, main_property_for, read_mtgx, write_mtgx


def ent(i: str, t: str, v: str, label: str = "x", **props: str) -> EntityRecord:
    return EntityRecord(i, "c", label, t, v, 0.8, ["s"], dict(props))


def test_ida_y_vuelta_conserva_tipos_valores_propiedades_y_enlaces() -> None:
    ents = [
        ent("a", "maltego.Domain", "example.com", registrar="ACME <&>"),
        ent("b", "maltego.IPv4Address", "1.2.3.4"),
        ent("c", "acme.Ticket", "TCK-1", label="custom"),
    ]
    edges = [EdgeRecord("e1", "c", "resolves_to", "a", "b"), EdgeRecord("e2", "c", "ref", "c", "a")]
    data = write_mtgx(ents, edges)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        assert GRAPH_MEMBER in zf.namelist()
        xml = zf.read(GRAPH_MEMBER).decode()
    assert 'xmlns:mtg="http://maltego.paterva.com/xml/mtgx"' in xml
    assert '<mtg:MaltegoEntity type="maltego.Domain">' in xml
    assert 'xmlns="http://graphml.graphdrawing.org/xmlns"' in xml
    assert 'name="fqdn"' in xml and "maltego.link.manual.type" in xml
    g = read_mtgx(data)
    got = {(e.maltego_type, e.value): e.properties for e in g.entities}
    assert got[("maltego.Domain", "example.com")] == {"registrar": "ACME <&>"}
    assert ("acme.Ticket", "TCK-1") in got
    assert sorted((x.source, x.target, x.label) for x in g.links) == [("a", "b", "resolves_to"), ("c", "a", "ref")]
    assert {e.confidence for e in g.entities} == {0.8}


def test_lee_exportacion_con_estructura_de_maltego() -> None:
    """Estructura documentada de una exportación real de Maltego (enlace de transform, sin etiqueta manual)."""
    xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns" xmlns:mtg="http://maltego.paterva.com/xml/mtgx">
 <key id="d4" for="node" attr.name="MaltegoEntity"/><key id="d6" for="edge" attr.name="MaltegoLink"/>
 <graph edgedefault="directed" id="G">
  <node id="n0"><data key="d4"><mtg:MaltegoEntity type="maltego.Domain"><mtg:Properties>
   <mtg:Property name="fqdn" displayName="Domain Name" type="string"><mtg:Value>paterva.com</mtg:Value></mtg:Property>
   <mtg:Property name="whois-info" displayName="WHOIS Info" type="string"><mtg:Value>x</mtg:Value></mtg:Property>
  </mtg:Properties></mtg:MaltegoEntity></data></node>
  <node id="n1"><data key="d4"><mtg:MaltegoEntity type="maltego.Website"><mtg:Properties>
   <mtg:Property name="fqdn" displayName="Website" type="string"><mtg:Value>www.paterva.com</mtg:Value></mtg:Property>
  </mtg:Properties></mtg:MaltegoEntity></data></node>
  <node id="n2"><data key="d4"><mtg:MaltegoEntity type="maltego.Phrase"><mtg:Properties/>
  </mtg:MaltegoEntity></data></node>
  <edge id="e0" source="n0" target="n1"><data key="d6"><mtg:MaltegoLink type="maltego.link.transform-link">
   <mtg:Properties><mtg:Property name="maltego.link.transform.display-name" type="string">
   <mtg:Value>To Website</mtg:Value></mtg:Property></mtg:Properties></mtg:MaltegoLink></data></edge>
 </graph></graphml>"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(GRAPH_MEMBER, xml)
    g = read_mtgx(buf.getvalue())
    assert [(e.maltego_type, e.value) for e in g.entities] == [
        ("maltego.Domain", "paterva.com"),
        ("maltego.Website", "www.paterva.com"),
    ]
    assert g.entities[0].properties == {"whois-info": "x"}
    assert [(x.source, x.target, x.label) for x in g.links] == [("n0", "n1", "To Website")]
    assert g.skipped == 1


@pytest.mark.parametrize(
    "payload",
    [
        b"no zip",
        b"PK\x05\x06" + b"\x00" * 18,  # ZIP vacío
    ],
)
def test_ficheros_invalidos(payload: bytes) -> None:
    with pytest.raises(InvalidInput):
        read_mtgx(payload)


def test_xml_malicioso_se_rechaza() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(GRAPH_MEMBER, b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><graphml>&e;</graphml>')
    with pytest.raises(InvalidInput, match="inseguro"):
        read_mtgx(buf.getvalue())


def test_propiedad_principal() -> None:
    assert main_property_for("maltego.EmailAddress") == "email"
    assert main_property_for("acme.Ticket") == "properties.ticket"


def test_url_incluye_propiedad_visible_de_maltego() -> None:
    data = write_mtgx([ent("u", "maltego.URL", "https://example.com/a")], [])
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        xml = zf.read(GRAPH_MEMBER).decode()
    assert 'name="url"' in xml and 'name="short-title"' in xml
    assert read_mtgx(data).entities[0].value == "https://example.com/a"


def test_no_altera_el_espacio_de_nombres_global() -> None:
    from xml.etree.ElementTree import Element, SubElement, tostring

    write_mtgx([ent("a", "maltego.Domain", "a.com")], [])
    root = Element("{http://graphml.graphdrawing.org/xmlns}graphml")
    SubElement(root, "plain")
    tostring(root)  # fallaría con ValueError si se hubiera registrado "" como prefijo global
