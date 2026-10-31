"""Compatibilidad del protocolo con el SDK oficial maltego-trx (en ambos sentidos)."""

import pytest
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform

from maltego_mcp.errors import TransformError
from maltego_mcp.transforms.protocol import build_request, parse_response


def test_peticion_la_entiende_maltego_trx() -> None:
    body = build_request(
        "maltego.Domain",
        "example.com]]></Value><Evil/>",
        properties={"fqdn": "a&b<c>", "extra": "ñ"},
        settings={"api_mode": "fast"},
        soft_limit=7,
    )
    msg = MaltegoMsg(body)
    assert msg.Type == "maltego.Domain"
    assert msg.Value == "example.com]]></Value><Evil/>"
    assert msg.Properties == {"fqdn": "a&b<c>", "extra": "ñ"}
    assert msg.TransformSettings == {"api_mode": "fast"}
    assert msg.Slider == 7


def test_respuesta_generada_por_maltego_trx_se_parsea() -> None:
    out = MaltegoTransform()
    ip = out.addEntity("maltego.IPv4Address", "1.2.3.4")
    ip.setLinkLabel("resolves_to")
    ip.addProperty("ipv4-address.internal", "Interna", "loose", "false")
    ip.addDisplayInformation("<b>info</b>", "Detalle")
    ip.setWeight(80)
    ip.setNote("nota")
    ip.reverseLink()
    out.addEntity("maltego.Phrase", "hola")
    out.addUIMessage("aviso", "PartialError")
    resp = parse_response(out.returnOutput().encode())
    assert [e.value for e in resp.entities] == ["1.2.3.4", "hola"]
    first = resp.entities[0]
    assert first.entity_type == "maltego.IPv4Address"
    assert first.weight == 80
    assert first.link_label == "resolves_to"
    assert first.reversed_link is True
    assert first.properties == {"ipv4-address.internal": "false"}  # notes# no es una propiedad
    assert first.display_info == ["<b>info</b>"]
    assert resp.messages == [("PartialError", "aviso")]


def test_mensaje_de_excepcion() -> None:
    out = MaltegoTransform()
    out.addException("API key inválida")
    resp = parse_response(out.throwExceptions().encode())
    assert resp.exceptions == ["API key inválida"]
    assert resp.entities == []


@pytest.mark.parametrize(
    "payload",
    [
        b"no es xml",
        b"<Otra/>",
        b"<MaltegoMessage><Nada/></MaltegoMessage>",
        b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]>'
        b"<MaltegoMessage>&b;</MaltegoMessage>",
        b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
        b"<MaltegoMessage>&e;</MaltegoMessage>",
    ],
)
def test_respuestas_invalidas_o_maliciosas_se_rechazan(payload: bytes) -> None:
    with pytest.raises(TransformError):
        parse_response(payload)


def test_respuesta_enorme_se_trunca() -> None:
    out = MaltegoTransform()
    for i in range(1205):
        out.addEntity("maltego.Phrase", f"p{i}")
    resp = parse_response(out.returnOutput().encode())
    assert len(resp.entities) == 1000
    assert resp.truncated
