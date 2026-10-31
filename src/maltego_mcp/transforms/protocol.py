"""Protocolo XML de transforms de Maltego (compatible con maltego-trx e iTDS).

Petición: MaltegoMessage/MaltegoTransformRequestMessage con una entidad, límites y TransformFields.
Respuesta: MaltegoTransformResponseMessage (entidades + UIMessages) o MaltegoTransformExceptionMessage.
El XML de respuesta es no confiable: se parsea con defusedxml y se acotan tamaños.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from xml.etree.ElementTree import Element, SubElement, tostring

import defusedxml.ElementTree as SafeET
from defusedxml import DefusedXmlException

from maltego_mcp.errors import TransformError

MAX_RESULT_ENTITIES = 1000
MAX_FIELD_LEN = 4000
LINK_PREFIX = "link#"


@dataclass(slots=True)
class ResultEntity:
    entity_type: str
    value: str
    weight: int = 100
    properties: dict[str, str] = field(default_factory=dict)
    link_properties: dict[str, str] = field(default_factory=dict)
    display_info: list[str] = field(default_factory=list)

    @property
    def link_label(self) -> str:
        return self.link_properties.get("maltego.link.label", "")

    @property
    def reversed_link(self) -> bool:
        return self.link_properties.get("maltego.link.direction", "") == "output-to-input"


@dataclass(slots=True)
class TransformResponse:
    entities: list[ResultEntity] = field(default_factory=list)
    messages: list[tuple[str, str]] = field(default_factory=list)
    exceptions: list[str] = field(default_factory=list)
    truncated: bool = False


def build_request(
    entity_type: str,
    value: str,
    properties: dict[str, str] | None = None,
    settings: dict[str, str] | None = None,
    soft_limit: int = 12,
    hard_limit: int = 255,
) -> bytes:
    """Construye la petición XML. ElementTree escapa todos los valores."""
    msg = Element("MaltegoMessage")
    req = SubElement(msg, "MaltegoTransformRequestMessage")
    ents = SubElement(req, "Entities")
    ent = SubElement(ents, "Entity", Type=entity_type)
    SubElement(ent, "Value").text = value
    SubElement(ent, "Weight").text = "100"
    if properties:
        fields = SubElement(ent, "AdditionalFields")
        for name, val in properties.items():
            SubElement(fields, "Field", Name=name, DisplayName=name).text = val
    SubElement(req, "Limits", SoftLimit=str(soft_limit), HardLimit=str(hard_limit))
    tf = SubElement(req, "TransformFields")
    for name, val in (settings or {}).items():
        SubElement(tf, "Field", Name=name).text = val
    return bytes(tostring(msg, encoding="utf-8", xml_declaration=False))


def _text(el: Element | None) -> str:
    return ((el.text or "") if el is not None else "").strip()[:MAX_FIELD_LEN]


def parse_response(payload: bytes) -> TransformResponse:
    try:
        root = SafeET.fromstring(payload)
    except (DefusedXmlException, SafeET.ParseError) as exc:
        raise TransformError("El servidor de transforms devolvió un XML inválido o inseguro.") from exc
    if root.tag != "MaltegoMessage":
        raise TransformError("Respuesta inesperada: no es un MaltegoMessage.")

    exc_msg = root.find("MaltegoTransformExceptionMessage")
    if exc_msg is not None:
        return TransformResponse(exceptions=[_text(e) for e in exc_msg.iter("Exception")][:20])

    resp = root.find("MaltegoTransformResponseMessage")
    if resp is None:
        raise TransformError("Respuesta sin MaltegoTransformResponseMessage.")
    out = TransformResponse()
    for ent in resp.iterfind("Entities/Entity"):
        if len(out.entities) >= MAX_RESULT_ENTITIES:
            out.truncated = True
            break
        props: dict[str, str] = {}
        link: dict[str, str] = {}
        for f in ent.iterfind("AdditionalFields/Field"):
            name = (f.get("Name") or "").strip()
            if not name:
                continue
            if name.startswith(LINK_PREFIX):
                link[name[len(LINK_PREFIX) :]] = _text(f)
            elif not name.endswith("#"):  # bookmark#, notes# son metadatos de UI
                props[name] = _text(f)
        try:
            weight = int(_text(ent.find("Weight")) or 100)
        except ValueError:
            weight = 100
        out.entities.append(
            ResultEntity(
                entity_type=(ent.get("Type") or "maltego.Phrase").strip(),
                value=_text(ent.find("Value")),
                weight=weight,
                properties=props,
                link_properties=link,
                display_info=[_text(lbl) for lbl in ent.iterfind("DisplayInformation/Label")][:5],
            )
        )
    for m in resp.iterfind("UIMessages/UIMessage"):
        out.messages.append(((m.get("MessageType") or "Inform"), _text(m)))
    return out
