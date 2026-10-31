"""Catálogo de tipos de entidad Maltego y su correspondencia con el grafo.

Los nombres de tipo y de propiedad principal siguen las entidades estándar de Maltego
(ver maltego_trx.entities). Se admiten además tipos personalizados con formato `prefijo.Nombre`.
"""

import re
from dataclasses import asdict, dataclass
from typing import Literal

from maltego_mcp.errors import InvalidInput

Normalizer = Literal["domain", "ipv4", "ipv6", "netblock", "asn", "url", "email", "phone", "hash", "text"]


@dataclass(frozen=True, slots=True)
class EntityType:
    maltego_type: str
    graph_label: str
    main_property: str
    normalizer: Normalizer
    example: str
    description: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


ENTITY_TYPES: tuple[EntityType, ...] = (
    EntityType("maltego.Domain", "domain", "fqdn", "domain", "example.com", "Nombre de dominio"),
    EntityType("maltego.DNSName", "dns_name", "fqdn", "domain", "www.example.com", "Nombre DNS (host)"),
    EntityType("maltego.MXRecord", "mx_record", "fqdn", "domain", "mail.example.com", "Registro MX"),
    EntityType("maltego.NSRecord", "ns_record", "fqdn", "domain", "ns1.example.com", "Registro NS"),
    EntityType("maltego.Website", "website", "fqdn", "domain", "www.example.com", "Sitio web"),
    EntityType("maltego.IPv4Address", "ipv4", "ipv4-address", "ipv4", "93.184.216.34", "Dirección IPv4"),
    EntityType("maltego.IPv6Address", "ipv6", "ipv6-address", "ipv6", "2001:db8::1", "Dirección IPv6"),
    EntityType("maltego.Netblock", "netblock", "ipv4-range", "netblock", "93.184.216.0/24", "Rango de red"),
    EntityType("maltego.AS", "as", "as.number", "asn", "15133", "Sistema autónomo (número)"),
    EntityType("maltego.URL", "url", "url", "url", "https://example.com/a", "URL"),
    EntityType("maltego.EmailAddress", "email", "email", "email", "info@example.com", "Correo"),
    EntityType("maltego.PhoneNumber", "phone", "phonenumber", "phone", "+34600000000", "Teléfono"),
    EntityType("maltego.Hash", "hash", "properties.hash", "hash", "d41d8cd98f00b204e9800998ecf8427e", "Hash"),
    EntityType("maltego.Person", "person", "person.fullname", "text", "Jane Doe", "Persona física"),
    EntityType("maltego.Alias", "alias", "alias", "text", "jdoe", "Alias o usuario"),
    EntityType("maltego.Company", "company", "title", "text", "ACME S.L.", "Empresa"),
    EntityType("maltego.Organization", "organization", "title", "text", "ACME Group", "Organización"),
    EntityType("maltego.Location", "location", "location.name", "text", "Madrid, ES", "Ubicación"),
    EntityType("maltego.Document", "document", "url", "url", "https://example.com/doc.pdf", "Documento"),
    EntityType("maltego.Phrase", "phrase", "text", "text", "texto libre", "Texto libre o término"),
)

_BY_TYPE: dict[str, EntityType] = {e.maltego_type.lower(): e for e in ENTITY_TYPES}
CUSTOM_TYPE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+)+$")
CUSTOM_LABEL = "custom"


def resolve_entity_type(maltego_type: str) -> EntityType:
    """Devuelve el tipo conocido, o uno genérico para tipos personalizados válidos."""
    name = maltego_type.strip()
    known = _BY_TYPE.get(name.lower())
    if known:
        return known
    if not CUSTOM_TYPE_RE.match(name) or len(name) > 120:
        raise InvalidInput(
            f"entity_type '{maltego_type[:80]}' no es válido. Usa un tipo de osint_list_entity_types "
            "(p. ej. maltego.Domain) o un tipo personalizado con formato prefijo.Nombre (p. ej. acme.Ticket)."
        )
    return EntityType(name, CUSTOM_LABEL, "value", "text", "", "Tipo personalizado")
