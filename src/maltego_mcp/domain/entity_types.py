"""Catálogo de tipos de entidad Maltego soportados.

Versión inicial fija; se ampliará con el mapeo completo Maltego <-> grafo (PLAN.md §1).
"""

from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class EntityType:
    maltego_type: str
    graph_label: str
    main_property: str
    example: str
    description: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


ENTITY_TYPES: tuple[EntityType, ...] = (
    EntityType("maltego.Domain", "domain", "fqdn", "example.com", "Nombre de dominio DNS"),
    EntityType("maltego.IPv4Address", "ipv4", "ipv4-address", "93.184.216.34", "Dirección IPv4"),
    EntityType("maltego.EmailAddress", "email", "email", "info@example.com", "Dirección de correo"),
    EntityType("maltego.Person", "person", "person.fullname", "Jane Doe", "Persona física"),
    EntityType("maltego.Phrase", "phrase", "text", "texto libre", "Texto libre o término de búsqueda"),
)
