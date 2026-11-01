"""Ontología de entidades Maltego y su correspondencia con el grafo.

- Tipos estándar: identificadores y propiedad principal según las entidades estándar de Maltego (fuente:
  maltego_trx.entities y su tabla de propiedades v3).
- Tipos importados: la ontología exacta de tu Maltego, importada de un .mtz exportado desde Maltego
  (`maltegoctl import-entities`), que añade o corrige tipos (incluidas entidades de hubs y propias).
- Tipos personalizados `prefijo.Nombre` no declarados: se aceptan como genéricos.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from maltego_mcp.errors import InvalidInput

logger = logging.getLogger(__name__)

Normalizer = Literal["domain", "ipv4", "ipv6", "netblock", "asn", "url", "email", "phone", "hash", "port", "text"]
Category = Literal[
    "infraestructura", "identidad", "organizacion", "artefacto", "cripto", "social", "humint", "general"
]
HUMINT_ONTOLOGY_PATH = Path(__file__).resolve().parents[1] / "ontology" / "humint.json"


@dataclass(frozen=True, slots=True)
class EntityType:
    maltego_type: str
    graph_label: str
    main_property: str
    normalizer: Normalizer
    example: str
    description: str
    category: Category = "general"
    origin: str = "estándar"

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _t(
    mtype: str,
    label: str,
    prop: str,
    norm: Normalizer,
    example: str,
    desc: str,
    cat: Category,
    origin: str = "estándar",
) -> EntityType:
    return EntityType(mtype, label, prop, norm, example, desc, cat, origin)


def _load_humint_ontology() -> tuple[EntityType, ...]:
    try:
        raw = json.loads(HUMINT_ONTOLOGY_PATH.read_text(encoding="utf-8"))
        return tuple(
            EntityType(
                maltego_type=str(item["maltego_type"]),
                graph_label=str(item["graph_label"]),
                main_property=str(item["main_property"]),
                normalizer="text",
                example=str(item.get("example", "")),
                description=str(item.get("description", "")),
                category="humint",
                origin=str(item.get("origin", "humint")),
            )
            for item in raw.get("entity_types", [])
        )
    except (OSError, ValueError, KeyError, TypeError):  # pragma: no cover
        return ()


ENTITY_TYPES: tuple[EntityType, ...] = (
    # Infraestructura digital
    _t("maltego.Domain", "domain", "fqdn", "domain", "example.com", "Nombre de dominio", "infraestructura"),
    _t("maltego.DNSName", "dns_name", "fqdn", "domain", "www.example.com", "Nombre DNS (host)", "infraestructura"),
    _t("maltego.MXRecord", "mx_record", "fqdn", "domain", "mail.example.com", "Registro MX", "infraestructura"),
    _t("maltego.NSRecord", "ns_record", "fqdn", "domain", "ns1.example.com", "Registro NS", "infraestructura"),
    _t("maltego.Website", "website", "fqdn", "domain", "www.example.com", "Sitio web", "infraestructura"),
    _t("maltego.URL", "url", "url", "url", "https://example.com/a", "URL", "infraestructura"),
    _t("maltego.IPv4Address", "ipv4", "ipv4-address", "ipv4", "93.184.216.34", "Dirección IPv4", "infraestructura"),
    _t("maltego.IPv6Address", "ipv6", "ipv6-address", "ipv6", "2001:db8::1", "Dirección IPv6", "infraestructura"),
    _t("maltego.Netblock", "netblock", "ipv4-range", "netblock", "93.184.216.0/24", "Rango de red", "infraestructura"),
    _t("maltego.AS", "as", "as.number", "asn", "15133", "Sistema autónomo (número)", "infraestructura"),
    _t("maltego.Port", "port", "port.number", "port", "443", "Puerto de red", "infraestructura"),
    _t("maltego.Service", "service", "service.name", "text", "443/https nginx", "Servicio de red", "infraestructura"),
    _t("maltego.Device", "device", "device", "text", "Cisco ASA", "Dispositivo", "infraestructura"),
    # Identidades y personas
    _t("maltego.Person", "person", "person.fullname", "text", "Jane Doe", "Persona física", "identidad"),
    _t("maltego.EmailAddress", "email", "email", "email", "info@example.com", "Correo", "identidad"),
    _t("maltego.PhoneNumber", "phone", "phonenumber", "phone", "+34600000000", "Teléfono", "identidad"),
    _t("maltego.Alias", "alias", "alias", "text", "jdoe", "Alias o usuario", "identidad"),
    _t("maltego.Image", "image", "description", "text", "Foto de perfil", "Imagen", "identidad"),
    _t("maltego.Document", "document", "url", "url", "https://example.com/doc.pdf", "Documento", "identidad"),
    _t("maltego.Location", "location", "location.name", "text", "Madrid, ES", "Ubicación", "identidad"),
    _t("maltego.GPS", "gps", "gps.coordinate", "text", "40.4168,-3.7038", "Coordenadas GPS", "identidad"),
    # Organización
    _t("maltego.Company", "company", "title", "text", "ACME S.L.", "Empresa", "organizacion"),
    _t("maltego.Organization", "organization", "title", "text", "ACME Group", "Organización", "organizacion"),
    # Artefactos y malware
    _t("maltego.Hash", "hash", "properties.hash", "hash", "d41d8cd98f00b204e9800998ecf8427e", "Hash", "artefacto"),
    _t("maltego.File", "file", "properties.file", "text", "invoice.exe", "Fichero", "artefacto"),
    # Criptoactivos (verifica el identificador en tu Maltego e importa tu ontología si difiere)
    _t(
        "maltego.CryptocurrencyAddress",
        "crypto_address",
        "cryptocurrency.address",
        "text",
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        "Dirección de criptomoneda",
        "cripto",
    ),
    _t(
        "maltego.CryptocurrencyTransaction",
        "crypto_tx",
        "cryptocurrency.transaction",
        "text",
        "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
        "Transacción de criptomoneda",
        "cripto",
    ),
    # Redes sociales
    _t("maltego.Affiliation", "affiliation", "affiliation.uid", "text", "jdoe", "Perfil/afiliación social", "social"),
    _t(
        "maltego.AffiliationTwitter",
        "affiliation_twitter",
        "affiliation.uid",
        "text",
        "jdoe",
        "Perfil de X/Twitter",
        "social",
    ),
    _t("maltego.FacebookObject", "facebook_object", "facebook.object", "text", "jdoe", "Objeto de Facebook", "social"),
    _t("maltego.Hashtag", "hashtag", "hashtag", "text", "#osint", "Hashtag", "social"),
    # General
    _t(
        "maltego.Phrase",
        "phrase",
        "text",
        "text",
        "texto libre",
        "Texto libre; categorías con prefijo [T1566]",
        "general",
    ),
    _t("maltego.UniqueIdentifier", "unique_id", "identifier", "text", "UA-12345-1", "Identificador único", "general"),
    *_load_humint_ontology(),
)

CUSTOM_TYPE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+)+$")
CUSTOM_LABEL = "custom"
_NORMALIZER_BY_PROPERTY: dict[str, Normalizer] = {
    e.main_property: e.normalizer for e in ENTITY_TYPES if e.normalizer not in ("text",)
}

_BY_TYPE: dict[str, EntityType] = {e.maltego_type.lower(): e for e in ENTITY_TYPES}
_IMPORTED: dict[str, EntityType] = {}


def all_entity_types() -> list[EntityType]:
    """Estándar + importados (los importados con el mismo id sustituyen al estándar)."""
    merged = {**_BY_TYPE, **_IMPORTED}
    return sorted(merged.values(), key=lambda e: (e.category, e.maltego_type.lower()))


def resolve_entity_type(maltego_type: str) -> EntityType:
    """Tipo importado, estándar o genérico para tipos personalizados válidos."""
    name = maltego_type.strip()
    key = name.lower()
    known = _IMPORTED.get(key) or _BY_TYPE.get(key)
    if known:
        return known
    if not CUSTOM_TYPE_RE.match(name) or len(name) > 120:
        raise InvalidInput(
            f"entity_type '{maltego_type[:80]}' no es válido. Usa un tipo de osint_list_entity_types "
            '(p. ej. maltego.Domain), "auto", o uno personalizado con formato prefijo.Nombre (p. ej. acme.Ticket).'
        )
    return EntityType(name, CUSTOM_LABEL, f"properties.{name.rsplit('.', 1)[-1].lower()}", "text", "", "Personalizado")


def _label_for(maltego_type: str) -> str:
    standard = _BY_TYPE.get(maltego_type.lower())
    if standard:
        return standard.graph_label
    return CUSTOM_LABEL


def register_imported_types(types: list[EntityType]) -> None:
    _IMPORTED.clear()
    for t in types:
        _IMPORTED[t.maltego_type.lower()] = t


def imported_type(maltego_type: str, main_property: str, display: str, category: str = "") -> EntityType:
    """Construye un tipo importado conservando la etiqueta del grafo (ids estables) y el normalizador adecuado."""
    standard = _BY_TYPE.get(maltego_type.lower())
    normalizer: Normalizer = standard.normalizer if standard else _NORMALIZER_BY_PROPERTY.get(main_property, "text")
    cat: Category = standard.category if standard else "general"
    return EntityType(
        maltego_type,
        _label_for(maltego_type),
        main_property,
        normalizer,
        standard.example if standard else "",
        display or maltego_type,
        cat,
        "importado",
    )


def load_imported_types(path: Path) -> int:
    """Carga la ontología importada (JSON escrito por `maltegoctl import-entities`)."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        types = [
            imported_type(str(t["maltego_type"]), str(t["main_property"]), str(t.get("description", "")))
            for t in raw.get("entity_types", [])
            if CUSTOM_TYPE_RE.match(str(t.get("maltego_type", ""))) and str(t.get("main_property", "")).strip()
        ]
    except FileNotFoundError:
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        logger.warning("Ontología importada ignorada (%s): %s", path, exc.__class__.__name__)
        return 0
    register_imported_types(types)
    return len(types)
