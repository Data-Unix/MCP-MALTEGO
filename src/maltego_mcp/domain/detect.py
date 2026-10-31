"""Detección automática del tipo de entidad a partir del valor (entity_type="auto")."""

import ipaddress
import re

from maltego_mcp.domain.entity_types import EntityType, resolve_entity_type

_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$|^[0-9a-fA-F]{128}$")
_ASN_RE = re.compile(r"^AS\d{1,10}$", re.IGNORECASE)
_PHONE_RE = re.compile(r"^\+\d[\d\s().-]{5,20}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})\.?$"
)

AUTO = "auto"
# Extensiones de fichero frecuentes en OSINT que no son TLD reales (evita "malware.exe" -> dominio).
_FILE_EXTENSIONS = frozenset(
    {
        "exe",
        "dll",
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "txt",
        "jpg",
        "jpeg",
        "png",
        "gif",
        "bat",
        "ps1",
        "tmp",
        "log",
        "bin",
        "iso",
        "msi",
        "lnk",
        "csv",
        "json",
        "xml",
        "js",
        "vbs",
        "hta",
        "jar",
        "apk",
    }
)


def detect_entity_type(value: str) -> EntityType:
    """Devuelve el tipo Maltego más probable; si no encaja nada, maltego.Phrase."""
    text = value.strip()
    lower = text.lower()
    if _EMAIL_RE.match(text):
        return resolve_entity_type("maltego.EmailAddress")
    if lower.startswith(("http://", "https://")):
        return resolve_entity_type("maltego.URL")
    try:
        ip = ipaddress.ip_address(text)
        return resolve_entity_type("maltego.IPv4Address" if ip.version == 4 else "maltego.IPv6Address")
    except ValueError:
        pass
    if "/" in text:
        try:
            ipaddress.ip_network(text, strict=False)
            return resolve_entity_type("maltego.Netblock")
        except ValueError:
            pass
    if _HASH_RE.match(text):
        return resolve_entity_type("maltego.Hash")
    if _ASN_RE.match(text):
        return resolve_entity_type("maltego.AS")
    if _PHONE_RE.match(text):
        return resolve_entity_type("maltego.PhoneNumber")
    if _DOMAIN_RE.match(lower) and lower.rstrip(".").rsplit(".", 1)[-1] not in _FILE_EXTENSIONS:
        return resolve_entity_type("maltego.Domain")
    return resolve_entity_type("maltego.Phrase")


def resolve_type_for_value(entity_type: str, value: str) -> EntityType:
    """entity_type explícito, o detección automática si es "auto" o está vacío."""
    if not entity_type.strip() or entity_type.strip().lower() == AUTO:
        return detect_entity_type(value)
    return resolve_entity_type(entity_type)
