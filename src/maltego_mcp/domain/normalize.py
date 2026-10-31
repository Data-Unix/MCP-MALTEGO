"""Normalización y validación de valores de entidad e identificadores deterministas."""

import hashlib
import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit, urlunsplit

from maltego_mcp.domain.entity_types import EntityType
from maltego_mcp.errors import InvalidInput

MAX_VALUE_LEN = 2048
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_HASH_LENGTHS = {32, 40, 56, 64, 96, 128}
_CASE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}$")
_EDGE_LABEL_RE = re.compile(r"^[a-z][a-z0-9_]{0,62}$")


def clean_text(value: str) -> str:
    """Quita caracteres de control y colapsa espacios."""
    text = "".join(ch for ch in value if unicodedata.category(ch)[0] != "C" or ch in " \t")
    return " ".join(text.split())


def _domain(value: str) -> str:
    host = value.strip().rstrip(".").lower()
    if host.startswith("*."):
        host = host[2:]
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidInput(f"'{value[:80]}' no es un nombre de dominio válido (IDNA).") from exc
    labels = ascii_host.split(".")
    if len(ascii_host) > 253 or len(labels) < 2 or not all(_LABEL_RE.match(lbl) for lbl in labels):
        raise InvalidInput(f"'{value[:80]}' no es un nombre de dominio válido (ej.: example.com).")
    return ascii_host


def _ip(value: str, version: int) -> str:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise InvalidInput(f"'{value[:80]}' no es una dirección IPv{version} válida.") from exc
    if ip.version != version:
        raise InvalidInput(f"'{value[:80]}' es IPv{ip.version}; usa maltego.IPv{ip.version}Address.")
    return ip.compressed


def _netblock(value: str) -> str:
    text = value.strip()
    if "-" in text:
        start, _, end = text.partition("-")
        a, b = ipaddress.ip_address(start.strip()), ipaddress.ip_address(end.strip())
        if a.version != b.version or int(a) > int(b):
            raise InvalidInput(f"Rango '{value[:80]}' inválido: usa CIDR (10.0.0.0/24) o inicio-fin.")
        return f"{a.compressed}-{b.compressed}"
    try:
        return ipaddress.ip_network(text, strict=False).compressed
    except ValueError as exc:
        raise InvalidInput(f"'{value[:80]}' no es un rango de red válido (ej.: 10.0.0.0/24).") from exc


def _asn(value: str) -> str:
    text = value.strip().upper().removeprefix("AS")
    if not text.isdigit() or not 0 < int(text) < 2**32:
        raise InvalidInput(f"'{value[:80]}' no es un número de AS válido (ej.: 15133 o AS15133).")
    return str(int(text))


def _url(value: str) -> str:
    parts = urlsplit(value.strip())
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise InvalidInput(f"'{value[:80]}' no es una URL http(s) válida (ej.: https://example.com/a).")
    if _is_ip(parts.hostname):
        ip = ipaddress.ip_address(parts.hostname)
        host = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    else:
        host = _domain(parts.hostname)
    port = parts.port  # ValueError si el puerto es inválido: se traduce en normalize_value
    netloc = host if port is None else f"{host}:{port}"
    if parts.username or parts.password:
        raise InvalidInput("La URL no puede incluir credenciales (usuario:clave@).")
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _email(value: str) -> str:
    text = value.strip()
    if not _EMAIL_RE.match(text):
        raise InvalidInput(f"'{value[:80]}' no es un correo válido (ej.: info@example.com).")
    local, _, domain = text.rpartition("@")
    return f"{local.lower()}@{_domain(domain)}"


def _phone(value: str) -> str:
    text = value.strip()
    digits = re.sub(r"[\s().\-/]", "", text)
    if digits.startswith("00"):
        digits = "+" + digits[2:]
    body = digits.removeprefix("+")
    if not body.isdigit() or not 6 <= len(body) <= 15:
        raise InvalidInput(f"'{value[:80]}' no es un teléfono válido; usa formato E.164 (ej.: +34600000000).")
    return digits


def _hash(value: str) -> str:
    text = value.strip().lower()
    if not _HEX_RE.match(text) or len(text) not in _HASH_LENGTHS:
        raise InvalidInput(f"'{value[:80]}' no es un hash hexadecimal válido (MD5, SHA-1, SHA-256...).")
    return text


def normalize_value(entity_type: EntityType, value: str) -> str:
    """Normaliza el valor según el tipo. Lanza InvalidInput con un mensaje accionable."""
    if not isinstance(value, str) or not value.strip():
        raise InvalidInput("value no puede estar vacío.")
    if len(value) > MAX_VALUE_LEN:
        raise InvalidInput(f"value supera {MAX_VALUE_LEN} caracteres.")
    try:
        return _normalize(entity_type, value)
    except ValueError as exc:  # p. ej. puertos o rangos fuera de límites en la librería estándar
        raise InvalidInput(f"'{value[:80]}' no es un valor válido para {entity_type.maltego_type}.") from exc


def _normalize(entity_type: EntityType, value: str) -> str:
    match entity_type.normalizer:
        case "domain":
            return _domain(value)
        case "ipv4":
            return _ip(value, 4)
        case "ipv6":
            return _ip(value, 6)
        case "netblock":
            return _netblock(value)
        case "asn":
            return _asn(value)
        case "url":
            return _url(value)
        case "email":
            return _email(value)
        case "phone":
            return _phone(value)
        case "hash":
            return _hash(value)
        case _:
            text = clean_text(value)
            if not text:
                raise InvalidInput("value no puede estar vacío.")
            return text


def entity_id(entity_type: EntityType, normalized_value: str) -> str:
    """Id determinista y válido para Cosmos (sin / \\ ? #), estable entre ejecuciones."""
    digest = hashlib.sha256(f"{entity_type.maltego_type.lower()}|{normalized_value}".encode()).hexdigest()
    return f"{entity_type.graph_label}-{digest[:32]}"


def edge_id(case_id: str, out_id: str, label: str, in_id: str) -> str:
    digest = hashlib.sha256(f"{case_id}|{out_id}|{label}|{in_id}".encode()).hexdigest()
    return f"e-{digest[:32]}"


def validate_case_id(case_id: str) -> str:
    text = case_id.strip().lower()
    if not _CASE_ID_RE.match(text):
        raise InvalidInput(
            f"case_id '{case_id[:80]}' no es válido: usa 2-63 caracteres a-z, 0-9, '-' o '_' "
            "empezando por letra o número (ej.: caso-2026-001)."
        )
    return text


def normalize_edge_label(label: str) -> str:
    text = re.sub(r"[^a-z0-9]+", "_", label.strip().lower()).strip("_")
    if text and text[0].isdigit():
        text = "r_" + text
    if not _EDGE_LABEL_RE.match(text):
        raise InvalidInput(f"edge_label '{label[:80]}' no es válido: usa palabras como resolves_to o owns.")
    return text


def validate_entity_id(value: str) -> str:
    text = value.strip()
    if not re.match(r"^[a-z0-9_]+-[0-9a-f]{32}$", text):
        raise InvalidInput(
            f"entity_id '{value[:80]}' no es válido. Obtén ids con osint_upsert_entity u osint_search_entities."
        )
    return text
