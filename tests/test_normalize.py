import pytest

from maltego_mcp.domain.entity_types import CUSTOM_LABEL, ENTITY_TYPES, resolve_entity_type
from maltego_mcp.domain.normalize import (
    clean_text,
    entity_id,
    normalize_edge_label,
    normalize_value,
    validate_case_id,
    validate_entity_id,
)
from maltego_mcp.errors import InvalidInput


def norm(t: str, v: str) -> str:
    return normalize_value(resolve_entity_type(t), v)


@pytest.mark.parametrize(
    ("etype", "raw", "expected"),
    [
        ("maltego.Domain", " Example.COM. ", "example.com"),
        ("maltego.Domain", "*.example.com", "example.com"),
        ("maltego.Domain", "münchen.de", "xn--mnchen-3ya.de"),
        ("maltego.DNSName", "WWW.Example.com", "www.example.com"),
        ("maltego.IPv4Address", " 8.8.8.8 ", "8.8.8.8"),
        ("maltego.IPv6Address", "2001:0db8:0000::0001", "2001:db8::1"),
        ("maltego.Netblock", "10.0.0.5/24", "10.0.0.0/24"),
        ("maltego.Netblock", "10.0.0.1 - 10.0.0.9", "10.0.0.1-10.0.0.9"),
        ("maltego.AS", "as15133", "15133"),
        ("maltego.URL", "HTTPS://Example.com", "https://example.com/"),
        ("maltego.URL", "http://example.com:8080/a?b=1#frag", "http://example.com:8080/a?b=1"),
        ("maltego.EmailAddress", "John.Doe@Example.COM", "john.doe@example.com"),
        ("maltego.PhoneNumber", "0034 600-000 000", "+34600000000"),
        ("maltego.PhoneNumber", "(91) 555 12 34", "915551234"),
        ("maltego.Hash", "D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e"),
        ("maltego.Person", "  Jane \n\t Doe\x00 ", "Jane Doe"),
        ("acme.Ticket", "TCK-1", "TCK-1"),
    ],
)
def test_normaliza_valores_validos(etype: str, raw: str, expected: str) -> None:
    assert norm(etype, raw) == expected


@pytest.mark.parametrize(
    ("etype", "raw", "fragment"),
    [
        ("maltego.Domain", "localhost", "dominio"),
        ("maltego.Domain", "-bad-.com", "dominio"),
        ("maltego.Domain", "a" * 64 + ".com", "dominio"),
        ("maltego.IPv4Address", "999.1.1.1", "IPv4"),
        ("maltego.IPv4Address", "2001:db8::1", "usa maltego.IPv6Address"),
        ("maltego.Netblock", "10.0.0.9-10.0.0.1", "rango"),
        ("maltego.Netblock", "nope", "rango"),
        ("maltego.AS", "AS0", "AS"),
        ("maltego.URL", "ftp://example.com", "URL"),
        ("maltego.URL", "https://user:pass@example.com/", "credenciales"),
        ("maltego.EmailAddress", "no-at-sign", "correo"),
        ("maltego.PhoneNumber", "12", "E.164"),
        ("maltego.Hash", "xyz", "hash"),
        ("maltego.Phrase", "   ", "vacío"),
        ("maltego.Phrase", "\x00\x01", "vacío"),
        ("maltego.Phrase", "x" * 3000, "2048"),
    ],
)
def test_rechaza_valores_invalidos_con_mensaje_accionable(etype: str, raw: str, fragment: str) -> None:
    with pytest.raises(InvalidInput) as exc:
        norm(etype, raw)
    assert fragment.lower() in str(exc.value).lower()


def test_tipos_conocidos_y_personalizados() -> None:
    assert resolve_entity_type("MALTEGO.domain").maltego_type == "maltego.Domain"
    assert resolve_entity_type("acme.Ticket").graph_label == CUSTOM_LABEL
    for bad in ("Domain", "not a type", "a.", "x" * 200 + ".y"):
        with pytest.raises(InvalidInput):
            resolve_entity_type(bad)


def test_catalogo_sin_duplicados_y_ejemplos_validos() -> None:
    assert len({e.maltego_type.lower() for e in ENTITY_TYPES}) == len(ENTITY_TYPES)
    assert len({e.graph_label for e in ENTITY_TYPES}) == len(ENTITY_TYPES)
    for e in ENTITY_TYPES:
        normalize_value(e, e.example)  # cada ejemplo documentado debe ser válido


def test_entity_id_determinista_y_seguro_para_cosmos() -> None:
    t = resolve_entity_type("maltego.URL")
    a = entity_id(t, "https://example.com/a?b=1#x")
    assert a == entity_id(t, "https://example.com/a?b=1#x")
    assert not any(ch in a for ch in "/\\?#")
    assert validate_entity_id(a) == a
    assert entity_id(resolve_entity_type("maltego.Domain"), "x.com") != entity_id(
        resolve_entity_type("maltego.DNSName"), "x.com"
    )


@pytest.mark.parametrize("bad", ["", "a", "-abc", "Con Espacios", "x" * 64, "caso/1", "caso;drop"])
def test_case_id_invalido(bad: str) -> None:
    with pytest.raises(InvalidInput):
        validate_case_id(bad)


def test_case_id_se_normaliza_a_minusculas() -> None:
    assert validate_case_id(" Caso-2026_01 ") == "caso-2026_01"


@pytest.mark.parametrize(("raw", "expected"), [("Resolves To", "resolves_to"), ("owns!", "owns"), ("2fa", "r_2fa")])
def test_edge_label(raw: str, expected: str) -> None:
    assert normalize_edge_label(raw) == expected


def test_edge_label_invalido() -> None:
    with pytest.raises(InvalidInput):
        normalize_edge_label("!!!")


def test_entity_id_invalido() -> None:
    for bad in ("", "domain-xyz", "x' or 1=1", "domain-" + "0" * 31):
        with pytest.raises(InvalidInput):
            validate_entity_id(bad)


def test_clean_text_elimina_controles() -> None:
    assert clean_text("a​b\x07c‮") == "abc"
