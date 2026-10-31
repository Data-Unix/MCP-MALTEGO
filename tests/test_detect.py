import pytest

from maltego_mcp.domain.detect import detect_entity_type, resolve_type_for_value


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("ana@example.com", "maltego.EmailAddress"),
        ("https://example.com/x", "maltego.URL"),
        ("8.8.8.8", "maltego.IPv4Address"),
        ("2001:db8::1", "maltego.IPv6Address"),
        ("10.0.0.0/24", "maltego.Netblock"),
        ("d41d8cd98f00b204e9800998ecf8427e", "maltego.Hash"),
        ("AS15133", "maltego.AS"),
        ("+34 600 000 000", "maltego.PhoneNumber"),
        ("Example.COM", "maltego.Domain"),
        ("sub.dominio.co.uk.", "maltego.Domain"),
        ("xn--mnchen-3ya.de", "maltego.Domain"),
        ("Jane Doe", "maltego.Phrase"),
        ("archivo.exe", "maltego.Phrase"),
        ("informe.PDF", "maltego.Phrase"),
        ("1.2", "maltego.Phrase"),
    ],
)
def test_detecta_tipos(value: str, expected: str) -> None:
    assert detect_entity_type(value).maltego_type == expected


def test_auto_y_vacio_detectan_y_explicito_respeta() -> None:
    assert resolve_type_for_value("auto", "a.com").maltego_type == "maltego.Domain"
    assert resolve_type_for_value("", "a.com").maltego_type == "maltego.Domain"
    assert resolve_type_for_value("maltego.DNSName", "a.com").maltego_type == "maltego.DNSName"
