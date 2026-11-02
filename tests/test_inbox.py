"""Tests unitarios y de integración para el gestor de buzones y receptor de OTPs."""

from __future__ import annotations

import httpx
import pytest

from maltego_mcp.inbox import (
    PROVIDER_CATALOG,
    MailTmClient,
    extract_otps_and_links,
)


def test_extract_otps_and_links_multilingual() -> None:
    # 1. Mensaje en español con código y enlace
    text_es = """
    Hola agente,
    Gracias por registrarte. Tu código de verificación es 849201.
    También puedes activar tu cuenta haciendo clic en el siguiente enlace:
    https://target-portal.com/auth/activate?token=9f8a8b7c6d5e4f3a2b1
    Este código expirará en 15 minutos.
    """
    res_es = extract_otps_and_links(text_es)
    assert "849201" in res_es["otps"]
    assert any("activate?token=" in url for url in res_es["activation_links"])

    # 2. Mensaje en inglés con HTML
    html_en = """
    <html>
      <body>
        <p>Your security pin: <strong>552190</strong></p>
        <p>Please confirm your signup at <a href="https://service.io/signup/confirm?session=xyz">here</a>.</p>
      </body>
    </html>
    """
    res_en = extract_otps_and_links(html_en)
    assert "552190" in res_en["otps"]
    assert any("confirm?session=" in url for url in res_en["activation_links"])

    # 3. Formato OTP con token de 6 dígitos genérico
    plain = "Validation Code: 123456"
    res_plain = extract_otps_and_links(plain)
    assert "123456" in res_plain["otps"]


def test_provider_catalog_structure() -> None:
    assert len(PROVIDER_CATALOG) >= 10
    categories = {p.category for p in PROVIDER_CATALOG}
    assert "permanent_encrypted" in categories
    assert "alias_forwarding" in categories
    assert "disposable_api" in categories

    ids = [p.id for p in PROVIDER_CATALOG]
    assert "protonmail" in ids
    assert "tutamail" in ids
    assert "mailfence" in ids
    assert "onionmail" in ids
    assert "simplelogin" in ids
    assert "addyio" in ids
    assert "mailtm" in ids
    assert "guerrillamail" in ids

    for p in PROVIDER_CATALOG:
        assert p.name
        assert p.url.startswith("https://")
        assert len(p.recommended_opsec) > 0
        d = p.to_dict()
        assert d["id"] == p.id
        assert d["category"] == p.category


@pytest.mark.asyncio
async def test_mailtm_client_mocked() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/domains"):
            return httpx.Response(200, json={"hydra:member": [{"domain": "temp-osint.org", "isActive": True}]})
        if url.endswith("/accounts"):
            return httpx.Response(201, json={"id": "acc_123", "address": "osint_test@temp-osint.org"})
        if url.endswith("/token"):
            return httpx.Response(200, json={"token": "jwt_token_sample_123"})
        if url.endswith("/messages"):
            return httpx.Response(
                200,
                json={
                    "hydra:member": [
                        {
                            "id": "msg_999",
                            "from": {"address": "auth@service.com"},
                            "subject": "Tu código de acceso",
                            "intro": "Código: 789123",
                            "createdAt": "2026-11-02T18:00:00Z",
                        }
                    ]
                },
            )
        if "/messages/msg_999" in url:
            return httpx.Response(
                200,
                json={
                    "id": "msg_999",
                    "from": {"address": "auth@service.com"},
                    "subject": "Tu código de acceso",
                    "text": "Hola, tu código OTP de confirmación es 789123. Accede a https://service.com/verify?token=abc",
                    "html": ["<p>Código 789123</p>"],
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http:
        client = MailTmClient(http)

        # 1. Dominios
        domains = await client.get_domains()
        assert domains == ["temp-osint.org"]

        # 2. Crear buzón
        inbox = await client.create_inbox()
        assert inbox["ok"] is True
        assert inbox["token"] == "jwt_token_sample_123"
        assert "@" in inbox["address"]

        # 3. Lista de mensajes
        msgs = await client.get_messages(inbox["token"])
        assert len(msgs) == 1
        assert msgs[0]["id"] == "msg_999"

        # 4. Detalle y extracción de OTP
        detail = await client.get_message_detail(inbox["token"], "msg_999")
        assert detail["ok"] is True
        assert "789123" in detail["detected_otps"]
        assert any("verify?token=" in u for u in detail["detected_links"])

