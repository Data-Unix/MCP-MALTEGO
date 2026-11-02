"""Gestor de buzones de activación y proveedores de correo para Sock Puppets.

Permite:
1. Buzones desechables y programables vía API (Mail.tm) para recibir códigos OTP y enlaces de activación al vuelo.
2. Generación y gestión de alias de reenvío anónimo (Addy.io / SimpleLogin).
3. Catálogo de proveedores permanentes y cifrados (Proton, Tuta, Mailfence, Disroot, Atomic, Onionmail) con OPSEC.
4. Extractor automático de códigos OTP (2FA) y enlaces de confirmación de registro a partir de correos recibidos.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from typing import Any

import httpx

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"


@dataclass(slots=True)
class EmailProviderInfo:
    id: str
    name: str
    category: str  # "permanent_encrypted", "alias_forwarding", "disposable_api"
    url: str
    description: str
    jurisdiction: str
    requires_phone: bool
    encryption_type: str
    tor_onion_available: bool
    recommended_opsec: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "url": self.url,
            "description": self.description,
            "jurisdiction": self.jurisdiction,
            "requires_phone": self.requires_phone,
            "encryption_type": self.encryption_type,
            "tor_onion_available": self.tor_onion_available,
            "recommended_opsec": self.recommended_opsec,
        }


PROVIDER_CATALOG: list[EmailProviderInfo] = [
    # Nivel 1: Cifrados y Permanentes
    EmailProviderInfo(
        id="protonmail",
        name="Proton Mail",
        category="permanent_encrypted",
        url="https://proton.me/mail",
        description="Cifrado E2EE basado en Suiza. Plan gratuito de 1 GB, sin número de teléfono obligatorio.",
        jurisdiction="Suiza (fuera de jurisdicción UE/EE.UU.)",
        requires_phone=False,
        encryption_type="Zero-Access / OpenPGP E2EE",
        tor_onion_available=True,
        recommended_opsec=[
            "Registrar cuenta preferentemente desde Tor Browser a través de su mirror .onion.",
            "Utilizar frase de contraseña robusta generada en gestor de claves offline.",
            "Configurar 2FA por aplicación TOTP en lugar de SMS.",
        ],
    ),
    EmailProviderInfo(
        id="tutamail",
        name="Tuta Mail",
        category="permanent_encrypted",
        url="https://tuta.com/es/",
        description="Servicio alemán con cifrado completo en asunto y contactos. 1 GB de almacenamiento.",
        jurisdiction="Alemania (estrictas leyes de privacidad del RGPD)",
        requires_phone=False,
        encryption_type="Cifrado híbrido cuántico simétrico",
        tor_onion_available=False,
        recommended_opsec=[
            "Guardar el código de recuperación de 256 bits en un almacenamiento cifrado seguro.",
            "Esperar el período de aprobación de 48 horas tras el registro antes de usarlo en el caso.",
            "No reutilizar contraseñas de cuentas personales.",
        ],
    ),
    EmailProviderInfo(
        id="mailfence",
        name="Mailfence",
        category="permanent_encrypted",
        url="https://mailfence.com/",
        description="Buzón seguro belga sin registros de IP ni anuncios rastreadores. Incluye suite PGP integrada.",
        jurisdiction="Bélgica",
        requires_phone=False,
        encryption_type="OpenPGP integrado en navegador",
        tor_onion_available=False,
        recommended_opsec=[
            "Generar el par de claves PGP dentro del navegador sin exportar la clave privada a la nube.",
            "Conectar por VPN o proxy residencial para el acceso habitual.",
        ],
    ),
    EmailProviderInfo(
        id="disroot",
        name="Disroot",
        category="permanent_encrypted",
        url="https://disroot.org/",
        description="Plataforma comunitaria construida sobre software libre. Correos cifrados de 1 GB sin publicidad.",
        jurisdiction="Países Bajos",
        requires_phone=False,
        encryption_type="RainLoop / Webmail cifrado",
        tor_onion_available=False,
        recommended_opsec=[
            "Solicitar cuenta con antelación ya que la activación puede requerir validación manual comunitaria.",
        ],
    ),
    EmailProviderInfo(
        id="atomicmail",
        name="Atomic Mail",
        category="permanent_encrypted",
        url="https://atomicmail.io/",
        description="Proveedor enfocado en anonimato estricto, mensajes efímeros y recuperación por frase semilla.",
        jurisdiction="Descentralizado / Privacidad avanzada",
        requires_phone=False,
        encryption_type="Seed phrase recovery / E2EE",
        tor_onion_available=True,
        recommended_opsec=[
            "Anotar la frase semilla mnemotécnica en un medio físico o almacén offline.",
            "Ideal para comunicaciones de máxima sensibilidad que requieran caducidad de mensajes.",
        ],
    ),
    EmailProviderInfo(
        id="onionmail",
        name="Onionmail",
        category="permanent_encrypted",
        url="https://onionmail.org/",
        description="Nativo para la red Tor (.onion), ocultando localización IP y metadatos de extremo a extremo.",
        jurisdiction="Red distribuida Tor",
        requires_phone=False,
        encryption_type="Tor Onion Hidden Service E2EE",
        tor_onion_available=True,
        recommended_opsec=[
            "Acceder únicamente mediante Tor Browser a direcciones .onion.",
            "Desactivar JavaScript en Tor Browser al operar con este buzón.",
        ],
    ),
    # Nivel 2: Alias y Reenvío
    EmailProviderInfo(
        id="simplelogin",
        name="SimpleLogin",
        category="alias_forwarding",
        url="https://simplelogin.io/",
        description="Ecosistema de alias de Proton. Genera alias ilimitados que reenvían a tu buzón seguro central.",
        jurisdiction="Francia / Suiza",
        requires_phone=False,
        encryption_type="PGP Forwarding / Cifrado en tránsito",
        tor_onion_available=False,
        recommended_opsec=[
            "Generar un alias exclusivo por cada plataforma objetivo investigada.",
            "Desactivar el alias de inmediato si la plataforma sufre una brecha de seguridad.",
        ],
    ),
    EmailProviderInfo(
        id="addyio",
        name="Addy.io (AnonAddy)",
        category="alias_forwarding",
        url="https://addy.io/",
        description="Servicio open-source para crear alias de correo al vuelo y responder manteniendo el anonimato.",
        jurisdiction="Reino Unido",
        requires_phone=False,
        encryption_type="GPG Key Forwarding",
        tor_onion_available=False,
        recommended_opsec=[
            "Configurar clave pública GPG para que los correos reenviados lleguen cifrados a tu bandeja.",
        ],
    ),
    # Nivel 3: Desechables y Programables con API
    EmailProviderInfo(
        id="mailtm",
        name="Mail.tm (API Automatizada)",
        category="disposable_api",
        url="https://mail.tm/",
        description="Buzón temporal con API REST pública y gratuita para automatizar registros y recibir OTPs.",
        jurisdiction="Unión Europea",
        requires_phone=False,
        encryption_type="TLS en tránsito",
        tor_onion_available=False,
        recommended_opsec=[
            "Usar exclusivamente para activaciones rápidas y registros desechables.",
            "No almacenar información sensible en este buzón ya que expira automáticamente.",
        ],
    ),
    EmailProviderInfo(
        id="guerrillamail",
        name="Guerrilla Mail",
        category="disposable_api",
        url="https://www.guerrillamail.com/",
        description="Buzón efímero de 60 minutos sin contraseñas ni registro previo. Ideal para bypass de muros.",
        jurisdiction="Global",
        requires_phone=False,
        encryption_type="Efímero sin registro",
        tor_onion_available=True,
        recommended_opsec=[
            "Utilizar para registros donde no se necesite volver a acceder a la cuenta más adelante.",
        ],
    ),
]


def extract_otps_and_links(content: str) -> dict[str, list[str]]:
    """Extrae códigos OTP y enlaces de verificación/activación de un texto o correo HTML."""
    results: dict[str, list[str]] = {"otps": [], "activation_links": []}

    # 1. Extracción de códigos OTP numéricos (4 a 8 dígitos)
    # Detecta patrones con palabras clave como 'code', 'código', 'token', 'otp', 'pin', 'verification'
    otp_context_re = re.compile(
        r"(?:código|codigo|code|pin|otp|verification|activación|activacion|token)[^\w\d]{1,25}(\b\d{4,8}\b)",
        re.IGNORECASE,
    )
    for m in otp_context_re.finditer(content):
        val = m.group(1).strip()
        if val not in results["otps"]:
            results["otps"].append(val)

    # Respaldo para números destacados si no hubo coincidencia contextual
    if not results["otps"]:
        generic_otp = re.findall(r"\b([0-9]{5,6})\b", content)
        for g in generic_otp:
            if g not in results["otps"]:
                results["otps"].append(g)

    # 2. Extracción de enlaces de verificación/activación
    url_re = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
    all_urls = url_re.findall(content)

    kw_filter = re.compile(
        r"(verify|verification|activate|activation|confirm|confirmation|validate|token=|auth/|signup)",
        re.IGNORECASE,
    )
    for u in all_urls:
        clean_url = u.rstrip(".,;)>]")
        if kw_filter.search(clean_url) and clean_url not in results["activation_links"]:
            results["activation_links"].append(clean_url)

    return results


class MailTmClient:
    """Cliente HTTP asíncrono para interactuar con la API REST de Mail.tm."""

    BASE_URL = "https://api.mail.tm"

    def __init__(self, http_client: httpx.AsyncClient | None = None) -> None:
        self.http = http_client or httpx.AsyncClient(timeout=15.0, headers={"User-Agent": USER_AGENT})

    async def get_domains(self) -> list[str]:
        """Obtiene la lista de dominios disponibles en Mail.tm."""
        try:
            resp = await self.http.get(f"{self.BASE_URL}/domains")
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("hydra:member", [])
                return [d["domain"] for d in items if isinstance(d, dict) and d.get("isActive", True)]
        except Exception:
            pass
        return ["mailtm.me"]

    async def create_inbox(self, address: str = "", password: str = "") -> dict[str, Any]:
        """Crea una nueva cuenta/buzón temporal en Mail.tm y devuelve las credenciales y el token JWT."""
        domains = await self.get_domains()
        selected_domain = domains[0] if domains else "mailtm.me"

        if not address:
            user_part = f"osint_{secrets.token_hex(4)}"
            address = f"{user_part}@{selected_domain}"

        if not password:
            password = secrets.token_urlsafe(12)

        # 1. Crear cuenta
        create_resp = await self.http.post(
            f"{self.BASE_URL}/accounts",
            json={"address": address, "password": password},
        )
        if create_resp.status_code not in (200, 201):
            return {
                "ok": False,
                "error": f"Error creando cuenta en Mail.tm ({create_resp.status_code}): {create_resp.text}",
            }

        acc_data = create_resp.json()
        acc_id = acc_data.get("id", "")

        # 2. Iniciar sesión para obtener token JWT de lectura de bandeja
        token_resp = await self.http.post(
            f"{self.BASE_URL}/token",
            json={"address": address, "password": password},
        )
        token = ""
        if token_resp.status_code == 200:
            token = token_resp.json().get("token", "")

        return {
            "ok": True,
            "provider": "mail.tm",
            "inbox_id": acc_id,
            "address": address,
            "password": password,
            "token": token,
            "status": "ready",
        }

    async def get_messages(self, token: str) -> list[dict[str, Any]]:
        """Recupera la lista de mensajes entrantes en el buzón."""
        if not token:
            return []
        try:
            headers = {"Authorization": f"Bearer {token}", "User-Agent": USER_AGENT}
            resp = await self.http.get(f"{self.BASE_URL}/messages", headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                messages = data.get("hydra:member", [])
                formatted = []
                for m in messages:
                    sender = m.get("from", {}).get("address", "") if isinstance(m.get("from"), dict) else ""
                    msg_id = m.get("id", "")
                    subject = m.get("subject", "(Sin asunto)")
                    intro = m.get("intro", "")
                    created_at = m.get("createdAt", "")
                    formatted.append(
                        {
                            "id": msg_id,
                            "from": sender,
                            "subject": subject,
                            "intro": intro,
                            "created_at": created_at,
                            "seen": m.get("seen", False),
                        }
                    )
                return formatted
        except Exception:
            pass
        return []

    async def get_message_detail(self, token: str, message_id: str) -> dict[str, Any]:
        """Recupera el contenido completo de un mensaje y extrae automáticamente OTPs y enlaces."""
        if not token or not message_id:
            return {"ok": False, "error": "Faltan credenciales o id del mensaje"}

        try:
            headers = {"Authorization": f"Bearer {token}", "User-Agent": USER_AGENT}
            resp = await self.http.get(f"{self.BASE_URL}/messages/{message_id}", headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                text_content = data.get("text", "") or ""
                raw_html = data.get("html", "")
                html_content = "".join(raw_html) if isinstance(raw_html, list) else str(raw_html or "")
                combined_body = f"{text_content}\n{html_content}"

                analysis = extract_otps_and_links(combined_body)
                return {
                    "ok": True,
                    "id": data.get("id"),
                    "from": data.get("from", {}).get("address", "") if isinstance(data.get("from"), dict) else "",
                    "subject": data.get("subject", ""),
                    "text": text_content,
                    "html": html_content,
                    "detected_otps": analysis["otps"],
                    "detected_links": analysis["activation_links"],
                }
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

        return {"ok": False, "error": "No se pudo obtener el mensaje"}
