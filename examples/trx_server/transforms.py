"""Transforms de ejemplo con maltego-trx (el SDK Python de Maltego para servidores de transforms).

Sirven para probar MCP Maltego de punta a punta sin APIs de pago. Los mismos transforms se pueden
registrar en Maltego Desktop (transform local o servidor TRX/iTDS).
"""

import socket
from urllib.parse import urlsplit

from maltego_trx.entities import URL, Domain, Email, IPAddress, Website
from maltego_trx.maltego import UIM_PARTIAL, MaltegoMsg, MaltegoTransform
from maltego_trx.transform import DiscoverableTransform


class EmailToDomain(DiscoverableTransform):
    """maltego.EmailAddress -> maltego.Domain (dominio del correo)."""

    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform) -> None:
        _, _, domain = request.Value.rpartition("@")
        if not domain:
            response.addUIMessage("El valor no parece un correo.", UIM_PARTIAL)
            return
        ent = response.addEntity(Domain, domain)
        ent.setLinkLabel("email_domain")


class URLToDomain(DiscoverableTransform):
    """maltego.URL -> maltego.Domain (host de la URL)."""

    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform) -> None:
        host = urlsplit(request.Value).hostname
        if not host:
            response.addUIMessage("La URL no tiene host.", UIM_PARTIAL)
            return
        response.addEntity(Domain, host).setLinkLabel("hosted_on")


class DomainToWebsite(DiscoverableTransform):
    """maltego.Domain -> maltego.Website (www.<dominio>) y maltego.URL (https://<dominio>/)."""

    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform) -> None:
        domain = request.Value.strip().lower()
        site = response.addEntity(Website, f"www.{domain}")
        site.setLinkLabel("has_website")
        url = response.addEntity(URL, f"https://{domain}/")
        url.addProperty("url", "URL", "strict", f"https://{domain}/")
        url.setLinkLabel("has_url")


class DomainToIP(DiscoverableTransform):
    """maltego.Domain/DNSName/Website -> maltego.IPv4Address mediante resolución DNS real."""

    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform) -> None:
        try:
            _, _, ips = socket.gethostbyname_ex(request.Value)
        except OSError as exc:
            response.addUIMessage(f"No se pudo resolver {request.Value}: {exc.__class__.__name__}", UIM_PARTIAL)
            return
        for ip in ips[: request.Slider or 12]:
            response.addEntity(IPAddress, ip).setLinkLabel("resolves_to")


class EmailToHandle(DiscoverableTransform):
    """maltego.EmailAddress -> maltego.Alias (parte local), ejemplo de entidad con propiedades."""

    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform) -> None:
        local, _, _ = request.Value.partition("@")
        alias = response.addEntity("maltego.Alias", local)
        alias.addProperty("alias", "Alias", "strict", local)
        alias.setLinkLabel("possible_alias")
        alias.setWeight(40)


ALL = [EmailToDomain, URLToDomain, DomainToWebsite, DomainToIP, EmailToHandle]
__all__ = ["ALL", "Email"]
