"""Machines: secuencias automáticas de transforms (equivalentes a las Machines de Maltego).

Una Machine es una lista de etapas; cada etapa es una lista de transforms que se aplican a las entidades de la
frontera que aceptan. Una ronda recorre todas las etapas; con varias rondas, la frontera de la siguiente ronda son
las entidades nuevas de la anterior (expansión recursiva acotada por max_rounds y presupuestos).

Las predefinidas usan transforms integrados; los de proveedores sin clave configurada se omiten y se informa.
Se pueden añadir Machines propias en el catálogo TOML con [[machines]].
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from maltego_mcp.errors import ConfigError, InvalidInput

_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{1,60}$")


@dataclass(frozen=True, slots=True)
class Machine:
    name: str
    description: str
    input_types: tuple[str, ...]
    stages: tuple[tuple[str, ...], ...]
    default_rounds: int = 1
    origin: str = "predefinida"
    # True: cada etapa ve todo lo descubierto en la ronda (Machines). False: solo lo de la etapa anterior (cadena).
    accumulate: bool = True

    def accepts(self, maltego_type: str) -> bool:
        return not self.input_types or maltego_type.lower() in {t.lower() for t in self.input_types}

    @property
    def transforms(self) -> list[str]:
        return [t for stage in self.stages for t in stage]


BUILTIN_MACHINES: tuple[Machine, ...] = (
    Machine(
        "DomainRecon",
        "Enumeración de un dominio: DNS (A/AAAA/MX/NS/TXT), WHOIS, subdominios por certificados y web; "
        "después resuelve los hosts encontrados y ubica las IPs (AS y bloque).",
        ("maltego.Domain",),
        (
            (
                "DNSToIP",
                "DNSToIPv6",
                "DomainToMX",
                "DomainToNS",
                "DomainToTXT",
                "DomainToWhois",
                "DomainToSubdomains",
                "DomainToWebsite",
                "VTDomainToSubdomains",
                "SecurityTrailsSubdomains",
                "ShodanDomainToSubdomains",
            ),
            ("DNSToIP", "DNSToCNAME"),
            ("IPToAS", "IPToNetblock"),
        ),
    ),
    Machine(
        "InfrastructureRecon",
        "Topología de red a partir de una IP: DNS inverso, AS, bloque, WHOIS y servicios expuestos "
        "(InternetDB sin clave y Shodan/Censys/GreyNoise si hay clave).",
        ("maltego.IPv4Address", "maltego.IPv6Address"),
        (
            (
                "IPToReverseDNS",
                "IPToAS",
                "IPToNetblock",
                "IPToWhois",
                "InternetDBIPToServices",
                "ShodanIPToServices",
                "CensysIPToServices",
                "GreyNoiseIPContext",
                "VTIPToDomain",
            ),
            ("DNSToIP",),
        ),
    ),
    Machine(
        "EmailRecon",
        "Correo: dominio, alias, Gravatar, filtraciones (HIBP si hay clave) y servidores MX/NS del dominio; "
        "perfiles públicos y GitHub del alias.",
        ("maltego.EmailAddress",),
        (
            ("EmailToDomain", "EmailToAlias", "GravatarEmailToProfile", "HIBPEmailToBreaches"),
            ("DomainToMX", "DomainToNS", "DomainToWhois", "AliasToProfiles", "GitHubAliasToDetails"),
        ),
    ),
    Machine(
        "CompanyFootprint",
        "Huella corporativa desde su dominio: DomainRecon ampliado con HackerTarget, urlscan.io, correos corporativos "
        "(Hunter si hay clave), perfiles de los alias y ubicación y servicios de toda la infraestructura.",
        ("maltego.Domain",),
        (
            (
                "DNSToIP",
                "DomainToMX",
                "DomainToNS",
                "DomainToTXT",
                "DomainToWhois",
                "DomainToSubdomains",
                "HackerTargetSubdomains",
                "URLScanDomainSearch",
                "HunterDomainToEmails",
                "VTDomainToSubdomains",
                "SecurityTrailsSubdomains",
            ),
            ("DNSToIP", "EmailToAlias"),
            (
                "IPToAS",
                "IPToNetblock",
                "IPToWhois",
                "InternetDBIPToServices",
                "AliasToProfiles",
                "GitHubAliasToDetails",
            ),
        ),
        default_rounds=1,
    ),
    Machine(
        "PersonalFootprint",
        "Presencia digital desde correo o alias: alias, Gravatar, perfiles públicos, detalle en GitHub, "
        "filtraciones y dominio asociado.",
        ("maltego.EmailAddress", "maltego.Alias"),
        (
            (
                "EmailToAlias",
                "EmailToDomain",
                "GravatarEmailToProfile",
                "HIBPEmailToBreaches",
                "AliasToProfiles",
                "GitHubAliasToDetails",
            ),
            ("AliasToProfiles", "GitHubAliasToDetails", "DomainToWhois"),
        ),
    ),
    Machine(
        "URLRecon",
        "URL: web y dominio que la alojan, y DomainRecon ligero del dominio.",
        ("maltego.URL",),
        (("URLToDomain",), ("DNSToIP", "DomainToWhois", "DomainToNS"), ("IPToAS",)),
    ),
    Machine(
        "ThreatSweep",
        "Triaje defensivo de un indicador (hash, IP o dominio): pulsos OTX y VirusTotal para hashes, "
        "puertos/CVEs (InternetDB/Shodan/GreyNoise) para IPs, y WHOIS + urlscan.io para dominios.",
        ("maltego.Hash", "maltego.IPv4Address", "maltego.Domain"),
        (
            (
                "OTXHashToThreatPulses",
                "VTHashToDetection",
                "InternetDBIPToServices",
                "GreyNoiseIPContext",
                "ShodanIPToServices",
                "DomainToWhois",
                "URLScanDomainSearch",
            ),
            ("IPToAS", "IPToWhois"),
        ),
    ),
    Machine(
        "ASNToNetblocks",
        "Mapeo de un sistema autónomo (ASN): organización titular y prefijos BGP anunciados (RIPE Stat).",
        ("maltego.AS",),
        (("RIPEStatASNToNetblocks",),),
    ),
)

DEFAULT_MACHINE_BY_TYPE = {
    "maltego.domain": "DomainRecon",
    "maltego.dnsname": "DomainRecon",
    "maltego.website": "DomainRecon",
    "maltego.ipv4address": "InfrastructureRecon",
    "maltego.ipv6address": "InfrastructureRecon",
    "maltego.emailaddress": "EmailRecon",
    "maltego.alias": "PersonalFootprint",
    "maltego.url": "URLRecon",
    "maltego.hash": "ThreatSweep",
    "maltego.as": "ASNToNetblocks",
}


@dataclass(frozen=True, slots=True)
class MachineCatalog:
    machines: dict[str, Machine] = field(default_factory=dict)

    def get(self, name: str) -> Machine:
        m = self.machines.get(name.lower())
        if m is None:
            names = ", ".join(sorted(x.name for x in self.machines.values()))
            raise InvalidInput(f"La machine '{name[:60]}' no existe. Disponibles: {names}.")
        return m

    def for_type(self, maltego_type: str) -> Machine | None:
        name = DEFAULT_MACHINE_BY_TYPE.get(maltego_type.lower())
        return self.machines.get(name.lower()) if name else None


def custom_machine(transforms: list[str]) -> Machine:
    """Machine ad hoc: cada transform es una etapa (cadena clásica)."""
    if not transforms:
        raise InvalidInput("transforms no puede estar vacío: indica al menos un transform o usa machine.")
    return Machine(
        "cadena",
        "Cadena definida por el agente",
        (),
        tuple((t,) for t in transforms),
        origin="ad hoc",
        accumulate=False,
    )


def load_machines(raw: list[dict[str, Any]]) -> MachineCatalog:
    machines = {m.name.lower(): m for m in BUILTIN_MACHINES}
    for item in raw:
        name = str(item.get("name", ""))
        if not _NAME_RE.match(name):
            raise ConfigError(f"Machine con nombre inválido: '{name}'.")
        stages_raw = item.get("stages", [])
        if not isinstance(stages_raw, list) or not stages_raw:
            raise ConfigError(f"La machine '{name}' necesita stages = [[\"Transform\", ...], ...].")
        stages = tuple(tuple(str(t) for t in (st if isinstance(st, list) else [st])) for st in stages_raw)
        machines[name.lower()] = Machine(
            name=name,
            description=str(item.get("description", ""))[:500],
            input_types=tuple(str(t) for t in item.get("input_types", [])),
            stages=stages,
            default_rounds=int(item.get("rounds", 1)),
            origin="catálogo",
        )
    return MachineCatalog(machines)
