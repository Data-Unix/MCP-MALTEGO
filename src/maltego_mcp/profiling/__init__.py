"""Módulo de perfilado (profiling) multidimensional para MCP Maltego.

Unifica 21 tipologías de investigación pericial organizadas en 6 pilares:
1. Corporativo, Financiero y M&A
2. Técnico, Cibernético y Telemetría CTI
3. Criminológico y Forense
4. Inteligencia, Seguridad Nacional y Amenazas Internas
5. Social, Psicográfico y Audiencias
6. Clínico y Psiquiátrico Forense (Marco Ético Goldwater)
"""

from maltego_mcp.domain.profiling import (
    GOLDWATER_ETHICAL_WARNING,
    TYPOLOGY_TITLES,
    TYPOLOGY_TO_DOMAIN,
    ProfileDimension,
    ProfileRecord,
    ProfileTypology,
    ProfilingDomain,
    ProfilingTraitNode,
    RiskLevel,
)
from maltego_mcp.profiling.engine import deduce_typology, execute_profile

__all__ = [
    "GOLDWATER_ETHICAL_WARNING",
    "TYPOLOGY_TITLES",
    "TYPOLOGY_TO_DOMAIN",
    "ProfileDimension",
    "ProfileRecord",
    "ProfileTypology",
    "ProfilingDomain",
    "ProfilingTraitNode",
    "RiskLevel",
    "deduce_typology",
    "execute_profile",
]
