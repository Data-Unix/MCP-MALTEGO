---
name: identity-footprint
description: Rastreo de identidad digital con el MCP maltego (PersonalFootprint y EmailRecon) - desde un correo o alias hasta alias, perfiles públicos, filtraciones conocidas (HIBP) y dominio y servidores de correo asociados, con salvaguardas legales y de privacidad. Úsala cuando el objetivo sea una persona o cuenta.
license: MIT
---
# Huella de identidad digital (PersonalFootprint / EmailRecon)

**Antes de empezar**: confirma base legítima (investigación autorizada, propia, o protección de la propia
organización) y minimiza datos: no recojas más de lo necesario (RGPD).

1. Correo → `osint_run_machine(machine="EmailRecon")`: dominio, alias, filtraciones (`HIBPEmailToBreaches` con
   `HIBP_API_KEY`), MX/NS/WHOIS del dominio y perfiles del alias.
2. Alias o usuario → `osint_run_machine(machine="PersonalFootprint", max_rounds=2)`: `AliasToProfiles` (GitHub,
   GitLab, Hacker News, Keybase, DEV).
3. Coincidencia de alias ≠ misma persona: marca la confianza baja (`osint_manage_entity confidence=0.3`) hasta
   corroborarla con otra evidencia y anótalo en `notes`.
4. Correlación entre casos: `osint_search_entities` con `case_id` vacío.
5. Entrega: informe con hechos, hipótesis y fuentes; `.mtgx` con layout `radial` alrededor de la persona.
No publiques ni compartas datos personales fuera del caso.
