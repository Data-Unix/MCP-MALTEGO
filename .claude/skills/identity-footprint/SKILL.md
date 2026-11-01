---
name: identity-footprint
description: Rastreo de identidad digital con el MCP maltego (PersonalFootprint y EmailRecon) - desde un correo o alias hasta alias, perfiles públicos, filtraciones conocidas (HIBP) y dominio y servidores de correo asociados, con salvaguardas legales y de privacidad. Úsala cuando el objetivo sea una persona o cuenta.
license: MIT
---
# Huella de identidad digital (PersonalFootprint / EmailRecon)

**Antes de empezar**: confirma base legítima (investigación autorizada, propia, o protección de la propia
organización) y minimiza datos: no recojas más de lo necesario (RGPD).

1. Correo → `osint_run_machine(machine="EmailRecon")`: dominio, alias, filtraciones (`BreachSemanticPivot` y
   `HIBPEmailToBreaches`), MX/NS/WHOIS del dominio y perfiles del alias.
2. Alias, persona o perfil HUMINT → `osint_run_machine(machine="PersonaFootprint", max_rounds=2)` o
   `PersonalFootprint`: `AliasToProfiles`, `GitHubAliasToDetails`, `GravatarEmailToProfile`, `BreachSemanticPivot` y
   `AnalyzeSubjectBehavior` (genera rasgos `humint.PsychologicalTrait` etiquetados como `[Hipótesis]`,
   `humint.LocationHistory` y `humint.Organization`).
3. Correlación matemática de identidades → `osint_link_entities(action="correlate")` evalúa similitud de handle,
   metadatos, estilometría (3-gramas) y solapamiento de vecindario Jaccard; enlaza automáticamente si >= 85 %.
4. Línea temporal del sujeto y desconflicción → `osint_get_timeline(mode="subject")` consolida fechas de creación,
   filtraciones y actividad detectando paradojas cronológicas, saltos de huso horario y rotación post-brecha.
5. Coincidencia de alias ≠ misma persona: marca la confianza baja (`osint_manage_entity confidence=0.3`) hasta
   corroborarla con otra evidencia y anótalo en `notes`.
6. Correlación entre casos: `osint_search_entities` con `case_id` vacío.
7. Entrega: informe con hechos, hipótesis y fuentes; `.mtgx` con layout `radial` alrededor de la persona.
No publiques ni compartas datos personales fuera del caso.
