---
name: identity-footprint
description: Rastreo de identidad digital con el MCP maltego (PersonalFootprint y EmailRecon) - desde un correo o alias hasta alias, perfiles públicos, filtraciones conocidas (HIBP) y dominio y servidores de correo asociados, con salvaguardas legales y de privacidad. Úsala cuando el objetivo sea una persona o cuenta.
license: MIT
---
# Huella de identidad digital (PersonalFootprint / EmailRecon)

> **Aviso de pasividad:** Para rastreo 100 % pasivo sin telemetría de propietario ni interacción con el sujeto, sigue
> prioritariamente la skill `investigacion-pasiva-no-zoom`.

**Antes de empezar**: confirma base legítima (Ley 5/2014, interés legítimo) y minimiza datos personales (RGPD); no investigues la vida íntima.

1. **Modo pasivo para correo**:
   - NO ejecutar `machine="EmailRecon"` en modo pasivo: ejecuta resoluciones DNS en vivo sobre el dominio del correo.
   - En su lugar, usa `osint_manage_case` + `osint_upsert_entity` y ejecuta exclusivamente transforms pasivos:
     `BreachSemanticPivot`, `HIBPEmailToBreaches`, `GravatarEmailToProfile`, `HudsonRockStealerCheck`, `EmailToDomain` y `DomainToWhois`. Nunca uses verificadores SMTP activos.
2. **Alias, persona o perfil HUMINT**:
   - `machine="PersonalFootprint"` o `machine="PersonaFootprint"`: ambas son 100 % pasivas y utilizan datasets agregados:
     `AliasToProfiles`, `GitHubAliasToDetails`, `GravatarEmailToProfile`, `BreachSemanticPivot`, `KeybaseAliasToProofs` y `AnalyzeSubjectBehavior`.
   - Consulta perfiles sin sesión iniciada para no disparar alertas de visualización (`owner_telemetry`).
3. **Correlación matemática de identidades**: `osint_link_entities(action="correlate")` evalúa similitud de handle, metadatos, estilometría (3-gramas) y solapamiento Jaccard.
4. **Línea temporal y desconflicción**: `osint_get_timeline(mode="subject")` consolida fechas de creación, filtraciones y actividad detectando paradojas cronológicas.
5. **Coincidencia de alias ≠ misma persona**: marca la confianza baja (`osint_manage_entity confidence=0.3`) hasta corroborarla con una segunda fuente independiente.
6. **Entrega**: `osint_export_case` con informe de hechos frente a hipótesis y `.mtgx`.
