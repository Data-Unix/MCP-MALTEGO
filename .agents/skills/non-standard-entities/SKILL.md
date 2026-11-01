---
name: non-standard-entities
description: Cómo representar en el grafo conceptos fuera de la ontología estándar de Maltego (reglas SIEM, firmas, técnicas ATT&CK, casos, tickets) con Phrase prefijada, tipos propios prefijo.Nombre u ontología importada de tu Maltego. Úsala al modelar datos que no son dominio, IP, correo, etc.
license: MIT
---
# Entidades no estándar

Elige, de más simple a más rico:

1. **`maltego.Phrase` con prefijo de categoría** (siempre compatible y legible en Maltego):
   `[MI-PROYECTO] Caso #102`, `[SIEM regla 4711] Login anómalo`, `[ATT&CK T1059] Command and Scripting`.
   Mantén el formato `[CATEGORÍA identificador] descripción` para poder buscar con `osint_search_entities`.
2. **Tipo propio `prefijo.Nombre`** (p. ej. `acme.Ticket`): el MCP lo acepta sin declararlo; en el `.mtgx` su valor
   va en `properties.<nombre>`. Úsalo si en Maltego tienes esa entidad definida.
3. **Ontología importada**: exporta tu configuración desde Maltego (`Import | Export → Export Config`) y ejecuta
   `npx mcp-maltego ctl import-entities config.mtz`; el MCP usará tus ids y propiedades exactos y el puente creará
   transforms locales para esos tipos.

Consulta lo disponible con `osint_list_entity_types` y revisa un `.mtgx` con `maltegoctl inspect` (avisa de tipos
desconocidos).
