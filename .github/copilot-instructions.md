# Instrucciones para Agentes de VS Code (GitHub Copilot, Claude Code y equivalentes) — MCP Maltego

Cuando el usuario realice **cualquier petición de investigación OSINT** —incluso si es una petición vaga o en texto claro (por ejemplo: *"investiga example.com"*, *"¿qué hay detrás de este correo?"*, *"analiza la empresa X y dame un informe"*, *"investiga esta IP/alias"*)—, aplica el siguiente protocolo híbrido sin inventar datos y actualizando en tiempo real el Dashboard de Descubrimiento (`maltegoctl dashboard`):

## 1. Flujo Híbrido de Investigación en Tiempo Real (Transforms Activos y Pasivos No Intrusivos Habilitados)
1. **Arranque inmediato con `osint_investigate`**:
   - Invoca `osint_investigate(value="<indicador o petición en texto claro>", reason="<objetivo>")`.
   - Todos los transforms pasivos y activos no intrusivos están activados por defecto (`MALTEGO_MCP_ALLOW_ACTIVE=1`, `MALTEGO_MCP_MODE=active`), con control anti-ráfaga (`CHAIN_CONCURRENCY=3`) y bloqueo de endpoints intrusivos (sin escaneos de puertos activos, sin subidas de ficheros ni peticiones masivas).
   - El servidor deduce automáticamente el indicador y su tipo Maltego, crea el caso, ejecuta la Machine completa correspondiente (`DomainRecon`, `CompanyFootprint`, `InfrastructureRecon`, `EmailRecon`, `URLRecon`, `PersonalFootprint`, `PersonaFootprint`, `ASNToNetblocks`, `CryptoFlowRecon`, `ThreatSweep`), ejecuta el perfilado pericial multidimensional sobre las entidades nucleares y sincroniza en vivo todas las fases **P0 a P9** del Dashboard (Encuadre P0, Semillas Admiralty, Fase 2 Infraestructura y Vigencia, Fase 3 Archivos Web, Fase 6 Brechas, Fase 7 HUMINT con desacoplamiento Heuer, Fase 8 Ecosistema con mitigación de culpa por asociación y Fase 9 Matriz ACH + Síntesis ICD 203).
2. **Profundización multi-salto (Pivotes de alto valor)**:
   - Revisa la tabla de **Siguientes pasos recomendados** (`next_actions`) devuelta por `osint_investigate` o llama a `osint_suggest_next_steps`.
   - Ejecuta los transforms pasivos de mayor puntuación con `osint_run_transform` (indicando siempre `case_id`, `save=True` y `reason`) para ampliar la cobertura multi-clúster.
   - Si descubres actores, dominios u organizaciones clave adicionales, ejecuta sobre ellos `osint_manage_entity(case_id=..., entity_id=..., action="profile")` para incorporar su dictamen pericial de 21 tipologías al grafo y al Dashboard.
3. **Exportación final y cierre pericial**:
   - Si ejecutaste transforms o perfilados adicionales tras `osint_investigate`, invoca `osint_export_case(case_id=..., format="report_html", inline=True)` y `osint_export_case(case_id=..., format="mtgx")` para regenerar los artefactos verificados con sello SHA-256.

## 2. Estándar de Calidad del Informe al Usuario
- **Entrega íntegra**: Muestra siempre al usuario el **Informe Pericial Ejecutivo completo** en Markdown (Portada `TLP:AMBER+STRICT`, `§ 01` Resumen Ejecutivo BLUF y Dictamen Pericial, `§ 02/03` Matrices de Evidencias Consolidadas de 6 columnas, `§ 03B` Perfilado Pericial Multidimensional y Vigencia Objetiva §4.4, `§ 03C` Síntesis Analítica ACH / ICD 203 de Fases P0-P9, `§ 04` Arquitectura Topológica en 9 Tiers y `§ 05-07` Cronología Procedimental + Certificación Criptográfica SHA-256).
- **Cero emojis y neutralización de IOCs**: Mantén el estilo pericial formal sin emojis y con URLs/IOCs neutralizados (`hxxps[://]`, `[.]`).
- **Rutas de entregables y Dashboard**: Indica siempre al final las rutas locales de los ficheros `.html`, `.mtgx` y `.mcpcase` exportados en `~/.maltego-mcp/exports/` y recuerda que el caso está sincronizado en vivo en el Dashboard (`http://127.0.0.1:8000`).
