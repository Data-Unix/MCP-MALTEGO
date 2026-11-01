# PLAN — MCP Maltego

> **Documento histórico** de la planificación inicial (v0.1). Estado actual: `docs/COBERTURA.md`. Agentes y skills
> actuales: `.agents/` (ver `AGENTS.md`). Los agentes citados abajo eran genéricos y se retiraron en la v0.2.

Estado: **v1 implementada** (14 tools, backends memory y gremlin, transforms TRX/iTDS y cadenas). Detalle y pendientes en `docs/USO.md`. Base metodológica: skill `mcp-builder` (Anthropic) — fases 1-4.

## 0. Decisiones clave

| Tema | Decisión | Motivo |
|---|---|---|
| Lenguaje | **Python 3.12 + FastMCP (SDK oficial `mcp`)** | Toda la pila es Python: Maltego TRX / maltego-transforms, `gremlinpython`, Azure Functions v2. La skill recomienda TS por defecto, pero aquí compartir código con Functions y transforms pesa más. |
| Transporte | stdio (local) + Streamable HTTP **stateless JSON** (remoto) | Gemini CLI y Claude Code soportan ambos. SSE está obsoleto. |
| Hosting remoto | Azure Container Apps (o Functions Flex Consumption) con Managed Identity | Escalado a cero y acceso a Cosmos/Key Vault sin secretos. |
| Acceso al grafo | `gremlin_python.driver.client.Client.submit(query, bindings)`, GraphSON v2 | Cosmos DB Gremlin **no soporta bytecode/traversals fluidos**. Bindings = anti-inyección. |
| Ingesta | Event Hubs / Service Bus → Azure Functions (Python v2) → Cosmos Gremlin; ficheros crudos en Blob | Según las fuentes de arquitectura. El MCP **lee y encola**, no hace ingesta masiva. |
| Maltego | Capa adaptadora: TRX/iTDS invoca la misma librería de dominio que el MCP | Una sola lógica, dos fachadas (Maltego y MCP). Verificar que se usa el SDK actual `maltego-transforms` en lugar de TRX legado. |

## 1. Arquitectura (capas)

```
src/maltego_mcp/
  domain/        # entidades, normalización, mapeo Maltego<->grafo (sin I/O)
  graph/         # cliente Cosmos Gremlin: catálogo de queries parametrizadas, retries 429, RU logging
  sources/       # conectores OSINT (APIs), cada uno con rate limit + timeout + caché
  pipeline/      # publicación a Event Hubs/Service Bus (jobs asíncronos)
  mcp/server.py  # FastMCP: tools finas que llaman a domain/graph/pipeline
  mcp/schemas.py # modelos Pydantic PLANOS + validador de portabilidad
functions/       # Azure Functions v2 (triggers Event Hub/Service Bus/Blob/HTTP)
maltego/         # transforms TRX/iTDS que reutilizan domain/ y graph/
infra/           # Bicep + GitHub Actions (OIDC)
evals/           # evaluaciones XML + runner multi-proveedor (Claude y Gemini)
tests/
```

## 2. Catálogo de tools (v1, ≤ 20)

Lectura (`readOnlyHint=true`, `idempotentHint=true`):
1. `osint_search_entities(query, entity_type="any", case_id="", limit=20, offset=0, response_format="markdown")`
2. `osint_get_entity(entity_id, include_properties=true)`
3. `osint_get_neighbors(entity_id, edge_label="any", direction="both", limit=25)`
4. `osint_find_paths(source_id, target_id, max_depth=3, limit=5)` — `max_depth` acotado 1..4
5. `osint_list_cases(limit=20, offset=0)`
6. `osint_get_case_summary(case_id)` — conteos por tipo, entidades más conectadas
7. `osint_list_entity_types()` — tabla de mapeo Maltego
8. `osint_get_job_status(job_id)`

Escritura (`readOnlyHint=false`, `destructiveHint=false`, `idempotentHint=true` por ids deterministas):
9. `osint_upsert_entity(entity_type, value, case_id, source, confidence=0.5)`
10. `osint_link_entities(source_id, target_id, edge_label, case_id, source)`
11. `osint_enqueue_enrichment(entity_id, transform, case_id)` → `job_id` (asíncrono vía Service Bus, `openWorldHint=true`)

Exportación:
12. `osint_export_case(case_id, format="graphml")` — escribe en Blob y devuelve URL SAS de corta duración (o MTGL para Maltego)

Sin tools destructivas en v1 (borrado solo por pipeline administrativo).

## 3. Compatibilidad multi-modelo (Gemini incluido)

Problemas reales documentados: el validador de Gemini acepta un subconjunto OpenAPI de JSON Schema y devuelve 400 con `exclusiveMinimum`, `anyOf`, `additionalProperties`, `$ref` etc. Pydantic los genera por defecto (`Optional[X]` → `anyOf`, `Field(gt=0)` → `exclusiveMinimum`, modelos anidados → `$defs`).

Medidas:
- Parámetros como argumentos planos de la función con valores por defecto; `Literal[...]` para enums; `Field(ge=, le=)` (no `gt/lt`).
- Hook que post-procesa el `inputSchema` de cada tool y elimina/aplana claves no portables + test que falla si aparecen.
- Descripciones ≤ 1024 caracteres, sin depender de que el cliente lea `outputSchema`.
- Siempre `TextContent`; `structuredContent` como extra.
- Probar con: MCP Inspector, Claude Code, **Gemini CLI** (`~/.gemini/settings.json` → `mcpServers`), y `google-genai` SDK (que acepta una `ClientSession` MCP como tool).
- El `evaluation.py` de la skill usa solo Anthropic → añadir `evals/run_gemini.py` con el mismo XML para comparar tasa de acierto entre modelos.

## 4. Seguridad y cumplimiento

- Prompt injection indirecta: el contenido OSINT (bios, páginas web, WHOIS) se devuelve marcado como dato y truncado; nunca se usa para decidir llamadas.
- Auth remota: Entra ID (OAuth 2.1) delante del endpoint HTTP; validar audiencia del token. Local: sin red.
- Managed Identity para Cosmos (RBAC de plano de datos si está disponible para Gremlin; si no, clave en Key Vault).
- Rate limit por usuario y presupuesto de RU por llamada; `limit` máximo 100.
- RGPD: datos personales → base legal, minimización, retención por `case_id`, registro de auditoría de consultas.
- Agentes de apoyo: `threat-modeling-expert` (STRIDE del flujo MCP→Gremlin) y `security-auditor` antes de desplegar.

## 5. Fases

| Fase | Entregable | Agente(s) |
|---|---|---|
| 1 Investigación | Validar fuentes pendientes (sección 7), modelo de grafo + partition key | `osint-graph-modeler`, `cloud-architect` |
| 2 Núcleo | `domain/`, `graph/` con tests (Gremlin simulado + emulador/cuenta dev) | `python-pro`, skills `async-python-patterns`, `python-resilience` |
| 3 MCP | `server.py`, tools 1-8, test de portabilidad de esquemas | `mcp-developer`, skill `mcp-builder` |
| 4 Escritura + pipeline | tools 9-12, Functions, colas | `data-engineer` |
| 5 Infra | Bicep + GitHub Actions OIDC | `azure-infra-engineer` |
| 6 Calidad | pytest + Inspector + 10 evals XML en Claude **y** Gemini | `test-automator`, `security-auditor` |

Criterio de "hecho" v1: los 10 evals con ≥ 80 % de acierto en ambos proveedores y cero errores 400 de esquema en Gemini.

## 6. Agentes y skills

Sustituidos en la v0.2 por agentes y skills propios del proyecto con fuente única en `.agents/` y copias para
cada herramienta (`scripts/sync_agents.py`). Ver `AGENTS.md`.

## 7. Fuentes: a verificar / añadir

La lista recibida llegó truncada en el bloque Maltego. Fuentes fundamentales que faltaban en lo visible:
- Especificación MCP (versión vigente) y README del Python SDK oficial.
- Documentación de Gemini CLI sobre servidores MCP y del esquema de *function declarations* de Gemini.
- Diferencias de Cosmos DB Gremlin con TinkerPop (sin bytecode, pasos no soportados) — ya está en la lista; es crítica.
- Extensión MCP de Azure Functions (alternativa de hosting).
- OWASP Top 10 para aplicaciones LLM (prompt injection indirecta).
- Estado del producto Cosmos DB for Gremlin: no encontré anuncio de retirada, pero Microsoft empuja alternativas (Fabric Graph). Confirmar antes de comprometerse a largo plazo.
- Estado de Maltego TRX frente a `maltego-transforms` (SDK actual).
