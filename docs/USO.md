# Uso de MCP Maltego

## Qué hace
Permite que cualquier agente (Gemini, Claude, Codex...) ejecute transforms de Maltego, encadenarlos como una
Machine, guardar los resultados en un grafo por caso, analizarlo y exportarlo.

## Tools (16)

| Tool | Para qué | Escribe |
|---|---|---|
| `osint_list_entity_types` | Tipos de entidad Maltego soportados (y personalizados `prefijo.Nombre`) | no |
| `osint_list_transforms` | Transforms del catálogo, filtrables por tipo de entrada | no |
| `osint_create_case` | Crear caso / actualizar descripción | sí |
| `osint_list_cases` | Listar casos (paginado) | no |
| `osint_get_case_summary` | Recuentos por tipo y entidades más conectadas | no |
| `osint_upsert_entity` | Guardar entidad (normaliza el valor, id determinista, fusiona fuentes) | sí |
| `osint_get_entity` | Detalle de una entidad | no |
| `osint_search_entities` | Buscar por texto/tipo en un caso o en todos (correlación entre casos) | no |
| `osint_link_entities` | Relación dirigida entre entidades | sí |
| `osint_get_neighbors` | Entidades relacionadas | no |
| `osint_find_paths` | Caminos entre dos entidades (hasta 4 saltos) | no |
| `osint_run_transform` | Ejecutar un transform sobre una entidad (opcionalmente sin guardar) | sí |
| `osint_run_transform_chain` | Cadena de transforms tipo Machine, con límites de coste | sí |
| `osint_expand_entity` | Ejecutar todos los transforms aplicables sobre una entidad (como "Run All") | sí |
| `osint_import_graph` | Importar un grafo guardado en Maltego (.mtgx) o un CSV a un caso | sí |
| `osint_export_case` | Exportar a mtgx (se abre en Maltego), json, graphml (Gephi/yEd) o csv | fichero |

`entity_type` admite `"auto"`: detecta correo, URL, IP, rango, hash, AS, teléfono, dominio o frase.

Todas aceptan `response_format` = `markdown` (por defecto) o `json` cuando devuelven datos.

## Configuración (variables de entorno)

| Variable | Por defecto | Descripción |
|---|---|---|
| `MALTEGO_MCP_HOME` | `~/.maltego-mcp` | Carpeta compartida por todos los agentes y worktrees |
| `MALTEGO_MCP_BACKEND` | `memory` | `memory` (local) o `gremlin` (Azure Cosmos DB) |
| `MALTEGO_MCP_DATA_FILE` | `<home>/graph.json` | Persistencia del backend memory; `none` para no guardar |
| `MALTEGO_MCP_TRANSFORMS_FILE` | `<home>/transforms.toml`, si no `config/transforms.toml` | Catálogo de transforms |
| `MALTEGO_MCP_EXPORT_DIR` | `<home>/exports` | Carpeta de exportaciones |
| `MALTEGO_MCP_IMPORT_DIR` | `<home>/imports` | Única carpeta (junto a exports) desde la que se importa |
| `GREMLIN_ENDPOINT` | — | `wss://<cuenta>.gremlin.cosmos.azure.com:443/` |
| `GREMLIN_USERNAME` | — | `/dbs/<base>/colls/<grafo>` |
| `GREMLIN_PASSWORD` | — | Clave de la cuenta (desde Key Vault o variable de entorno) |

En Windows, `<home>` es `C:\Users\<usuario>\.maltego-mcp`. Integración con Maltego Desktop: `docs/MALTEGO.md`.

## Transforms

1. Los servidores TRX/iTDS no publican su lista de transforms: se declaran en `~/.maltego-mcp/transforms.toml`
   (copia `config/transforms.example.toml`).
2. Ruta de cada transform: por defecto, el nombre en minúsculas con `_` → `-` (convención de maltego-trx:
   `DNSToIP` → `/run/dnstoip/`). Se puede fijar con `path`.
3. El agente solo puede ejecutar transforms del catálogo; nunca indica URLs (protección SSRF).
4. Claves de API: `api_key_env = "VARIABLE"` en el servidor → cabecera `Authorization: Bearer ...`.

### Servidor de ejemplo (sin APIs de pago)
```
uv run python examples/trx_server/server.py          # http://127.0.0.1:8080
cp config/transforms.example.toml ~/.maltego-mcp/transforms.toml
```
Incluye `EmailToDomain`, `EmailToHandle`, `URLToDomain`, `DomainToWebsite` y `DomainToIP` (DNS real).
Sirve de plantilla para escribir transforms propios con maltego-trx; los mismos transforms se pueden
registrar en Maltego Desktop.

Prueba rápida desde un agente:
```
Crea el caso demo y ejecuta la cadena EmailToDomain, DomainToWebsite, DomainToIP sobre ana@example.com.
Luego dame el resumen del caso y expórtalo a csv.
```

## Backends del grafo
- **memory** (por defecto): verificado con tests y de punta a punta. Guarda todo el grafo en un JSON en cada
  escritura; pensado para uso local y casos de tamaño moderado (miles de entidades).
- **gremlin** (Cosmos DB): `uv sync --extra gremlin`. Consultas de texto con bindings (sin bytecode), partición
  `pk` = case_id, reintentos ante 429. **Pendiente de validar contra una cuenta real de Cosmos DB**: los tests
  usan un ejecutor simulado que comprueba plantillas, bindings y parseo, pero no la sintaxis en el servidor.

## Seguridad
- Valores OSINT tratados como no confiables: limpieza de caracteres de control, truncado, mostrados como código
  y aviso en cada respuesta con datos.
- XML de transforms parseado con defusedxml (bloquea XXE y "billion laughs"); respuestas limitadas a 5 MB y
  1000 entidades.
- CSV protegido contra inyección de fórmulas.
- HTTP fuera de localhost bloqueado salvo `--allow-remote-unauthenticated` (aún no hay autenticación).

## Pendiente
- Validar el backend gremlin contra Cosmos DB real.
- Validar `.mtgx` y transforms locales en Maltego Desktop real (formato contrastado con dos implementaciones de la comunidad).
- Autenticación (Entra ID) para el modo HTTP remoto.
- Trabajos asíncronos vía Service Bus para cadenas largas.
