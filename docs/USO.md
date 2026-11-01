# Uso de MCP Maltego

## Qué hace
Permite que cualquier agente (Gemini, Claude, Codex...) ejecute transforms de Maltego, encadenarlos como una
Machine, guardar los resultados en un grafo por caso, analizarlo y exportarlo.

## Tools (20)

| Grupo | Tool | Para qué |
|---|---|---|
| Catálogo | `osint_list_entity_types` | Ontología por categoría (estándar + importada de tu Maltego) |
| | `osint_list_transforms` | Transforms, Machines, proveedores configurados y estado de servidores |
| Casos | `osint_manage_case` | Crear, fusionar (`merge`) o borrar (`delete` + `confirm`) |
| | `osint_list_cases` | Listado paginado |
| | `osint_get_case_summary` | Recuentos, entidades prioritarias e índices de calidad |
| Entidades | `osint_upsert_entity` | Crear o fusionar (normaliza, id determinista, notas) |
| | `osint_manage_entity` | Editar confianza, notas o propiedades; borrar |
| | `osint_get_entity` | Detalle, puntuación explicada, procedencia y transforms pendientes |
| | `osint_search_entities` | Búsqueda en un caso o entre casos; orden por prioridad |
| Relaciones | `osint_link_entities` | Relacionar (`link`) o quitar relación (`unlink`) |
| | `osint_get_neighbors` | Vecinos con dirección y tipo de relación |
| | `osint_find_paths` | Caminos entre dos entidades (hasta 6 saltos) |
| Transforms | `osint_run_transform` | Un transform (integrado, de proveedor o TRX/iTDS) |
| | `osint_expand_entity` | Todos los transforms aplicables ("Run All") |
| | `osint_run_machine` | Machines predefinidas/propias o cadena ad hoc, con rondas y presupuestos |
| Copiloto | `osint_investigate` | Todo en una llamada: tipo, caso, Machine, puntuación, recomendaciones |
| | `osint_suggest_next_steps` | Siguiente mejor acción, determinista, con rendimiento histórico |
| | `osint_get_timeline` | Memoria del caso; sondeo de novedades con `since_seq` |
| Intercambio | `osint_export_case` | mtgx (con layout y memoria), json, graphml, csv, report_md, report_html |
| | `osint_import_graph` | Importar `.mtgx` (con memoria) o CSV a un caso |

`entity_type` admite `"auto"`. Las acciones aceptan `reason`, que queda en la memoria del caso.
Matriz completa de funciones y verificación: `docs/COBERTURA.md`.

## Transforms integrados
- **Sin API key (26):** DNSToIP, DNSToIPv6, DomainToMX, DomainToNS, DomainToTXT, DNSToCNAME, IPToReverseDNS (DNS sobre
  HTTPS), HackerTargetSubdomains, DomainToWhois, IPToWhois (RDAP con respaldo ARIN), DomainToSubdomains (crt.sh con
  respaldo CertSpotter), CertSpotterSubdomains, URLScanDomainSearch, IPToAS, IPToNetblock (Team Cymru),
  RIPEStatASNToNetblocks, InternetDBIPToServices (Shodan InternetDB), AliasToProfiles (GitHub, GitLab, Hacker News,
  Keybase, DEV), GitHubAliasToDetails, GravatarEmailToProfile, OTXHashToThreatPulses (AlienVault OTX), EmailToDomain,
  EmailToAlias, URLToDomain, WebsiteToDomain, DomainToWebsite.
- **Con API key** (define la variable de entorno o guárdala en `~/.maltego-mcp/.env` y se activan solos):
  `VIRUSTOTAL_API_KEY`, `SHODAN_API_KEY`, `SECURITYTRAILS_API_KEY`, `HUNTER_API_KEY`, `GREYNOISE_API_KEY`,
  `TATUM_API_KEY` (todos con capa gratuita / Community sin suscripción de pago), más `CENSYS_API_ID` +
  `CENSYS_API_SECRET` y `HIBP_API_KEY`. El fichero `~/.maltego-mcp/.env` vive fuera del repositorio y lo leen
  automáticamente todos los agentes (Orca, Claude, Gemini, Codex, Cursor...) y el puente de Maltego Desktop.

## Machines
DomainRecon, InfrastructureRecon, EmailRecon, CompanyFootprint, PersonalFootprint y URLRecon. Las propias se
declaran en el catálogo:
```toml
[[machines]]
name = "MiRecon"
input_types = ["maltego.Domain"]
stages = [["DNSToIP", "DomainToNS"], ["IPToAS"]]
rounds = 1
```

## maltegoctl (terminal / CI)
```
uv run maltegoctl inspect grafo.mtgx          # valida un .mtgx
uv run maltegoctl lookup DomainToMX gmail.com # consulta rápida sin guardar
uv run maltegoctl transforms --type maltego.Domain
uv run maltegoctl import-entities config.mtz  # ontología exacta de tu Maltego
uv run maltegoctl export demo --format report_html
uv run maltegoctl mtz                         # transforms locales para Maltego
```

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
