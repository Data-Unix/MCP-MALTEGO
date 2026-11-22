# Uso de MCP Maltego

## Qué hace
Permite que cualquier agente (Gemini, Claude, Codex...) ejecute transforms de Maltego, encadenarlos como una
Machine, guardar los resultados en un grafo por caso, analizarlo y exportarlo.

## Tools (20)

| Grupo | Tool | Para qué |
|---|---|---|
| Catálogo | `osint_list_entity_types` | 41 tipos de entidad estándar por categoría (más `humint.*`, cripto/AML e importados de tu Maltego) |
| | `osint_list_transforms` | 63 transforms integrados, 16 Machines, proveedores configurados y estado de servidores |
| Casos | `osint_manage_case` | Crear (`create`), bifurcar/delegar (`fork`/`delegate`), fusionar (`merge`) o borrar (`delete` + `confirm`) |
| | `osint_list_cases` | Listado paginado |
| | `osint_get_case_summary` | Recuentos, entidades prioritarias e índices de calidad |
| Entidades | `osint_upsert_entity` | Crear o fusionar (normaliza, id determinista, notas) |
| | `osint_manage_entity` | Editar confianza, notas o propiedades; `visual_style`; `analyze_behavior`; **Perfilado Pericial Multidimensional de 21 tipologías** (`profile`); generación de identidades operativas (`generate_persona`); borrar |
| | `osint_get_entity` | Detalle, puntuación explicada, procedencia y transforms pendientes |
| | `osint_search_entities` | Búsqueda en un caso o entre casos; orden por prioridad |
| Relaciones | `osint_link_entities` | Relacionar (`link`), quitar relación (`unlink`), analizar rol/peso HUMINT (`analyze`) o correlacionar identidades (`correlate`) |
| | `osint_get_neighbors` | Vecinos con dirección y tipo de relación |
| | `osint_find_paths` | Caminos entre dos entidades (hasta 6 saltos) |
| Transforms | `osint_run_transform` | Un transform (integrado, de proveedor, plugin o TRX/iTDS) con emisión de eventos en vivo al dashboard |
| | `osint_expand_entity` | Todos los transforms aplicables ("Run All") con concurrencia controlada (`CHAIN_CONCURRENCY = 3`) |
| | `osint_run_machine` | 16 Machines predefinidas/propias o cadena ad hoc, con rondas y presupuestos |
| Copiloto | `osint_investigate` | Todo en una llamada (admite valores directos o peticiones en texto claro / vagas): extrae la semilla, crea el caso, ejecuta la Machine y pivotes activos/pasivos no intrusivos, sincroniza en tiempo real el dashboard (P0–P9, ACH/ICD 203 y perfiles de 21 tipologías), auto-exporta `report_html` + `.mcpcase` y devuelve el **Informe Pericial Ejecutivo Completo** |
| | `osint_suggest_next_steps` | Siguiente mejor acción, determinista, con rendimiento histórico |
| | `osint_get_timeline` | Memoria procedimental del caso (`steps`) o línea de vida y anomalías del sujeto (`subject`); sondeo incremental con `since_seq` |
| Intercambio | `osint_export_case` | `mtgx` (con layout y memoria), `mcpcase` (paquete nativo sellado con SHA-256), `json`, `graphml`, `csv`, `report_md`, `report_html` |
| | `osint_import_graph` | Importar `.mtgx`, `.mcpcase` (con memoria) o CSV a un caso |

`entity_type` admite `"auto"`. Las acciones aceptan `reason`, que queda en la memoria del caso.
Matriz completa de funciones y verificación: `docs/COBERTURA.md`.

## Transforms integrados (63)
- **Sin API key (51):**
  - *DNS sobre HTTPS y pDNS (9):* `DNSToIP`, `DNSToIPv6`, `DomainToMX`, `DomainToNS`, `DomainToTXT`, `DNSToCNAME`, `IPToReverseDNS`, `HackerTargetSubdomains`, `AnubisSubdomains`.
  - *WHOIS / RDAP y Registros Oficiales (4):* `DomainToWhois`, `IPToWhois` (RDAP con respaldo ARIN), `BOEEntityToRecords` (BOE/BORME), `GLEIFCompanyToStructure` (GLEIF LEI).
  - *Certificados, Web y Archivos Históricos (8):* `DomainToSubdomains` (crt.sh con respaldo CertSpotter), `CertSpotterSubdomains`, `CTOrgToCertificates`, `URLScanDomainSearch`, `WaybackCDXSearch`, `WaybackSnapshotExtract`, `ArquivoCDXSearch`, `CommonCrawlCDXSearch`.
  - *Red, BGP y Exposición (6):* `IPToAS`, `IPToNetblock` (Team Cymru), `IPToPassiveContext`, `RIPEStatASNToNetblocks`, `InternetDBIPToServices` (Shodan InternetDB), `CisaKevToVulnerabilities` (CISA KEV).
  - *Identidad, Redes Sociales y HUMINT (8):* `AliasToProfiles`, `SocialAliasDeepRecon`, `GitHubAliasToDetails`, `GitHubAliasToCommitEmails`, `KeybaseAliasToProofs`, `GravatarEmailToProfile`, `EmailToAlias`, `AnalyzeSubjectBehavior`.
  - *Filtraciones, Fugas y Amenazas CTI (7):* `BreachSemanticPivot`, `HudsonRockStealerCheck`, `GitHubDomainToLeaks`, `UrlhausHostToThreats` (Abuse.ch URLhaus), `OTXHashToThreatPulses` (AlienVault OTX), `DeepDarkCTISearch`, `OnionPassivePivot`.
  - *Criptoforense y AML Blockchain (5):* `MempoolAddressToTransactions`, `MempoolTxToInputsOutputs`, `CryptoClusteringCIOH`, `OFACSanctionsCryptoLookup`, `CryptoAddressToExchange`.
  - *Análisis estructural local (4):* `EmailToDomain`, `URLToDomain`, `WebsiteToDomain`, `DomainToWebsite`.
- **Con API key (12)** (define la variable de entorno o guárdala en `~/.maltego-mcp/.env` y se activan solos):
  `VIRUSTOTAL_API_KEY` (`VTDomainToIP`, `VTIPToDomain`, `VTDomainToSubdomains`, `VTHashToDetection`),
  `SHODAN_API_KEY` (`ShodanIPToServices`, `ShodanDomainToSubdomains`), `SECURITYTRAILS_API_KEY` (`SecurityTrailsSubdomains`),
  `HUNTER_API_KEY` (`HunterDomainToEmails`), `GREYNOISE_API_KEY` (`GreyNoiseIPContext`),
  `TATUM_API_KEY` (`TatumBTCAddressToTx`), más `CENSYS_API_ID` + `CENSYS_API_SECRET` (`CensysIPToServices`) y
  `HIBP_API_KEY` (`HIBPEmailToBreaches`). El fichero `~/.maltego-mcp/.env` vive fuera del repositorio y lo leen
  automáticamente todos los agentes (Orca, VS Code, Claude, Gemini, Codex, Cursor...) y el puente de Maltego Desktop.

## Machines (16 predefinidas)
- **Activas + Pasivas no intrusivas (11):** `DomainRecon`, `InfrastructureRecon`, `EmailRecon`, `CompanyFootprint`,
  `PersonalFootprint`, `PersonaFootprint`, `URLRecon`, `ThreatSweep`, `ASNToNetblocks`, `DarkWebFootprint` y `CryptoFlowRecon`.
- **Modo Pasivo Estricto (5):** `PassiveDomainRecon`, `PassiveInfrastructureRecon`, `PassiveEmailRecon`,
  `PassiveURLRecon` y `PassiveCompanyFootprint`.
- Las propias se declaran en el catálogo:
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
| `MALTEGO_MCP_ALLOW_ACTIVE` | `1` (en configs de agentes y `.env`) | Habilita todos los transforms activos y pasivos no intrusivos con concurrencia controlada (`CHAIN_CONCURRENCY = 3`) |
| `MALTEGO_MCP_MODE` | `active` (con `ALLOW_ACTIVE=1`) / `passive` | Modo operativo de transforms (`active` o `passive` estricto) |
| `MALTEGO_MCP_REQUIRE_MULLVAD` | `1` | Anillo Mullvad obligatorio: todo el egreso del MCP sale por el proxy interno del túnel tras la atestación doble. `0` lo desactiva de forma consciente |
| `MALTEGO_MCP_MULLVAD_SOCKS` | `socks5h://10.64.0.1:1080` | Proxy del anillo; solo admite proxies internos de Mullvad (10.64.0.1 o 10.124.x.x, puerto 1080) |
| `MALTEGO_MCP_MULLVAD_ATTEST_TTL` | `30` | Segundos que vale una atestación (5-300) |
| `MALTEGO_MCP_MULLVAD_REMOTE_CHECK` | `1` | Comprobación remota en am.i.mullvad.net a través del túnel |
| `MALTEGO_MCP_MULLVAD_ISOLATION` | `off` | `per_provider`: cada proveedor sale por un relay propio fijo (SOCKS por relay) |
| `MALTEGO_MCP_DASHBOARD_AUTH` | `1` | Autenticación de sesión PBKDF2-HMAC-SHA256 (600.000 iteraciones) + CSRF en el panel web |
| `MALTEGO_MCP_DASHBOARD_USER` | `admin` | Usuario del panel web local |
| `MALTEGO_MCP_DASHBOARD_PASSWORD_HASH` | — | Hash PBKDF2-HMAC-SHA256 de la contraseña del panel web |

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

### Plugins comunitarios en Python (sin servidor externo)
Puedes añadir tus propios transforms colocando scripts Python en `~/.maltego-mcp/plugins/*.py` o en `./plugins/*.py`.
El servidor los descubre automáticamente en el arranque sin tocar el código fuente:

```python
from maltego_mcp.transforms.plugins import custom_transform, result_entity, transform_response


@custom_transform(
    name="DomainToCustomData",
    input_types=("maltego.Domain",),
    output_types=("maltego.Phrase",),
    description="Extrae inteligencia personalizada para un dominio",
    category="comunidad",
)
async def mi_transform(ctx, etype, value, props, limit):
    return transform_response([result_entity("maltego.Phrase", f"Intel: {value}", label="custom_intel")])
```

Prueba rápida desde un agente:
```
Crea el caso demo y ejecuta la cadena EmailToDomain, DomainToWebsite, DomainToIP sobre ana@example.com.
Luego dame el resumen del caso y expórtalo a csv.
```

## Consola Web y Visualizador de Grafos OSINT (`maltegoctl dashboard`)

Inicia la consola de control interactiva local con aceleración gráfica:

```bash
uv run maltegoctl dashboard --port 8000
```

### Capacidades del Visualizador de Grafos en Vivo:
- **Disposiciones Espaciales Multimodales (Layouts)**:
  - *Orgánico (Fuerzas físicas de Fruchterman-Reingold)*: simulación elástica con amortiguamiento.
  - *Jerárquico (Piramidal Top-Down)*: entidad objetivo y dictámenes arriba, proveedores e intermediarios en medio, evidencias y campañas abajo.
  - *Radial (Órbitas concéntricas)*: distribución por saltos de distancia topológica.
  - *Por Categoría (Bloques espaciales)*: agrupación por familias de entidades (Empresas, Redes, Personas, Amenazas, Ubicaciones).
- **Filtrado Multidimensional**:
  - *Filtrado por Relaciones (Aristas)*: selector selectivo de tipos de aristas con contadores en vivo (`owns`, `operates`, `resolves_to`, `hosts`, etc.).
  - *Filtrado por Familias de Entidades*: selección granular de tipos de nodo.
  - *Certeza Continua (0% - 100%)*: deslizador para aislar evidencias confirmadas de meros indicios.
  - *Distancia Topológica (Ego-Network / Hops)*: filtro por 1 salto (perímetro inmediato), 2 saltos o grafo completo.
  - *Ocultación de Nodos Huérfanos*: depura el lienzo eliminando entidades desconectadas.
  - *Buscador Reactivo en Tiempo Real*: caja de búsqueda con autoenfoque y centrado suave de cámara.
- **Renderizado Impeccable de Alta Fidelidad**:
  - Glifos vectoriales geométricos dentro de los nodos según su tipo (edificio, servidor, avatar, pin, triángulo de alerta, globo terráqueo).
  - Anillo perimetral de confianza radial (*Confidence Ring*) que visualiza el grado de certeza perimetral.
  - Aristas con curvas cuadráticas Bézier automáticas para conexiones paralelas y bidireccionales.
  - Modo de enfoque (*Focus Mode*): atenuación de nodos y enlaces no conectados al pasar el cursor o seleccionar.
  - Micro-tarjeta flotante (*Tooltip*) con información de inteligencia al vuelo.
- **Bóveda de Cuentas, Sock Puppets & Buzones Efímeros**:
  - Modal y panel categorizado para **Redes Sociales** (Twitter/X, Telegram, Discord, Reddit, Bluesky, Mastodon, LinkedIn, VK, Session), **Foros Ciber & Underground** (BreachForums, Exploit.in, XSS.is, Dread .onion, RaidForums, Nulled, Cracked, RAMP) y **Mercados Dark Web & Leaks** (IntelX, Russian Market, 2easy, DeHashed, Leak-Lookup, Snusbase, DnmX).
  - Soporte integrado para Cookies de sesión de foros/mercados (`xf_user`, `xf_session`), claves API y botón de 1 clic para enrutamiento Tor SOCKS5 local (`socks5h://127.0.0.1:9050`).
  - Filtro dinámico multidimensional en la bóveda (`[Todas]`, `[🌐 Redes Sociales]`, `[💀 Foros Ciber]`, `[🛒 Mercados & Leaks]`, `[✉️ Buzones]`) y buscador en tiempo real.
  - Generador de buzones temporales con `Mail.tm` sin registro previo.
  - Extractor automático de códigos 2FA/OTP y enlaces de activación por regex multilingüe.
  - Catálogo OPSEC con 10 proveedores clasificados por nivel de privacidad (*Proton Mail, Tuta, Disroot, Onionmail, Addy.io, SimpleLogin*, etc.).

## Anillo de egreso Mullvad (obligatorio)

Todas las consultas del MCP (agentes y panel) salen **solo** por Mullvad VPN, con servidores **propios** de Mullvad
y **online**. Hay dos anillos:

1. **Anillo 1 (sistema)**: la app de Mullvad con bloqueo sin VPN (lockdown), conexión automática, sin split
   tunnel y selección de relays propios (`mullvad relay set ownership owned` y `mullvad lockdown-mode set on`).
   Protege también las herramientas web nativas de los agentes y el websocket de Gremlin, que no pasan por el MCP.
2. **Anillo 2 (MCP, fail-closed)**: cada petición HTTP sale por `socks5h://10.64.0.1:1080`, un proxy que solo
   existe dentro del túnel, y solo si la **atestación doble** está al día:
   - daemon (`mullvad status -j` y `lockdown-mode get`): conectado, bloqueo activo, entrada y salida propias;
   - remota (`am.i.mullvad.net` por el propio proxy): `mullvad_exit_ip` y, si viene, el hostname de salida
     coincide con el del daemon y es propio.

   Si falla cualquier comprobación, la petición se aborta sin tocar la red (`EgressKillSwitchError`) y queda en el
   `audit.log` encadenado. Las peticiones permitidas registran el perfil efectivo con el relay atestado
   (`mullvad:se-sto-wg-001`). Loopback (TRX local, Tor local) no sale de la máquina y no necesita atestación.

Detalles:
- El binario de Mullvad se ejecuta desde su ruta fija, con la firma Authenticode "Mullvad VPN AB" verificada,
  argv en lista, sin shell y con una allowlist (`status`, `lockdown-mode get`, `connect`, `disconnect`,
  `reconnect`, `relay set location <host>`, `relay set entry location <host>`). Nunca se exponen lockdown off,
  cuenta, split tunnel, ownership any, relay custom, api-access ni DNS.
- La lista de relays propios arranca con una instantánea empaquetada (`src/maltego_mcp/resources/`), se refresca cada
  hora desde la API de Mullvad a través del túnel y se guarda en `<home>/mullvad_owned_relays.json`.
- La salida de `status -j` incluye la IP real y la geolocalización cuando el túnel está caído: se descartan al
  parsear y nunca llegan al panel ni a los logs.
- Guardián PEP 578 estricto (solo en `maltego-mcp` y `maltegoctl dashboard`): además de bloquear DNS no
  autorizado, rechaza cualquier `socket.connect` que no sea a loopback, a un proxy interno de Mullvad o a un
  endpoint declarado (Gremlin). En Windows se usa el bucle `SelectorEventLoop`, porque el Proactor conecta con
  `ConnectEx` sin emitir el evento de auditoría.
- Overrides por proveedor (`MALTEGO_MCP_EGRESS_PER_PROVIDER`) solo admiten `mullvad` o `tor`; `direct`/`vpn` se
  rechazan. `MALTEGO_MCP_EGRESS=direct|vpn` se eleva a `mullvad` con aviso.
- El perfil `vpn` sin `MALTEGO_MCP_EGRESS_PROXY` ahora **bloquea** (antes salía directo en silencio).
- Gremlin abre su propio websocket y no pasa por el proxy del anillo: depende del Anillo 1.
- Las herramientas web nativas de los agentes (WebFetch, WebSearch…) no pasan por el MCP: con el Anillo 1 activo
  salen por el túnel; si quieres que toda la investigación pase por el anillo del MCP, deniégalas en la
  configuración de permisos de cada agente.

### Control desde el Centro de Mando
El panel principal del dashboard responde a "¿puedo investigar ahora sin exponerme?". Muestra el estado atestado
por el servidor (nunca la IP real), la ruta entrada → salida, seis comprobaciones y una acción principal:
- **Conectar**: sin reautenticación (aumenta la protección).
- **Desconectar…** y **Cambiar servidor de salida/entrada…**: piden la contraseña del operador (válida 5 min).
  Desconectar **bloquea**; nunca pasa a salida directa. El MCP cierra su compuerta antes de tocar el túnel.
- Una operación a la vez (409), CSRF y Origin en cada POST, y cada acción queda en el `audit.log` como
  `vpn_control` con operador, estado anterior y posterior.
- El control solo existe con autenticación activa y escuchando en loopback. Con `--allow-remote-unauthenticated`,
  un host no loopback o `MALTEGO_MCP_DASHBOARD_AUTH=0`, la vista es de solo lectura.
- Los agentes no pueden controlar la VPN: no hay tool MCP para ello.

API: `GET /api/egress/ring`, `GET /api/egress/ring/relays`, `POST /api/egress/ring/connect`,
`POST /api/egress/ring/disconnect`, `POST /api/egress/ring/relay` (`{"role": "exit"|"entry", "hostname": ...}`)
y el evento SSE `egress_ring`.

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
- Egreso obligatorio por Mullvad con relays propios y atestación doble (ver "Anillo de egreso Mullvad").

## Pendiente
- Validar el backend gremlin contra Cosmos DB real.
- Validar `.mtgx` y transforms locales en Maltego Desktop real (formato contrastado con dos implementaciones de la comunidad).
- Autenticación (Entra ID) para el modo HTTP remoto.
- Trabajos asíncronos vía Service Bus para cadenas largas.
