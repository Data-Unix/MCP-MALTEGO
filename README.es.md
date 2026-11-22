<h1 align="center">mcp-maltego</h1>

<p align="center">
  <strong>Maltego OSINT para agentes de IA.</strong><br>
  Ejecuta transforms y Machines, construye y analiza grafos de relaciones y devuelve el resultado a Maltego como
  <code>.mtgx</code> nativo, desde Claude, Gemini, Codex, Copilot, Cursor o cualquier cliente MCP.
</p>

<p align="center">
  <img src="docs/assets/banner.jpg" alt="MCP-MALTEGO — Model Context Protocol Intelligence Graph Integration" width="100%">
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/mcp-maltego"><img alt="npm" src="https://img.shields.io/npm/v/mcp-maltego?logo=npm"></a>
  <a href="https://github.com/Data-Unix/MCP-MALTEGO/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Data-Unix/MCP-MALTEGO/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="Licencia: MIT" src="https://img.shields.io/badge/licencia-MIT-green"></a>
  <img alt="Maltego CE" src="https://img.shields.io/badge/Maltego-Community%20Edition%20Compatible-orange">
  <img alt="Cero Coste" src="https://img.shields.io/badge/Plan-100%25%20Libre%20y%20Gratuito-brightgreen">
  <img alt="MCP" src="https://img.shields.io/badge/MCP-servidor-8A2BE2">
  <a href="https://registry.modelcontextprotocol.io/v0/servers?search=mcp-maltego"><img alt="MCP Registry" src="https://img.shields.io/badge/MCP%20Registry-active-5b21b6"></a>
  <a href="https://glama.ai/mcp/servers/Data-Unix/MCP-MALTEGO"><img alt="Puntuación del servidor MCP en Glama" src="https://glama.ai/mcp/servers/Data-Unix/MCP-MALTEGO/badges/score.svg"></a>
  <img alt="Tools" src="https://img.shields.io/badge/tools-20-blue">
  <a href="CONTRIBUTING.md"><img alt="Contribuciones" src="https://img.shields.io/badge/PRs-bienvenidas-blue"></a>
  <a href="README.md"><img alt="English" src="https://img.shields.io/badge/docs-English-blue"></a>
</p>

---

**mcp-maltego** es un servidor [Model Context Protocol](https://modelcontextprotocol.io) de alto rendimiento que convierte a cualquier agente de IA en un analista experto de Maltego. Ejecuta transforms reales, los encadena en Machines de reconocimiento autónomo, mantiene un grafo de investigación persistente con memoria de cada paso y procedencia explicable, recomienda el siguiente pivote, se sincroniza en tiempo real con el Centro de Control Web (`maltegoctl dashboard`) y se integra limpiamente con Maltego Desktop mediante archivos `.mtgx` y paquetes forenses sellados `.mcpcase`.

> [!TIP]
> **Cero Coste y Sin Licencias Comerciales de Maltego**: No necesitas un plan de pago de Maltego (Pro/XL) ni claves comerciales para empezar. `mcp-maltego` funciona de forma completamente gratuita en local, generando archivos `.mtgx` nativos 100% compatibles con la versión gratuita **Maltego Community Edition (CE)** o Basic.

---

## 🏛️ Arquitectura Desacoplada en Tres Capas

`mcp-maltego` se estructura en tres capas modulares para que puedas comenzar de inmediato sin sobrecarga ni complejidad de configuración:

| Capa | Componente | Descripción y Coste |
| :--- | :--- | :--- |
| **Capa 0: Núcleo Gratuito** | CLI y Servidor MCP | Ejecución directa (`npx mcp-maltego`). Genera y lee archivos `.mtgx` para **Maltego Community Edition (CE)** y paquetes forenses sellados `.mcpcase` (SHA-256). Incluye **51 transforms integrados sin API key** (DoH, RDAP/WHOIS, crt.sh, CertSpotter, Anubis-DB, Wayback Machine CDX y snapshots, Arquivo.pt, Common Crawl, BOE/BORME, GLEIF LEI, ASN Cymru, RIPEstat, CISA KEV, URLhaus, AlienVault OTX, URLscan, Hudson Rock, GitHub leaks/commits, Keybase, DeepDarkCTI, Mempool.space Bitcoin UTXO, clustering CIOH, sanciones OFAC SDN y puntos VASP) y motor de plugins comunitarios (`@custom_transform`). **100% Local y Gratuito.** |
| **Capa 1: Memoria de Casos** | Memoria de Grafo y Copiloto | Almacenamiento local determinista de casos (`~/.maltego-mcp/graph.json`), fusión de identidades, auditoría forense de pasos, **16 Machines autónomas**, soporte para peticiones en texto claro o vagas en `osint_investigate`, Perfilado Pericial Multidimensional (21 tipologías) y síntesis analítica P0–P9 (ACH / ICD 203). |
| **Capa 2: Plataforma Avanzada** | Consola Web y Bóveda CTI | Web Dashboard interactivo (`maltegoctl dashboard`) con **sincronización en tiempo real entre procesos (`stdio` ↔ SSE)** desde agentes en VS Code, aceleración por Web Worker y 4 layouts (Orgánico, Jerárquico, Radial, Por Categoría), filtrado multidimensional (aristas, entidades, certeza continua, saltos y buscador en vivo), renderizado vectorial Impeccable (iconos en canvas, anillos de confianza y aristas Bézier), Suite Universal de Tablas (densidad compacta/normal/expandida, paginación, tarjetas acordeón detalladas), Consola de Reconocimiento P0–P9 y ACH/ICD 203, Radar de Perfilado Pericial de 21 tipologías, Anillo de Egreso Mullvad obligatorio con atestación doble y Guardián PEP 578, autenticación de sesión PBKDF2-HMAC-SHA256, Ledger Blockchain AML con detección de mixers, aislamiento y scoping estricto de casos, purgado atómico, Bóveda de Cuentas categorizadas, buzones efímeros (Mail.tm + extractor OTP), feeds CTI Tor/Dark Web, núcleo nativo Rust opcional (`maltego_core_rs`) y persistencia opcional en Azure Cosmos DB Gremlin. |

---

## Características Principales

- **20 tools compatibles con todos los modelos.** Esquemas planos validados contra el subconjunto estricto de Gemini;
  las variantes van en un parámetro `action` para no saturar a los agentes.
- **Peticiones en texto claro o vagas desde VS Code + Sincronización en tiempo real con el Dashboard.** Pide a cualquier agente en VS Code (Claude Code, GitHub Copilot, Cursor) o terminal (`"investiga example.com y dame un informe completo"`). `osint_investigate` extrae automáticamente la semilla, ejecuta todos los transforms activos y pasivos no intrusivos con concurrencia controlada (`CHAIN_CONCURRENCY = 3`), transmite cada hallazgo en vivo mediante `~/.maltego-mcp/events.jsonl` y Server-Sent Events (`/api/events`) a `maltegoctl dashboard`, autocompleta las **10 fases del expediente P0–P9** y los **perfiles periciales de 21 tipologías**, auto-exporta `report_html` y `.mcpcase`, y devuelve en línea el **Informe Pericial Ejecutivo Completo**.
- **63 transforms reales incluidos.** **51 sin API key** (DNS sobre HTTPS, RDAP/WHOIS con respaldo ARIN, vulnerabilidades activas en CISA KEV, malware en Abuse.ch URLhaus, transparencia de certificados en crt.sh y CertSpotter, Anubis-DB pDNS, HackerTarget, urlscan.io, Shodan InternetDB, ASN y prefijos BGP en Team Cymru y RIPEstat, archivos web históricos en Wayback Machine CDX y extracción de snapshots, Arquivo.pt y Common Crawl CDX, registros oficiales BOE/BORME y estructura societaria GLEIF LEI, fugas de código y correos de commits en GitHub, pruebas criptográficas en Keybase, exposición a infostealers en Hudson Rock, Gravatar, pulsos de amenazas en AlienVault OTX, perfiles por alias, inteligencia Dark Web CTI y pivote `.onion` pasivo, transacciones Bitcoin e inputs/outputs en Mempool.space, clustering por co-gasto CIOH, cotejo de sanciones cripto OFAC SDN, touchpoints en exchanges/VASPs y análisis) y **12 de proveedores** que se activan al definir su clave: VirusTotal, Shodan, SecurityTrails, Censys, Hunter.io, Have I Been Pwned, GreyNoise y Tatum.
- **Ejecución Activa y Pasiva No Intrusiva + Anillo de Egreso Mullvad.** Los transforms activos no intrusivos (DNS sobre HTTPS, consultas GET a VirusTotal, inspección pasiva `.onion`) y los pasivos están habilitados por defecto, bloqueando cualquier operación intrusiva (sin escaneo de puertos ni subidas o POST `/analyse` en VirusTotal). Todo el tráfico sale por un único guardián (`egress.py`) con auditoría PEP 578 y soporte para el Anillo Mullvad obligatorio (`socks5h://10.64.0.1:1080`) con atestación doble.
- **Perfilado Pericial Multidimensional (21 Tipologías) y Síntesis P0–P9 ACH / ICD 203.** `osint_manage_entity(action="profile")` evalúa 21 tipologías forenses sobre un radar de 6 pilares (`investor`, `company_due_diligence`, `device`, `geographic`, `criminal`, `victimology`, `cyberbullying`, `political`, `psychographic`, `clinical`, etc.) con cálculo de vigencia objetiva (`OBSERVADO_RECIENTE`, `HISTORICO`, `MENCIONADO_SIN_FECHA`) y síntesis de Hipótesis en Competencia (ACH) bajo la directiva ICD 203.
- **Motor de Extensibilidad Comunitaria (`@custom_transform`).** Permite soltar ficheros Python en `~/.maltego-mcp/plugins/` o `./plugins/` para exponer nueva lógica OSINT a los LLMs sin tocar el núcleo.
- **También tus transforms de Maltego.** Habla el protocolo XML TRX/iTDS de Maltego.
- **16 Machines predefinidas.** `DomainRecon`, `InfrastructureRecon`, `EmailRecon`, `CompanyFootprint`, `PersonalFootprint`, `PersonaFootprint`, `CryptoFlowRecon`, `URLRecon`, `ThreatSweep`, `ASNToNetblocks`, `DarkWebFootprint`, más sus equivalentes en modo pasivo estricto (`PassiveDomainRecon`, `PassiveInfrastructureRecon`, `PassiveEmailRecon`, `PassiveURLRecon`, `PassiveCompanyFootprint`) y las tuyas en TOML, con rondas recursivas y presupuestos.
- **Trazabilidad Criptoforense & AML Blockchain.** Ontología nativa (`maltego.CryptoCluster`, `maltego.VASPExchange`, `maltego.MixerContract`, `maltego.DeFiBridge`), reconstrucción de flujos transaccionales UTXO/EVM, heurísticas de co-gasto (CIOH) y peeling chains, detección de mezcladores (Tornado Cash, CoinJoin), verificación de sanciones OFAC SDN y puntos de salida a fiat (VASPs regulados con KYC).
- **Aislamiento Multi-Investigación, Purgado Atómico y Paquetes `.mcpcase`.** Selector global de proyecto sincronizado, selector modular independiente, eliminación segura e irreversible de casos (`DELETE /api/cases/{case_id}`) y empaquetado forense `.mcpcase` con verificación criptográfica SHA-256.
- **Núcleo Nativo Rust Opcional (`maltego_core_rs`).** Fallback puro en Python con paridad exacta bit a bit junto con una extensión opcional en Rust/PyO3 (`uv run python scripts/build_native.py`) que libera el GIL en layouts Fruchterman-Reingold y similitud de cadenas.
- **Informes Periciales y CLI.** Informes ejecutivos sin emojis en Markdown o HTML autocontenido (con IOCs neutralizados y CSP estricta) y `maltegoctl` para terminal y CI.
- **Seguro por defecto.** Los datos OSINT se tratan como no confiables, XML con defusedxml, lecturas acotadas de
  ficheros comprimidos, sin URLs arbitrarias y sin API keys en los logs.

## Contribuciones y Gobernanza Comunitaria
¡Agradecemos las contribuciones! Todo cambio está sujeto a nuestra [Guía de Contribución](CONTRIBUTING.md). Las Pull Requests son evaluadas automáticamente por nuestro analizador AST de seguridad y blast radius, y toda fusión a `main` requiere la aprobación manual exclusiva del mantenedor principal [@Data-Unix](https://github.com/Data-Unix).

## Requisitos

- [Node.js](https://nodejs.org) 18 o superior (para `npx`).
- [uv](https://docs.astral.sh/uv/), que gestiona Python 3.12 (si no está instalado, `mcp-maltego` lo instala de forma
  autónoma en `~/.maltego-mcp/bin` en el primer arranque).

Prepara el entorno, la plantilla `~/.maltego-mcp/.env` y el `.mtz` para Maltego Desktop en un solo comando:

```bash
npx -y mcp-maltego setup
```

## Inicio rápido

Configuración estándar, válida para la mayoría de clientes MCP:

```json
{
  "mcpServers": {
    "maltego": {
      "command": "npx",
      "args": ["-y", "mcp-maltego"]
    }
  }
}
```

Y pide a tu agente:

> Investiga example.com, dame el resumen del caso y expórtalo para Maltego.

<details>
<summary><b>📦 Guía de Instalación y Primer Despliegue por Sistema Operativo</b></summary>

### 🍏 macOS (Apple Silicon M1/M2/M3/M4 & Mac Intel Core)

Compatible nativamente con arquitecturas `arm64` (Apple Silicon) y `x86_64` (Intel). No requiere Xcode ni compiladores C locales.

1. **Requisito inicial**: [Node.js](https://nodejs.org) 18 o superior (`brew install node` o instalador oficial).
2. **Auto-despliegue en 1 solo comando**:
   ```bash
   npx -y mcp-maltego setup
   ```
   *Este comando auto-detecta tu procesador (Intel o Apple Silicon), descarga uv nativo, crea el runtime aislado Python 3.12 en `~/.maltego-mcp`, genera `.env`, el paquete `.mtz` de Maltego y añade los comandos globales (`maltegoctl`, `mcp-maltego`) a tu shell `zsh` (`~/.zshrc` y `~/.zprofile`).*
3. **Lanzar el Centro de Mando / Dashboard interactivo**:
   ```bash
   maltegoctl dashboard
   ```
   *(Abre automáticamente `http://127.0.0.1:8000/dashboard` en Safari / Chrome con el visualizador gráfico de casos y la bóveda).*
4. **Verificar estado y diagnóstico**:
   ```bash
   maltegoctl doctor
   ```
5. **Integración con Maltego Desktop CE para Mac (`/Applications/Maltego.app`)**:
   - Genera el paquete de configuración local: `maltegoctl mtz`
   - En Maltego Desktop: Menú **Import \| Export → Import Config** y selecciona `~/.maltego-mcp/maltego-mcp-local.mtz`.

---

### 🪟 Windows (Windows 10 / 11 · PowerShell & Terminal)

1. **Requisito inicial**: [Node.js](https://nodejs.org) 18 o superior (`winget install OpenJS.NodeJS` o instalador oficial).
2. **Auto-despliegue en 1 solo comando**:
   ```powershell
   npx -y mcp-maltego setup
   ```
   *Instala `uv.exe` de forma autónoma en `%USERPROFILE%\.maltego-mcp\bin`, crea los ejecutables globales `.cmd` y `.ps1` en `%USERPROFILE%\.local\bin`, y actualiza el PATH de usuario de Windows y el perfil de PowerShell.*
3. **Lanzar el Dashboard interactivo**:
   ```powershell
   maltegoctl dashboard
   ```
   *(Abre `http://127.0.0.1:8000/dashboard` en tu navegador predeterminado).*

---

### 🐧 Linux (Ubuntu, Debian, Kali Linux, Arch, Fedora)

1. **Requisito inicial**: Node.js 18+ y `curl`.
2. **Auto-despliegue en 1 solo comando**:
   ```bash
   npx -y mcp-maltego setup
   ```
   *Configura el entorno en `~/.maltego-mcp`, los ejecutables en `~/.local/bin` y exporta la ruta a tu `~/.bashrc` o `~/.profile`.*
3. **Lanzar el Dashboard**:
   ```bash
   maltegoctl dashboard
   ```
</details>

<details>
<summary><b>🤖 Guía de Configuración con Agentes de IA en diferentes IDEs</b></summary>

### 🚀 Antigravity IDE
Para integrar el servidor MCP de Maltego con tus agentes en **Antigravity IDE**:

1. Abre la configuración de extensiones MCP o el archivo `.gemini/settings.json`:
   ```json
   {
     "mcpServers": {
       "maltego": {
         "command": "mcp-maltego"
       }
     }
   }
   ```
   *O de forma directa y portátil con npx:*
   ```json
   {
     "mcpServers": {
       "maltego": {
         "command": "npx",
         "args": ["-y", "mcp-maltego"]
       }
     }
   }
   ```
2. **Ejemplo de prompt operativo para el agente en Antigravity**:
   > *"Inicia un caso OSINT sobre `example.com`, ejecuta la Machine `DomainRecon` para mapear subdominios y servidores DNS, y guarda las entidades en el grafo para que pueda analizarlas en el visualizador web de `maltegoctl dashboard`."*

---

### 💻 Cursor IDE
En Cursor (**Settings → Features → MCP → Add New MCP Server**):
- **Name**: `maltego`
- **Type**: `command`
- **Command**: `npx -y mcp-maltego`

O en `~/.cursor/mcp.json` / `.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "maltego": {
      "command": "npx",
      "args": ["-y", "mcp-maltego"]
    }
  }
}
```

---

### ⚡ Claude Code (CLI) y Claude Desktop
- **Claude Code**:
  ```bash
  claude mcp add maltego -- npx -y mcp-maltego
  ```
- **Claude Desktop**:
  En `claude_desktop_config.json` (**Settings → Developer → Edit Config**):
  ```json
  {
    "mcpServers": {
      "maltego": {
        "command": "npx",
        "args": ["-y", "mcp-maltego"]
      }
    }
  }
  ```

---

### 🧠 Codex CLI
```bash
codex mcp add maltego -- npx -y mcp-maltego
```
O en `~/.codex/config.toml`:
```toml
[mcp_servers.maltego]
command = "npx"
args = ["-y", "mcp-maltego"]
```

---

### ♊ Gemini CLI
En `~/.gemini/settings.json` o `.gemini/settings.json`:
```json
{
  "mcpServers": {
    "maltego": {
      "command": "npx",
      "args": ["-y", "mcp-maltego"]
    }
  }
}
```

---

### 🐙 VS Code / Copilot CLI
En `.vscode/mcp.json` o `.copilot/mcp-config.json`:
```json
{
  "servers": {
    "maltego": {
      "command": "npx",
      "args": ["-y", "mcp-maltego"]
    }
  }
}
```
</details>

| Cliente | Dónde va la configuración |
|---|---|
| Claude Code | `claude mcp add maltego -- npx -y mcp-maltego` |
| Claude Desktop | `claude_desktop_config.json` (Ajustes → Desarrollador → Editar configuración) |
| Gemini CLI | `~/.gemini/settings.json` o `.gemini/settings.json` |
| Codex | `codex mcp add maltego -- npx -y mcp-maltego` o `~/.codex/config.toml` |
| Copilot CLI | `~/.copilot/mcp-config.json`, `.mcp.json` o `.github/mcp.json` |
| VS Code | `.vscode/mcp.json` con clave `servers` |
| Cursor | `~/.cursor/mcp.json` o `.cursor/mcp.json` |
| OpenCode | `opencode.json` con `"type": "local"` y `command` como lista |
| Qwen Code | `~/.qwen/settings.json` o `.qwen/settings.json` |
| Orca IDE | Clona el repo: ya incluye el fichero de cada agente ([docs/ORCA.md](docs/ORCA.md)) |

Ejemplos exactos para cada cliente en el [README en inglés](README.md#getting-started).

## Tools (20)

| Grupo | Tool | Para qué |
|---|---|---|
| Catálogo | `osint_list_entity_types` | 41 tipos de entidad estándar por categoría (más `humint.*`, cripto/AML y los importados de tu Maltego `.mtz`) |
| | `osint_list_transforms` | 63 transforms integrados, 16 Machines, claves de proveedores y estado de servidores TRX |
| Casos | `osint_manage_case` | Crear, bifurcar/delegar subcasos (`fork`/`delegate`), fusionar (`merge`) o borrar (`delete` con confirmación) |
| | `osint_list_cases` | Listado paginado de casos |
| | `osint_get_case_summary` | Recuentos, entidades prioritarias e índices de calidad |
| Entidades | `osint_upsert_entity` | Crear o fusionar (valor normalizado, id determinista, notas) |
| | `osint_manage_entity` | Editar confianza/notas/propiedades, `visual_style` en `.mtgx`, `analyze_behavior` HUMINT, **Perfilado Pericial Multidimensional de 21 tipologías** (`profile`), generación de identidades operativas (`generate_persona`) o borrar |
| | `osint_get_entity` | Detalle, puntuación explicada, procedencia, transforms pendientes |
| | `osint_search_entities` | Búsqueda en un caso o entre casos; orden por prioridad |
| Relaciones | `osint_link_entities` | Relacionar/desrelacionar, `analyze` rol/sentimiento/peso HUMINT o `correlate` identidades entre plataformas |
| | `osint_get_neighbors` | Vecinos con dirección y tipo de relación |
| | `osint_find_paths` | Caminos más cortos entre dos entidades |
| Transforms | `osint_run_transform` | Un transform sobre una entidad (emite eventos en vivo a `maltegoctl dashboard`) |
| | `osint_expand_entity` | Todos los transforms aplicables ("Run All") con concurrencia anti-ráfaga |
| | `osint_run_machine` | Una de las 16 Machines predefinidas o una cadena propia, con rondas y presupuestos |
| Copiloto | `osint_investigate` | Todo en una llamada (admite objetivos o peticiones en texto claro / vagas): extrae la semilla, crea el caso, ejecuta la Machine y los pivotes activos/pasivos no intrusivos, sincroniza en vivo P0–P9 y los perfiles de 21 tipologías en el dashboard, auto-exporta `report_html` + `.mcpcase` y devuelve el **Informe Pericial Ejecutivo Completo** |
| | `osint_suggest_next_steps` | Siguiente mejor acción con historial de rendimiento |
| | `osint_get_timeline` | Memoria procedimental de la investigación (`steps`) o línea de vida cronológica y anomalías del sujeto (`subject`) |
| Intercambio | `osint_export_case` | `mtgx`, `mcpcase` (paquete nativo sellado con SHA-256), `json`, `graphml`, `csv`, `report_md`, `report_html` |
| | `osint_import_graph` | Importar `.mtgx`, `.mcpcase` o CSV de Maltego (con memoria) |

## API keys de proveedores

`VIRUSTOTAL_API_KEY`, `SHODAN_API_KEY`, `SECURITYTRAILS_API_KEY`, `CENSYS_API_ID` + `CENSYS_API_SECRET`,
`HUNTER_API_KEY`, `HIBP_API_KEY`, `GREYNOISE_API_KEY`, `TATUM_API_KEY`. Pásalas en el bloque `env` de la
configuración del cliente o como variables de entorno de usuario.

## Integración con Maltego Desktop

| Dirección | Cómo |
|---|---|
| Agente → Maltego | `osint_export_case` genera un `.mtgx`; ábrelo con **File → Open** |
| Maltego → agente | Guarda el `.mtgx` en `~/.maltego-mcp/imports/` y pide al agente que lo importe |
| En vivo dentro de Maltego | `npx mcp-maltego ctl mtz` genera los transforms locales **MCP · Abrir caso**, **MCP · Vecinos en el caso** y **MCP · Guardar en el caso**; impórtalo con **Import \| Export → Import Config** |
| Tu ontología | Exporta tu configuración de Maltego y ejecuta `npx mcp-maltego ctl import-entities config.mtz` |

Para el puente, instala el paquete de forma global (`npm i -g mcp-maltego`). Detalles en [docs/MALTEGO.md](docs/MALTEGO.md).

## Agentes y skills

El repositorio incluye 10 agentes y 15 skills con una única fuente (`.agents/`) para Claude Code, Gemini CLI, Qwen
Code, GitHub Copilot, Codex y Cursor: agentes de investigación (`osint-analyst`, `cti-analyst`, `ioc-composer`,
`recon-toolchain-integrator`) y de desarrollo, y skills de huella corporativa, identidad digital, infraestructura,
composición de IOC con otros MCP, herramientas OSINT externas, proveedores propios, entidades no estándar y
despliegue. Sin capacidades ofensivas (explotación).

## Documentación

- Uso y configuración: [docs/USO.md](docs/USO.md)
- Maltego Desktop: [docs/MALTEGO.md](docs/MALTEGO.md)
- Orca y varios agentes: [docs/ORCA.md](docs/ORCA.md)
- Cobertura funcional y verificación: [docs/COBERTURA.md](docs/COBERTURA.md)
- Seguridad: [SECURITY.md](SECURITY.md) · Cambios: [CHANGELOG.md](CHANGELOG.md) · Contribuir: [AGENTS.md](AGENTS.md)

## Uso responsable

Esta herramienta consulta fuentes públicas. Eres responsable de cumplir la ley, los términos de cada proveedor y la
normativa de protección de datos (por ejemplo, el RGPD).

## Licencia

[MIT](LICENSE). Maltego es una marca de Maltego Technologies GmbH. Este proyecto es independiente y no está afiliado
ni respaldado por Maltego Technologies.
