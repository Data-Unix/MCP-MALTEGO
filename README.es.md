<h1 align="center">mcp-maltego</h1>

<p align="center">
  <strong>Maltego OSINT para agentes de IA.</strong><br>
  Ejecuta transforms y Machines, construye y analiza grafos de relaciones y devuelve el resultado a Maltego como
  <code>.mtgx</code> nativo, desde Claude, Gemini, Codex, Copilot, Cursor o cualquier cliente MCP.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/mcp-maltego"><img alt="npm" src="https://img.shields.io/npm/v/mcp-maltego?logo=npm"></a>
  <a href="https://github.com/Data-Unix/MCP-MALTEGO/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Data-Unix/MCP-MALTEGO/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="Licencia: MIT" src="https://img.shields.io/badge/licencia-MIT-green"></a>
  <img alt="MCP" src="https://img.shields.io/badge/MCP-servidor-8A2BE2">
  <img alt="Tools" src="https://img.shields.io/badge/tools-20-blue">
  <a href="README.md"><img alt="English" src="https://img.shields.io/badge/docs-English-blue"></a>
</p>

---

**mcp-maltego** es un servidor [Model Context Protocol](https://modelcontextprotocol.io) que convierte a un agente de
IA en un operador de Maltego. Ejecuta transforms reales (integrados, de proveedores comerciales o de tus servidores
TRX/iTDS), los encadena en Machines, mantiene un grafo de investigación persistente con memoria de cada paso,
recomienda el siguiente pivote y lo exporta todo a Maltego Desktop. Todos los agentes que uses comparten el mismo grafo.

## Características

- **20 tools compatibles con todos los modelos.** Esquemas planos validados contra el subconjunto estricto de Gemini;
  las variantes van en un parámetro `action` para no saturar a los agentes.
- **30 transforms reales incluidos.** 18 sin API key (DNS sobre HTTPS, RDAP/WHOIS, transparencia de certificados,
  ASN, perfiles por alias, análisis) y 12 de proveedores que se activan al definir su clave: VirusTotal, Shodan,
  SecurityTrails, Censys, Hunter.io, Have I Been Pwned, GreyNoise y Tatum.
- **También tus transforms de Maltego.** Habla el protocolo XML TRX/iTDS de Maltego.
- **Machines.** DomainRecon, InfrastructureRecon, EmailRecon, CompanyFootprint, PersonalFootprint, URLRecon y las
  tuyas en TOML, con rondas recursivas y presupuestos.
- **Copiloto de investigación.** `osint_investigate` lo hace todo en una llamada. Cada paso queda registrado (qué, sobre
  qué, por qué, resultado), cada entidad tiene procedencia y prioridad explicables, y la siguiente mejor acción aprende
  del rendimiento de cada transform.
- **Ida y vuelta con Maltego.** `.mtgx` con layout jerárquico, radial o por fuerzas y la memoria incluida; importación
  de `.mtgx`; transforms locales dentro de Maltego para abrir un caso, ver vecinos y enviar entidades a los agentes;
  importación de tu ontología exacta de Maltego.
- **Informes y CLI.** Informes en Markdown o HTML autocontenido y `maltegoctl` para terminal y CI.
- **Seguro por defecto.** Los datos OSINT se tratan como no confiables, XML con defusedxml, lecturas acotadas de
  ficheros comprimidos, sin URLs arbitrarias y sin API keys en los logs.

## Requisitos

- [Node.js](https://nodejs.org) 18 o superior (para `npx`).
- [uv](https://docs.astral.sh/uv/), que gestiona Python (descarga Python 3.12 si hace falta).
  - Windows: `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"`
  - macOS / Linux: `curl -LsSf https://astral.sh/uv/install.sh | sh`

Comprueba todo con:

```bash
npx -y mcp-maltego doctor
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

## Tools

| Grupo | Tool | Para qué |
|---|---|---|
| Catálogo | `osint_list_entity_types` | Ontología por categoría (estándar + importada de tu Maltego) |
| | `osint_list_transforms` | Transforms, Machines, claves de proveedores y estado de servidores |
| Casos | `osint_manage_case` | Crear, fusionar o borrar (con confirmación) |
| | `osint_list_cases` | Listado paginado |
| | `osint_get_case_summary` | Recuentos, entidades prioritarias e índices de calidad |
| Entidades | `osint_upsert_entity` | Crear o fusionar (valor normalizado, id determinista, notas) |
| | `osint_manage_entity` | Editar confianza, notas o propiedades; borrar |
| | `osint_get_entity` | Detalle, puntuación explicada, procedencia, transforms pendientes |
| | `osint_search_entities` | Búsqueda en un caso o entre casos; orden por prioridad |
| Relaciones | `osint_link_entities` | Relacionar o desrelacionar |
| | `osint_get_neighbors` | Vecinos con dirección y tipo de relación |
| | `osint_find_paths` | Caminos entre dos entidades |
| Transforms | `osint_run_transform` | Un transform sobre una entidad |
| | `osint_expand_entity` | Todos los transforms aplicables ("Run All") |
| | `osint_run_machine` | Una Machine o una cadena propia, con rondas y presupuestos |
| Copiloto | `osint_investigate` | Todo en una llamada |
| | `osint_suggest_next_steps` | Siguiente mejor acción con historial de rendimiento |
| | `osint_get_timeline` | Memoria de la investigación; novedades con `since_seq` |
| Intercambio | `osint_export_case` | `mtgx`, `json`, `graphml`, `csv`, `report_md`, `report_html` |
| | `osint_import_graph` | Importar `.mtgx` de Maltego (con memoria) o CSV |

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
