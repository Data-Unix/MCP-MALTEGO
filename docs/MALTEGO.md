# Integración con Maltego Desktop

Hay tres vías, que se combinan:

| Vía | Dirección | Para qué |
|---|---|---|
| Transforms locales "MCP" | Maltego ⇄ grafo del MCP | Abrir en Maltego lo que investigan los agentes y enviarles entidades desde Maltego |
| Ficheros `.mtgx` | MCP → Maltego y Maltego → MCP | Llevar un caso completo (con relaciones y disposición) en un fichero |
| Servidores de transforms (TRX/iTDS) | Agentes → tus transforms | Que los agentes ejecuten los mismos transforms que usas en Maltego |

## 1. Transforms locales (puente)
Funcionan en Maltego CE y comerciales, sin servidor ni iTDS: Maltego ejecuta un comando en tu equipo.

Generar e importar (una vez, y de nuevo si mueves la carpeta del repo o uv):
```
cd <carpeta del repo>
uv run maltego-mcp-bridge mtz
```
Crea `~/.maltego-mcp/maltego-mcp-local.mtz` con el SDK oficial `maltego-trx`. En Maltego: **Import | Export →
Import Config** → elige ese fichero → importa todo.

Transforms (set "MCP Maltego"):
- **MCP · Listar casos** (sobre una frase cualquiera): una frase por caso.
- **MCP · Abrir caso** (sobre una frase con el id del caso): lo fija como caso actual y trae sus entidades.
- **MCP · Vecinos en el caso** (sobre cualquier entidad soportada): las relaciones que guardaron los agentes,
  con su etiqueta y dirección.
- **MCP · Guardar en el caso** (sobre cualquier entidad soportada): la guarda en el caso actual para los agentes.

Las entidades que llegan desde el MCP traen propiedades `mcp.entity_id`, `mcp.case`, `mcp.confidence` y
`mcp.sources`. El peso de la entidad refleja la confianza.

Limitación de Maltego: un transform local solo recibe el valor y las propiedades (no el tipo), por eso hay una
versión de "Vecinos" y "Guardar" por cada tipo de entidad.

## 2. Ficheros .mtgx
- **MCP → Maltego**: `osint_export_case` con `format="mtgx"` (por defecto) escribe en `~/.maltego-mcp/exports/`.
  En Maltego: **File → Open** el `.mtgx`.
- **Maltego → MCP**: en Maltego, **File → Save As** `.mtgx` dentro de `~/.maltego-mcp/imports/` y pide al agente
  `osint_import_graph` con el nombre del fichero.

El formato sigue la estructura de las exportaciones de Maltego (contrastada con dos implementaciones de la
comunidad); confírmalo abriendo un export en tu versión de Maltego.

## 3. Tus transforms TRX/iTDS
Declara tus servidores y transforms en `~/.maltego-mcp/transforms.toml` (ver `config/transforms.example.toml`).
Un servidor `maltego-trx` propio sirve a la vez a Maltego y a los agentes.
