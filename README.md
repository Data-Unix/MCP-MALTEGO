# MCP Maltego

Servidor MCP (Python) para delegar en agentes LLM de cualquier proveedor (Gemini, Claude, Codex, OpenCode...) flujos
de Maltego: desde transforms individuales hasta cadenas tipo Machine, entidades y transforms personalizados y
análisis de grafos OSINT persistidos en Azure Cosmos DB (Gremlin).

Estado: 16 tools (casos, entidades, relaciones, análisis, transforms, cadenas tipo Machine, expansión, importación/exportación .mtgx) y puente con Maltego Desktop. Arranque: `uv sync` y `uv run maltego-mcp` (stdio) o `uv run maltego-mcp --transport http`. Guía: [docs/USO.md](docs/USO.md).

| Documento | Contenido |
|---|---|
| [PLAN.md](PLAN.md) | Arquitectura, tools, fases, fuentes |
| [AGENTS.md](AGENTS.md) | Reglas para todos los agentes (`CLAUDE.md`, `GEMINI.md`, `QWEN.md` lo importan) |
| [docs/USO.md](docs/USO.md) | Tools, configuración, transforms, backends y pendientes |
| [docs/ORCA.md](docs/ORCA.md) | Uso en el IDE Orca: roles por modelo, worktrees, orquestación |
| [orca.yaml](orca.yaml), [.worktreeinclude](.worktreeinclude) | Preparación automática de cada worktree en Orca |
| [docs/MALTEGO.md](docs/MALTEGO.md) | Integración con Maltego Desktop (transforms locales y .mtgx) |
| `.mcp.json`, `.gemini/`, `.codex/`, `.cursor/`, `.qwen/`, `opencode.json` | Registro automático del MCP en cada agente |
| [.claude/](.claude/) | Agentes y skills de apoyo (Claude Code) |
