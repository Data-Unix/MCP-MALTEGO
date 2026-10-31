# MCP Maltego

Servidor MCP (Python) para delegar en agentes LLM de cualquier proveedor (Gemini, Claude, Codex, OpenCode...) flujos
de Maltego: desde transforms individuales hasta cadenas tipo Machine, entidades y transforms personalizados y
análisis de grafos OSINT persistidos en Azure Cosmos DB (Gremlin).

Estado: esqueleto inicial (una tool de prueba). Arranque: `uv sync` y `uv run maltego-mcp` (stdio) o `uv run maltego-mcp --transport http`.

| Documento | Contenido |
|---|---|
| [PLAN.md](PLAN.md) | Arquitectura, tools, fases, fuentes |
| [AGENTS.md](AGENTS.md) | Reglas para todos los agentes (`CLAUDE.md`, `GEMINI.md`, `QWEN.md` lo importan) |
| [docs/ORCA.md](docs/ORCA.md) | Uso en el IDE Orca: roles por modelo, worktrees, orquestación |
| [orca.yaml](orca.yaml), [.worktreeinclude](.worktreeinclude) | Preparación automática de cada worktree en Orca |
| [config/mcp-clients/](config/mcp-clients/) | Plantillas para conectar el MCP a cada agente |
| [.claude/](.claude/) | Agentes y skills de apoyo (Claude Code) |
