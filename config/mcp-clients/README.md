# Plantillas de cliente MCP

Plantillas para conectar el servidor `maltego-mcp` a cada agente. **No están activas**: el servidor todavía no existe
(fase 3 de `PLAN.md`). Cuando exista, cópialas a su ubicación:

| Agente | Plantilla | Destino |
|---|---|---|
| Claude Code | `claude-code.mcp.json` | `.mcp.json` en la raíz del repo |
| Gemini CLI | `gemini-cli.settings.json` | `.gemini/settings.json` (fusionar con el existente) |
| Codex | `codex.config.toml` | `~/.codex/config.toml` |
| OpenCode | `opencode.json` | `opencode.json` en la raíz del repo |
| Todos (vía Orca) | — | Orca → Settings → Integrations → MCP (comando `uv run maltego-mcp`) |

Registrarlo una sola vez en Orca (Settings → Integrations → MCP) lo expone a todos los agentes con soporte MCP;
las plantillas por agente sirven si se usa el agente fuera de Orca.
