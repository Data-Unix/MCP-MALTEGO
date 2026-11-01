# Trabajo con varios modelos en Orca

Orca no elige modelos por sí mismo: cada worktree ejecuta el agente que tú (o un agente coordinador) indicas.
Este documento fija qué agente se usa para qué en este proyecto y cómo coordinarlos.

## 1. Reparto de roles por agente

| Rol | Agente recomendado | Alternativa | Por qué |
|---|---|---|---|
| Coordinación, arquitectura, decisiones | Claude Code | Codex | Orquestación y planificación largas; `--model` admitido en `orca orchestration` |
| Implementación principal (Python, MCP, Functions) | Gemini CLI | Codex / OpenCode | Desarrollador principal del proyecto; valida en la práctica que el MCP funciona con Gemini |
| Revisión de código y seguridad | Un proveedor distinto del autor | — | Revisión cruzada: Gemini escribe → Claude o Codex revisan, y viceversa |
| Tests y evaluaciones del MCP | Codex | Gemini CLI | Las evaluaciones se ejecutan contra Claude **y** Gemini para medir compatibilidad |
| Releases y publicación | Cualquiera (agente `release-manager`) | — | Skill `release` |
| Investigación con fuentes web | Gemini CLI | Claude Code | |
| Decisiones difíciles de diseño | **Varios en paralelo** (2-3 agentes, mismo prompt) | — | Comparar propuestas y quedarse con la mejor |

Los 7 agentes del proyecto (`mcp-architect`, `transform-engineer`, `osint-graph-modeler`, `security-reviewer`,
`test-engineer`, `release-manager`, `osint-analyst`) y las 7 skills existen para todas las herramientas (ver `AGENTS.md`,
sección «Agentes y skills»). Las reglas comunes están en `AGENTS.md`.

## 2. Flujos de trabajo

### Una tarea, un agente
1. `+` junto al repo → nombre de tarea (p. ej. `feat-graph-client`) → elegir agente → crear.
2. Orca crea worktree y rama, ejecuta `orca.yaml` (`uv sync`) y copia `.worktreeinclude` (`.env`).
3. Pegar el prompt de la tarea (sección 3).
4. Revisar el diff en Orca → abrir PR → revisión por otro modelo → merge.

### Mismo prompt en varios agentes (comparar)
Crear 2-3 worktrees con agentes distintos (`spike-gemini`, `spike-codex`, `spike-claude`), pegar el mismo prompt,
comparar diffs y fusionar solo el mejor. Borrar el resto de worktrees.

### Orquestación automatizada (experimental en Orca)
Activar en Settings → Experimental. El coordinador (normalmente Claude Code) reparte tareas a otros agentes:

```bash
orca orchestration run-create --objective "Fase 2: núcleo domain/ y graph/" --json
orca orchestration task-create --task-title "Cliente Gremlin" --spec "Ver PLAN.md §1 y §2; tests incluidos" --json
orca orchestration worker-start --task <taskId> --worktree new-child --name graph-client --agent gemini --setup run --json
orca orchestration task-create --task-title "Revisión de seguridad graph/" --spec "Revisar inyección Gremlin y 429" --json
orca orchestration worker-start --task <taskId> --worktree current --agent codex --json
orca orchestration check --wait --types worker_done,escalation,question --timeout-ms 900000 --json
```

Antes de cambiar tools públicas o el esquema del grafo, el coordinador abre un *decision gate*
(`orca orchestration gate-create`) para que decidas tú.

## 3. Plantilla de prompt para cada tarea

```
Lee AGENTS.md y la sección <N> de PLAN.md.
Tarea: <qué hay que hacer, en una frase>.
Alcance: solo <ficheros/carpetas>. No modifiques <lo que no se toca>.
Hecho cuando: <criterio verificable, p. ej. "uv run pytest -q en verde y test_schema_portability incluido">.
Al terminar: resume los cambios y lo que quede pendiente.
```

## 4. Precauciones

- Orca lanza los agentes en modo de autonomía total (`--yolo` en Gemini, etc.). Trabaja siempre en worktrees,
  nunca en `main`, y revisa el diff antes de cualquier merge.
- MCP: ver sección 5.

## 5. Registro del MCP en los agentes (verificado)

Orca **no** registra servidores MCP para los agentes: lo comprobé en su código fuente (`src/shared/mcp-config.ts`
y `McpConfigSection.tsx`). Su apartado **Settings → Repository → MCP Configs** solo *inspecciona* los ficheros MCP
del repo (`.mcp.json`, `.cursor/mcp.json`, `.claude.json`, `.claude/mcp.json`) y cada agente CLI lee su propia
configuración. La documentación de Orca que menciona "Settings → Integrations → MCP" está desactualizada.

Por eso el repo incluye el fichero de proyecto que lee cada agente (todos ejecutan `uv run --quiet maltego-mcp`
desde la raíz del worktree). Como están versionados, **cada worktree nuevo ya trae el MCP**:

| Agente | Fichero | Paso único la primera vez |
|---|---|---|
| Claude Code | `.mcp.json` | Aprobar el servidor del proyecto cuando lo pregunte |
| GitHub Copilot CLI | `.mcp.json` | Confirmar la confianza en la carpeta |
| Gemini CLI | `.gemini/settings.json` | Ninguno, salvo que tengas activado "Trusted Folders" (entonces, confiar en la carpeta) |
| Qwen Code | `.qwen/settings.json` | Igual que Gemini |
| Codex | `.codex/config.toml` | Marcar el proyecto como de confianza |
| OpenCode | `opencode.json` | Ninguno |
| Cursor CLI | `.cursor/mcp.json` | Aprobar el servidor (`agent mcp enable maltego` o `--approve-mcps`) |

Todos los agentes y worktrees comparten el mismo estado en `~/.maltego-mcp` (grafo, catálogo de transforms,
importaciones y exportaciones), así que lo que guarda Gemini lo ve Claude y viceversa.

Si antes registraste `maltego` a mano en la configuración de usuario de un agente (p. ej. `~/.gemini/settings.json`),
quítalo para no tener el servidor duplicado.
