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
| Infra Azure (Bicep, GitHub Actions) | Claude Code (agente `azure-infra-engineer`) | Gemini CLI | |
| Investigación con fuentes web | Gemini CLI | Claude Code | |
| Decisiones difíciles de diseño | **Varios en paralelo** (2-3 agentes, mismo prompt) | — | Comparar propuestas y quedarse con la mejor |

Los agentes de `.claude/agents/` (mcp-developer, osint-graph-modeler, security-auditor...) solo los carga Claude Code.
Para el resto, las reglas comunes están en `AGENTS.md`, que todos leen directamente o vía `GEMINI.md`/`CLAUDE.md`/`QWEN.md`.

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
- MCP: cuando exista el servidor, regístralo una vez en Orca → Settings → Integrations → MCP para que lo vean
  todos los agentes (plantillas por agente en `config/mcp-clients/`).
