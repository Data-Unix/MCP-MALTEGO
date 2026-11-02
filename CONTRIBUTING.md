# Guía de Contribución · MCP Maltego

¡Gracias por tu interés en contribuir a **MCP Maltego**! Este proyecto es de código abierto (licencia MIT) y busca proporcionar el puente más potente, seguro y elegante entre modelos de lenguaje (LLMs) y el ecosistema de investigación de Maltego.

---

## 🏛️ Gobernanza y Modelo de Aprobación

Para preservar la estabilidad arquitectónica, la portabilidad multi-modelo y la seguridad frente a vectores de ataque en OSINT:

1. **Aprobación Exclusiva por el Propietario**:
   - Todo cambio debe canalizarse mediante una **Pull Request (PR)**.
   - **Ningún código se fusionará a la rama `main` sin la revisión y aprobación manual explícita de `@Data-Unix`** (definido en `.github/CODEOWNERS`).
2. **Evaluación Automatizada de PRs**:
   - Cada PR es analizada de forma inmediata por el workflow `PR Security & Architecture Assessment`.
   - El sistema analiza el árbol de sintaxis (AST) para verificar que no haya llamadas inseguras (`eval`, `exec`, inyecciones de shell, SSRF) y calcula el **Blast Radius** (impacto arquitectónico).
   - Genera un dictamen público para facilitar la decisión del mantenedor.
3. **Prohibición de Push Directo**:
   - `main` está protegida. Prohibido `git push --force`.

---

## 📐 Reglas Arquitectónicas Inviolables

Antes de escribir código, ten en cuenta los siguientes contratos de diseño que **no pueden romperse**:

### 1. Límite Estricto de 20 Tools MCP
* El servidor MCP expone exactamente **20 herramientas públicas** (verificadas por `tests/test_copilot.py`).
* **NO agregues nuevas tools en `src/maltego_mcp/tools.py`**:
  - Si desarrollas una nueva fuente OSINT o conector, créalo como una **Transformada** (`BuiltinTransform` o plugin comunitario).
  - En Maltego MCP, las transformadas son **datos y capacidades internas** que el agente descubre vía `osint_list_transforms` y ejecuta con `osint_run_transform`. No inflan el catálogo de tools del LLM.

### 2. Esquemas de Entrada 100% Planos (Multi-LLM Portability)
* Para garantizar que Gemini, Claude, OpenAI Codex, GitHub Copilot y Qwen puedan llamar a las tools sin errores de validación de esquema:
  - **Permitido**: `string`, `integer`, `number`, `boolean`, `array` de primitivos y `enum` de strings.
  - **Prohibido en `inputSchema`**: `$ref`, `$defs`, `anyOf`, `oneOf`, `allOf`, `additionalProperties`, `exclusiveMinimum/Maximum`, tipos múltiples (`["string", "null"]`).
  - `tests/test_schema_portability.py` debe pasar siempre en verde.

### 3. Tests 100% Aislados (Sin Dependencias de Red)
* Los tests unitarios jamás deben depender de conexiones activas a internet (las APIs externas pueden caerse, limitar tráfico o filtrar consultas).
* Todas las peticiones HTTP externas en tests deben usar `httpx.MockTransport(Router())` (ver `tests/test_builtin.py`).

### 4. Sincronización de Agentes y Skills
* La fuente única de verdad para subagentes y skills reside en `.agents/agents/` y `.agents/skills/`.
* Si modificas estas carpetas, ejecuta siempre:
  ```bash
  uv run python scripts/sync_agents.py
  ```
  `tests/test_agent_assets.py` fallará en CI si las copias para Claude, Gemini, Qwen o Copilot quedan desincronizadas.

---

## 🛠️ Flujo de Trabajo para Desarrolladores

### 1. Preparar el Entorno Local
El proyecto utiliza [uv](https://github.com/astral-sh/uv) como gestor de paquetes y entornos Python:

```bash
git clone https://github.com/Data-Unix/MCP-MALTEGO.git
cd MCP-MALTEGO
uv sync
```

### 2. Crear una Rama de Trabajo
Utiliza nombres descriptivos en español o inglés siguiendo las convenciones:
* `feat/nombre-transform` para nuevas fuentes o capacidades.
* `fix/descripcion-error` para correcciones de bugs.
* `docs/mejora-documentacion` para documentación.

```bash
git checkout -b feat/nueva-fuente-osint
```

### 3. Estándar de Código y Verificación Local
Antes de enviar tu PR, asegúrate de que toda la batería de calidad esté en verde:

```bash
# 1. Comprobación y formato de código (Ruff)
uv run ruff check .
uv run ruff format --check .

# 2. Verificación estricta de tipos (Mypy)
uv run mypy src

# 3. Batería completa de pruebas
uv run pytest -q

# 4. Evaluación local de seguridad y blast radius de tu PR
uv run python scripts/analyze_pr.py
```

### 4. Commits y Mensajes
* Mensajes claros y concisos en español (o inglés).
* No incluyas líneas de atribución de herramientas o asistentes generativos (`Co-authored-by: ...`).
* Nunca incluyas ficheros `.env`, credenciales, datos de casos de investigación (`graph.json`, `.mtgx`) ni volcados temporales.

---

## 📬 Envío de la Pull Request
1. Abre tu Pull Request hacia la rama `main` de `Data-Unix/MCP-MALTEGO`.
2. Completa la plantilla con una descripción clara del objetivo y qué capa del sistema afecta.
3. El bot de análisis publicará el dictamen de seguridad en el hilo de la PR.
4. `@Data-Unix` revisará el cambio y, tras validar el informe de seguridad y las pruebas, procederá con la fusión.

