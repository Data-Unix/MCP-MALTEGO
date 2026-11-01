---
name: mcp-tool-change
description: Reglas y lista de comprobación para añadir o cambiar una tool MCP de maltego-mcp manteniendo 20 tools como máximo y esquemas compatibles con Gemini, Claude, Codex y el resto de clientes. Úsala antes de tocar src/maltego_mcp/tools.py.
license: MIT
---
# Cambiar una tool MCP

**Antes de crear una tool nueva**: ¿cabe como `action` de una existente? Si ya hay 20 tools, tiene que caber.

Lista de comprobación:
- [ ] Parámetros planos con `Annotated[tipo, Field(description=..., ge=, le=, max_length=)]` y valor por defecto en
      los opcionales. Prohibido `X | None`, modelos anidados, `gt/lt`, `dict`.
- [ ] Listas con `Field(default_factory=list, max_length=N)` (van antes de los parámetros con valor por defecto).
- [ ] Descripción: qué hace, cuándo usarla, qué devuelve, límites. Menos de 1024 caracteres.
- [ ] `response_format` markdown/json en las tools que devuelven datos; paginación en listados.
- [ ] La lógica va en `service.py`; la tool solo valida, llama y formatea (`format.py`: `safe`, `code`, `cell`).
- [ ] Valores OSINT en markdown con `code()`/`code_cell()` y la nota `UNTRUSTED_NOTE`.
- [ ] Errores esperados como `MaltegoMcpError` con instrucciones para el agente.
- [ ] Anotaciones (`READ_ONLY`, `WRITE_IDEMPOTENT`, `DESTRUCTIVE`, `OPEN_WORLD`).
- [ ] Tests: `tests/test_schema_portability.py`, `tests/test_copilot.py::test_exactamente_las_20_tools` y un test
      de comportamiento con el cliente MCP en proceso.
- [ ] Tablas de tools en `README.md`, `README.es.md`, `docs/USO.md`, `docs/COBERTURA.md`.
