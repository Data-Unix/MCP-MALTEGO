---
name: add-builtin-transform
description: Procedimiento para añadir un transform integrado a maltego-mcp (sin API key o de un proveedor con API key) con tests sin red, verificación en vivo y documentación. Úsala cuando haya que incorporar una nueva fuente OSINT o un conector de proveedor.
license: MIT
---
# Añadir un transform integrado

1. **Diseño**: tipo(s) Maltego de entrada y salida, etiqueta de relación (`snake_case`), fuente y si necesita API key.
   Comprueba en `osint_list_entity_types` que los tipos existen.
2. **Implementación** en `src/maltego_mcp/transforms/builtin.py`:
   - handler `async def _mi_transform(ctx, etype, value, props, n) -> TransformResponse`.
   - HTTP solo con `_get_json(ctx, url, headers=..., params=..., not_found_ok=...)` o `doh(ctx, nombre, tipo)`.
   - Clave con `ctx.key("PROVEEDOR_API_KEY")`; preferible en cabecera antes que en la URL.
   - Resultados con `_ent(tipo, valor, etiqueta, weight=..., prop__con__puntos="...")` y `return _limit(items, n)`.
   - Valida lo que llega de fuera (hostnames con `_HOSTNAME_RE`, IPs con `ipaddress`).
3. **Registro**: añade `_b("Nombre", entradas, salidas, "descripción", "categoria", handler, ("CLAVE",))` a
   `BUILTIN_TRANSFORMS`. Proveedores: categoría `proveedor:<nombre>` y su clave en `PROVIDER_KEYS`.
4. **Machines**: si encaja, añádelo a la etapa adecuada en `machines.py` (se omite solo si falta la clave).
5. **Tests** en `tests/test_builtin.py`: respuesta simulada con el formato REAL del servicio en `Router`, caso
   parametrizado, errores (401/429/timeout) y cabeceras de autenticación.
6. **Verificación en vivo** (solo transforms sin clave): ejecútalo una vez contra el servicio real con
   `uv run maltegoctl lookup Nombre valor`.
7. **Documentación**: tabla de transforms en `README.md`, `README.es.md`, `docs/USO.md`; `docs/COBERTURA.md`
   (V = probado en vivo, S = simulado); `.env.example` si hay clave nueva; `CHANGELOG.md`.
8. `uv run pytest -q && uv run ruff check . && uv run mypy src`.
