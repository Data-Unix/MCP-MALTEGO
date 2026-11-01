---
name: custom-provider
description: Cómo conectar APIs internas, bases de datos privadas o transforms propios al MCP maltego sin tocar el núcleo (capa enchufable mediante servidor de transforms TRX declarado en el catálogo) y cómo hacerlas aparecer automáticamente en las Machines. Úsala para integrar fuentes privadas o de la organización.
license: MIT
---
# Proveedor propio (capa enchufable)

**Opción recomendada (sin tocar el código del MCP)**: un servidor de transforms con maltego-trx.
1. Copia `examples/trx_server/` y escribe una clase `DiscoverableTransform` por consulta a tu API
   (`response.addEntity(tipo, valor)`, `setLinkLabel(...)`); las credenciales, en variables de entorno del servidor.
2. Arráncalo (`uv run python tu_servidor.py --port 8090`, solo en `127.0.0.1` o tras autenticación).
3. Decláralo en `~/.maltego-mcp/transforms.toml`:
   ```toml
   [[servers]]
   name = "interno"
   url = "http://127.0.0.1:8090"
   api_key_env = "MI_API_INTERNA_TOKEN"   # opcional: se envía como Authorization: Bearer

   [[transforms]]
   name = "InternalDomainToOwner"
   server = "interno"
   input_types = ["maltego.Domain"]
   output_types = ["maltego.Person"]
   ```
4. Úsalo en una Machine propia (skill `add-machine`) o con `osint_run_transform`. El mismo servidor sirve también a
   Maltego Desktop (registro como iTDS o transforms locales).

**Opción integrada** (fuentes públicas útiles para todos): skill `add-builtin-transform`.

Comprueba con `osint_list_transforms(check_servers=true)` que el servidor responde.
