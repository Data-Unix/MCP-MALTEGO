---
name: release
description: Procedimiento para publicar una nueva versión de maltego-mcp (subida de versión, CHANGELOG, comprobaciones, PR y release de GitHub que publica en npm, GitHub Packages y el registro oficial de MCP). Úsala cuando haya que sacar una versión.
license: MIT
---
# Publicar una versión

1. Elige la versión con SemVer (`MAJOR` rompe tools o formatos, `MINOR` añade, `PATCH` corrige).
2. Cambia la versión en: `package.json`, `pyproject.toml`, `src/maltego_mcp/__init__.py` y `server.json` (dos
   campos). Ejecuta `uv lock`.
3. Añade la sección `## [X.Y.Z] - AAAA-MM-DD` a `CHANGELOG.md` (Added / Changed / Fixed / Security) y el enlace.
4. Comprueba: `uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src && npm test`
   y `npm pack --dry-run` (sin `.env`, claves, `.mtgx`, `__pycache__`).
5. Rama `release/vX.Y.Z`, PR, CI en verde (incluido el job de seguridad), revisión de `security-reviewer`, merge.
6. En GitHub: Releases → Draft new release → tag `vX.Y.Z` sobre `main`, título y notas del CHANGELOG → Publish.
   El workflow `release.yml` publica todo y es relanzable (omite lo ya publicado).
7. Comprueba: `npm view mcp-maltego version`, `npx -y mcp-maltego@X.Y.Z --version`, sección Packages y artefactos
   de la release.
Nunca publiques desde una máquina local ni con tokens en la línea de comandos.
