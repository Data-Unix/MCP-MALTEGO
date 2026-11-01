---
name: security-review
description: Lista de comprobación de seguridad de maltego-mcp para revisar cambios y preparar releases (secretos, datos OSINT no confiables, XML y ZIP, SSRF, Gremlin, CSV/HTML, workflows de GitHub y contenido del paquete npm). Úsala en cada revisión de código y antes de cada release.
license: MIT
---
# Revisión de seguridad

**Secretos**
- Ninguna clave en código, tests, docs ni ejemplos (`.env.example` vacío). Solo variables de entorno.
- `.gitignore` cubre `.env*`, claves, `data/`, `exports/`, `imports/`, `*.mtgx`, `*.mtz`, `transforms.toml`.
- Logs: httpx/httpcore nunca por debajo de WARNING (algunas claves van en la URL).
- `npm pack --dry-run`: sin ficheros sensibles (lo comprueba la CI).

**Datos no confiables**
- Valores OSINT limpiados y truncados (`format.safe`), mostrados como código y con `UNTRUSTED_NOTE`.
- Ningún texto recuperado decide acciones del servidor.

**Entradas y formatos**
- XML solo con `defusedxml`; ZIP con tamaños y número de ficheros acotados antes de leer.
- Importaciones solo desde `imports/` y `exports/` (comprobación con `resolve()` + `is_relative_to`).
- URLs de transforms solo del catálogo (sin SSRF); `follow_redirects=False` en TRX.
- Gremlin: plantillas constantes, valores en bindings, sin nombres reservados.
- CSV con protección de fórmulas; HTML de informes escapado y con CSP sin scripts.

**GitHub**
- Workflows con `permissions` mínimos por job, `persist-credentials: false`, secretos solo en el paso que los usa.
- Acciones de terceros revisadas; Dependabot activo; job `security` (gitleaks + pip-audit) en verde.

Entrega: hallazgos con fichero:línea, escenario concreto y gravedad; sin cambios de código.
