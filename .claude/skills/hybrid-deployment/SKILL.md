---
name: hybrid-deployment
description: Despliegue del MCP maltego - local por stdio (gratis, grafo en ~/.maltego-mcp, .mtgx para Maltego), enriquecimiento opcional con API keys por variables de entorno, HTTP remoto y uso multiagente en Orca. Úsala para instalar, configurar clientes o diagnosticar la conexión.
license: MIT
---
# Despliegue híbrido

- **Local (recomendado)**: `npx -y mcp-maltego` en la configuración del cliente (stdio). Requisitos: Node 18+ y uv.
  Diagnóstico: `npx -y mcp-maltego doctor`. Sin claves funcionan los 18 transforms gratuitos y todo el grafo.
- **Claves bajo demanda**: en el bloque `env` del cliente MCP o variables de entorno de usuario:
  `VIRUSTOTAL_API_KEY`, `SHODAN_API_KEY`, `HUNTER_API_KEY`, `HIBP_API_KEY`, `GREYNOISE_API_KEY`,
  `SECURITYTRAILS_API_KEY`, `CENSYS_API_ID`+`CENSYS_API_SECRET`, `TATUM_API_KEY` (plantilla en `.env.example`).
  `osint_list_transforms` muestra qué proveedores están activos. Nunca las pongas en ficheros versionados.
- **Varios agentes** (Orca, Claude + Gemini...): todos comparten `~/.maltego-mcp`; en este repo cada herramienta ya
  tiene su fichero de proyecto (`.mcp.json`, `.gemini/settings.json`, `.codex/config.toml`...).
- **Remoto**: `npx -y mcp-maltego --transport http` (solo localhost; sin autenticación todavía, no lo expongas).
- **Maltego Desktop**: `npx mcp-maltego ctl mtz` para los transforms locales del puente.
