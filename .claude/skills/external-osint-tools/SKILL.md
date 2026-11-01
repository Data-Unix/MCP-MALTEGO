---
name: external-osint-tools
description: Integrar en el grafo del MCP maltego resultados de herramientas OSINT de Kali y similares (theHarvester, amass, sublist3r, recon-ng, SpiderFoot, metagoofil) o de un servidor MCP de Kali, con ejecución segura y conversión a CSV/entidades. Úsala cuando haya salidas de esas herramientas que incorporar.
license: MIT
---
# Herramientas OSINT externas → grafo

**Requisitos**: herramienta instalada, petición explícita del usuario y objetivo autorizado. Prefiere modos pasivos.

**Ejecución segura** (si el agente la lanza): valida el objetivo con un patrón estricto (dominio/IP), pásalo como
argumento independiente (sin interpolar en una cadena de shell), y escribe la salida en `~/.maltego-mcp/imports/`.

| Herramienta | Salida útil | Entidades |
|---|---|---|
| theHarvester (`-d dom -b <fuentes> -f salida`) | correos, hosts, IPs | EmailAddress, DNSName, IPv4Address |
| amass (`enum -passive -d dom -json salida`) | subdominios, IPs | DNSName, IPv4Address |
| sublist3r (`-d dom -o salida`) | subdominios | DNSName |
| recon-ng (módulos de reconocimiento, export CSV) | contactos, hosts | Person, EmailAddress, DNSName |
| SpiderFoot (export CSV) | variado | según tipo |
| metagoofil (metadatos de documentos) | autores, rutas | Person, Document |

**Importación**: genera un CSV `source_type,source_value,relation,target_type,target_value,confidence`
(p. ej. `maltego.Domain,example.com,subdomain,maltego.DNSName,www.example.com,0.6`) y llama a
`osint_import_graph`; o usa `osint_upsert_entity(entity_type="auto", source="amass")` para pocos datos.
Después: `osint_run_machine(machine="DomainRecon")` sobre lo importado y `osint_suggest_next_steps`.
