---
name: infrastructure-mapping
description: Mapeo de topología e infraestructura con el MCP maltego (DomainRecon e InfrastructureRecon) - DNS, subdominios por certificados SSL/TLS, IPs, AS, bloques, WHOIS de red, DNS inverso y servicios/puertos expuestos. Úsala para dominios, hosts o IPs.
license: MIT
---
# Mapeo de infraestructura (DomainRecon / InfrastructureRecon)

- **Dominio** → `osint_run_machine(machine="DomainRecon", max_rounds=1)`: etapa 1 DNS + WHOIS + certificados +
  web; etapa 2 resuelve hosts nuevos (`DNSToIP`, `DNSToCNAME`); etapa 3 `IPToAS` + `IPToNetblock`.
- **IP** → `osint_run_machine(machine="InfrastructureRecon")`: DNS inverso, AS, bloque, WHOIS de red; con claves,
  `ShodanIPToServices`/`CensysIPToServices` (puertos, servicios, `[CVE] ...`) y `GreyNoiseIPContext`.
- Agrupa por AS/bloque con `osint_get_neighbors` para separar infraestructura propia de terceros (CDN, nube).
- Caminos entre activos: `osint_find_paths`.
- Presupuestos: empieza con `max_total_entities=150`; sube rondas solo si `osint_suggest_next_steps` lo justifica.
Solo fuentes pasivas: nunca escanees ni pruebes servicios de terceros sin autorización.
