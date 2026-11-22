---
name: infrastructure-mapping
description: Mapeo de topología e infraestructura con el MCP maltego (DomainRecon e InfrastructureRecon) - DNS pasivo, subdominios por certificados SSL/TLS, IPs, AS, bloques, WHOIS de red y servicios/puertos expuestos. Úsala para dominios, hosts o IPs.
license: MIT
---
# Mapeo de infraestructura (DomainRecon / InfrastructureRecon)

> **Aviso de pasividad:** Para mapeo de infraestructura 100 % pasivo sin generar tráfico hacia los servidores del objetivo,
> sigue prioritariamente la skill `investigacion-pasiva-no-zoom`.

**Advertencia de pasividad**:
En modo pasivo están PROHIBIDAS las Machines activas:
- NO usar `machine="DomainRecon"`: ejecuta resoluciones DNS en vivo (DNSToIP, DNSToIPv6, DomainToMX, DomainToNS, DomainToTXT, DNSToCNAME) hacia los NS autoritativos del objetivo.
- NO usar `machine="InfrastructureRecon"`: ejecuta DNS inverso en vivo (`IPToReverseDNS`) y resolución directa (`DNSToIP`).

**Flujo pasivo sustitutivo**:
1. **Dominio** → `osint_manage_case` + `osint_upsert_entity`:
   - Subdominios por certificados y datasets pasivos: `DomainToSubdomains`, `CertSpotterSubdomains`, `HackerTargetSubdomains`, `URLScanDomainSearch`.
   - Titularidad y registro: `DomainToWhois`.
2. **IP** → `osint_manage_case` + `osint_upsert_entity`:
   - Red y BGP: `IPToAS`, `IPToNetblock`, `IPToWhois` y `RIPEStatASNToNetblocks`.
   - Servicios expuestos en datasets agregados: `InternetDBIPToServices`.
   - Con API keys configuradas: `ShodanIPToServices`, `CensysIPToServices` y `GreyNoiseIPContext`.
   - Reputación y malware: `UrlhausHostToThreats`, `CisaKevToVulnerabilities`.
3. **Agrupación y topología**: agrupa por AS/bloque con `osint_get_neighbors` para separar infraestructura propia de terceros (CDN, hosting, nube).
4. **Caminos y dependencias**: `osint_find_paths` para trazar relaciones entre activos sin tocarlos.
5. **Presupuestos**: empieza con `max_total_entities=150`; sube rondas solo si `osint_suggest_next_steps` lo justifica y filtrando siempre cualquier sugerencia activa.

Regla de oro: Cero peticiones de cualquier protocolo hacia la infraestructura del objetivo; todo activo descubierto entra en el Perímetro Intocable.
