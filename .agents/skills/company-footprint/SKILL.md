---
name: company-footprint
description: Flujo de reconocimiento corporativo con el MCP maltego - desde el dominio de una empresa hasta su infraestructura (DNS, subdominios, IPs, bloques y AS), registrador, correos corporativos y perfiles asociados. Úsala cuando el objetivo sea una organización.
license: MIT
---
# Huella corporativa (CompanyFootprint)

1. Semilla: el dominio principal de la empresa (`maltego.Domain`). Si solo tienes el nombre, guárdalo como
   `maltego.Company` y pide o busca el dominio oficial antes de continuar.
2. `osint_run_machine(machine="CompanyFootprint", max_rounds=1, max_total_entities=200, reason=...)`:
   DNS (A, MX, NS, TXT), WHOIS/RDAP, subdominios por certificados (crt.sh), correos (Hunter si hay clave), IPs → AS,
   bloque y WHOIS de red, alias de los correos → perfiles públicos.
3. Revisa con `osint_get_case_summary`; los registros TXT revelan proveedores (SPF, verificaciones de dominio).
4. Pivotes: `osint_suggest_next_steps`; para cada bloque o AS propio, `InfrastructureRecon` sobre IPs clave.
5. Más fuentes con clave: `VTDomainToSubdomains`, `SecurityTrailsSubdomains`, `ShodanIPToServices`.
6. Entrega: `osint_export_case` (`mtgx` con layout `hierarchical`, `report_html`).
Separa activos confirmados (DNS/RDAP actuales) de históricos (certificados antiguos, resoluciones pasadas).
