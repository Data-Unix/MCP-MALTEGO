---
name: company-footprint
description: Flujo de reconocimiento corporativo con el MCP maltego - desde el dominio de una empresa hasta su infraestructura (DNS pasivo, subdominios por certificados, IPs, bloques y AS), registrador, correos corporativos y perfiles asociados. Úsala cuando el objetivo sea una organización.
license: MIT
---
# Huella corporativa (CompanyFootprint)

> **Aviso de pasividad:** Para reconocimiento 100 % pasivo sin generar tráfico hacia el objetivo, sigue prioritariamente
> la skill `investigacion-pasiva-no-zoom`.

1. **Semilla**: el dominio principal de la empresa (`maltego.Domain`) u organización (`maltego.Organization`).
2. **Modo pasivo estricto**:
   - NO ejecutar `machine="CompanyFootprint"` en modo pasivo: lanza transforms DNS en vivo (A, MX, NS, TXT) que contactan los servidores autoritativos del objetivo.
   - NO ejecutar `InfrastructureRecon` ni `VTDomainToSubdomains` (VirusTotal escanea bajo demanda y expone las consultas).
   - Flujo pasivo corporativo:
     a. `osint_manage_case(action="create", ...)` y `osint_upsert_entity(...)`.
     b. Subdominios pasivos: `CertSpotterSubdomains`, `HackerTargetSubdomains`, `URLScanDomainSearch`.
     c. Atribución y titularidad: `DomainToWhois`, `IPToWhois`, `IPToAS`, `IPToNetblock`, `RIPEStatASNToNetblocks`.
     d. Servicios pasivos agregados: `InternetDBIPToServices` (y `ShodanIPToServices` / `CensysIPToServices` si hay clave).
3. **Pivotes no-zoom**: `osint_suggest_next_steps` filtrando cualquier transform DNS o activo; para cada bloque o AS propio, inspecciona la titularidad y prestadores SaaS.
4. **Entrega**: `osint_export_case` (`mtgx` con layout `hierarchical`, `report_html`).
Separa siempre activos observados recientemente de históricos y respeta el Perímetro Intocable dinámico.
