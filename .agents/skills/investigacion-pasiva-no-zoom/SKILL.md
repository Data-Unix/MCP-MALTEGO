---
name: investigacion-pasiva-no-zoom
description: Metodología de investigación OSINT 100 % pasiva y sin zoom (Outside-In Thinking y lectura lateral) sobre infraestructura, organizaciones y personas, con Perímetro Intocable dinámico, cadena modular P0-P9 y redacción estimativa.
license: MIT
---
# Metodología de Investigación OSINT 100 % Pasiva y "No Zoom"

Guía operativa para investigaciones rigurosas sin interacción, donde cualquier tráfico hacia la infraestructura del objetivo
está terminantemente prohibido. Combina la garantía de pasividad técnica con la disciplina analítica "No Zoom" (Outside-In Thinking
y lectura lateral) y redacción estimativa de inteligencia.

---

## 1. Regla de Oro y Perímetro Intocable

### Regla de Oro
**Cero peticiones de cualquier protocolo a cualquier activo del objetivo**, ni directas ni por proxy, ni desde el software
(`maltego-mcp`), ni desde el navegador, scripts o Maltego Desktop del analista.

### Perímetro Intocable Dinámico ("Efecto Contagio")
El objetivo bajo investigación no es un dominio estático: **crece con cada nuevo hallazgo**. Todo elemento descubierto pasa a
formar parte inmediata del Perímetro Intocable:
- Dominios principales, dominios hermanos, subdominios, direcciones IP y prefijos de red del objetivo.
- Empleados identificados, directivos, colaboradores y sus sitios web o blogs personales.
- **Activos del objetivo alojados en plataformas de terceros:**
  - Espacios de trabajo: `empresa.slack.com`, `empresa.atlassian.net`, `empresa.notion.site`, `empresa.sharepoint.com`.
  - Repositorios y almacenamiento: buckets `*.s3.amazonaws.com`, contenedores Azure Blob, Google Cloud Storage.
  - Canales de difusión y captación: enlaces Linktree (`linktr.ee/empresa`), páginas de Calendly, URLs cortas de Bitly.
  *(Aviso: El bloqueo aplica al host o identificador del activo en el tercero, no a la plataforma en su conjunto).*

### Clasificación Operativa de Tráfico
Toda acción se clasifica bajo una de las siguientes clases:
- `local`: Sin tráfico de red. Cálculo o inferencia determinista sobre el grafo local en memoria o base de datos local. **(PERMITIDO)**.
- `passive`: Consulta a datasets agregados de terceros que sirven datos recolectados previamente de forma ajena a nuestra consulta. **(PERMITIDO)**.
- `active_proxy`: Un tercero contacta al objetivo como consecuencia directa de nuestra petición (DoH recursivo contra el NS autoritativo, escaneo bajo demanda, VirusTotal, peticiones web en vivo). **(BLOQUEADO)**.
- `active_direct`: Conexión de red directa iniciada desde nuestra infraestructura hacia activos del objetivo. **(BLOQUEADO)**.
- `owner_telemetry`: Consulta a plataformas de terceros que notifican al titular del activo sobre la visita o registran telemetría identificativa en su panel de administración. **(BLOQUEADO / RESTRINGIDO)**.

---

## 2. Prohibiciones Operativas Vigentes (Protección por Procedimiento)

Mientras no se implemente la barrera automática a nivel de transporte HTTP en el código, el analista debe aplicar estrictamente
las siguientes prohibiciones por procedimiento:

1. **Transforms PROHIBIDOS**:
   - Transforms DNS en vivo: `DNSToIP`, `DNSToIPv6`, `DomainToMX`, `DomainToNS`, `DomainToTXT`, `DNSToCNAME`, `IPToReverseDNS`.
     *(Motivo: resuelven mediante DoH recursivo que alcanza a los servidores de nombres autoritativos del objetivo, transfiriendo la subred del cliente ECS).*
   - Pivote Dark Web activo: `OnionPassivePivot`.
     *(Motivo: ejecuta un HTTP GET directo contra el servidor .onion e inyecta credenciales o cookies de sesión).*
   - Transforms de VirusTotal: `VTDomainToIP`, `VTIPToDomain`, `VTDomainToSubdomains`, `VTHashToDetection`.
     *(Motivo: la API de VirusTotal escanea bajo demanda y hace públicas las búsquedas efectuadas).*
2. **Machines PROHIBIDAS**:
   - `DomainRecon`, `InfrastructureRecon`, `EmailRecon`, `URLRecon`, `CompanyFootprint` y `DarkWebFootprint`.
   - Prohibido invocar `osint_expand_entity` sobre dominios, IPs, URLs o sitios web (ejecuta en cascada todos los transforms aplicables, incluidos los activos).
3. **Herramienta `osint_investigate` PROHIBIDA en Modo Pasivo**:
   - En el código actual, `osint_investigate` siempre ejecuta automáticamente la Machine asociada al tipo de semilla (ej. `DomainRecon` para dominios), desencadenando DNS en vivo.
   - **Flujo Pasivo Obligatorio:**
     1. `osint_manage_case(action="create", case_id=...)`: Crear el caso con identificador temático.
     2. `osint_upsert_entity(case_id=..., entity_type=..., value=...)`: Registrar la entidad semilla.
     3. `osint_run_transform(...)`: Ejecutar uno a uno exclusivamente los transforms pasivos permitidos (sección 3).
     4. Revisión y filtrado: `osint_get_case_summary`, `osint_get_neighbors`, `osint_find_paths`, `osint_get_timeline`.
     5. `osint_suggest_next_steps`: Usar solo como orientación heurística; si sugiere un transform activo, **descartarlo**.
     6. Entrega: `osint_export_case` (`mtgx` y reportes HTML/Markdown).
4. **Machines Permitidas en Modo Pasivo**:
   - `machine="ASNToNetblocks"`: Solo consulta RIPEstat API (100 % pasiva).
   - `machine="CryptoFlowRecon"`: Solo consulta mempool.space y algoritmos de clustering locales (100 % pasiva).
   - `machine="PersonalFootprint"`: Consulta Gravatar, HIBP, GitHub API y RDAP (100 % pasiva).

---

## 3. Catálogo de Transforms Pasivos Permitidos Hoy

Todos los siguientes transforms operan exclusivamente contra datasets históricos y preexistentes de terceros:

### Certificados y Descubrimiento de Subdominios
- `DomainToSubdomains`: Consulta logs públicos de Certificate Transparency (CT) en crt.sh con respaldo automático en CertSpotter (fuente principal de certificados).
- `CertSpotterSubdomains`: Consulta logs públicos de Certificate Transparency (CT) en CertSpotter.
- `HackerTargetSubdomains`: Consulta el dataset histórico `hostsearch` de HackerTarget (nunca sus herramientas activas).
- `URLScanDomainSearch`: Consulta el histórico de escaneos públicos indexados en urlscan.io (búsqueda `/api/v1/search/`; nunca endpoints de submit o escaneo en vivo).

### WHOIS, BGP y Superficie de Red
- `DomainToWhois`: Consulta datos de registro y titularidad histórica mediante RDAP público (rdap.org).
- `IPToWhois`: Consulta asignación de bloques y titularidad de red en registros RIR mediante RDAP.
- `IPToAS`: Consulta DNS TXT a Team Cymru a través de DoH (dns.google). Es pasivo respecto al objetivo, pero Google y Cymru ven la IP consultada. No es un cálculo en memoria.
- `IPToNetblock`: Consulta DNS TXT a Team Cymru a través de DoH (dns.google). Es pasivo respecto al objetivo, pero Google y Cymru ven la IP consultada. No es un cálculo en memoria.
- `RIPEStatASNToNetblocks`: Consulta la API de RIPEstat para obtener bloques BGP anunciados por un ASN.
- `InternetDBIPToServices`: Consulta la base consolidada Shodan InternetDB (puertos abiertos, vulnerabilidades y etiquetas ya indexadas, sin escanear).

### Proveedores Especializados (Requieren API Key)
- `ShodanIPToServices`: Consulta histórico indexado en Shodan (solo endpoint de búsqueda; nunca escaneo interactivo).
- `CensysIPToServices`: Consulta registros de hosts indexados en Censys Search.
- `SecurityTrailsSubdomains`: Consulta subdominios históricos indexados en SecurityTrails.
- `GreyNoiseIPContext`: Contextualiza si una IP pertenece a ruido de escaneo indiscriminado en Internet.

### Identidad, Filtraciones y Atribución
- `HudsonRockStealerCheck`: Consulta la base de datos de Hudson Rock sobre registros de malware infostealer (recuentos de empleados/clientes comprometidos).
- `BreachSemanticPivot`: Correlación semántica en bases de datos locales de filtraciones conocidas.
- `HIBPEmailToBreaches`: Consulta brechas públicas asociadas a una cuenta en Have I Been Pwned.
- `GravatarEmailToProfile`: Consulta perfil público asociado al hash criptográfico de un correo.
- `GitHubAliasToDetails`: Consulta metadatos del perfil de un usuario en la API pública de GitHub.
- `GitHubAliasToCommitEmails`: Extrae correos de autoría de commits en repositorios públicos de GitHub.
- `KeybaseAliasToProofs`: Consulta identidades verificadas y claves PGP públicas en Keybase.
- `AliasToProfiles`: Comprueba la existencia de perfiles de un alias en redes públicas de terceros mediante endpoints estáticos.
- `AnalyzeSubjectBehavior`: Perfilado conductual pericial local sin conexión de red.

### Reputación, Inteligencia de Amenazas y Blockchain
- `UrlhausHostToThreats`: Consulta reportes históricos de malware en abuse.ch para un dominio o dirección IP.
- `CisaKevToVulnerabilities`: Verificación en catálogo CISA de vulnerabilidades activamente explotadas.
- `DeepDarkCTISearch`: Consulta índice local + api.ransomware.live + ahmia.fi + sincronización desde GitHub (no es solo local). Sus resultados .onion NUNCA se pasan a OnionPassivePivot.
- `MempoolAddressToTransactions` / `MempoolTxToInputsOutputs`: Trazabilidad pública de transacciones Bitcoin vía mempool.space.
- `CryptoClusteringCIOH`: Algoritmo de grafo local para clustering de direcciones por co-gasto (CIOH).
- `OFACSanctionsCryptoLookup` / `CryptoAddressToExchange`: Cotejo contra tablas locales de sanciones OFAC y exchanges.

*(Restricción: Ningún transform se ejecuta sobre semillas clasificadas como "activo del objetivo en tercero", ej. Slack o S3).*

---

## 4. Metodología "No Zoom" (Outside-In Thinking y Lectura Lateral)

El enfoque "No Zoom" rompe con el sesgo habitual de enfocar la lupa directamente sobre la infraestructura del objetivo (Inside-Out).
Se fundamenta en dos disciplinas analíticas consolidadas:

1. **Outside-In Thinking** (CIA Tradecraft Primer 2009, p. 30):
   *Identificar el conjunto completo de fuerzas indirectas, factores ambientales, proveedores y terceros que moldean al objetivo, en lugar de mirar únicamente sus activos centrales.*
   Se investiga lo que el ecosistema exterior dice o expone sobre el objetivo.
2. **Lectura Lateral** (Wineburg y McGrew, Stanford History Education Group 2017):
   *Nunca evaluar una fuente permaneciendo dentro de ella; abrir pestañas laterales para investigar quién es la fuente, qué intereses tiene, quién la financia y quién más corrobora o contradice su información.*

### Principios del Análisis No Zoom
- **Desconfianza de la presencia oficial:** La información más valiosa nunca está en la página principal corporativa; reside en certificados históricos, boletines mercantiles, ofertas de empleo de proveedores, filtraciones y repositorios de terceros.
- **Trazabilidad en cadena (Cadena de Custodia):** Cada dato debe registrar fuente original, fecha de recolección, hash del contenido y familia independiente.
- **Evaluación disociada:** La fiabilidad de la fuente y la credibilidad del dato se evalúan por separado (sistema Admiralty).
- **Prohibición de confirmar en vivo:** Nunca se "verifica si un host sigue levantado" haciendo ping o visitándolo en el navegador.

---

## 5. Motor de Semillas Recursivo por Tipo

El proceso pasivo no es una secuencia lineal de un solo paso; es un motor modular donde cada dato descubierto actúa como **semilla**
que habilita módulos específicos según su naturaleza:

| Tipo de Semilla | Módulos No-Zoom Aplicables | transforms / Procedimiento Pasivo |
|---|---|---|
| **Organización** | P1 (Identidad), P8 (Ecosistema), P4/P5 (Dorking), P7 (HUMINT) | Registros mercantiles, O= en CT, BOE/BORM, contratos públicos. |
| **Dominio** | P2 (Infraestructura), P3 (Archivos web), P4/P5 (Dorking), P6 (Código) | `DomainToSubdomains`, `CertSpotterSubdomains`, `HackerTargetSubdomains`, `DomainToWhois`. |
| **Subdominio / Host** | P2 (Vigencia pasiva), P3 (Archivos web), P5 (Dorking dirigido) | `URLScanDomainSearch`, cotejo de registros históricos en pDNS. |
| **Persona / Empleado** | P7 (HUMINT pasivo), P5 (Dorking), P6 (Commits), P6 (Filtraciones) | Snippets de perfiles públicos sin sesión, `GitHubAliasToDetails`. |
| **Alias / Usuario** | P7 (Redes y foros), P6 (Código), P5 (Dorking) | `AliasToProfiles`, `KeybaseAliasToProofs`, búsqueda en repositorios. |
| **Correo Electrónico** | P6 (Filtraciones), P7 (Identidad), P5 (Dorking) | `BreachSemanticPivot`, `HIBPEmailToBreaches`, `GravatarEmailToProfile`. *(Prohibida verificación SMTP).* |
| **Documento Descargado** | P3 (Metadatos offline) → Nuevas semillas | Extracción forense offline de metadatos (autores, rutas, software). |
| **Tecnología / Proveedor** | P8 (Ecosistema), P5 (Dorking de configuraciones) | Casos de éxito de proveedores, documentación pública de despliegues. |
| **Activo en Tercero** (S3, Slack...) | P4/P5 (Solo snippets / archivo) | Entra automáticamente en el Perímetro Intocable. Prohibido GET o LIST. |

### Atributos de cada Semilla en el Grafo
Cada entidad descubierta debe registrar en sus notas o propiedades:
- `seed_type`: Tipo normalizado de semilla.
- `seed_origin`: Fase donde se originó, fuente primaria y semilla padre.
- `hop_depth`: Nivel de profundidad en el árbol de investigación (máximo 2 saltos).
- `status`: Estado operativo (`nueva`, `en_analisis`, `completada`, `descartada_motivo`).
- `families_applied`: Lista de familias de fuentes independientes ya consultadas.
- `remaining_budget`: Presupuesto de consultas restantes.

### Bucle No Zoom por Semilla
Antes de profundizar en cualquier semilla, el analista debe responderse:
1. *¿Quién más habla de esto fuera del objetivo?*
2. *¿Qué familia de fuentes independiente aún no se ha consultado para contrastar?*
3. *¿Qué evidencia concreta refutaría la hipótesis sobre esta semilla?*

### Presupuesto de Amplitud y Criterios de Parada
- **Mínimos obligatorios:** Al menos 4 familias de fuentes independientes, 3 hipótesis alternativas en competencia y 1 búsqueda dirigida explícitamente a refutar la hipótesis principal.
- **Máximos por caso:** Alrededor de 8 familias de fuentes, máximo 5 consultas por familia y tope estricto de 2 saltos de profundidad.
- **Criterio de Parada:** El ciclo concluye cuando una ronda de recolección no modifica la probabilidad estimativa de ninguna de las hipótesis activas.

---

## 6. Cadena Modular de Fases (P0 - P9)

### P0. Encuadre y Alcance
- **Objetivo:** Definir con claridad la pregunta de inteligencia, el marco legal y el presupuesto.
- **Fuentes:** Documento de encargo, mandato de investigación, base legítima (Ley 5/2014, RGPD).
- **Semillas producidas:** Pregunta neutral del caso, delimitación del Perímetro Intocable inicial, registro de supuestos previos.
- **Giro No Zoom:** Identificar qué estamos dando por sentado antes de buscar y planificar búsquedas de refutación.

### P1. Identidad y Dominio Principal
- **Objetivo:** Determinar la estructura legal de la empresa y resolver la **Pregunta de Decisión:** *¿Cuenta la empresa con dominio web principal actualmente?*
- **Fuentes Pasivas:** Registros mercantiles oficiales (BORME, Infocif), snippets de buscadores, campo `O=` (Organization) en certificados de Certificate Transparency (crt.sh), registros WHOIS/RDAP históricos, identificadores de analítica compartidos en capturas antiguas.
- **Semillas producidas:** Razón social, NIF/CIF, marcas registradas, dominio principal o dominios hermanos.
- **Giro No Zoom:** No asumir que la empresa se limita a su dominio público visible; los certificados y el WHOIS histórico revelan infraestructuras que la empresa nunca enlaza activamente.
- **Bifurcación:**
  - **SI cuenta con dominio principal:** Continuar hacia la fase **P2**.
  - **NO cuenta con dominio principal:** Desviar inmediatamente la investigación hacia las fases **P5 (Dorking No Zoom)**, **P7 (HUMINT Pasivo)** y **P8 (Ecosistema y Terceros)**.

### P2. Reconocimiento Pasivo de Infraestructura y Vigencia
- **Objetivo:** Inventariar subdominios, prefijos de red, proveedores de nube/correo y determinar la vigencia de los activos.
- **Fuentes Pasivas:** Certificate Transparency (`DomainToSubdomains` con respaldo `CertSpotterSubdomains`), dataset histórico `HackerTargetSubdomains`, búsqueda en `URLScanDomainSearch`, RDAP (`DomainToWhois`, `IPToWhois`), BGP (`RIPEStatASNToNetblocks`, `IPToAS`). *(Futura integración en código: Mnemonic pDNS, Robtex pDNS, OTX pDNS).*
- **Semillas producidas:** Subdominios catalogados por estado de vigencia, IPs de infraestructura, ASN, rangos de red, prestadores SaaS.
- **Giro No Zoom:** Descubrir proveedores terceros (SaaS, CDN, agencias) que amplían la superficie sin ser infraestructura directa; aislar posibles canarios o dominios trampa.
- **Clasificación de Vigencia sin tocar el host:**
  - `OBSERVADO_RECIENTE`: Evidencia con marca temporal menor o igual a 30 días en pDNS o escaneos agregados, o certificado CT no revocado emitido en los últimos 90 días.
  - `HISTORICO`: Solo registros con fechas antiguas.
  - `MENCIONADO_SIN_FECHA`: Agregadores sin marcas de tiempo corroboradas.

### P3. Huella Histórica en Archivos Web
- **Objetivo:** Recuperar documentación, páginas corporativas y activos que la entidad publicó y posteriormente eliminó.
- **Fuentes Pasivas:** Wayback Machine CDX API (`web.archive.org/cdx/`), Arquivo.pt, Common Crawl.
- **Semillas producidas:** URLs y parámetros antiguos, rutas internas, documentos (PDF, DOCX) con metadatos de autor, versiones borradas de páginas de equipo y contactos.
- **Riesgo de Pasividad:** Descarga **exclusivamente desde la réplica del archivo** (`id_`); nunca descargar el documento desde el servidor del objetivo.
- **Metadatos Offline:** El análisis de archivos descargados debe realizarse en un entorno offline sin conexión, extrayendo metadatos mediante herramientas locales (`exiftool`, `pdfinfo`) sin renderizar el documento ni ejecutar JavaScript incrustado.

### P4. Dorking Básico
- **Objetivo:** Localizar documentación expuesta, paneles administrativos y referencias indexadas mediante operadores avanzados.
- **Fuentes Pasivas:** Buscadores públicos consultados en modo guiado manual aislado.
- **Semillas producidas:** Documentos indexados, subdominios adicionales, patrones de nomenclatura.
- **Regla Estricta:** Se leen **únicamente los snippets** de los resultados de búsqueda. Está terminantemente prohibido hacer clic en un enlace que apunte a infraestructura del objetivo (abrir siempre la versión archivada en archivos web como Wayback o arquivo.pt; la caché de motores de búsqueda ya no existe).

### P5. Dorking Profundo "No Zoom"
- **Objetivo:** Localizar menciones, configuraciones y filtraciones sembrando búsquedas dirigidas **hacia el exterior** del dominio objetivo.
- **Fuentes Pasivas:** Plataformas públicas de terceros: GitHub, Gist, GitLab, Pastebin, workspaces públicos de Postman, tableros públicos de Trello/Notion, Stack Overflow, Docker Hub, registros de contratación pública y foros especializados.
- **Semillas producidas:** Subdominios internos (ej. `"intranet.dominio"`), claves o endpoints en colecciones de Postman, quejas o reseñas de proveedores.
- **Giro No Zoom:** Se buscan las semillas descubiertas en P1-P4 en entornos ajenos al objetivo; toda valoración de reputación o críticas de clientes se somete al filtro de desinformación MOM/POP/MOSES/EVE.

### P6. Exposición de Código y Filtraciones
- **Objetivo:** Evaluar la exposición de credenciales corporativas, infraestructura interna y código fuente.
- **Fuentes Pasivas:** `HudsonRockStealerCheck`, `BreachSemanticPivot`, `HIBPEmailToBreaches`, búsquedas de código público en GitHub/GitLab, `GitHubAliasToCommitEmails`.
- **Semillas producidas:** Repositorios de empleados, cuentas corporativas en dumps, dominios internos reflejados en configuraciones.
- **Regla de Seguridad:** Las credenciales descubiertas en filtraciones o repositorios se tratan como potenciales señuelos o honeytokens; está terminantemente prohibido utilizarlas o verificar su validez contra servicios del objetivo.

### P7. HUMINT Pasivo (Personal y Colaboradores)
- **Objetivo:** Inferir la estructura operativa, tecnologías empleadas y proyectos a partir de la información que los trabajadores publican como méritos profesionales.
- **Fuentes Pasivas:** Perfiles profesionales consultados **sin iniciar sesión**, portfolios (Behance, GitHub), charlas técnicas, diapositivas y ofertas de empleo publicadas en portales de trabajo.
- **Semillas producidas:** Organigrama estimado, stack tecnológico interno, proyectos en curso, clientes mencionados.
- **Protección Legal:** Restricción estricta a información profesional y redes públicas; queda prohibido indagar sobre la vida privada o íntima (Ley 5/2014 de Seguridad Privada, principio de minimización del RGPD). Prohibida cualquier interacción o envío de solicitudes.

### P8. Ecosistema, Proveedores y Terceros
- **Objetivo:** Cartografiar la red de relaciones comerciales, litigios, reguladores y dependencias tecnológicas.
- **Fuentes Pasivas:** Casos de éxito publicados por proveedores de software o hardware, adjudicaciones públicas, resoluciones judiciales, memorias anuales de socios comerciales.
- **Semillas producidas:** Proveedores críticos, clientes institucionales, riesgos de concentración.
- **Giro No Zoom:** Lectura lateral obligatoria: analizar quién publica el caso de éxito y qué interés comercial tiene en presentarlo.

### P9. Síntesis y Evaluación Estimativa
- **Objetivo:** Integrar el grafo, confrontar hipótesis rivales y formular el juicio de inteligencia.
- **Metodología:** Análisis de Hipótesis en Competencia (ACH), escala de probabilidad ICD 203 y tabla de fiabilidad/credibilidad Admiralty.
- **Resultado:** Informe de inteligencia estructurado con hipótesis alternativas, lagunas identificadas e indicadores que refutarían la estimación.

---

## 7. Matriz de Telemetría del Propietario (`owner_telemetry`)

Determinadas plataformas de terceros notifican al propietario sobre quién consulta su perfil o registran datos atribuibles.
Se aplica la siguiente matriz rigurosa:

### PROHIBIDO (Activo por Telemetría de Propietario)
- Consultar LinkedIn con sesión iniciada fuera de modo totalmente privado; usar Sales Navigator; realizar búsquedas logueado en LinkedIn.
- Visualizar Stories de Instagram o Facebook (generan lista de visualizadores al titular).
- Navegar en TikTok con historial de visualizaciones activado.
- Búsquedas o consultas en Truecaller (alerta al titular del número).
- Unirse, suscribirse o interactuar en canales o grupos de Telegram (genera evento de incorporación).
- Añadir números a la agenda telefónica sincronizada con WhatsApp o Telegram.
- Acciones interactivas en GitHub/Postman: star, watch, follow, fork.
- Hacer clic en enlaces de Bitly o acortadores similares; visitar directamente perfiles de Linktree, Typeform o Calendly del objetivo.
- Enumeración activa de usuarios en Microsoft 365 (autologon, GetCredentialType).
- Enviar peticiones GET o LIST a buckets S3 de AWS, Azure o Google Cloud (los accesos, incluso anónimos, quedan registrados en el bucket logging del objetivo).
- Abrir documentos PDF/DOCX en visores o editores ofimáticos conectados a Internet (riesgo de web bugs y canarytokens).

### PERMITIDO (Sin Sesión o vía API)
- Perfiles y publicaciones públicas de Instagram, Facebook, X, Threads y Bluesky consultados sin iniciar sesión o mediante agregadores.
- Canales públicos de Telegram consultados mediante la vista web de vista previa `t.me/s/<canal>` sin cuenta.
- API REST pública anónima de GitHub para consultar perfiles y repositorios.
- Blogs y plataformas de contenido: Medium, Substack, YouTube, Behance, Pastebin (`/raw/`), Glassdoor (sin autenticar).
- Documentos de Google Drive/Docs públicos abiertos en navegador aislado sin cuenta de Google activa.
- Páginas públicas de Notion y Trello consultadas sin sesión.

---

## 8. Protección del Cliente y Confidencialidad de la Investigación

1. **Compartimentación y Huella ante Terceros**:
   - Todas las consultas a proveedores y buscadores deben realizarse a través de túneles VPN o proxies de salida no atribuibles al despacho ni al cliente.
   - Las claves de API y cuentas operativas deben estar desvinculadas de identidades reales o corporativas.
   - Empleo de User-Agent genérico y neutro sin menciones al software ni repositorios privados.
2. **Documentos Trampa (Canarytokens y Web Bugs)**:
   - Todo archivo obtenido desde archivos web o repositorios públicos debe procesarse en un entorno local aislado de red.
   - Prohibido abrir documentos en navegadores convencionales o suites ofimáticas sin deshabilitar la carga de recursos remotos.
3. **Credenciales Trampa (Honeytokens)**:
   - Cualquier contraseña o token hallado en repositorios o filtraciones debe registrarse como indicio documental; jamás debe intentarse su autenticación contra servicios remotos.
4. **Prohibición de Verificación Activa**:
   - Prohibido validar correos mediante handshakes SMTP VRFY/RCPT.
   - Prohibido expandir URLs acortadas mediante navegadores interactivos.
   - Prohibido realizar microtransacciones de prueba en cadenas blockchain.
5. **Confidencialidad Local y Datos Sensibles**:
   - Prohibido versionar en git nombres reales de clientes o entidades bajo investigación en scripts de exportación.
   - Prohibido sincronizar volcados de informes o memorias del caso en directorios compartidos o almacenamientos en la nube sin cifrado.
6. **Cumplimiento Legal Estricto**:
   - Conforme a la **Ley 5/2014 de Seguridad Privada** (España), la investigación privada exige legitimación de interés y prohíbe expresamente investigar la vida íntima de las personas.
   - Conforme al **RGPD**, rige el principio de minimización de datos personales: solo se recopila y procesa lo estrictamente indispensable para responder a la pregunta de inteligencia legítima.

---

## 9. Metodología de Dorking en Dos Modos

### Modo 1: Manual Guiado (Predeterminado)
- Ejecutado en el navegador del analista dentro de un perfil limpio, aislado, sin extensiones y sin sesiones iniciadas.
- Conexión obligatoria a través de VPN o proxy de salida no atribuible.
- El analista introduce el dork, revisa **exclusivamente los títulos, URLs visibles y snippets de texto** devueltos por el motor.
- **NUNCA pulsar en enlaces de la infraestructura investigada.** Si un resultado parece crítico, copiar la URL y consultar su versión archivada en la Wayback Machine o similar.

### Modo 2: API Opcional (Automatizado)
- Consultas mediante APIs de búsqueda independientes (Brave Search API o SerpAPI) con autenticación compartimentada, evitando el renderizado del navegador.

### Plantillas de Dorks por Fase

#### Dorks P4 (Búsqueda General sobre el Dominio)
- Documentos expuestos: `site:{dominio} filetype:pdf OR filetype:docx OR filetype:xlsx OR filetype:csv`
- Rutas de configuración y respaldos: `site:{dominio} inurl:admin OR inurl:login OR inurl:backup OR inurl:config`
- Fugas de correos y menciones: `"@{dominio}" -site:{dominio}`

#### Dorks P5 (Sembrados No-Zoom hacia el Exterior)
- Subdominios internos descubiertos: `"{subdominio_interno}" -site:{dominio}`
- Colecciones de API y tokens: `site:postman.com/workspaces "{nombre_empresa}" OR "{dominio}"`
- Fugas en repositorios de código: `site:github.com OR site:gitlab.com "{dominio}" "password" OR "token" OR "secret"`
- Tableros y documentos compartidos: `site:trello.com OR site:notion.site "{nombre_empresa}"`
- Ecosistema de proveedores: `"{nombre_empresa}" "caso de éxito" OR "case study" OR "proveedor"`
- Litigios y alertas legales: `"{nombre_empresa}" OR "{razon_social}" "demanda" OR "sentencia" OR "sanción" OR "BOE"`

---

## 10. Redacción Estimativa de Inteligencia

Todo hallazgo analítico debe formularse como una **suposición sujeta a evaluación probabilística**, huyendo de afirmaciones categóricas basadas en datos parciales.

### Plantilla Obligatoria de Suposición (H-n)
> **H-{n}:** Es **{Nivel de Probabilidad ICD 203}** que **{enunciado analítico preciso}**.  
> **Base Evidencial:** {Dato contrastado} — *Fuente:* {Fuente primaria}, *Fecha:* {Fecha observación}, *Hash:* {sha256} — *Fiabilidad de Fuente:* **{A-F}** / *Credibilidad del Dato:* **{1-6}** — *Clúster de Independencia:* {ID Clúster}.  
> **Nivel de Confianza Analítica:** **{Alta / Moderada / Baja}** porque {justificación de la solidez y consistencia de las fuentes}.  
> **Supuestos Subyacentes:** {Factores asumidos que, de variar, alteran la estimación}.  
> **Hipótesis Alternativas Evaluadas:** {Explicación de al menos dos interpretaciones rivales}.  
> **Indicadores de Engaño o Manipulación:** {Evaluación MOM/POP/MOSES/EVE}.  
> **Evidencia que la Refutaría:** {Condición fáctica observable que obligaría a descartar esta hipótesis}.

### Escala de Probabilidad Estimativa (ICD 203)
En las conclusiones se emplea exclusivamente la escala estandarizada de inteligencia ICD 203:
- **Casi seguro (almost certain):** 95-99 %
- **Muy probable (very likely):** 80-95 %
- **Probable (likely):** 55-80 %
- **Probabilidad aproximadamente igual (roughly even chance):** 45-55 %
- **Improbable (unlikely):** 20-45 %
- **Muy improbable (very unlikely):** 05-20 %
- **Casi ninguna posibilidad (almost no chance):** 01-05 %

*(Regla de estilo: La probabilidad estimativa del hecho y la confianza analítica en el juicio deben expresarse en frases gramaticales separadas).*

### Sistema de Evaluación de Fuentes (Admiralty / NATO, AJP-2.1, verificado solo en fuente secundaria)
- **Fiabilidad de la Fuente (A-F):**
  - **A:** Totalmente fiable
  - **B:** Fiable en general
  - **C:** Bastante fiable
  - **D:** No fiable habitualmente
  - **E:** Infiable
  - **F:** Fiabilidad no determinable
- **Credibilidad de la Información (1-6):**
  - **1:** Confirmada por otras fuentes independientes
  - **2:** Probablemente cierta
  - **3:** Posiblemente cierta
  - **4:** Dudosa
  - **5:** Improbable
  - **6:** Credibilidad no determinable

### Filtro de Desinformación y Reputación (MOM / POP / MOSES / EVE)
Antes de incorporar una crítica, reseña negativa o testimonio de terceros sobre el objetivo:
- **MOM:** Motive, Opportunity, Means
- **POP:** Past Opposition Practices
- **MOSES:** Manipulability of Sources
- **EVE:** Evaluation of Evidence
*(Heuer y Pherson; texto literal [NV]).*

### Propiedades Recomendadas para Entidades y Aristas en Maltego MCP
Al vincular nodos mediante `osint_upsert_entity` u `osint_link_entities`, se recomienda incorporar en las propiedades:
`source_reliability` (A-F), `info_credibility` (1-6), `estimative_probability` (escala ICD 203), `analytic_confidence` (Alta/Moderada/Baja), `independence_cluster`, `source_family`, `collection_mode=passive`.

---

## 11. Métricas "No Zoom" y Lista de Comprobación Final

### Métricas de Calidad de la Investigación
- **Número de Familias Independientes:** Mínimo 4 familias cubiertas (ej. Registros Mercantiles, Logs CT, RDAP, Repositorios de Código).
- **Índice de Concentración Evidencial:** Ninguna familia individual de fuentes debe aportar más del 50 % de las entidades del caso.
- **Cobertura de Hipótesis Rival:** 100 % de los juicios clave deben incluir una hipótesis alternativa y su refutación.
- **Ratio de Lectura Lateral:** 100 % de las fuentes no oficiales deben haber sido evaluadas externamente.

### Lista de Comprobación Final del Caso (Antes de Exportar)
1. ¿Se garantizó el Perímetro Intocable en todas las fases sin generar tráfico hacia los activos del objetivo?
2. ¿Se abstuvo el analista de ejecutar `osint_investigate`, transforms DNS en vivo, `OnionPassivePivot` o VirusTotal?
3. ¿Se verificó que los subdominios descubiertos no fueron resueltos activamente para comprobar su estado?
4. ¿Los documentos descargados proceden exclusivamente de réplicas de archivos históricos y se analizaron offline?
5. ¿Se mantuvo la sesión cerrada en todas las consultas a redes y plataformas profesionales (`owner_telemetry`)?
6. ¿Las afirmaciones analíticas están redactadas bajo la plantilla H-n con probabilidades ICD 203 y evaluación Admiralty?
7. ¿Se eliminó cualquier mención de datos reservados del cliente en los artefactos del caso?

---

## 12. Elementos Pendientes de Verificación Técnica [NV]

Los siguientes aspectos se mantienen bajo estado [NV] hasta su comprobación experimental en código:
- [NV] Bandas numéricas PHIA (Professional Head of Intelligence Assessment) frente a ICD 203.
- [NV] Texto literal de las preguntas y formulación de MOM/POP/MOSES/EVE en Richards Heuer y Randolph Pherson.
- [NV] Cita literal de Richards Heuer sobre "satisficing" y concepto WYSIATI ("what you see is all there is", Kahneman) en el contexto de fuentes pasivas.
- [NV] Registro de eventos e IP en logs de enumeración de usuarios de Microsoft 365 (`GetCredentialType`, autologon).
- [NV] Override de configuración y persistencia de anonimato en LinkedIn Sales Navigator bajo dos ajustes simultáneos.
- [NV] Si la vista previa web anónima de canales de Telegram (`t.me/s/<canal>`) incrementa o no el contador de visualizaciones visible para administradores.
- [NV] Registro y exposición de IP individual en el panel analítico de enlaces Bitly corporativos.
- [NV] Registro de visitas o telemetría atribuible en estadísticas de perfiles y presentaciones en Dribbble, SlideShare y Speaker Deck.
- [NV] Avisos o eventos push en WhatsApp y Telegram al añadir un número a la agenda telefónica local.
- [NV] Confirmación de ausencia total de resolución DNS activa en el motor backend de DNSDumpster.
- [NV] Validación de APIs de Brave Search y SerpAPI como alternativas programáticas para dorking pasivo sin renderizado de navegador.
- [NV] Validación de los endpoints históricos de Mnemonic pDNS y Robtex pDNS antes de su incorporación al catálogo de transforms.
