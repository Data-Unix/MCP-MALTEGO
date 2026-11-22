# Matriz de cobertura frente a la especificación funcional

Leyenda de verificación: **T** = tests automáticos · **V** = probado en vivo contra el servicio real ·
**S** = probado con respuestas simuladas del formato real · **M** = pendiente de validar en Maltego Desktop real.

Las 20 tools agrupan todas las funciones (el límite de 20 mantiene la compatibilidad con Gemini y el contexto de
los modelos; las variantes van en un parámetro `action`).

## 1. Gestión de grafos y persistencia `.mtgx`
| Requisito | Implementación | Verificación |
|---|---|---|
| Crear / consultar / borrar grafos | Casos: `osint_manage_case` (create/merge/delete), `osint_list_cases`, `osint_get_case_summary` | T |
| Renombrar / grafo activo | No hay grafo activo implícito: todas las tools reciben `case_id` explícito (evita errores entre agentes concurrentes). Renombrar = `merge` a un caso nuevo + `delete` | T |
| Contenedor `.mtgx` (ZIP + `Graphs/Graph1.graphml`) | `maltego/mtgx.py` (escritura/lectura) | T, M |
| Límites y validación | Lectura segura: 20 MB ZIP, 50 MB GraphML, 2.000 ficheros internos, 20.000 entidades, 50.000 enlaces, XML con defusedxml; `maltegoctl inspect`. *Los límites "8 MiB / 1.024 / 10.000" de la especificación son de lidless-labs/maltego-mcp, no de Maltego.* | T |
| Fusión de investigaciones | `osint_import_graph` fusiona un `.mtgx` en un caso; `osint_manage_case action=merge` fusiona casos | T |
| Coordenadas para Maltego | `mtg:EntityRenderer/Position` en cada nodo | T, M |

## 2. Ontología de entidades
| Requisito | Implementación | Verificación |
|---|---|---|
| Tipos estándar (infraestructura, identidad, organización, artefactos, cripto/AML, social, HUMINT) | 41 tipos con categoría y propiedad principal (`domain/entity_types.py`) | T |
| Ontología exacta de tu Maltego | `maltegoctl import-entities config.mtz` lee `Entities/*.entity` | T, M |
| Entidades genéricas con prefijo (`[T1566]`, `[TheHive]`) | `maltego.Phrase` documentado en la tool y usado por los transforms (`[CVE]`, `[Breach]`, `[TXT]`) | T |
| Mapeo de propiedades (`fqdn`, `ipv4-address`, `url`/`short-title`...) | Propiedad principal por tipo + propiedad visible para URL/Document | T, M |
| CRUD de nodos, enlaces y perfilado pericial | `osint_upsert_entity`, `osint_manage_entity` (update/delete, notas, confianza=peso, `profile` con 21 tipologías periciales, `generate_persona`), `osint_link_entities` (link/unlink/analyze/correlate) | T |

## 3. Transforms, proveedores y servidores
| Requisito | Implementación | Verificación |
|---|---|---|
| Inventario filtrable | `osint_list_transforms` (tipo, categoría, modo de pasividad, disponibilidad) | T |
| Transforms sin API key | 51 integrados (63 en total): DNS sobre HTTPS (A, AAAA, MX, NS, TXT, CNAME, PTR), Anubis-DB, HackerTarget, RDAP de dominio e IP (con respaldo ARIN), BOE/BORME, GLEIF LEI, crt.sh, CertSpotter, CTOrgToCertificates, urlscan.io, Wayback Machine CDX y extracción de snapshots, Arquivo.pt, Common Crawl CDX, Shodan InternetDB, CISA KEV, URLhaus, ASN y prefijos BGP (Team Cymru, RIPEstat, IPToPassiveContext), Gravatar, GitHub (perfil, commits y fugas de dominio), Keybase, Hudson Rock, BreachSemanticPivot, pulsos OTX para hashes, DeepDarkCTI y pivote `.onion`, Mempool.space Bitcoin UTXO, clustering CIOH, sanciones OFAC SDN, touchpoints VASP, perfiles por alias y análisis local | T, V |
| Proveedores con API key (12 transforms que se activan solos) | VirusTotal (4, solo GET), Shodan (2), SecurityTrails, Censys, Hunter.io, HIBP, GreyNoise, Tatum | T, S |
| Servidores TRX / iTDS / TDS y plugins `@custom_transform` | Catálogo TOML + protocolo XML de Maltego (compatible con maltego-trx) + plugins Python en `~/.maltego-mcp/plugins/` | T |
| Estado de credenciales y servidores | `osint_list_transforms` muestra proveedores configurados y, con `check_servers=true`, la conexión de cada servidor | T |

Nota: los TDS no publican su lista de transforms por API; por eso se declaran en el catálogo (otras implementaciones
de la comunidad inventan rutas `/transforms` que no existen o simulan los resultados).

## 4. Machines
| Requisito | Implementación | Verificación |
|---|---|---|
| Secuencias con profundidad y rondas | `osint_run_machine` (`max_rounds`, presupuestos por paso y total, concurrencia anti-ráfaga `CHAIN_CONCURRENCY = 3`) | T, V |
| 16 Machines predefinidas (11 Activas+Pasivas y 5 Pasivas estrictas) | `DomainRecon`, `InfrastructureRecon`, `EmailRecon`, `CompanyFootprint`, `PersonalFootprint`, `PersonaFootprint`, `URLRecon`, `ThreatSweep`, `ASNToNetblocks`, `DarkWebFootprint`, `CryptoFlowRecon`, `PassiveDomainRecon`, `PassiveInfrastructureRecon`, `PassiveEmailRecon`, `PassiveURLRecon`, `PassiveCompanyFootprint`; las propias van en `[[machines]]` del catálogo | T, V |

## 5. Layout y aceleración nativa
| Requisito | Implementación | Verificación |
|---|---|---|
| Jerárquico, radial, por fuerzas | `compute_layout` (BFS por niveles, anillos alrededor del pivote, Fruchterman-Reingold determinista) con aceleración opcional en Rust (`maltego_core_rs`) y paridad exacta bit a bit con el fallback Python | T |
| Coordenadas guardadas en el `.mtgx` | `osint_export_case format=mtgx layout=...` | T, M |

## 6. Copiloto, Reconocimiento P0–P9 (ACH / ICD 203), Perfilado Pericial y Memoria
| Requisito | Implementación | Verificación |
|---|---|---|
| Punto de entrada único (objetivos y peticiones en texto claro o vagas) | `osint_investigate` (extrae semilla de lenguaje natural, detecta tipo, crea caso, ejecuta Machine y pivotes activos/pasivos no intrusivos, puntúa, autocompleta expediente P0–P9 y perfiles de 21 tipologías, auto-exporta `report_html` + `.mcpcase` y devuelve el Informe Pericial Ejecutivo Completo) | T, V |
| Sincronización en tiempo real (`stdio` ↔ Web Dashboard SSE) | Bus de eventos `~/.maltego-mcp/events.jsonl` + puntero `active_case` + `/api/events` (SSE) y `/api/events/poll` | T |
| Perfilado Pericial Multidimensional (21 tipologías) y Vigencia Objetiva (§4.4) | `profiling.py` (`osint_manage_entity action=profile`) + cálculo automático de `OBSERVADO_RECIENTE`, `HISTORICO` y `MENCIONADO_SIN_FECHA` | T |
| Expediente de Reconocimiento P0–P9 y Síntesis Estimativa ACH / ICD 203 | `sync_case_recon_from_graph` en `service.py` + secciones `§03B` y `§03C` en `report.py` | T |
| Memoria procedimental (motivo, acción, resultado, duración, error) | Cada ejecución queda registrada como paso (`StepRecord`); parámetro `reason` | T |
| Memoria dentro del `.mtgx` y paquete forense `.mcpcase` | `maltego_mcp/investigation.json` en `.mtgx`; contenedor `.mcpcase` con sellado de integridad criptográfica SHA-256 (`osint_export_case format=mcpcase`) | T, M |
| Procedencia y explicación | `osint_get_entity`: descubierta por, transforms ejecutados y pendientes, puntuación desglosada | T |
| Línea de tiempo | `osint_get_timeline` (`steps` y `subject`) | T |
| Siguiente mejor acción | `osint_suggest_next_steps` (determinista y explicada) | T |
| Puntuaciones (confianza, fiabilidad de fuente, enlaces, novedad, prioridad) | `analysis.py`; `osint_search_entities sort=priority` | T |
| Aprendizaje por resultados | Rendimiento histórico por transform a partir de la memoria; ajusta las recomendaciones | T |

## 7. Interoperabilidad y Seguridad de Egreso
| Requisito | Implementación | Verificación |
|---|---|---|
| CSV en ida y vuelta | `osint_export_case csv` / `osint_import_graph` (con confianza) | T |
| JSON / GraphML / `.mcpcase` | `osint_export_case` (`json`, `graphml`, `mcpcase`) | T |
| Informes Periciales Markdown / HTML | `report_md`, `report_html` (HTML autocontenido sin emojis, con IOCs neutralizados, CSP estricta sin scripts, `§01`–`§07` + `§03B` + `§03C`) | T, V |
| Eventos en tiempo real | Sondeo incremental `osint_get_timeline since_seq` y streaming SSE `/api/events` desde `events.jsonl` | T |
| Guardián de egreso, PEP 578, Anillo Mullvad y autenticación PBKDF2 | `egress.py`, `mullvad.py` (atestación doble por `socks5h://10.64.0.1:1080`) y `auth.py` (PBKDF2-HMAC-SHA256 con 600.000 iteraciones + CSRF) | T |
| Composición con otros MCP (MISP, ATT&CK, TheHive...) | El agente vuelca sus resultados con `osint_upsert_entity` (`source=<mcp>`, Phrase con prefijo) | T |

## 8. CLI
| Requisito | Implementación | Verificación |
|---|---|---|
| Inspección de `.mtgx` y consultas sin GUI | `maltegoctl inspect / lookup / transforms / import-entities / export / mtz` | T, V |

## Pendiente
- **M**: abrir `.mtgx`, importar el `.mtz` del puente y la ontología en tu Maltego Desktop.
- **S**: los proveedores con API key se han probado con respuestas simuladas; valídalos con tus claves.
- Backend Cosmos DB (Gremlin) sin validar contra una cuenta real.
- Autenticación (Entra ID) del modo HTTP remoto.
