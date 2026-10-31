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
| Tipos estándar (infraestructura, identidad, organización, artefactos, cripto, social) | 34 tipos con categoría y propiedad principal (`domain/entity_types.py`) | T |
| Ontología exacta de tu Maltego | `maltegoctl import-entities config.mtz` lee `Entities/*.entity` | T, M |
| Entidades genéricas con prefijo (`[T1566]`, `[TheHive]`) | `maltego.Phrase` documentado en la tool y usado por los transforms (`[CVE]`, `[Breach]`, `[TXT]`) | T |
| Mapeo de propiedades (`fqdn`, `ipv4-address`, `url`/`short-title`...) | Propiedad principal por tipo + propiedad visible para URL/Document | T, M |
| CRUD de nodos y enlaces | `osint_upsert_entity`, `osint_manage_entity` (update/delete, notas, confianza=peso), `osint_link_entities` (link/unlink) | T |

## 3. Transforms, proveedores y servidores
| Requisito | Implementación | Verificación |
|---|---|---|
| Inventario filtrable | `osint_list_transforms` (tipo, categoría, disponibilidad) | T |
| Transforms sin API key | 18 integrados: DNS sobre HTTPS (A, AAAA, MX, NS, TXT, CNAME, PTR), RDAP de dominio e IP, crt.sh, ASN y prefijo (Team Cymru), perfiles por alias, análisis de correo/URL/web | T, V |
| Proveedores con API key (se activan solos) | VirusTotal (4), Shodan (2), SecurityTrails, Censys, Hunter.io, HIBP, GreyNoise, Tatum | T, S |
| Servidores TRX / iTDS / TDS | Catálogo TOML + protocolo XML de Maltego (compatible con maltego-trx) | T |
| Estado de credenciales y servidores | `osint_list_transforms` muestra proveedores configurados y, con `check_servers=true`, la conexión de cada servidor | T |

Nota: los TDS no publican su lista de transforms por API; por eso se declaran en el catálogo (otras implementaciones
de la comunidad inventan rutas `/transforms` que no existen o simulan los resultados).

## 4. Machines
| Requisito | Implementación | Verificación |
|---|---|---|
| Secuencias con profundidad y rondas | `osint_run_machine` (`max_rounds`, presupuestos por paso y total) | T, V |
| CompanyFootprint, PersonalFootprint, DomainRecon, InfrastructureRecon, EmailRecon | Predefinidas, más URLRecon; las propias van en `[[machines]]` del catálogo | T, V |

## 5. Layout
| Requisito | Implementación | Verificación |
|---|---|---|
| Jerárquico, radial, por fuerzas | `compute_layout` (BFS por niveles, anillos alrededor del pivote, Fruchterman-Reingold determinista) | T |
| Coordenadas guardadas en el `.mtgx` | `osint_export_case format=mtgx layout=...` | T, M |

## 6. Copiloto y memoria
| Requisito | Implementación | Verificación |
|---|---|---|
| Punto de entrada único | `osint_investigate` (detecta tipo, crea caso, Machine, puntúa, recomienda, informe) | T, V |
| Memoria procedimental (motivo, acción, resultado, duración, error) | Cada ejecución queda registrada como paso; parámetro `reason` | T |
| Memoria dentro del `.mtgx` | `maltego_mcp/investigation.json` (Maltego lo ignora); se recupera al importar | T, M |
| Procedencia y explicación | `osint_get_entity`: descubierta por, transforms ejecutados y pendientes, puntuación desglosada | T |
| Línea de tiempo | `osint_get_timeline` | T |
| Siguiente mejor acción | `osint_suggest_next_steps` (determinista y explicada) | T |
| Puntuaciones (confianza, fiabilidad de fuente, enlaces, novedad, prioridad) | `analysis.py`; `osint_search_entities sort=priority` | T |
| Aprendizaje por resultados | Rendimiento histórico por transform a partir de la memoria; ajusta las recomendaciones | T |

## 7. Interoperabilidad
| Requisito | Implementación | Verificación |
|---|---|---|
| CSV en ida y vuelta | `osint_export_case csv` / `osint_import_graph` (con confianza) | T |
| JSON / GraphML | `osint_export_case` | T |
| Informes Markdown / HTML | `report_md`, `report_html` (HTML autocontenido con CSP, sin scripts) | T, V |
| Eventos en tiempo real | Sondeo incremental: `osint_get_timeline since_seq` | T |
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
