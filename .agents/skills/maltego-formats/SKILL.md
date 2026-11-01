---
name: maltego-formats
description: Referencia de los formatos de Maltego que usa maltego-mcp (protocolo XML de transforms TRX/iTDS, grafos .mtgx, configuraciones .mtz, transforms locales y ontología .entity). Úsala al leer, generar o depurar cualquiera de estos ficheros o el puente con Maltego Desktop.
license: MIT
---
# Formatos de Maltego

**Transforms TRX/iTDS** (`transforms/protocol.py`): POST de XML a `/run/<nombre>/`, donde el nombre es el de la
clase en minúsculas con `_` → `-` (convención de maltego-trx). Petición `MaltegoMessage/MaltegoTransformRequestMessage`
(una entidad con `Value`, `AdditionalFields`, `Limits SoftLimit`, `TransformFields`). Respuesta
`MaltegoTransformResponseMessage` (entidades + `UIMessages`) o `MaltegoTransformExceptionMessage`. Propiedades de
enlace con prefijo `link#` (`maltego.link.label`, `maltego.link.direction=output-to-input`).

**.mtgx** (`maltego/mtgx.py`): ZIP con `Graphs/Graph1.graphml`. Nodos con `mtg:MaltegoEntity type=...` y
`mtg:Properties/mtg:Property name/displayName/type + mtg:Value`; posición en `mtg:EntityRenderer/mtg:Position`;
aristas con `mtg:MaltegoLink type="maltego.link.manual-link"` y la etiqueta en `maltego.link.manual.type`.
maltego-mcp añade `maltego_mcp/investigation.json` (memoria), que Maltego ignora. URL y Document muestran
`short-title`/`title`, pero el valor real está en `url`.

**.mtz** (`maltego/bridge.py`, `cli.py`): ZIP de configuración. Transforms locales generados con
`maltego_trx.decorator_registry.TransformRegistry.write_local_mtz` (`Servers/Local.tas`,
`TransformRepositories/Local/*.transform|.transformsettings`, `TransformSets/*.set`). Entidades en
`Entities/*.entity` (`<MaltegoEntity id=...><Properties value="propiedad principal">`).

**Transforms locales**: Maltego ejecuta `comando parámetros valor "k=v#k2=v2"`; solo reciben valor y propiedades
(no el tipo), por eso hay un transform puente por tipo. La salida XML va por stdout en UTF-8.

Lecturas siempre acotadas y con defusedxml (ver `read_mtgx`, `inspect_mtgx`).
