# Product

<!-- impeccable:product-schema 1 -->

> Estado: redactado a partir del repositorio (README, AGENTS.md, docs/USO.md y el propio panel). Los apartados
> marcados como «inferido» no han sido confirmados por el propietario del producto.

## Platform

web

## Users

Analistas OSINT y de ciberinteligencia que investigan desde su propio equipo, normalmente una sola persona por
instalación. Trabajan sesiones largas sobre un caso concreto, alternan entre el agente de IA que ejecuta los
transforms y el panel web donde revisan el grafo, y necesitan saber en todo momento por dónde sale su tráfico.
(Inferido: perfil y situación de uso.)

## Product Purpose

Servidor MCP que permite a cualquier agente de IA delegar flujos de Maltego: ejecutar transforms y Machines,
mantener un grafo de investigación persistente con memoria de cada paso y procedencia explicable, recomendar el
siguiente pivote y sincronizarse con Maltego Desktop mediante archivos `.mtgx`.

El panel web (`maltegoctl dashboard`) es la consola de control local de ese servidor: estado del egreso, casos,
grafo, reconocimiento pasivo por fases, perfilado, claves de proveedores, feeds CTI, ledger AML y bóveda de cuentas.

## Positioning

Funciona en local y sin licencias comerciales de Maltego. Cada entidad del grafo conserva su procedencia y cada
transform queda registrado como paso del caso, de modo que una investigación se puede auditar y reproducir.

## Operating Context

- Uso local en `127.0.0.1`, con autenticación propia del panel y CSP estricta (`script-src 'self'`).
- Todo el egreso sale por el anillo Mullvad obligatorio; si la atestación falla, el servidor no envía consultas.
  El panel debe mostrar ese estado antes que cualquier otra cosa.
- Los datos OSINT recuperados son contenido no confiable: se muestran como dato, neutralizados, nunca como
  instrucciones ni como enlaces activos.
- Los casos, claves y registros viven fuera del repositorio, en `~/.maltego-mcp`.

## Capabilities and Constraints

- Frontend sin compilación: `index.html`, `dashboard.css`, `dashboard.js`, `egress-ring.js` y un Web Worker.
- Ningún manejador ni script en línea; las acciones se declaran con `data-on-*` o clases `action-*` y se ejecutan por
  delegación con lista cerrada.
- Sin recursos remotos: ni fuentes, ni imágenes, ni CDN.
- 20 tools MCP como máximo, con esquemas planos compatibles con todos los modelos.
- Terminología propia que el panel debe respetar: caso, proyecto activo, entidad, arista, transform, Machine,
  perímetro intocable, semilla, anillo de egreso.

## Brand Commitments

- Nombre: MCP Maltego. Interfaz en español.
- Informes periciales sin emojis (lo comprueban los tests).

## Evidence on Hand

- Capturas del panel sobre una instancia vacía. No hay casos de demostración versionables: los datos reales de
  investigación nunca entran en el repositorio.
- No hay testimonios, clientes ni métricas de uso; no deben inventarse.

## Product Principles

1. El estado del egreso manda: si no está confirmado, se ve antes que nada y nada lo tapa.
2. Procedencia siempre visible: cada dato dice de dónde viene y con qué certeza.
3. Densidad útil: un analista lee mucho en poco espacio, pero ningún texto baja de un tamaño legible.
4. Lo destructivo exige confirmación explícita y nunca se dispara con un solo clic.
5. Nada sale del equipo sin que el analista lo haya decidido.

## Accessibility & Inclusion

Objetivo WCAG 2.2 AA en contraste y foco visible. El panel se usa con teclado en sesiones largas; se respeta
`prefers-reduced-motion`. (Inferido: no hay un estándar fijado por el propietario.)
