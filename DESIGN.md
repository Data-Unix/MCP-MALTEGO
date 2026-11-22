---
name: MCP Maltego · Panel
description: Consola de control local para investigación OSINT, densa, oscura y sin recursos remotos.
colors:
  bg-base: "#080a11"
  bg-surface: "#0f1322"
  bg-surface-raised: "#151a2e"
  bg-surface-active: "#1b223b"
  border-subtle: "#1e263d"
  border-strong: "#2d3858"
  text-primary: "#f1f5f9"
  text-secondary: "#94a3b8"
  text-muted: "#8593a8"
  accent-cyan: "#06b6d4"
  accent-emerald: "#10b981"
  accent-amber: "#f59e0b"
  accent-crimson: "#ef4444"
  accent-rose: "#f43f5e"
  accent-indigo: "#6366f1"
  accent-purple: "#a855f7"
  action-primary: "#0369a1"
  action-primary-hover: "#075985"
  accent-cyan-light: "#67e8f9"
  accent-emerald-light: "#34d399"
  accent-amber-light: "#fbbf24"
  accent-crimson-light: "#f87171"
  accent-rose-light: "#fda4af"
  accent-indigo-light: "#a5b4fc"
  accent-purple-light: "#c084fc"
  accent-sky: "#38bdf8"
  bg-deep: "#0b0f19"
  text-main: "#e2e8f0"
  text-inverse: "#ffffff"
  overlay-black: "#000000"
typography:
  display:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "26px"
    fontWeight: 700
  headline:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "20px"
    fontWeight: 600
  headline-small:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "18px"
    fontWeight: 600
  title-large:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "16px"
    fontWeight: 600
  title:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "15px"
    fontWeight: 600
  control:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "13px"
    fontWeight: 500
  body:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "14px"
    lineHeight: 1.5
  body-small:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "12px"
  label:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "12px"
    fontWeight: 500
  data:
    fontFamily: "ui-monospace, 'SF Mono', Menlo, Monaco, Consolas, 'Liberation Mono', monospace"
    fontSize: "12px"
rounded:
  xs: "2px"
  sm: "4px"
  md: "6px"
  lg: "8px"
  pill: "999px"
components:
  button-primary:
    backgroundColor: "{colors.action-primary}"
    textColor: "#ffffff"
    rounded: "{rounded.md}"
    padding: "0.45rem 0.85rem"
  button-primary-hover:
    backgroundColor: "{colors.action-primary-hover}"
  button-secondary:
    backgroundColor: "{colors.bg-surface-raised}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.md}"
    padding: "0.45rem 0.85rem"
  hud-pill:
    backgroundColor: "{colors.bg-surface-raised}"
    textColor: "{colors.text-secondary}"
    rounded: "{rounded.sm}"
    padding: "0.2rem 0.55rem"
---

## Overview

Panel de trabajo en modo operación: el analista viene a hacer una tarea, así que mandan la legibilidad, la
consistencia y los controles estándar. La identidad vive en la paleta oscura azulada, el cian como color de foco y
selección, y la tipografía monoespaciada reservada a datos. Documento extraído del código (`dashboard.css`); describe
lo que hay, no una aspiración.

## Colors

- **Fondos por capas tonales:** `bg-base` → `bg-surface` → `bg-surface-raised` → `bg-surface-active`. La jerarquía se
  consigue subiendo de capa, no con sombras.
- **Cian** (`accent-cyan`): foco, selección, elemento activo y enlaces. No se usa como decoración.
- **Colores de estado**, solo donde significan algo: esmeralda (correcto, protegido), ámbar (aviso), carmesí y rosa
  (error, acción destructiva), índigo y morado (categorías secundarias).
- **Acción primaria:** `action-primary` con texto blanco (5,9:1). El azul más claro `#0284c7` no se usa con texto
  blanco porque se queda en 4,1:1.
- Texto sobre fondo: `text-muted` es el mínimo admisible sobre `bg-surface` (5,9:1).
- **Variantes claras** (`accent-*-light`, `accent-sky`): texto de estado sobre fondos tintados y estados hover,
  donde el color base no llega a 4,5:1.
- **Translúcidos:** tintes y velos se escriben como `rgba()` de un color de la paleta (cian, esmeralda, ámbar,
  carmesí, cielo, `bg-deep`, negro o blanco). No se introducen matices nuevos por esa vía.
- En la hoja de estilos y en los atributos `style` los colores van como `var(--token)`. Los literales solo quedan
  en el dibujo del grafo sobre `canvas`, que no puede leer variables CSS directamente.

## Typography

- Fuente de sistema para la interfaz; monoespaciada solo para identificadores, cifras, hashes, IP y estado técnico.
- Escala cerrada: 26, 20, 18 y 16 px para cifras y encabezados; 15 px títulos de vista; 14 px cuerpo; 13 px
  botones y controles; 12 px texto secundario, etiquetas, píldoras, cabeceras de tabla y datos.
- **Suelo:** ningún texto por debajo de 12 px. No se usan tamaños fuera de la escala ni unidades `rem` sueltas.
- Cifras tabulares en tablas, píldoras y contadores.

## Layout

- Estructura fija: barra lateral redimensionable (250 px por defecto), barra de estado superior de 56 px, cabecera
  de vista de 56 px y zona de contenido con desplazamiento propio.
- Las dos barras superiores van siempre en una fila. Se adaptan al ancho de la propia barra (consultas de
  contenedor), no al de la ventana, porque la lateral cambia de tamaño: primero los comandos pasan a solo icono,
  después se ocultan las píldoras secundarias y la etiqueta del selector de proyecto.
- Ningún bloque provoca desplazamiento horizontal de la página; las tablas anchas se desplazan dentro de su
  contenedor.
- Los modales caben en la ventana y desplazan su contenido internamente.

## Elevation & Depth

Plano por capas tonales y bordes de 1 px. Las sombras se reservan para lo que flota de verdad (menús, toasts,
modales) y llevan desplazamiento y desenfoque. No hay halos de color sin desplazamiento ni brillos decorativos.

## Shapes

Radios: 2 px en barras y marcas finas, 4 px en píldoras y controles compactos, 6 px en botones y campos, 8 px en
tarjetas y paneles, 999 px en insignias. No hay radios de 3 ni de 5 px.
Bordes de 1 px. El estado de una tarjeta o aviso se marca con un borde completo tintado, nunca con una franja
lateral de color.

## Components

- **Botones:** primario (uno por vista como mucho), secundario y peligro. Los que quedan en solo icono llevan
  `aria-label`.
- **Píldoras de estado:** punto de color más texto. El punto es estático; no pulsa ni brilla.
- **Tablas:** barra de herramientas con densidad (compacta, normal, ampliada), límite de filas y expandir/contraer.
- **Toasts:** borde completo tintado según el tipo, icono del mismo color.
- **Modales:** cabecera con título y botón de cierre, cuerpo con desplazamiento, acciones al pie.
- **Acciones:** se declaran con `data-on-*` o clases `action-*`; nunca con manejadores en línea (los bloquea la CSP).

## Do's and Don'ts

- Sí: usar los tokens existentes; subir de capa tonal para dar jerarquía; comprobar el contraste de cualquier
  combinación nueva.
- Sí: probar cada cambio a 1440, 1280, 1100 y 1000 px de ancho.
- No: texto por debajo de 12 px ni tamaños fuera de la escala.
- No: franjas laterales de color, halos, pulsos decorativos, texto en degradado.
- No: recursos remotos (fuentes, imágenes, scripts) ni estilos que dependan de ellos.
- No: emojis como iconos en controles nuevos.
