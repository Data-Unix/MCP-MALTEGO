/**
 * Web Worker para renderizado de fondo en OffscreenCanvas.
 * - Corre en un hilo de procesamiento aislado (0% CPU en hilo principal).
 * - Renderiza una rejilla de perspectiva matemática con pulso reactivo al tráfico del MCP.
 * - Respeta prefers-reduced-motion (modo estático si está activado).
 */

let canvas = null;
let ctx = null;
let width = 0;
let height = 0;
let dpr = 1;
let animId = null;
let pulseIntensity = 0.0;
let reducedMotion = false;
let time = 0;

self.onmessage = function (e) {
  const data = e.data || {};
  switch (data.type) {
    case "init":
      canvas = data.canvas;
      width = data.width || 800;
      height = data.height || 600;
      dpr = data.dpr || 1;
      reducedMotion = Boolean(data.reducedMotion);
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      ctx = canvas.getContext("2d");
      if (ctx) {
        ctx.scale(dpr, dpr);
      }
      if (!animId) {
        render();
      }
      break;

    case "resize":
      width = data.width || width;
      height = data.height || height;
      dpr = data.dpr || dpr;
      if (canvas && ctx) {
        canvas.width = width * dpr;
        canvas.height = height * dpr;
        ctx.scale(dpr, dpr);
      }
      break;

    case "pulse":
      pulseIntensity = Math.min(1.0, pulseIntensity + (data.intensity || 0.6));
      break;

    case "reducedMotion":
      reducedMotion = Boolean(data.reducedMotion);
      break;
  }
};

function render() {
  if (!ctx || !canvas) {
    animId = requestAnimationFrame(render);
    return;
  }

  // Si el usuario prefiere movimiento reducido, dibuja una rejilla estática sobria
  if (reducedMotion) {
    drawStaticGrid();
    animId = requestAnimationFrame(render);
    return;
  }

  time += 0.015;
  pulseIntensity *= 0.96; // decaimiento suave del pulso

  // Limpiar lienzo con fondo base profundo
  ctx.fillStyle = "#080a11";
  ctx.fillRect(0, 0, width, height);

  const horizon = height * 0.45;
  const cx = width / 2;

  // Gradiente radial sutil en el horizonte que reacciona al pulso MCP
  const gradRadius = Math.max(width, height) * (0.35 + pulseIntensity * 0.15);
  const glow = ctx.createRadialGradient(cx, horizon, 0, cx, horizon, gradRadius);
  const alphaGlow = 0.05 + pulseIntensity * 0.12;
  glow.addColorStop(0, `rgba(6, 182, 212, ${alphaGlow})`); // Cian sobrio
  glow.addColorStop(0.5, `rgba(16, 185, 129, ${alphaGlow * 0.3})`); // Esmeralda sutil
  glow.addColorStop(1, "rgba(8, 10, 17, 0)");
  ctx.fillStyle = glow;
  ctx.fillRect(0, 0, width, height);

  // Líneas de perspectiva (rayos desde el punto de fuga hacia abajo)
  const numRays = 24;
  ctx.lineWidth = 1;
  for (let i = -numRays; i <= numRays; i++) {
    const spread = (i / numRays) * (width * 1.6);
    const xEnd = cx + spread;
    const rayDist = Math.abs(i) / numRays;
    const rayAlpha = Math.max(0.02, (1 - rayDist * 0.8) * (0.09 + pulseIntensity * 0.08));

    ctx.strokeStyle = `rgba(32, 45, 75, ${rayAlpha})`;
    ctx.beginPath();
    ctx.moveTo(cx, horizon);
    ctx.lineTo(xEnd, height);
    ctx.stroke();
  }

  // Líneas horizontales espaciadas exponencialmente (efecto rejilla infinita)
  const numHorizontals = 18;
  const speed = (time * 0.25) % 1;

  for (let j = 0; j < numHorizontals; j++) {
    const progress = (j + speed) / numHorizontals;
    const expY = Math.pow(progress, 2.2);
    const y = horizon + expY * (height - horizon);

    // Atenuación natural hacia el horizonte
    const lineAlpha = Math.min(1, Math.max(0, expY)) * (0.12 + pulseIntensity * 0.15);
    ctx.strokeStyle = `rgba(38, 55, 90, ${lineAlpha})`;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();
  }

  animId = requestAnimationFrame(render);
}

function drawStaticGrid() {
  ctx.fillStyle = "#080a11";
  ctx.fillRect(0, 0, width, height);
  const horizon = height * 0.45;
  const cx = width / 2;

  ctx.lineWidth = 1;
  ctx.strokeStyle = "rgba(32, 45, 75, 0.06)";
  for (let i = -16; i <= 16; i++) {
    const xEnd = cx + (i / 16) * (width * 1.5);
    ctx.beginPath();
    ctx.moveTo(cx, horizon);
    ctx.lineTo(xEnd, height);
    ctx.stroke();
  }
  for (let j = 0; j < 14; j++) {
    const expY = Math.pow(j / 14, 2.2);
    const y = horizon + expY * (height - horizon);
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();
  }
}
