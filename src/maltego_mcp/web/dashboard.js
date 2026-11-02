/**
 * MCP Maltego Web Dashboard - Cliente Operativo
 */

let bgWorker = null;
let currentTab = "overview";
let currentPersona = null;
let totpTimer = null;

document.addEventListener("DOMContentLoaded", () => {
  initBackgroundCanvas();
  initNavigation();
  initSSE();
  loadStatus();
  loadAccounts();
  loadProviders();
  loadCTIFeeds();
  loadTransforms();
});

// 1. Inicialización del Lienzo en Web Worker (OffscreenCanvas)
function initBackgroundCanvas() {
  const canvas = document.getElementById("bg-canvas");
  if (!canvas) return;

  const width = window.innerWidth;
  const height = window.innerHeight;
  const dpr = Math.min(window.devicePixelRatio || 1, 2);

  if ("transferControlToOffscreen" in canvas) {
    try {
      const offscreen = canvas.transferControlToOffscreen();
      bgWorker = new Worker("/bg-worker.js");
      bgWorker.postMessage(
        {
          type: "init",
          canvas: offscreen,
          width,
          height,
          dpr,
          reducedMotion: window.matchMedia("(prefers-reduced-motion: reduce)").matches,
        },
        [offscreen]
      );

      window.addEventListener("resize", () => {
        if (bgWorker) {
          bgWorker.postMessage({
            type: "resize",
            width: window.innerWidth,
            height: window.innerHeight,
            dpr: Math.min(window.devicePixelRatio || 1, 2),
          });
        }
      });
      return;
    } catch (e) {
      console.warn("Fallo al inicializar Worker OffscreenCanvas, usando fallback estático:", e);
    }
  }

  // Fallback para navegadores antiguos
  canvas.width = width * dpr;
  canvas.height = height * dpr;
  const ctx = canvas.getContext("2d");
  if (ctx) {
    ctx.scale(dpr, dpr);
    ctx.fillStyle = "#080a11";
    ctx.fillRect(0, 0, width, height);
  }
}

function triggerVisualPulse(intensity = 0.6) {
  if (bgWorker) {
    bgWorker.postMessage({ type: "pulse", intensity });
  }
}

// 2. Navegación de vistas
function initNavigation() {
  const links = document.querySelectorAll(".nav-link[data-tab]");
  links.forEach((link) => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const tab = link.getAttribute("data-tab");
      switchTab(tab);
    });
  });
}

function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll(".nav-link").forEach((l) => l.classList.remove("active"));
  const activeLink = document.querySelector(`.nav-link[data-tab="${tab}"]`);
  if (activeLink) activeLink.classList.add("active");

  document.querySelectorAll(".view-section").forEach((sec) => sec.classList.remove("active"));
  const activeSec = document.getElementById(`view-${tab}`);
  if (activeSec) activeSec.classList.add("active");

  const titleEl = document.getElementById("current-view-title");
  if (titleEl && activeLink) {
    titleEl.textContent = activeLink.querySelector(".nav-label")?.textContent || tab;
  }
}

// 3. Conexión en tiempo real (Server-Sent Events)
function initSSE() {
  try {
    const sse = new EventSource("/api/events");
    sse.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleServerEvent(data);
      } catch (err) {
        // Ping o texto plano
      }
    };
    sse.onerror = () => {
      // Reconexión automática nativa del navegador
    };
  } catch (err) {
    console.warn("SSE no disponible en este entorno.");
  }
}

function handleServerEvent(ev) {
  if (ev.type === "pulse" || ev.type === "step") {
    triggerVisualPulse(0.8);
  }
  if (ev.type === "step" || ev.type === "transform") {
    appendLogEntry("MCP", `${ev.transform || "Transform"}: ${ev.target || ""}`);
  }
  if (ev.type === "accounts_updated") {
    loadAccounts();
  }
  if (ev.type === "cti_synced") {
    loadCTIFeeds();
  }
}

function appendLogEntry(source, message) {
  const logBox = document.getElementById("event-log");
  if (!logBox) return;
  const time = new Date().toLocaleTimeString();
  const entry = document.createElement("div");
  entry.className = "log-entry";
  entry.innerHTML = `<span class="log-time">${time}</span><span class="log-source">[${escapeHtml(
    source
  )}]</span><span class="log-msg">${escapeHtml(message)}</span>`;
  logBox.appendChild(entry);
  logBox.scrollTop = logBox.scrollHeight;
}

// 4. Carga de estado general
async function loadStatus() {
  try {
    const res = await fetch("/api/status");
    if (!res.ok) return;
    const data = await res.json();

    document.getElementById("stat-status") &&
      (document.getElementById("stat-status").innerHTML = `<span class="pill pill-ok">Online</span>`);
    document.getElementById("stat-transport") &&
      (document.getElementById("stat-transport").textContent = data.transport || "http");
    document.getElementById("stat-tor") &&
      (document.getElementById("stat-tor").innerHTML = data.tor_active
        ? `<span class="pill pill-ok">Tor Activo</span>`
        : `<span class="pill pill-warn">Tor No Detectado</span>`);
    document.getElementById("stat-accounts-count") &&
      (document.getElementById("stat-accounts-count").textContent = data.accounts_summary?.total ?? 0);
    document.getElementById("stat-cti-count") &&
      (document.getElementById("stat-cti-count").textContent = data.cti_summary?.active_sources ?? 0);
    document.getElementById("stat-transforms-count") &&
      (document.getElementById("stat-transforms-count").textContent = data.transforms_count ?? 0);
  } catch (err) {
    console.error("Error al cargar estado:", err);
  }
}

// 5. Cuentas y Sock Puppets
async function loadAccounts() {
  const tbody = document.getElementById("accounts-tbody");
  if (!tbody) return;

  try {
    const res = await fetch("/api/accounts");
    const data = await res.json();
    const accounts = data.accounts || [];

    const badge = document.getElementById("badge-accounts-count");
    if (badge) badge.textContent = accounts.length;

    if (accounts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 2rem; color: var(--text-muted);">
        Sin cuentas registradas. Utiliza <strong>Nuevo Registro</strong> o el <strong>Generador de Sock Puppets</strong> para añadir una.
      </td></tr>`;
      return;
    }

    tbody.innerHTML = accounts
      .map((acc) => {
        const isCooldown = acc.cooldown_until && acc.cooldown_until > Date.now() / 1000;
        const cooldownBadge = isCooldown
          ? `<span class="pill pill-warn">Enfriamiento (${Math.round(
              acc.cooldown_until - Date.now() / 1000
            )}s)</span>`
          : "";
        const enabledPill = acc.enabled
          ? `<span class="pill pill-ok">Habilitada</span>`
          : `<span class="pill pill-muted">Deshabilitada</span>`;
        const isOnion = acc.platform === "onion" || acc.platform === "tor" || (acc.target_site || "").includes(".onion");
        const realmPill = isOnion
          ? `<span class="pill pill-cyan">Dark Web (.onion)</span>`
          : `<span class="pill pill-muted">Clearnet</span>`;

        return `
        <tr id="row-acc-${escapeHtml(acc.id)}">
          <td>
            <div style="font-weight:600;">${escapeHtml(acc.handle || acc.username || "Sin alias")}</div>
            <div class="mono" style="font-size:11px; color:var(--text-muted);">${escapeHtml(acc.id)}</div>
          </td>
          <td><strong>${escapeHtml(acc.platform)}</strong></td>
          <td>${realmPill}</td>
          <td>
            <div class="mono" style="font-size:11px;">${escapeHtml(acc.status_text || "Activa")}</div>
            ${acc.target_site ? `<div class="mono" style="font-size:10px; color:var(--text-muted);">Destino: ${escapeHtml(acc.target_site)}</div>` : ""}
          </td>
          <td>
            <span class="mono">${acc.rate_limit_rpm} RPM</span>
            ${cooldownBadge}
          </td>
          <td>${enabledPill}</td>
          <td>
            <div style="display:flex; gap:0.35rem;">
              <button class="btn btn-secondary btn-sm" onclick="verifyAccount('${escapeHtml(acc.id)}')">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>
                Verificar
              </button>
              <button class="btn btn-danger btn-sm" onclick="deleteAccount('${escapeHtml(acc.id)}')">
                Eliminar
              </button>
            </div>
          </td>
        </tr>`;
      })
      .join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" style="color:var(--accent-crimson); padding:1rem;">Error al cargar cuentas: ${escapeHtml(
      err.message
    )}</td></tr>`;
  }
}

async function verifyAccount(accountId) {
  const row = document.getElementById(`row-acc-${accountId}`);
  const btn = row?.querySelector("button");
  const origText = btn ? btn.innerHTML : "";
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `Comprobando...`;
  }

  try {
    const res = await fetch("/api/accounts/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ account_id: accountId }),
    });
    const report = await res.json();
    triggerVisualPulse(report.ok ? 0.7 : 0.4);

    let statusPill = "";
    if (report.status === "ok") {
      statusPill = `<span class="pill pill-ok">Válida (${report.latency_ms}ms)</span>`;
    } else if (report.status === "rate_limited") {
      statusPill = `<span class="pill pill-warn">Rate Limit (429)</span>`;
    } else if (report.status === "tor_unreachable") {
      statusPill = `<span class="pill pill-err">Tor Inaccesible</span>`;
    } else {
      statusPill = `<span class="pill pill-err">${escapeHtml(report.status)}</span>`;
    }

    alert(`Resultado de verificación para ${accountId}:\n\nEstado: ${report.status.toUpperCase()}\nDiagnóstico: ${report.message}\nLatencia: ${report.latency_ms} ms`);
    loadAccounts();
  } catch (err) {
    alert(`Error al contactar con el backend: ${err.message}`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = origText;
    }
  }
}

async function deleteAccount(accountId) {
  if (!confirm(`¿Eliminar la cuenta '${accountId}' de ~/.maltego-mcp/accounts.toml?`)) {
    return;
  }
  try {
    const res = await fetch(`/api/accounts/${encodeURIComponent(accountId)}`, {
      method: "DELETE",
    });
    const data = await res.json();
    if (data.ok) {
      loadAccounts();
      loadStatus();
    } else {
      alert(`No se pudo eliminar: ${data.error || "error desconocido"}`);
    }
  } catch (err) {
    alert(`Error de red: ${err.message}`);
  }
}

// Modal Nueva Cuenta
function openNewAccountModal() {
  document.getElementById("modal-account").classList.add("open");
}

function closeNewAccountModal() {
  document.getElementById("modal-account").classList.remove("open");
}

async function submitNewAccount(e) {
  e.preventDefault();
  const form = document.getElementById("form-account");
  const payload = {
    id: form.acc_id.value.trim() || undefined,
    platform: form.acc_platform.value.trim().toLowerCase(),
    username: form.acc_username.value.trim(),
    token: form.acc_token.value.trim() || undefined,
    cookie: form.acc_cookie.value.trim() || undefined,
    token_env: form.acc_token_env.value.trim() || undefined,
    target_site: form.acc_target_site.value.trim() || undefined,
    proxy: form.acc_proxy.value.trim() || undefined,
    user_agent: form.acc_user_agent.value.trim() || undefined,
    rate_limit_rpm: parseInt(form.acc_rpm.value, 10) || 30,
    enabled: form.acc_enabled.checked,
  };

  try {
    const res = await fetch("/api/accounts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (data.ok) {
      closeNewAccountModal();
      form.reset();
      loadAccounts();
      loadStatus();
      triggerVisualPulse(0.9);
    } else {
      alert(`Error al guardar: ${data.error}`);
    }
  } catch (err) {
    alert(`Error de red: ${err.message}`);
  }
}

// Modal Generador de Sock Puppets
function openPersonaModal() {
  document.getElementById("modal-persona").classList.add("open");
  generatePersonaPreview();
}

function closePersonaModal() {
  document.getElementById("modal-persona").classList.remove("open");
  if (totpTimer) clearInterval(totpTimer);
}

async function generatePersonaPreview() {
  const role = document.getElementById("persona-role")?.value || "threat_intel_collector";
  const region = document.getElementById("persona-region")?.value || "EE";
  const site = document.getElementById("persona-site")?.value || "exploit.in";

  try {
    const res = await fetch("/api/accounts/generate-persona", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role, region, target_site: site, save: false }),
    });
    const persona = await res.json();
    currentPersona = persona;
    renderPersonaKit(persona);
  } catch (err) {
    console.error("Error al generar persona:", err);
  }
}

function renderPersonaKit(p) {
  const container = document.getElementById("persona-result");
  if (!container) return;

  container.innerHTML = `
    <div class="persona-kit">
      <div style="display:flex; justify-content:space-between; align-items:flex-start;">
        <div>
          <div style="font-size:17px; font-weight:700; color:var(--text-primary);">${escapeHtml(p.display_name)}</div>
          <div class="mono" style="font-size:13px; color:var(--accent-cyan);">@${escapeHtml(p.handle)}</div>
        </div>
        <span class="pill pill-cyan">${escapeHtml(p.role)}</span>
      </div>
      
      <p style="margin: 0.75rem 0; font-size:12px; color:var(--text-secondary);">${escapeHtml(p.bio)}</p>

      <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.5rem; font-size:11px; margin-bottom:1rem;">
        <div><span style="color:var(--text-muted);">Zona horaria:</span> <strong class="mono">${escapeHtml(p.timezone)}</strong></div>
        <div><span style="color:var(--text-muted);">Correo burner:</span> <strong class="mono">${escapeHtml(p.burner_email_hint)}</strong></div>
        <div><span style="color:var(--text-muted);">Huella PGP:</span> <strong class="mono">${escapeHtml(p.pgp_key_id_hint)}</strong></div>
        <div><span style="color:var(--text-muted);">Proxy sugerido:</span> <strong class="mono">${escapeHtml(p.proxy_recommendation)}</strong></div>
      </div>

      <div class="totp-box">
        <div>
          <div style="font-size:10px; text-transform:uppercase; color:var(--text-muted); font-weight:600;">Semilla TOTP 2FA Offline</div>
          <div class="mono" style="font-size:11px; color:var(--text-secondary); word-break:break-all;">${escapeHtml(p.totp_secret_base32)}</div>
        </div>
        <div style="text-align:right;">
          <div class="totp-code" id="totp-live-display">------</div>
          <div style="font-size:10px; color:var(--text-muted);" id="totp-countdown">30s</div>
        </div>
      </div>

      <div style="font-weight:600; font-size:12px; margin-bottom:0.35rem;">Checklist de Seguridad OPSEC:</div>
      <ul class="opsec-list">
        ${p.opsec_checklist.map((item) => `<li class="opsec-item"><input type="checkbox"> <span>${escapeHtml(item)}</span></li>`).join("")}
      </ul>

      <div style="margin-top:1.25rem; display:flex; justify-content:flex-end; gap:0.5rem;">
        <button class="btn btn-secondary btn-sm" onclick="copyPersonaJSON()">Copiar JSON</button>
        <button class="btn btn-primary btn-sm" onclick="saveCurrentPersona()">Guardar en accounts.toml</button>
      </div>
    </div>
  `;

  startTOTPCalculator(p.totp_secret_base32);
}

function startTOTPCalculator(secret) {
  if (totpTimer) clearInterval(totpTimer);
  updateTOTP(secret);
  totpTimer = setInterval(() => updateTOTP(secret), 1000);
}

function updateTOTP(secret) {
  const display = document.getElementById("totp-live-display");
  const countdown = document.getElementById("totp-countdown");
  if (!display || !countdown) return;

  const epoch = Math.floor(Date.now() / 1000);
  const remaining = 30 - (epoch % 30);
  countdown.textContent = `${remaining}s`;

  // Cálculo determinista simplificado para preview visual offline
  const timeSlice = Math.floor(epoch / 30);
  let hash = 0;
  for (let i = 0; i < secret.length; i++) {
    hash = (hash << 5) - hash + secret.charCodeAt(i) + timeSlice;
    hash |= 0;
  }
  const code = Math.abs(hash % 1000000).toString().padStart(6, "0");
  display.textContent = code;
}

async function saveCurrentPersona() {
  if (!currentPersona) return;
  try {
    const res = await fetch("/api/accounts/generate-persona", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        role: currentPersona.role,
        region: currentPersona.region,
        target_site: currentPersona.target_site,
        save: true,
      }),
    });
    const data = await res.json();
    alert(`Sock Puppet '${currentPersona.handle}' guardado en accounts.toml exitosamente.`);
    closePersonaModal();
    loadAccounts();
    loadStatus();
    triggerVisualPulse(0.9);
  } catch (err) {
    alert(`Error al guardar persona: ${err.message}`);
  }
}

function copyPersonaJSON() {
  if (!currentPersona) return;
  navigator.clipboard.writeText(JSON.stringify(currentPersona, null, 2));
  alert("Datos de Persona copiados al portapapeles.");
}

// 6. Proveedores y Claves API
async function loadProviders() {
  const container = document.getElementById("providers-grid");
  if (!container) return;

  try {
    const res = await fetch("/api/providers");
    const data = await res.json();
    const providers = data.providers || [];

    container.innerHTML = providers
      .map(
        (p) => `
      <div class="metric-box">
        <div style="display:flex; justify-content:space-between; align-items:flex-start;">
          <strong>${escapeHtml(p.name)}</strong>
          ${
            p.is_configured
              ? `<span class="pill pill-ok">Configurada</span>`
              : `<span class="pill pill-muted">Sin clave</span>`
          }
        </div>
        <p style="font-size:11px; color:var(--text-secondary); margin:0.5rem 0;">${escapeHtml(p.description)}</p>
        <div class="mono" style="font-size:10px; color:var(--text-muted);">Variable: ${escapeHtml(p.env_vars.join(", "))}</div>
      </div>
    `
      )
      .join("");
  } catch (err) {
    console.error("Error al cargar proveedores:", err);
  }
}

// 7. Feeds CTI Dark Web
async function loadCTIFeeds() {
  const tbody = document.getElementById("cti-tbody");
  if (!tbody) return;

  try {
    const res = await fetch("/api/cti-feeds");
    const data = await res.json();
    const sources = data.sources || [];

    document.getElementById("cti-active-count") &&
      (document.getElementById("cti-active-count").textContent = data.active_count || 0);
    document.getElementById("cti-purged-count") &&
      (document.getElementById("cti-purged-count").textContent = data.purged_count || 0);

    if (sources.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:1.5rem; color:var(--text-muted);">Sin fuentes indexadas. Pulsa 'Sincronizar Feeds CTI'.</td></tr>`;
      return;
    }

    tbody.innerHTML = sources
      .map(
        (s) => `
      <tr>
        <td style="font-weight:600;">${escapeHtml(s.name)}</td>
        <td><span class="pill pill-cyan">${escapeHtml(s.category)}</span></td>
        <td class="mono" style="font-size:11px; max-width:240px; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(
          s.url
        )}</td>
        <td><span class="pill pill-ok">${escapeHtml(s.status)}</span></td>
        <td class="mono" style="font-size:10px; color:var(--text-muted);">${escapeHtml(s.updated_at || "-")}</td>
      </tr>
    `
      )
      .join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" style="color:var(--accent-crimson);">Error al cargar CTI: ${escapeHtml(
      err.message
    )}</td></tr>`;
  }
}

async function triggerCTISync() {
  const btn = document.getElementById("btn-sync-cti");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Sincronizando...";
  }
  try {
    const res = await fetch("/api/cti-feeds/sync", { method: "POST" });
    const data = await res.json();
    alert(`Sincronización CTI completada:\n\nFuentes activas (ONLINE): ${data.active_rows}\nFuentes purgadas (OFFLINE): ${data.purged_rows}`);
    loadCTIFeeds();
    loadStatus();
    triggerVisualPulse(1.0);
  } catch (err) {
    alert(`Fallo en la sincronización: ${err.message}`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Sincronizar Feeds CTI";
    }
  }
}

// 8. Catálogo de Transforms y Playground
async function loadTransforms() {
  const select = document.getElementById("playground-transform");
  const listContainer = document.getElementById("transforms-list");

  try {
    const res = await fetch("/api/transforms");
    const data = await res.json();
    const transforms = data.transforms || [];

    if (select) {
      select.innerHTML = transforms
        .map((t) => `<option value="${escapeHtml(t.name)}">${escapeHtml(t.name)} (${escapeHtml(t.category)})</option>`)
        .join("");
    }

    if (listContainer) {
      listContainer.innerHTML = transforms
        .map(
          (t) => `
        <div style="padding:0.65rem 0; border-bottom:1px solid var(--border-subtle); display:flex; justify-content:space-between; align-items:center;">
          <div>
            <strong style="color:var(--text-primary); font-size:13px;">${escapeHtml(t.name)}</strong>
            <p style="font-size:11px; color:var(--text-secondary); margin-top:2px;">${escapeHtml(t.description)}</p>
          </div>
          <span class="pill pill-muted">${escapeHtml(t.category)}</span>
        </div>
      `
        )
        .join("");
    }
  } catch (err) {
    console.error("Error al cargar transforms:", err);
  }
}

async function runPlaygroundLookup(e) {
  e.preventDefault();
  const tx = document.getElementById("playground-transform")?.value;
  const val = document.getElementById("playground-value")?.value?.trim();
  const type = document.getElementById("playground-type")?.value?.trim() || "auto";
  const resultDiv = document.getElementById("playground-results");

  if (!tx || !val) {
    alert("Introduce un valor objetivo para consultar.");
    return;
  }

  if (resultDiv) {
    resultDiv.innerHTML = `<div style="padding:1rem; color:var(--text-muted);">Ejecutando transformada '${escapeHtml(tx)}'...</div>`;
  }

  try {
    triggerVisualPulse(0.8);
    const res = await fetch("/api/lookup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ transform: tx, value: val, type }),
    });
    const data = await res.json();

    if (!data.ok) {
      resultDiv.innerHTML = `<div style="padding:1rem; color:var(--accent-crimson);">Error: ${escapeHtml(
        data.error || "Fallo en ejecución"
      )}</div>`;
      return;
    }

    const entities = data.entities || [];
    if (entities.length === 0) {
      resultDiv.innerHTML = `<div style="padding:1rem; color:var(--text-muted);">${escapeHtml(
        data.message || "Sin resultados para la búsqueda."
      )}</div>`;
      return;
    }

    resultDiv.innerHTML = `
      <div style="font-size:11px; margin-bottom:0.5rem; color:var(--accent-emerald);">Se obtuvieron ${entities.length} entidades:</div>
      <table class="data-table">
        <thead><tr><th>Tipo</th><th>Valor</th><th>Relación</th></tr></thead>
        <tbody>
          ${entities
            .map(
              (ent) => `
            <tr>
              <td><span class="pill pill-cyan">${escapeHtml(ent.type)}</span></td>
              <td class="mono"><strong>${escapeHtml(ent.value)}</strong></td>
              <td class="mono" style="color:var(--text-muted);">${escapeHtml(ent.label || "-")}</td>
            </tr>
          `
            )
            .join("")}
        </tbody>
      </table>
    `;
  } catch (err) {
    resultDiv.innerHTML = `<div style="padding:1rem; color:var(--accent-crimson);">Fallo de red: ${escapeHtml(
      err.message
    )}</div>`;
  }
}

// Utilidad anti-XSS
function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
