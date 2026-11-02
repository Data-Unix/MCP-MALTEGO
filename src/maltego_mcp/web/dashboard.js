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
  loadBurnerInboxesFromStorage();
  loadEmailProviders();
  loadProviders();
  loadCTIFeeds();
  loadTransforms();
  loadCasesList();
  initInteractiveGraph();
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

  if (tab === "graph") {
    setTimeout(() => {
      resizeGraphCanvas();
      if (currentCaseId && graphNodes.length === 0) {
        loadCaseGraph(currentCaseId);
      } else {
        physicsAlpha = Math.max(physicsAlpha, 0.4);
      }
    }, 50);
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
  if (ev.type === "inbox_created") {
    appendLogEntry("INBOX", `Buzón efímero creado: ${ev.address}`);
    triggerVisualPulse(0.7);
  }
  if (ev.type === "cti_synced") {
    loadCTIFeeds();
  }
  if (ev.type === "case_created") {
    appendLogEntry("CASO", `Caso creado: ${ev.case_id}`);
    triggerVisualPulse(0.8);
    loadCasesList(ev.case_id);
  }
  if (ev.type === "case_deleted") {
    appendLogEntry("CASO", `Caso eliminado: ${ev.case_id}`);
    loadCasesList();
  }
  if (ev.type === "graph_updated") {
    if (ev.case_id) {
      loadCasesList(ev.case_id);
      loadCaseGraph(ev.case_id);
    }
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

// 9. Motor de Grafo Interactivo 2D en Canvas con Simulación de Fuerzas Físicas
let graphCanvas = null;
let graphCtx = null;
let currentCaseId = "";
let rawGraphData = { nodes: [], links: [] };
let activeFilter = "all";
let currentLayoutMode = "force";
let graphNodes = [];
let graphLinks = [];
let graphSteps = [];
let selectedNode = null;
let hoveredNode = null;

// Cámara y navegación (Pan & Zoom)
let graphCamera = { x: 0, y: 0, scale: 1.0 };
let isPanning = false;
let panStart = { x: 0, y: 0 };
let draggedNode = null;

// Simulación de fuerzas físicas (Force-Directed Damped Physics)
let physicsAnimId = null;
let physicsAlpha = 1.0;

function initInteractiveGraph() {
  graphCanvas = document.getElementById("graph-interactive-canvas");
  if (!graphCanvas) return;
  graphCtx = graphCanvas.getContext("2d");

  resizeGraphCanvas();
  window.addEventListener("resize", () => {
    resizeGraphCanvas();
    physicsAlpha = Math.max(physicsAlpha, 0.3);
  });

  // Eventos del ratón para navegación, arrastre y selección
  graphCanvas.addEventListener("mousedown", onGraphMouseDown);
  window.addEventListener("mousemove", onGraphMouseMove);
  window.addEventListener("mouseup", onGraphMouseUp);
  graphCanvas.addEventListener("wheel", onGraphWheel, { passive: false });

  // Iniciar bucle de animación
  if (!physicsAnimId) {
    physicsAnimId = requestAnimationFrame(physicsLoop);
  }
}

function resizeGraphCanvas() {
  if (!graphCanvas || !graphCanvas.parentElement) return;
  const rect = graphCanvas.parentElement.getBoundingClientRect();
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const w = Math.floor(rect.width || 800);
  const h = Math.floor(rect.height || 600);

  graphCanvas.width = w * dpr;
  graphCanvas.height = h * dpr;
  graphCanvas.style.width = `${w}px`;
  graphCanvas.style.height = `${h}px`;
}

function updateGraphStatusBar(msg) {
  const bar = document.getElementById("graph-status-bar");
  if (bar) bar.textContent = msg;
}

async function loadCasesList(autoSelectId = null) {
  const select = document.getElementById("graph-case-select");
  if (!select) return;

  try {
    const res = await fetch("/api/cases");
    const data = await res.json();
    const cases = data.cases || [];

    if (cases.length === 0) {
      select.innerHTML = `<option value="">(Sin casos creados)</option>`;
      updateGraphStatusBar("No hay casos OSINT registrados en GraphStore.");
      return;
    }

    select.innerHTML = cases
      .map(
        (c) =>
          `<option value="${escapeHtml(c.case_id)}">${escapeHtml(c.case_id)} (${c.entity_count} ents, ${c.edge_count} rels)</option>`
      )
      .join("");

    let targetId = autoSelectId;
    if (!targetId || !cases.some((c) => c.case_id === targetId)) {
      targetId = cases[0].case_id;
    }

    select.value = targetId;
    currentCaseId = targetId;
    loadCaseGraph(targetId);
  } catch (err) {
    console.error("Error al cargar lista de casos:", err);
  }
}

async function promptCreateCase() {
  const caseId = prompt("Identificador del nuevo caso (ej. caso-operacion-01):");
  if (!caseId || !caseId.trim()) return;
  const desc = prompt("Descripción del caso (opcional):") || "";

  try {
    const res = await fetch("/api/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ case_id: caseId.trim(), description: desc.trim() }),
    });
    const data = await res.json();
    if (!data.ok) {
      alert(`Error al crear caso: ${data.error || "Fallo desconocido"}`);
      return;
    }
    loadCasesList(data.case_id);
  } catch (err) {
    alert(`Error de red: ${err.message}`);
  }
}

function onCaseSelected(caseId) {
  if (!caseId) return;
  currentCaseId = caseId;
  loadCaseGraph(caseId);
}

function reloadCurrentGraph() {
  if (currentCaseId) {
    loadCaseGraph(currentCaseId);
  } else {
    loadCasesList();
  }
}

function exportCurrentCaseMtgx() {
  const select = document.getElementById("graph-case-select");
  const cid = (select && select.value) ? select.value : currentCaseId;
  if (!cid) {
    showToast("Selecciona un caso para exportar a .mtgx", "warning");
    return;
  }
  showToast(`Descargando ${cid}.mtgx para Maltego...`, "info");
  window.location.href = `/api/cases/${encodeURIComponent(cid)}/export/mtgx`;
}

async function loadCaseGraph(caseId) {
  if (!caseId) return;
  currentCaseId = caseId;
  updateGraphStatusBar(`Cargando topología del caso '${caseId}'...`);

  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/graph`);
    const data = await res.json();

    if (!data.ok) {
      updateGraphStatusBar(`Error al cargar caso: ${data.error || "No encontrado"}`);
      return;
    }

    rawGraphData = data;
    graphSteps = data.steps || [];
    buildGraphModel(data);
    updateGraphStatusBar(
      `Caso: ${caseId} | Nodos: ${data.nodes.length} | Aristas: ${data.links.length} | Calidad: ${(data.quality * 100).toFixed(0)}%`
    );
  } catch (err) {
    updateGraphStatusBar(`Fallo de conexión al cargar grafo: ${err.message}`);
  }
}

function buildGraphModel(data) {
  const nodeMap = new Map();
  const rawNodes = data.nodes || [];

  // Determinación genérica de nodo objetivo / raíz (por prioridad, rol o primer nodo)
  const targetId =
    rawNodes.find((n) => n.properties?.role === "target" || n.properties?.role === "client_target")?.id ||
    rawNodes[0]?.id ||
    "";

  // Construcción de nodos enriquecidos
  graphNodes = rawNodes.map((n, idx) => {
    const isTarget = n.id === targetId || n.properties?.role === "target" || n.properties?.role === "client_target";
    const isRisk =
      Boolean(n.properties?.risk) ||
      Boolean(n.properties?.conflict) ||
      n.properties?.market_role === "concurrent_client" ||
      String(n.value).toLowerCase().includes("risk") ||
      String(n.type).toLowerCase().includes("threat");

    const isLocation =
      n.type.includes("Location") || n.type.includes("Country") || Boolean(n.properties?.["geo.scope"]);
    const isService =
      n.type.includes("Service") || n.type.includes("Server") || n.type.includes("URL");
    const isNetwork =
      n.type.includes("IPv4") || n.type.includes("Domain") || n.type.includes("DNS");
    const isPerson =
      n.type.includes("Person") || n.type.includes("Alias") || n.type.includes("Email");
    const isOrganization =
      n.type.includes("Company") || n.type.includes("Organization");

    let color = "#a78bfa";
    let radius = 14;

    if (isTarget) {
      color = "#00f5ff"; // Cyan - Objetivo Principal / Raíz
      radius = 22;
    } else if (isRisk) {
      color = "#f43f5e"; // Crimson - Conflicto / Riesgo / Alerta
      radius = 16;
    } else if (isLocation) {
      color = "#818cf8"; // Indigo - Ubicación / Infraestructura
      radius = 14;
    } else if (isService) {
      color = "#38bdf8"; // Sky - Servicio / Conector
      radius = 13;
    } else if (isNetwork) {
      color = "#60a5fa"; // Blue - Red / Dominio / IP
      radius = 15;
    } else if (isPerson) {
      color = "#c084fc"; // Purple - Identidad / Persona
      radius = 16;
    } else if (isOrganization) {
      if (n.confidence >= 0.8) {
        color = "#10b981"; // Emerald - Alta Certeza
        radius = 18;
      } else {
        color = "#f59e0b"; // Amber - Indicio
        radius = 16;
      }
    } else {
      color = n.confidence >= 0.8 ? "#10b981" : "#f59e0b";
      radius = 14;
    }

    // Distribución geométrica natural radial (Phyllotaxis spiral)
    let initialX = 0;
    let initialY = 0;

    if (!isTarget && idx > 0) {
      const angle = idx * 2.39996;
      const dist = 60 + Math.sqrt(idx) * 46;
      initialX = Math.cos(angle) * dist;
      initialY = Math.sin(angle) * dist;
    }

    const nodeObj = {
      ...n,
      x: initialX,
      y: initialY,
      vx: 0,
      vy: 0,
      radius,
      color,
      isTarget,
      isRisk,
      isLocation,
      isService,
      isNetwork,
      isPerson,
      isOrganization,
      visible: true,
    };
    nodeMap.set(n.id, nodeObj);
    return nodeObj;
  });

  // Construcción y resolución de aristas
  graphLinks = (data.links || [])
    .map((l) => {
      const sourceNode = nodeMap.get(l.source);
      const targetNode = nodeMap.get(l.target);
      if (!sourceNode || !targetNode) return null;

      const lbl = String(l.label || "").toLowerCase();
      const isRiskLink =
        lbl.includes("concurrent") || lbl.includes("conflict") || lbl.includes("threat") || lbl.includes("exclusivity");
      const isTargetLink =
        targetNode.isTarget || lbl.includes("target") || lbl.includes("serves") || lbl.includes("operates");
      const isFacilityLink =
        lbl.includes("facility") || lbl.includes("located") || lbl.includes("infrastructure");

      return {
        ...l,
        sourceNode,
        targetNode,
        isRiskLink,
        isTargetLink,
        isFacilityLink,
        visible: true,
      };
    })
    .filter(Boolean);

  applyFilter();
  graphResetZoom();
  physicsAlpha = 1.0;

  // Auto-seleccionar nodo objetivo si existe
  const targetNode = graphNodes.find((n) => n.isTarget) || graphNodes[0];
  if (targetNode) {
    selectNode(targetNode);
  }

  if (currentLayoutMode !== "force") {
    setGraphLayout(currentLayoutMode);
  }
}

function setGraphLayout(layoutMode) {
  currentLayoutMode = layoutMode;

  // Actualizar botones UI
  document.querySelectorAll(".layout-btn-group .btn").forEach((btn) => btn.classList.remove("active"));
  const activeBtn = document.getElementById(`layout-btn-${layoutMode}`);
  if (activeBtn) activeBtn.classList.add("active");

  if (graphNodes.length === 0) return;

  const targetNode = graphNodes.find((n) => n.isTarget) || graphNodes[0];
  const targetId = targetNode ? targetNode.id : "";

  // 1. MODO FORZADO / ORGÁNICO
  if (layoutMode === "force") {
    physicsAlpha = 1.0;
    showToast("Disposición cambiada a: Orgánico (Fuerzas físicas)", "info");
    return;
  }

  // 2. MODO JERÁRQUICO (TOP-DOWN)
  if (layoutMode === "hierarchical") {
    const withCustomPos = graphNodes.filter((n) => n.properties?.["mcp.pos.x"] && n.properties?.["mcp.pos.y"]);
    if (withCustomPos.length >= graphNodes.length * 0.5) {
      graphNodes.forEach((n) => {
        const px = parseFloat(n.properties?.["mcp.pos.x"]);
        const py = parseFloat(n.properties?.["mcp.pos.y"]);
        if (!isNaN(px) && !isNaN(py)) {
          n.x = px;
          n.y = py;
        }
        n.vx = 0;
        n.vy = 0;
      });
    } else {
      const adj = new Map();
      graphNodes.forEach((n) => adj.set(n.id, []));
      graphLinks.forEach((l) => {
        if (adj.has(l.sourceNode.id) && adj.has(l.targetNode.id)) {
          adj.get(l.sourceNode.id).push(l.targetNode.id);
          adj.get(l.targetNode.id).push(l.sourceNode.id);
        }
      });

      const levels = new Map();
      const visited = new Set();
      const queue = [{ id: targetId, depth: 0 }];
      visited.add(targetId);

      while (queue.length > 0) {
        const item = queue.shift();
        if (!levels.has(item.depth)) levels.set(item.depth, []);
        levels.get(item.depth).push(item.id);

        const neighbors = adj.get(item.id) || [];
        for (const nbr of neighbors) {
          if (!visited.has(nbr)) {
            visited.add(nbr);
            queue.push({ id: nbr, depth: item.depth + 1 });
          }
        }
      }

      graphNodes.forEach((n) => {
        if (!visited.has(n.id)) {
          const maxD = Math.max(...Array.from(levels.keys()), 0) + 1;
          if (!levels.has(maxD)) levels.set(maxD, []);
          levels.get(maxD).push(n.id);
        }
      });

      levels.forEach((nodesInLvl, depth) => {
        const lvlWidth = nodesInLvl.length;
        nodesInLvl.forEach((nid, i) => {
          const node = graphNodes.find((n) => n.id === nid);
          if (node) {
            node.x = (i - (lvlWidth - 1) / 2) * 200.0;
            node.y = depth * 350.0;
            node.vx = 0;
            node.vy = 0;
          }
        });
      });
    }

    physicsAlpha = 0;
    graphResetZoom();
    drawGraph();
    showToast("Disposición cambiada a: Jerárquico (Piramidal Top-Down)", "info");
    return;
  }

  // 3. MODO RADIAL (CÍRCULOS CONCÉNTRICOS)
  if (layoutMode === "radial") {
    const adj = new Map();
    graphNodes.forEach((n) => adj.set(n.id, []));
    graphLinks.forEach((l) => {
      if (adj.has(l.sourceNode.id) && adj.has(l.targetNode.id)) {
        adj.get(l.sourceNode.id).push(l.targetNode.id);
        adj.get(l.targetNode.id).push(l.sourceNode.id);
      }
    });

    const hops = new Map();
    const visited = new Set();
    const queue = [{ id: targetId, depth: 0 }];
    visited.add(targetId);

    while (queue.length > 0) {
      const item = queue.shift();
      if (!hops.has(item.depth)) hops.set(item.depth, []);
      hops.get(item.depth).push(item.id);

      for (const nbr of adj.get(item.id) || []) {
        if (!visited.has(nbr)) {
          visited.add(nbr);
          queue.push({ id: nbr, depth: item.depth + 1 });
        }
      }
    }

    graphNodes.forEach((n) => {
      if (!visited.has(n.id)) {
        const maxH = Math.max(...Array.from(hops.keys()), 0) + 1;
        if (!hops.has(maxH)) hops.set(maxH, []);
        hops.get(maxH).push(n.id);
      }
    });

    hops.forEach((nodesInHop, hop) => {
      if (hop === 0) {
        const rootNode = graphNodes.find((n) => n.id === nodesInHop[0]);
        if (rootNode) {
          rootNode.x = 0;
          rootNode.y = 0;
          rootNode.vx = 0;
          rootNode.vy = 0;
        }
      } else {
        const radius = hop * 300.0;
        const total = nodesInHop.length;
        nodesInHop.forEach((nid, i) => {
          const angle = (2 * Math.PI * i) / total;
          const node = graphNodes.find((n) => n.id === nid);
          if (node) {
            node.x = radius * Math.cos(angle);
            node.y = radius * Math.sin(angle);
            node.vx = 0;
            node.vy = 0;
          }
        });
      }
    });

    physicsAlpha = 0;
    graphResetZoom();
    drawGraph();
    showToast("Disposición cambiada a: Radial (Círculos Concéntricos)", "info");
    return;
  }

  // 4. MODO POR CATEGORÍA / TIPO
  if (layoutMode === "cluster") {
    const clusters = {
      target: { x: 0, y: 0, nodes: [] },
      orgs: { x: -650, y: -380, nodes: [] },
      services: { x: -650, y: 420, nodes: [] },
      locations: { x: 650, y: -380, nodes: [] },
      evidence: { x: 650, y: 420, nodes: [] },
    };

    graphNodes.forEach((n) => {
      if (n.isTarget) {
        clusters.target.nodes.push(n);
      } else if (n.isLocation || n.type?.includes("GPS")) {
        clusters.locations.nodes.push(n);
      } else if (n.isService || n.type?.includes("Service")) {
        clusters.services.nodes.push(n);
      } else if (n.isOrganization || n.type?.includes("Company") || n.type?.includes("Organization")) {
        clusters.orgs.nodes.push(n);
      } else {
        clusters.evidence.nodes.push(n);
      }
    });

    Object.values(clusters).forEach((c) => {
      c.nodes.forEach((node, idx) => {
        if (node.isTarget) {
          node.x = c.x;
          node.y = c.y;
        } else {
          const angle = idx * 2.39996;
          const dist = 35 + Math.sqrt(idx) * 48;
          node.x = c.x + Math.cos(angle) * dist;
          node.y = c.y + Math.sin(angle) * dist;
        }
        node.vx = 0;
        node.vy = 0;
      });
    });

    physicsAlpha = 0;
    graphResetZoom();
    drawGraph();
    showToast("Disposición cambiada a: Por Categoría (Bloques)", "info");
  }
}

function setGraphFilter(filter) {
  activeFilter = filter;
  applyFilter();
  physicsAlpha = Math.max(physicsAlpha, 0.4);
}

function applyFilter() {
  graphNodes.forEach((n) => {
    if (activeFilter === "all") {
      n.visible = true;
    } else if (activeFilter === "high") {
      n.visible = n.isTarget || n.confidence >= 0.8 || n.isLocation;
    } else if (activeFilter === "medium") {
      n.visible = n.confidence < 0.8;
    } else if (activeFilter === "risk") {
      n.visible = n.isRisk || n.isTarget;
    }
  });

  graphLinks.forEach((l) => {
    l.visible = l.sourceNode.visible && l.targetNode.visible;
    if (activeFilter === "risk" && !l.isRiskLink && !l.isTargetLink) {
      l.visible = false;
    }
  });
}

function graphZoom(factor, clientX = null, clientY = null) {
  const oldScale = graphCamera.scale;
  const newScale = Math.min(Math.max(oldScale * factor, 0.25), 4.0);
  if (newScale === oldScale) return;

  if (clientX !== null && clientY !== null && graphCanvas) {
    const rect = graphCanvas.getBoundingClientRect();
    const mouseX = clientX - rect.left - rect.width / 2;
    const mouseY = clientY - rect.top - rect.height / 2;
    graphCamera.x -= (mouseX - graphCamera.x) * (newScale / oldScale - 1);
    graphCamera.y -= (mouseY - graphCamera.y) * (newScale / oldScale - 1);
  }

  graphCamera.scale = newScale;
  physicsAlpha = Math.max(physicsAlpha, 0.1);
}

function graphResetZoom() {
  graphCamera = { x: 0, y: 0, scale: 1.0 };
  physicsAlpha = Math.max(physicsAlpha, 0.2);
}

// Interacciones de Ratón en Canvas
function getGraphCoordinates(e) {
  const rect = graphCanvas.getBoundingClientRect();
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const clientX = e.clientX;
  const clientY = e.clientY;

  const canvasX = clientX - rect.left;
  const canvasY = clientY - rect.top;

  const worldX = (canvasX - rect.width / 2 - graphCamera.x) / graphCamera.scale;
  const worldY = (canvasY - rect.height / 2 - graphCamera.y) / graphCamera.scale;

  return { worldX, worldY, clientX, clientY };
}

function findNodeAt(worldX, worldY) {
  for (let i = graphNodes.length - 1; i >= 0; i--) {
    const n = graphNodes[i];
    if (!n.visible) continue;
    const dx = worldX - n.x;
    const dy = worldY - n.y;
    if (dx * dx + dy * dy <= (n.radius + 6) * (n.radius + 6)) {
      return n;
    }
  }
  return null;
}

function onGraphMouseDown(e) {
  if (e.button !== 0) return; // Solo clic izquierdo
  const { worldX, worldY, clientX, clientY } = getGraphCoordinates(e);
  const hitNode = findNodeAt(worldX, worldY);

  if (hitNode) {
    draggedNode = hitNode;
    selectNode(hitNode);
    physicsAlpha = Math.max(physicsAlpha, 0.5);
  } else {
    isPanning = true;
    panStart = { x: clientX - graphCamera.x, y: clientY - graphCamera.y };
  }
}

function onGraphMouseMove(e) {
  const { worldX, worldY, clientX, clientY } = getGraphCoordinates(e);

  if (draggedNode) {
    draggedNode.x = worldX;
    draggedNode.y = worldY;
    draggedNode.vx = 0;
    draggedNode.vy = 0;
    physicsAlpha = Math.max(physicsAlpha, 0.3);
  } else if (isPanning) {
    graphCamera.x = clientX - panStart.x;
    graphCamera.y = clientY - panStart.y;
    physicsAlpha = Math.max(physicsAlpha, 0.05);
  } else if (graphCanvas) {
    const hit = findNodeAt(worldX, worldY);
    if (hit !== hoveredNode) {
      hoveredNode = hit;
      graphCanvas.style.cursor = hit ? "pointer" : "grab";
      physicsAlpha = Math.max(physicsAlpha, 0.05);
    }
  }
}

function onGraphMouseUp() {
  draggedNode = null;
  isPanning = false;
  if (graphCanvas) {
    graphCanvas.style.cursor = hoveredNode ? "pointer" : "default";
  }
}

function onGraphWheel(e) {
  e.preventDefault();
  const factor = e.deltaY < 0 ? 1.12 : 0.88;
  graphZoom(factor, e.clientX, e.clientY);
}

// Selección e Inspector Lateral
function selectNode(node) {
  selectedNode = node;
  renderInspector(node);
  physicsAlpha = Math.max(physicsAlpha, 0.1);
}

function renderInspector(node) {
  const typeEl = document.getElementById("insp-type");
  const badgeEl = document.getElementById("insp-badge");
  const bodyEl = document.getElementById("insp-body");

  if (!typeEl || !badgeEl || !bodyEl || !node) return;

  typeEl.textContent = node.type || "maltego.Entity";

  if (node.isTarget) {
    badgeEl.className = "pill pill-cyan";
    badgeEl.textContent = "Objetivo / Raíz";
  } else if (node.isRisk) {
    badgeEl.className = "pill pill-crimson";
    badgeEl.textContent = "Alerta / Conflicto";
  } else if (node.confidence >= 0.8) {
    badgeEl.className = "pill pill-ok";
    badgeEl.textContent = `Alta Certeza (${(node.confidence * 100).toFixed(0)}%)`;
  } else {
    badgeEl.className = "pill pill-amber";
    badgeEl.textContent = `Indicio (${(node.confidence * 100).toFixed(0)}%)`;
  }

  // Buscar relaciones incidentes
  const incidentEdges = graphLinks.filter(
    (l) => l.sourceNode.id === node.id || l.targetNode.id === node.id
  );

  const connectedList = incidentEdges.map((l) => {
    const isOut = l.sourceNode.id === node.id;
    const other = isOut ? l.targetNode : l.sourceNode;
    const direction = isOut ? "saliente ➔" : "entrante ⬅";
    return {
      edge: l,
      direction,
      other,
    };
  });

  // Trazabilidad y cadena de obtención desde los StepRecords
  const stepsDiscovered = (graphSteps || []).filter(
    (s) => s.outputs && s.outputs.includes(node.id)
  );

  const incomingParents = incidentEdges
    .filter((l) => l.targetNode.id === node.id && l.sourceNode.id !== node.id)
    .map((l) => l.sourceNode);

  const sourcesList = node.sources || [];
  const propsEntries = Object.entries(node.properties || {});

  bodyEl.innerHTML = `
    <div style="font-size:16px; font-weight:700; color:var(--text-primary); margin-bottom:0.25rem;">
      ${escapeHtml(node.value)}
    </div>
    <div class="mono" style="font-size:11px; color:var(--text-muted); margin-bottom:0.85rem; word-break:break-all;">
      ID: ${escapeHtml(node.id)}
    </div>

    <!-- 1. CADENA DE OBTENCIÓN Y TRAZABILIDAD CLICKABLE -->
    <div class="inspector-section" style="margin-bottom:0.85rem;">
      <div class="inspector-label" style="display:flex; justify-content:space-between; align-items:center;">
        <span>Cadena de Obtención / Procedencia</span>
        <span class="mono" style="font-size:9px; color:var(--accent-cyan); font-weight:600;">
          ${stepsDiscovered.length > 0 ? `${stepsDiscovered.length} paso(s)` : "Entidad Raíz"}
        </span>
      </div>

      ${
        stepsDiscovered.length > 0
          ? `
        <div style="display:flex; flex-direction:column; gap:0.4rem; margin-top:0.35rem;">
          ${stepsDiscovered
            .map((s) => {
              const inputNode = graphNodes.find((n) => n.id === s.input_id);
              const inputLabel = inputNode ? inputNode.value : s.input_value || s.input_id || "Definición del Caso";
              return `
              <div style="background:rgba(0, 245, 255, 0.04); border:1px solid rgba(0, 245, 255, 0.2); border-radius:5px; padding:0.45rem 0.6rem; font-size:11px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:2px;">
                  <strong class="mono" style="color:var(--accent-cyan); font-size:11px;">${escapeHtml(s.action)}</strong>
                  <span class="pill pill-muted" style="font-size:9px; padding:1px 5px;">Paso #${s.seq}</span>
                </div>
                ${
                  s.input_id
                    ? `
                  <div style="margin-top:4px; font-size:11px; display:flex; align-items:center; gap:4px; flex-wrap:wrap;">
                    <span style="color:var(--text-muted);">Disparado desde:</span>
                    <button class="pill pill-cyan" onclick="selectNodeById('${escapeHtml(s.input_id)}')" style="cursor:pointer; border:none; padding:1px 6px; font-size:10px; font-weight:600;">
                      ${escapeHtml(inputLabel)} ➔
                    </button>
                  </div>
                `
                    : ""
                }
                ${
                  s.reason
                    ? `<div style="font-size:10px; color:var(--text-secondary); margin-top:3px;"><em>${escapeHtml(s.reason)}</em></div>`
                    : ""
                }
                <div class="mono" style="font-size:9px; color:var(--text-muted); margin-top:3px;">${escapeHtml(s.timestamp || "")}</div>
              </div>
            `;
            })
            .join("")}
        </div>
      `
          : `
        <div style="background:rgba(255,255,255,0.02); border:1px solid var(--border-subtle); border-radius:5px; padding:0.4rem 0.6rem; font-size:11px; color:var(--text-muted); margin-top:0.35rem;">
          Punto de partida de la investigación (Entidad inicial / Ámbito definido)
        </div>
      `
      }

      ${
        incomingParents.length > 0
          ? `
        <div style="margin-top:0.5rem; font-size:11px;">
          <span style="color:var(--text-muted);">Saltos antecedentes:</span>
          <div style="display:flex; flex-wrap:wrap; gap:0.35rem; margin-top:0.25rem;">
            ${incomingParents
              .map(
                (p) => `
              <button class="pill pill-secondary" onclick="selectNodeById('${escapeHtml(p.id)}')" style="cursor:pointer; border:1px solid var(--border-subtle); font-size:10px; padding:1px 6px;">
                ⬅ ${escapeHtml(p.value)}
              </button>
            `
              )
              .join("")}
          </div>
        </div>
      `
          : ""
      }
    </div>

    <!-- 2. EVIDENCIAS Y NOTAS VERIFICABLES -->
    ${
      node.notes
        ? `
      <div class="inspector-fact-box" style="margin-bottom:0.85rem;">
        <div style="font-size:11px; font-weight:700; color:var(--accent-cyan); text-transform:uppercase; margin-bottom:0.35rem; display:flex; align-items:center; gap:0.35rem;">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
          Evidencias & Fuentes OSINT Verificables
        </div>
        <div style="font-size:12px; line-height:1.45; color:var(--text-secondary);">
          ${escapeHtml(node.notes)}
        </div>
      </div>
    `
        : ""
    }

    <!-- 3. FUENTES PRIMARIAS CITADAS -->
    ${
      sourcesList.length > 0
        ? `
      <div class="inspector-section" style="margin-bottom:0.85rem;">
        <div class="inspector-label">Fuentes Primarias Registradas (${sourcesList.length})</div>
        <div style="display:flex; flex-wrap:wrap; gap:0.35rem; margin-top:0.3rem;">
          ${sourcesList
            .map(
              (src) =>
                `<span class="pill pill-muted mono" style="font-size:10px; max-width:260px; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(src)}</span>`
            )
            .join("")}
        </div>
      </div>
    `
        : ""
    }

    <!-- 4. PROPIEDADES Y METADATOS -->
    <div class="inspector-section">
      <div class="inspector-label">Propiedades & Metadatos</div>
      <table style="width:100%; font-size:11px; border-collapse:collapse; margin-top:0.3rem;">
        <tbody>
          ${
            propsEntries.length > 0
              ? propsEntries
                  .map(
                    ([k, v]) => `
              <tr style="border-bottom:1px solid var(--border-subtle);">
                <td style="color:var(--text-muted); padding:3px 0;">${escapeHtml(k)}</td>
                <td class="mono" style="color:var(--accent-cyan); text-align:right; padding:3px 0; max-width:160px; overflow:hidden; text-overflow:ellipsis;">
                  ${escapeHtml(v)}
                </td>
              </tr>
            `
                  )
                  .join("")
              : `<tr><td colspan="2" style="color:var(--text-muted); padding:4px 0;">Sin metadatos extendidos</td></tr>`
          }
          <tr style="border-bottom:1px solid var(--border-subtle);">
            <td style="color:var(--text-muted); padding:3px 0;">prioridad_grafo</td>
            <td class="mono" style="color:var(--accent-emerald); text-align:right; padding:3px 0;">
              ${(node.priority || 0).toFixed(2)}
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- 5. RELACIONES CONECTADAS -->
    <div class="inspector-section" style="margin-top:1rem;">
      <div class="inspector-label">Relaciones Conectadas (${connectedList.length})</div>
      <div style="display:flex; flex-direction:column; gap:0.4rem; margin-top:0.4rem; max-height:220px; overflow-y:auto;">
        ${
          connectedList.length > 0
            ? connectedList
                .map(
                  (c) => `
              <div style="background:rgba(255,255,255,0.02); border:1px solid var(--border-subtle); border-radius:4px; padding:0.45rem 0.6rem; font-size:11px; cursor:pointer;" onclick="selectNodeById('${escapeHtml(c.other.id)}')">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:2px;">
                  <span class="mono" style="color:${c.edge.isRiskLink ? "var(--accent-crimson)" : "var(--accent-amber)"}; font-weight:600;">
                    ${escapeHtml(c.edge.label)}
                  </span>
                  <span style="font-size:10px; color:var(--text-muted);">${c.direction}</span>
                </div>
                <div style="color:var(--text-primary); font-weight:600;">
                  ${escapeHtml(c.other.value)}
                </div>
              </div>
            `
                )
                .join("")
            : `<div style="font-size:11px; color:var(--text-muted);">Nodo aislado sin conexiones directas.</div>`
        }
      </div>
    </div>
  `;
}

function selectNodeById(nodeId) {
  const node = graphNodes.find((n) => n.id === nodeId);
  if (node) {
    selectNode(node);
  }
}

// Bucle de Física y Renderizado Canvas
function physicsLoop() {
  stepPhysics();
  drawGraph();
  physicsAnimId = requestAnimationFrame(physicsLoop);
}

function stepPhysics() {
  if (currentLayoutMode !== "force") {
    physicsAlpha = 0;
    return;
  }
  if (physicsAlpha < 0.003) {
    physicsAlpha = 0;
    return; // En reposo: cero carga de CPU
  }

  const kCenter = 0.008 * physicsAlpha;
  const kRepulsion = 12000 * physicsAlpha;
  const kSpring = 0.045 * physicsAlpha;
  const damping = 0.82;

  // 1. Fuerza de centrado hacia el origen
  for (const n of graphNodes) {
    if (!n.visible || n === draggedNode) continue;
    n.vx -= n.x * kCenter;
    n.vy -= n.y * kCenter;
  }

  // 2. Repulsión entre nodos visibles
  const visibleNodes = graphNodes.filter((n) => n.visible);
  for (let i = 0; i < visibleNodes.length; i++) {
    const a = visibleNodes[i];
    for (let j = i + 1; j < visibleNodes.length; j++) {
      const b = visibleNodes[j];
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const distSq = dx * dx + dy * dy + 0.1;
      const dist = Math.sqrt(distSq);

      if (dist < 420) {
        const force = kRepulsion / distSq;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;

        if (a !== draggedNode) {
          a.vx -= fx;
          a.vy -= fy;
        }
        if (b !== draggedNode) {
          b.vx += fx;
          b.vy += fy;
        }
      }
    }
  }

  // 3. Atracción elástica por aristas conectadas
  for (const l of graphLinks) {
    if (!l.visible) continue;
    const a = l.sourceNode;
    const b = l.targetNode;
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    const dist = Math.sqrt(dx * dx + dy * dy) + 0.1;

    let targetDist = 120;
    if (l.isTargetLink) targetDist = 140;
    if (l.isFacilityLink) targetDist = 80;
    if (l.isConcurrentLink) targetDist = 160;

    const diff = dist - targetDist;
    const force = diff * kSpring;
    const fx = (dx / dist) * force;
    const fy = (dy / dist) * force;

    if (a !== draggedNode) {
      a.vx += fx;
      a.vy += fy;
    }
    if (b !== draggedNode) {
      b.vx -= fx;
      b.vy -= fy;
    }
  }

  // 4. Integración y amortiguamiento
  for (const n of graphNodes) {
    if (!n.visible || n === draggedNode) continue;
    n.vx *= damping;
    n.vy *= damping;

    // Límite de velocidad
    const speed = Math.sqrt(n.vx * n.vx + n.vy * n.vy);
    if (speed > 20) {
      n.vx = (n.vx / speed) * 20;
      n.vy = (n.vy / speed) * 20;
    }

    n.x += n.vx;
    n.y += n.vy;
  }

  physicsAlpha *= 0.985;
}

function drawGraph() {
  if (!graphCanvas || !graphCtx) return;

  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const w = graphCanvas.width / dpr;
  const h = graphCanvas.height / dpr;

  graphCtx.save();
  graphCtx.scale(dpr, dpr);
  graphCtx.clearRect(0, 0, w, h);

  // Cuadrícula sutil de fondo
  drawSubtleGrid(graphCtx, w, h);

  // Transformación de Cámara (Pan & Zoom)
  graphCtx.translate(w / 2 + graphCamera.x, h / 2 + graphCamera.y);
  graphCtx.scale(graphCamera.scale, graphCamera.scale);

  // 1. Dibujar Aristas
  for (const l of graphLinks) {
    if (!l.visible) continue;
    drawEdge(graphCtx, l);
  }

  // 2. Dibujar Nodos
  for (const n of graphNodes) {
    if (!n.visible) continue;
    drawNode(graphCtx, n);
  }

  graphCtx.restore();
}

function drawSubtleGrid(ctx, w, h) {
  ctx.strokeStyle = "rgba(255, 255, 255, 0.02)";
  ctx.lineWidth = 1;
  const step = 40;
  ctx.beginPath();
  for (let x = 0; x < w; x += step) {
    ctx.moveTo(x, 0);
    ctx.lineTo(x, h);
  }
  for (let y = 0; y < h; y += step) {
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
  }
  ctx.stroke();
}

function drawEdge(ctx, l) {
  const a = l.sourceNode;
  const b = l.targetNode;
  const isSelected = selectedNode && (selectedNode.id === a.id || selectedNode.id === b.id);

  ctx.beginPath();
  if (l.isRiskLink) {
    ctx.strokeStyle = isSelected ? "rgba(244, 63, 94, 0.9)" : "rgba(244, 63, 94, 0.55)";
    ctx.lineWidth = isSelected ? 2.5 : 1.5;
    ctx.setLineDash([5, 4]);
  } else if (l.isTargetLink) {
    ctx.strokeStyle = isSelected ? "rgba(0, 245, 255, 0.95)" : "rgba(0, 245, 255, 0.4)";
    ctx.lineWidth = isSelected ? 2.5 : 1.5;
    ctx.setLineDash([]);
  } else if (l.isFacilityLink) {
    ctx.strokeStyle = isSelected ? "rgba(129, 140, 248, 0.85)" : "rgba(129, 140, 248, 0.35)";
    ctx.lineWidth = isSelected ? 2.0 : 1.2;
    ctx.setLineDash([]);
  } else {
    ctx.strokeStyle = isSelected ? "rgba(255, 255, 255, 0.7)" : "rgba(255, 255, 255, 0.18)";
    ctx.lineWidth = isSelected ? 2.0 : 1.0;
    ctx.setLineDash([]);
  }

  ctx.moveTo(a.x, a.y);
  ctx.lineTo(b.x, b.y);
  ctx.stroke();
  ctx.setLineDash([]);

  // Flecha direccional orientada hacia el destino
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const dist = Math.sqrt(dx * dx + dy * dy);
  if (dist > b.radius + 10) {
    const arrowX = b.x - (dx / dist) * (b.radius + 4);
    const arrowY = b.y - (dy / dist) * (b.radius + 4);
    const angle = Math.atan2(dy, dx);
    const arrowSize = 6;

    ctx.fillStyle = ctx.strokeStyle;
    ctx.beginPath();
    ctx.moveTo(arrowX, arrowY);
    ctx.lineTo(
      arrowX - arrowSize * Math.cos(angle - Math.PI / 6),
      arrowY - arrowSize * Math.sin(angle - Math.PI / 6)
    );
    ctx.lineTo(
      arrowX - arrowSize * Math.cos(angle + Math.PI / 6),
      arrowY - arrowSize * Math.sin(angle + Math.PI / 6)
    );
    ctx.closePath();
    ctx.fill();
  }

  // Etiqueta de la arista si hay zoom suficiente o está seleccionada
  if (graphCamera.scale >= 0.85 || isSelected) {
    const midX = (a.x + b.x) / 2;
    const midY = (a.y + b.y) / 2;
    ctx.font = "9px Inter, system-ui, sans-serif";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";

    const labelText = l.label || "";
    const textWidth = ctx.measureText(labelText).width;

    ctx.fillStyle = "rgba(10, 13, 20, 0.85)";
    ctx.fillRect(midX - textWidth / 2 - 3, midY - 6, textWidth + 6, 12);

    ctx.fillStyle = l.isRiskLink ? "#f43f5e" : isSelected ? "#00f5ff" : "#94a3b8";
    ctx.fillText(labelText, midX, midY);
  }
}

function drawNode(ctx, n) {
  const isSelected = selectedNode && selectedNode.id === n.id;
  const isHovered = hoveredNode && hoveredNode.id === n.id;

  // 1. Halo de resplandor para nodos activos o seleccionados
  if (isSelected || isHovered || n.isTarget) {
    ctx.beginPath();
    ctx.arc(n.x, n.y, n.radius + (isSelected ? 9 : 5), 0, Math.PI * 2);
    ctx.fillStyle = isSelected
      ? "rgba(0, 245, 255, 0.35)"
      : n.isTarget
      ? "rgba(0, 245, 255, 0.2)"
      : "rgba(255, 255, 255, 0.15)";
    ctx.fill();
  }

  // 2. Cuerpo del nodo
  ctx.beginPath();
  ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
  ctx.fillStyle = n.color;
  ctx.fill();

  ctx.lineWidth = isSelected ? 2.5 : 1.5;
  ctx.strokeStyle = isSelected ? "#ffffff" : "rgba(10, 13, 20, 0.75)";
  ctx.stroke();

  // 3. Etiqueta de texto debajo del nodo con fondo contrastado
  ctx.font = isSelected ? "bold 11px Inter, system-ui, sans-serif" : "11px Inter, system-ui, sans-serif";
  ctx.textAlign = "center";
  ctx.textBaseline = "top";

  const label = n.value;
  const metrics = ctx.measureText(label);
  const textW = metrics.width;
  const labelY = n.y + n.radius + 4;

  ctx.fillStyle = "rgba(10, 13, 20, 0.88)";
  ctx.beginPath();
  roundRect(ctx, n.x - textW / 2 - 5, labelY - 2, textW + 10, 16, 4);
  ctx.fill();
  ctx.strokeStyle = isSelected ? "rgba(0, 245, 255, 0.6)" : "rgba(255, 255, 255, 0.08)";
  ctx.lineWidth = 1;
  ctx.stroke();

  ctx.fillStyle = isSelected ? "#ffffff" : "#e2e8f0";
  ctx.fillText(label, n.x, labelY);
}

function roundRect(ctx, x, y, width, height, radius) {
  ctx.moveTo(x + radius, y);
  ctx.lineTo(x + width - radius, y);
  ctx.quadraticCurveTo(x + width, y, x + width, y + radius);
  ctx.lineTo(x + width, y + height - radius);
  ctx.quadraticCurveTo(x + width, y + height, x + width - radius, y + height);
  ctx.lineTo(x + radius, y + height);
  ctx.quadraticCurveTo(x, y + height, x, y + height - radius);
  ctx.lineTo(x, y + radius);
  ctx.quadraticCurveTo(x, y, x + radius, y);
}

// ============================================================================
// 10. Buzones Efímeros, Receptor de OTPs y Catálogo OPSEC de Correos
// ============================================================================
let burnerInboxes = [];
let selectedInboxId = null;
let allEmailProviders = [];

function loadBurnerInboxesFromStorage() {
  try {
    const raw = localStorage.getItem("maltego_burner_inboxes");
    if (raw) {
      burnerInboxes = JSON.parse(raw);
    }
  } catch (e) {
    burnerInboxes = [];
  }
  if (burnerInboxes.length > 0) {
    selectedInboxId = burnerInboxes[0].inbox_id;
  }
  renderInboxList();
  if (selectedInboxId) {
    refreshCurrentInboxMessages();
  }
}

function saveBurnerInboxesToStorage() {
  try {
    localStorage.setItem("maltego_burner_inboxes", JSON.stringify(burnerInboxes));
  } catch (e) {
    console.error("Error guardando buzones en localStorage", e);
  }
}

async function createBurnerInbox() {
  const btn = document.getElementById("btn-create-inbox");
  const origText = btn ? btn.innerHTML : "";
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner" style="width:12px; height:12px; border-width:2px; display:inline-block; vertical-align:middle; margin-right:4px;"></span> Generando...`;
  }

  const saveSock = document.getElementById("chk-save-sockpuppet")?.checked || false;

  try {
    const res = await fetch("/api/inbox/create", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ save_as_sockpuppet: saveSock }),
    });
    const data = await res.json();
    if (data.ok) {
      const inboxEntry = {
        inbox_id: data.inbox_id,
        address: data.address,
        password: data.password,
        token: data.token,
        createdAt: new Date().toISOString(),
      };
      burnerInboxes.unshift(inboxEntry);
      selectedInboxId = inboxEntry.inbox_id;
      saveBurnerInboxesToStorage();
      renderInboxList();
      triggerVisualPulse(0.9);
      appendLogEntry("INBOX", `Buzón listo: ${data.address}`);
      refreshCurrentInboxMessages();
      if (saveSock) {
        loadAccounts();
      }
    } else {
      alert(`Error al generar buzón: ${data.error || "respuesta desconocida"}`);
    }
  } catch (err) {
    alert(`Error de red al crear buzón: ${err.message}`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = origText;
    }
  }
}

function renderInboxList() {
  const container = document.getElementById("inbox-list");
  const countPill = document.getElementById("inbox-count-pill");
  if (countPill) countPill.textContent = `${burnerInboxes.length} activos`;
  if (!container) return;

  if (burnerInboxes.length === 0) {
    container.innerHTML = `
      <div style="text-align:center; padding:1.5rem; color:var(--text-muted); font-size:0.85rem; border:1px dashed var(--border-subtle); border-radius:8px;">
        Ningún buzón temporal activo.<br>Haz clic en <strong>+ Generar Buzón Efímero</strong> para crear uno.
      </div>`;
    return;
  }

  container.innerHTML = burnerInboxes
    .map((ib) => {
      const isSelected = ib.inbox_id === selectedInboxId;
      const createdTime = ib.createdAt ? new Date(ib.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "";
      return `
        <div class="inbox-card ${isSelected ? "active" : ""}" onclick="selectInbox('${ib.inbox_id}')">
          <div class="inbox-card-header">
            <span class="inbox-addr" title="${ib.address}">📧 ${ib.address}</span>
            <span style="font-size:0.7rem; color:var(--text-muted);">${createdTime}</span>
          </div>
          <div style="display:flex; justify-content:space-between; align-items:center; margin-top:0.4rem;">
            <button class="btn btn-secondary btn-sm" style="font-size:0.7rem; padding:0.15rem 0.4rem;" onclick="event.stopPropagation(); copyInboxAddress('${ib.address}')" title="Copiar dirección de correo">
              📋 Copiar
            </button>
            <button class="btn btn-secondary btn-sm" style="font-size:0.7rem; padding:0.15rem 0.4rem; color:var(--accent-rose);" onclick="event.stopPropagation(); deleteBurnerInbox('${ib.inbox_id}')" title="Eliminar buzón de la sesión">
              ✕
            </button>
          </div>
        </div>
      `;
    })
    .join("");
}

function selectInbox(inboxId) {
  selectedInboxId = inboxId;
  renderInboxList();
  refreshCurrentInboxMessages();
}

function deleteBurnerInbox(inboxId) {
  burnerInboxes = burnerInboxes.filter((b) => b.inbox_id !== inboxId);
  if (selectedInboxId === inboxId) {
    selectedInboxId = burnerInboxes.length > 0 ? burnerInboxes[0].inbox_id : null;
  }
  saveBurnerInboxesToStorage();
  renderInboxList();
  if (selectedInboxId) {
    refreshCurrentInboxMessages();
  } else {
    const container = document.getElementById("inbox-messages-container");
    if (container) {
      container.innerHTML = `<div style="text-align:center; padding:2rem; color:var(--text-muted); font-size:0.85rem;">Ningún buzón seleccionado.</div>`;
    }
  }
}

function copyInboxAddress(address) {
  navigator.clipboard.writeText(address);
  appendLogEntry("PORTAPAPELES", `Copiado correo: ${address}`);
}

function copyInboxOTP(otp) {
  navigator.clipboard.writeText(otp);
  appendLogEntry("OTP", `Código ${otp} copiado al portapapeles`);
  triggerVisualPulse(0.7);
}

async function refreshCurrentInboxMessages() {
  const container = document.getElementById("inbox-messages-container");
  if (!container) return;

  const currentInbox = burnerInboxes.find((b) => b.inbox_id === selectedInboxId);
  if (!currentInbox) {
    container.innerHTML = `<div style="text-align:center; padding:2rem; color:var(--text-muted); font-size:0.85rem;">Ningún buzón seleccionado.</div>`;
    return;
  }

  container.innerHTML = `
    <div style="text-align:center; padding:2rem; color:var(--text-muted); font-size:0.85rem;">
      <span class="spinner" style="width:16px; height:16px; border-width:2px; display:inline-block; vertical-align:middle; margin-right:6px;"></span>
      Consultando mensajes para ${currentInbox.address}...
    </div>`;

  try {
    const res = await fetch(`/api/inbox/messages?token=${encodeURIComponent(currentInbox.token)}`);
    const data = await res.json();
    const msgs = data.messages || [];

    if (msgs.length === 0) {
      container.innerHTML = `
        <div style="text-align:center; padding:2.5rem 1rem; color:var(--text-muted); font-size:0.85rem;">
          <div style="font-size:1.5rem; margin-bottom:0.5rem;">📭</div>
          Bandeja vacía.<br>
          Esperando mensajes de activación para <code>${currentInbox.address}</code>.<br>
          <span style="font-size:0.75rem; color:var(--text-secondary);">Haz clic en <strong>🔄 Consultar Mensajes</strong> cuando completes el formulario de registro en la web objetivo.</span>
        </div>`;
      return;
    }

    // Para cada mensaje, recuperar detalles con extracción de OTP y enlaces
    const detailedHtml = [];
    for (const m of msgs) {
      let detail = null;
      try {
        const dRes = await fetch(`/api/inbox/messages/${m.id}?token=${encodeURIComponent(currentInbox.token)}`);
        detail = await dRes.json();
      } catch (e) {
        detail = null;
      }

      const otps = detail && detail.detected_otps ? detail.detected_otps : [];
      const links = detail && detail.detected_links ? detail.detected_links : [];
      const msgDate = m.created_at ? new Date(m.created_at).toLocaleTimeString() : "";

      let otpHtml = "";
      if (otps.length > 0) {
        otpHtml = otps
          .map(
            (code) => `
          <div class="otp-alert-box">
            <div>
              <div style="font-size:0.7rem; text-transform:uppercase; font-weight:700; color:var(--accent-emerald);">🔑 Código de Activación / 2FA Detectado</div>
              <div class="otp-code">${code}</div>
            </div>
            <button class="btn btn-primary btn-sm" onclick="copyInboxOTP('${code}')">📋 Copiar Código</button>
          </div>
        `
          )
          .join("");
      }

      let linksHtml = "";
      if (links.length > 0) {
        linksHtml = links
          .map(
            (url) => `
          <div class="activation-url-box">
            <div style="font-size:0.7rem; font-weight:600; color:var(--accent-cyan); margin-bottom:0.2rem;">🔗 Enlace de Verificación / Activación:</div>
            <a href="${url}" target="_blank" rel="noopener noreferrer" style="color:#67e8f9; text-decoration:underline;">${url}</a>
          </div>
        `
          )
          .join("");
      }

      detailedHtml.push(`
        <div class="inbox-msg-card">
          <div class="inbox-msg-meta">
            <span>De: <strong>${m.from || "Desconocido"}</strong></span>
            <span>${msgDate}</span>
          </div>
          <div class="inbox-msg-subject">${m.subject || "(Sin asunto)"}</div>
          ${otpHtml}
          ${linksHtml}
          <div style="font-size:0.78rem; color:var(--text-secondary); line-height:1.4; margin-top:0.4rem; white-space:pre-wrap; max-height:120px; overflow-y:auto; background:rgba(0,0,0,0.2); padding:0.4rem; border-radius:4px;">
            ${(detail && detail.text) ? detail.text.slice(0, 500) : (m.intro || "")}
          </div>
        </div>
      `);
    }

    container.innerHTML = detailedHtml.join("");
  } catch (err) {
    container.innerHTML = `<div style="text-align:center; padding:2rem; color:var(--accent-rose); font-size:0.85rem;">Error al recuperar mensajes: ${err.message}</div>`;
  }
}

// Catálogo OPSEC de Proveedores de Correo
async function loadEmailProviders() {
  const grid = document.getElementById("email-providers-grid");
  if (!grid) return;

  try {
    const res = await fetch("/api/inbox/providers");
    const data = await res.json();
    allEmailProviders = data.providers || [];
    renderEmailProviders(allEmailProviders);
  } catch (err) {
    grid.innerHTML = `<div style="color:var(--text-muted); font-size:0.85rem;">No se pudo cargar el catálogo de proveedores de correo.</div>`;
  }
}

function filterEmailProviders(category, btn) {
  const filterGroup = document.getElementById("email-prov-filter-group");
  if (filterGroup) {
    filterGroup.querySelectorAll("button").forEach((b) => b.classList.remove("active"));
  }
  if (btn) btn.classList.add("active");

  if (category === "all") {
    renderEmailProviders(allEmailProviders);
  } else {
    renderEmailProviders(allEmailProviders.filter((p) => p.category === category));
  }
}

function renderEmailProviders(providers) {
  const grid = document.getElementById("email-providers-grid");
  if (!grid) return;

  if (providers.length === 0) {
    grid.innerHTML = `<div style="color:var(--text-muted); font-size:0.85rem;">Ningún proveedor en esta categoría.</div>`;
    return;
  }

  grid.innerHTML = providers
    .map((p) => {
      const opsecList = (p.recommended_opsec || [])
        .map((tip) => `<li>${tip}</li>`)
        .join("");

      return `
        <div class="email-prov-card">
          <div>
            <div class="email-prov-title">
              <span>${p.name}</span>
              <a href="${p.url}" target="_blank" rel="noopener noreferrer" class="btn btn-secondary btn-sm" style="font-size:0.7rem; padding:0.15rem 0.45rem;">
                Web ↗
              </a>
            </div>
            <div style="font-size:0.78rem; color:var(--text-secondary); line-height:1.4;">${p.description}</div>
            
            <div class="email-prov-tags">
              <span class="email-prov-tag">📍 ${p.jurisdiction}</span>
              <span class="email-prov-tag">🔒 ${p.encryption_type}</span>
              <span class="email-prov-tag">${p.requires_phone ? "📱 Teléfono req." : "🚫 Sin teléfono"}</span>
              ${p.tor_onion_available ? '<span class="email-prov-tag" style="color:var(--accent-purple);">🧅 Tor .onion</span>' : ""}
            </div>
          </div>

          <div class="email-prov-opsec">
            <div style="font-weight:600; color:var(--accent-cyan); margin-bottom:0.2rem;">🛡️ Pautas OPSEC Recomendadas:</div>
            <ul style="margin:0; padding-left:1.1rem; line-height:1.35;">
              ${opsecList}
            </ul>
          </div>
        </div>
      `;
    })
    .join("");
}

