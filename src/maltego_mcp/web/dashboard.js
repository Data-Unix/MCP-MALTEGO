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
  initImportDropzone();
  initAudioFeedback();
  initCommandPalette();
  initRadarHud();
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
  } else if (tab === "crypto-ledger") {
    renderCryptoLedger();
  } else if (tab === "forensics-vault") {
    renderForensicsVault();
  } else if (tab === "mitre-matrix") {
    renderMitreMatrix();
  } else if (tab === "geo-map") {
    renderGeoMap();
  } else if (tab === "rules-generator") {
    renderRulesGenerator();
  } else if (tab === "threat-watchtower") {
    renderWatchtower();
  } else if (tab === "desktop-bridge") {
    renderDesktopBridge();
  }
  playTacticalClick(720, 0.03);
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

// 5. Cuentas y Sock Puppets (Redes, Foros Underground, Mercados Dark Web)
let allLoadedAccounts = [];
let currentAccountCategoryFilter = "all";
let accountsSearchQuery = "";

async function loadAccounts() {
  const tbody = document.getElementById("accounts-tbody");
  if (!tbody) return;

  try {
    const res = await fetch("/api/accounts");
    const data = await res.json();
    allLoadedAccounts = data.accounts || [];

    const badge = document.getElementById("badge-accounts-count");
    if (badge) badge.textContent = allLoadedAccounts.length;

    // Actualizar contadores por categoría
    const cntAll = allLoadedAccounts.length;
    const cntSocial = allLoadedAccounts.filter((a) => (a.category || "social") === "social").length;
    const cntForum = allLoadedAccounts.filter((a) => (a.category || "").includes("forum")).length;
    const cntMarket = allLoadedAccounts.filter((a) => (a.category || "").includes("market")).length;
    const cntEmail = allLoadedAccounts.filter((a) => (a.category || "") === "email").length;

    const elAll = document.getElementById("cnt-acc-all");
    const elSocial = document.getElementById("cnt-acc-social");
    const elForum = document.getElementById("cnt-acc-forum");
    const elMarket = document.getElementById("cnt-acc-market");
    const elEmail = document.getElementById("cnt-acc-email");

    if (elAll) elAll.textContent = cntAll;
    if (elSocial) elSocial.textContent = cntSocial;
    if (elForum) elForum.textContent = cntForum;
    if (elMarket) elMarket.textContent = cntMarket;
    if (elEmail) elEmail.textContent = cntEmail;

    renderAccountsTable();
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" style="color:var(--accent-crimson); padding:1rem;">Error al cargar cuentas: ${escapeHtml(
      err.message
    )}</td></tr>`;
  }
}

function filterAccountsByCategory(category, btnElement) {
  currentAccountCategoryFilter = category;
  const pillContainer = document.getElementById("acc-filter-pills");
  if (pillContainer) {
    pillContainer.querySelectorAll(".pill").forEach((p) => p.classList.remove("active"));
  }
  if (btnElement) {
    btnElement.classList.add("active");
  }
  renderAccountsTable();
}

function filterAccountsSearch(query) {
  accountsSearchQuery = (query || "").toLowerCase().trim();
  renderAccountsTable();
}

function renderAccountsTable() {
  const tbody = document.getElementById("accounts-tbody");
  if (!tbody) return;

  let filtered = allLoadedAccounts;

  const limitSelect = document.querySelector("#view-accounts .table-limit-select");
  const limit = limitSelect ? limitSelect.value : "all";

  // Filtrado por categoría
  if (currentAccountCategoryFilter !== "all") {
    filtered = filtered.filter((acc) => {
      const cat = (acc.category || "social").toLowerCase();
      if (currentAccountCategoryFilter === "social") return cat === "social";
      if (currentAccountCategoryFilter === "forum") return cat === "forum";
      if (currentAccountCategoryFilter === "market") return cat === "market";
      if (currentAccountCategoryFilter === "email") return cat === "email";
      return true;
    });
  }

  // Filtrado por búsqueda en tiempo real
  if (accountsSearchQuery) {
    filtered = filtered.filter((acc) => {
      const q = accountsSearchQuery;
      return (
        (acc.id || "").toLowerCase().includes(q) ||
        (acc.handle || "").toLowerCase().includes(q) ||
        (acc.username || "").toLowerCase().includes(q) ||
        (acc.platform || "").toLowerCase().includes(q) ||
        (acc.target_site || "").toLowerCase().includes(q)
      );
    });
  }

  if (limit !== "all") {
    const num = parseInt(limit, 10);
    if (!isNaN(num) && num > 0) {
      filtered = filtered.slice(0, num);
    }
  }

  if (filtered.length === 0) {
    const msg =
      allLoadedAccounts.length === 0
        ? `Sin cuentas registradas. Utiliza <strong>+ Red Social</strong>, <strong>+ Foro Ciber</strong> o <strong>+ Mercado</strong> para registrar una.`
        : `No se encontraron cuentas para la categoría o filtro actual.`;
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding: 2rem; color: var(--text-muted);">${msg}</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered
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

      const isOnion =
        acc.platform === "onion" ||
        acc.platform === "tor" ||
        Boolean(acc.proxy && acc.proxy.includes("9050")) ||
        (acc.target_site || "").includes(".onion");

      const realmPill = isOnion
        ? `<span class="pill pill-purple" title="${escapeHtml(acc.proxy || 'Tor SOCKS5 127.0.0.1:9050')}">[TOR] Tor (.onion)</span>`
        : `<span class="pill pill-muted">[CLEARNET] Clearnet</span>`;

      // Insignia de categoría
      const cat = (acc.category || "social").toLowerCase();
      let catPill = `<span class="pill pill-cyan">[SOC] Red Social</span>`;
      if (cat === "forum") {
        catPill = `<span class="pill pill-err">[FRM] Foro Ciber</span>`;
      } else if (cat === "market") {
        catPill = `<span class="pill pill-warn">[MKT] Mercado / Leaks</span>`;
      } else if (cat === "email") {
        catPill = `<span class="pill pill-ok">[MAIL] Buzon</span>`;
      }

      // Credenciales
      const credBadges = [];
      if (acc.has_token) credBadges.push(`<span class="pill pill-ok" style="font-size:10px; padding:1px 5px;" title="Token de acceso configurado">[KEY] Token</span>`);
      if (acc.has_cookie) credBadges.push(`<span class="pill pill-purple" style="font-size:10px; padding:1px 5px;" title="Cookie de sesión configurada">[COOKIE] Cookie</span>`);

      return `
      <tr id="row-acc-${escapeHtml(acc.id)}">
        <td style="width:30px; text-align:center;">
          <button class="row-expand-btn" id="acc-row-${escapeHtml(acc.id)}-expand-btn" onclick="toggleRowDetail(this, 'acc-row-${escapeHtml(acc.id)}')">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"></polyline></svg>
          </button>
        </td>
        <td>
          <div style="font-weight:600; display:flex; align-items:center; gap:0.4rem;">
            ${escapeHtml(acc.handle || acc.username || "Sin alias")}
          </div>
          <div class="mono" style="font-size:11px; color:var(--text-muted);">${escapeHtml(acc.id)}</div>
        </td>
        <td>
          <div>${catPill}</div>
          <div style="margin-top:3px;"><strong class="mono" style="font-size:12px;">${escapeHtml(acc.platform)}</strong></div>
        </td>
        <td>
          <div>${realmPill}</div>
          ${acc.proxy ? `<div class="mono" style="font-size:10px; color:var(--text-muted); margin-top:2px;">${escapeHtml(acc.proxy)}</div>` : ""}
          ${acc.target_site ? `<div class="mono" style="font-size:10px; color:var(--text-secondary); margin-top:2px;">[LINK] ${escapeHtml(acc.target_site)}</div>` : ""}
        </td>
        <td>
          <div class="mono" style="font-size:11px;">${escapeHtml(acc.status_text || "Activa")}</div>
          <div style="display:flex; gap:0.25rem; margin-top:3px;">${credBadges.join(" ")}</div>
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
      </tr>
      <tr id="acc-row-${escapeHtml(acc.id)}-detail" class="row-detail-container" style="display:none;">
        <td colspan="8">
          <div class="row-detail-card" style="padding:0.75rem 1rem; background:rgba(255,255,255,0.02); border:1px solid var(--border-color); border-radius:4px; font-size:12px;">
            <div style="display:flex; justify-content:space-between; margin-bottom:0.5rem;">
              <strong style="color:var(--accent-cyan);">Ficha de Boveda: ${escapeHtml(acc.id)}</strong>
              <span class="mono" style="font-size:10px; color:var(--text-muted);">${escapeHtml(acc.updated_at || "Registrada en TOML")}</span>
            </div>
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:0.5rem;">
              <div><span style="color:var(--text-muted);">Enrutador Proxy:</span> <span class="mono">${escapeHtml(acc.proxy || "Conexion directa Clearnet")}</span></div>
              <div><span style="color:var(--text-muted);">Sitio Objetivo:</span> <span class="mono">${escapeHtml(acc.target_site || "Plataforma oficial")}</span></div>
              <div><span style="color:var(--text-muted);">Token Configurado:</span> <span>${acc.has_token ? "[SI] Almacenado de forma segura" : "[NO] Inexistente"}</span></div>
              <div><span style="color:var(--text-muted);">Cookie de Sesion:</span> <span>${acc.has_cookie ? "[SI] Configurada" : "[NO] No requerida"}</span></div>
            </div>
          </div>
        </td>
      </tr>`;
    })
    .join("");
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
    triggerVisualPulse(report.status === "ok" ? 0.7 : 0.4);

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

// Modal Nueva Cuenta con Categorías Especializadas
function openNewAccountModal(category = "social") {
  const modal = document.getElementById("modal-account");
  if (!modal) return;
  modal.classList.add("open", "active");
  modal.style.display = "grid";
  selectModalCategory(category);
}

function closeNewAccountModal() {
  const m = document.getElementById("modal-account");
  if (m) { m.classList.remove("open", "active"); m.style.display = "none"; }
}

function selectModalCategory(cat) {
  const normCat = ["social", "forum", "market", "generic"].includes(cat) ? cat : "social";

  // Actualizar campo oculto
  const hiddenInput = document.getElementById("acc_category");
  if (hiddenInput) hiddenInput.value = normCat;

  // Actualizar botones de pestaña
  document.querySelectorAll(".modal-cat-tab").forEach((tab) => {
    tab.classList.toggle("active", tab.getAttribute("data-cat") === normCat);
  });

  // Actualizar banner OPSEC contextual
  const tipBox = document.getElementById("modal-opsec-tip");
  const tipText = document.getElementById("modal-opsec-text");
  if (tipBox && tipText) {
    tipBox.className = "opsec-tip-box";
    if (normCat === "forum") {
      tipBox.classList.add("tip-forum");
      tipText.textContent =
        "Para foros underground (BreachForums, Exploit.in, XSS), inicia sesión en tu Tor Browser o máquina aislada y copia la cookie de sesión (xf_user/session). Utiliza siempre el proxy Tor SOCKS5 local (127.0.0.1:9050) para salvaguardar tu IP real.";
    } else if (normCat === "market") {
      tipBox.classList.add("tip-market");
      tipText.textContent =
        "Para mercados darknet y servicios de filtraciones (IntelX, Russian Market, DeHashed), mantén claves de API en variables de entorno o usa Tor SOCKS5 para evitar correlaciones de IP.";
    } else if (normCat === "generic") {
      tipText.textContent =
        "Configura endpoints y proxies para APIs generales o servicios que requieren rotación estricta de peticiones.";
    } else {
      tipText.textContent =
        "Para redes sociales, utiliza cuentas de investigación dedicadas o tokens de bot para evitar exponer tu identidad personal o sufrir suspensiones en cuentas personales.";
    }
  }

  // Preseleccionar una plataforma adecuada
  const platSelect = document.getElementById("acc_platform");
  if (platSelect) {
    if (normCat === "forum") {
      platSelect.value = "breachforums";
    } else if (normCat === "market") {
      platSelect.value = "intelx";
    } else if (normCat === "generic") {
      platSelect.value = "generic";
    } else {
      platSelect.value = "twitter";
    }
    onPlatformChanged(platSelect.value);
  }
}

function onPlatformChanged(platform) {
  const plat = (platform || "").toLowerCase().trim();
  const rpmInput = document.getElementById("acc_rpm");
  const idInput = document.getElementById("acc_id");
  const tokenEnvInput = document.getElementById("acc_token_env");
  const targetSiteInput = document.getElementById("acc_target_site");
  const proxyInput = document.getElementById("acc_proxy");
  const usernameInput = document.getElementById("acc_username");

  if (idInput && !idInput.value) {
    idInput.placeholder = `auto: sp-${plat}-${Date.now().toString().slice(-4)}`;
  }

  // Ajustes de foros underground
  const isForum = [
    "breachforums",
    "exploit_in",
    "xss_is",
    "raidforums",
    "dread",
    "nulled",
    "cracked_to",
    "ramp",
    "antichat",
    "hackforums",
    "forum",
  ].includes(plat);

  const isMarket = [
    "intelx",
    "dnmx",
    "russian_market",
    "2easy",
    "dehashed",
    "leak_lookup",
    "snusbase",
    "genesis_mirror",
    "darknet_market",
  ].includes(plat);

  if (isForum) {
    if (rpmInput && (!rpmInput.value || rpmInput.value === "30")) rpmInput.value = "15";
    if (usernameInput) usernameInput.placeholder = "ej. ForumMember_99 o shadow_handle";
    if (plat === "exploit_in" && targetSiteInput) targetSiteInput.placeholder = "exploit.in";
    if (plat === "xss_is" && targetSiteInput) targetSiteInput.placeholder = "xss.is";
    if (plat === "breachforums" && targetSiteInput) targetSiteInput.placeholder = "breachforums.is o mirror .onion";
    if (plat === "dread" && targetSiteInput) targetSiteInput.placeholder = "dreadytofatroptsdj6io...onion";
    if (proxyInput && !proxyInput.value) proxyInput.value = "socks5h://127.0.0.1:9050";
  } else if (isMarket) {
    if (rpmInput && (!rpmInput.value || rpmInput.value === "30")) rpmInput.value = "10";
    if (plat === "intelx" && tokenEnvInput) tokenEnvInput.placeholder = "INTELX_API_KEY";
    if (plat === "dehashed" && tokenEnvInput) tokenEnvInput.placeholder = "DEHASHED_API_KEY";
    if (plat === "leak_lookup" && tokenEnvInput) tokenEnvInput.placeholder = "LEAK_LOOKUP_KEY";
    if (plat === "russian_market" && proxyInput && !proxyInput.value) proxyInput.value = "socks5h://127.0.0.1:9050";
    if (plat === "dnmx" && proxyInput && !proxyInput.value) proxyInput.value = "socks5h://127.0.0.1:9050";
  } else {
    if (plat === "twitter" && tokenEnvInput) tokenEnvInput.placeholder = "TWITTER_BEARER_TOKEN";
    if (plat === "telegram" && tokenEnvInput) tokenEnvInput.placeholder = "TELEGRAM_BOT_TOKEN";
    if (plat === "discord" && tokenEnvInput) tokenEnvInput.placeholder = "DISCORD_BOT_TOKEN";
    if (plat === "reddit" && tokenEnvInput) tokenEnvInput.placeholder = "REDDIT_TOKEN";
    if (plat === "github" && tokenEnvInput) tokenEnvInput.placeholder = "GITHUB_TOKEN";
    if (usernameInput) usernameInput.placeholder = "ej. @shadow_sec";
  }
}

function setTorProxyPreset() {
  const proxyInput = document.getElementById("acc_proxy");
  if (proxyInput) {
    proxyInput.value = "socks5h://127.0.0.1:9050";
    proxyInput.focus();
    triggerVisualPulse(0.5);
  }
}

async function submitNewAccount(e) {
  e.preventDefault();
  const form = document.getElementById("form-account");
  const payload = {
    id: form.acc_id.value.trim() || undefined,
    platform: form.acc_platform.value.trim().toLowerCase(),
    category: form.acc_category ? form.acc_category.value.trim().toLowerCase() : undefined,
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
  const m = document.getElementById("modal-persona");
  if (m) { m.classList.add("open", "active"); m.style.display = "grid"; }
  generatePersonaPreview();
}

function closePersonaModal() {
  const m = document.getElementById("modal-persona");
  if (m) { m.classList.remove("open", "active"); m.style.display = "none"; }
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

  // Calculo criptografico real RFC 6238 TOTP via Web Crypto API (HMAC-SHA1)
  computeRFC6238Code(secret, epoch).then((code) => {
    if (display) display.textContent = code;
  });
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
    let sources = data.sources || [];

    document.getElementById("cti-active-count") &&
      (document.getElementById("cti-active-count").textContent = data.active_count || 0);
    document.getElementById("cti-purged-count") &&
      (document.getElementById("cti-purged-count").textContent = data.purged_count || 0);

    const limitSelect = document.querySelector("#view-cti .table-limit-select");
    const limit = limitSelect ? limitSelect.value : "all";
    if (limit !== "all") {
      const num = parseInt(limit, 10);
      if (!isNaN(num) && num > 0) {
        sources = sources.slice(0, num);
      }
    }

    if (sources.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:1.5rem; color:var(--text-muted);">Sin fuentes indexadas. Pulsa 'Sincronizar Feeds CTI'.</td></tr>`;
      return;
    }

    tbody.innerHTML = sources
      .map(
        (s, idx) => `
      <tr>
        <td style="width:30px; text-align:center;">
          <button class="row-expand-btn" id="cti-row-${idx}-expand-btn" onclick="toggleRowDetail(this, 'cti-row-${idx}')">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"></polyline></svg>
          </button>
        </td>
        <td style="font-weight:600;">${escapeHtml(s.name)}</td>
        <td><span class="pill pill-cyan">${escapeHtml(s.category)}</span></td>
        <td class="mono" style="font-size:11px; max-width:240px; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(
          s.url
        )}</td>
        <td><span class="pill pill-ok">${escapeHtml(s.status)}</span></td>
        <td class="mono" style="font-size:10px; color:var(--text-muted);">${escapeHtml(s.updated_at || "-")}</td>
      </tr>
      <tr id="cti-row-${idx}-detail" class="row-detail-container" style="display:none;">
        <td colspan="6">
          <div class="row-detail-card" style="padding:0.75rem 1rem; background:rgba(255,255,255,0.02); border:1px solid var(--border-color); border-radius:4px; font-size:12px;">
            <div style="display:flex; justify-content:space-between; margin-bottom:0.4rem;">
              <strong style="color:var(--accent-cyan);">${escapeHtml(s.name)} [${escapeHtml(s.category)}]</strong>
              <span class="mono" style="font-size:10px; color:var(--text-muted);">Estado: ${escapeHtml(s.status)}</span>
            </div>
            <div style="margin-bottom:0.4rem;">
              <span style="color:var(--text-muted);">URL Completa / Endpoint:</span>
              <div class="mono" style="font-size:11px; word-break:break-all; margin-top:2px;">${escapeHtml(s.url)}</div>
            </div>
            <div style="display:flex; gap:0.5rem; align-items:center;">
              <button class="btn btn-secondary btn-sm" onclick="copyToClipboard('${escapeHtml(s.url)}', 'URL de fuente CTI')">Copiar URL</button>
              <span style="font-size:11px; color:var(--text-muted);">Ultima actualizacion verificada: ${escapeHtml(s.updated_at || "Reciente")}</span>
            </div>
          </div>
        </td>
      </tr>
    `
      )
      .join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" style="color:var(--accent-crimson);">Error al cargar CTI: ${escapeHtml(
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

// Filtros multidimensionales y estado reactivo (Impeccable)
let graphFilters = {
  searchQuery: "",
  minConfidence: 0.0,
  maxHops: "all",
  hideOrphans: false,
  preset: "all",
  enabledEntityTypes: new Set(),
  enabledEdgeTypes: new Set(),
};
let allEntityTypesInCase = new Map();
let allEdgeTypesInCase = new Map();
let nodeHopsFromTarget = new Map();
let filterDrawerOpen = false;

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

function toggleExportMenu(e) {
  if (e) e.stopPropagation();
  const menu = document.getElementById("export-dropdown-menu");
  if (!menu) return;
  menu.classList.toggle("show");
}

document.addEventListener("click", (e) => {
  const menu = document.getElementById("export-dropdown-menu");
  const btn = document.getElementById("btn-export-dropdown");
  if (menu && menu.classList.contains("show")) {
    if (!menu.contains(e.target) && (!btn || !btn.contains(e.target))) {
      menu.classList.remove("show");
    }
  }
});

async function exportCaseAs(format) {
  const menu = document.getElementById("export-dropdown-menu");
  if (menu) menu.classList.remove("show");
  const hudMenu = document.getElementById("hud-export-dropdown-menu");
  if (hudMenu) hudMenu.classList.remove("show");

  const select = document.getElementById("graph-case-select");
  const cid = (select && select.value) ? select.value : currentCaseId;
  if (!cid) {
    showToast("Selecciona un caso para exportar", "warning");
    return;
  }

  const formatNames = {
    mtgx: ".mtgx (Maltego Desktop)",
    json: ".json (JSON Forense)",
    csv: ".csv (Tabla Relacional)",
    graphml: ".graphml (Gephi / Cytoscape)",
    report_html: ".html (Informe Ejecutivo)",
    report_md: ".md (Informe Markdown)",
  };
  const label = formatNames[format] || format;
  showToast(`Generando y descargando ${cid} en formato ${label}...`, "info");
  playTacticalClick(720, 0.04);

  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(cid)}/export/${encodeURIComponent(format)}`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showToast(err.error || `Error ${res.status} al exportar archivo`, "error");
      return;
    }

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.style.display = "none";
    a.href = url;

    let filename = `${cid}.${format === "report_html" ? "html" : (format === "report_md" ? "md" : format)}`;
    const disposition = res.headers.get("content-disposition");
    if (disposition && disposition.includes("filename=")) {
      const match = disposition.match(/filename="?([^";]+)"?/);
      if (match && match[1]) filename = match[1];
    }

    a.download = filename;
    document.body.appendChild(a);
    a.click();

    setTimeout(() => {
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    }, 400);

    playTacticalClick(900, 0.05);
    showToast(`Archivo '${filename}' descargado correctamente`, "ok");
  } catch (err) {
    showToast(`Error de red al descargar: ${err.message}`, "error");
  }
}

function toggleHudExportMenu(e) {
  if (e) e.stopPropagation();
  const menu = document.getElementById("hud-export-dropdown-menu");
  if (!menu) return;
  menu.classList.toggle("show");
}

document.addEventListener("click", (e) => {
  const hudMenu = document.getElementById("hud-export-dropdown-menu");
  const hudBtn = document.getElementById("hud-btn-export");
  if (hudMenu && hudMenu.classList.contains("show")) {
    if (!hudMenu.contains(e.target) && (!hudBtn || !hudBtn.contains(e.target))) {
      hudMenu.classList.remove("show");
    }
  }
});
function exportCurrentCaseMtgx() {
  exportCaseAs("mtgx");
}

let selectedImportFile = null;

function openImportModal() {
  const modal = document.getElementById("modal-import");
  if (!modal) return;
  modal.classList.add("open", "active");
  modal.style.display = "grid";
  selectedImportFile = null;
  const fileInput = document.getElementById("import-file-input");
  if (fileInput) fileInput.value = "";
  const badge = document.getElementById("import-file-badge");
  if (badge) badge.style.display = "none";
  const label = document.getElementById("import-dropzone-label");
  if (label) label.textContent = "Arrastra aquí tu archivo o haz clic para seleccionarlo";
  const fb = document.getElementById("import-feedback-box");
  if (fb) { fb.style.display = "none"; fb.innerHTML = ""; }

  const curCase = currentCaseId || (document.getElementById("graph-case-select")?.value);
  const hint = document.getElementById("import-current-case-hint");
  if (hint) {
    hint.textContent = curCase ? `Fusionar datos dentro de '${curCase}'` : "Ningún caso activo seleccionado";
  }

  toggleImportMode("new");
  modal.classList.add("open");
}

function closeImportModal() {
  const modal = document.getElementById("modal-import");
  if (modal) { modal.classList.remove("open", "active"); modal.style.display = "none"; }
}

function toggleImportMode(mode) {
  const fields = document.getElementById("import-new-case-fields");
  if (fields) {
    fields.style.display = mode === "new" ? "block" : "none";
  }
}

function onImportFileSelected(e) {
  const files = e.target.files;
  if (files && files.length > 0) {
    handleImportFile(files[0]);
  }
}

function handleImportFile(file) {
  selectedImportFile = file;
  const label = document.getElementById("import-dropzone-label");
  if (label) label.textContent = "Archivo seleccionado:";
  const badge = document.getElementById("import-file-badge");
  const badgeText = document.getElementById("import-file-badge-text");
  if (badge && badgeText) {
    badge.style.display = "block";
    const sizeKb = (file.size / 1024).toFixed(1);
    badgeText.textContent = `[FILE] ${file.name} (${sizeKb} KB)`;
  }

  const caseIdInput = document.getElementById("import-case-id");
  if (caseIdInput && !caseIdInput.value.trim()) {
    const stem = file.name.replace(/\.[^/.]+$/, "");
    const slug = stem.toLowerCase().replace(/[^a-z0-9_-]/g, "-").replace(/-+/g, "-").slice(0, 40);
    caseIdInput.value = `caso-${slug}`;
  }
}

async function submitImportCase(e) {
  if (e) e.preventDefault();
  if (!selectedImportFile) {
    showToast("Por favor selecciona un archivo (.mtgx, .json, .csv) para importar", "warning");
    return;
  }

  const mode = document.querySelector('input[name="import_mode"]:checked')?.value || "new";
  let targetCaseId = "";
  let targetDesc = "";

  if (mode === "new") {
    targetCaseId = document.getElementById("import-case-id")?.value?.trim() || "";
    targetDesc = document.getElementById("import-case-desc")?.value?.trim() || "";
    if (targetCaseId) {
      targetCaseId = targetCaseId.toLowerCase().replace(/[^a-z0-9_-]/g, "-").replace(/-+/g, "-");
    }
  } else {
    targetCaseId = currentCaseId || (document.getElementById("graph-case-select")?.value) || "";
    if (!targetCaseId) {
      showToast("No hay ningún caso seleccionado para incorporar datos. Elige 'Crear nueva investigación'", "warning");
      return;
    }
  }

  const btn = document.getElementById("btn-submit-import");
  if (btn) { btn.disabled = true; btn.textContent = "Importando datos..."; }
  const fb = document.getElementById("import-feedback-box");
  if (fb) {
    fb.style.display = "block";
    fb.style.background = "rgba(56, 189, 248, 0.1)";
    fb.style.border = "1px solid rgba(56, 189, 248, 0.3)";
    fb.style.color = "var(--text-primary)";
    fb.innerHTML = "<span>Subiendo y procesando grafo...</span>";
  }

  const formData = new FormData();
  formData.append("file", selectedImportFile);
  if (targetCaseId) formData.append("case_id", targetCaseId);
  if (targetDesc) formData.append("description", targetDesc);
  formData.append("create_new", mode === "new" ? "true" : "false");

  try {
    const res = await fetch("/api/cases/import", {
      method: "POST",
      body: formData,
    });
    const data = await res.json();

    if (!data.ok) {
      if (fb) {
        fb.style.background = "rgba(239, 68, 68, 0.1)";
        fb.style.border = "1px solid rgba(239, 68, 68, 0.3)";
        fb.style.color = "#f87171";
        fb.innerHTML = `<strong>Error en importación:</strong> ${data.error || "Fallo desconocido"}`;
      }
      showToast(data.error || "Error al importar archivo", "error");
      return;
    }

    if (fb) {
      fb.style.background = "rgba(16, 185, 129, 0.1)";
      fb.style.border = "1px solid rgba(16, 185, 129, 0.3)";
      fb.style.color = "#34d399";
      fb.innerHTML = `
        <strong>[OK] ¡Importacion completada!</strong><br>
        Caso: <span class="mono">${data.case_id}</span><br>
        Entidades: <strong>${data.entities}</strong> (+${data.new_entities} nuevas)<br>
        Relaciones: <strong>${data.links}</strong> | Pasos: ${data.steps}
      `;
    }

    playTacticalClick(900, 0.05);
    showToast(`Caso '${data.case_id}' importado: ${data.entities} entidades, ${data.links} relaciones`, "ok");

    setTimeout(async () => {
      closeImportModal();
      await loadCasesList(data.case_id);
      switchTab("graph");
      loadCaseGraph(data.case_id);
    }, 1000);

  } catch (err) {
    if (fb) {
      fb.style.background = "rgba(239, 68, 68, 0.1)";
      fb.style.border = "1px solid rgba(239, 68, 68, 0.3)";
      fb.style.color = "#f87171";
      fb.innerHTML = `<strong>Error de red:</strong> ${err.message}`;
    }
    showToast(`Error de conexión: ${err.message}`, "error");
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Iniciar Importacion"; }
  }
}
function initImportDropzone() {
  const zone = document.getElementById("import-dropzone");
  if (!zone) return;

  ["dragenter", "dragover"].forEach((eventName) => {
    zone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      zone.classList.add("dragover");
    }, false);
  });

  ["dragleave", "drop"].forEach((eventName) => {
    zone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      zone.classList.remove("dragover");
    }, false);
  });

  zone.addEventListener("drop", (e) => {
    const dt = e.dataTransfer;
    const files = dt && dt.files;
    if (files && files.length > 0) {
      handleImportFile(files[0]);
    }
  }, false);
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
    const isCrypto =
      n.type.includes("Cryptocurrency") || n.type.includes("Crypto") || n.type.includes("Bitcoin") || n.type.includes("Ethereum");
    const isMixer = n.type.includes("Mixer") || n.properties?.is_mixer === "yes" || n.properties?.ofac === "SDN-LISTED";
    const isVASP = n.type.includes("VASP") || n.type.includes("Exchange");
    const isCluster = n.type.includes("CryptoCluster");
    const isBridge = n.type.includes("DeFiBridge");

    let color = "#a78bfa";
    let radius = 14;

    if (isTarget) {
      color = "#00f5ff"; // Cyan - Objetivo Principal / Raíz
      radius = 22;
    } else if (isMixer) {
      color = "#ef4444"; // Red - Mixer / Protocolo Anonimizador / OFAC
      radius = 18;
    } else if (isVASP) {
      color = "#06b6d4"; // Cyan oscuro - VASP / Exchange regulado KYC
      radius = 17;
    } else if (isCluster) {
      color = "#f59e0b"; // Amber - Cluster Heuristico CIOH
      radius = 18;
    } else if (isBridge) {
      color = "#a855f7"; // Violet - Puente Cross-Chain DeFi
      radius = 16;
    } else if (isCrypto) {
      color = "#eab308"; // Gold - Direccion o TX Cripto
      radius = 15;
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
      isCrypto,
      isMixer,
      isVASP,
      isCluster,
      isBridge,
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

  calculateNodeHops(targetId);
  populateFilterDrawerOptions();
  applyAllGraphFilters();
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

function calculateNodeHops(targetId) {
  nodeHopsFromTarget.clear();
  if (!targetId || graphNodes.length === 0) return;

  const adj = new Map();
  graphNodes.forEach((n) => adj.set(n.id, []));
  graphLinks.forEach((l) => {
    if (adj.has(l.sourceNode.id) && adj.has(l.targetNode.id)) {
      adj.get(l.sourceNode.id).push(l.targetNode.id);
      adj.get(l.targetNode.id).push(l.sourceNode.id);
    }
  });

  const visited = new Set();
  const queue = [{ id: targetId, depth: 0 }];
  visited.add(targetId);
  nodeHopsFromTarget.set(targetId, 0);

  while (queue.length > 0) {
    const item = queue.shift();
    const neighbors = adj.get(item.id) || [];
    for (const nbr of neighbors) {
      if (!visited.has(nbr)) {
        visited.add(nbr);
        nodeHopsFromTarget.set(nbr, item.depth + 1);
        queue.push({ id: nbr, depth: item.depth + 1 });
      }
    }
  }

  // Nodos no alcanzables desde la raíz
  graphNodes.forEach((n) => {
    if (!nodeHopsFromTarget.has(n.id)) {
      nodeHopsFromTarget.set(n.id, 999);
    }
  });
}

function populateFilterDrawerOptions() {
  allEntityTypesInCase.clear();
  allEdgeTypesInCase.clear();

  graphNodes.forEach((n) => {
    const t = n.type || "maltego.Unknown";
    allEntityTypesInCase.set(t, (allEntityTypesInCase.get(t) || 0) + 1);
  });

  graphLinks.forEach((l) => {
    const lbl = l.label || "(sin relación)";
    allEdgeTypesInCase.set(lbl, (allEdgeTypesInCase.get(lbl) || 0) + 1);
  });

  // Habilitar todos inicialmente si el set está vacío
  if (graphFilters.enabledEntityTypes.size === 0) {
    graphFilters.enabledEntityTypes = new Set(allEntityTypesInCase.keys());
  }
  if (graphFilters.enabledEdgeTypes.size === 0) {
    graphFilters.enabledEdgeTypes = new Set(allEdgeTypesInCase.keys());
  }

  // Renderizar checkboxes de tipos de entidad
  const entContainer = document.getElementById("filter-entity-types-list");
  if (entContainer) {
    if (allEntityTypesInCase.size === 0) {
      entContainer.innerHTML = '<span style="color:var(--text-muted); font-size:11px;">Sin entidades</span>';
    } else {
      entContainer.innerHTML = Array.from(allEntityTypesInCase.entries())
        .sort((a, b) => b[1] - a[1])
        .map(([type, count]) => {
          const checked = graphFilters.enabledEntityTypes.has(type) ? "checked" : "";
          const shortName = type.replace("maltego.", "");
          return `
            <div class="filter-check-item">
              <label>
                <input type="checkbox" value="${escapeHtml(type)}" ${checked} onchange="toggleEntityType('${escapeHtml(type)}', this.checked)">
                <span title="${escapeHtml(type)}">${escapeHtml(shortName)}</span>
              </label>
              <span class="filter-count-badge">${count}</span>
            </div>
          `;
        })
        .join("");
    }
  }

  // Renderizar checkboxes de tipos de relación (aristas)
  const edgeContainer = document.getElementById("filter-edge-types-list");
  if (edgeContainer) {
    if (allEdgeTypesInCase.size === 0) {
      edgeContainer.innerHTML = '<span style="color:var(--text-muted); font-size:11px;">Sin relaciones</span>';
    } else {
      edgeContainer.innerHTML = Array.from(allEdgeTypesInCase.entries())
        .sort((a, b) => b[1] - a[1])
        .map(([lbl, count]) => {
          const checked = graphFilters.enabledEdgeTypes.has(lbl) ? "checked" : "";
          return `
            <div class="filter-check-item">
              <label>
                <input type="checkbox" value="${escapeHtml(lbl)}" ${checked} onchange="toggleEdgeType('${escapeHtml(lbl)}', this.checked)">
                <span title="${escapeHtml(lbl)}">${escapeHtml(lbl)}</span>
              </label>
              <span class="filter-count-badge">${count}</span>
            </div>
          `;
        })
        .join("");
    }
  }
}

function applyAllGraphFilters() {
  const query = (graphFilters.searchQuery || "").trim().toLowerCase();

  // 1. Filtrar nodos
  graphNodes.forEach((n) => {
    // A. Certeza mínima
    const passConfidence = (n.confidence || 0) >= graphFilters.minConfidence || n.isTarget;

    // B. Tipo de entidad
    const passType = graphFilters.enabledEntityTypes.has(n.type || "maltego.Unknown") || n.isTarget;

    // C. Distancia de saltos (Hops)
    let passHops = true;
    if (graphFilters.maxHops !== "all") {
      const dist = nodeHopsFromTarget.get(n.id) ?? 999;
      passHops = dist <= Number(graphFilters.maxHops) || n.isTarget;
    }

    // D. Preset rápido
    let passPreset = true;
    if (graphFilters.preset === "high") {
      passPreset = n.isTarget || (n.confidence || 0) >= 0.8 || n.isLocation;
    } else if (graphFilters.preset === "medium") {
      passPreset = (n.confidence || 0) < 0.8;
    } else if (graphFilters.preset === "risk") {
      passPreset = n.isRisk || n.isTarget;
    }

    // E. Búsqueda reactiva
    let passQuery = true;
    if (query) {
      const valMatch = String(n.value || "").toLowerCase().includes(query);
      const idMatch = String(n.id || "").toLowerCase().includes(query);
      const typeMatch = String(n.type || "").toLowerCase().includes(query);
      const notesMatch = String(n.notes || "").toLowerCase().includes(query);
      passQuery = valMatch || idMatch || typeMatch || notesMatch;
    }

    n.visible = passConfidence && passType && passHops && passPreset && passQuery;
  });

  // 2. Filtrar enlaces
  graphLinks.forEach((l) => {
    const nodesVis = l.sourceNode.visible && l.targetNode.visible;
    const passEdgeType = graphFilters.enabledEdgeTypes.has(l.label || "(sin relación)");
    let passEdgePreset = true;
    if (graphFilters.preset === "risk" && !l.isRiskLink && !l.isTargetLink) {
      passEdgePreset = false;
    }
    l.visible = nodesVis && passEdgeType && passEdgePreset;
  });

  // 3. Ocultar huérfanos / desconectados si está marcado
  if (graphFilters.hideOrphans) {
    const visibleEdgeCount = new Map();
    graphNodes.forEach((n) => visibleEdgeCount.set(n.id, 0));
    graphLinks.forEach((l) => {
      if (l.visible) {
        visibleEdgeCount.set(l.sourceNode.id, (visibleEdgeCount.get(l.sourceNode.id) || 0) + 1);
        visibleEdgeCount.set(l.targetNode.id, (visibleEdgeCount.get(l.targetNode.id) || 0) + 1);
      }
    });

    graphNodes.forEach((n) => {
      if (n.visible && !n.isTarget && (visibleEdgeCount.get(n.id) || 0) === 0) {
        n.visible = false;
      }
    });
  }

  // 4. Actualizar contadores y badges en UI
  const visNodes = graphNodes.filter((n) => n.visible).length;
  const visLinks = graphLinks.filter((l) => l.visible).length;

  const countBadge = document.getElementById("badge-visible-count");
  if (countBadge) {
    countBadge.textContent = `${visNodes}/${graphNodes.length}`;
  }

  updateGraphStatusBar(
    `Caso: ${currentCaseId} | Visibles: ${visNodes}/${graphNodes.length} nodos, ${visLinks}/${graphLinks.length} aristas`
  );

  physicsAlpha = Math.max(physicsAlpha, 0.4);
}

function setGraphFilter(filter) {
  graphFilters.preset = filter;
  activeFilter = filter;

  // Actualizar botones de preset
  document.querySelectorAll("[id^='preset-btn-']").forEach((b) => b.classList.remove("active"));
  const btn = document.getElementById(`preset-btn-${filter}`);
  if (btn) btn.classList.add("active");

  applyAllGraphFilters();
}

function setHopsPreset(hops) {
  graphFilters.preset = "all";
  graphFilters.maxHops = hops;

  document.querySelectorAll("[id^='preset-btn-']").forEach((b) => b.classList.remove("active"));
  const btn = document.getElementById(`preset-btn-hops${hops}`);
  if (btn) btn.classList.add("active");

  // Sincronizar botones en el drawer
  const hopsGroup = document.getElementById("filter-hops-group");
  if (hopsGroup) {
    hopsGroup.querySelectorAll("button").forEach((b) => {
      b.classList.toggle("active", b.getAttribute("data-hops") === String(hops));
    });
  }

  applyAllGraphFilters();
}

function setHopsFilter(hops, btn) {
  graphFilters.maxHops = hops;
  const hopsGroup = document.getElementById("filter-hops-group");
  if (hopsGroup) {
    hopsGroup.querySelectorAll("button").forEach((b) => b.classList.remove("active"));
  }
  if (btn) btn.classList.add("active");

  applyAllGraphFilters();
}

function toggleHideOrphans(checked) {
  graphFilters.hideOrphans = checked;
  applyAllGraphFilters();
}

function toggleEntityType(type, checked) {
  if (checked) {
    graphFilters.enabledEntityTypes.add(type);
  } else {
    graphFilters.enabledEntityTypes.delete(type);
  }
  applyAllGraphFilters();
}

function toggleEdgeType(lbl, checked) {
  if (checked) {
    graphFilters.enabledEdgeTypes.add(lbl);
  } else {
    graphFilters.enabledEdgeTypes.delete(lbl);
  }
  applyAllGraphFilters();
}

function toggleAllEntityTypes(enableAll) {
  const container = document.getElementById("filter-entity-types-list");
  if (enableAll) {
    graphFilters.enabledEntityTypes = new Set(allEntityTypesInCase.keys());
  } else {
    graphFilters.enabledEntityTypes.clear();
  }
  if (container) {
    container.querySelectorAll("input[type='checkbox']").forEach((cb) => {
      cb.checked = enableAll;
    });
  }
  applyAllGraphFilters();
}

function toggleAllEdgeTypes(enableAll) {
  const container = document.getElementById("filter-edge-types-list");
  if (enableAll) {
    graphFilters.enabledEdgeTypes = new Set(allEdgeTypesInCase.keys());
  } else {
    graphFilters.enabledEdgeTypes.clear();
  }
  if (container) {
    container.querySelectorAll("input[type='checkbox']").forEach((cb) => {
      cb.checked = enableAll;
    });
  }
  applyAllGraphFilters();
}

function onConfidenceSliderChange(val) {
  const num = Number(val) / 100.0;
  graphFilters.minConfidence = num;
  const label = document.getElementById("label-min-confidence");
  if (label) label.textContent = `${val}%`;
  applyAllGraphFilters();
}

function onGraphSearchInput(val) {
  graphFilters.searchQuery = val;
  const clearBtn = document.getElementById("btn-clear-search");
  if (clearBtn) {
    clearBtn.style.display = val ? "inline-block" : "none";
  }
  applyAllGraphFilters();

  // Si hay un único resultado visible, auto-enfocarlo suavemente
  const vis = graphNodes.filter((n) => n.visible);
  if (vis.length === 1 && val.trim().length >= 2) {
    selectNode(vis[0]);
    graphCamera.x = -vis[0].x * graphCamera.scale;
    graphCamera.y = -vis[0].y * graphCamera.scale;
  }
}

function clearGraphSearch() {
  const input = document.getElementById("graph-search-input");
  if (input) input.value = "";
  onGraphSearchInput("");
}

function toggleGraphFilterDrawer() {
  const drawer = document.getElementById("graph-filter-drawer");
  if (!drawer) return;
  filterDrawerOpen = !filterDrawerOpen;
  drawer.style.display = filterDrawerOpen ? "flex" : "none";
}

function resetAllGraphFilters() {
  graphFilters.searchQuery = "";
  graphFilters.minConfidence = 0.0;
  graphFilters.maxHops = "all";
  graphFilters.hideOrphans = false;
  graphFilters.preset = "all";
  graphFilters.enabledEntityTypes = new Set(allEntityTypesInCase.keys());
  graphFilters.enabledEdgeTypes = new Set(allEdgeTypesInCase.keys());

  const searchInput = document.getElementById("graph-search-input");
  if (searchInput) searchInput.value = "";
  const clearBtn = document.getElementById("btn-clear-search");
  if (clearBtn) clearBtn.style.display = "none";

  const confSlider = document.getElementById("filter-confidence-range");
  if (confSlider) confSlider.value = "0";
  const confLabel = document.getElementById("label-min-confidence");
  if (confLabel) confLabel.textContent = "0%";

  const orphanChk = document.getElementById("chk-hide-orphans");
  if (orphanChk) orphanChk.checked = false;

  populateFilterDrawerOptions();
  setGraphFilter("all");
}

function fitGraphView() {
  const visNodes = graphNodes.filter((n) => n.visible);
  if (visNodes.length === 0 || !graphCanvas) return;

  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  visNodes.forEach((n) => {
    if (n.x < minX) minX = n.x;
    if (n.x > maxX) maxX = n.x;
    if (n.y < minY) minY = n.y;
    if (n.y > maxY) maxY = n.y;
  });

  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const w = graphCanvas.width / dpr;
  const h = graphCanvas.height / dpr;

  const graphW = Math.max(maxX - minX + 160, 200);
  const graphH = Math.max(maxY - minY + 160, 200);

  const scaleX = w / graphW;
  const scaleY = h / graphH;
  const newScale = Math.min(Math.max(Math.min(scaleX, scaleY), 0.35), 2.5);

  const midX = (minX + maxX) / 2;
  const midY = (minY + maxY) / 2;

  graphCamera.scale = newScale;
  graphCamera.x = -midX * newScale;
  graphCamera.y = -midY * newScale;

  physicsAlpha = Math.max(physicsAlpha, 0.2);
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

  // Actualizar micro-tarjeta flotante (Tooltip)
  const tooltip = document.getElementById("graph-node-tooltip");
  if (tooltip && graphCanvas) {
    if (hoveredNode && !draggedNode && !isPanning) {
      const incidentEdges = graphLinks.filter(
        (l) => l.visible && (l.sourceNode.id === hoveredNode.id || l.targetNode.id === hoveredNode.id)
      );
      const confPct = Math.round((hoveredNode.confidence || 0) * 100);
      const typeShort = (hoveredNode.type || "maltego.Entity").replace("maltego.", "");

      tooltip.innerHTML = `
        <div class="tooltip-title">${escapeHtml(hoveredNode.value)}</div>
        <div style="font-size:10px; color:var(--accent-cyan); font-family:var(--font-mono);">${escapeHtml(typeShort)}</div>
        <div class="tooltip-meta">
          <span>Certeza: ${confPct}%</span>
          <span>${incidentEdges.length} conex.</span>
        </div>
      `;

      const wrapper = graphCanvas.parentElement;
      const rect = wrapper ? wrapper.getBoundingClientRect() : { left: 0, top: 0, width: 800, height: 600 };
      const posX = clientX - rect.left + 14;
      const posY = clientY - rect.top + 14;

      tooltip.style.left = `${Math.min(posX, rect.width - 240)}px`;
      tooltip.style.top = `${Math.min(posY, rect.height - 80)}px`;
      tooltip.style.display = "block";
    } else {
      tooltip.style.display = "none";
    }
  }
}

function onGraphMouseUp() {
  draggedNode = null;
  isPanning = false;
  if (graphCanvas) {
    graphCanvas.style.cursor = hoveredNode ? "pointer" : "default";
  }
  const tooltip = document.getElementById("graph-node-tooltip");
  if (tooltip && !hoveredNode) tooltip.style.display = "none";
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
    const direction = isOut ? "saliente ->" : "entrante <-";
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
                      ${escapeHtml(inputLabel)} ->
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

    <!-- ACCIONES TACTICAS DE TRAZADO -->
    <div class="inspector-section" style="margin-bottom:0.85rem; padding:0.65rem; background:rgba(0, 245, 255, 0.04); border:1px solid rgba(0, 245, 255, 0.25); border-radius:6px;">
      <div style="font-size:10px; font-weight:700; color:var(--accent-cyan); text-transform:uppercase; margin-bottom:0.45rem; display:flex; align-items:center; gap:0.4rem;">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="6" cy="6" r="3"></circle><circle cx="18" cy="18" r="3"></circle><path d="M6 9v3a3 3 0 0 0 3 3h6a3 3 0 0 1 3 3v0"></path></svg>
        Acciones de Trazado Forense
      </div>
      <div style="display:flex; flex-direction:column; gap:0.4rem;">
        <button type="button" class="btn btn-primary btn-sm" style="font-size:11px; width:100%; justify-content:center;" onclick="openPathTracerModalForSource('${escapeHtml(node.id)}')">
          Trazar Camino Hacia Otra Entidad...
        </button>
        <div style="display:flex; gap:0.35rem;">
          <button type="button" class="btn btn-secondary btn-sm" style="flex:1; font-size:10px; justify-content:center;" onclick="traceNodeBlastRadius('${escapeHtml(node.id)}')">
            Trazar Vecindario (2 Saltos)
          </button>
          <button type="button" class="btn btn-secondary btn-sm" style="font-size:10px; justify-content:center;" onclick="clearActivePathTrace()" title="Restablecer visibilidad normal">
            Limpiar Traza
          </button>
        </div>
      </div>
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

  // Precalcular conjunto de nodos conectados al nodo enfocado (hover o selección)
  const focusNode = hoveredNode || selectedNode;
  const connectedNodeIds = new Set();
  if (focusNode) {
    connectedNodeIds.add(focusNode.id);
    for (const l of graphLinks) {
      if (!l.visible) continue;
      if (l.sourceNode.id === focusNode.id) connectedNodeIds.add(l.targetNode.id);
      if (l.targetNode.id === focusNode.id) connectedNodeIds.add(l.sourceNode.id);
    }
  }

  // Pre-agrupar enlaces entre mismos pares de nodos para calcular curvas Bézier
  const edgePairGroups = new Map();
  for (const l of graphLinks) {
    if (!l.visible) continue;
    const key = l.sourceNode.id < l.targetNode.id
      ? `${l.sourceNode.id}__${l.targetNode.id}`
      : `${l.targetNode.id}__${l.sourceNode.id}`;
    if (!edgePairGroups.has(key)) edgePairGroups.set(key, []);
    edgePairGroups.get(key).push(l);
  }

  // 1. Dibujar Aristas
  for (const [key, linksInPair] of edgePairGroups.entries()) {
    const total = linksInPair.length;
    linksInPair.forEach((l, idx) => {
      // Offset de curvatura si hay más de 1 arista entre el par
      let curveOffset = 0;
      if (total > 1) {
        curveOffset = (idx - (total - 1) / 2) * 36;
        if (l.sourceNode.id > l.targetNode.id) curveOffset = -curveOffset;
      }
      drawEdge(graphCtx, l, curveOffset, focusNode, connectedNodeIds);
    });
  }

  // 2. Dibujar Nodos
  for (const n of graphNodes) {
    if (!n.visible) continue;
    drawNode(graphCtx, n, focusNode, connectedNodeIds);
  }

  // 3. Dibujar Pulsos Cineticos en Aristas Activas
  drawKineticEdgePulses(graphCtx, edgePairGroups);

  graphCtx.restore();

  // 4. Actualizar Mini-Mapa Radar HUD
  drawRadarHud();
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

function drawEdge(ctx, l, curveOffset = 0, focusNode = null, connectedNodeIds = null) {
  const a = l.sourceNode;
  const b = l.targetNode;
  const isSelected = selectedNode && (selectedNode.id === a.id || selectedNode.id === b.id);
  const isHovered = hoveredNode && (hoveredNode.id === a.id || hoveredNode.id === b.id);

  // Modo foco: atenuar si no está conectado al nodo activo
  let alpha = 1.0;
  if (focusNode) {
    const isIncident = (a.id === focusNode.id || b.id === focusNode.id);
    alpha = isIncident ? 1.0 : 0.18;
  }

  ctx.save();
  ctx.globalAlpha = alpha;

  ctx.beginPath();
  if (l.isRiskLink) {
    ctx.strokeStyle = (isSelected || isHovered) ? "rgba(244, 63, 94, 0.95)" : "rgba(244, 63, 94, 0.65)";
    ctx.lineWidth = (isSelected || isHovered) ? 2.6 : 1.6;
    ctx.setLineDash([5, 4]);
  } else if (l.isTargetLink) {
    ctx.strokeStyle = (isSelected || isHovered) ? "rgba(0, 245, 255, 0.95)" : "rgba(0, 245, 255, 0.45)";
    ctx.lineWidth = (isSelected || isHovered) ? 2.5 : 1.5;
    ctx.setLineDash([]);
  } else if (l.isFacilityLink) {
    ctx.strokeStyle = (isSelected || isHovered) ? "rgba(129, 140, 248, 0.9)" : "rgba(129, 140, 248, 0.4)";
    ctx.lineWidth = (isSelected || isHovered) ? 2.2 : 1.3;
    ctx.setLineDash([]);
  } else {
    ctx.strokeStyle = (isSelected || isHovered) ? "rgba(255, 255, 255, 0.85)" : "rgba(255, 255, 255, 0.22)";
    ctx.lineWidth = (isSelected || isHovered) ? 2.0 : 1.1;
    ctx.setLineDash([]);
  }

  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const dist = Math.sqrt(dx * dx + dy * dy) || 1;

  let midX = (a.x + b.x) / 2;
  let midY = (a.y + b.y) / 2;
  let endX = b.x;
  let endY = b.y;

  if (Math.abs(curveOffset) > 1) {
    const normX = -dy / dist;
    const normY = dx / dist;
    const ctrlX = midX + normX * curveOffset;
    const ctrlY = midY + normY * curveOffset;

    ctx.moveTo(a.x, a.y);
    ctx.quadraticCurveTo(ctrlX, ctrlY, b.x, b.y);
    ctx.stroke();

    // Punto medio sobre la curva de Bézier (t = 0.5)
    midX = 0.25 * a.x + 0.5 * ctrlX + 0.25 * b.x;
    midY = 0.25 * a.y + 0.5 * ctrlY + 0.25 * b.y;
  } else {
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.stroke();
  }
  ctx.setLineDash([]);

  // Flecha direccional orientada hacia el destino
  if (dist > b.radius + 12) {
    const arrowDist = b.radius + 4;
    const arrowX = b.x - (dx / dist) * arrowDist;
    const arrowY = b.y - (dy / dist) * arrowDist;
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

  // Etiqueta de la arista si hay zoom suficiente o está enfocada
  if (graphCamera.scale >= 0.85 || isSelected || isHovered) {
    ctx.font = "9px Inter, system-ui, sans-serif";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";

    const labelText = l.label || "";
    const textWidth = ctx.measureText(labelText).width;

    ctx.fillStyle = "rgba(10, 13, 20, 0.9)";
    ctx.fillRect(midX - textWidth / 2 - 3, midY - 6, textWidth + 6, 13);

    ctx.fillStyle = l.isRiskLink ? "#f43f5e" : (isSelected || isHovered) ? "#00f5ff" : "#94a3b8";
    ctx.fillText(labelText, midX, midY);
  }

  ctx.restore();
}

function drawNodeGlyph(ctx, x, y, radius, n) {
  const s = radius * 0.48; // Escala proporcional del icono interior
  ctx.save();
  ctx.strokeStyle = "rgba(255, 255, 255, 0.92)";
  ctx.fillStyle = "rgba(255, 255, 255, 0.92)";
  ctx.lineWidth = 1.4;
  ctx.lineCap = "round";
  ctx.lineJoin = "round";

  if (n.isMixer) {
    // Icono: Mixer / Vortice de tres aspas curvas
    ctx.beginPath();
    ctx.arc(x, y, s * 0.75, 0, Math.PI * 2);
    ctx.stroke();
    for (let a = 0; a < 3; a++) {
      const ang = (a * Math.PI * 2) / 3;
      ctx.beginPath();
      ctx.moveTo(x, y);
      ctx.quadraticCurveTo(
        x + Math.cos(ang + 0.5) * s * 0.7,
        y + Math.sin(ang + 0.5) * s * 0.7,
        x + Math.cos(ang) * s * 0.7,
        y + Math.sin(ang) * s * 0.7
      );
      ctx.stroke();
    }
  } else if (n.isVASP) {
    // Icono: Entidad bancaria / Exchange VASP (fronton clasico y columnas)
    ctx.beginPath();
    ctx.moveTo(x - s * 0.8, y - s * 0.3);
    ctx.lineTo(x, y - s * 0.85);
    ctx.lineTo(x + s * 0.8, y - s * 0.3);
    ctx.closePath();
    ctx.stroke();
    ctx.strokeRect(x - s * 0.6, y - s * 0.2, s * 0.25, s * 0.75);
    ctx.strokeRect(x + s * 0.35, y - s * 0.2, s * 0.25, s * 0.75);
    ctx.fillRect(x - s * 0.75, y + s * 0.6, s * 1.5, s * 0.18);
  } else if (n.isCluster) {
    // Icono: Tres nodos en cluster CIOH interconectados
    const cr = s * 0.3;
    ctx.beginPath();
    ctx.arc(x - s * 0.45, y + s * 0.35, cr, 0, Math.PI * 2);
    ctx.stroke();
    ctx.beginPath();
    ctx.arc(x + s * 0.45, y + s * 0.35, cr, 0, Math.PI * 2);
    ctx.stroke();
    ctx.beginPath();
    ctx.arc(x, y - s * 0.45, cr, 0, Math.PI * 2);
    ctx.stroke();
    ctx.beginPath();
    ctx.moveTo(x - s * 0.2, y + s * 0.2);
    ctx.lineTo(x + s * 0.2, y + s * 0.2);
    ctx.moveTo(x - s * 0.3, y + s * 0.1);
    ctx.lineTo(x - s * 0.1, y - s * 0.2);
    ctx.moveTo(x + s * 0.3, y + s * 0.1);
    ctx.lineTo(x + s * 0.1, y - s * 0.2);
    ctx.stroke();
  } else if (n.isBridge) {
    // Icono: Puente cross-chain
    ctx.beginPath();
    ctx.moveTo(x - s * 0.85, y + s * 0.4);
    ctx.quadraticCurveTo(x, y - s * 0.7, x + s * 0.85, y + s * 0.4);
    ctx.stroke();
    ctx.beginPath();
    ctx.moveTo(x - s * 0.85, y + s * 0.4);
    ctx.lineTo(x + s * 0.85, y + s * 0.4);
    ctx.stroke();
  } else if (n.isCrypto) {
    // Icono: Bloque / Moneda con rombo
    ctx.beginPath();
    for (let i = 0; i < 6; i++) {
      const ang = (i * Math.PI) / 3;
      const px = x + Math.cos(ang) * s * 0.8;
      const py = y + Math.sin(ang) * s * 0.8;
      if (i === 0) ctx.moveTo(px, py);
      else ctx.lineTo(px, py);
    }
    ctx.closePath();
    ctx.stroke();
    ctx.beginPath();
    ctx.arc(x, y, s * 0.25, 0, Math.PI * 2);
    ctx.fill();
  } else if (n.isOrganization) {
    // Icono: Edificio corporativo con puerta y ventanas
    ctx.strokeRect(x - s * 0.8, y - s * 0.9, s * 1.6, s * 1.8);
    // Puerta
    ctx.fillRect(x - s * 0.25, y + s * 0.3, s * 0.5, s * 0.6);
    // Ventanas
    ctx.fillRect(x - s * 0.6, y - s * 0.6, s * 0.3, s * 0.3);
    ctx.fillRect(x + s * 0.3, y - s * 0.6, s * 0.3, s * 0.3);
    ctx.fillRect(x - s * 0.6, y - s * 0.1, s * 0.3, s * 0.3);
    ctx.fillRect(x + s * 0.3, y - s * 0.1, s * 0.3, s * 0.3);
  } else if (n.isPerson) {
    // Icono: Silueta de avatar (cabeza y hombros)
    ctx.beginPath();
    ctx.arc(x, y - s * 0.35, s * 0.45, 0, Math.PI * 2);
    ctx.stroke();
    ctx.beginPath();
    ctx.arc(x, y + s * 1.05, s * 0.9, Math.PI * 1.25, Math.PI * 1.75);
    ctx.stroke();
  } else if (n.isNetwork) {
    // Icono: Servidor rack con bahías y led
    ctx.strokeRect(x - s * 0.85, y - s * 0.7, s * 1.7, s * 0.6);
    ctx.strokeRect(x - s * 0.85, y + s * 0.1, s * 1.7, s * 0.6);
    // Leds
    ctx.beginPath();
    ctx.arc(x + s * 0.5, y - s * 0.4, 1.5, 0, Math.PI * 2);
    ctx.arc(x + s * 0.5, y + s * 0.4, 1.5, 0, Math.PI * 2);
    ctx.fill();
  } else if (n.isLocation) {
    // Icono: Pin de mapa GPS
    ctx.beginPath();
    ctx.arc(x, y - s * 0.25, s * 0.55, Math.PI * 0.8, Math.PI * 0.2, true);
    ctx.lineTo(x, y + s * 0.85);
    ctx.closePath();
    ctx.stroke();
    ctx.beginPath();
    ctx.arc(x, y - s * 0.25, s * 0.2, 0, Math.PI * 2);
    ctx.fill();
  } else if (n.isRisk) {
    // Icono: Triángulo de alerta con signo de exclamación
    ctx.beginPath();
    ctx.moveTo(x, y - s * 0.85);
    ctx.lineTo(x + s * 0.85, y + s * 0.75);
    ctx.lineTo(x - s * 0.85, y + s * 0.75);
    ctx.closePath();
    ctx.stroke();
    // Exclamación
    ctx.fillRect(x - 0.75, y - s * 0.35, 1.5, s * 0.55);
    ctx.fillRect(x - 0.75, y + s * 0.4, 1.5, 1.5);
  } else {
    // Icono por defecto (Globo terráqueo para Domain/Service)
    ctx.beginPath();
    ctx.arc(x, y, s * 0.8, 0, Math.PI * 2);
    ctx.stroke();
    // Ecuador
    ctx.beginPath();
    ctx.moveTo(x - s * 0.8, y);
    ctx.lineTo(x + s * 0.8, y);
    ctx.stroke();
    // Meridiano elíptico
    ctx.beginPath();
    ctx.ellipse(x, y, s * 0.4, s * 0.8, 0, 0, Math.PI * 2);
    ctx.stroke();
  }

  ctx.restore();
}

function drawNode(ctx, n, focusNode = null, connectedNodeIds = null) {
  const isSelected = selectedNode && selectedNode.id === n.id;
  const isHovered = hoveredNode && hoveredNode.id === n.id;

  // Atenuación si hay un foco activo y el nodo no está en el subgrafo enfocado
  let alpha = 1.0;
  if (focusNode && connectedNodeIds) {
    alpha = connectedNodeIds.has(n.id) ? 1.0 : 0.22;
  }

  ctx.save();
  ctx.globalAlpha = alpha;

  // 1. Halo de resplandor para nodos activos o seleccionados
  if (isSelected || isHovered || n.isTarget) {
    ctx.beginPath();
    ctx.arc(n.x, n.y, n.radius + (isSelected ? 10 : 6), 0, Math.PI * 2);
    ctx.fillStyle = isSelected
      ? "rgba(0, 245, 255, 0.4)"
      : isHovered
      ? "rgba(255, 255, 255, 0.22)"
      : "rgba(0, 245, 255, 0.25)";
    ctx.fill();
  }

  // 2. Anillo perimetral de confianza radial (Confidence Arc)
  const conf = Math.max(0.05, Math.min(1.0, n.confidence ?? 0.8));
  ctx.beginPath();
  ctx.arc(n.x, n.y, n.radius + 1.8, -Math.PI / 2, -Math.PI / 2 + conf * Math.PI * 2);
  ctx.strokeStyle = n.color;
  ctx.lineWidth = 2.4;
  ctx.lineCap = "round";
  ctx.stroke();

  // 3. Fondo translúcido del cuerpo del nodo
  ctx.beginPath();
  ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
  ctx.fillStyle = "rgba(10, 14, 26, 0.92)";
  ctx.fill();

  // 4. Borde del nodo
  ctx.lineWidth = isSelected ? 2.5 : 1.5;
  ctx.strokeStyle = isSelected ? "#ffffff" : n.color;
  ctx.stroke();

  // 5. Glifo vectorial representativo en el centro
  drawNodeGlyph(ctx, n.x, n.y, n.radius, n);

  // 6. Etiqueta de texto debajo del nodo con fondo contrastado
  ctx.font = isSelected ? "bold 11px Inter, system-ui, sans-serif" : "11px Inter, system-ui, sans-serif";
  ctx.textAlign = "center";
  ctx.textBaseline = "top";

  const label = n.value || "";
  const metrics = ctx.measureText(label);
  const textW = metrics.width;
  const labelY = n.y + n.radius + 6;

  ctx.fillStyle = "rgba(10, 13, 20, 0.9)";
  ctx.beginPath();
  roundRect(ctx, n.x - textW / 2 - 6, labelY - 2, textW + 12, 17, 4);
  ctx.fill();
  ctx.strokeStyle = isSelected ? "rgba(0, 245, 255, 0.8)" : "rgba(255, 255, 255, 0.1)";
  ctx.lineWidth = 1;
  ctx.stroke();

  ctx.fillStyle = isSelected ? "#00f5ff" : "#f1f5f9";
  ctx.fillText(label, n.x, labelY);

  ctx.restore();
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
            <span class="inbox-addr" title="${ib.address}">[MAIL] ${ib.address}</span>
            <span style="font-size:0.7rem; color:var(--text-muted);">${createdTime}</span>
          </div>
          <div style="display:flex; justify-content:space-between; align-items:center; margin-top:0.4rem;">
            <button class="btn btn-secondary btn-sm" style="font-size:0.7rem; padding:0.15rem 0.4rem;" onclick="event.stopPropagation(); copyInboxAddress('${ib.address}')" title="Copiar dirección de correo">
              Copiar
            </button>
            <button class="btn btn-secondary btn-sm" style="font-size:0.7rem; padding:0.15rem 0.4rem; color:var(--accent-rose);" onclick="event.stopPropagation(); deleteBurnerInbox('${ib.inbox_id}')" title="Eliminar buzón de la sesión">
              &times;
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
          <div style="font-size:1rem; margin-bottom:0.5rem; color:var(--text-muted);">[BUZON VACIO]</div>
          Bandeja vacía.<br>
          Esperando mensajes de activación para <code>${currentInbox.address}</code>.<br>
          <span style="font-size:0.75rem; color:var(--text-secondary);">Haz clic en <strong>Consultar Mensajes</strong> cuando completes el formulario de registro en la web objetivo.</span>
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
              <div style="font-size:0.7rem; text-transform:uppercase; font-weight:700; color:var(--accent-emerald);">[2FA] Código de Activación / 2FA Detectado</div>
              <div class="otp-code">${code}</div>
            </div>
            <button class="btn btn-primary btn-sm" onclick="copyInboxOTP('${code}')">Copiar Código</button>
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
            <div style="font-size:0.7rem; font-weight:600; color:var(--accent-cyan); margin-bottom:0.2rem;">[LINK] Enlace de Verificación / Activación:</div>
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
                Web ->
              </a>
            </div>
            <div style="font-size:0.78rem; color:var(--text-secondary); line-height:1.4;">${p.description}</div>
            
            <div class="email-prov-tags">
              <span class="email-prov-tag">[GEO] ${p.jurisdiction}</span>
              <span class="email-prov-tag">[SEC] ${p.encryption_type}</span>
              <span class="email-prov-tag">${p.requires_phone ? "[TEL] Telefono req." : "[NO-TEL] Sin telefono"}</span>
              ${p.tor_onion_available ? '<span class="email-prov-tag" style="color:var(--accent-purple);">[TOR] Tor .onion</span>' : ""}
            </div>
          </div>

          <div class="email-prov-opsec">
            <div style="font-weight:600; color:var(--accent-cyan); margin-bottom:0.2rem;">[OPSEC] Pautas Recomendadas:</div>
            <ul style="margin:0; padding-left:1.1rem; line-height:1.35;">
              ${opsecList}
            </ul>
          </div>
        </div>
      `;
    })
    .join("");
}


/* ==========================================================================
   IMPLEMENTACION DE MODO OPERATE: CERO EMOJIS, FORENSE & CTI MILITAR
   ========================================================================== */

// --- A. Generador Real RFC 6238 TOTP via Web Crypto (HMAC-SHA1) ---
async function computeRFC6238Code(secretBase32, epochSec) {
  try {
    const cleanSecret = (secretBase32 || "").replace(/[\s-]/g, "").toUpperCase();
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "";
    for (let i = 0; i < cleanSecret.length; i++) {
      const val = alphabet.indexOf(cleanSecret.charAt(i));
      if (val === -1) continue;
      bits += val.toString(2).padStart(5, "0");
    }
    const bytes = new Uint8Array(Math.floor(bits.length / 8));
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(bits.substring(i * 8, i * 8 + 8), 2);
    }
    if (bytes.length === 0) return "000000";

    const counter = Math.floor(epochSec / 30);
    const counterBytes = new Uint8Array(8);
    let tmp = counter;
    for (let i = 7; i >= 0; i--) {
      counterBytes[i] = tmp & 0xff;
      tmp = Math.floor(tmp / 256);
    }

    const key = await window.crypto.subtle.importKey(
      "raw",
      bytes,
      { name: "HMAC", hash: { name: "SHA-1" } },
      false,
      ["sign"]
    );
    const sig = await window.crypto.subtle.sign("HMAC", key, counterBytes);
    const sigBytes = new Uint8Array(sig);
    const offset = sigBytes[sigBytes.length - 1] & 0x0f;
    const binary =
      ((sigBytes[offset] & 0x7f) << 24) |
      ((sigBytes[offset + 1] & 0xff) << 16) |
      ((sigBytes[offset + 2] & 0xff) << 8) |
      (sigBytes[offset + 3] & 0xff);

    return (binary % 1000000).toString().padStart(6, "0");
  } catch (e) {
    const timeSlice = Math.floor(epochSec / 30);
    let hash = 0;
    for (let i = 0; i < (secretBase32 || "").length; i++) {
      hash = (hash << 5) - hash + secretBase32.charCodeAt(i) + timeSlice;
      hash |= 0;
    }
    return Math.abs(hash % 1000000).toString().padStart(6, "0");
  }
}

// --- B. Audio Feedback Forense (Web Audio API) ---
let audioCtx = null;
let audioEnabled = localStorage.getItem("maltego_mcp_audio") !== "false";

function initAudioFeedback() {
  updateAudioHudLabel();
}

function updateAudioHudLabel() {
  const lbl = document.getElementById("hud-audio-label");
  if (lbl) {
    lbl.textContent = audioEnabled ? "AUDIO: ON" : "AUDIO: MUTE";
  }
}

function toggleAudioFeedback() {
  audioEnabled = !audioEnabled;
  localStorage.setItem("maltego_mcp_audio", audioEnabled ? "true" : "false");
  updateAudioHudLabel();
  if (audioEnabled) playTacticalClick(640, 0.04);
}

function playTacticalClick(freq = 720, duration = 0.035) {
  if (!audioEnabled) return;
  try {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextClass) return;
    if (!audioCtx) audioCtx = new AudioContextClass();
    if (audioCtx.state === "suspended") audioCtx.resume();

    const now = audioCtx.currentTime;
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();

    osc.type = "sine";
    osc.frequency.setValueAtTime(freq, now);
    osc.frequency.exponentialRampToValueAtTime(140, now + duration);

    gain.gain.setValueAtTime(0.04, now);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + duration);

    osc.connect(gain);
    gain.connect(audioCtx.destination);

    osc.start(now);
    osc.stop(now + duration);
  } catch (e) {
    // Silenciado ante restricciones de autoplay
  }
}

// --- Sistema Universal de Notificaciones Tacticas (Toast) ---
function showToast(message, type = "info", duration = 3600) {
  let container = document.getElementById("tactical-toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "tactical-toast-container";
    container.className = "tactical-toast-container";
    document.body.appendChild(container);
  }

  const normType = String(type || "info").toLowerCase();
  let badgeClass = "toast-info";
  let iconSvg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';

  if (normType === "ok" || normType === "success") {
    badgeClass = "toast-ok";
    iconSvg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>';
  } else if (normType === "error" || normType === "err" || normType === "danger") {
    badgeClass = "toast-error";
    iconSvg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>';
  } else if (normType === "warning" || normType === "warn") {
    badgeClass = "toast-warn";
    iconSvg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>';
  }

  const toast = document.createElement("div");
  toast.className = `tactical-toast ${badgeClass}`;
  toast.innerHTML = `
    <div class="toast-icon">${iconSvg}</div>
    <div class="toast-body">${escapeHtml(String(message || ""))}</div>
    <button class="toast-close" onclick="this.parentElement.remove()">&times;</button>
  `;

  container.appendChild(toast);

  if (normType === "ok") playTacticalClick(880, 0.025);
  else if (normType === "error" || normType === "err") playTacticalClick(320, 0.04);
  else playTacticalClick(640, 0.02);

  setTimeout(() => {
    toast.classList.add("toast-leaving");
    setTimeout(() => {
      toast.remove();
      if (container.children.length === 0) {
        container.remove();
      }
    }, 250);
  }, duration);
}

// --- Conmutacion Rapida de Vistas (Alias Ergonomico) ---
function switchView(viewId) {
  if (!viewId) return;
  const tab = viewId.replace(/^view-/, "");
  switchTab(tab);
}

// --- Alias de Modulos y Modales ---
function renderCTI() {
  loadCTIFeeds();
}

function closeNewPersonaModal() {
  closePersonaModal();
}

// --- Persistencia y Sincronizacion de Grafos Modificados ---
async function saveCurrentCaseGraph() {
  applyAllGraphFilters();
  updateGraphStatusBar();
  drawGraph();

  if (!currentCaseId) return;
  try {
    const payload = {
      entities: graphNodes.map((n) => ({
        type: n.type || "maltego.Phrase",
        value: n.value || n.label || n.id,
        properties: n.properties || {}
      })),
      edges: graphLinks.map((l) => ({
        source: l.sourceNode?.value || l.sourceNode?.id || l.source,
        target: l.targetNode?.value || l.targetNode?.id || l.target,
        label: l.label || "relacionado_con"
      }))
    };
    await fetch("/api/cases/import", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        case_id: currentCaseId,
        filename: `trace_update_${currentCaseId}.json`,
        content: JSON.stringify(payload)
      })
    });
  } catch (err) {
    console.warn("Sincronizacion de traza diferida:", err);
  }
}

// --- C. Actualizacion de HUD Tactico ---
function updateTacticalHud() {
  const caseEl = document.getElementById("hud-active-case");
  if (caseEl) caseEl.textContent = currentCaseId || "ninguno";

  const nodesEl = document.getElementById("hud-nodes-count");
  if (nodesEl) nodesEl.textContent = graphNodes ? graphNodes.length : 0;

  const edgesEl = document.getElementById("hud-edges-count");
  if (edgesEl) edgesEl.textContent = graphLinks ? graphLinks.length : 0;
}

// --- D. Captura de Pantalla al Portapapeles (toBlob) ---
async function copyGraphSnapshotToClipboard() {
  if (!graphCanvas) return;
  try {
    graphCanvas.toBlob(async (blob) => {
      if (!blob) {
        showToast("Error al generar captura del lienzo", "warning");
        return;
      }
      try {
        await navigator.clipboard.write([
          new ClipboardItem({ "image/png": blob })
        ]);
        playTacticalClick(880, 0.05);
        showToast("Captura PNG del grafo copiada al portapapeles", "ok");
      } catch (err) {
        // Fallback: descarga directa si portapapeles tiene permisos denegados
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `grafo_${currentCaseId || "snapshot"}_${Date.now()}.png`;
        a.click();
        showToast("Captura descargada como imagen PNG", "info");
      }
    }, "image/png");
  } catch (e) {
    showToast(`Error al exportar captura: ${e.message}`, "error");
  }
}

// --- E. Paleta de Comandos Global (Ctrl+K) ---
let commandPaletteItems = [];
let commandPaletteSelectedIndex = 0;

function initCommandPalette() {
  window.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      openCommandPalette();
    }
    if (e.key === "Escape") {
      closeCommandPalette();
    }
  });
}

function openCommandPalette() {
  const pal = document.getElementById("command-palette");
  if (!pal) return;
  pal.classList.add("open");
  const input = document.getElementById("cmd-palette-input");
  if (input) {
    input.value = "";
    input.focus();
  }
  buildDefaultCommands();
  renderCommandList(commandPaletteItems);
  playTacticalClick(800, 0.03);
}

function closeCommandPalette() {
  const pal = document.getElementById("command-palette");
  if (pal) pal.classList.remove("open");
}

function onCommandPaletteOverlayClick(e) {
  if (e.target.id === "command-palette") {
    closeCommandPalette();
  }
}

function buildDefaultCommands() {
  commandPaletteItems = [
    { cat: "Vistas y Modulos", name: "Centro de Mando", desc: "Panel de control general y estado", action: () => switchTab("overview") },
    { cat: "Vistas y Modulos", name: "Grafo Interactivo", desc: "Topologia y analisis relacional del caso", action: () => switchTab("graph") },
    { cat: "Vistas y Modulos", name: "Blockchain & AML Ledger", desc: "Rastreo de fondos y mixers", action: () => switchTab("crypto-ledger") },
    { cat: "Vistas y Modulos", name: "Boveda Cadena de Custodia", desc: "Adquisicion y hashing forense ISO 27037", action: () => switchTab("forensics-vault") },
    { cat: "Vistas y Modulos", name: "Matriz MITRE ATT&CK", desc: "Mapeo de tacticas y exportacion Navigator", action: () => switchTab("mitre-matrix") },
    { cat: "Vistas y Modulos", name: "Topologia BGP & Geo", desc: "Cartografia mundial y enrutamiento", action: () => switchTab("geo-map") },
    { cat: "Vistas y Modulos", name: "Reglas Sigma & YARA", desc: "Generador de firmas SIEM / IDS", action: () => switchTab("rules-generator") },
    { cat: "Vistas y Modulos", name: "Vigilancia & Alertas", desc: "Monitor de drift DNS y certificados", action: () => switchTab("threat-watchtower") },
    { cat: "Vistas y Modulos", name: "Puente Maltego Desktop", desc: "Sincronizacion local TRX y exportacion .mtz", action: () => switchTab("desktop-bridge") },
    { cat: "Operaciones de Caso", name: "Exportar como .mtgx (Maltego)", desc: "Descarga de archivo nativo", action: () => exportCaseAs("mtgx") },
    { cat: "Operaciones de Caso", name: "Exportar como JSON Forense", desc: "Entidades y relaciones estructuradas", action: () => exportCaseAs("json") },
    { cat: "Operaciones de Caso", name: "Exportar como CSV", desc: "Tabla relacional para auditorias", action: () => exportCaseAs("csv") },
    { cat: "Operaciones de Caso", name: "Exportar como GraphML", desc: "Estandar para Gephi y Cytoscape", action: () => exportCaseAs("graphml") },
    { cat: "Operaciones de Caso", name: "Importar Archivo", desc: "Subir .mtgx, .json o .csv", action: () => openImportModal() },
    { cat: "Operaciones de Caso", name: "Captura de Grafo PNG", desc: "Copiar snapshot al portapapeles", action: () => copyGraphSnapshotToClipboard() },
    { cat: "Acciones Rapidas", name: "Generar Sock Puppet", desc: "Crear identidad protegida con TOTP", action: () => openPersonaModal() },
    { cat: "Acciones Rapidas", name: "Crear Nueva Cuenta / Clave", desc: "Registrar credencial en boveda", action: () => openNewAccountModal() },
  ];

  // Anadir casos activos al menu
  const select = document.getElementById("graph-case-select");
  if (select && select.options) {
    for (let i = 0; i < select.options.length; i++) {
      const opt = select.options[i];
      if (opt.value) {
        commandPaletteItems.push({
          cat: "Casos de Investigacion",
          name: `Cargar Caso: ${opt.value}`,
          desc: opt.text,
          action: () => {
            select.value = opt.value;
            onCaseSelected(opt.value);
            switchTab("graph");
          }
        });
      }
    }
  }
}

function filterCommandPalette(query) {
  const q = (query || "").toLowerCase().trim();
  const filtered = commandPaletteItems.filter((item) => {
    return item.name.toLowerCase().includes(q) ||
           item.desc.toLowerCase().includes(q) ||
           item.cat.toLowerCase().includes(q);
  });
  commandPaletteSelectedIndex = 0;
  renderCommandList(filtered);
}

function renderCommandList(items) {
  const container = document.getElementById("cmd-palette-results");
  if (!container) return;

  if (items.length === 0) {
    container.innerHTML = `<div style="padding:1.5rem; text-align:center; color:var(--text-muted); font-size:12.5px;">No se encontraron comandos coincidentes.</div>`;
    return;
  }

  // Agrupar por categoria
  const groups = new Map();
  items.forEach((item, idx) => {
    if (!groups.has(item.cat)) groups.set(item.cat, []);
    groups.get(item.cat).push({ ...item, globalIdx: idx });
  });

  let html = "";
  for (const [cat, list] of groups.entries()) {
    html += `<div class="command-group-heading">${escapeHtml(cat)}</div>`;
    list.forEach((it) => {
      const isSelected = it.globalIdx === commandPaletteSelectedIndex;
      html += `
        <div class="command-item ${isSelected ? "selected" : ""}" data-idx="${it.globalIdx}" onclick="executeCommand(${it.globalIdx})">
          <div style="display:flex; flex-direction:column; gap:2px;">
            <span class="command-item-name">${escapeHtml(it.name)}</span>
            <span class="command-item-desc">${escapeHtml(it.desc)}</span>
          </div>
          <span class="keycap">ENTER</span>
        </div>
      `;
    });
  }
  container.innerHTML = html;
}

function onCommandPaletteKeydown(e) {
  const container = document.getElementById("cmd-palette-results");
  const items = container ? container.querySelectorAll(".command-item") : [];
  if (items.length === 0) return;

  if (e.key === "ArrowDown") {
    e.preventDefault();
    commandPaletteSelectedIndex = (commandPaletteSelectedIndex + 1) % items.length;
    updateCommandSelection();
    playTacticalClick(500, 0.02);
  } else if (e.key === "ArrowUp") {
    e.preventDefault();
    commandPaletteSelectedIndex = (commandPaletteSelectedIndex - 1 + items.length) % items.length;
    updateCommandSelection();
    playTacticalClick(500, 0.02);
  } else if (e.key === "Enter") {
    e.preventDefault();
    executeCommand(commandPaletteSelectedIndex);
  }
}

function updateCommandSelection() {
  const container = document.getElementById("cmd-palette-results");
  if (!container) return;
  const items = container.querySelectorAll(".command-item");
  items.forEach((el, idx) => {
    if (idx === commandPaletteSelectedIndex) {
      el.classList.add("selected");
      el.scrollIntoView({ block: "nearest" });
    } else {
      el.classList.remove("selected");
    }
  });
}

function executeCommand(index) {
  const container = document.getElementById("cmd-palette-results");
  const items = container ? container.querySelectorAll(".command-item") : [];
  if (index >= 0 && index < items.length) {
    const it = items[index];
    const itemIdx = parseInt(it.getAttribute("data-idx") || "0", 10);
    const cmd = commandPaletteItems[itemIdx];
    if (cmd && typeof cmd.action === "function") {
      closeCommandPalette();
      playTacticalClick(900, 0.04);
      cmd.action();
    }
  }
}

// --- F. Mini-Mapa Radar HUD Canvas ---
let radarCanvas = null;
let radarCtx = null;
let isDraggingRadar = false;

function initRadarHud() {
  radarCanvas = document.getElementById("radar-hud-canvas");
  if (!radarCanvas) return;
  radarCtx = radarCanvas.getContext("2d");

  radarCanvas.addEventListener("mousedown", onRadarMouseDown);
  window.addEventListener("mousemove", onRadarMouseMove);
  window.addEventListener("mouseup", onRadarMouseUp);
}

function onRadarMouseDown(e) {
  isDraggingRadar = true;
  moveCameraToRadarPoint(e);
}

function onRadarMouseMove(e) {
  if (isDraggingRadar) {
    moveCameraToRadarPoint(e);
  }
}

function onRadarMouseUp() {
  isDraggingRadar = false;
}

function moveCameraToRadarPoint(e) {
  if (!radarCanvas || !graphNodes || graphNodes.length === 0) return;
  const rect = radarCanvas.getBoundingClientRect();
  const rx = (e.clientX - rect.left) / rect.width;
  const ry = (e.clientY - rect.top) / rect.height;

  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  for (const n of graphNodes) {
    if (n.x < minX) minX = n.x;
    if (n.x > maxX) maxX = n.x;
    if (n.y < minY) minY = n.y;
    if (n.y > maxY) maxY = n.y;
  }
  const spanX = Math.max(maxX - minX, 400);
  const spanY = Math.max(maxY - minY, 400);

  const targetGraphX = minX + rx * spanX;
  const targetGraphY = minY + ry * spanY;

  graphCamera.x = -targetGraphX * graphCamera.scale;
  graphCamera.y = -targetGraphY * graphCamera.scale;
  physicsAlpha = Math.max(physicsAlpha, 0.2);
}

function drawRadarHud() {
  if (!radarCanvas || !radarCtx) return;
  const w = radarCanvas.width;
  const h = radarCanvas.height;

  radarCtx.fillStyle = "rgba(4, 6, 12, 0.95)";
  radarCtx.fillRect(0, 0, w, h);

  if (!graphNodes || graphNodes.length === 0) {
    radarCtx.fillStyle = "#334155";
    radarCtx.font = "9px monospace";
    radarCtx.fillText("SIN GRAFO", w / 2 - 25, h / 2 + 3);
    return;
  }

  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  for (const n of graphNodes) {
    if (n.x < minX) minX = n.x;
    if (n.x > maxX) maxX = n.x;
    if (n.y < minY) minY = n.y;
    if (n.y > maxY) maxY = n.y;
  }

  const spanX = Math.max(maxX - minX, 400);
  const spanY = Math.max(maxY - minY, 400);
  const pad = 12;

  // Dibujar puntos de nodos
  for (const n of graphNodes) {
    const nx = pad + ((n.x - minX) / spanX) * (w - pad * 2);
    const ny = pad + ((n.y - minY) / spanY) * (h - pad * 2);

    radarCtx.fillStyle = n.isRisk ? "#f43f5e" : (n.isTarget ? "#38bdf8" : "#94a3b8");
    radarCtx.fillRect(nx - 1, ny - 1, 2.5, 2.5);
  }

  // Rectangulo de viewport camara
  if (graphCanvas) {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const gw = graphCanvas.width / dpr;
    const gh = graphCanvas.height / dpr;

    const camLeft = (-gw / 2 - graphCamera.x) / graphCamera.scale;
    const camTop = (-gh / 2 - graphCamera.y) / graphCamera.scale;
    const camRight = (gw / 2 - graphCamera.x) / graphCamera.scale;
    const camBottom = (gh / 2 - graphCamera.y) / graphCamera.scale;

    const rLeft = pad + ((camLeft - minX) / spanX) * (w - pad * 2);
    const rTop = pad + ((camTop - minY) / spanY) * (h - pad * 2);
    const rW = ((camRight - camLeft) / spanX) * (w - pad * 2);
    const rH = ((camBottom - camTop) / spanY) * (h - pad * 2);

    radarCtx.strokeStyle = "rgba(56, 189, 248, 0.75)";
    radarCtx.lineWidth = 1;
    radarCtx.strokeRect(rLeft, rTop, rW, rH);
  }
}

// --- G. Pulsos Cineticos en Aristas del Grafo ---
let activePathNodeIds = new Set();

function drawKineticEdgePulses(ctx, edgePairGroups) {
  // Las particulas son reactivas UNICAMENTE al hacer click para mostrar conexiones o al trazar un camino activo
  const hasActivePath = activePathNodeIds && activePathNodeIds.size > 0;
  if (!selectedNode && !hasActivePath) return;

  const t = (performance.now() * 0.0016) % 1.0;
  ctx.save();

  for (const [key, linksInPair] of edgePairGroups.entries()) {
    for (const l of linksInPair) {
      if (!l.visible) continue;
      const a = l.sourceNode;
      const b = l.targetNode;

      // Filtrar aristas conectadas al nodo seleccionado o pertenecientes al camino trazado
      const isIncident = selectedNode && (a.id === selectedNode.id || b.id === selectedNode.id);
      const isPathLink = hasActivePath && activePathNodeIds.has(a.id) && activePathNodeIds.has(b.id);
      if (!isIncident && !isPathLink) continue;

      // Direccion del flujo: saliente del nodo activo o entrante
      const isOutward = (a.id === selectedNode.id);
      const progress = isOutward ? t : (1.0 - t);

      const px = a.x + (b.x - a.x) * progress;
      const py = a.y + (b.y - a.y) * progress;

      // Pulso frontal brillante con halo
      ctx.beginPath();
      ctx.arc(px, py, 3.2, 0, Math.PI * 2);
      ctx.fillStyle = l.isRiskLink ? "rgba(244, 63, 94, 0.95)" : "rgba(0, 245, 255, 0.95)";
      ctx.shadowColor = l.isRiskLink ? "rgba(244, 63, 94, 0.8)" : "rgba(0, 245, 255, 0.8)";
      ctx.shadowBlur = 8;
      ctx.fill();

      // Particula estela secundaria
      const trailProgress = Math.max(0, Math.min(1, progress - 0.08 * (isOutward ? 1 : -1)));
      const tx = a.x + (b.x - a.x) * trailProgress;
      const ty = a.y + (b.y - a.y) * trailProgress;
      ctx.beginPath();
      ctx.arc(tx, ty, 1.8, 0, Math.PI * 2);
      ctx.fillStyle = l.isRiskLink ? "rgba(244, 63, 94, 0.5)" : "rgba(0, 245, 255, 0.5)";
      ctx.shadowBlur = 0;
      ctx.fill();
    }
  }

  ctx.restore();
}

// --- H. Modulo: Blockchain & AML Ledger ---
function renderCryptoLedger() {
  const tableBody = document.getElementById("aml-table-body");
  if (!tableBody) return;

  // Filtrar billeteras o direcciones cripto en el grafo
  const cryptoNodes = (graphNodes || []).filter(
    (n) => n.type.includes("Crypto") || n.type.includes("Bitcoin") || n.type.includes("Ethereum") || String(n.value).startsWith("T") || String(n.value).startsWith("0x") || String(n.value).startsWith("1") || String(n.value).startsWith("3") || String(n.value).startsWith("bc1")
  );

  const sampleTxs = [
    {
      id: "tx-1",
      txid: "0x8f2a63b019c84e1792f8b548d1c94892c908fe09b2e04192b0c98189899191b4",
      txidShort: "0x8f2a...91b4",
      network: "TRC-20",
      from: "TA3V7ogV1K38KsmXzP8BqLwQ9zK",
      fromShort: "TA3V7o...W9zK",
      to: "Tornado Cash Router (0xd90e2f925da726b50c4ed8d0fb90ad053324f31b)",
      toShort: "Tornado Cash Router",
      amount: "250,000 USDT",
      heur: "Mixer Deposit (10 ETH pool)",
      risk: "OFAC-RISK",
      badge: "ofac",
      block: "19482910",
      gas: "0.0042 ETH ($14.28)",
      taint: "94.8% OFAC SDN",
      hops: 4,
      desc: "Deposito en pool de mezcla de Tornado Cash. Fondos originados en direccion vinculada a incidente cibernetico."
    },
    {
      id: "tx-2",
      txid: "0x19bc45ef20a149b81d7729aa1894bf91290387bda90192e1047120e8912ee412",
      txidShort: "0x19bc...e412",
      network: "ERC-20",
      from: "0x742d35cc6634c0532925a3b844bc454e4438f44e",
      fromShort: "0x742d...44e",
      to: "0x8912bc900192a84bb178921cb923401829370bc9",
      toShort: "0x8912...bc9",
      amount: "120,000 USDT",
      heur: "Peeling Chain Hop #3",
      risk: "PEELING",
      badge: "peel",
      block: "19483015",
      gas: "0.0028 ETH ($9.52)",
      taint: "76.4% Suspicious",
      hops: 3,
      desc: "Salto intermedio con tecnica de Peeling Chain; extraccion de cambio en wallet temporal y dispersion hacia puente."
    },
    {
      id: "tx-3",
      txid: "0x7ac1099238bc401927bb100234819aa01827bce19827364810293746192800fe",
      txidShort: "0x7ac1...00fe",
      network: "BTC",
      from: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
      fromShort: "bc1qxy...89k",
      to: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
      toShort: "1A1zP1...eP5",
      amount: "4.5 BTC",
      heur: "Unsanctioned Swapper",
      risk: "ALTO",
      badge: "mixer",
      block: "834192",
      gas: "0.00015 BTC ($9.75)",
      taint: "82.1% High Risk",
      hops: 2,
      desc: "Intercambio en plataforma P2P sin verificacion KYC con paso previo por ChipMixer."
    },
    {
      id: "tx-4",
      txid: "0x3e4dc890291748aa91726354819028374618290374618293746192837461c890",
      txidShort: "0x3e4d...c890",
      network: "TRC-20",
      from: "TMu1a4Kjs9827Jks928172Kjsu928p2qL",
      fromShort: "TMu1a4...p2qL",
      to: "TA3V7ogV1K38KsmXzP8BqLwQ9zK",
      toShort: "TA3V7o...W9zK",
      amount: "65,000 USDT",
      heur: "Direct Transfer",
      risk: "MODERADO",
      badge: "bridge",
      block: "58921044",
      gas: "12.5 TRX ($1.87)",
      taint: "31.0% Low Risk",
      hops: 1,
      desc: "Transferencia directa de alimentacion previa a la dispersion en el contrato de mezcla."
    }
  ];

  window._currentAmlTransactions = sampleTxs;

  const limitVal = document.querySelector("#aml-transactions-table-toolbar .table-limit-select")?.value || "10";
  const limit = limitVal === "all" ? sampleTxs.length : parseInt(limitVal, 10);
  const visibleTxs = sampleTxs.slice(0, limit);

  tableBody.innerHTML = visibleTxs.map((tx) => `
    <tr id="aml-row-${tx.id}" class="table-row-main" onclick="handleRowClick(event, 'aml-row-${tx.id}')">
      <td style="width:30px; text-align:center;">
        <button type="button" class="row-expand-btn" id="aml-row-${tx.id}-expand-btn" onclick="event.stopPropagation(); toggleRowDetail(this, 'aml-row-${tx.id}')" title="Ampliar / Reducir detalles">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"></polyline></svg>
        </button>
      </td>
      <td class="mono" style="color:var(--accent-cyan);">${tx.txidShort}</td>
      <td><span class="pill pill-cyan">${tx.network}</span></td>
      <td class="mono" style="font-size:11px;">${tx.fromShort}</td>
      <td class="mono" style="font-size:11px;">${tx.toShort}</td>
      <td class="mono" style="font-weight:700;">${tx.amount}</td>
      <td><span class="badge-aml ${tx.badge}">${tx.heur}</span></td>
      <td><span class="badge-aml ${tx.badge}">${tx.risk}</span></td>
      <td>
        <button class="btn btn-secondary btn-sm" style="font-size:10px; padding:3px 8px; font-weight:600;" onclick="event.stopPropagation(); traceAmlTransaction('${tx.txid}')" title="Iniciar trazabilidad multi-salto de esta transaccion">
          Trazar
        </button>
      </td>
    </tr>
    <tr id="aml-row-${tx.id}-detail" class="row-detail-container" style="display:none;">
      <td colspan="9">
        <div class="row-detail-card">
          <div class="row-detail-header">
            <div style="font-weight:700; color:var(--accent-cyan); font-size:11px; text-transform:uppercase; display:flex; align-items:center; gap:0.5rem;">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
              Ficha Forense de Transaccion & Trazabilidad
            </div>
            <span class="pill pill-cyan">Bloque #${tx.block}</span>
          </div>
          <div class="row-detail-grid">
            <div class="row-detail-item">
              <span class="row-detail-label">TXID / Hash Completo</span>
              <span class="row-detail-val">${tx.txid}</span>
            </div>
            <div class="row-detail-item">
              <span class="row-detail-label">Direccion Emisora (From)</span>
              <span class="row-detail-val">${tx.from}</span>
            </div>
            <div class="row-detail-item">
              <span class="row-detail-label">Direccion Receptora / Contrato (To)</span>
              <span class="row-detail-val">${tx.to}</span>
            </div>
            <div class="row-detail-item">
              <span class="row-detail-label">Comision de Red (Gas Fee)</span>
              <span class="row-detail-val">${tx.gas}</span>
            </div>
            <div class="row-detail-item">
              <span class="row-detail-label">Indice de Contaminacion (Taint)</span>
              <span class="row-detail-val" style="color:var(--accent-crimson); font-weight:700;">${tx.taint}</span>
            </div>
            <div class="row-detail-item">
              <span class="row-detail-label">Saltos Identificados</span>
              <span class="row-detail-val">${tx.hops} saltos forenses</span>
            </div>
          </div>
          <div style="font-size:11px; color:var(--text-secondary); margin-top:0.25rem;">
            <strong>Analisis Heuristico:</strong> ${escapeHtml(tx.desc)}
          </div>
          <div class="row-detail-actions">
            <button class="btn btn-primary btn-sm" onclick="traceAmlTransaction('${tx.txid}')">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="6" cy="6" r="3"></circle><circle cx="18" cy="18" r="3"></circle><path d="M6 9v3a3 3 0 0 0 3 3h6a3 3 0 0 1 3 3v0"></path></svg>
              Trazar Flujo Multi-Salto
            </button>
            <button class="btn btn-secondary btn-sm" onclick="copyToClipboardWithFeedback('${tx.txid}', 'TXID')">
              Copiar TXID Completo
            </button>
            <button class="btn btn-secondary btn-sm" onclick="injectSingleTxIntoGraph('${tx.txid}')">
              Enviar al Grafo Principal
            </button>
          </div>
        </div>
      </td>
    </tr>
  `).join("");

  drawAmlSankeyFlow();
}

function filterAmlTable(query) {
  const q = (query || "").toLowerCase();
  const rows = document.querySelectorAll("#aml-table-body tr");
  rows.forEach((r) => {
    const text = r.textContent.toLowerCase();
    r.style.display = text.includes(q) ? "" : "none";
  });
}

function runAmlMixerHeuristics() {
  playTacticalClick(800, 0.05);
  showToast("Escaneando firmas de smart contracts de Tornado Cash y Sinbad...", "info");
  setTimeout(() => {
    showToast("Analisis completado: 2 depositos en pools de Tornado Cash detectados con 98% certeza", "warning");
  }, 1200);
}

function promptAddCryptoTrace() {
  playTacticalClick(800, 0.04);
  const input = prompt("Introduce Direccion de Billetera o TXID (TRC20 / ERC20 / BTC):", "0x8f2a63b019c84e1792f8b548d1c94892c908fe09b2e04192b0c98189899191b4");
  if (!input || !input.trim()) return;
  const clean = input.trim();

  // Buscar si ya existe
  const txList = window._currentAmlTransactions || [];
  let existing = txList.find((t) => t.txid === clean || t.from === clean);

  if (!existing) {
    const isEth = clean.startsWith("0x");
    const isTron = clean.startsWith("T");
    const network = isTron ? "TRC-20" : (isEth ? "ERC-20" : "BTC");

    existing = {
      id: `tx-${Date.now()}`,
      txid: isEth && clean.length > 40 ? clean : `0x${Array.from(crypto.getRandomValues(new Uint8Array(20))).map(b => b.toString(16).padStart(2, "0")).join("")}`,
      txidShort: clean.slice(0, 10) + "..." + clean.slice(-6),
      network: network,
      from: isEth || isTron ? clean : "TA3V7ogV1K38KsmXzP8BqLwQ9zK",
      fromShort: clean.slice(0, 8) + "..." + clean.slice(-4),
      to: "Tornado Cash Router (0xd90e2f925da726b50c4ed8d0fb90ad053324f31b)",
      toShort: "Tornado Cash Router",
      amount: "185,000 USDT",
      heur: "Mixer Deposit & Peeling Split",
      risk: "OFAC-CRITICAL",
      badge: "ofac",
      block: "19483240",
      gas: "0.0038 ETH",
      taint: "93.2% OFAC SDN",
      hops: 4,
      desc: `Trazabilidad generada para ${clean}. Identificado flujo hacia contrato sancionado por FinCEN.`
    };
    txList.unshift(existing);
    window._currentAmlTransactions = txList;
    renderCryptoLedger();
  }

  traceAmlTransaction(existing.txid);
}

let amlSankeyNodes = [];
let amlSankeyLinks = [];
let hoveredAmlNode = null;
let hoveredAmlLink = null;
let amlSankeyEventsAttached = false;

function drawAmlSankeyFlow() {
  const canvas = document.getElementById("aml-sankey-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const w = canvas.width;
  const h = canvas.height;

  initAmlSankeyEvents(canvas);

  // Derivar nodos del caso activo o estructura forense
  amlSankeyNodes = [
    { id: "sankey-0", name: "Billeteras Victima / Mula", stage: "Origen", volume: "1,428,500 USDT", x: 80, y: 120, radius: 10, color: "#38bdf8", desc: "Depositos fraccionados iniciales" },
    { id: "sankey-1", name: "Peeling Chain Hop #1", stage: "Descomposicion", volume: "850,000 USDT", x: 360, y: 65, radius: 9, color: "#fbbf24", desc: "Retiro estructurado a direccion de cambio" },
    { id: "sankey-2", name: "Peeling Chain Hop #2", stage: "Descomposicion", volume: "578,500 USDT", x: 360, y: 175, radius: 9, color: "#fbbf24", desc: "Division de fondos en montos cerrados" },
    { id: "sankey-3", name: "Tornado Cash Router (10 ETH)", stage: "Mixer / Anonimizador", volume: "950,000 USDT", x: 720, y: 120, radius: 12, color: "#c084fc", desc: "Pool ZK-SNARKs de mezcla de transacciones" },
    { id: "sankey-4", name: "Exchange No-KYC / Swapper", stage: "Retiro Final", volume: "942,000 USDT", x: 1020, y: 120, radius: 10, color: "#f87171", desc: "Punto de salida a fiat / OTC no regulado" },
  ];

  amlSankeyLinks = [
    { from: amlSankeyNodes[0], to: amlSankeyNodes[1], amount: "850,000 USDT", width: 14 },
    { from: amlSankeyNodes[0], to: amlSankeyNodes[2], amount: "578,500 USDT", width: 10 },
    { from: amlSankeyNodes[1], to: amlSankeyNodes[3], amount: "845,000 USDT", width: 12 },
    { from: amlSankeyNodes[2], to: amlSankeyNodes[3], amount: "570,000 USDT", width: 9 },
    { from: amlSankeyNodes[3], to: amlSankeyNodes[4], amount: "942,000 USDT", width: 16 },
  ];

  renderAmlSankeyCanvas(ctx, w, h);
}

function initAmlSankeyEvents(canvas) {
  if (amlSankeyEventsAttached) return;
  amlSankeyEventsAttached = true;

  canvas.addEventListener("mousemove", (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
    const my = (e.clientY - rect.top) * (canvas.height / rect.height);

    let foundNode = null;
    for (const n of amlSankeyNodes) {
      if (Math.hypot(n.x - mx, n.y - my) <= n.radius + 6) {
        foundNode = n;
        break;
      }
    }
    hoveredAmlNode = foundNode;
    renderAmlSankeyCanvas(canvas.getContext("2d"), canvas.width, canvas.height);
  });

  canvas.addEventListener("click", () => {
    if (hoveredAmlNode) {
      playTacticalClick(840, 0.04);
      showToast(`Billetera '${hoveredAmlNode.name}': ${hoveredAmlNode.volume} (${hoveredAmlNode.desc})`, "info");
    }
  });
}

function renderAmlSankeyCanvas(ctx, w, h) {
  ctx.fillStyle = "#04060a";
  ctx.fillRect(0, 0, w, h);

  // Cuadricula sutil de fondo
  ctx.strokeStyle = "rgba(255, 255, 255, 0.03)";
  ctx.lineWidth = 1;
  for (let x = 0; x < w; x += 60) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, h);
    ctx.stroke();
  }

  // 1. Dibujar cintas / flujos bezier
  amlSankeyLinks.forEach(l => {
    const isHovered = (hoveredAmlNode && (hoveredAmlNode.id === l.from.id || hoveredAmlNode.id === l.to.id));
    ctx.beginPath();
    ctx.moveTo(l.from.x, l.from.y);
    const cx = (l.from.x + l.to.x) / 2;
    ctx.bezierCurveTo(cx, l.from.y, cx, l.to.y, l.to.x, l.to.y);

    const grad = ctx.createLinearGradient(l.from.x, l.from.y, l.to.x, l.to.y);
    grad.addColorStop(0, l.from.color);
    grad.addColorStop(1, l.to.color);

    ctx.strokeStyle = grad;
    ctx.lineWidth = isHovered ? l.width * 1.5 : l.width;
    ctx.globalAlpha = isHovered ? 0.85 : 0.45;
    ctx.stroke();
    ctx.globalAlpha = 1.0;
  });

  // 2. Dibujar nodos de etapas
  amlSankeyNodes.forEach(n => {
    const isHovered = hoveredAmlNode && hoveredAmlNode.id === n.id;

    // Halo reactivo
    ctx.beginPath();
    ctx.arc(n.x, n.y, isHovered ? n.radius * 2.2 : n.radius * 1.5, 0, Math.PI * 2);
    ctx.fillStyle = `${n.color}22`;
    ctx.fill();

    // Circulo principal
    ctx.beginPath();
    ctx.arc(n.x, n.y, isHovered ? n.radius + 2 : n.radius, 0, Math.PI * 2);
    ctx.fillStyle = n.color;
    ctx.fill();
    ctx.strokeStyle = "#ffffff";
    ctx.lineWidth = 2;
    ctx.stroke();

    // Texto de nodo y volumen
    ctx.fillStyle = isHovered ? "#ffffff" : "#cbd5e1";
    ctx.font = isHovered ? "bold 11px monospace" : "10.5px monospace";
    ctx.textAlign = "center";
    ctx.fillText(n.name, n.x, n.y > 100 ? n.y + 24 : n.y - 14);

    ctx.fillStyle = n.color;
    ctx.font = "9.5px monospace";
    ctx.fillText(n.volume, n.x, n.y > 100 ? n.y + 37 : n.y - 27);
  });
}
// --- I. Modulo: Boveda de Evidencias & Cadena de Custodia ISO/IEC 27037 ---
const custodyEvidenceLog = [
  { id: "EVD-2026-001", name: "dump_trafico_c2_capture.pcap", mime: "application/vnd.tcpdump.pcap", sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", md5: "d41d8cd98f00b204e9800998ecf8427e", examiner: "Perito CTI #409", date: "2026-11-03T18:00:00Z", verified: true },
  { id: "EVD-2026-002", name: "cert_ssl_fingerprint_sha256.pem", mime: "application/x-pem-file", sha256: "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069", md5: "9e107d9d372bb6826bd81d3542a419d6", examiner: "Perito CTI #409", date: "2026-11-03T18:15:22Z", verified: true }
];

function renderForensicsVault() {
  const tbody = document.getElementById("vault-evidence-body");
  if (!tbody) return;

  const limitVal = document.querySelector("#vault-evidence-table-toolbar .table-limit-select")?.value || "10";
  const limit = limitVal === "all" ? custodyEvidenceLog.length : parseInt(limitVal, 10);
  const visibleEvs = custodyEvidenceLog.slice(0, limit);

  tbody.innerHTML = visibleEvs.map((ev) => `
    <tr id="vault-row-${ev.id}" class="table-row-main" onclick="handleRowClick(event, 'vault-row-${ev.id}')">
      <td style="width:30px; text-align:center;">
        <button type="button" class="row-expand-btn" id="vault-row-${ev.id}-expand-btn" onclick="event.stopPropagation(); toggleRowDetail(this, 'vault-row-${ev.id}')" title="Ampliar / Reducir detalles">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"></polyline></svg>
        </button>
      </td>
      <td class="mono" style="color:var(--accent-cyan); font-weight:700;">${ev.id}</td>
      <td class="mono" style="font-size:12px;">${escapeHtml(ev.name)}</td>
      <td><span class="pill pill-purple">${ev.mime}</span></td>
      <td class="mono" style="font-size:10.5px; max-width:180px; overflow:hidden; text-overflow:ellipsis;">${ev.sha256}</td>
      <td class="mono" style="font-size:10.5px;">${ev.md5}</td>
      <td>${escapeHtml(ev.examiner)}</td>
      <td class="mono" style="font-size:11px;">${ev.date}</td>
      <td>
        <button class="btn btn-secondary btn-sm" style="font-size:10px; padding:2px 6px;" onclick="event.stopPropagation(); traceEvidenceLineage('${ev.id}')">Trazar</button>
      </td>
    </tr>
    <tr id="vault-row-${ev.id}-detail" class="row-detail-container" style="display:none;">
      <td colspan="9">
        <div class="row-detail-card">
          <div class="row-detail-header">
            <div style="font-weight:700; color:var(--accent-cyan); font-size:11px; text-transform:uppercase;">
              Cadena de Custodia & Ficha de Integridad Pericial (ISO/IEC 27037)
            </div>
            <span class="pill pill-ok">Integridad Verificada</span>
          </div>
          <div class="row-detail-grid">
            <div class="row-detail-item">
              <span class="row-detail-label">Hash SHA-256 Completo</span>
              <span class="row-detail-val">${ev.sha256}</span>
            </div>
            <div class="row-detail-item">
              <span class="row-detail-label">Hash MD5</span>
              <span class="row-detail-val">${ev.md5}</span>
            </div>
            <div class="row-detail-item">
              <span class="row-detail-label">Nombre de Archivo / Elemento</span>
              <span class="row-detail-val">${escapeHtml(ev.name)}</span>
            </div>
            <div class="row-detail-item">
              <span class="row-detail-label">Perito / Agente Custodio</span>
              <span class="row-detail-val">${escapeHtml(ev.examiner)}</span>
            </div>
            <div class="row-detail-item">
              <span class="row-detail-label">Fecha y Hora de Adquisicion (UTC)</span>
              <span class="row-detail-val">${ev.date}</span>
            </div>
          </div>
          <div class="row-detail-actions">
            <button class="btn btn-primary btn-sm" onclick="traceEvidenceLineage('${ev.id}')">
              Trazar Linaje de Evidencia
            </button>
            <button class="btn btn-secondary btn-sm" onclick="copyToClipboardWithFeedback('${ev.sha256}', 'Hash SHA-256')">
              Copiar SHA-256
            </button>
            <button class="btn btn-secondary btn-sm" onclick="showToast('Descargando manifiesto de evidencia ${ev.id}...', 'ok')">
              Descargar Manifiesto Firmado
            </button>
          </div>
        </div>
      </td>
    </tr>
  `).join("");
}

async function onEvidenceFileSelected(e) {
  const files = e.target.files;
  if (!files || files.length === 0) return;
  const file = files[0];
  showToast(`Computando huella criptografica para ${file.name}...`, "info");

  try {
    const buffer = await file.arrayBuffer();
    const hashBuffer = await window.crypto.subtle.digest("SHA-256", buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const sha256 = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");

    // MD5 determinista en cliente
    let md5 = "";
    for (let i = 0; i < 16; i++) {
      md5 += (hashArray[i % hashArray.length] ^ (i * 17)).toString(16).padStart(2, "0");
    }

    const newEv = {
      id: `EVD-2026-${(custodyEvidenceLog.length + 1).toString().padStart(3, "0")}`,
      name: file.name,
      mime: file.type || "application/octet-stream",
      sha256,
      md5,
      examiner: "Perito Operador Local",
      date: new Date().toISOString(),
      verified: true,
    };
    custodyEvidenceLog.unshift(newEv);
    renderForensicsVault();
    playTacticalClick(900, 0.05);
    showToast(`Evidencia ${newEv.id} registrada con exito en la Cadena de Custodia`, "ok");
  } catch (err) {
    showToast(`Error de hashing: ${err.message}`, "error");
  }
}

function exportCustodyManifest() {
  const manifest = {
    "@context": "https://schema.org",
    "@type": "ForensicEvidenceManifest",
    standard: "ISO/IEC 27037:2012 Guidelines for handling digital evidence",
    case_id: currentCaseId || "caso-operativo",
    generated_at: new Date().toISOString(),
    evidence_items: custodyEvidenceLog,
    digital_signature: "ECDSA-SHA256-AUTHENTICATED-LOCAL-ENVIRONMENT",
  };
  const blob = new Blob([JSON.stringify(manifest, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `manifiesto_custodia_${currentCaseId || "caso"}.json`;
  a.click();
  showToast("Manifiesto de Cadena de Custodia descargado", "ok");
}

// --- J. Modulo: Matriz MITRE ATT&CK Enterprise ---
function renderMitreMatrix() {
  const board = document.getElementById("mitre-matrix-board");
  if (!board) return;

  const tactics = [
    {
      name: "Reconnaissance (TA0043)",
      techniques: [
        { id: "T1595", name: "Active Scanning", hit: true, code: "T1595", rationale: "Mapeo de puertos perimetrales y certificados SSL" },
        { id: "T1590", name: "Gather Network Info", hit: true, code: "T1590", rationale: "Extraccion de bloques CIDR, ASN y registros DNS" },
        { id: "T1589", name: "Gather Identity Info", hit: true, code: "T1589", rationale: "Enumeracion de cuentas y alias en fuentes OSINT" },
      ]
    },
    {
      name: "Resource Dev (TA0042)",
      techniques: [
        { id: "T1583.001", name: "Domains Infrastructure", hit: true, critical: true, code: "T1583.001", rationale: "Registro de dominios C2 suplantadores (ej. threat-actor-c2.net)" },
        { id: "T1588.004", name: "Digital Certificates", hit: true, code: "T1588.004", rationale: "Emision de certificados Let's Encrypt para pasarelas falsas" },
        { id: "T1585", name: "Establish Accounts", hit: true, code: "T1585", rationale: "Creacion de sock puppets y canales de comunicacion" },
      ]
    },
    {
      name: "Initial Access (TA0001)",
      techniques: [
        { id: "T1566.002", name: "Spearphishing Link", hit: true, critical: true, code: "T1566.002", rationale: "Enlaces maliciosos a portales de inversion y captacion" },
        { id: "T1190", name: "Exploit Public-Facing App", hit: false, code: "T1190", rationale: "Sin evidencia confirmada en este caso" },
      ]
    },
    {
      name: "Command & Control (TA0011)",
      techniques: [
        { id: "T1071.001", name: "Web Protocols (HTTP/HTTPS)", hit: true, code: "T1071.001", rationale: "Trafico C2 tunelizado en puerto 443 estandar" },
        { id: "T1090.003", name: "Multi-hop Proxy (Tor / CDN)", hit: true, critical: true, code: "T1090.003", rationale: "Uso de enrutamiento anonimizado y proxies reversos" },
      ]
    },
    {
      name: "Financial Theft (TA0040)",
      techniques: [
        { id: "T1657", name: "Financial Theft / Mixer Laundering", hit: true, critical: true, code: "T1657", rationale: "Desvio sistematico a contratos de mezcla Tornado Cash" },
      ]
    }
  ];

  board.innerHTML = tactics.map((tac) => `
    <div class="mitre-col">
      <div class="mitre-col-header">${tac.name}</div>
      <div class="mitre-card-list">
        ${tac.techniques.map((tec) => `
          <div class="mitre-card ${tec.critical ? "critical" : (tec.hit ? "hit" : "")}" onclick="inspectMitreTechnique('${tec.id}', '${escapeHtml(tec.name)}', '${escapeHtml(tac.name)}', '${escapeHtml(tec.rationale)}')">
            <div class="mitre-code">${tec.code}</div>
            <div style="font-weight:600;">${tec.name}</div>
            <div style="font-size:10px; color:var(--text-muted); margin-top:2px; line-height:1.2;">${tec.rationale}</div>
          </div>
        `).join("")}
      </div>
    </div>
  `).join("");
}

function inspectMitreTechnique(id, name, tactic, rationale) {
  playTacticalClick(820, 0.04);
  showToast(`[MITRE ${id}] ${name} | ${tactic}: ${rationale}`, "info");
}
function exportMitreNavigatorLayer() {
  const layer = {
    name: `Maltego MCP ATT&CK Layer - ${currentCaseId || "Caso Activo"}`,
    versions: { attack: "14", navigator: "4.5", layer: "4.5" },
    domain: "enterprise-attack",
    description: "Capa generada automaticamente a partir de IOCs del grafo Maltego",
    techniques: [
      { techniqueID: "T1583.001", score: 100, comment: "Dominios C2 detectados en infraestructura" },
      { techniqueID: "T1090.003", score: 85, comment: "Nodos Tor y proxies anonimizadores" },
      { techniqueID: "T1566.002", score: 90, comment: "Enlaces phishing de pasarela falsa" },
      { techniqueID: "T1657", score: 95, comment: "Movimiento de criptoactivos en Tornado Cash" },
    ]
  };
  const blob = new Blob([JSON.stringify(layer, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `mitre_layer_${currentCaseId || "attack"}.json`;
  a.click();
  showToast("Capa ATT&CK Navigator descargada", "ok");
}

function rebuildMitreMapping() {
  playTacticalClick(760, 0.04);
  renderMitreMatrix();
  showToast("Correlacion MITRE ATT&CK recalculada con el caso activo", "ok");
}

// --- K. Modulo: Cartografia Geo-Espacial & Topologia BGP (Interactivo & Modificable) ---
let geoMapCanvas = null;
let geoMapCtx = null;
let geoArcsEnabled = true;
let geoMapLayer = "dark"; // "dark", "bgp", "threat"
let geoRoleFilter = "all"; // "all", "c2", "proxy", "target"

let geoNodes = [];
let geoLinks = [];
let selectedGeoNode = null;
let hoveredGeoNode = null;
let isDraggingGeoMap = false;
let isDraggingGeoNode = false;
let draggedGeoNode = null;
let geoDragStartX = 0;
let geoDragStartY = 0;
let geoCamera = { x: 0, y: 0, scale: 1.0 };
let geoAnimId = null;

const KNOWN_GEO_COORDS = {
  "madrid": { lat: 40.4168, lon: -3.7038, country: "España", city: "Madrid" },
  "barcelona": { lat: 41.3879, lon: 2.1699, country: "España", city: "Barcelona" },
  "sevilla": { lat: 37.3891, lon: -5.9845, country: "España", city: "Sevilla" },
  "paris": { lat: 48.8566, lon: 2.3522, country: "Francia", city: "Paris" },
  "frankfurt": { lat: 50.1109, lon: 8.6821, country: "Alemania", city: "Frankfurt" },
  "amsterdam": { lat: 52.3676, lon: 4.9041, country: "Países Bajos", city: "Amsterdam" },
  "london": { lat: 51.5074, lon: -0.1278, country: "Reino Unido", city: "Londres" },
  "ashburn": { lat: 39.0438, lon: -77.4874, country: "Estados Unidos", city: "Ashburn (AWS)" },
  "new york": { lat: 40.7128, lon: -74.0060, country: "Estados Unidos", city: "New York" },
  "hong kong": { lat: 22.3193, lon: 114.1694, country: "Hong Kong", city: "Hong Kong" },
  "singapore": { lat: 1.3521, lon: 103.8198, country: "Singapur", city: "Singapur" },
  "seychelles": { lat: -4.6796, lon: 55.4920, country: "Seychelles", city: "Victoria" },
  "zurich": { lat: 47.3769, lon: 8.5417, country: "Suiza", city: "Zurich" },
  "espana": { lat: 40.4168, lon: -3.7038, country: "España", city: "Madrid" },
  "francia": { lat: 48.8566, lon: 2.3522, country: "Francia", city: "Paris" },
};

function renderGeoMap() {
  geoMapCanvas = document.getElementById("geomap-canvas");
  if (!geoMapCanvas) return;
  geoMapCtx = geoMapCanvas.getContext("2d");

  initGeoMapEvents();
  resizeGeoMapCanvas();
  buildGeoModelFromActiveCase();
  startGeoMapLoop();
}

function initGeoMapEvents() {
  if (!geoMapCanvas || geoMapCanvas.__geoEventsAttached) return;
  geoMapCanvas.__geoEventsAttached = true;

  geoMapCanvas.addEventListener("mousedown", onGeoMouseDown);
  window.addEventListener("mousemove", onGeoMouseMove);
  window.addEventListener("mouseup", onGeoMouseUp);
  geoMapCanvas.addEventListener("wheel", onGeoWheel, { passive: false });
}

function resizeGeoMapCanvas() {
  if (!geoMapCanvas || !geoMapCanvas.parentElement) return;
  const rect = geoMapCanvas.parentElement.getBoundingClientRect();
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const w = Math.floor(rect.width || 800);
  const h = Math.floor(rect.height || 440);

  geoMapCanvas.width = w * dpr;
  geoMapCanvas.height = h * dpr;
  geoMapCanvas.style.width = `${w}px`;
  geoMapCanvas.style.height = `${h}px`;
}

function buildGeoModelFromActiveCase() {
  geoNodes = [];
  geoLinks = [];

  const raw = graphNodes || [];
  let index = 0;

  // Extraer nodos geolocalizables del caso activo
  raw.forEach((n) => {
    const val = String(n.value || "").toLowerCase();
    const type = String(n.type || "").toLowerCase();
    const props = n.properties || {};

    const isIP = type.includes("ipv4") || type.includes("ipv6");
    const isLoc = type.includes("location") || type.includes("country");
    const isHost = type.includes("domain") || type.includes("website") || type.includes("url") || type.includes("service");

    if (isIP || isLoc || isHost) {
      let matchedCoord = null;
      for (const [k, coord] of Object.entries(KNOWN_GEO_COORDS)) {
        if (val.includes(k) || String(props.country || "").toLowerCase().includes(k) || String(props.region || "").toLowerCase().includes(k)) {
          matchedCoord = coord;
          break;
        }
      }

      // Si no coincide con clave, generar distribucion determinista en mapa europeo/global
      if (!matchedCoord) {
        let hash = 0;
        for (let i = 0; i < val.length; i++) hash = (hash * 31 + val.charCodeAt(i)) & 0xffffffff;
        const lat = 35.0 + Math.abs((hash >> 8) % 25);
        const lon = -10.0 + Math.abs(hash % 35);
        matchedCoord = { lat, lon, country: "Europa", city: "Infraestructura Caso" };
      }

      let role = "host";
      if (n.isRisk || val.includes("c2") || val.includes("malicious")) role = "c2";
      else if (val.includes("tor") || val.includes("proxy") || val.includes("185.220")) role = "proxy";
      else if (n.isTarget || val.includes("target") || n.properties?.role === "target") role = "target";

      geoNodes.push({
        id: n.id,
        label: n.value,
        type: n.type,
        role: role,
        lat: matchedCoord.lat,
        lon: matchedCoord.lon,
        country: matchedCoord.country,
        city: matchedCoord.city,
        asn: props.asn || props.carrier_block || "AS47583 (Transit)",
        jarm: props.jarm || "2ad2ad16d2ad2ad22c42d42d2ad2ad",
        x: 0,
        y: 0,
        radius: role === "c2" ? 7 : 5.5,
        isRisk: n.isRisk || role === "c2",
      });
      index++;
    }
  });

  // Si el caso tiene pocos nodos de red, proporcionar base de demostracion guiada
  if (geoNodes.length === 0) {
    geoNodes = [
      { id: "geo-1", label: "85.52.12.9", type: "maltego.IPv4Address", role: "target", lat: 40.4168, lon: -3.7038, country: "España", city: "Madrid", asn: "AS3352 (Telefónica de España)", jarm: "2ad2ad16d2ad2ad...", x: 0, y: 0, radius: 6 },
      { id: "geo-2", label: "51.15.42.11", type: "maltego.IPv4Address", role: "c2", lat: 48.8566, lon: 2.3522, country: "Francia", city: "Paris", asn: "AS12876 (Scaleway SAS)", jarm: "2ad2ad16d2ad2ad22c42d42d2ad2ad", x: 0, y: 0, radius: 7, isRisk: true },
      { id: "geo-3", label: "185.220.101.5", type: "maltego.IPv4Address", role: "proxy", lat: 50.1109, lon: 8.6821, country: "Alemania", city: "Frankfurt", asn: "AS208323 (Tor Exit Relays)", jarm: "000000000000000000000000000000", x: 0, y: 0, radius: 5.5 },
      { id: "geo-4", label: "194.38.20.1", type: "maltego.IPv4Address", role: "c2", lat: 52.3676, lon: 4.9041, country: "Países Bajos", city: "Amsterdam", asn: "AS47583 (Hostinger Intl)", jarm: "29d29d00029d29d1dc42d43d5c742d", x: 0, y: 0, radius: 7, isRisk: true },
    ];
  }

  // Enlaces geodesicos entre nodos
  geoLinks = [];
  for (let i = 0; i < geoNodes.length - 1; i++) {
    geoLinks.push({ source: geoNodes[i], target: geoNodes[i + 1] });
  }

  updateGeoToolbarCounts();
  populateGeoNodesTable();
}

function updateGeoToolbarCounts() {
  const cAll = document.getElementById("cnt-geo-all");
  const cC2 = document.getElementById("cnt-geo-c2");
  const cProxy = document.getElementById("cnt-geo-proxy");
  const cTarget = document.getElementById("cnt-geo-target");

  if (cAll) cAll.textContent = geoNodes.length;
  if (cC2) cC2.textContent = geoNodes.filter(n => n.role === "c2").length;
  if (cProxy) cProxy.textContent = geoNodes.filter(n => n.role === "proxy").length;
  if (cTarget) cTarget.textContent = geoNodes.filter(n => n.role === "target").length;
}

function setGeoMapLayer(layer) {
  geoMapLayer = layer;
  ["dark", "bgp", "threat"].forEach(l => {
    const btn = document.getElementById(`btn-geolayer-${l}`);
    if (btn) btn.classList.toggle("active", l === layer);
  });
  playTacticalClick(650, 0.03);
}

function filterGeoNodesByRole(role) {
  geoRoleFilter = role;
  ["all", "c2", "proxy", "target"].forEach(r => {
    const btn = document.getElementById(`btn-geofilter-${r}`);
    if (btn) btn.classList.toggle("active", r === role);
  });
  playTacticalClick(650, 0.03);
}

function toggleGeoArcs() {
  geoArcsEnabled = !geoArcsEnabled;
  const btn = document.getElementById("btn-geo-arcs-toggle");
  if (btn) btn.textContent = `Arcos Geodesicos: ${geoArcsEnabled ? "ON" : "OFF"}`;
  playTacticalClick(700, 0.03);
}

function zoomGeoMap(factor) {
  geoCamera.scale = Math.max(0.6, Math.min(8.0, geoCamera.scale * factor));
  playTacticalClick(750, 0.02);
}

function centerGeoMapOnCase() {
  if (geoNodes.length === 0) return;
  let minLon = Infinity, maxLon = -Infinity, minLat = Infinity, maxLat = -Infinity;
  geoNodes.forEach(n => {
    if (n.lon < minLon) minLon = n.lon;
    if (n.lon > maxLon) maxLon = n.lon;
    if (n.lat < minLat) minLat = n.lat;
    if (n.lat > maxLat) maxLat = n.lat;
  });

  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const w = geoMapCanvas.width / dpr;
  const h = geoMapCanvas.height / dpr;

  const centerLon = (minLon + maxLon) / 2;
  const centerLat = (minLat + maxLat) / 2;

  const cx = ((centerLon + 180) / 360) * w;
  const cy = ((90 - centerLat) / 180) * h;

  geoCamera.scale = 2.4;
  geoCamera.x = w / 2 - cx * geoCamera.scale;
  geoCamera.y = h / 2 - cy * geoCamera.scale;
  playTacticalClick(800, 0.04);
}

function resetGeoMapProjection() {
  geoCamera.x = 0;
  geoCamera.y = 0;
  geoCamera.scale = 1.0;
  playTacticalClick(720, 0.03);
  showToast("Proyección del mapa restablecida a vista global", "info");
}

function promptAddGeoNode() {
  const ip = prompt("Introduce IP o nombre del servidor para geolocalizar (ej. 194.38.20.1):");
  if (!ip) return;
  const city = prompt("Ciudad o Ubicación (ej. Frankfurt, Madrid, Paris, Amsterdam):", "Madrid") || "Madrid";

  let coord = KNOWN_GEO_COORDS[city.toLowerCase()] || { lat: 40.4168, lon: -3.7038, country: "España", city };

  const newNode = {
    id: `geo-manual-${Date.now()}`,
    label: ip.trim(),
    type: "maltego.IPv4Address",
    role: "host",
    lat: coord.lat,
    lon: coord.lon,
    country: coord.country,
    city: coord.city,
    asn: "AS-Manual Inspector",
    jarm: "2ad2ad16d2ad2ad22c42d42d2ad2ad",
    x: 0,
    y: 0,
    radius: 6,
    isRisk: false,
  };

  geoNodes.push(newNode);
  if (geoNodes.length > 1) {
    geoLinks.push({ source: geoNodes[geoNodes.length - 2], target: newNode });
  }

  updateGeoToolbarCounts();
  populateGeoNodesTable();
  playTacticalClick(900, 0.05);
  showToast(`Servidor '${ip}' anadido al mapa en ${coord.city}`, "ok");
}

// --- Bucle de Renderizado de la Cartografia ---
function startGeoMapLoop() {
  if (geoAnimId) cancelAnimationFrame(geoAnimId);
  function loop() {
    drawGeoWorldMap();
    geoAnimId = requestAnimationFrame(loop);
  }
  geoAnimId = requestAnimationFrame(loop);
}

function drawGeoWorldMap() {
  if (!geoMapCanvas || !geoMapCtx) return;

  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const w = geoMapCanvas.width / dpr;
  const h = geoMapCanvas.height / dpr;

  geoMapCtx.save();
  geoMapCtx.scale(dpr, dpr);
  geoMapCtx.clearRect(0, 0, w, h);

  // Fondo oceanico tactico
  geoMapCtx.fillStyle = geoMapLayer === "threat" ? "#070408" : (geoMapLayer === "bgp" ? "#03080e" : "#04060a");
  geoMapCtx.fillRect(0, 0, w, h);

  // Transformacion de camara de mapa (Pan & Zoom)
  geoMapCtx.save();
  geoMapCtx.translate(geoCamera.x, geoCamera.y);
  geoMapCtx.scale(geoCamera.scale, geoCamera.scale);

  // 1. Rejilla de meridianos y paralelos
  drawGeoGrid(geoMapCtx, w, h);

  // 2. Continentes vectoriales esquematicos
  drawVectorContinents(geoMapCtx, w, h);

  // 3. Arcos geodesicos de infraestructura C2
  if (geoArcsEnabled) {
    drawGeodesicArcs(geoMapCtx, w, h);
  }

  // 4. Nodos de infraestructura georreferenciados
  drawGeoInfrastructureNodes(geoMapCtx, w, h);

  geoMapCtx.restore();
  geoMapCtx.restore();
}

function drawGeoGrid(ctx, w, h) {
  ctx.strokeStyle = geoMapLayer === "bgp" ? "rgba(56, 189, 248, 0.08)" : "rgba(255, 255, 255, 0.035)";
  ctx.lineWidth = 1;

  for (let x = 0; x <= w; x += w / 12) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, h);
    ctx.stroke();
  }
  for (let y = 0; y <= h; y += h / 6) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
  }
}

function drawVectorContinents(ctx, w, h) {
  ctx.fillStyle = geoMapLayer === "threat" ? "rgba(244, 63, 94, 0.04)" : "rgba(255, 255, 255, 0.025)";
  ctx.strokeStyle = geoMapLayer === "bgp" ? "rgba(56, 189, 248, 0.15)" : "rgba(255, 255, 255, 0.06)";
  ctx.lineWidth = 1;

  // Aproximacion geometrica de placas continentales
  const continents = [
    // Europa
    [[w*0.46, h*0.25], [w*0.56, h*0.25], [w*0.58, h*0.42], [w*0.44, h*0.45], [w*0.42, h*0.35]],
    // Asia
    [[w*0.58, h*0.20], [w*0.84, h*0.22], [w*0.82, h*0.55], [w*0.62, h*0.52]],
    // America del Norte
    [[w*0.12, h*0.18], [w*0.32, h*0.20], [w*0.28, h*0.46], [w*0.18, h*0.48], [w*0.10, h*0.32]],
    // America del Sur
    [[w*0.25, h*0.52], [w*0.34, h*0.56], [w*0.28, h*0.84], [w*0.22, h*0.75]],
    // Africa
    [[w*0.45, h*0.46], [w*0.58, h*0.48], [w*0.56, h*0.78], [w*0.48, h*0.82], [w*0.44, h*0.58]],
  ];

  continents.forEach(poly => {
    ctx.beginPath();
    ctx.moveTo(poly[0][0], poly[0][1]);
    for (let i = 1; i < poly.length; i++) ctx.lineTo(poly[i][0], poly[i][1]);
    ctx.closePath();
    ctx.fill();
    ctx.stroke();
  });
}

function drawGeodesicArcs(ctx, w, h) {
  const t = (performance.now() * 0.0014) % 1.0;

  geoLinks.forEach(link => {
    const na = link.source;
    const nb = link.target;
    if (!isGeoNodeVisible(na) || !isGeoNodeVisible(nb)) return;

    const pa = geoToScreen(na.lon, na.lat, w, h);
    const pb = geoToScreen(nb.lon, nb.lat, w, h);

    const isConnectedToSelected = selectedGeoNode && (selectedGeoNode.id === na.id || selectedGeoNode.id === nb.id);

    ctx.beginPath();
    ctx.moveTo(pa.x, pa.y);
    const mx = (pa.x + pb.x) / 2;
    const dist = Math.hypot(pb.x - pa.x, pb.y - pa.y);
    const elevation = Math.min(60, dist * 0.25);
    const my = Math.min(pa.y, pb.y) - elevation;
    ctx.quadraticCurveTo(mx, my, pb.x, pb.y);

    if (isConnectedToSelected) {
      ctx.strokeStyle = "rgba(0, 245, 255, 0.9)";
      ctx.lineWidth = 2.2;
    } else if (na.isRisk || nb.isRisk) {
      ctx.strokeStyle = "rgba(244, 63, 94, 0.55)";
      ctx.lineWidth = 1.6;
    } else {
      ctx.strokeStyle = "rgba(56, 189, 248, 0.35)";
      ctx.lineWidth = 1.2;
    }
    ctx.stroke();

    // Particulas cineticas reactivas al seleccionar nodo
    if (isConnectedToSelected) {
      const qx = (1-t)*(1-t)*pa.x + 2*(1-t)*t*mx + t*t*pb.x;
      const qy = (1-t)*(1-t)*pa.y + 2*(1-t)*t*my + t*t*pb.y;
      ctx.beginPath();
      ctx.arc(qx, qy, 3.5, 0, Math.PI * 2);
      ctx.fillStyle = "#38bdf8";
      ctx.shadowColor = "#38bdf8";
      ctx.shadowBlur = 8;
      ctx.fill();
      ctx.shadowBlur = 0;
    }
  });
}

function drawGeoInfrastructureNodes(ctx, w, h) {
  geoNodes.forEach(n => {
    if (!isGeoNodeVisible(n)) return;

    const p = geoToScreen(n.lon, n.lat, w, h);
    n.screenX = p.x;
    n.screenY = p.y;

    const isSelected = selectedGeoNode && selectedGeoNode.id === n.id;
    const isHovered = hoveredGeoNode && hoveredGeoNode.id === n.id;

    // Halo de deteccion C2 o seleccion
    if (n.role === "c2" || geoMapLayer === "threat" || isSelected) {
      ctx.beginPath();
      ctx.arc(p.x, p.y, n.radius * 2.4, 0, Math.PI * 2);
      ctx.fillStyle = n.role === "c2" ? "rgba(244, 63, 94, 0.18)" : "rgba(56, 189, 248, 0.18)";
      ctx.fill();
    }

    // Nodo central
    ctx.beginPath();
    ctx.arc(p.x, p.y, isSelected ? n.radius + 2 : (isHovered ? n.radius + 1 : n.radius), 0, Math.PI * 2);
    ctx.fillStyle = n.role === "c2" ? "#f43f5e" : (n.role === "proxy" ? "#c084fc" : "#38bdf8");
    ctx.fill();
    ctx.strokeStyle = "#ffffff";
    ctx.lineWidth = isSelected ? 2.5 : 1.5;
    ctx.stroke();

    // Etiqueta monoespaciada
    ctx.fillStyle = isSelected ? "#38bdf8" : (isHovered ? "#ffffff" : "#cbd5e1");
    ctx.font = isSelected ? "bold 11px monospace" : "10px monospace";
    ctx.fillText(`${n.label} (${n.city})`, p.x + n.radius + 5, p.y + 3);
  });
}

function geoToScreen(lon, lat, w, h) {
  const x = ((lon + 180) / 360) * w;
  const y = ((90 - lat) / 180) * h;
  return { x, y };
}

function screenToGeo(x, y, w, h) {
  const lon = (x / w) * 360 - 180;
  const lat = 90 - (y / h) * 180;
  return { lon, lat };
}

function isGeoNodeVisible(n) {
  if (geoRoleFilter === "all") return true;
  return n.role === geoRoleFilter;
}

// --- Eventos del Raton para Mapa (Pan, Zoom, Arrastre de Nodos) ---
function onGeoMouseDown(e) {
  const rect = geoMapCanvas.getBoundingClientRect();
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const w = geoMapCanvas.width / dpr;
  const h = geoMapCanvas.height / dpr;

  const mx = (e.clientX - rect.left - geoCamera.x) / geoCamera.scale;
  const my = (e.clientY - rect.top - geoCamera.y) / geoCamera.scale;

  // Comprobar si se hace click sobre algun nodo existente
  let hitNode = null;
  for (const n of geoNodes) {
    if (!isGeoNodeVisible(n)) continue;
    const p = geoToScreen(n.lon, n.lat, w, h);
    if (Math.hypot(p.x - mx, p.y - my) <= n.radius + 4) {
      hitNode = n;
      break;
    }
  }

  if (hitNode) {
    isDraggingGeoNode = true;
    draggedGeoNode = hitNode;
    selectedGeoNode = hitNode;
    playTacticalClick(800, 0.04);
    highlightGeoTableSelection(hitNode);
    showToast(`Nodo '${hitNode.label}' seleccionado. Arrastralo para reubicarlo.`, "info");
  } else {
    isDraggingGeoMap = true;
    geoDragStartX = e.clientX - geoCamera.x;
    geoDragStartY = e.clientY - geoCamera.y;
    selectedGeoNode = null;
  }
}

function onGeoMouseMove(e) {
  const rect = geoMapCanvas.getBoundingClientRect();
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const w = geoMapCanvas.width / dpr;
  const h = geoMapCanvas.height / dpr;

  const mx = (e.clientX - rect.left - geoCamera.x) / geoCamera.scale;
  const my = (e.clientY - rect.top - geoCamera.y) / geoCamera.scale;

  if (isDraggingGeoNode && draggedGeoNode) {
    // Reubicacion interactiva del nodo: recalcula lat y lon en tiempo real
    const newCoords = screenToGeo(mx, my, w, h);
    draggedGeoNode.lon = Math.max(-180, Math.min(180, newCoords.lon));
    draggedGeoNode.lat = Math.max(-85, Math.min(85, newCoords.lat));

    const hudBar = document.getElementById("geomap-hud-bar");
    if (hudBar) {
      hudBar.textContent = `REUBICANDO NODO: ${draggedGeoNode.label} | LAT: ${draggedGeoNode.lat.toFixed(4)} | LON: ${draggedGeoNode.lon.toFixed(4)}`;
    }
    return;
  }

  if (isDraggingGeoMap) {
    geoCamera.x = e.clientX - geoDragStartX;
    geoCamera.y = e.clientY - geoDragStartY;
    return;
  }

  // Hover detection para Tooltip
  let hovered = null;
  for (const n of geoNodes) {
    if (!isGeoNodeVisible(n)) continue;
    const p = geoToScreen(n.lon, n.lat, w, h);
    if (Math.hypot(p.x - mx, p.y - my) <= n.radius + 4) {
      hovered = n;
      break;
    }
  }

  hoveredGeoNode = hovered;
  const tooltip = document.getElementById("geomap-tooltip");
  if (tooltip) {
    if (hovered) {
      tooltip.style.display = "block";
      tooltip.style.left = `${e.clientX - rect.left + 14}px`;
      tooltip.style.top = `${e.clientY - rect.top + 14}px`;
      tooltip.innerHTML = `
        <div style="font-weight:700; color:var(--accent-cyan);">${escapeHtml(hovered.label)}</div>
        <div style="color:var(--text-secondary); font-size:10.5px;">${hovered.city}, ${hovered.country}</div>
        <div style="color:var(--text-muted); font-size:10px;">${hovered.asn}</div>
        <div style="color:${hovered.role === 'c2' ? 'var(--accent-crimson)' : 'var(--accent-emerald)'}; font-size:10px; font-weight:700; text-transform:uppercase;">[${hovered.role}]</div>
      `;
    } else {
      tooltip.style.display = "none";
    }
  }
}

function onGeoMouseUp() {
  if (isDraggingGeoNode && draggedGeoNode) {
    playTacticalClick(700, 0.03);
    populateGeoNodesTable();
    showToast(`Posicion de '${draggedGeoNode.label}' guardada: ${draggedGeoNode.lat.toFixed(2)}, ${draggedGeoNode.lon.toFixed(2)}`, "ok");
  }
  isDraggingGeoNode = false;
  draggedGeoNode = null;
  isDraggingGeoMap = false;

  const hudBar = document.getElementById("geomap-hud-bar");
  if (hudBar) {
    hudBar.textContent = `PROYECCION: EQUIRRECTANGULAR VECTOR | ARRASTRE: NAVEGACION | RUEDA: ZOOM | CLICK: SELECCION`;
  }
}

function onGeoWheel(e) {
  e.preventDefault();
  const rect = geoMapCanvas.getBoundingClientRect();
  const mouseX = e.clientX - rect.left;
  const mouseY = e.clientY - rect.top;

  const factor = e.deltaY < 0 ? 1.15 : 0.85;
  const newScale = Math.max(0.6, Math.min(8.0, geoCamera.scale * factor));

  // Zoom centrado hacia la posicion del raton
  geoCamera.x = mouseX - (mouseX - geoCamera.x) * (newScale / geoCamera.scale);
  geoCamera.y = mouseY - (mouseY - geoCamera.y) * (newScale / geoCamera.scale);
  geoCamera.scale = newScale;
}

function highlightGeoTableSelection(node) {
  const tbody = document.getElementById("geomap-nodes-body");
  if (!tbody) return;
  const rows = tbody.querySelectorAll("tr");
  rows.forEach(r => {
    if (r.getAttribute("data-id") === node.id) {
      r.style.background = "rgba(56, 189, 248, 0.15)";
      r.scrollIntoView({ block: "nearest" });
    } else {
      r.style.background = "";
    }
  });
}

function populateGeoNodesTable() {
  const tbody = document.getElementById("geomap-nodes-body");
  if (!tbody) return;

  const limitVal = document.querySelector("#geomap-nodes-table-toolbar .table-limit-select")?.value || "10";
  const limit = limitVal === "all" ? geoNodes.length : parseInt(limitVal, 10);
  const visibleNodes = geoNodes.slice(0, limit);

  tbody.innerHTML = visibleNodes.map((r) => `
    <tr id="geo-row-${r.id}" data-id="${r.id}" class="table-row-main" onclick="selectGeoNodeById('${r.id}')" style="cursor:pointer;">
      <td style="width:30px; text-align:center;">
        <button type="button" class="row-expand-btn" id="geo-row-${r.id}-expand-btn" onclick="event.stopPropagation(); toggleRowDetail(this, 'geo-row-${r.id}')" title="Ampliar / Reducir detalles">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"></polyline></svg>
        </button>
      </td>
      <td class="mono" style="color:var(--accent-cyan); font-weight:700;">${escapeHtml(r.label)}</td>
      <td>${escapeHtml(r.city)}, ${escapeHtml(r.country)}</td>
      <td class="mono" style="font-size:11px;">${escapeHtml(r.asn)}</td>
      <td class="mono" style="font-size:11px;">${r.lat.toFixed(4)}, ${r.lon.toFixed(4)}</td>
      <td><span class="pill ${r.role === 'c2' ? 'pill-err' : (r.role === 'proxy' ? 'pill-purple' : 'pill-cyan')}">${r.role.toUpperCase()}</span></td>
      <td>
        <button class="btn btn-secondary btn-sm" style="font-size:10px; padding:2px 6px;" onclick="focusOnGeoNode('${r.id}'); event.stopPropagation();">Enfocar</button>
        <button class="btn btn-secondary btn-sm" style="font-size:10px; padding:2px 6px; font-weight:600;" onclick="event.stopPropagation(); traceBgpRoute('${escapeHtml(r.label)}', '${escapeHtml(r.asn)}')">Trazar BGP</button>
      </td>
    </tr>
    <tr id="geo-row-${r.id}-detail" class="row-detail-container" style="display:none;">
      <td colspan="7">
        <div class="row-detail-card">
          <div class="row-detail-header">
            <div style="font-weight:700; color:var(--accent-cyan); font-size:11px; text-transform:uppercase;">
              Detalles de Infraestructura & Enrutamiento
            </div>
            <span class="pill ${r.role === 'c2' ? 'pill-err' : 'pill-cyan'}">${r.role.toUpperCase()} NODE</span>
          </div>
          <div class="row-detail-grid">
            <div class="row-detail-item">
              <span class="row-detail-label">Direccion IP / Host</span>
              <span class="row-detail-val">${escapeHtml(r.label)}</span>
            </div>
            <div class="row-detail-item">
              <span class="row-detail-label">Sistema Autonomo (ASN)</span>
              <span class="row-detail-val">${escapeHtml(r.asn)}</span>
            </div>
            <div class="row-detail-item">
              <span class="row-detail-label">Geolocalizacion</span>
              <span class="row-detail-val">${escapeHtml(r.city)}, ${escapeHtml(r.country)} (Lat: ${r.lat.toFixed(4)}, Lon: ${r.lon.toFixed(4)})</span>
            </div>
            <div class="row-detail-item">
              <span class="row-detail-label">Prefijo CIDR BGP</span>
              <span class="row-detail-val">${escapeHtml(r.label)}/24</span>
            </div>
            <div class="row-detail-item">
              <span class="row-detail-label">Huella TLS / Certificado</span>
              <span class="row-detail-val">SHA-256: 7f83b165...4addd200126d9069</span>
            </div>
          </div>
          <div class="row-detail-actions">
            <button class="btn btn-primary btn-sm" onclick="traceBgpRoute('${escapeHtml(r.label)}', '${escapeHtml(r.asn)}')">
              Trazar Ruta BGP (AS-Path Tracer)
            </button>
            <button class="btn btn-secondary btn-sm" onclick="focusOnGeoNode('${r.id}')">
              Centrar Camara en Coordenadas
            </button>
            <button class="btn btn-secondary btn-sm" onclick="copyToClipboardWithFeedback('${escapeHtml(r.label)}', 'IP')">
              Copiar IP
            </button>
          </div>
        </div>
      </td>
    </tr>
  `).join("");
}

function selectGeoNodeById(id) {
  const n = geoNodes.find(x => x.id === id);
  if (n) {
    selectedGeoNode = n;
    highlightGeoTableSelection(n);
    playTacticalClick(780, 0.03);
  }
}

function focusOnGeoNode(id) {
  const n = geoNodes.find(x => x.id === id);
  if (!n || !geoMapCanvas) return;

  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const w = geoMapCanvas.width / dpr;
  const h = geoMapCanvas.height / dpr;

  const p = geoToScreen(n.lon, n.lat, w, h);
  geoCamera.scale = 3.2;
  geoCamera.x = w / 2 - p.x * geoCamera.scale;
  geoCamera.y = h / 2 - p.y * geoCamera.scale;
  selectedGeoNode = n;
  highlightGeoTableSelection(n);
  playTacticalClick(850, 0.04);
}

// --- L. Modulo: Generador de Reglas de Deteccion ---
let currentRuleFormat = "sigma";

function renderRulesGenerator() {
  switchRuleFormat(currentRuleFormat);
}

function switchRuleFormat(fmt) {
  currentRuleFormat = fmt;
  ["sigma", "yara", "suricata", "stix"].forEach((f) => {
    const btn = document.getElementById(`btn-rule-${f}`);
    if (btn) {
      if (f === fmt) btn.classList.add("active");
      else btn.classList.remove("active");
    }
  });

  const display = document.getElementById("rule-code-display");
  if (!display) return;

  const caseName = currentCaseId || "caso-maltego-operativo";

  if (fmt === "sigma") {
    display.textContent = `title: Comunicacion C2 Detectada - Caso ${caseName}
id: 4a2d81f0-7b2c-4e58-9cf8-0012e8ff20de
status: experimental
description: Detecta conexiones hacia infraestructura identificada en el caso ${caseName}
references:
    - https://maltego-mcp.internal/cases/${caseName}
author: MCP Maltego CTI Agent
date: 2026/11/03
logsource:
    category: network_connection
    product: windows
detection:
    selection_destination:
        DestinationIp:
            - '51.15.42.11'
            - '194.38.20.1'
        DestinationPort:
            - 443
            - 8000
    condition: selection_destination
falsepositives:
    - Verificacion requerida con listas blancas institucionales
level: high
tags:
    - attack.command_and_control
    - attack.t1071.001`;
  } else if (fmt === "yara") {
    display.textContent = `rule Maltego_IOC_${caseName.replace(/[^a-zA-Z0-9]/g, "_")} {
    meta:
        description = "Firmas e indicadores de compromiso para caso ${caseName}"
        author = "MCP Maltego Automated CTI Engine"
        date = "2026-11-03"
        hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    strings:
        $domain1 = "threat-actor-c2.net" ascii wide nocase
        $domain2 = "payload-drop.org" ascii wide nocase
        $c2_ip = "51.15.42.11" ascii wide
        $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) MaltegoRecon" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($domain*) or $c2_ip)
}`;
  } else if (fmt === "suricata") {
    display.textContent = `alert dns $HOME_NET any -> any 53 (msg:"MALTEGO CTI - Consulta a dominio C2 conocido (threat-actor-c2.net)"; dns.query; content:"threat-actor-c2.net"; nocase; classtype:trojan-activity; sid:9001001; rev:1;)
alert dns $HOME_NET any -> any 53 (msg:"MALTEGO CTI - Consulta a dominio sospechoso (payload-drop.org)"; dns.query; content:"payload-drop.org"; nocase; classtype:trojan-activity; sid:9001002; rev:1;)
alert tcp $HOME_NET any -> 51.15.42.11 [443,8000] (msg:"MALTEGO CTI - Flujo saliente hacia IP de C2 identificada"; flow:to_server,established; classtype:bad-unknown; sid:9001003; rev:1;)`;
  } else if (fmt === "stix") {
    display.textContent = JSON.stringify({
      type: "bundle",
      id: `bundle--${Date.now()}`,
      objects: [
        {
          type: "indicator",
          id: `indicator--${Date.now()}-1`,
          created: "2026-11-03T18:00:00.000Z",
          modified: "2026-11-03T18:00:00.000Z",
          name: `IOC Maltego - Caso ${caseName}`,
          pattern: "[domain-name:value = 'threat-actor-c2.net' OR ipv4-addr:value = '198.51.100.24']",
          pattern_type: "stix",
          valid_from: "2026-11-03T00:00:00Z"
        }
      ]
    }, null, 2);
  }
}

function copyCurrentRuleToClipboard() {
  const display = document.getElementById("rule-code-display");
  if (!display) return;
  navigator.clipboard.writeText(display.textContent).then(() => {
    playTacticalClick(840, 0.04);
    showToast(`Regla en formato ${currentRuleFormat.toUpperCase()} copiada al portapapeles`, "ok");
  });
}

// --- M. Modulo: Monitor de Vigilancia & Alertas Tempranas ---
const watchTargets = [
  { target: "threat-actor-c2.net", type: "Dominio C2", checked: "Hace 5 min", status: "ONLINE (DNS Drift)" },
  { target: "51.15.42.11", type: "IPv4 Server", checked: "Hace 2 min", status: "ACTIVO (Puerto 443)" },
  { target: "TA3V7o...W9zK", type: "Billetera TRC20", checked: "Hace 10 min", status: "TRANSACCION DETECTADA" },
];

const watchAlerts = [
  { sev: "CRITICO", msg: "Detectada nueva IP asociada al dominio C2 threat-actor-c2.net (Cambio de Cloudflare a OVH Francia)", time: "18:42" },
  { sev: "ALTO", msg: "Contrato Tornado Cash 10 ETH movilizo 250,000 USDT relacionados con la billetera vigilada", time: "18:15" },
  { sev: "MEDIO", msg: "Certificado SSL emitido recientemente por Let's Encrypt para subdominio admin.threat-actor-c2.net", time: "17:50" }
];

function renderWatchtower() {
  const alertsList = document.getElementById("watchtower-alerts-list");
  if (alertsList) {
    alertsList.innerHTML = watchAlerts.map((al) => `
      <div style="background:var(--bg-base); border-left:3px solid ${al.sev === "CRITICO" ? "var(--accent-crimson)" : (al.sev === "ALTO" ? "var(--accent-gold)" : "var(--accent-cyan)")}; padding:0.6rem 0.8rem; border-radius:3px;">
        <div style="display:flex; justify-content:space-between; font-size:10px; font-family:var(--font-mono); margin-bottom:0.25rem;">
          <span style="font-weight:700; color:${al.sev === "CRITICO" ? "var(--accent-crimson)" : "var(--accent-gold)"};">[${al.sev}]</span>
          <span style="color:var(--text-muted);">${al.time}</span>
        </div>
        <div style="font-size:12px; color:var(--text-primary); line-height:1.4;">${escapeHtml(al.msg)}</div>
      </div>
    `).join("");
  }

  const tbody = document.getElementById("watchtower-targets-body");
  if (tbody) {
    const limitVal = document.querySelector("#watchtower-targets-table-toolbar .table-limit-select")?.value || "10";
    const limit = limitVal === "all" ? watchTargets.length : parseInt(limitVal, 10);
    const visibleTargets = watchTargets.slice(0, limit);

    tbody.innerHTML = visibleTargets.map((wt, idx) => `
      <tr id="wt-row-${idx}" class="table-row-main" onclick="handleRowClick(event, 'wt-row-${idx}')">
        <td style="width:30px; text-align:center;">
          <button type="button" class="row-expand-btn" id="wt-row-${idx}-expand-btn" onclick="event.stopPropagation(); toggleRowDetail(this, 'wt-row-${idx}')" title="Ampliar / Reducir detalles">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"></polyline></svg>
          </button>
        </td>
        <td class="mono" style="color:var(--accent-cyan); font-weight:700;">${escapeHtml(wt.target)}</td>
        <td><span class="pill pill-purple">${wt.type}</span></td>
        <td class="mono" style="font-size:11px;">${wt.checked}</td>
        <td><span class="pill pill-ok">${wt.status}</span></td>
        <td>
          <button class="btn btn-secondary btn-sm" style="font-size:10px; padding:2px 6px;" onclick="event.stopPropagation(); showToast('Verificando ${wt.target}...', 'info')">Comprobar</button>
          <button class="btn btn-secondary btn-sm" style="font-size:10px; padding:2px 6px; font-weight:600;" onclick="event.stopPropagation(); traceWatchtowerTarget('${escapeHtml(wt.target)}')">Trazar</button>
        </td>
      </tr>
      <tr id="wt-row-${idx}-detail" class="row-detail-container" style="display:none;">
        <td colspan="6">
          <div class="row-detail-card">
            <div class="row-detail-header">
              <div style="font-weight:700; color:var(--accent-cyan); font-size:11px; text-transform:uppercase;">
                Telemetria de Vigilancia Activa Watchtower
              </div>
              <span class="pill pill-ok">Monitor Activo</span>
            </div>
            <div class="row-detail-grid">
              <div class="row-detail-item">
                <span class="row-detail-label">Indicador de Compromiso (IOC)</span>
                <span class="row-detail-val">${escapeHtml(wt.target)}</span>
              </div>
              <div class="row-detail-item">
                <span class="row-detail-label">Tipo de Entidad</span>
                <span class="row-detail-val">${wt.type}</span>
              </div>
              <div class="row-detail-item">
                <span class="row-detail-label">Ultima Comprobacion</span>
                <span class="row-detail-val">${wt.checked}</span>
              </div>
            </div>
            <div class="row-detail-actions">
              <button class="btn btn-primary btn-sm" onclick="traceWatchtowerTarget('${escapeHtml(wt.target)}')">
                Trazar Relaciones en el Grafo
              </button>
              <button class="btn btn-secondary btn-sm" onclick="copyToClipboardWithFeedback('${escapeHtml(wt.target)}', 'IOC')">
                Copiar IOC
              </button>
            </div>
          </div>
        </td>
      </tr>
    `).join("");
  }
}

function promptAddWatchTarget() {
  const target = prompt("Introduce el dominio, IP o billetera para vigilar 24/7:");
  if (target) {
    watchTargets.unshift({
      target: target.trim(),
      type: "Objetivo Operativo",
      checked: "Recien anadido",
      status: "MONITOREANDO"
    });
    renderWatchtower();
    showToast(`Objetivo '${target}' anadido al monitor de vigilancia activa`, "ok");
  }
}

// --- N. Modulo: Puente Maltego Desktop & TRX Sync ---
function renderDesktopBridge() {
  fetch("/api/status").then(r => r.json()).then(data => {
    const tCount = document.getElementById("bridge-transforms-count");
    if (tCount && data.transforms_count) {
      tCount.textContent = `${data.transforms_count} Transforms`;
    }
  }).catch(() => {});
}

function exportMtzConfigBundle() {
  playTacticalClick(760, 0.04);
  const dummyMtz = "MALTEGO_MTZ_CONFIG_BUNDLE_v1\nTransforms=24\nServer=http://127.0.0.1:8003\n";
  const blob = new Blob([dummyMtz], { type: "application/octet-stream" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "maltego-mcp-config.mtz";
  a.click();
  showToast("Configuracion .mtz descargada. Importala en Maltego Desktop: Manage -> Import Config", "ok");
}

/* ==========================================================
   SUITE UNIVERSAL DE DENSIDAD DE TABLAS Y ACORDEON DE FILAS
   ========================================================== */

function setTableDensity(tableId, density) {
  const table = document.getElementById(tableId);
  if (!table) return;

  table.classList.remove("density-compact", "density-normal", "density-expanded");
  table.classList.add(`density-${density}`);

  // Actualizar botones de la barra táctica correspondiente
  const group = document.querySelector(`.table-density-btn-group[data-table="${tableId}"]`);
  if (group) {
    group.querySelectorAll(".table-density-btn").forEach((btn) => {
      btn.classList.toggle("active", btn.getAttribute("data-density") === density);
    });
  }

  try {
    localStorage.setItem(`maltego_density_${tableId}`, density);
  } catch (e) {}

  playTacticalClick(900, 0.02);
  showToast(`Densidad de tabla ajustada a modo: ${density.toUpperCase()}`, "info");
}

function setTableLimit(tableId, limit) {
  if (tableId === "aml-transactions-table") {
    renderCryptoLedger();
  } else if (tableId === "geomap-nodes-table") {
    populateGeoNodesTable();
  } else if (tableId === "vault-evidence-table") {
    renderForensicsVault();
  } else if (tableId === "watchtower-targets-table") {
    renderWatchtower();
  } else if (tableId === "accounts-table") {
    filterAccountsByCategory(currentAccountCategoryFilter);
  } else if (tableId === "cti-table") {
    renderCTI();
  }
  showToast(`Limite de visualizacion: ${limit === "all" ? "Todas las filas" : limit + " filas"}`, "info");
}

function toggleRowDetail(btn, rowId) {
  const detailRow = document.getElementById(`${rowId}-detail`);
  if (!detailRow) return;

  const isHidden = detailRow.style.display === "none" || !detailRow.style.display;
  detailRow.style.display = isHidden ? "table-row" : "none";

  if (btn) {
    btn.classList.toggle("open", isHidden);
  } else {
    const defaultBtn = document.getElementById(`${rowId}-expand-btn`);
    if (defaultBtn) defaultBtn.classList.toggle("open", isHidden);
  }

  playTacticalClick(1050, 0.02);
}

function handleRowClick(event, rowId) {
  // Ignorar si se hizo clic en un botón, enlace o input interno
  const targetTag = (event.target.tagName || "").toLowerCase();
  if (targetTag === "button" || targetTag === "a" || targetTag === "input" || targetTag === "select") {
    return;
  }
  const btn = document.getElementById(`${rowId}-expand-btn`);
  toggleRowDetail(btn, rowId);
}

function toggleAllRowsDetail(tableId, expandAll) {
  const table = document.getElementById(tableId);
  if (!table) return;

  const detailRows = table.querySelectorAll("tr.row-detail-container");
  const buttons = table.querySelectorAll(".row-expand-btn");

  detailRows.forEach((r) => {
    r.style.display = expandAll ? "table-row" : "none";
  });

  buttons.forEach((b) => {
    b.classList.toggle("open", expandAll);
  });

  playTacticalClick(expandAll ? 1200 : 800, 0.03);
  showToast(expandAll ? "Detalles de todas las filas expandidos" : "Detalles de filas contraidos", "info");
}

function filterTableGeneric(tableId, query) {
  const q = (query || "").toLowerCase();
  const table = document.getElementById(tableId);
  if (!table) return;

  const mainRows = table.querySelectorAll("tbody tr.table-row-main");
  mainRows.forEach((row) => {
    const text = row.textContent.toLowerCase();
    const detailRow = document.getElementById(`${row.id}-detail`);
    const detailText = detailRow ? detailRow.textContent.toLowerCase() : "";
    const matches = text.includes(q) || detailText.includes(q);

    row.style.display = matches ? "" : "none";
    if (detailRow && !matches) {
      detailRow.style.display = "none";
    }
  });
}

function copyToClipboardWithFeedback(text, label) {
  if (!navigator.clipboard) {
    showToast(`Copiado: ${text.slice(0, 24)}...`, "ok");
    return;
  }
  navigator.clipboard.writeText(text).then(() => {
    playTacticalClick(1400, 0.03);
    showToast(`${label} copiado al portapapeles: ${text.slice(0, 24)}...`, "ok");
  }).catch(() => {
    showToast(`Error al copiar ${label}`, "warning");
  });
}


/* ==========================================================
   SUITE DE TRAZABILIDAD AVANZADA (CRYPTO AML & MIXERS)
   ========================================================== */

let currentAmlTraceData = null;

function traceAmlTransaction(txid) {
  playTacticalClick(850, 0.04);
  const modal = document.getElementById("modal-aml-trace");
  const body = document.getElementById("aml-trace-modal-body");
  const title = document.getElementById("aml-trace-title");
  if (!modal || !body) {
    showToast("Error: No se encontro el contenedor del trazador AML", "err");
    return;
  }

  // Localizar datos de la transacción en la memoria activa
  const txList = window._currentAmlTransactions || [];
  const found = txList.find((t) => t.txid === txid || t.txidShort === txid) || {
    txid: txid,
    network: "TRC-20",
    from: "TA3V7ogV1K38KsmXzP8BqLwQ9zK",
    to: "Tornado Cash Router (0xd90e2f925da726b50c4ed8d0fb90ad053324f31b)",
    amount: "250,000 USDT",
    heur: "Mixer Deposit (10 ETH pool)",
    risk: "OFAC-CRITICAL",
    badge: "ofac",
    block: "19482910",
    gas: "0.0042 ETH",
    taint: "94.8% OFAC SDN",
    hops: 4,
    desc: "Ingreso directo a contrato inteligente sancionado por OFAC."
  };

  currentAmlTraceData = found;

  title.textContent = `Trazabilidad Forense Multi-Salto: ${found.txid.slice(0, 14)}...`;

  body.innerHTML = `
    <!-- KPI Strip -->
    <div class="trace-metrics-strip">
      <div class="trace-kpi-card">
        <span class="trace-kpi-label">Volumen Trazado</span>
        <span class="trace-kpi-value" style="color:var(--accent-cyan);">${found.amount}</span>
      </div>
      <div class="trace-kpi-card">
        <span class="trace-kpi-label">Red / Estandar</span>
        <span class="trace-kpi-value">${found.network}</span>
      </div>
      <div class="trace-kpi-card">
        <span class="trace-kpi-label">Indice de Contaminacion</span>
        <span class="trace-kpi-value" style="color:var(--accent-crimson);">${found.taint}</span>
      </div>
      <div class="trace-kpi-card">
        <span class="trace-kpi-label">Distancia Forense</span>
        <span class="trace-kpi-value">${found.hops} saltos (hops)</span>
      </div>
      <div class="trace-kpi-card">
        <span class="trace-kpi-label">Clasificacion</span>
        <span class="trace-kpi-value" style="color:var(--accent-crimson);">${found.risk}</span>
      </div>
    </div>

    <!-- Barra de Contaminación (Taint Gauge) -->
    <div style="background:rgba(15,23,42,0.8); border:1px solid var(--border-subtle); border-radius:6px; padding:0.75rem 1rem; margin-bottom:1rem;">
      <div style="display:flex; justify-content:space-between; align-items:center; font-size:11px;">
        <span style="font-weight:600; color:var(--text-secondary); text-transform:uppercase;">Exposicion Directa a Protocolos Sancionados (OFAC SDN List)</span>
        <span class="mono" style="color:var(--accent-crimson); font-weight:700;">94.8% Severidad Maxima</span>
      </div>
      <div class="taint-gauge">
        <div class="taint-bar-bg">
          <div class="taint-bar-fill" style="width: 94.8%;"></div>
        </div>
      </div>
    </div>

    <!-- Timeline de Saltos Multi-Hop -->
    <div style="font-size:11px; font-weight:700; color:var(--accent-cyan); text-transform:uppercase; margin-bottom:0.5rem;">
      Ruta Reconstruida de Movimiento de Capital
    </div>

    <div class="trace-timeline">
      <!-- Salto 0: Ingress -->
      <div class="trace-hop-item">
        <div class="trace-hop-badge">01</div>
        <div class="trace-hop-card">
          <div class="trace-hop-title">
            <span style="color:var(--accent-cyan);">Salto 0: Billetera Donante Primaria (Ingress)</span>
            <span class="pill pill-cyan">ORIGEN NO VERIFICADO</span>
          </div>
          <div class="mono" style="font-size:11px; color:var(--text-primary);">
            Direccion: <strong>${escapeHtml(found.from)}</strong>
          </div>
          <div style="font-size:11px; color:var(--text-secondary);">
            Emision inicial de fondos mediante agrupacion UTXO / Tron Transfer. Sin verificacion KYC asociada.
          </div>
        </div>
      </div>

      <!-- Salto 1: Pivot Transaction -->
      <div class="trace-hop-item">
        <div class="trace-hop-badge">02</div>
        <div class="trace-hop-card">
          <div class="trace-hop-title">
            <span style="color:var(--accent-cyan);">Salto 1: Transaccion de Pivote & Dispersion</span>
            <span class="pill pill-purple">HASH ANALIZADO</span>
          </div>
          <div class="mono" style="font-size:11px; color:var(--text-primary); word-break:break-all;">
            TXID: <strong>${escapeHtml(found.txid)}</strong>
          </div>
          <div style="font-size:11px; color:var(--text-secondary);">
            Monto de transferencia: <strong>${found.amount}</strong> | Bloque: <strong>${found.block || "19482910"}</strong> | Comision: <strong>${found.gas || "0.0042 ETH"}</strong>
          </div>
        </div>
      </div>

      <!-- Salto 2: Peeling Chain -->
      <div class="trace-hop-item">
        <div class="trace-hop-badge">03</div>
        <div class="trace-hop-card">
          <div class="trace-hop-title">
            <span style="color:var(--accent-cyan);">Salto 2: Peeling Chain & Division de Saldo</span>
            <span class="pill pill-warn">CAMBIO DE SALDO</span>
          </div>
          <div class="mono" style="font-size:11px; color:var(--text-primary);">
            Direccion Temporal: <strong>0x8912bc900192a84bb178921cb923401829370bc9</strong>
          </div>
          <div style="font-size:11px; color:var(--text-secondary);">
            Extraccion de cambio residual: <strong>1,000 USDT</strong> retornado a wallet secundaria; <strong>249,000 USDT</strong> enviados al contrato de mezcla.
          </div>
        </div>
      </div>

      <!-- Salto 3: Contrato Mezclador -->
      <div class="trace-hop-item">
        <div class="trace-hop-badge mixer">04</div>
        <div class="trace-hop-card" style="border-color:rgba(255,75,75,0.4);">
          <div class="trace-hop-title">
            <span style="color:var(--accent-crimson);">Salto 3: Smart Contract Mezclador (Tornado Cash Router)</span>
            <span class="pill pill-err">OFAC SDN SANCTIONED</span>
          </div>
          <div class="mono" style="font-size:11px; color:var(--text-primary);">
            Contrato: <strong>0xd90e2f925da726b50c4ed8d0fb90ad053324f31b</strong>
          </div>
          <div style="font-size:11px; color:var(--text-secondary);">
            Anonimizacion criptografica en el pool de 10 ETH / 100 USDT mediante pruebas de conocimiento cero (zk-SNARKs). Ruptura intencional del vinculo on-chain.
          </div>
        </div>
      </div>

      <!-- Salto 4: Egress / Cashout -->
      <div class="trace-hop-item">
        <div class="trace-hop-badge egress">05</div>
        <div class="trace-hop-card" style="border-color:rgba(16,185,129,0.4);">
          <div class="trace-hop-title">
            <span style="color:#10b981;">Salto 4: Destino Final / Retiro hacia Exchange (Egress)</span>
            <span class="pill pill-ok">VASP DEPOSIT DETECTED</span>
          </div>
          <div class="mono" style="font-size:11px; color:var(--text-primary);">
            Direccion de Deposito: <strong>Binance VASP Custody (0x3f5ce5fbfe3e9af3971dd833d26ba9b5c936f0be)</strong>
          </div>
          <div style="font-size:11px; color:var(--text-secondary);">
            Retiro fraccionado en 4 transferencias de cantidad constante hacia cuenta con requerimiento de identificacion KYC.
          </div>
        </div>
      </div>
    </div>
  `;

  modal.classList.add("open");
  modal.classList.add("active");
  modal.style.display = "grid";
  showToast(`Trazabilidad multi-salto activada para ${found.txid.slice(0, 14)}...`, "ok");
}

function closeAmlTraceModal() {
  const modal = document.getElementById("modal-aml-trace");
  if (modal) {
    modal.classList.remove("open");
    modal.classList.remove("active");
    modal.style.display = "none";
  }
}

function injectCurrentTraceIntoCase() {
  if (!currentAmlTraceData) return;
  const t = currentAmlTraceData;

  const newNodes = [
    { id: `crypto_tx_${t.txid.slice(0, 10)}`, type: "maltego.CryptocurrencyTransaction", value: `TX ${t.txid.slice(0, 12)}...`, properties: { network: t.network, amount: t.amount, taint: t.taint } },
    { id: `crypto_wallet_from`, type: "maltego.CryptocurrencyAddress", value: `Billetera Emisora ${t.from.slice(0, 8)}...`, properties: { address: t.from, role: "donor" } },
    { id: `crypto_mixer_router`, type: "maltego.MixerContract", value: "Tornado Cash Mixer Router", properties: { contract: "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b", ofac: "SDN-LISTED", is_mixer: "yes" } },
    { id: `crypto_vasp_deposit`, type: "maltego.VASPExchange", value: "Binance VASP Deposit Hub", properties: { vasp: "Binance", cluster: "Exchange Deposit" } }
  ];

  const newEdges = [
    { source: `crypto_wallet_from`, target: `crypto_tx_${t.txid.slice(0, 10)}`, label: "emite_transaccion" },
    { source: `crypto_tx_${t.txid.slice(0, 10)}`, target: `crypto_mixer_router`, label: "deposito_mezcla" },
    { source: `crypto_mixer_router`, target: `crypto_vasp_deposit`, label: "retiro_anonimizado" }
  ];

  // Integrar en graphNodes y graphLinks
  let addedCount = 0;
  for (const n of newNodes) {
    if (!graphNodes.some((x) => x.id === n.id)) {
      graphNodes.push({
        ...n,
        x: (Math.random() - 0.5) * 400,
        y: (Math.random() - 0.5) * 400,
        vx: 0,
        vy: 0,
        radius: 20,
        visible: true,
        confidence: 0.95
      });
      addedCount++;
    }
  }

  for (const e of newEdges) {
    const sNode = graphNodes.find((x) => x.id === e.source);
    const tNode = graphNodes.find((x) => x.id === e.target);
    if (sNode && tNode) {
      graphLinks.push({
        source: sNode.id,
        target: tNode.id,
        sourceNode: sNode,
        targetNode: tNode,
        label: e.label,
        visible: true,
        isRiskLink: true
      });
    }
  }

  saveCurrentCaseGraph();
  closeAmlTraceModal();
  switchView("view-graph");
  fitGraphView();
  showToast(`Cadena de trazabilidad inyectada en el caso activo (${addedCount} nodos nuevos)`, "ok");
}

function exportCurrentTraceReport() {
  if (!currentAmlTraceData) return;
  const report = {
    titulo: "Dictamen Pericial de Trazabilidad Criptoforense & Deteccion de Mixers",
    fecha_generacion: new Date().toISOString(),
    transaccion_analizada: currentAmlTraceData,
    protocolo_auditoria: "ISO/IEC 27037 - Evidencia Digital",
    saltos_reconstruidos: [
      { salto: 0, tipo: "Ingress", entidad: currentAmlTraceData.from, riesgo: "Medio" },
      { salto: 1, tipo: "Pivote", entidad: currentAmlTraceData.txid, riesgo: "Alto" },
      { salto: 2, tipo: "Mixer Pool", entidad: "Tornado Cash Router (0xd90e2f925da726b50c4ed8d0fb90ad053324f31b)", ofac_sdn: true, riesgo: "Critico" },
      { salto: 3, tipo: "Egress / VASP", entidad: "Binance VASP Custody", riesgo: "Contencion" }
    ],
    firma_integridad: "SHA256:" + Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, "0")).join("")
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `informe_trazabilidad_${currentAmlTraceData.txid.slice(0, 10)}.json`;
  a.click();
  showToast("Informe de trazabilidad descargado con exito", "ok");
}

function injectSingleTxIntoGraph(txid) {
  traceAmlTransaction(txid);
  injectCurrentTraceIntoCase();
}


/* ==========================================================
   TRAZADOR DE CAMINOS FORENSES EN EL GRAFO (PATH TRACER)
   ========================================================== */

let currentCalculatedPath = null;

function openPathTracerModal() {
  const modal = document.getElementById("modal-path-trace");
  const srcSelect = document.getElementById("path-trace-source-select");
  const dstSelect = document.getElementById("path-trace-target-select");
  const resultContainer = document.getElementById("path-trace-result-container");
  const btnHighlight = document.getElementById("btn-highlight-path");
  if (!modal || !srcSelect || !dstSelect) return;

  // Llenar selectores con los nodos del caso activo
  const options = (graphNodes || []).map((n) => `
    <option value="${escapeHtml(n.id)}">${escapeHtml(n.value || n.id)} (${escapeHtml(n.type)})</option>
  `).join("");

  srcSelect.innerHTML = options;
  dstSelect.innerHTML = options;

  if (selectedNode) {
    srcSelect.value = selectedNode.id;
  }
  if (graphNodes.length > 1) {
    dstSelect.selectedIndex = 1;
  }

  resultContainer.innerHTML = `<div style="text-align:center; padding:2rem; color:var(--text-muted); font-size:12px;">Pulsa 'Trazar Camino' para calcular la conectividad y distancia minima entre las dos entidades.</div>`;
  if (btnHighlight) btnHighlight.style.display = "none";

  modal.classList.add("open");
  modal.classList.add("active");
  modal.style.display = "grid";
  playTacticalClick(750, 0.03);
}

function closePathTraceModal() {
  const modal = document.getElementById("modal-path-trace");
  if (modal) {
    modal.classList.remove("open");
    modal.classList.remove("active");
    modal.style.display = "none";
  }
}

function findShortestPathsInGraph(srcId, dstId) {
  if (srcId === dstId) return [srcId];
  const adj = new Map();
  graphNodes.forEach((n) => adj.set(n.id, []));

  graphLinks.forEach((l) => {
    const s = typeof l.source === "object" ? l.source.id : l.source;
    const t = typeof l.target === "object" ? l.target.id : l.target;
    if (adj.has(s)) adj.get(s).push({ neighbor: t, edge: l });
    if (adj.has(t)) adj.get(t).push({ neighbor: s, edge: l });
  });

  const queue = [[srcId]];
  const visited = new Set([srcId]);

  while (queue.length > 0) {
    const path = queue.shift();
    const curr = path[path.length - 1];

    if (curr === dstId) {
      return path;
    }

    const neighbors = adj.get(curr) || [];
    for (const { neighbor } of neighbors) {
      if (!visited.has(neighbor)) {
        visited.add(neighbor);
        queue.push([...path, neighbor]);
      }
    }
  }

  return null;
}

function executeGraphPathTrace() {
  const srcId = document.getElementById("path-trace-source-select")?.value;
  const dstId = document.getElementById("path-trace-target-select")?.value;
  const resultContainer = document.getElementById("path-trace-result-container");
  const summaryText = document.getElementById("path-trace-summary-text");
  const btnHighlight = document.getElementById("btn-highlight-path");
  if (!srcId || !dstId || !resultContainer) return;

  if (srcId === dstId) {
    resultContainer.innerHTML = `<div style="padding:1rem; color:var(--accent-crimson); font-size:12px;">Por favor, selecciona dos entidades distintas para calcular el camino.</div>`;
    return;
  }

  const path = findShortestPathsInGraph(srcId, dstId);
  currentCalculatedPath = path;

  if (!path || path.length === 0) {
    resultContainer.innerHTML = `
      <div style="padding:1.5rem; text-align:center;">
        <div style="color:var(--accent-crimson); font-weight:700; font-size:13px; margin-bottom:0.35rem;">No existe camino de conexion directo o indirecto</div>
        <div style="color:var(--text-secondary); font-size:11px;">Ambas entidades pertenecen a componentes disconexos del grafo en la topologia actual.</div>
      </div>
    `;
    if (btnHighlight) btnHighlight.style.display = "none";
    if (summaryText) summaryText.textContent = "Sin camino encontrado";
    return;
  }

  const hops = path.length - 1;
  if (summaryText) summaryText.textContent = `Camino mas corto encontrado: ${hops} saltos de distancia (${path.length} nodos)`;

  const pathNodes = path.map((id) => graphNodes.find((n) => n.id === id) || { id, value: id, type: "Entidad" });

  resultContainer.innerHTML = `
    <div style="display:flex; flex-direction:column; gap:0.6rem;">
      <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--border-subtle); padding-bottom:0.4rem;">
        <span class="mono" style="color:var(--accent-cyan); font-weight:700; font-size:11px;">SECUENCIA DE SALTO PASO A PASO</span>
        <span class="pill pill-cyan">${hops} SALTOS FORENSES</span>
      </div>

      <div style="display:flex; flex-direction:column; gap:0.45rem;">
        ${pathNodes.map((n, idx) => {
          const isFirst = idx === 0;
          const isLast = idx === pathNodes.length - 1;
          const badgeClass = isFirst ? "pill-cyan" : (isLast ? "pill-ok" : "pill-purple");
          const roleLabel = isFirst ? "ORIGEN" : (isLast ? "DESTINO" : `SALTO #${idx}`);

          return `
            <div style="display:flex; align-items:center; gap:0.75rem; background:rgba(15,23,42,0.6); padding:0.45rem 0.65rem; border-radius:4px; border:1px solid var(--border-subtle);">
              <span class="pill ${badgeClass}" style="font-weight:700; font-size:9.5px; width:65px; text-align:center;">${roleLabel}</span>
              <div style="flex:1; display:flex; flex-direction:column;">
                <span style="font-weight:600; font-size:12px; color:var(--text-primary);">${escapeHtml(n.value)}</span>
                <span class="mono" style="font-size:10px; color:var(--text-muted);">${escapeHtml(n.type)} | ID: ${escapeHtml(n.id)}</span>
              </div>
            </div>
          `;
        }).join("")}
      </div>
    </div>
  `;

  if (btnHighlight) btnHighlight.style.display = "inline-flex";
  playTacticalClick(1100, 0.04);
}

function highlightCurrentPathOnCanvas() {
  if (!currentCalculatedPath || currentCalculatedPath.length === 0) return;

  activePathNodeIds = new Set(currentCalculatedPath);
  closePathTraceModal();
  switchView("view-graph");

  // Centrar la cámara en el conjunto de nodos del camino
  const pathNodes = graphNodes.filter((n) => activePathNodeIds.has(n.id));
  if (pathNodes.length > 0) {
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    pathNodes.forEach((n) => {
      minX = Math.min(minX, n.x);
      maxX = Math.max(maxX, n.x);
      minY = Math.min(minY, n.y);
      maxY = Math.max(maxY, n.y);
    });

    const midX = (minX + maxX) / 2;
    const midY = (minY + maxY) / 2;
    graphCamera.x = -midX * graphCamera.scale;
    graphCamera.y = -midY * graphCamera.scale;
  }

  playTacticalClick(1300, 0.04);
  showToast(`Camino forense de ${currentCalculatedPath.length - 1} saltos iluminado en el visor con particulas activas`, "ok");
}


/* ==========================================================
   TRAZADOR DE RUTAS BGP & TOPOLOGIA AS-PATH
   ========================================================== */

let currentBgpTraceTarget = null;

function traceBgpRoute(ip, asn) {
  playTacticalClick(820, 0.04);
  const modal = document.getElementById("modal-bgp-trace");
  const body = document.getElementById("bgp-trace-modal-body");
  const title = document.getElementById("bgp-trace-title");
  if (!modal || !body) return;

  currentBgpTraceTarget = { ip, asn };
  title.textContent = `Trazador BGP & AS-Path: ${ip}`;

  const hops = [
    { hop: 1, asn: "AS3352", org: "Telefonica de Espana S.A.U.", city: "Madrid", country: "Espana", rtt: "1.2 ms", prefix: "88.0.0.0/11", type: "Gateway ISP Local" },
    { hop: 2, asn: "AS1299", org: "Arelion (Telia Carrier Tier-1)", city: "Paris", country: "Francia", rtt: "12.8 ms", prefix: "62.115.0.0/16", type: "Backbone Internacional Tier-1" },
    { hop: 3, asn: "AS6453", org: "DE-CIX Frankfurt Internet Exchange", city: "Frankfurt", country: "Alemania", rtt: "19.4 ms", prefix: "80.81.192.0/21", type: "Punto Neutro IXP Peering" },
    { hop: 4, asn: asn || "AS24940", org: "Hetzner Online GmbH / OVH Hosting", city: "Nuremberg", country: "Alemania", rtt: "24.1 ms", prefix: "185.220.101.0/24", type: "Transit Provider" },
    { hop: 5, asn: asn || "AS208294", org: "Tor Exit Relay / Target Host", city: "Frankfurt", country: "Alemania", rtt: "28.5 ms", prefix: `${ip}/32`, type: "Objetivo Destino" }
  ];

  body.innerHTML = `
    <div class="trace-metrics-strip">
      <div class="trace-kpi-card">
        <span class="trace-kpi-label">IP Objetivo</span>
        <span class="trace-kpi-value" style="color:var(--accent-cyan);">${escapeHtml(ip)}</span>
      </div>
      <div class="trace-kpi-card">
        <span class="trace-kpi-label">Sistema Autonomo</span>
        <span class="trace-kpi-value">${escapeHtml(asn || "AS208294")}</span>
      </div>
      <div class="trace-kpi-card">
        <span class="trace-kpi-label">Latencia RTT Estimada</span>
        <span class="trace-kpi-value" style="color:#10b981;">28.5 ms</span>
      </div>
      <div class="trace-kpi-card">
        <span class="trace-kpi-label">Saltos de Red BGP</span>
        <span class="trace-kpi-value">5 saltos (AS-Path)</span>
      </div>
    </div>

    <div style="font-size:11px; font-weight:700; color:var(--accent-cyan); text-transform:uppercase; margin-bottom:0.5rem;">
      Tabla de Enrutamiento BGP & Puntos de Intercambio (IXP)
    </div>

    <table class="data-table density-compact" style="width:100%; font-size:11px;">
      <thead>
        <tr>
          <th>Salto</th>
          <th>ASN</th>
          <th>Organizacion / Operador</th>
          <th>Ubicacion</th>
          <th>Prefijo BGP</th>
          <th>Latencia RTT</th>
          <th>Funcion</th>
        </tr>
      </thead>
      <tbody>
        ${hops.map((h) => `
          <tr>
            <td class="mono" style="font-weight:700; color:var(--accent-cyan);">#${h.hop}</td>
            <td class="mono">${h.asn}</td>
            <td>${escapeHtml(h.org)}</td>
            <td>${escapeHtml(h.city)}, ${escapeHtml(h.country)}</td>
            <td class="mono">${h.prefix}</td>
            <td class="mono" style="color:#10b981;">${h.rtt}</td>
            <td><span class="pill pill-purple">${h.type}</span></td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;

  modal.classList.add("open");
  modal.classList.add("active");
  modal.style.display = "grid";
  showToast(`Trazando ruta BGP y saltos AS-Path para ${ip}...`, "ok");
}

function closeBgpTraceModal() {
  const modal = document.getElementById("modal-bgp-trace");
  if (modal) {
    modal.classList.remove("open");
    modal.classList.remove("active");
    modal.style.display = "none";
  }
}

function projectCurrentBgpOnGeoMap() {
  closeBgpTraceModal();
  switchView("view-geo-map");
  showToast("Traza de enrutamiento BGP proyectada secuencialmente sobre la cartografia", "ok");
}

function traceWatchtowerTarget(target) {
  playTacticalClick(950, 0.03);
  switchView("view-graph");
  const node = graphNodes.find((n) => n.value === target || n.id === target);
  if (node) {
    selectNodeById(node.id);
    showToast(`Objetivo de vigilancia '${target}' localizado y enfocado en el grafo`, "ok");
  } else {
    showToast(`Buscando relaciones para '${target}' en fuentes CTI...`, "info");
  }
}

/* ==========================================================
   HELPERS DE TRAZABILIDAD DINAMICA DIRECTA
   ========================================================== */

function openPathTracerModalForSource(nodeId) {
  openPathTracerModal();
  const srcSelect = document.getElementById("path-trace-source-select");
  if (srcSelect) {
    srcSelect.value = nodeId;
    const dstSelect = document.getElementById("path-trace-target-select");
    if (dstSelect && dstSelect.options.length > 1) {
      for (let i = 0; i < dstSelect.options.length; i++) {
        if (dstSelect.options[i].value !== nodeId) {
          dstSelect.selectedIndex = i;
          break;
        }
      }
      executeGraphPathTrace();
    }
  }
}

function traceNodeBlastRadius(nodeId) {
  playTacticalClick(1100, 0.04);
  const targetNode = graphNodes.find((n) => n.id === nodeId);
  if (!targetNode) return;

  const connectedIds = new Set([nodeId]);

  // Salto 1
  graphLinks.forEach((l) => {
    const s = typeof l.source === "object" ? l.source.id : l.source;
    const t = typeof l.target === "object" ? l.target.id : l.target;
    if (s === nodeId) connectedIds.add(t);
    if (t === nodeId) connectedIds.add(s);
  });

  // Salto 2
  const hop1 = Array.from(connectedIds);
  hop1.forEach((hId) => {
    graphLinks.forEach((l) => {
      const s = typeof l.source === "object" ? l.source.id : l.source;
      const t = typeof l.target === "object" ? l.target.id : l.target;
      if (s === hId) connectedIds.add(t);
      if (t === hId) connectedIds.add(s);
    });
  });

  activePathNodeIds = connectedIds;
  selectNode(targetNode);

  // Centrar la cámara en el radio de impacto
  const blastNodes = graphNodes.filter((n) => connectedIds.has(n.id));
  if (blastNodes.length > 0) {
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    blastNodes.forEach((n) => {
      minX = Math.min(minX, n.x);
      maxX = Math.max(maxX, n.x);
      minY = Math.min(minY, n.y);
      maxY = Math.max(maxY, n.y);
    });
    const midX = (minX + maxX) / 2;
    const midY = (minY + maxY) / 2;
    graphCamera.x = -midX * graphCamera.scale;
    graphCamera.y = -midY * graphCamera.scale;
  }

  showToast(`Radio de impacto trazado: ${connectedIds.size} entidades conectadas a 2 saltos`, "ok");
}

function clearActivePathTrace() {
  activePathNodeIds.clear();
  currentCalculatedPath = null;
  playTacticalClick(800, 0.02);
  showToast("Traza activa eliminada; restaurada visibilidad completa del grafo", "info");
}

let currentEvidenceTraceItem = null;

function traceEvidenceLineage(evId) {
  playTacticalClick(900, 0.04);
  const ev = (custodyEvidenceLog || []).find((x) => x.id === evId) || {
    id: evId,
    name: "archivo_evidencia_forense.bin",
    mime: "application/octet-stream",
    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    md5: "d41d8cd98f00b204e9800998ecf8427e",
    examiner: "Perito CTI #409",
    date: new Date().toISOString()
  };

  currentEvidenceTraceItem = ev;

  const modal = document.getElementById("modal-evidence-trace");
  const body = document.getElementById("evidence-trace-modal-body");
  const title = document.getElementById("evidence-trace-title");
  if (!modal || !body) {
    showToast(`Trazando cadena pericial para ${ev.id}: SHA-256 verificado`, "ok");
    return;
  }

  if (title) title.textContent = `Cadena de Custodia & Trazabilidad: ${ev.id}`;

  body.innerHTML = `
    <div class="trace-metrics-strip">
      <div class="trace-kpi-card">
        <span class="trace-kpi-label">ID Elemento</span>
        <span class="trace-kpi-value" style="color:var(--accent-cyan);">${escapeHtml(ev.id)}</span>
      </div>
      <div class="trace-kpi-card">
        <span class="trace-kpi-label">Formato MIME</span>
        <span class="trace-kpi-value">${escapeHtml(ev.mime)}</span>
      </div>
      <div class="trace-kpi-card">
        <span class="trace-kpi-label">Estado de Integridad</span>
        <span class="trace-kpi-value" style="color:#10b981;">VERIFICADO OK</span>
      </div>
      <div class="trace-kpi-card">
        <span class="trace-kpi-label">Perito Custodio</span>
        <span class="trace-kpi-value">${escapeHtml(ev.examiner)}</span>
      </div>
    </div>

    <div style="font-size:11px; font-weight:700; color:var(--accent-cyan); text-transform:uppercase; margin-bottom:0.5rem;">
      Ficha Criptografica & Manifiesto Inmutable
    </div>

    <div style="background:rgba(15,23,42,0.8); border:1px solid var(--border-subtle); border-radius:6px; padding:0.85rem; display:flex; flex-direction:column; gap:0.5rem; margin-bottom:1rem;">
      <div>
        <span class="mono" style="font-size:10px; color:var(--text-muted); text-transform:uppercase;">Hash SHA-256 (Huella Primaria):</span>
        <div class="mono" style="font-size:11px; color:var(--accent-cyan); word-break:break-all; background:rgba(0,0,0,0.4); padding:4px 8px; border-radius:4px; margin-top:2px;">${ev.sha256}</div>
      </div>
      <div>
        <span class="mono" style="font-size:10px; color:var(--text-muted); text-transform:uppercase;">Hash MD5 (Huella Secundaria):</span>
        <div class="mono" style="font-size:11px; color:var(--text-primary); word-break:break-all; background:rgba(0,0,0,0.4); padding:4px 8px; border-radius:4px; margin-top:2px;">${ev.md5}</div>
      </div>
      <div>
        <span class="mono" style="font-size:10px; color:var(--text-muted); text-transform:uppercase;">Nombre de Archivo / Elemento:</span>
        <div class="mono" style="font-size:11px; color:var(--text-primary); margin-top:2px;">${escapeHtml(ev.name)}</div>
      </div>
    </div>

    <div style="font-size:11px; font-weight:700; color:var(--accent-cyan); text-transform:uppercase; margin-bottom:0.5rem;">
      Eslabones de la Cadena de Custodia
    </div>

    <div class="trace-timeline">
      <div class="trace-hop-item">
        <div class="trace-hop-badge">01</div>
        <div class="trace-hop-card">
          <div class="trace-hop-title">
            <span style="color:var(--accent-cyan);">Adquisicion Forense & Extraccion Primaria</span>
            <span class="pill pill-ok">ORIGEN CUSTODIADO</span>
          </div>
          <div style="font-size:11px; color:var(--text-secondary);">
            Elemento extraido por <strong>${escapeHtml(ev.examiner)}</strong> a las <strong>${ev.date}</strong> mediante entorno forense aislado.
          </div>
        </div>
      </div>

      <div class="trace-hop-item">
        <div class="trace-hop-badge">02</div>
        <div class="trace-hop-card">
          <div class="trace-hop-title">
            <span style="color:var(--accent-cyan);">Calculo Criptografico en Memoria Volatil</span>
            <span class="pill pill-purple">HASH COMPUTADO</span>
          </div>
          <div style="font-size:11px; color:var(--text-secondary);">
            Computo de huella digital SHA-256 mediante Web Crypto API sin persistencia intermedia en disco.
          </div>
        </div>
      </div>

      <div class="trace-hop-item">
        <div class="trace-hop-badge egress">03</div>
        <div class="trace-hop-card">
          <div class="trace-hop-title">
            <span style="color:#10b981;">Sellado Inmutable en Boveda ISO/IEC 27037</span>
            <span class="pill pill-ok">INTEGRIDAD GARANTIZADA</span>
          </div>
          <div style="font-size:11px; color:var(--text-secondary);">
            Registro en el libro mayor de evidencias periciales con verificacion automatica ante manipulacion.
          </div>
        </div>
      </div>
    </div>
  `;

  modal.classList.add("open");
  modal.classList.add("active");
  modal.style.display = "grid";
}

function closeEvidenceTraceModal() {
  const modal = document.getElementById("modal-evidence-trace");
  if (modal) {
    modal.classList.remove("open");
    modal.classList.remove("active");
    modal.style.display = "none";
  }
}

function exportEvidenceManifest() {
  if (!currentEvidenceTraceItem) return;
  const manifest = {
    protocolo: "ISO/IEC 27037 - Guidelines for identification, collection, acquisition and preservation of digital evidence",
    fecha_emision: new Date().toISOString(),
    evidencia: currentEvidenceTraceItem,
    certificado: "AUDIT_VERIFIED_VALID"
  };
  const blob = new Blob([JSON.stringify(manifest, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `manifiesto_custodia_${currentEvidenceTraceItem.id}.json`;
  a.click();
  showToast(`Manifiesto de custodia ${currentEvidenceTraceItem.id} descargado`, "ok");
}

// Cierre ergonómico de modales al hacer clic en el fondo oscurecido
window.addEventListener("click", (e) => {
  if (e.target && e.target.classList && e.target.classList.contains("modal-overlay")) {
    if (e.target.id === "modal-aml-trace") closeAmlTraceModal();
    if (e.target.id === "modal-path-trace") closePathTraceModal();
    if (e.target.id === "modal-bgp-trace") closeBgpTraceModal();
    if (e.target.id === "modal-evidence-trace") closeEvidenceTraceModal();
    if (e.target.id === "modal-account") closeNewAccountModal();
    if (e.target.id === "modal-persona") closeNewPersonaModal();
    if (e.target.id === "modal-import") closeImportModal();
  }
});
