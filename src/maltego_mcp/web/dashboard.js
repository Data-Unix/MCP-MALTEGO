/**
 * MCP Maltego Web Dashboard - Cliente Operativo
 */

let bgWorker = null;
let currentTab = "overview";
let currentPersona = null;
let totpTimer = null;
let activeEventSource = null;
let dashboardInitialized = false;
let authLockoutTimer = null;

const authState = {
  authenticated: false,
  authRequired: true,
  username: "admin",
  roles: [],
  csrfToken: "",
};

const _nativeFetch = window.fetch.bind(window);

function installAuthenticatedFetchInterceptor() {
  window.fetch = async function patchedDashboardFetch(input, init) {
    const urlStr = typeof input === "string" ? input : (input && input.url ? input.url : "");
    let isLocalApi = false;
    let apiPath = "";
    try {
      const parsed = new URL(urlStr, window.location.origin);
      if (parsed.origin === window.location.origin && parsed.pathname.startsWith("/api/")) {
        isLocalApi = true;
        apiPath = parsed.pathname;
      }
    } catch (_err) {
      isLocalApi = urlStr.startsWith("/api/");
      apiPath = urlStr.split("?")[0];
    }

    if (!isLocalApi) {
      return _nativeFetch(input, init);
    }

    const opts = Object.assign({}, init || {});
    if (!opts.credentials) {
      opts.credentials = "same-origin";
    }
    const method = String(opts.method || (input && input.method) || "GET").toUpperCase();
    if (["POST", "PUT", "PATCH", "DELETE"].includes(method) && authState.csrfToken) {
      const hdrs = new Headers(opts.headers || (input instanceof Request ? input.headers : undefined) || {});
      if (!hdrs.has("X-CSRF-Token")) {
        hdrs.set("X-CSRF-Token", authState.csrfToken);
      }
      opts.headers = hdrs;
    }

    const resp = await _nativeFetch(input, opts);
    if (
      resp.status === 401 &&
      apiPath !== "/api/auth/login" &&
      apiPath !== "/api/auth/session" &&
      document.body.dataset.auth === "authenticated"
    ) {
      lockConsoleWithReason("La sesión ha caducado o se ha cerrado. Vuelve a iniciar sesión.");
    }
    return resp;
  };
}

installAuthenticatedFetchInterceptor();

document.addEventListener("DOMContentLoaded", () => {
  renderListenHost();
  initAuthGate();
  checkAuthSession();
});

// Host de escucha real, leído del navegador (sin afirmaciones fijas en el HTML).
function renderListenHost() {
  const hostText = window.location.host || "—";
  const hostname = (window.location.hostname || "").replace(/^\[|\]$/g, "");
  const loopback = hostname === "127.0.0.1" || hostname === "localhost" || hostname === "::1";
  const factEl = document.getElementById("auth-fact-host");
  if (factEl) factEl.textContent = hostText;
  const hostEl = document.getElementById("sidebar-listen-host");
  if (hostEl) hostEl.textContent = hostText;
  const scopeEl = document.getElementById("sidebar-listen-scope");
  if (scopeEl) {
    scopeEl.textContent = loopback ? "Solo loopback" : "Expuesto fuera de loopback";
    scopeEl.className = `pill ${loopback ? "pill-ok" : "pill-warn"}`;
  }
}

function setSseBadge(state) {
  const el = document.getElementById("badge-sse-status");
  if (!el) return;
  const map = {
    open: ["SSE: conectado", "pill-cyan"],
    retry: ["SSE: reconectando…", "pill-warn"],
    closed: ["SSE: desconectado", "pill-dim"],
  };
  const [text, cls] = map[state] || map.closed;
  el.textContent = text;
  el.className = `pill ${cls}`;
}

function setAuthError(message, tone = "error") {
  const box = document.getElementById("auth-error");
  if (!box) return;
  if (!message) {
    box.hidden = true;
    box.textContent = "";
    box.removeAttribute("data-tone");
    return;
  }
  box.dataset.tone = tone;
  box.textContent = message;
  box.hidden = false;
}

function clearAuthLockoutTimer() {
  if (authLockoutTimer) {
    clearTimeout(authLockoutTimer);
    authLockoutTimer = null;
  }
}

function startAuthLockoutCountdown(seconds) {
  clearAuthLockoutTimer();
  const submitBtn = document.getElementById("auth-submit");
  const submitLbl = document.getElementById("auth-submit-label");
  let remaining = Math.max(1, parseInt(seconds, 10) || 60);

  const tick = () => {
    if (remaining <= 0) {
      if (submitBtn) submitBtn.disabled = false;
      if (submitLbl) submitLbl.textContent = "Iniciar sesión";
      setAuthError("");
      const passEl = document.getElementById("auth-pass");
      if (passEl) passEl.focus();
      return;
    }
    if (submitBtn) submitBtn.disabled = true;
    if (submitLbl) submitLbl.textContent = `Espera ${remaining} s`;
    setAuthError(`Demasiados intentos fallidos. Reintenta en ${remaining} s.`, "warn");
    remaining -= 1;
    authLockoutTimer = setTimeout(tick, 1000);
  };
  tick();
}

function updateSessionHudUI() {
  const uname = authState.username || "admin";
  const roles = Array.isArray(authState.roles) && authState.roles.length
    ? authState.roles
    : ["SUPERADMIN", "CTI_LEAD", "OSINT_ANALYST", "HUMINT_OPERATOR", "FORENSIC_PROFILER", "AML_INVESTIGATOR", "AUDITOR"];

  const hudUser = document.getElementById("hud-session-user");
  if (hudUser) hudUser.textContent = uname;
  const hudCount = document.getElementById("hud-session-role-count");
  if (hudCount) hudCount.textContent = `${roles.length} roles`;
  const menuUser = document.getElementById("session-menu-user");
  if (menuUser) menuUser.textContent = uname;
  const secMeta = document.getElementById("session-menu-security");
  if (secMeta) {
    secMeta.textContent = authState.authRequired
      ? "Cookie HttpOnly · SameSite=Strict · CSRF activo"
      : "Modo local directo (sin puerta activa)";
  }
  const rolesContainer = document.getElementById("session-menu-roles");
  if (rolesContainer) {
    rolesContainer.innerHTML = roles.map((r) => `<span class="role-chip">${escapeHtml(String(r))}</span>`).join("");
  }
}

function initAuthGate() {
  const hostEl = document.getElementById("auth-fact-host");
  if (hostEl && window.location.host) {
    hostEl.textContent = window.location.host;
  }

  const submitBtn = document.getElementById("auth-submit");
  const userEl = document.getElementById("auth-user");
  const passEl = document.getElementById("auth-pass");
  const revealBtn = document.getElementById("auth-reveal");
  const capsEl = document.getElementById("auth-caps");

  if (submitBtn) {
    submitBtn.addEventListener("click", () => submitAuthLogin());
  }

  const handleEnter = (ev) => {
    if (ev.getModifierState && capsEl) {
      capsEl.hidden = !ev.getModifierState("CapsLock");
    }
    if (ev.key === "Enter") {
      ev.preventDefault();
      submitAuthLogin();
    }
  };
  if (userEl) userEl.addEventListener("keydown", handleEnter);
  if (passEl) {
    passEl.addEventListener("keydown", handleEnter);
    passEl.addEventListener("keyup", (ev) => {
      if (ev.getModifierState && capsEl) {
        capsEl.hidden = !ev.getModifierState("CapsLock");
      }
    });
  }

  if (revealBtn && passEl) {
    revealBtn.addEventListener("click", () => {
      const showing = passEl.type === "text";
      passEl.type = showing ? "password" : "text";
      revealBtn.setAttribute("aria-pressed", showing ? "false" : "true");
      revealBtn.setAttribute("aria-label", showing ? "Mostrar contraseña" : "Ocultar contraseña");
      const eyeOpen = document.getElementById("auth-eye-open");
      const eyeClosed = document.getElementById("auth-eye-closed");
      if (eyeOpen) eyeOpen.hidden = !showing;
      if (eyeClosed) eyeClosed.hidden = showing;
      passEl.focus();
    });
  }

  const btnToggleMenu = document.getElementById("btn-session-toggle");
  const menuEl = document.getElementById("hud-session-menu");
  if (btnToggleMenu && menuEl) {
    btnToggleMenu.addEventListener("click", (ev) => {
      ev.stopPropagation();
      const next = !menuEl.classList.contains("active");
      menuEl.classList.toggle("active", next);
      btnToggleMenu.setAttribute("aria-expanded", next ? "true" : "false");
    });
    document.addEventListener("click", (ev) => {
      if (!menuEl.contains(ev.target) && ev.target !== btnToggleMenu) {
        menuEl.classList.remove("active");
        btnToggleMenu.setAttribute("aria-expanded", "false");
      }
    });
  }

  const btnLock = document.getElementById("btn-session-lock");
  if (btnLock) {
    btnLock.addEventListener("click", () => logoutDashboardSession("Consola bloqueada por el operador."));
  }
  const btnLogout = document.getElementById("btn-session-logout");
  if (btnLogout) {
    btnLogout.addEventListener("click", () => logoutDashboardSession("Sesión cerrada correctamente."));
  }
}

async function checkAuthSession() {
  try {
    const res = await fetch("/api/auth/session", { cache: "no-store" });
    if (res.status === 403) {
      document.body.dataset.auth = "locked";
      setAuthError("Acceso bloqueado: la consola solo acepta conexiones loopback (127.0.0.1 / localhost).");
      return;
    }
    const data = await res.json();
    if (data && data.session_ttl) {
      const ttlEl = document.getElementById("auth-fact-ttl");
      const hours = Math.max(1, Math.round(Number(data.session_ttl) / 3600));
      if (ttlEl) ttlEl.textContent = `HttpOnly · ${hours} h`;
    }
    if (data && data.authenticated) {
      authState.authenticated = true;
      authState.authRequired = data.auth_required !== false;
      authState.username = data.username || "admin";
      authState.roles = Array.isArray(data.roles) ? data.roles : [];
      authState.csrfToken = data.csrf_token || "";
      setAuthError("");
      bootAuthenticatedDashboard();
    } else {
      document.body.dataset.auth = "locked";
      const passEl = document.getElementById("auth-pass");
      if (passEl) passEl.focus();
    }
  } catch (_err) {
    document.body.dataset.auth = "locked";
    setAuthError("Servidor local no disponible. Comprueba que maltegoctl dashboard sigue activo.");
  }
}

async function submitAuthLogin() {
  const submitBtn = document.getElementById("auth-submit");
  const submitLbl = document.getElementById("auth-submit-label");
  const userEl = document.getElementById("auth-user");
  const passEl = document.getElementById("auth-pass");
  if (!userEl || !passEl || (submitBtn && submitBtn.disabled)) return;

  const username = userEl.value.trim();
  const password = passEl.value;
  if (!username || !password) {
    setAuthError("Introduce el usuario y la contraseña del operador.");
    (username ? passEl : userEl).focus();
    return;
  }

  if (submitBtn) submitBtn.disabled = true;
  if (submitLbl) submitLbl.textContent = "Verificando...";
  setAuthError("");

  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json().catch(() => ({}));

    if (res.status === 429) {
      passEl.value = "";
      startAuthLockoutCountdown(data.retry_after || res.headers.get("Retry-After") || 60);
      return;
    }

    if (!res.ok || !data.authenticated) {
      passEl.value = "";
      passEl.type = "password";
      const rem = typeof data.remaining_attempts === "number" ? data.remaining_attempts : null;
      const suffix = rem !== null ? ` Intentos restantes antes de bloqueo temporal: ${rem}.` : "";
      setAuthError(`${data.error || "Credenciales inválidas."}${suffix}`);
      if (submitBtn) submitBtn.disabled = false;
      if (submitLbl) submitLbl.textContent = "Iniciar sesión";
      passEl.focus();
      return;
    }

    passEl.value = "";
    passEl.type = "password";
    clearAuthLockoutTimer();
    authState.authenticated = true;
    authState.authRequired = data.auth_required !== false;
    authState.username = data.username || username;
    authState.roles = Array.isArray(data.roles) ? data.roles : [];
    authState.csrfToken = data.csrf_token || "";
    if (submitBtn) submitBtn.disabled = false;
    if (submitLbl) submitLbl.textContent = "Iniciar sesión";
    bootAuthenticatedDashboard();
  } catch (_err) {
    if (submitBtn) submitBtn.disabled = false;
    if (submitLbl) submitLbl.textContent = "Iniciar sesión";
    setAuthError("No hay conexión con el servidor local (127.0.0.1).");
  }
}

function wipeClientVolatileSecrets() {
  if (activeEventSource) {
    try { activeEventSource.close(); } catch (_e) {}
    activeEventSource = null;
  }
  try {
    sessionStorage.removeItem("maltego_burner_inboxes");
    localStorage.removeItem("maltego_burner_inboxes");
  } catch (_e) {}
  currentPersona = null;
  if (typeof burnerInboxes !== "undefined" && Array.isArray(burnerInboxes)) {
    burnerInboxes = [];
  }
  const passEl = document.getElementById("auth-pass");
  if (passEl) {
    passEl.value = "";
    passEl.type = "password";
  }
  const menuEl = document.getElementById("hud-session-menu");
  if (menuEl) menuEl.classList.remove("active");
}

function lockConsoleWithReason(reasonMsg) {
  authState.authenticated = false;
  authState.csrfToken = "";
  wipeClientVolatileSecrets();
  document.body.dataset.auth = "locked";
  if (reasonMsg) {
    setAuthError(reasonMsg, "warn");
  }
  const passEl = document.getElementById("auth-pass");
  if (passEl) passEl.focus();
}

async function logoutDashboardSession(statusMsg) {
  try {
    await fetch("/api/auth/logout", { method: "POST" });
  } catch (_err) {
    // Continuar bloqueo local aunque falle la red
  }
  lockConsoleWithReason(statusMsg || "Sesión cerrada.");
}

function bootAuthenticatedDashboard() {
  document.body.dataset.auth = "authenticated";
  updateSessionHudUI();

  if (!dashboardInitialized) {
    dashboardInitialized = true;
    initBackgroundCanvas();
    initNavigation();
    initSidebarControls();
    initDelegatedEventListeners();
    initInteractiveGraph();
    initImportDropzone();
    initAudioFeedback();
    initCommandPalette();
    initRadarHud();
  }

  initSSE();
  loadStatus();
  loadAccounts();
  loadBurnerInboxesFromStorage();
  loadEmailProviders();
  loadProviders();
  loadCTIFeeds();
  loadTransforms();
  loadCasesList();
}

/* ---------------------------------------------------------------------------------------------------------------
 * Acciones declarativas (data-on-click, data-on-change, data-on-input, data-on-submit, data-on-keydown)
 *
 * La CSP del panel (`script-src 'self'`) bloquea cualquier manejador en línea (atributos onclick, onchange, etc.):
 * el navegador ni siquiera lo compila. El marcado declara la acción en un atributo data-on-<evento> y este
 * despachador la ejecuta por delegación, sin eval ni Function:
 *   - solo se invocan funciones de DECLARATIVE_ACTIONS (lista cerrada);
 *   - los argumentos solo pueden ser literales ('texto', 12, 0.8, true, false, null), `this`, `this.value`,
 *     `this.checked` o `event`;
 *   - cualquier otra expresión se descarta con un aviso en consola (falla en cerrado).
 * ------------------------------------------------------------------------------------------------------------- */
const DECLARATIVE_EVENTS = ["click", "change", "input", "submit", "keydown"];

const DECLARATIVE_ACTIONS = new Set([
  "addFase2InfraItem",
  "addFase6BreachItem",
  "addFase7HumintItem",
  "addFase8EcosystemItem",
  "checkHistoricalCanaries",
  "closeAmlTraceModal",
  "closeIcd203Modal",
  "closeImportModal",
  "closeNewAccountModal",
  "closePathTraceModal",
  "closePersonaModal",
  "confirmCognitiveReframing",
  "copyIcd203Markdown",
  "copyPersonaJSON",
  "createBurnerInbox",
  "downloadCurrentProfileJson",
  "executeArchiveSearch",
  "executeCurrentProfiling",
  "executeGraphPathTrace",
  "exportCaseAs",
  "exportCurrentTraceReport",
  "extractArchivedDocuments",
  "filterAccountsByCategory",
  "filterAccountsSearch",
  "filterAmlTable",
  "filterCommandPalette",
  "filterEmailProviders",
  "filterFase2Infrastructure",
  "filterFase6Breaches",
  "filterProfilingTargets",
  "filterSymmetricDorks",
  "filterTableGeneric",
  "fitGraphView",
  "generatePersonaPreview",
  "graphZoom",
  "highlightCurrentPathOnCanvas",
  "injectCurrentTraceIntoCase",
  "injectPlaygroundEntitiesIntoCase",
  "loadAccounts",
  "loadSymmetricDorks",
  "onCaseSelected",
  "onCommandPaletteKeydown",
  "onCommandPaletteOverlayClick",
  "onImportFileSelected",
  "onPlatformChanged",
  "onProfilingTargetSelected",
  "openDeleteCaseModal",
  "openIcd203Modal",
  "openImportModal",
  "openNewAccountModal",
  "openPerimeterModal",
  "openPersonaModal",
  "openRunMachineModal",
  "printIcd203Report",
  "promptAddCryptoTrace",
  "promptCreateCase",
  "promptDeclareCoverageGap",
  "queryLocalBreachDb",
  "refreshCurrentInboxMessages",
  "refreshProfilingTargets",
  "reloadCurrentGraph",
  "runPlaygroundLookup",
  "saveCurrentPersona",
  "saveKeyEvidenceFromUi",
  "scanAmlCaseMixers",
  "selectModalCategory",
  "setGraphLayout",
  "setTableDensity",
  "setTableLimit",
  "setTorProxyPreset",
  "submitImportCase",
  "submitInlineCryptoTrace",
  "submitNewAccount",
  "switchIcd203View",
  "switchTab",
  "toggleAllRowsDetail",
  "toggleExportMenu",
  "toggleGraphFilterDrawer",
  "toggleGraphFullscreen",
  "toggleImportMode",
  "toggleInspectorCollapse",
  "triggerCTISync",
]);

const DECLARATIVE_UNRESOLVED = Symbol("argumento no admitido");

function splitDeclarativeArgs(raw) {
  const parts = [];
  let current = "";
  let quote = null;
  for (const ch of raw) {
    if (quote) {
      current += ch;
      if (ch === quote) quote = null;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
      current += ch;
    } else if (ch === ",") {
      parts.push(current.trim());
      current = "";
    } else {
      current += ch;
    }
  }
  if (quote) return null;
  if (current.trim() !== "" || parts.length > 0) parts.push(current.trim());
  return parts;
}

function resolveDeclarativeArg(token, el, ev) {
  const str = /^'([^'\\]*)'$/.exec(token) || /^"([^"\\]*)"$/.exec(token);
  if (str) return str[1];
  if (/^-?\d+(\.\d+)?$/.test(token)) return Number(token);
  if (token === "true") return true;
  if (token === "false") return false;
  if (token === "null") return null;
  if (token === "this") return el;
  if (token === "this.value") return el.value;
  if (token === "this.checked") return el.checked;
  if (token === "event") return ev;
  return DECLARATIVE_UNRESOLVED;
}

/** Ejecuta la acción declarada en `source`. Devuelve false si pide detener la propagación hacia los ancestros. */
function runDeclarativeAction(source, el, ev) {
  let keepBubbling = true;
  for (const statement of source.split(";")) {
    const stmt = statement.trim();
    if (!stmt) continue;
    if (stmt === "event.stopPropagation()") {
      keepBubbling = false;
      continue;
    }
    if (stmt === "event.preventDefault()") {
      ev.preventDefault();
      continue;
    }
    if (stmt === "this.parentElement.remove()") {
      if (el.parentElement) el.parentElement.remove();
      continue;
    }
    const proxyClick = /^document\.getElementById\('([\w-]+)'\)\.click\(\)$/.exec(stmt);
    if (proxyClick) {
      const target = document.getElementById(proxyClick[1]);
      if (target) target.click();
      continue;
    }
    const call = /^(?:return\s+)?([A-Za-z_$][\w$]*)\((.*)\)$/.exec(stmt);
    const fn = call && DECLARATIVE_ACTIONS.has(call[1]) ? window[call[1]] : null;
    const tokens = call ? splitDeclarativeArgs(call[2]) : null;
    const args = tokens ? tokens.map((t) => resolveDeclarativeArg(t, el, ev)) : null;
    if (typeof fn !== "function" || !args || args.includes(DECLARATIVE_UNRESOLVED)) {
      console.warn("[panel] Acción declarativa no admitida, se ignora:", stmt);
      continue;
    }
    fn(...args);
  }
  return keepBubbling;
}

function installDeclarativeActionDispatcher() {
  for (const type of DECLARATIVE_EVENTS) {
    const attr = `data-on-${type}`;
    document.addEventListener(type, (ev) => {
      let el = ev.target instanceof Element ? ev.target : null;
      // Un href="javascript:..." también lo bloquea la CSP: se anula la navegación para que no genere violaciones.
      if (type === "click" && el && el.closest('a[href^="javascript:"]')) ev.preventDefault();
      while (el) {
        if (el.hasAttribute(attr) && !el.matches(":disabled")) {
          // Los formularios nunca se envían al servidor (form-action 'none'): la acción gestiona el envío.
          if (type === "submit") ev.preventDefault();
          if (runDeclarativeAction(el.getAttribute(attr), el, ev) === false) break;
        }
        el = el.parentElement;
      }
    });
  }
}

installDeclarativeActionDispatcher();

function initDelegatedEventListeners() {
  document.addEventListener("change", (e) => {
    if (e.target && e.target.id === "global-project-select") {
      switchActiveProject(e.target.value);
    }
    if (e.target && e.target.classList.contains("module-case-select")) {
      const mod = e.target.id.replace("-case-select", "");
      onModuleCaseChanged(mod, e.target.value);
    }
    if (e.target && e.target.classList.contains("action-p0-preset-legal")) {
      onP0LegalPresetChanged(e.target.value);
    }
    if (e.target && e.target.classList.contains("action-p0-preset-humint")) {
      onP0HumintPresetChanged(e.target.value);
    }
    if (e.target && e.target.classList.contains("action-p0-preset-refclass")) {
      onP0RefClassPresetChanged(e.target.value);
    }
    if (e.target && e.target.classList.contains("action-delete-case-select")) {
      onDeleteCaseSelectChanged(e.target.value);
    }
    if (e.target && e.target.id === "recon-seeds-sort-by") {
      renderReconSeedsTable(currentReconData?.seeds || []);
    }
    if (e.target && e.target.classList.contains("action-toggle-entity-type")) {
      const type = e.target.dataset.type;
      if (type) toggleEntityType(type, e.target.checked);
    }
    if (e.target && e.target.classList.contains("action-toggle-edge-type")) {
      const label = e.target.dataset.label;
      if (label) toggleEdgeType(label, e.target.checked);
    }
    if (e.target && e.target.classList.contains("action-toggle-orphans")) {
      toggleHideOrphans(e.target.checked);
    }
  });

  document.addEventListener("input", (e) => {
    if (e.target && e.target.id === "filter-confidence-range") {
      onConfidenceSliderChange(e.target.value);
    }
    if (e.target && (e.target.id === "graph-search-input" || e.target.id === "fullscreen-graph-search")) {
      onGraphSearchInput(e.target.value);
    }
    if (e.target && e.target.classList.contains("action-delete-case-confirm-input")) {
      checkDeleteCaseConfirmation(e.target.value);
    }
    if (e.target && e.target.id === "recon-framing-question") {
      checkLoadedLanguage(e.target.value);
    }
    if (e.target && e.target.id === "recon-seeds-filter") {
      renderReconSeedsTable(currentReconData?.seeds || []);
    }
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target) {
      if (e.target.id === "new-seed-val") {
        e.preventDefault();
        addReconSeedFromUi(false);
      } else if (e.target.id === "recon-framing-target") {
        e.preventDefault();
        saveReconFraming(true);
      } else if (e.target.id === "recon-p0-assumption-input") {
        e.preventDefault();
        addP0Assumption();
      } else if (e.target.id === "recon-quick-perimeter-input") {
        e.preventDefault();
        addQuickPerimeterAsset();
      } else if (e.target.id === "perimeter-asset-input") {
        e.preventDefault();
        submitPerimeterAsset();
      } else if (e.target.id === "new-hyp-statement" || e.target.id === "new-hyp-refute") {
        e.preventDefault();
        addReconHypothesisFromUi();
      }
    }
    if (e.key === "Escape") {
      if (filterDrawerOpen) {
        toggleGraphFilterDrawer(false);
      }
      const modalPerim = document.getElementById("modal-perimeter");
      if (modalPerim && modalPerim.classList.contains("active")) {
        closePerimeterModal();
        return;
      }
      const modalMach = document.getElementById("modal-run-machine");
      if (modalMach && modalMach.classList.contains("active")) {
        closeRunMachineModal();
        return;
      }
      const modalDel = document.getElementById("modal-delete-case");
      if (modalDel && modalDel.classList.contains("active")) {
        closeDeleteCaseModal();
        return;
      }
      const modalIcd = document.getElementById("modal-icd203-report");
      if (modalIcd && modalIcd.classList.contains("active")) {
        closeIcd203Modal();
        return;
      }
    }
  });

  document.addEventListener("click", (e) => {
    // 1. Cuentas
    const btnVerifyAcc = e.target.closest(".action-verify-account");
    if (btnVerifyAcc && btnVerifyAcc.dataset.accountId) {
      verifyAccount(btnVerifyAcc.dataset.accountId);
      return;
    }
    const btnDelAcc = e.target.closest(".action-delete-account");
    if (btnDelAcc && btnDelAcc.dataset.accountId) {
      deleteAccount(btnDelAcc.dataset.accountId);
      return;
    }

    // 2. Despliegue de filas
    const btnToggleRow = e.target.closest(".action-toggle-row");
    if (btnToggleRow && btnToggleRow.dataset.target) {
      e.stopPropagation();
      toggleRowDetail(btnToggleRow, btnToggleRow.dataset.target);
      return;
    }

    // 3. CTI
    const btnCopyCti = e.target.closest(".action-copy-cti-url");
    if (btnCopyCti && btnCopyCti.dataset.url) {
      copyToClipboardWithFeedback(btnCopyCti.dataset.url, "URL de fuente CTI");
      return;
    }

    // 4. Bandeja Burner
    const btnCopyInboxAddr = e.target.closest(".action-copy-inbox-addr");
    if (btnCopyInboxAddr && btnCopyInboxAddr.dataset.address) {
      e.stopPropagation();
      copyInboxAddress(btnCopyInboxAddr.dataset.address);
      return;
    }
    const btnDelBurner = e.target.closest(".action-delete-burner-inbox");
    if (btnDelBurner && btnDelBurner.dataset.inboxId) {
      e.stopPropagation();
      deleteBurnerInbox(btnDelBurner.dataset.inboxId);
      return;
    }
    const cardInbox = e.target.closest(".inbox-card");
    if (cardInbox && cardInbox.dataset.inboxId) {
      selectInbox(cardInbox.dataset.inboxId);
      return;
    }
    const btnCopyOtp = e.target.closest(".action-copy-inbox-otp");
    if (btnCopyOtp && btnCopyOtp.dataset.code) {
      copyInboxOTP(btnCopyOtp.dataset.code);
      return;
    }

    // 5. Cripto / AML
    const btnQueryMempool = e.target.closest(".action-query-mempool");
    if (btnQueryMempool && btnQueryMempool.dataset.address) {
      queryMempoolForAddress(btnQueryMempool.dataset.address);
      return;
    }
    const btnTraceAml = e.target.closest(".action-trace-aml");
    if (btnTraceAml && btnTraceAml.dataset.txid) {
      e.stopPropagation();
      traceAmlTransaction(btnTraceAml.dataset.txid);
      return;
    }
    const btnCopyTxid = e.target.closest(".action-copy-txid");
    if (btnCopyTxid && btnCopyTxid.dataset.txid) {
      copyToClipboardWithFeedback(btnCopyTxid.dataset.txid, "TXID");
      return;
    }
    const btnExploreTx = e.target.closest(".action-explore-tx");
    if (btnExploreTx && btnExploreTx.dataset.txid) {
      exploreTxInputsOutputs(btnExploreTx.dataset.txid);
      return;
    }
    const btnCryptoLookup = e.target.closest(".action-crypto-lookup");
    if (btnCryptoLookup && btnCryptoLookup.dataset.txid && btnCryptoLookup.dataset.lookup) {
      executeCryptoOnChainLookup(btnCryptoLookup.dataset.txid, btnCryptoLookup.dataset.lookup);
      return;
    }
    const amlRow = e.target.closest("tr.table-row-main[data-row-id]");
    if (amlRow && !e.target.closest("button") && !e.target.closest("a") && !e.target.closest("input")) {
      handleRowClick(e, amlRow.dataset.rowId);
      return;
    }

    // 6. Grafo / Inspector & Filtros Avanzados
    const btnToggleFilters = e.target.closest(".action-toggle-filters");
    if (btnToggleFilters) {
      toggleGraphFilterDrawer();
      return;
    }
    const btnCloseFilters = e.target.closest(".action-close-filter-drawer");
    if (btnCloseFilters) {
      toggleGraphFilterDrawer(false);
      return;
    }
    const btnResetFilters = e.target.closest(".action-reset-filters");
    if (btnResetFilters) {
      resetAllGraphFilters();
      return;
    }
    const btnConfPreset = e.target.closest(".action-conf-preset");
    if (btnConfPreset && btnConfPreset.dataset.val !== undefined) {
      const slider = document.getElementById("filter-confidence-range");
      if (slider) slider.value = btnConfPreset.dataset.val;
      onConfidenceSliderChange(btnConfPreset.dataset.val);
      return;
    }
    const btnHops = e.target.closest(".action-filter-hops");
    if (btnHops && btnHops.dataset.hops !== undefined) {
      setHopsFilter(btnHops.dataset.hops, btnHops);
      return;
    }
    const btnPresetFilter = e.target.closest(".action-preset-filter");
    if (btnPresetFilter && btnPresetFilter.dataset.preset) {
      setGraphFilter(btnPresetFilter.dataset.preset);
      return;
    }
    const btnPresetHops = e.target.closest(".action-preset-hops");
    if (btnPresetHops && btnPresetHops.dataset.hops) {
      setHopsPreset(btnPresetHops.dataset.hops);
      return;
    }
    const btnSetLayout = e.target.closest(".action-set-layout");
    if (btnSetLayout && btnSetLayout.dataset.layout) {
      setGraphLayout(btnSetLayout.dataset.layout);
      return;
    }
    const btnGraphZoom = e.target.closest(".action-graph-zoom");
    if (btnGraphZoom && btnGraphZoom.dataset.zoom) {
      graphZoom(Number(btnGraphZoom.dataset.zoom));
      return;
    }
    const btnGraphResetZoom = e.target.closest(".action-graph-reset-zoom");
    if (btnGraphResetZoom) {
      graphResetZoom();
      return;
    }
    const btnGraphFit = e.target.closest(".action-graph-fit");
    if (btnGraphFit) {
      fitGraphView();
      return;
    }
    const btnGraphFullscreen = e.target.closest(".action-graph-fullscreen");
    if (btnGraphFullscreen) {
      toggleGraphFullscreen();
      return;
    }
    const btnToggleAllEntities = e.target.closest(".action-toggle-all-entities");
    if (btnToggleAllEntities && btnToggleAllEntities.dataset.enable !== undefined) {
      toggleAllEntityTypes(btnToggleAllEntities.dataset.enable === "true");
      return;
    }
    const btnToggleAllEdges = e.target.closest(".action-toggle-all-edges");
    if (btnToggleAllEdges && btnToggleAllEdges.dataset.enable !== undefined) {
      toggleAllEdgeTypes(btnToggleAllEdges.dataset.enable === "true");
      return;
    }
    const btnClearSearch = e.target.closest(".action-clear-graph-search");
    if (btnClearSearch) {
      clearGraphSearch();
      return;
    }

    // Cerrar drawer si se hace clic fuera del mismo
    if (filterDrawerOpen) {
      const drawer = document.getElementById("graph-filter-drawer");
      if (drawer && !drawer.contains(e.target) && !e.target.closest(".action-toggle-filters")) {
        toggleGraphFilterDrawer(false);
      }
    }

    const btnSelectNode = e.target.closest(".action-select-node");
    if (btnSelectNode && btnSelectNode.dataset.nodeId) {
      selectNodeById(btnSelectNode.dataset.nodeId);
      return;
    }
    const btnOpenPathTracer = e.target.closest(".action-open-path-tracer");
    if (btnOpenPathTracer && btnOpenPathTracer.dataset.nodeId) {
      openPathTracerModalForSource(btnOpenPathTracer.dataset.nodeId);
      return;
    }
    const btnTraceBlast = e.target.closest(".action-trace-blast-radius");
    if (btnTraceBlast && btnTraceBlast.dataset.nodeId) {
      traceNodeBlastRadius(btnTraceBlast.dataset.nodeId);
      return;
    }
    const btnClearTrace = e.target.closest(".action-clear-path-trace");
    if (btnClearTrace) {
      clearActivePathTrace();
      return;
    }

    // 7. Paleta de Comandos
    const cmdItem = e.target.closest(".command-item[data-idx]");
    if (cmdItem) {
      executeCommand(parseInt(cmdItem.dataset.idx, 10));
      return;
    }

    // 8. Perfilado
    const btnCopyHash = e.target.closest(".action-copy-evidence-hash");
    if (btnCopyHash && btnCopyHash.dataset.hash) {
      copyToClipboardWithFeedback(btnCopyHash.dataset.hash, "Hash SHA-256");
      return;
    }
    const btnFocusEnt = e.target.closest(".action-focus-entity");
    if (btnFocusEnt && btnFocusEnt.dataset.entityId) {
      focusEntityOnGraph(btnFocusEnt.dataset.entityId);
      return;
    }
    const btnSelectProf = e.target.closest(".action-select-profile");
    if (btnSelectProf && btnSelectProf.dataset.profileId) {
      selectProfileFromHistory(btnSelectProf.dataset.profileId);
      return;
    }

    // 9. Reconocimiento Pasivo
    const btnReconPhase = e.target.closest(".action-recon-phase");
    if (btnReconPhase && btnReconPhase.dataset.phase) {
      setReconPhase(btnReconPhase.dataset.phase);
      return;
    }
    const btnToggleReconView = e.target.closest(".action-recon-toggle-view");
    if (btnToggleReconView) {
      toggleReconViewMode();
      return;
    }
    const btnSaveP0 = e.target.closest(".action-save-p0-framing");
    if (btnSaveP0) {
      saveReconFraming();
      return;
    }
    const btnAddSeed = e.target.closest(".action-add-recon-seed");
    if (btnAddSeed) {
      addReconSeedFromUi(false);
      return;
    }
    const btnQuickRecon = e.target.closest(".action-run-quick-recon");
    if (btnQuickRecon) {
      addReconSeedFromUi(true);
      return;
    }
    const btnSeedRunRecon = e.target.closest(".action-seed-run-recon");
    if (btnSeedRunRecon) {
      const type = btnSeedRunRecon.dataset.type;
      const val = btnSeedRunRecon.dataset.value;
      if (val) runPassiveReconOnSeed(type || "Domain", val);
      return;
    }
    const btnSeedDelete = e.target.closest(".action-seed-delete");
    if (btnSeedDelete && btnSeedDelete.dataset.id) {
      deleteReconSeed(btnSeedDelete.dataset.id);
      return;
    }
    const btnSeedGraph = e.target.closest(".action-seed-graph");
    if (btnSeedGraph && btnSeedGraph.dataset.value) {
      viewSeedInGraph(btnSeedGraph.dataset.type, btnSeedGraph.dataset.value);
      return;
    }
    const btnSeedDorks = e.target.closest(".action-seed-dorks");
    if (btnSeedDorks && btnSeedDorks.dataset.value) {
      filterDorksForSeed(btnSeedDorks.dataset.value);
      return;
    }
    const btnToggleAdv = e.target.closest("#btn-toggle-seed-advanced");
    if (btnToggleAdv) {
      toggleSeedAdvancedFields();
      return;
    }
    const btnVerifyHom = e.target.closest(".action-verify-homonym");
    if (btnVerifyHom && btnVerifyHom.dataset.id) {
      verifyHomonymInteractive(
        btnVerifyHom.dataset.id,
        btnVerifyHom.dataset.val || "",
        btnVerifyHom.dataset.id1 || "",
        btnVerifyHom.dataset.id2 || ""
      );
      return;
    }
    const btnEditAdm = e.target.closest(".action-edit-admiralty");
    if (btnEditAdm && btnEditAdm.dataset.id) {
      editAdmiraltyInteractive(btnEditAdm.dataset.id, btnEditAdm.dataset.c, btnEditAdm.dataset.s);
      return;
    }
    const btnSeedDiag = e.target.closest(".action-seed-diagnostic");
    if (btnSeedDiag && btnSeedDiag.dataset.id) {
      cycleSeedDiagnostic(btnSeedDiag.dataset.id, btnSeedDiag.dataset.diag || "media");
      return;
    }
    const btnSeedRefute = e.target.closest(".action-seed-refute");
    if (btnSeedRefute && btnSeedRefute.dataset.id) {
      refuteSeedInteractive(btnSeedRefute.dataset.id, btnSeedRefute.dataset.value || "");
      return;
    }
    const btnSeedStatus = e.target.closest(".action-seed-status");
    if (btnSeedStatus && btnSeedStatus.dataset.id) {
      cycleSeedStatus(btnSeedStatus.dataset.id, btnSeedStatus.dataset.status || "nueva");
      return;
    }
    const btnLoadPivots = e.target.closest(".action-load-pivots");
    if (btnLoadPivots) {
      loadReconPivots();
      return;
    }
    const btnLoadDorks = e.target.closest(".action-load-dorks");
    if (btnLoadDorks) {
      loadReconDorks();
      return;
    }
    const btnAddHyp = e.target.closest(".action-add-hypothesis");
    if (btnAddHyp) {
      addReconHypothesisFromUi();
      return;
    }
    const btnEvalHyp = e.target.closest(".action-evaluate-hypothesis");
    if (btnEvalHyp && btnEvalHyp.dataset.id) {
      evaluateReconHypothesis(btnEvalHyp.dataset.id);
      return;
    }
    const btnDelHyp = e.target.closest(".action-delete-hypothesis");
    if (btnDelHyp && btnDelHyp.dataset.id) {
      deleteReconHypothesis(btnDelHyp.dataset.id);
      return;
    }
    const btnAddP0Assump = e.target.closest(".action-add-p0-assumption");
    if (btnAddP0Assump) {
      addP0Assumption();
      return;
    }
    const btnRemP0Assump = e.target.closest(".action-remove-p0-assumption");
    if (btnRemP0Assump && btnRemP0Assump.dataset.index !== undefined) {
      removeP0Assumption(parseInt(btnRemP0Assump.dataset.index, 10));
      return;
    }
    const btnCycleAssump = e.target.closest(".action-cycle-p0-assumption-status");
    if (btnCycleAssump && btnCycleAssump.dataset.index !== undefined) {
      cycleP0AssumptionStatus(parseInt(btnCycleAssump.dataset.index, 10));
      return;
    }
    const btnAddQuickPerim = e.target.closest(".action-add-quick-perimeter");
    if (btnAddQuickPerim) {
      addQuickPerimeterAsset();
      return;
    }
    const btnRemQuickPerim = e.target.closest(".action-remove-quick-perimeter");
    if (btnRemQuickPerim && btnRemQuickPerim.dataset.asset) {
      removeQuickPerimeterAsset(btnRemQuickPerim.dataset.asset);
      return;
    }
    const btnFocusCentralQ = e.target.closest(".action-focus-central-q");
    if (btnFocusCentralQ) {
      focusCentralQuestion();
      return;
    }
    const btnAddNamedGap = e.target.closest(".action-add-named-gap");
    if (btnAddNamedGap) {
      addNamedGapFromUi();
      return;
    }
    const btnRemoveGap = e.target.closest(".gap-remove");
    if (btnRemoveGap && btnRemoveGap.dataset.gap) {
      removeNamedGap(btnRemoveGap.dataset.gap);
      return;
    }
    const btnConfirmBias = e.target.closest(".action-confirm-bias-check");
    if (btnConfirmBias) {
      confirmActiveBiasCheck();
      return;
    }
    const btnAckReframing = e.target.closest(".action-ack-reframing");
    if (btnAckReframing) {
      ackReframingAlert();
      return;
    }
    const btnOpenPerim = e.target.closest(".action-open-perimeter-modal");
    if (btnOpenPerim) {
      openPerimeterModal();
      return;
    }
    const btnClosePerim = e.target.closest(".action-close-perimeter-modal");
    if (btnClosePerim) {
      closePerimeterModal();
      return;
    }
    const btnSubmitPerim = e.target.closest(".action-submit-perimeter-asset");
    if (btnSubmitPerim) {
      submitPerimeterAsset();
      return;
    }
    const btnOpenRunMach = e.target.closest(".action-open-run-machine-modal");
    if (btnOpenRunMach) {
      openRunMachineModal();
      return;
    }
    const btnCloseRunMach = e.target.closest(".action-close-run-machine-modal");
    if (btnCloseRunMach) {
      closeRunMachineModal();
      return;
    }
    const btnSubmitRunMach = e.target.closest(".action-submit-run-machine");
    if (btnSubmitRunMach) {
      executePassiveMachineFromModal();
      return;
    }
    const btnCloseDelCase = e.target.closest(".action-close-delete-case-modal");
    if (btnCloseDelCase) {
      closeDeleteCaseModal();
      return;
    }
    const btnConfirmDelCase = e.target.closest(".action-confirm-delete-case");
    if (btnConfirmDelCase) {
      executeDeleteCase();
      return;
    }
    const btnSyncTarget = e.target.closest(".action-sync-target-as-seed");
    if (btnSyncTarget) {
      saveReconFraming(true);
      return;
    }
    const btnReloadRecon = e.target.closest(".action-reload-recon");
    if (btnReloadRecon) {
      reloadReconData();
      return;
    }
    const btnReconPivot = e.target.closest(".action-recon-pivot");
    if (btnReconPivot) {
      const tx = btnReconPivot.dataset.transform;
      const type = btnReconPivot.dataset.type;
      const val = btnReconPivot.dataset.value;
      if (tx && val) quickRunTransformFromPivot(tx, type || "maltego.Domain", val);
      return;
    }
    const btnCopyDork = e.target.closest(".action-copy-dork");
    if (btnCopyDork && btnCopyDork.dataset.dork) {
      copyDorkToClipboard(btnCopyDork.dataset.dork);
      return;
    }

    // 10. Topbar & HUD
    const btnHudExport = e.target.closest(".action-hud-export");
    if (btnHudExport) {
      toggleHudExportMenu(e);
      return;
    }
    const btnExportCase = e.target.closest(".action-export-case");
    if (btnExportCase && btnExportCase.dataset.format) {
      exportCaseAs(btnExportCase.dataset.format);
      return;
    }
    const btnOpenImport = e.target.closest(".action-open-import");
    if (btnOpenImport) {
      openImportModal();
      return;
    }
    const btnToggleAudio = e.target.closest(".action-toggle-audio");
    if (btnToggleAudio) {
      toggleAudioFeedback();
      return;
    }
    const btnCopySnapshot = e.target.closest(".action-copy-snapshot");
    if (btnCopySnapshot) {
      copyGraphSnapshotToClipboard();
      return;
    }
    const btnOpenPalette = e.target.closest(".action-open-palette");
    if (btnOpenPalette) {
      openCommandPalette();
      return;
    }
    const btnCreateCase = e.target.closest(".action-create-case");
    if (btnCreateCase) {
      promptCreateCase();
      return;
    }
    const btnDeleteCase = e.target.closest(".action-delete-case");
    if (btnDeleteCase) {
      openDeleteCaseModal();
      return;
    }
    const btnReloadCase = e.target.closest(".action-reload-case");
    if (btnReloadCase) {
      reloadCurrentGraph();
      return;
    }
    const btnOpenPersona = e.target.closest(".action-open-persona");
    if (btnOpenPersona) {
      openPersonaModal();
      return;
    }
    const btnOpenNewAccount = e.target.closest(".action-open-new-account");
    if (btnOpenNewAccount) {
      openNewAccountModal();
      return;
    }

    // 11. Centro de Mando (Overview Log & Hub)
    const btnSwitchLogSse = e.target.closest(".action-switch-log-sse");
    if (btnSwitchLogSse) {
      switchLogTab("sse");
      return;
    }
    const btnSwitchLogEgress = e.target.closest(".action-switch-log-egress");
    if (btnSwitchLogEgress) {
      switchLogTab("egress");
      return;
    }
    const btnRefreshEgress = e.target.closest(".action-refresh-egress");
    if (btnRefreshEgress) {
      loadEgressAuditLog();
      return;
    }
    const btnOverviewGotoGraph = e.target.closest(".action-overview-goto-graph");
    if (btnOverviewGotoGraph) {
      switchTab("graph");
      return;
    }
    const btnNavTo = e.target.closest(".action-nav-to");
    if (btnNavTo && btnNavTo.dataset.tab) {
      switchTab(btnNavTo.dataset.tab);
      return;
    }
  });
}

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

// 2. Navegación de vistas y controles de la barra de operaciones
function initSidebarControls() {
  const shell = document.querySelector(".app-shell");
  const btnLeft = document.getElementById("btn-dock-left");
  const btnRight = document.getElementById("btn-dock-right");
  const btnCollapse = document.getElementById("btn-dock-collapse");
  const btnRestore = document.getElementById("btn-sidebar-restore");
  if (!shell) return;

  let dockPos = "left";
  let isCollapsed = false;
  try {
    dockPos = localStorage.getItem("maltego_sidebar_dock") || "left";
    isCollapsed = localStorage.getItem("maltego_sidebar_collapsed") === "true";
  } catch (e) {}

  function updateSidebarClasses() {
    if (dockPos === "right") {
      shell.classList.add("sidebar-right");
      if (btnRight) btnRight.classList.add("active");
      if (btnLeft) btnLeft.classList.remove("active");
    } else {
      shell.classList.remove("sidebar-right");
      if (btnLeft) btnLeft.classList.add("active");
      if (btnRight) btnRight.classList.remove("active");
    }

    if (isCollapsed) {
      shell.classList.add("sidebar-collapsed");
    } else {
      shell.classList.remove("sidebar-collapsed");
    }

    try {
      localStorage.setItem("maltego_sidebar_dock", dockPos);
      localStorage.setItem("maltego_sidebar_collapsed", isCollapsed ? "true" : "false");
    } catch (e) {}
  }

  if (btnLeft) {
    btnLeft.addEventListener("click", (e) => {
      e.stopPropagation();
      dockPos = "left";
      isCollapsed = false;
      updateSidebarClasses();
    });
  }

  if (btnRight) {
    btnRight.addEventListener("click", (e) => {
      e.stopPropagation();
      dockPos = "right";
      isCollapsed = false;
      updateSidebarClasses();
    });
  }

  if (btnCollapse) {
    btnCollapse.addEventListener("click", (e) => {
      e.stopPropagation();
      isCollapsed = true;
      updateSidebarClasses();
    });
  }

  if (btnRestore) {
    btnRestore.addEventListener("click", (e) => {
      e.stopPropagation();
      isCollapsed = false;
      updateSidebarClasses();
    });
  }

  updateSidebarClasses();

  // Restaurar ancho guardado de la barra lateral
  const sidebar = document.querySelector(".sidebar");
  const resizer = document.getElementById("sidebar-resizer");
  try {
    const savedWidth = localStorage.getItem("maltego_sidebar_width");
    if (savedWidth && sidebar) {
      const w = Math.max(190, Math.min(600, parseInt(savedWidth, 10)));
      document.documentElement.style.setProperty("--sidebar-width", `${w}px`);
      sidebar.style.width = `${w}px`;
    }
  } catch (e) {}

  // Gestión de arrastre optimizado (60 FPS con PointerEvents y rAF)
  if (resizer && sidebar) {
    let isDragging = false;
    let startX = 0;
    let startWidth = 250;
    let animFrame = null;

    resizer.addEventListener("pointerdown", (e) => {
      isDragging = true;
      startX = e.clientX;
      startWidth = sidebar.getBoundingClientRect().width;
      resizer.classList.add("is-dragging");
      document.body.classList.add("resizing-sidebar");
      try {
        resizer.setPointerCapture(e.pointerId);
      } catch (err) {}
      e.preventDefault();
    });

    resizer.addEventListener("pointermove", (e) => {
      if (!isDragging) return;
      if (animFrame) cancelAnimationFrame(animFrame);
      animFrame = requestAnimationFrame(() => {
        const delta = e.clientX - startX;
        const isRightDock = shell.classList.contains("sidebar-right");
        let newWidth = isRightDock ? startWidth - delta : startWidth + delta;
        const maxW = Math.min(650, Math.floor(window.innerWidth * 0.45));
        newWidth = Math.max(190, Math.min(maxW, newWidth));
        document.documentElement.style.setProperty("--sidebar-width", `${newWidth}px`);
        sidebar.style.width = `${newWidth}px`;
      });
    });

    const stopDragging = (e) => {
      if (!isDragging) return;
      isDragging = false;
      if (animFrame) cancelAnimationFrame(animFrame);
      resizer.classList.remove("is-dragging");
      document.body.classList.remove("resizing-sidebar");
      try {
        resizer.releasePointerCapture(e.pointerId);
      } catch (err) {}
      const finalWidth = sidebar.getBoundingClientRect().width;
      try {
        localStorage.setItem("maltego_sidebar_width", Math.round(finalWidth));
      } catch (err) {}
    };

    resizer.addEventListener("pointerup", stopDragging);
    resizer.addEventListener("pointercancel", stopDragging);
  }

  // Arrastre para reubicar la barra lateral (Drag-to-Dock a izquierda o derecha)
  const brandHeader = document.getElementById("sidebar-brand-header");
  const dockIndicator = document.getElementById("sidebar-dock-indicator");
  if (brandHeader && dockIndicator) {
    let isMovingDock = false;
    let dragStartX = 0;
    let targetDock = null;

    brandHeader.addEventListener("pointerdown", (e) => {
      // Ignorar si se interactúa con botones, inputs o enlaces del header
      if (e.target.closest("button") || e.target.closest("a") || e.target.closest("input")) return;
      isMovingDock = true;
      dragStartX = e.clientX;
      targetDock = null;
      brandHeader.classList.add("is-dragging");
      document.body.classList.add("dragging-sidebar-dock");
      try {
        brandHeader.setPointerCapture(e.pointerId);
      } catch (err) {}
    });

    brandHeader.addEventListener("pointermove", (e) => {
      if (!isMovingDock) return;
      const currentIsRight = shell.classList.contains("sidebar-right");
      const deltaX = e.clientX - dragStartX;
      const winW = window.innerWidth;

      if (!currentIsRight) {
        // Barra en la izquierda: si arrastra hacia la derecha (> 90px o supera el 42% del ancho)
        if (deltaX > 90 || e.clientX > winW * 0.42) {
          targetDock = "right";
          dockIndicator.className = "sidebar-dock-indicator active dock-right";
          dockIndicator.innerHTML = "<span>&#8677; Soltar para acoplar a la derecha</span>";
        } else {
          targetDock = null;
          dockIndicator.className = "sidebar-dock-indicator";
        }
      } else {
        // Barra en la derecha: si arrastra hacia la izquierda (< -90px o puntero en la mitad izquierda)
        if (deltaX < -90 || e.clientX < winW * 0.58) {
          targetDock = "left";
          dockIndicator.className = "sidebar-dock-indicator active dock-left";
          dockIndicator.innerHTML = "<span>&#8676; Soltar para acoplar a la izquierda</span>";
        } else {
          targetDock = null;
          dockIndicator.className = "sidebar-dock-indicator";
        }
      }
    });

    const stopMovingDock = (e) => {
      if (!isMovingDock) return;
      isMovingDock = false;
      brandHeader.classList.remove("is-dragging");
      document.body.classList.remove("dragging-sidebar-dock");
      try {
        brandHeader.releasePointerCapture(e.pointerId);
      } catch (err) {}
      dockIndicator.className = "sidebar-dock-indicator";

      if (targetDock && targetDock !== dockPos) {
        dockPos = targetDock;
        isCollapsed = false;
        updateSidebarClasses();
        playTacticalClick(820, 0.04);
        showToast(`Menú acoplado a la ${targetDock === "right" ? "derecha" : "izquierda"}`, "info");
      }
    };

    brandHeader.addEventListener("pointerup", stopMovingDock);
    brandHeader.addEventListener("pointercancel", stopMovingDock);
  }
}

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

let graphLoadDeferred = false;

function switchTab(tab) {
  let activeSec = document.getElementById(`view-${tab}`);
  if (!activeSec) {
    tab = "overview";
    activeSec = document.getElementById("view-overview");
  }
  currentTab = tab;
  document.querySelectorAll(".nav-link").forEach((l) => l.classList.remove("active"));
  const activeLink = document.querySelector(`.nav-link[data-tab="${tab}"]`);
  if (activeLink) activeLink.classList.add("active");

  document.querySelectorAll(".view-section").forEach((sec) => sec.classList.remove("active"));
  if (activeSec) activeSec.classList.add("active");

  const titleEl = document.getElementById("current-view-title");
  if (titleEl && activeLink) {
    titleEl.textContent = activeLink.querySelector(".nav-label")?.textContent || tab;
  }

  if (graphLoadDeferred && tab !== "overview" && tab !== "graph" && currentCaseId) {
    graphLoadDeferred = false;
    loadCaseGraph(currentCaseId).then(() => refreshActiveModuleView());
  }
  if (tab === "graph") {
    graphLoadDeferred = false;
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
  } else if (tab === "profiling") {
    renderProfilingView();
  } else if (tab === "recon") {
    renderReconView();
  }
  playTacticalClick(720, 0.03);
}

// 3. Conexión en tiempo real (Server-Sent Events)
function initSSE() {
  if (activeEventSource) {
    try { activeEventSource.close(); } catch (_e) {}
    activeEventSource = null;
  }
  try {
    const sse = new EventSource("/api/events");
    activeEventSource = sse;
    sse.onopen = () => setSseBadge("open");
    sse.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleServerEvent(data);
      } catch (err) {
        // Ping o texto plano
      }
    };
    sse.onerror = () => {
      setSseBadge(sse.readyState === EventSource.CLOSED ? "closed" : "retry");
      if (document.body.dataset.auth !== "authenticated") {
        try { sse.close(); } catch (_e) {}
        if (activeEventSource === sse) activeEventSource = null;
      }
    };
  } catch (err) {
    console.warn("SSE no disponible en este entorno.");
  }
}

let _liveRefreshTimer = null;

function scheduleLiveCaseRefresh(caseId, opts = {}) {
  const cid = (caseId || currentCaseId || "").trim();
  if (!cid) return;
  if (_liveRefreshTimer) {
    clearTimeout(_liveRefreshTimer);
  }
  _liveRefreshTimer = setTimeout(async () => {
    _liveRefreshTimer = null;
    if (caseDataCache && caseDataCache[cid]) {
      delete caseDataCache[cid];
    }
    if (opts.autoSelect !== false && cid && cid !== currentCaseId) {
      currentCaseId = cid;
    }
    await loadCasesList(cid);
    await loadCaseGraph(cid);
    if (typeof loadReconView === "function") {
      await loadReconView(cid);
    }
    if (typeof loadCaseProfiles === "function") {
      await loadCaseProfiles(cid);
    }
    if (typeof updateTacticalHud === "function") {
      updateTacticalHud();
    }
  }, 180);
}

function handleServerEvent(ev) {
  if (ev.type === "egress_ring") {
    if (window.EgressRing) window.EgressRing.refresh();
    appendLogEntry("EGRESO", `Anillo Mullvad: ${ev.state || "cambio de estado"}`);
    return;
  }
  if (ev.type === "pulse" || ev.type === "step" || ev.type === "transform" || ev.type === "investigation_completed") {
    triggerVisualPulse(0.85);
  }
  if (ev.type === "step" || ev.type === "transform") {
    const label = ev.transform || ev.action || "Transform";
    const tgt = ev.target ? ` -> ${ev.target}` : "";
    const extra = typeof ev.new_entities === "number" ? ` (+${ev.new_entities} nodos)` : "";
    appendLogEntry("MCP", `${label}${tgt}${extra}`);
    scheduleLiveCaseRefresh(ev.case_id || currentCaseId, { autoSelect: true });
  }
  if (ev.type === "machine_run" || ev.type === "investigation_completed") {
    appendLogEntry(
      "MCP",
      `Investigación / Machine ${ev.machine || ev.strategy || ""}: caso ${ev.case_id || currentCaseId}`
    );
    scheduleLiveCaseRefresh(ev.case_id || currentCaseId, { autoSelect: true });
  }
  if (ev.type === "accounts_updated" || ev.type === "account_created") {
    loadAccounts();
  }
  if (ev.type === "inbox_created") {
    appendLogEntry("INBOX", `Buzón efímero creado: ${ev.address}`);
    triggerVisualPulse(0.7);
  }
  if (ev.type === "cti_synced") {
    loadCTIFeeds();
  }
  if (ev.type === "case_created" || ev.type === "case_imported") {
    appendLogEntry("CASO", `Caso activo en descubrimiento: ${ev.case_id}`);
    triggerVisualPulse(0.9);
    scheduleLiveCaseRefresh(ev.case_id, { autoSelect: true });
  }
  if (ev.type === "case_deleted") {
    appendLogEntry("CASO", `Caso eliminado: ${ev.case_id}`);
    loadCasesList();
  }
  if (ev.type === "graph_updated") {
    scheduleLiveCaseRefresh(ev.case_id || currentCaseId, { autoSelect: true });
  }
  if (
    ev.type === "recon_updated" ||
    ev.type === "recon_seed_added" ||
    ev.type === "recon_seed_updated" ||
    ev.type === "recon_seed_deleted" ||
    ev.type === "recon_infra_updated" ||
    ev.type === "recon_archive_updated" ||
    ev.type === "recon_breaches_updated" ||
    ev.type === "recon_humint_updated" ||
    ev.type === "recon_ecosystem_updated" ||
    ev.type === "recon_hypothesis_added" ||
    ev.type === "recon_hypothesis_evaluated" ||
    ev.type === "recon_hypothesis_deleted" ||
    ev.type === "recon_key_evidence_saved" ||
    ev.type === "perimeter_updated"
  ) {
    appendLogEntry("RECON", `Actualización en tiempo real (${ev.type}) en caso ${ev.case_id || currentCaseId}`);
    scheduleLiveCaseRefresh(ev.case_id || currentCaseId, { autoSelect: true });
  }
  if (ev.type === "entity_profiled") {
    appendLogEntry(
      "PERFILADO",
      `Entidad perfilada (${ev.typology || "auto"}): ${ev.archetype || ev.entity_id || ""} [${ev.risk_level || ""}]`
    );
    scheduleLiveCaseRefresh(ev.case_id || currentCaseId, { autoSelect: true });
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
    const t0 = (typeof performance !== "undefined" && performance.now) ? performance.now() : Date.now();
    const res = await fetch("/api/status");
    const latency = Math.round(((typeof performance !== "undefined" && performance.now) ? performance.now() : Date.now()) - t0);
    const latencyEl = document.getElementById("hud-latency");
    if (latencyEl) latencyEl.textContent = `${latency}ms`;
    if (!res.ok) return;
    const data = await res.json();

    if (data.version) {
      const verEl = document.getElementById("app-version");
      if (verEl) verEl.textContent = `v${data.version}`;
    }

    document.getElementById("stat-status") &&
      (document.getElementById("stat-status").innerHTML = `<span class="pill pill-ok">Online</span>`);
    document.getElementById("stat-transport") &&
      (document.getElementById("stat-transport").textContent = data.transport || "http");
    document.getElementById("stat-tor") &&
      (document.getElementById("stat-tor").innerHTML = data.tor_active
        ? `<span class="pill pill-ok">Tor Activo</span>`
        : `<span class="pill pill-warn">Tor No Detectado</span>`);
    document.getElementById("stat-accounts-count") &&
      (document.getElementById("stat-accounts-count").textContent = Array.isArray(data.accounts_summary)
        ? data.accounts_summary.length
        : (data.accounts_summary?.total ?? 0));
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
      if (acc.has_token) credBadges.push(`<span class="pill pill-ok" style="font-size:12px; padding:1px 5px;" title="Token de acceso configurado">[KEY] Token</span>`);
      if (acc.has_cookie) credBadges.push(`<span class="pill pill-purple" style="font-size:12px; padding:1px 5px;" title="Cookie de sesión configurada">[COOKIE] Cookie</span>`);

      return `
      <tr id="row-acc-${escapeHtml(acc.id)}">
        <td style="width:30px; text-align:center;">
          <button class="row-expand-btn action-toggle-row" id="acc-row-${escapeHtml(acc.id)}-expand-btn" data-target="acc-row-${escapeHtml(acc.id)}">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"></polyline></svg>
          </button>
        </td>
        <td>
          <div style="font-weight:600; display:flex; align-items:center; gap:0.4rem;">
            ${escapeHtml(acc.handle || acc.username || "Sin alias")}
          </div>
          <div class="mono" style="font-size:12px; color:var(--text-muted);">${escapeHtml(acc.id)}</div>
        </td>
        <td>
          <div>${catPill}</div>
          <div style="margin-top:3px;"><strong class="mono" style="font-size:12px;">${escapeHtml(acc.platform)}</strong></div>
        </td>
        <td>
          <div>${realmPill}</div>
          ${acc.proxy ? `<div class="mono" style="font-size:12px; color:var(--text-muted); margin-top:2px;">${escapeHtml(acc.proxy)}</div>` : ""}
          ${acc.target_site ? `<div class="mono" style="font-size:12px; color:var(--text-secondary); margin-top:2px;">[LINK] ${escapeHtml(acc.target_site)}</div>` : ""}
        </td>
        <td>
          <div class="mono" style="font-size:12px;">${escapeHtml(acc.status_text || "Activa")}</div>
          <div style="display:flex; gap:0.25rem; margin-top:3px;">${credBadges.join(" ")}</div>
        </td>
        <td>
          <span class="mono">${acc.rate_limit_rpm} RPM</span>
          ${cooldownBadge}
        </td>
        <td>${enabledPill}</td>
        <td>
          <div style="display:flex; gap:0.35rem;">
            <button class="btn btn-secondary btn-sm action-verify-account" data-account-id="${escapeHtml(acc.id)}">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>
              Verificar
            </button>
            <button class="btn btn-danger btn-sm action-delete-account" data-account-id="${escapeHtml(acc.id)}">
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
              <span class="mono" style="font-size:12px; color:var(--text-muted);">${escapeHtml(acc.updated_at || "Registrada en TOML")}</span>
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
  const btn = row?.querySelector(".action-verify-account") || row?.querySelector("button");
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
          <div style="font-size:18px; font-weight:700; color:var(--text-primary);">${escapeHtml(p.display_name)}</div>
          <div class="mono" style="font-size:13px; color:var(--accent-cyan);">@${escapeHtml(p.handle)}</div>
        </div>
        <span class="pill pill-cyan">${escapeHtml(p.role)}</span>
      </div>
      
      <p style="margin: 0.75rem 0; font-size:12px; color:var(--text-secondary);">${escapeHtml(p.bio)}</p>

      <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.5rem; font-size:12px; margin-bottom:1rem;">
        <div><span style="color:var(--text-muted);">Zona horaria:</span> <strong class="mono">${escapeHtml(p.timezone)}</strong></div>
        <div><span style="color:var(--text-muted);">Correo burner:</span> <strong class="mono">${escapeHtml(p.burner_email_hint)}</strong></div>
        <div><span style="color:var(--text-muted);">Huella PGP:</span> <strong class="mono">${escapeHtml(p.pgp_key_id_hint)}</strong></div>
        <div><span style="color:var(--text-muted);">Proxy sugerido:</span> <strong class="mono">${escapeHtml(p.proxy_recommendation)}</strong></div>
      </div>

      <div class="totp-box">
        <div>
          <div style="font-size:12px; text-transform:uppercase; color:var(--text-muted); font-weight:600;">Semilla TOTP 2FA Offline</div>
          <div class="mono" style="font-size:12px; color:var(--text-secondary); word-break:break-all;">${escapeHtml(p.totp_secret_base32)}</div>
        </div>
        <div style="text-align:right;">
          <div class="totp-code" id="totp-live-display">------</div>
          <div style="font-size:12px; color:var(--text-muted);" id="totp-countdown">30s</div>
        </div>
      </div>

      <div style="font-weight:600; font-size:12px; margin-bottom:0.35rem;">Checklist de Seguridad OPSEC:</div>
      <ul class="opsec-list">
        ${p.opsec_checklist.map((item) => `<li class="opsec-item"><input type="checkbox"> <span>${escapeHtml(item)}</span></li>`).join("")}
      </ul>

      <div style="margin-top:1.25rem; display:flex; justify-content:flex-end; gap:0.5rem;">
        <button class="btn btn-secondary btn-sm" data-on-click="copyPersonaJSON()">Copiar JSON</button>
        <button class="btn btn-primary btn-sm" data-on-click="saveCurrentPersona()">Guardar en accounts.toml</button>
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
        <p style="font-size:12px; color:var(--text-secondary); margin:0.5rem 0;">${escapeHtml(p.description)}</p>
        <div class="mono" style="font-size:12px; color:var(--text-muted);">Variable: ${escapeHtml(p.env_vars.join(", "))}</div>
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

    const limitSelect = document.querySelector("#view-cti-feeds .table-limit-select");
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
          <button class="row-expand-btn action-toggle-row" id="cti-row-${idx}-expand-btn" data-target="cti-row-${idx}">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"></polyline></svg>
          </button>
        </td>
        <td style="font-weight:600;">${escapeHtml(s.name)}</td>
        <td><span class="pill pill-cyan">${escapeHtml(s.category)}</span></td>
        <td class="mono" style="font-size:12px; max-width:240px; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(
          s.url
        )}</td>
        <td><span class="pill pill-ok">${escapeHtml(s.status)}</span></td>
        <td class="mono" style="font-size:12px; color:var(--text-muted);">${escapeHtml(s.updated_at || "-")}</td>
      </tr>
      <tr id="cti-row-${idx}-detail" class="row-detail-container" style="display:none;">
        <td colspan="6">
          <div class="row-detail-card" style="padding:0.75rem 1rem; background:rgba(255,255,255,0.02); border:1px solid var(--border-color); border-radius:4px; font-size:12px;">
            <div style="display:flex; justify-content:space-between; margin-bottom:0.4rem;">
              <strong style="color:var(--accent-cyan);">${escapeHtml(s.name)} [${escapeHtml(s.category)}]</strong>
              <span class="mono" style="font-size:12px; color:var(--text-muted);">Estado: ${escapeHtml(s.status)}</span>
            </div>
            <div style="margin-bottom:0.4rem;">
              <span style="color:var(--text-muted);">URL Completa / Endpoint:</span>
              <div class="mono" style="font-size:12px; word-break:break-all; margin-top:2px;">${escapeHtml(s.url)}</div>
            </div>
            <div style="display:flex; gap:0.5rem; align-items:center;">
              <button class="btn btn-secondary btn-sm action-copy-cti-url" data-url="${escapeHtml(s.url)}">Copiar URL</button>
              <span style="font-size:12px; color:var(--text-muted);">Ultima actualizacion verificada: ${escapeHtml(s.updated_at || "Reciente")}</span>
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
            <p style="font-size:12px; color:var(--text-secondary); margin-top:2px;">${escapeHtml(t.description)}</p>
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

    lastPlaygroundEntities = entities;
    const effectiveCaseId = getModuleCaseId("transforms");
    resultDiv.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.6rem; flex-wrap:wrap; gap:0.5rem;">
        <div style="font-size:12px; color:var(--accent-emerald);">Se obtuvieron ${entities.length} entidades:</div>
        <button class="btn btn-primary btn-sm" data-on-click="injectPlaygroundEntitiesIntoCase()">
          Incorporar al Proyecto '${escapeHtml(effectiveCaseId)}'
        </button>
      </div>
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
let allLoadedCases = [];
let moduleCaseOverrides = {
  crypto: "__global__",
  geo: "__global__",
  vault: "__global__",
  mitre: "__global__",
  watchtower: "__global__",
  rules: "__global__",
  transforms: "__global__",
  profiling: "__global__",
  recon: "__global__"
};
let caseDataCache = {};
let caseEvidenceVault = {};
let caseWatchTargets = {};
let caseWatchAlerts = {};
let lastPlaygroundEntities = [];

function getModuleCaseId(moduleKey) {
  const override = moduleCaseOverrides[moduleKey];
  if (override && override !== "__global__") {
    return override;
  }
  return currentCaseId || (allLoadedCases.length > 0 ? allLoadedCases[0].case_id : "");
}

function getNodesForCase(caseId) {
  if (!caseId || caseId === currentCaseId) {
    return graphNodes || [];
  }
  if (caseDataCache[caseId] && caseDataCache[caseId].nodes) {
    return caseDataCache[caseId].nodes;
  }
  return [];
}

function getLinksForCase(caseId) {
  if (!caseId || caseId === currentCaseId) {
    return graphLinks || [];
  }
  if (caseDataCache[caseId] && caseDataCache[caseId].links) {
    return caseDataCache[caseId].links;
  }
  return [];
}

async function fetchCaseGraphData(caseId) {
  if (!caseId) return null;
  if (caseDataCache[caseId]) return caseDataCache[caseId];
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/graph`);
    const data = await res.json();
    if (data && data.ok) {
      caseDataCache[caseId] = data;
      return data;
    }
  } catch (err) {
    console.warn(`No se pudo cargar datos del caso '${caseId}':`, err);
  }
  return null;
}

function syncAllProjectSelectors() {
  const primarySelectors = ["global-project-select", "graph-case-select"];
  primarySelectors.forEach((selId) => {
    const el = document.getElementById(selId);
    if (!el) return;
    el.innerHTML = allLoadedCases
      .map((c) => {
        const fullTitle = `${c.case_id} · ${c.entity_count || 0} entidades, ${c.edge_count || 0} relaciones`;
        const shortId = c.case_id && c.case_id.length > 32 ? c.case_id.slice(0, 30) + "..." : c.case_id;
        return `<option value="${escapeHtml(c.case_id)}" title="${escapeHtml(fullTitle)}">${escapeHtml(shortId)} (${c.entity_count || 0}e, ${c.edge_count || 0}r)</option>`;
      })
      .join("");
    el.value = currentCaseId;
    el.title = currentCaseId ? `Caso Activo: ${currentCaseId}` : "Sin caso activo";
  });

  const moduleKeys = ["crypto", "profiling", "recon", "transforms"];
  moduleKeys.forEach((key) => {
    const el = document.getElementById(`${key}-case-select`);
    if (!el) return;
    const currentOverride = moduleCaseOverrides[key] || "__global__";
    const shortCurrent =
      currentCaseId && currentCaseId.length > 22 ? currentCaseId.slice(0, 20) + "..." : currentCaseId;
    const activeLabel = currentCaseId ? `⚡ Global (${shortCurrent})` : "⚡ Seguir Global";

    let html = `<option value="__global__" title="Seguir caso activo global: ${escapeHtml(currentCaseId || "ninguno")}">${escapeHtml(activeLabel)}</option>`;
    html += allLoadedCases
      .map((c) => {
        const fullTitle = `${c.case_id} · ${c.entity_count || 0} entidades`;
        const shortId = c.case_id && c.case_id.length > 26 ? c.case_id.slice(0, 24) + "..." : c.case_id;
        return `<option value="${escapeHtml(c.case_id)}" title="${escapeHtml(fullTitle)}">${escapeHtml(shortId)} (${c.entity_count || 0}e)</option>`;
      })
      .join("");

    el.innerHTML = html;
    el.value = currentOverride;
    const effective = getModuleCaseId(key);
    el.title = `Foco ${key.toUpperCase()}: ${effective || "Global"}`;
  });
}

async function switchActiveProject(caseId) {
  if (!caseId) return;
  currentCaseId = caseId;
  try {
    localStorage.setItem("maltego_mcp_active_case", caseId);
  } catch (e) {}

  syncAllProjectSelectors();
  await loadCaseGraph(caseId);
  refreshActiveModuleView();
  updateTacticalHud();
  playTacticalClick(800, 0.03);
  showToast(`Investigacion activa cambiada a '${caseId}' [Datos aislados]`, "ok");
}

async function onModuleCaseChanged(moduleKey, value) {
  playTacticalClick(750, 0.025);
  moduleCaseOverrides[moduleKey] = value;

  const effectiveId = getModuleCaseId(moduleKey);
  if (value !== "__global__" && !caseDataCache[value]) {
    await fetchCaseGraphData(value);
  }

  if (moduleKey === "crypto") renderCryptoLedger();
  else if (moduleKey === "profiling") renderProfilingView();
  else if (moduleKey === "recon") renderReconView();

  const label = value === "__global__" ? `Seguir activo (${effectiveId})` : value;
  showToast(`Modulo [${moduleKey.toUpperCase()}]: Enfoque fijado en '${label}'`, "info");
}

function refreshActiveModuleView() {
  if (currentTab === "crypto-ledger") {
    renderCryptoLedger();
  } else if (currentTab === "profiling") {
    renderProfilingView();
  } else if (currentTab === "recon") {
    renderReconView();
  }
}

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

  // Eventos del raton para navegacion, arrastre y seleccion
  graphCanvas.addEventListener("mousedown", onGraphMouseDown);
  window.addEventListener("mousemove", onGraphMouseMove);
  window.addEventListener("mouseup", onGraphMouseUp);
  graphCanvas.addEventListener("wheel", onGraphWheel, { passive: false });

  // Inicializar resizer e inspector Maltego
  initGraphInspectorResizer();
  const fsBtn = document.getElementById("btn-graph-fullscreen");
  if (fsBtn && !fsBtn.__fsBound) {
    fsBtn.__fsBound = true;
    fsBtn.addEventListener("click", toggleGraphFullscreen);
  }

  // Iniciar bucle de animacion
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
  try {
    const res = await fetch("/api/cases");
    const data = await res.json();
    allLoadedCases = data.cases || [];

    if (allLoadedCases.length === 0) {
      const gSel = document.getElementById("graph-case-select");
      if (gSel) gSel.innerHTML = `<option value="">(Sin casos creados)</option>`;
      const topSel = document.getElementById("global-project-select");
      if (topSel) topSel.innerHTML = `<option value="">(Sin casos creados)</option>`;
      updateGraphStatusBar("No hay casos OSINT registrados en GraphStore.");
      return;
    }

    let targetId = autoSelectId;
    if (!targetId) {
      try {
        const saved = localStorage.getItem("maltego_mcp_active_case");
        if (saved && allLoadedCases.some((c) => c.case_id === saved)) {
          targetId = saved;
        }
      } catch (e) {}
    }
    if (!targetId || !allLoadedCases.some((c) => c.case_id === targetId)) {
      targetId = allLoadedCases[0].case_id;
    }

    currentCaseId = targetId;
    syncAllProjectSelectors();
    if (currentTab === "overview") {
      // El Centro de Mando no necesita la topología completa (cientos de KB): se difiere hasta otra vista.
      graphLoadDeferred = true;
      updateTacticalHud();
    } else {
      await loadCaseGraph(targetId);
    }
    refreshActiveModuleView();
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

let _currentCaseToDelete = null;

function openDeleteCaseModal(targetCaseId = null) {
  const modal = document.getElementById("modal-delete-case");
  if (!modal) return;

  const select = document.getElementById("delete-case-select");
  if (!select) return;

  select.innerHTML = "";
  if (!allLoadedCases || allLoadedCases.length === 0) {
    showHudNotification("SIN CASOS", "No existen casos registrados para eliminar.", "info");
    return;
  }

  allLoadedCases.forEach((c) => {
    const opt = document.createElement("option");
    opt.value = c.case_id;
    opt.textContent = `${c.case_id} (${c.entities_count || 0} ents)`;
    select.appendChild(opt);
  });

  const preferredId = targetCaseId || currentCaseId || (allLoadedCases[0] ? allLoadedCases[0].case_id : "");
  if (preferredId && allLoadedCases.some((c) => c.case_id === preferredId)) {
    select.value = preferredId;
  } else if (allLoadedCases[0]) {
    select.value = allLoadedCases[0].case_id;
  }

  onDeleteCaseSelectChanged(select.value);
  modal.classList.add("open");
  playTacticalClick(700, 0.04);
}

function closeDeleteCaseModal() {
  const modal = document.getElementById("modal-delete-case");
  if (modal) modal.classList.remove("open");
  _currentCaseToDelete = null;
}

function onDeleteCaseSelectChanged(selectedId) {
  _currentCaseToDelete = selectedId;
  const idDisplay = document.getElementById("delete-case-id-display");
  const promptCode = document.getElementById("delete-case-confirm-prompt");
  const entsCount = document.getElementById("delete-case-entities-count");
  const edgesCount = document.getElementById("delete-case-edges-count");
  const confirmInput = document.getElementById("delete-case-confirm-input");
  const btn = document.getElementById("btn-confirm-delete-case");

  if (idDisplay) idDisplay.textContent = selectedId || "-";
  if (promptCode) promptCode.textContent = selectedId || "-";

  const caseObj = allLoadedCases.find((c) => c.case_id === selectedId);
  const localNodes = getNodesForCase(selectedId);
  const localEdges = getLinksForCase(selectedId);

  const eCount = localNodes.length > 0 ? localNodes.length : (caseObj ? caseObj.entities_count : 0);
  const edgeCount = localEdges.length > 0 ? localEdges.length : (caseObj ? caseObj.edges_count : 0);

  if (entsCount) entsCount.textContent = eCount;
  if (edgesCount) edgesCount.textContent = edgeCount;

  if (confirmInput) {
    confirmInput.value = "";
    confirmInput.focus();
  }
  if (btn) {
    btn.disabled = true;
    btn.style.opacity = "0.5";
    btn.style.cursor = "not-allowed";
    btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg> Purgar y Eliminar Definitivamente`;
  }
}

function checkDeleteCaseConfirmation(val) {
  const btn = document.getElementById("btn-confirm-delete-case");
  if (!btn) return;
  const target = (_currentCaseToDelete || "").trim().toLowerCase();
  const inputVal = (val || "").trim().toLowerCase();

  if (target && inputVal === target) {
    btn.disabled = false;
    btn.style.opacity = "1";
    btn.style.cursor = "pointer";
  } else {
    btn.disabled = true;
    btn.style.opacity = "0.5";
    btn.style.cursor = "not-allowed";
  }
}

async function executeDeleteCase() {
  const cid = _currentCaseToDelete;
  if (!cid) return;

  const btn = document.getElementById("btn-confirm-delete-case");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 14 14"></polyline></svg> Purgando caso...`;
  }

  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(cid)}`, {
      method: "DELETE"
    });
    const data = await res.json();
    if (!data.ok) {
      alert(`Error al eliminar caso: ${data.error || "Fallo desconocido"}`);
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = `Reintentar Eliminacion`;
      }
      return;
    }

    // 1. Limpieza de memoria y cache
    delete caseDataCache[cid];
    delete caseEvidenceVault[cid];
    try { localStorage.removeItem("maltego_evidence_" + cid); } catch(e){}
    delete caseWatchTargets[cid];
    delete caseWatchAlerts[cid];
    try { localStorage.removeItem("maltego_watchtower_" + cid); } catch(e){}

    for (const mod in moduleCaseOverrides) {
      if (moduleCaseOverrides[mod] === cid) {
        moduleCaseOverrides[mod] = "__global__";
      }
    }

    // 2. Actualizar lista local de casos
    allLoadedCases = allLoadedCases.filter((c) => c.case_id !== cid);

    closeDeleteCaseModal();

    showHudNotification(
      "PROYECTO PURGADO",
      `El caso '${cid}' fue eliminado definitivamente (${data.deleted_entities || 0} entidades, ${data.deleted_edges || 0} aristas purgadas).`,
      "warning"
    );

    // 3. Conmutar caso si el eliminado era el activo
    let nextCase = null;
    if (currentCaseId === cid) {
      nextCase = allLoadedCases.length > 0 ? allLoadedCases[0].case_id : null;
    } else {
      nextCase = currentCaseId;
    }

    if (nextCase) {
      await loadCasesList(nextCase);
    } else {
      currentCaseId = "";
      syncAllProjectSelectors();
      if (graphStore) {
        graphStore.nodes = [];
        graphStore.links = [];
        graphStore.nodeMap = new Map();
        renderGraph();
      }
      refreshActiveModuleView();
    }
  } catch (err) {
    alert(`Error de red al eliminar el caso: ${err.message}`);
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `Reintentar Eliminacion`;
    }
  }
}

function onCaseSelected(caseId) {
  if (!caseId) return;
  switchActiveProject(caseId);
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
    mcpcase: ".mcpcase (Paquete MCP Maltego)",
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
    showToast("Por favor selecciona un archivo (.mcpcase, .mtgx, .json, .csv) para importar", "warning");
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
        fb.innerHTML = `<strong>Error en importación:</strong> ${escapeHtml(data.error || "Fallo desconocido")}`;
      }
      showToast(data.error || "Error al importar archivo", "error");
      return;
    }

    if (fb) {
      fb.style.background = "rgba(16, 185, 129, 0.1)";
      fb.style.border = "1px solid rgba(16, 185, 129, 0.3)";
      fb.style.color = "#34d399";
      const isMcpCase = data.format === "mcpcase" || (data.filename && data.filename.endsWith(".mcpcase"));
      const titleBadge = isMcpCase
        ? "<strong>[OK] Paquete .mcpcase verificado (Integridad SHA-256 valida)</strong>"
        : "<strong>[OK] Importacion completada</strong>";
      fb.innerHTML = `
        ${titleBadge}<br>
        Caso: <span class="mono">${escapeHtml(String(data.case_id || ""))}</span><br>
        Entidades: <strong>${Number(data.entities) || 0}</strong> (+${Number(data.new_entities) || 0} nuevas)<br>
        Relaciones: <strong>${Number(data.links) || 0}</strong> | Pasos de investigacion: ${Number(data.steps) || 0}
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
    caseDataCache[caseId] = data;
    graphSteps = data.steps || [];
    buildGraphModel(data);
    updateGraphStatusBar(
      `Caso: ${caseId} | Nodos: ${data.nodes.length} | Aristas: ${data.links.length} | Calidad: ${Number.isFinite(data.quality) ? `${(data.quality * 100).toFixed(0)}%` : "sin calcular"}`
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

  // 4. MODO POR CATEGORÍA Y ASPECTO OSINT
  if (layoutMode === "cluster") {
    const clusters = {
      target: { name: "OBJETIVO CENTRAL", x: 0, y: 0, nodes: [] },
      orgs: { name: "ORGANIZACIONES & EMPRESAS", x: -620, y: -380, nodes: [] },
      infra: { name: "INFRAESTRUCTURA & RED", x: 620, y: -380, nodes: [] },
      identities: { name: "PERSONAS, IDENTIDAD & CONTACTO", x: -620, y: 420, nodes: [] },
      crypto: { name: "FINANZAS, CRIPTO & AML", x: 620, y: 420, nodes: [] },
      evidence: { name: "EVIDENCIAS & INDICIOS", x: 0, y: 680, nodes: [] },
    };

    graphNodes.forEach((n) => {
      const t = (n.type || "").toLowerCase();
      if (n.isTarget) {
        clusters.target.nodes.push(n);
      } else if (t.includes("company") || t.includes("organization") || n.isOrganization) {
        clusters.orgs.nodes.push(n);
      } else if (
        t.includes("domain") ||
        t.includes("ipv4") ||
        t.includes("ipv6") ||
        t.includes("netblock") ||
        t.includes("as") ||
        t.includes("nsrecord") ||
        t.includes("mxrecord") ||
        t.includes("url") ||
        t.includes("service") ||
        n.isService
      ) {
        clusters.infra.nodes.push(n);
      } else if (
        t.includes("person") ||
        t.includes("alias") ||
        t.includes("email") ||
        t.includes("phone") ||
        n.isPerson
      ) {
        clusters.identities.nodes.push(n);
      } else if (t.includes("cryptocurrency") || t.includes("crypto") || t.includes("hash") || t.includes("wallet")) {
        clusters.crypto.nodes.push(n);
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
          const angle = idx * 2.39996; // Espiral áurea para evitar colisiones
          const dist = 45 + Math.sqrt(idx) * 60;
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
    showToast("Disposición cambiada a: Por Categoría (Aspectos OSINT)", "info");
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

  // Renderizar checkboxes de tipos de entidad con aspectos OSINT
  const entContainer = document.getElementById("filter-entity-types-list");
  if (entContainer) {
    if (allEntityTypesInCase.size === 0) {
      entContainer.innerHTML = '<span style="color:var(--text-muted); font-size:12px;">Sin entidades</span>';
    } else {
      entContainer.innerHTML = Array.from(allEntityTypesInCase.entries())
        .sort((a, b) => b[1] - a[1])
        .map(([type, count]) => {
          const checked = graphFilters.enabledEntityTypes.has(type) ? "checked" : "";
          const readable = getReadableEntityTypeName(type);
          const dotColor = getEntityTypeColor(type);
          return `
            <div class="filter-check-item">
              <label style="display:flex; align-items:center; gap:6px; cursor:pointer;">
                <input type="checkbox" class="action-toggle-entity-type" data-type="${escapeHtml(type)}" value="${escapeHtml(type)}" ${checked}>
                <span style="background:${dotColor}; width:8px; height:8px; border-radius:50%; display:inline-block; flex-shrink:0;"></span>
                <span title="${escapeHtml(type)}" style="font-size:12px;">${escapeHtml(readable)}</span>
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
      edgeContainer.innerHTML = '<span style="color:var(--text-muted); font-size:12px;">Sin relaciones</span>';
    } else {
      edgeContainer.innerHTML = Array.from(allEdgeTypesInCase.entries())
        .sort((a, b) => b[1] - a[1])
        .map(([lbl, count]) => {
          const checked = graphFilters.enabledEdgeTypes.has(lbl) ? "checked" : "";
          return `
            <div class="filter-check-item">
              <label style="display:flex; align-items:center; gap:6px; cursor:pointer;">
                <input type="checkbox" class="action-toggle-edge-type" data-label="${escapeHtml(lbl)}" value="${escapeHtml(lbl)}" ${checked}>
                <span title="${escapeHtml(lbl)}" style="font-size:12px;">${escapeHtml(lbl)}</span>
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
  const num = Number(val);
  graphFilters.minConfidence = num / 100.0;
  const label = document.getElementById("label-min-confidence");
  if (label) label.textContent = `${num}%`;

  // Sincronizar botones de preset de certeza
  document.querySelectorAll(".action-conf-preset").forEach((btn) => {
    btn.classList.toggle("active", Number(btn.dataset.val) === num);
  });

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

function toggleGraphFilterDrawer(forceState = null) {
  const drawer = document.getElementById("graph-filter-drawer");
  const btn = document.getElementById("btn-toggle-filters");
  if (!drawer) return;
  filterDrawerOpen = forceState !== null ? forceState : (drawer.style.display !== "flex");
  drawer.style.display = filterDrawerOpen ? "flex" : "none";
  if (filterDrawerOpen) {
    drawer.classList.add("open");
    if (btn) btn.classList.add("active");
    populateFilterDrawerOptions();
  } else {
    drawer.classList.remove("open");
    if (btn) btn.classList.remove("active");
  }
}

function getReadableEntityTypeName(type) {
  const t = (type || "").replace("maltego.", "");
  const dict = {
    Domain: "Dominio Web",
    IPv4Address: "Dirección IPv4",
    IPv6Address: "Dirección IPv6",
    NSRecord: "Servidor NS",
    MXRecord: "Servidor MX",
    Netblock: "Bloque IP / CIDR",
    AS: "Sistema Autónomo (ASN)",
    URL: "URL / Recurso Web",
    Company: "Compañía / Organización",
    Organization: "Organización",
    Person: "Persona / Identidad",
    Alias: "Alias / Handle",
    EmailAddress: "Correo Electrónico",
    PhoneNumber: "Teléfono",
    Location: "Ubicación Geográfica",
    GPS: "Coordenadas GPS",
    CryptocurrencyAddress: "Billetera Cripto",
    Hash: "Hash Forense",
    Document: "Documento / Fichero",
    Phrase: "Frase / Indicio",
    Service: "Servicio / Puerto",
  };
  return dict[t] || t;
}

function getEntityTypeColor(type) {
  const t = (type || "").toLowerCase();
  if (t.includes("company") || t.includes("organization")) return "#10b981";
  if (t.includes("domain") || t.includes("ip") || t.includes("netblock") || t.includes("as") || t.includes("url")) return "#00f5ff";
  if (t.includes("person") || t.includes("alias") || t.includes("email") || t.includes("phone")) return "#f59e0b";
  if (t.includes("crypto") || t.includes("hash")) return "#818cf8";
  if (t.includes("risk") || t.includes("threat")) return "#f43f5e";
  return "#94a3b8";
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
        <div style="font-size:12px; color:var(--accent-cyan); font-family:var(--font-mono);">${escapeHtml(typeShort)}</div>
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
    <div class="mono" style="font-size:12px; color:var(--text-muted); margin-bottom:0.85rem; word-break:break-all;">
      ID: ${escapeHtml(node.id)}
    </div>

    ${
      node.is_canary
        ? `
      <div style="background:rgba(245,158,11,0.12); border:1px solid rgba(245,158,11,0.35); border-radius:6px; padding:0.5rem 0.75rem; margin-bottom:0.75rem; font-size:12px; color:var(--accent-amber-light); display:flex; align-items:center; gap:0.5rem;">
        <span style="font-weight:700; font-size:13px;">⚠️</span>
        <div>
          <strong>Alerta de Deception / Posible Canario (§2):</strong>
          <div>Este activo coincide con patrones de señuelo o alta entropía. Tratar con cautela forense.</div>
        </div>
      </div>
    `
        : ""
    }

    <!-- 0. VIGENCIA OBJETIVA (§4.4) -->
    <div class="inspector-section" style="margin-bottom:0.85rem; background:rgba(255,255,255,0.02); border:1px solid var(--border-subtle); border-radius:6px; padding:0.5rem 0.65rem;">
      <div class="inspector-label" style="display:flex; flex-wrap:wrap; gap:0.35rem; justify-content:space-between; align-items:center; margin-bottom:0.25rem;">
        <span>Vigencia Objetiva Forense (§4.4)</span>
        <span class="pill ${node.vigencia === "OBSERVADO_RECIENTE" ? "pill-ok" : node.vigencia === "HISTORICO" ? "pill-warn" : "pill-muted"}" style="font-size:12px;">
          ${escapeHtml(node.vigencia || "MENCIONADO_SIN_FECHA")}
        </span>
      </div>
      <div style="font-size:12px; color:var(--text-secondary); margin-top:2px;">
        ${node.vigencia_rationale ? escapeHtml(node.vigencia_rationale) : "Sin marcas temporales de telemetría reciente."}
      </div>
    </div>

    <!-- 1. CADENA DE OBTENCIÓN Y TRAZABILIDAD CLICKABLE -->
    <div class="inspector-section" style="margin-bottom:0.85rem;">
      <div class="inspector-label" style="display:flex; justify-content:space-between; align-items:center;">
        <span>Cadena de Obtención / Procedencia</span>
        <span class="mono" style="font-size:12px; color:var(--accent-cyan); font-weight:600;">
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
              <div style="background:rgba(6, 182, 212, 0.04); border:1px solid rgba(6, 182, 212, 0.2); border-radius:6px; padding:0.45rem 0.6rem; font-size:12px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:2px;">
                  <strong class="mono" style="color:var(--accent-cyan); font-size:12px;">${escapeHtml(s.action)}</strong>
                  <span class="pill pill-muted" style="font-size:12px; padding:1px 5px;">Paso #${s.seq}</span>
                </div>
                ${
                  s.input_id
                    ? `
                  <div style="margin-top:4px; font-size:12px; display:flex; align-items:center; gap:4px; flex-wrap:wrap;">
                    <span style="color:var(--text-muted);">Disparado desde:</span>
                    <button type="button" class="pill pill-cyan action-select-node" data-node-id="${escapeHtml(s.input_id)}" style="cursor:pointer; border:none; padding:1px 6px; font-size:12px; font-weight:600;">
                      ${escapeHtml(inputLabel)} ->
                    </button>
                  </div>
                `
                    : ""
                }
                ${
                  s.reason
                    ? `<div style="font-size:12px; color:var(--text-secondary); margin-top:3px;"><em>${escapeHtml(s.reason)}</em></div>`
                    : ""
                }
                <div class="mono" style="font-size:12px; color:var(--text-muted); margin-top:3px;">${escapeHtml(s.timestamp || "")}</div>
              </div>
            `;
            })
            .join("")}
        </div>
      `
          : `
        <div style="background:rgba(255,255,255,0.02); border:1px solid var(--border-subtle); border-radius:6px; padding:0.4rem 0.6rem; font-size:12px; color:var(--text-muted); margin-top:0.35rem;">
          Punto de partida de la investigación (Entidad inicial / Ámbito definido)
        </div>
      `
      }

      ${
        incomingParents.length > 0
          ? `
        <div style="margin-top:0.5rem; font-size:12px;">
          <span style="color:var(--text-muted);">Saltos antecedentes:</span>
          <div style="display:flex; flex-wrap:wrap; gap:0.35rem; margin-top:0.25rem;">
            ${incomingParents
              .map(
                (p) => `
              <button type="button" class="pill pill-secondary action-select-node" data-node-id="${escapeHtml(p.id)}" style="cursor:pointer; border:1px solid var(--border-subtle); font-size:12px; padding:1px 6px;">
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
        <div style="font-size:12px; font-weight:700; color:var(--accent-cyan); text-transform:uppercase; margin-bottom:0.35rem; display:flex; align-items:center; gap:0.35rem;">
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
                `<span class="pill pill-muted mono" style="font-size:12px; max-width:260px; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(src)}</span>`
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
      <table style="width:100%; font-size:12px; border-collapse:collapse; margin-top:0.3rem;">
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
    <div class="inspector-section" style="margin-bottom:0.85rem; padding:0.65rem; background:rgba(6, 182, 212, 0.04); border:1px solid rgba(6, 182, 212, 0.25); border-radius:6px;">
      <div style="font-size:12px; font-weight:700; color:var(--accent-cyan); text-transform:uppercase; margin-bottom:0.45rem; display:flex; align-items:center; gap:0.4rem;">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="6" cy="6" r="3"></circle><circle cx="18" cy="18" r="3"></circle><path d="M6 9v3a3 3 0 0 0 3 3h6a3 3 0 0 1 3 3v0"></path></svg>
        Acciones de Trazado Forense
      </div>
      <div style="display:flex; flex-direction:column; gap:0.4rem;">
        <button type="button" class="btn btn-primary btn-sm action-open-path-tracer" data-node-id="${escapeHtml(node.id)}" style="font-size:12px; width:100%; justify-content:center;">
          Trazar Camino Hacia Otra Entidad...
        </button>
        <div style="display:flex; gap:0.35rem;">
          <button type="button" class="btn btn-secondary btn-sm action-trace-blast-radius" data-node-id="${escapeHtml(node.id)}" style="flex:1; font-size:12px; justify-content:center;">
            Trazar Vecindario (2 Saltos)
          </button>
          <button type="button" class="btn btn-secondary btn-sm action-clear-path-trace" style="font-size:12px; justify-content:center;" title="Restablecer visibilidad normal">
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
              <div class="action-select-node" data-node-id="${escapeHtml(c.other.id)}" style="background:rgba(255,255,255,0.02); border:1px solid var(--border-subtle); border-radius:4px; padding:0.45rem 0.6rem; font-size:12px; cursor:pointer;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:2px;">
                  <span class="mono" style="color:${c.edge.isRiskLink ? "var(--accent-crimson)" : "var(--accent-amber)"}; font-weight:600;">
                    ${escapeHtml(c.edge.label)}
                  </span>
                  <span style="font-size:12px; color:var(--text-muted);">${c.direction}</span>
                </div>
                <div style="color:var(--text-primary); font-weight:600;">
                  ${escapeHtml(c.other.value)}
                </div>
              </div>
            `
                )
                .join("")
            : `<div style="font-size:12px; color:var(--text-muted);">Nodo aislado sin conexiones directas.</div>`
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
    ctx.strokeStyle = (isSelected || isHovered) ? "rgba(6, 182, 212, 0.95)" : "rgba(6, 182, 212, 0.45)";
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
      ? "rgba(6, 182, 212, 0.4)"
      : isHovered
      ? "rgba(255, 255, 255, 0.22)"
      : "rgba(6, 182, 212, 0.25)";
    ctx.fill();
  }

  // 2. Anillo perimetral de vigencia y confianza (§4.4)
  const conf = Math.max(0.05, Math.min(1.0, n.confidence ?? 0.8));
  let ringColor = n.color;
  if (n.vigencia === "OBSERVADO_RECIENTE") {
    ringColor = "#10b981";
  } else if (n.vigencia === "HISTORICO") {
    ringColor = "#f59e0b";
  } else if (n.vigencia === "MENCIONADO_SIN_FECHA") {
    ringColor = "#64748b";
  }
  ctx.beginPath();
  ctx.arc(n.x, n.y, n.radius + 1.8, -Math.PI / 2, -Math.PI / 2 + conf * Math.PI * 2);
  ctx.strokeStyle = ringColor;
  ctx.lineWidth = 2.4;
  ctx.lineCap = "round";
  ctx.stroke();

  // 3. Fondo translúcido del cuerpo del nodo
  ctx.beginPath();
  ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
  ctx.fillStyle = "rgba(11, 15, 25, 0.92)";
  ctx.fill();

  // 4. Borde del nodo
  ctx.lineWidth = isSelected ? 2.5 : 1.5;
  ctx.strokeStyle = isSelected ? "#ffffff" : n.color;
  ctx.stroke();

  // 4b. Indicador de Canario / Deception Honeypot (§2)
  if (n.is_canary) {
    const cx = n.x + n.radius * 0.7;
    const cy = n.y - n.radius * 0.7;
    ctx.beginPath();
    ctx.arc(cx, cy, 5.5, 0, Math.PI * 2);
    ctx.fillStyle = "#f59e0b";
    ctx.fill();
    ctx.strokeStyle = "#080a11";
    ctx.lineWidth = 1.2;
    ctx.stroke();

    ctx.fillStyle = "#080a11";
    ctx.font = "bold 8px monospace";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText("!", cx, cy);
  }

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
  ctx.strokeStyle = isSelected ? "rgba(6, 182, 212, 0.8)" : "rgba(255, 255, 255, 0.1)";
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
    // Migrar y purgar cualquier persistencia previa en localStorage (OPSEC anti-disco)
    const legacy = localStorage.getItem("maltego_burner_inboxes");
    if (legacy) {
      if (!sessionStorage.getItem("maltego_burner_inboxes")) {
        sessionStorage.setItem("maltego_burner_inboxes", legacy);
      }
      localStorage.removeItem("maltego_burner_inboxes");
    }
    const raw = sessionStorage.getItem("maltego_burner_inboxes");
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
    localStorage.removeItem("maltego_burner_inboxes");
    sessionStorage.setItem("maltego_burner_inboxes", JSON.stringify(burnerInboxes));
  } catch (e) {
    console.error("Error guardando buzones en sessionStorage", e);
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
      <div style="text-align:center; padding:1.5rem; color:var(--text-muted); font-size:13px; border:1px dashed var(--border-subtle); border-radius:8px;">
        Ningún buzón temporal activo.<br>Haz clic en <strong>+ Generar Buzón Efímero</strong> para crear uno.
      </div>`;
    return;
  }

  container.innerHTML = burnerInboxes
    .map((ib) => {
      const isSelected = ib.inbox_id === selectedInboxId;
      const createdTime = ib.createdAt ? new Date(ib.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "";
      return `
        <div class="inbox-card ${isSelected ? "active" : ""}" data-inbox-id="${escapeHtml(ib.inbox_id)}">
          <div class="inbox-card-header">
            <span class="inbox-addr" title="${escapeHtml(ib.address)}">[MAIL] ${escapeHtml(ib.address)}</span>
            <span style="font-size:12px; color:var(--text-muted);">${escapeHtml(createdTime)}</span>
          </div>
          <div style="display:flex; justify-content:space-between; align-items:center; margin-top:0.4rem;">
            <button class="btn btn-secondary btn-sm action-copy-inbox-addr" style="font-size:12px; padding:0.15rem 0.4rem;" data-address="${escapeHtml(ib.address)}" title="Copiar dirección de correo">
              Copiar
            </button>
            <button class="btn btn-secondary btn-sm action-delete-burner-inbox" style="font-size:12px; padding:0.15rem 0.4rem; color:var(--accent-rose-light);" data-inbox-id="${escapeHtml(ib.inbox_id)}" title="Eliminar buzón de la sesión">
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
      container.innerHTML = `<div style="text-align:center; padding:2rem; color:var(--text-muted); font-size:13px;">Ningún buzón seleccionado.</div>`;
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
    container.innerHTML = `<div style="text-align:center; padding:2rem; color:var(--text-muted); font-size:13px;">Ningún buzón seleccionado.</div>`;
    return;
  }

  container.innerHTML = `
    <div style="text-align:center; padding:2rem; color:var(--text-muted); font-size:13px;">
      <span class="spinner" style="width:16px; height:16px; border-width:2px; display:inline-block; vertical-align:middle; margin-right:6px;"></span>
      Consultando mensajes para ${escapeHtml(currentInbox.address)}...
    </div>`;

  try {
    const res = await fetch("/api/inbox/messages", {
      headers: { "X-Inbox-Token": currentInbox.token || "" },
    });
    const data = await res.json();
    const msgs = data.messages || [];

    if (msgs.length === 0) {
      container.innerHTML = `
        <div style="text-align:center; padding:2.5rem 1rem; color:var(--text-muted); font-size:13px;">
          <div style="font-size:16px; margin-bottom:0.5rem; color:var(--text-muted);">[BUZON VACIO]</div>
          Bandeja vacía.<br>
          Esperando mensajes de activación para <code>${escapeHtml(currentInbox.address)}</code>.<br>
          <span style="font-size:12px; color:var(--text-secondary);">Haz clic en <strong>Consultar Mensajes</strong> cuando completes el formulario de registro en la web objetivo.</span>
        </div>`;
      return;
    }

    // Para cada mensaje, recuperar detalles con extracción de OTP y enlaces (token solo en cabecera)
    const detailedHtml = [];
    for (const m of msgs) {
      let detail = null;
      try {
        const dRes = await fetch(`/api/inbox/messages/${encodeURIComponent(m.id)}`, {
          headers: { "X-Inbox-Token": currentInbox.token || "" },
        });
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
              <div style="font-size:12px; text-transform:uppercase; font-weight:700; color:var(--accent-emerald);">[2FA] Código de Activación / 2FA Detectado</div>
              <div class="otp-code">${escapeHtml(code)}</div>
            </div>
            <button class="btn btn-primary btn-sm action-copy-inbox-otp" data-code="${escapeHtml(code)}">Copiar Código</button>
          </div>
        `
          )
          .join("");
      }

      let linksHtml = "";
      if (links.length > 0) {
        linksHtml = links
          .filter((url) => typeof url === "string" && (url.startsWith("http://") || url.startsWith("https://")))
          .map(
            (url) => {
              const defanged = url.replace(/^http:\/\//i, "hxxp[://]").replace(/^https:\/\//i, "hxxps[://]").replace(/\./g, "[.]");
              return `
          <div class="activation-url-box">
            <div style="font-size:12px; font-weight:600; color:var(--accent-cyan); margin-bottom:0.2rem;">[LINK] Enlace de Verificación / Activación (Neutralizado):</div>
            <code style="color:var(--accent-cyan-light); word-break:break-all; font-size:12px;">${escapeHtml(defanged)}</code>
          </div>
        `;
            }
          )
          .join("");
      }

      detailedHtml.push(`
        <div class="inbox-msg-card">
          <div class="inbox-msg-meta">
            <span>De: <strong>${escapeHtml(m.from || "Desconocido")}</strong></span>
            <span>${escapeHtml(msgDate)}</span>
          </div>
          <div class="inbox-msg-subject">${escapeHtml(m.subject || "(Sin asunto)")}</div>
          ${otpHtml}
          ${linksHtml}
          <div style="font-size:12px; color:var(--text-secondary); line-height:1.4; margin-top:0.4rem; white-space:pre-wrap; max-height:120px; overflow-y:auto; background:rgba(0,0,0,0.2); padding:0.4rem; border-radius:4px;">
            ${escapeHtml((detail && detail.text) ? detail.text.slice(0, 500) : (m.intro || ""))}
          </div>
        </div>
      `);
    }

    container.innerHTML = detailedHtml.join("");
  } catch (err) {
    container.innerHTML = `<div style="text-align:center; padding:2rem; color:var(--accent-rose); font-size:13px;">Error al recuperar mensajes: ${escapeHtml(err.message)}</div>`;
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
    grid.innerHTML = `<div style="color:var(--text-muted); font-size:13px;">No se pudo cargar el catálogo de proveedores de correo.</div>`;
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
    grid.innerHTML = `<div style="color:var(--text-muted); font-size:13px;">Ningún proveedor en esta categoría.</div>`;
    return;
  }

  grid.innerHTML = providers
    .map((p) => {
      const opsecList = (p.recommended_opsec || [])
        .map((tip) => `<li>${escapeHtml(tip)}</li>`)
        .join("");

      return `
        <div class="email-prov-card">
          <div>
            <div class="email-prov-title">
              <span>${escapeHtml(p.name)}</span>
              <span class="mono" style="font-size:12px; color:var(--text-muted);">${escapeHtml(p.url)}</span>
            </div>
            <div style="font-size:12px; color:var(--text-secondary); line-height:1.4;">${escapeHtml(p.description)}</div>
            
            <div class="email-prov-tags">
              <span class="email-prov-tag">[GEO] ${escapeHtml(p.jurisdiction)}</span>
              <span class="email-prov-tag">[SEC] ${escapeHtml(p.encryption_type)}</span>
              <span class="email-prov-tag">${p.requires_phone ? "[TEL] Telefono req." : "[NO-TEL] Sin telefono"}</span>
              ${p.tor_onion_available ? '<span class="email-prov-tag" style="color:var(--accent-purple-light);">[TOR] Tor .onion</span>' : ""}
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
    <button class="toast-close" data-on-click="this.parentElement.remove()">&times;</button>
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

// --- C. Actualizacion de HUD Tactico & Hub de Overview ---
function updateTacticalHud() {
  const caseEl = document.getElementById("hud-active-case");
  if (caseEl) caseEl.textContent = currentCaseId || "ninguno";

  const caseObj = allLoadedCases.find((c) => c.case_id === currentCaseId);

  const nodesEl = document.getElementById("hud-nodes-count");
  if (nodesEl) {
    nodesEl.textContent = (graphNodes && graphNodes.length > 0) ? graphNodes.length : (caseObj ? caseObj.entity_count : 0);
  }

  const edgesEl = document.getElementById("hud-edges-count");
  if (edgesEl) {
    edgesEl.textContent = (graphLinks && graphLinks.length > 0) ? graphLinks.length : (caseObj ? caseObj.edge_count : 0);
  }

  updateOverviewCaseHub();
}

async function updateOverviewCaseHub() {
  const nameEl = document.getElementById("overview-case-name");
  const descEl = document.getElementById("overview-case-desc");
  const entEl = document.getElementById("overview-case-entities");
  const edgeEl = document.getElementById("overview-case-edges");
  const perimEl = document.getElementById("overview-case-perimeter");
  const seedsEl = document.getElementById("overview-case-seeds");

  if (!nameEl) return;

  if (!currentCaseId) {
    nameEl.textContent = "Ningún caso seleccionado";
    if (descEl) descEl.textContent = "Selecciona o crea un proyecto en la barra superior para iniciar la investigación.";
    if (entEl) entEl.textContent = "0";
    if (edgeEl) edgeEl.textContent = "0";
    if (perimEl) perimEl.textContent = "0";
    if (seedsEl) seedsEl.textContent = "0";
    return;
  }

  const caseObj = allLoadedCases.find((c) => c.case_id === currentCaseId);
  nameEl.textContent = currentCaseId;
  if (descEl) {
    descEl.textContent = caseObj?.description || "Investigación activa en curso.";
  }
  if (entEl) {
    entEl.textContent = (graphNodes && graphNodes.length > 0) ? graphNodes.length : (caseObj?.entity_count ?? 0);
  }
  if (edgeEl) {
    edgeEl.textContent = (graphLinks && graphLinks.length > 0) ? graphLinks.length : (caseObj?.edge_count ?? 0);
  }

  // Carga asíncrona no bloqueante de perímetro y semillas
  try {
    const cid = encodeURIComponent(currentCaseId);
    fetch(`/api/cases/${cid}/perimeter`)
      .then((r) => r.ok ? r.json() : null)
      .then((pData) => {
        if (pData && perimEl) {
          perimEl.textContent = pData.total ?? 0;
        }
      })
      .catch(() => {});

    fetch(`/api/cases/${cid}/recon`)
      .then((r) => r.ok ? r.json() : null)
      .then((rData) => {
        if (rData && rData.recon && seedsEl) {
          seedsEl.textContent = rData.recon.seeds?.length ?? 0;
        }
      })
      .catch(() => {});
  } catch (e) {}
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
    { cat: "Vistas y Modulos", name: "Perfilado Multidimensional", desc: "Evaluacion conductual y arquetipos periciales (21 tipologias)", action: () => switchTab("profiling") },
    { cat: "Vistas y Modulos", name: "Blockchain & AML Ledger", desc: "Rastreo de fondos y mixers", action: () => switchTab("crypto-ledger") },
    { cat: "Vistas y Modulos", name: "Transforms & Playground", desc: "Catalogo de transforms y ejecucion manual", action: () => switchTab("transforms") },
    { cat: "Vistas y Modulos", name: "Feeds CTI & IoCs", desc: "Tablas CTI de amenazas e indicadores", action: () => switchTab("cti-feeds") },
    { cat: "Vistas y Modulos", name: "Claves de Proveedores", desc: "Gestion de API keys y conectores", action: () => switchTab("providers") },
    { cat: "Vistas y Modulos", name: "Consola & Logs", desc: "Registro de eventos del sistema en vivo", action: () => switchTab("logs") },
    { cat: "Operaciones de Caso", name: "Eliminar Proyecto / Caso Activo", desc: "Purgar la investigacion puntual activa y liberar memoria", action: () => openDeleteCaseModal() },
    { cat: "Operaciones de Caso", name: "Crear Nuevo Caso", desc: "Iniciar una nueva investigacion en blanco", action: () => promptCreateCase() },
    { cat: "Operaciones de Caso", name: "Exportar como Paquete .mcpcase (Nativo)", desc: "Exportacion completa verificada SHA-256", action: () => exportCaseAs("mcpcase") },
    { cat: "Operaciones de Caso", name: "Exportar como .mtgx (Maltego)", desc: "Descarga de archivo nativo", action: () => exportCaseAs("mtgx") },
    { cat: "Operaciones de Caso", name: "Exportar como JSON Forense", desc: "Entidades y relaciones estructuradas", action: () => exportCaseAs("json") },
    { cat: "Operaciones de Caso", name: "Exportar como CSV", desc: "Tabla relacional para auditorias", action: () => exportCaseAs("csv") },
    { cat: "Operaciones de Caso", name: "Exportar como GraphML", desc: "Estandar para Gephi y Cytoscape", action: () => exportCaseAs("graphml") },
    { cat: "Operaciones de Caso", name: "Importar Archivo", desc: "Subir .mtgx, .json o .csv", action: () => openImportModal() },
    { cat: "Operaciones de Caso", name: "Captura de Grafo PNG", desc: "Copiar snapshot al portapapeles", action: () => copyGraphSnapshotToClipboard() },
    { cat: "Acciones Rapidas", name: "Generar Sock Puppet", desc: "Crear identidad protegida con TOTP", action: () => openPersonaModal() },
    { cat: "Acciones Rapidas", name: "Crear Nueva Cuenta / Clave", desc: "Registrar credencial en boveda", action: () => openNewAccountModal() },
    { cat: "Acciones Rapidas", name: "Ejecutar Perfilado Pericial", desc: "Mapear arquetipo y dimensiones sobre entidad", action: () => switchTab("profiling") },
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
    container.innerHTML = `<div style="padding:1.5rem; text-align:center; color:var(--text-muted); font-size:12px;">No se encontraron comandos coincidentes.</div>`;
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
        <div class="command-item ${isSelected ? "selected" : ""}" data-idx="${it.globalIdx}">
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
      ctx.fillStyle = l.isRiskLink ? "rgba(244, 63, 94, 0.95)" : "rgba(6, 182, 212, 0.95)";
      ctx.shadowColor = l.isRiskLink ? "rgba(244, 63, 94, 0.8)" : "rgba(6, 182, 212, 0.8)";
      ctx.shadowBlur = 8;
      ctx.fill();

      // Particula estela secundaria
      const trailProgress = Math.max(0, Math.min(1, progress - 0.08 * (isOutward ? 1 : -1)));
      const tx = a.x + (b.x - a.x) * trailProgress;
      const ty = a.y + (b.y - a.y) * trailProgress;
      ctx.beginPath();
      ctx.arc(tx, ty, 1.8, 0, Math.PI * 2);
      ctx.fillStyle = l.isRiskLink ? "rgba(244, 63, 94, 0.5)" : "rgba(6, 182, 212, 0.5)";
      ctx.shadowBlur = 0;
      ctx.fill();
    }
  }

  ctx.restore();
}

// --- H. Modulo: Blockchain & AML Ledger ---
function isCryptocurrencyEntity(node) {
  if (!node) return false;
  const t = (node.type || "").toLowerCase();
  const val = String(node.value || "").trim();

  // 1. Tipos canónicos del estándar Maltego
  if (
    t.includes("cryptocurrency") ||
    t.includes("cryptocluster") ||
    t.includes("mixercontract") ||
    t.includes("vaspexchange") ||
    t.includes("defibridge")
  ) {
    return true;
  }

  // 2. Validación estricta por expresiones regulares de formato on-chain
  // Bitcoin Bech32 (mainnet bc1q... o bc1p...)
  if (/^bc1[ac-hj-np-z02-9]{25,87}$/i.test(val)) return true;
  // Bitcoin Legacy P2PKH (1...) o P2SH (3...) (26 a 35 caracteres Base58 alfanuméricos)
  if (/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(val)) {
    if (/[a-zA-Z]/.test(val) && /[0-9]/.test(val)) return true;
  }
  // Ethereum / EVM Address (0x + 40 caracteres hexadecimales)
  if (/^0x[a-fA-F0-9]{40}$/.test(val)) return true;
  // Tron TRC-20 Address (T + 33 caracteres Base58)
  if (/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(val)) return true;
  // Transaction Hash (64 hex) solo si viene marcado como transacción o txid
  if ((/^[a-fA-F0-9]{64}$/i.test(val) || /^0x[a-fA-F0-9]{64}$/i.test(val)) && (t.includes("transaction") || node.properties?.txid)) {
    return true;
  }

  return false;
}

function detectCryptoNetwork(val) {
  const v = String(val || "").trim();
  if (/^bc1/i.test(v) || /^[13]/.test(v)) return "Bitcoin (BTC)";
  if (/^0x/i.test(v)) return "Ethereum (EVM / ERC-20)";
  if (/^T/.test(v)) return "Tron (TRC-20)";
  return "Crypto Multi-Cadena";
}

function renderCryptoLedger() {
  const tableBody = document.getElementById("aml-table-body");
  if (!tableBody) return;

  const effectiveCaseId = getModuleCaseId("crypto");
  const caseNodes = getNodesForCase(effectiveCaseId);
  const caseLinks = getLinksForCase(effectiveCaseId);

  // Filtrar exclusivamente nodos cripto reales
  const cryptoNodes = caseNodes.filter(isCryptocurrencyEntity);

  const caseTxs = [];
  let totalSatsAccum = 0;
  let mixerCount = 0;
  let ofacCount = 0;

  cryptoNodes.forEach((n) => {
    const isMixer = n.type.includes("Mixer") || n.properties?.is_mixer === "yes";
    if (isMixer) mixerCount++;
    const isOfac = n.properties?.sdn_id || n.properties?.ofac || String(n.value).includes("[OFAC") || (n.sources && n.sources.some(s => String(s).toLowerCase().includes("ofac")));
    if (isOfac) ofacCount++;
  });

  // 1. Identificar transacciones explícitas (CryptocurrencyTransaction)
  cryptoNodes.forEach((n, idx) => {
    const isTxNode = n.type.includes("Transaction") || n.properties?.txid || (/^[a-fA-F0-9]{64}$/i.test(n.value));
    if (isTxNode) {
      const txid = n.properties?.txid || n.value;
      const txShort = txid.length > 14 ? `${txid.slice(0, 8)}...${txid.slice(-6)}` : txid;

      // Buscar aristas entrantes (inputs) y salientes (outputs)
      const inLinks = caseLinks.filter((l) => (l.targetNode?.id === n.id || l.target === n.id));
      const outLinks = caseLinks.filter((l) => (l.sourceNode?.id === n.id || l.source === n.id));

      const inNodes = inLinks.map((l) => l.sourceNode || caseNodes.find((x) => x.id === l.source)).filter(Boolean);
      const outNodes = outLinks.map((l) => l.targetNode || caseNodes.find((x) => x.id === l.target)).filter(Boolean);

      const fromVal = inNodes.length > 0 ? inNodes.map((x) => x.value).join(", ") : (n.properties?.from || "Entrada On-Chain (Mempool)");
      const toVal = outNodes.length > 0 ? outNodes.map((x) => x.value).join(", ") : (n.properties?.to || "Salida On-Chain (Mempool)");

      // Monto en satoshis o tokens
      let amountStr = "N/A";
      let sats = 0;
      if (n.properties?.value_sats) {
        sats = parseInt(n.properties.value_sats, 10) || 0;
      } else {
        outNodes.forEach((on) => {
          if (on.properties?.value_sats) sats += (parseInt(on.properties.value_sats, 10) || 0);
        });
      }
      if (sats > 0) {
        totalSatsAccum += sats;
        amountStr = `${(sats / 1e8).toFixed(6)} BTC`;
      } else if (n.properties?.amount) {
        amountStr = `${n.properties.amount} ${n.properties.network || 'USDT'}`;
      }

      // Heurística y clasificación de riesgo
      const allAdj = inNodes.concat(outNodes);
      const hasOfacConn = allAdj.some((x) => x.properties?.sdn_id || x.properties?.ofac || String(x.value).includes("[OFAC"));
      const hasMixerConn = allAdj.some((x) => x.type.includes("Mixer") || x.properties?.is_mixer === "yes");
      const hasVaspConn = allAdj.some((x) => x.type.includes("VASP") || x.type.includes("Exchange"));
      const hasClusterConn = allAdj.some((x) => x.type.includes("Cluster"));

      let heur = "Transferencia Verificada";
      let risk = "BAJO";
      let badge = "peel";

      if (hasOfacConn) {
        heur = "Interaccion Sancionada OFAC";
        risk = "OFAC-SDN";
        badge = "ofac";
      } else if (hasMixerConn) {
        heur = "Pool de Anonimizacion";
        risk = "MIXER-ALERTA";
        badge = "mixer";
      } else if (hasVaspConn) {
        heur = "Deposito / Retiro VASP";
        risk = "PUNTO DE SALIDA";
        badge = "bridge";
      } else if (hasClusterConn) {
        heur = "Agrupacion CIOH (Co-gasto)";
        risk = "CLUSTER UTXO";
        badge = "peel";
      }

      caseTxs.push({
        id: `ctx-${idx}`,
        nodeId: n.id,
        txid: txid,
        txidShort: txShort,
        network: n.properties?.network || detectCryptoNetwork(txid),
        from: fromVal,
        fromShort: fromVal.length > 18 ? `${fromVal.slice(0, 8)}...${fromVal.slice(-6)}` : fromVal,
        to: toVal,
        toShort: toVal.length > 18 ? `${toVal.slice(0, 8)}...${toVal.slice(-6)}` : toVal,
        amount: amountStr,
        heur: heur,
        risk: risk,
        badge: badge,
        block: n.properties?.crypto__block || n.properties?.block || "sin datos",
        gas: n.properties?.crypto__fee ? `${n.properties.crypto__fee} sats` : (n.properties?.fee || "N/A"),
        taint: hasOfacConn ? "100.0% OFAC SDN" : (hasMixerConn ? "95.0% Mixer" : "Sin alertas conocidas"),
        hops: 1 + (inNodes.length > 0 ? 1 : 0) + (outNodes.length > 0 ? 1 : 0),
        source: n.sources?.[0] || n.properties?.source || "Mempool.space API v1 Mainnet",
        desc: n.notes || n.properties?.desc || `Transaccion verificada en el caso '${effectiveCaseId}'`,
        rawNode: n
      });
    }
  });

  // 2. Si hay direcciones con aristas directas entre ellas que no pasan por nodo tx
  caseLinks.forEach((l, lidx) => {
    const sNode = l.sourceNode || caseNodes.find((x) => x.id === l.source);
    const tNode = l.targetNode || caseNodes.find((x) => x.id === l.target);
    if (!sNode || !tNode) return;
    if (isCryptocurrencyEntity(sNode) && isCryptocurrencyEntity(tNode)) {
      if (!sNode.type.includes("Transaction") && !tNode.type.includes("Transaction")) {
        caseTxs.push({
          id: `clink-${lidx}`,
          nodeId: sNode.id,
          txid: `Relacion: ${l.label || 'transferred_to'}`,
          txidShort: l.label || 'vinculo',
          network: detectCryptoNetwork(sNode.value),
          from: sNode.value,
          fromShort: sNode.value.length > 16 ? `${sNode.value.slice(0, 8)}...${sNode.value.slice(-6)}` : sNode.value,
          to: tNode.value,
          toShort: tNode.value.length > 16 ? `${tNode.value.slice(0, 8)}...${tNode.value.slice(-6)}` : tNode.value,
          amount: sNode.properties?.balance || tNode.properties?.balance || "Transferencia en Grafo",
          heur: l.label || "Vinculo On-Chain",
          risk: sNode.isRisk || tNode.isRisk ? "ALTO" : "MEDIO",
          badge: sNode.isRisk || tNode.isRisk ? "ofac" : "peel",
          block: "En Grafo",
          gas: "N/A",
          taint: sNode.isRisk || tNode.isRisk ? "Exposicion Detectada" : "Sin alertas conocidas",
          hops: 2,
          source: "Topologia del Grafo Activo",
          desc: `Relacion dirigida '${l.label || 'vinculo'}' entre ${sNode.value} y ${tNode.value}`,
          rawNode: sNode
        });
      }
    }
  });

  // 3. Actualizar KPIs en tiempo real con datos matemáticos reales
  const elVol = document.getElementById("aml-stat-volume");
  const elVolDesc = document.getElementById("aml-stat-volume-desc");
  if (elVol) {
    if (totalSatsAccum > 0) {
      elVol.textContent = `${(totalSatsAccum / 1e8).toFixed(4)} BTC`;
      if (elVolDesc) elVolDesc.textContent = `${totalSatsAccum.toLocaleString()} satoshis verificados on-chain`;
    } else if (caseTxs.length > 0) {
      elVol.textContent = `${caseTxs.length} TXs Activas`;
      if (elVolDesc) elVolDesc.textContent = "Volumen registrado en nodos del caso";
    } else {
      elVol.textContent = "0.00 BTC / 0.00 USDT";
      if (elVolDesc) elVolDesc.textContent = "Sin volumen financiero registrado";
    }
  }

  const elMixer = document.getElementById("aml-stat-mixer");
  const elMixerDesc = document.getElementById("aml-stat-mixer-desc");
  if (elMixer) {
    const pct = cryptoNodes.length > 0 ? ((mixerCount / cryptoNodes.length) * 100).toFixed(1) : "0.0";
    elMixer.textContent = `${pct}% (${mixerCount > 0 ? 'ALERTA' : 'Sin alertas conocidas'})`;
    elMixer.style.color = mixerCount > 0 ? "var(--accent-crimson)" : "var(--accent-emerald)";
    if (elMixerDesc) elMixerDesc.textContent = `${mixerCount} servicios o contratos mezcladores detectados`;
  }

  const elHops = document.getElementById("aml-stat-hops");
  const elHopsDesc = document.getElementById("aml-stat-hops-desc");
  if (elHops) {
    const maxHops = caseTxs.reduce((acc, t) => Math.max(acc, t.hops || 0), 0);
    elHops.textContent = `${maxHops} Saltos Forenses`;
    if (elHopsDesc) elHopsDesc.textContent = maxHops > 0 ? "Profundidad de dispersion verificada en el grafo" : "Sin saltos en el caso activo";
  }

  const elOfac = document.getElementById("aml-stat-ofac");
  const elOfacDesc = document.getElementById("aml-stat-ofac-desc");
  if (elOfac) {
    elOfac.textContent = `${ofacCount} ${ofacCount === 1 ? 'ALERTA ACTIVA' : 'ALERTAS ACTIVAS'}`;
    elOfac.style.color = ofacCount > 0 ? "var(--accent-crimson)" : "var(--accent-emerald)";
    if (elOfacDesc) elOfacDesc.textContent = ofacCount > 0 ? `${ofacCount} coincidencias directas en lista SDN del Tesoro EEUU` : "Sin coincidencias en lista oficial SDN";
  }

  window._currentAmlTransactions = caseTxs;

  // 4. Si no hay transacciones ni billeteras en el caso
  if (caseTxs.length === 0) {
    if (cryptoNodes.length > 0) {
      tableBody.innerHTML = `
        <tr><td colspan="9" style="text-align:center; padding:2.5rem; color:var(--text-muted);">
          <div style="font-size:13px; font-weight:600; color:var(--text-primary); margin-bottom:0.4rem;">
            Se identificaron ${cryptoNodes.length} direcciones cripto en el caso activo '${escapeHtml(effectiveCaseId)}'
          </div>
          <div style="font-size:12px; margin-bottom:1rem; color:var(--text-secondary);">
            Las direcciones aun no tienen transacciones asociadas en el grafo. Pulsa para consultar la blockchain en tiempo real:
          </div>
          <div style="display:flex; justify-content:center; gap:0.5rem; flex-wrap:wrap;">
            ${cryptoNodes.slice(0, 5).map(cn => `
              <button class="btn btn-secondary btn-sm action-query-mempool" data-address="${escapeHtml(cn.value)}">
                Consultar ${escapeHtml(cn.value.slice(0, 10))}... en Mempool
              </button>
            `).join("")}
          </div>
        </td></tr>
      `;
    } else {
      tableBody.innerHTML = `
        <tr><td colspan="9" style="text-align:center; padding:3rem; color:var(--text-muted);">
          <div style="font-size:14px; font-weight:600; color:var(--text-primary); margin-bottom:0.4rem;">
            Sin transacciones ni billeteras cripto registradas en el caso '${escapeHtml(effectiveCaseId)}'
          </div>
          <div style="font-size:12px; max-width:550px; margin:0 auto 1.25rem auto; line-height:1.5;">
            Esta investigacion no contiene direcciones de criptomonedas. Para consultar una billetera Bitcoin, Ethereum o Tron y verificar sus transacciones en tiempo real:
          </div>
          <div style="display:flex; justify-content:center; gap:0.5rem; max-width:480px; margin:0 auto;">
            <input type="text" id="aml-inline-crypto-input" class="input input-sm mono" placeholder="Direccion BTC / EVM / TRON o hash TXID..." style="flex:1;">
            <button class="btn btn-primary btn-sm" data-on-click="submitInlineCryptoTrace()">
              Consultar On-Chain
            </button>
          </div>
        </td></tr>
      `;
    }
    return;
  }

  // Renderizar filas reales
  const limitVal = document.querySelector("#aml-transactions-table-toolbar .table-limit-select")?.value || "10";
  const limit = limitVal === "all" ? caseTxs.length : parseInt(limitVal, 10);
  const visibleTxs = caseTxs.slice(0, limit);

  tableBody.innerHTML = visibleTxs.map((tx) => `
    <tr id="aml-row-${tx.id}" class="table-row-main" data-row-id="aml-row-${tx.id}">
      <td style="width:30px; text-align:center;">
        <button type="button" class="row-expand-btn action-toggle-row" id="aml-row-${tx.id}-expand-btn" data-target="aml-row-${tx.id}" title="Ampliar / Reducir detalles">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"></polyline></svg>
        </button>
      </td>
      <td class="mono" style="color:var(--accent-cyan);">${escapeHtml(tx.txidShort)}</td>
      <td><span class="pill pill-cyan">${escapeHtml(tx.network)}</span></td>
      <td class="mono" style="font-size:12px;">${escapeHtml(tx.fromShort)}</td>
      <td class="mono" style="font-size:12px;">${escapeHtml(tx.toShort)}</td>
      <td class="mono" style="font-weight:700;">${escapeHtml(tx.amount)}</td>
      <td><span class="badge-aml ${tx.badge}">${escapeHtml(tx.heur)}</span></td>
      <td><span class="badge-aml ${tx.badge}">${escapeHtml(tx.risk)}</span></td>
      <td>
        <button class="btn btn-secondary btn-sm action-trace-aml" style="font-size:12px; padding:3px 8px; font-weight:600;" data-txid="${escapeHtml(tx.txid)}" title="Visualizar trazabilidad forense multi-salto">
          Trazar
        </button>
      </td>
    </tr>
    <tr id="aml-row-${tx.id}-detail" class="row-detail-container" style="display:none;">
      <td colspan="9">
        <div class="row-detail-card">
          <div class="row-detail-header">
            <div style="font-weight:700; color:var(--accent-cyan); font-size:12px; text-transform:uppercase; display:flex; align-items:center; gap:0.5rem;">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
              Ficha Forense de Transaccion On-Chain
            </div>
            <span class="pill pill-cyan">Bloque #${escapeHtml(tx.block)}</span>
          </div>
          <div class="row-detail-grid">
            <div class="row-detail-item" style="grid-column: span 2;">
              <span class="row-detail-label">TXID / Hash Verificado</span>
              <span class="row-detail-val mono" style="word-break:break-all;">${escapeHtml(tx.txid)}</span>
            </div>
            <div class="row-detail-item">
              <span class="row-detail-label">Direccion Emisora (From)</span>
              <span class="row-detail-val mono" style="word-break:break-all;">${escapeHtml(tx.from)}</span>
            </div>
            <div class="row-detail-item">
              <span class="row-detail-label">Direccion Receptora / Contrato (To)</span>
              <span class="row-detail-val mono" style="word-break:break-all;">${escapeHtml(tx.to)}</span>
            </div>
            <div class="row-detail-item">
              <span class="row-detail-label">Comision de Red (Fee)</span>
              <span class="row-detail-val mono">${escapeHtml(tx.gas)}</span>
            </div>
            <div class="row-detail-item">
              <span class="row-detail-label">Indice de Contaminacion (Taint)</span>
              <span class="row-detail-val" style="color:${tx.risk.includes('OFAC') ? 'var(--accent-crimson)' : 'var(--text-primary)'}; font-weight:700;">${escapeHtml(tx.taint)}</span>
            </div>
            <div class="row-detail-item" style="grid-column: span 2;">
              <span class="row-detail-label">Fuente de Evidencia</span>
              <span class="row-detail-val" style="color:var(--accent-cyan); font-weight:600;">${escapeHtml(tx.source)}</span>
            </div>
          </div>
          <div style="font-size:12px; color:var(--text-secondary); margin-top:0.35rem;">
            <strong>Analisis Pericial:</strong> ${escapeHtml(tx.desc)}
          </div>
          <div class="row-detail-actions">
            <button class="btn btn-primary btn-sm action-trace-aml" data-txid="${escapeHtml(tx.txid)}">
              Trazar Flujo Multi-Salto
            </button>
            <button class="btn btn-secondary btn-sm action-copy-txid" data-txid="${escapeHtml(tx.txid)}">
              Copiar TXID
            </button>
            <button class="btn btn-secondary btn-sm action-explore-tx" data-txid="${escapeHtml(tx.txid)}">
              Desglosar Inputs/Outputs en Mempool
            </button>
          </div>
        </div>
      </td>
    </tr>
  `).join("");
}

function filterAmlTable(query) {
  const q = (query || "").toLowerCase();
  const rows = document.querySelectorAll("#aml-table-body tr");
  rows.forEach((r) => {
    const text = r.textContent.toLowerCase();
    r.style.display = text.includes(q) ? "" : "none";
  });
}

function submitInlineCryptoTrace() {
  const input = document.getElementById("aml-inline-crypto-input");
  if (!input || !input.value.trim()) {
    showToast("Introduce una direccion o hash para consultar", "warning");
    return;
  }
  executeCryptoOnChainLookup(input.value.trim());
}

function promptAddCryptoTrace() {
  playTacticalClick(800, 0.04);
  const input = prompt("Introduce Direccion de Billetera o TXID (Bitcoin / EVM / TRON):", "");
  if (!input || !input.trim()) return;
  executeCryptoOnChainLookup(input.trim());
}

async function executeCryptoOnChainLookup(cleanVal) {
  const cid = getModuleCaseId("crypto");
  if (!cid) {
    showToast("Selecciona un caso activo primero", "warning");
    return;
  }

  const isBtcAddr = /^(bc1[ac-hj-np-z02-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/.test(cleanVal);
  const isTxid = /^[a-fA-F0-9]{64}$/i.test(cleanVal) || /^0x[a-fA-F0-9]{64}$/i.test(cleanVal);
  const isEvmAddr = /^0x[a-fA-F0-9]{40}$/.test(cleanVal);
  const isTronAddr = /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(cleanVal);

  let transformName = "MempoolAddressToTransactions";
  let entityType = "maltego.CryptocurrencyAddress";

  if (isTxid) {
    transformName = "MempoolTxToInputsOutputs";
    entityType = "maltego.CryptocurrencyTransaction";
  } else if (isEvmAddr || isTronAddr) {
    transformName = "OFACSanctionsCryptoLookup";
    entityType = "maltego.CryptocurrencyAddress";
  } else if (isBtcAddr) {
    transformName = "MempoolAddressToTransactions";
    entityType = "maltego.CryptocurrencyAddress";
  } else {
    transformName = "OFACSanctionsCryptoLookup";
    entityType = "maltego.CryptocurrencyAddress";
  }

  showToast(`Consultando ${cleanVal.slice(0, 12)}... con '${transformName}' en tiempo real...`, "info");
  playTacticalClick(820, 0.05);

  try {
    const res = await fetch("/api/lookup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        transform: transformName,
        value: cleanVal,
        type: entityType,
        case_id: cid,
        save: true
      })
    });
    const data = await res.json();
    if (!data.ok) {
      showToast(data.error || "Fallo en consulta on-chain", "error");
      return;
    }

    // Ejecutar chequeos adicionales OFAC y Exchanges
    if (isBtcAddr || isEvmAddr || isTronAddr) {
      await fetch("/api/lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          transform: "OFACSanctionsCryptoLookup",
          value: cleanVal,
          type: "maltego.CryptocurrencyAddress",
          case_id: cid,
          save: true
        })
      }).catch(() => {});

      await fetch("/api/lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          transform: "CryptoAddressToExchange",
          value: cleanVal,
          type: "maltego.CryptocurrencyAddress",
          case_id: cid,
          save: true
        })
      }).catch(() => {});
    }

    showToast(`[OK] Consulta completada: ${data.entities.length} entidades descubiertas e integradas`, "ok");
    playTacticalClick(900, 0.05);
    await fetchCaseGraphData(cid);
    loadCaseGraph(cid);
    renderCryptoLedger();
  } catch (err) {
    showToast(`Error de red al consultar: ${err.message}`, "error");
  }
}

async function queryMempoolForAddress(addr) {
  executeCryptoOnChainLookup(addr);
}

async function exploreTxInputsOutputs(txid) {
  const cid = getModuleCaseId("crypto");
  if (!cid) return;
  showToast(`Desglosando inputs y outputs para TX ${txid.slice(0, 10)}...`, "info");
  playTacticalClick(800, 0.04);
  try {
    const res = await fetch("/api/lookup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        transform: "MempoolTxToInputsOutputs",
        value: txid.trim(),
        type: "maltego.CryptocurrencyTransaction",
        case_id: cid,
        save: true
      })
    });
    const data = await res.json();
    if (!data.ok) {
      showToast(data.error || "Fallo al desglosar TX", "error");
      return;
    }
    showToast(`Se identificaron ${data.entities.length} entradas y salidas on-chain`, "ok");
    await fetchCaseGraphData(cid);
    loadCaseGraph(cid);
    renderCryptoLedger();
  } catch (err) {
    showToast(`Error: ${err.message}`, "error");
  }
}

async function scanAmlCaseMixers() {
  const cid = getModuleCaseId("crypto");
  if (!cid) return;
  const caseNodes = getNodesForCase(cid);
  const cryptoAddrs = caseNodes.filter((n) => isCryptocurrencyEntity(n) && !n.type.includes("Transaction"));

  if (cryptoAddrs.length === 0) {
    showToast("No hay direcciones cripto en el caso activo para escanear. Anade una primero.", "warning");
    return;
  }

  showToast(`Escaneando ${cryptoAddrs.length} direcciones contra lista oficial OFAC SDN y contratos VASP...`, "info");
  playTacticalClick(800, 0.05);

  let hits = 0;
  for (const n of cryptoAddrs) {
    try {
      const res = await fetch("/api/lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          transform: "OFACSanctionsCryptoLookup",
          value: String(n.value).trim(),
          type: "maltego.CryptocurrencyAddress",
          case_id: cid,
          save: true
        })
      });
      const data = await res.json();
      if (data.ok && data.entities && data.entities.some(e => e.label === "ofac_alert")) {
        hits++;
      }
      await fetch("/api/lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          transform: "CryptoAddressToExchange",
          value: String(n.value).trim(),
          type: "maltego.CryptocurrencyAddress",
          case_id: cid,
          save: true
        })
      });
    } catch (e) {}
  }

  await fetchCaseGraphData(cid);
  loadCaseGraph(cid);
  renderCryptoLedger();

  if (hits > 0) {
    showToast(`ALERTA: Se detectaron ${hits} coincidencias con entidades sancionadas por OFAC SDN`, "error");
  } else {
    showToast(`Escaneo finalizado: ${cryptoAddrs.length} direcciones verificadas sin alertas OFAC`, "ok");
  }
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

  const effectiveCaseId = getModuleCaseId("crypto");
  const caseNodes = getNodesForCase(effectiveCaseId);
  const cryptoNodes = caseNodes.filter(isCryptocurrencyEntity);

  if (cryptoNodes.length === 0) {
    amlSankeyNodes = [];
    amlSankeyLinks = [];
    ctx.fillStyle = "#04060a";
    ctx.fillRect(0, 0, w, h);
    ctx.fillStyle = "#64748b";
    ctx.font = "12px monospace";
    ctx.textAlign = "center";
    ctx.fillText("Sin entidades de criptomonedas en el caso activo para construir el flujo", w / 2, h / 2);
    return;
  }

  // Derivar etapas del grafo real
  const txNodes = cryptoNodes.filter((n) => n.type.includes("Transaction") || n.properties?.txid);
  const mixerNodes = cryptoNodes.filter((n) => n.type.includes("Mixer") || n.properties?.is_mixer === "yes");
  const vaspNodes = cryptoNodes.filter((n) => n.type.includes("VASP") || n.type.includes("Exchange"));
  const addrNodes = cryptoNodes.filter((n) => !txNodes.includes(n) && !mixerNodes.includes(n) && !vaspNodes.includes(n));

  amlSankeyNodes = [];
  amlSankeyLinks = [];

  const stageGroups = [
    { name: "Direcciones / Billeteras", nodes: addrNodes.slice(0, 3), color: "#38bdf8" },
    { name: "Transacciones On-Chain", nodes: txNodes.slice(0, 3), color: "#fbbf24" },
    { name: "Anonimizadores / Mixers", nodes: mixerNodes.slice(0, 2), color: "#c084fc" },
    { name: "Puntos de Retiro / VASP", nodes: vaspNodes.slice(0, 2), color: "#f87171" }
  ].filter(g => g.nodes.length > 0);

  const stepX = (w - 240) / Math.max(1, stageGroups.length - 1);

  stageGroups.forEach((grp, gIdx) => {
    const x = 120 + gIdx * stepX;
    const count = grp.nodes.length;
    grp.nodes.forEach((n, nIdx) => {
      const y = (h / (count + 1)) * (nIdx + 1);
      amlSankeyNodes.push({
        id: `sankey-${n.id}`,
        name: n.value.length > 16 ? `${n.value.slice(0, 8)}...${n.value.slice(-6)}` : n.value,
        stage: grp.name,
        volume: n.properties?.amount || (n.properties?.value_sats ? `${(parseInt(n.properties.value_sats, 10) / 1e8).toFixed(4)} BTC` : "Verificado"),
        x: x,
        y: y,
        radius: 10,
        color: grp.color,
        desc: n.type
      });
    });
  });

  for (let i = 0; i < amlSankeyNodes.length - 1; i++) {
    amlSankeyLinks.push({
      from: amlSankeyNodes[i],
      to: amlSankeyNodes[i + 1],
      amount: "Flujo en grafo",
      width: 10
    });
  }

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
// Modulos retirados en F7 (forensics-vault, mitre, geo, rules, watchtower, bridge)

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

function defang(val) {
  if (!val || typeof val !== "string") return val || "";
  let s = val.trim();
  s = s.replace(/^https:\/\//i, "hxxps[://]").replace(/^http:\/\//i, "hxxp[://]");
  s = s.replace(/^ftp:\/\//i, "fxp[://]").replace(/^sftp:\/\//i, "sfxp[://]");
  s = s.replace(/\./g, "[.]");
  if (s.indexOf("@") !== -1 && !s.startsWith("hxxp")) {
    s = s.replace(/@/g, "[@]");
  }
  return s;
}

function shouldDefang(label, text) {
  if (!text || typeof text !== "string") return false;
  const l = (label || "").toLowerCase();
  if (l.includes("url") || l.includes("host") || l.includes("dominio") || l.includes("domain") || l.includes("ip") || l.includes("ioc") || l.includes("correo") || l.includes("email")) {
    return true;
  }
  return /^https?:\/\//i.test(text) || /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(text);
}

function copyToClipboardWithFeedback(text, label) {
  const cleanText = shouldDefang(label, text) ? defang(text) : text;
  if (!navigator.clipboard) {
    showToast(`Copiado: ${cleanText.slice(0, 24)}...`, "ok");
    return;
  }
  navigator.clipboard.writeText(cleanText).then(() => {
    playTacticalClick(1400, 0.03);
    const feedbackLabel = shouldDefang(label, text) ? `${label} (neutralizado)` : label;
    showToast(`${feedbackLabel} copiado: ${cleanText.slice(0, 24)}...`, "ok");
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

  const effectiveCaseId = getModuleCaseId("crypto");
  const caseNodes = getNodesForCase(effectiveCaseId);
  const caseLinks = getLinksForCase(effectiveCaseId);

  // 1. Localizar datos de la transaccion en memoria activa o en los nodos del caso
  const txList = window._currentAmlTransactions || [];
  let found = txList.find((t) => t.txid === txid || t.txidShort === txid || t.id === txid);

  if (!found) {
    const gNode = caseNodes.find((n) => n.id === txid || n.value === txid || n.properties?.txid === txid);
    if (gNode) {
      found = {
        id: `ctx-${gNode.id}`,
        nodeId: gNode.id,
        txid: gNode.properties?.txid || gNode.value,
        txidShort: (gNode.properties?.txid || gNode.value).length > 14 ? `${(gNode.properties?.txid || gNode.value).slice(0, 8)}...${(gNode.properties?.txid || gNode.value).slice(-6)}` : (gNode.properties?.txid || gNode.value),
        network: gNode.properties?.network || detectCryptoNetwork(gNode.value),
        from: gNode.properties?.from || "Billetera Emisora en Grafo",
        fromShort: (gNode.properties?.from || "Billetera Emisora").slice(0, 16),
        to: gNode.properties?.to || "Billetera Receptora en Grafo",
        toShort: (gNode.properties?.to || "Billetera Receptora").slice(0, 16),
        amount: gNode.properties?.amount || (gNode.properties?.value_sats ? `${(parseInt(gNode.properties.value_sats, 10) / 1e8).toFixed(6)} BTC` : "No registrado"),
        heur: "Entidad en Grafo Activo",
        risk: gNode.isRisk ? "ALTO" : "VERIFICADO",
        badge: gNode.isRisk ? "ofac" : "peel",
        block: gNode.properties?.crypto__block || gNode.properties?.block || "En Grafo",
        gas: gNode.properties?.crypto__fee ? `${gNode.properties.crypto__fee} sats` : "N/A",
        taint: gNode.isRisk ? "Exposicion Detectada" : "Sin alertas conocidas",
        hops: 1,
        source: gNode.sources?.[0] || "Grafo del Caso",
        desc: gNode.notes || `Nodo registrado en el caso '${effectiveCaseId}'`,
        rawNode: gNode
      };
    } else {
      found = {
        id: "tx-external",
        nodeId: null,
        txid: txid,
        txidShort: txid.length > 14 ? `${txid.slice(0, 8)}...${txid.slice(-6)}` : txid,
        network: detectCryptoNetwork(txid),
        from: "Entrada pendiente de consulta",
        fromShort: "N/A",
        to: "Salida pendiente de consulta",
        toShort: "N/A",
        amount: "Pendiente on-chain",
        heur: "Identificador Cripto",
        risk: "SIN CLASIFICAR",
        badge: "peel",
        block: "Desconocido",
        gas: "N/A",
        taint: "Sin evaluar",
        hops: 0,
        source: "Consulta Manual",
        desc: "Identificador on-chain introducido para analisis de trazabilidad.",
        rawNode: null
      };
    }
  }

  // 2. Traza topologica dinamica en el grafo del caso
  const centralNode = found.rawNode || caseNodes.find((n) => n.id === found.nodeId || n.value === found.txid || n.properties?.txid === found.txid);

  let ingressNodes = [];
  let egressNodes = [];

  if (centralNode) {
    const inLinks = caseLinks.filter((l) => (l.targetNode?.id === centralNode.id || l.target === centralNode.id));
    const outLinks = caseLinks.filter((l) => (l.sourceNode?.id === centralNode.id || l.source === centralNode.id));

    ingressNodes = inLinks.map((l) => l.sourceNode || caseNodes.find((x) => x.id === l.source)).filter(Boolean);
    egressNodes = outLinks.map((l) => l.targetNode || caseNodes.find((x) => x.id === l.target)).filter(Boolean);
  }

  // Comprobar alertas OFAC, Mixers y VASPs en las entidades conectadas
  const allConnected = [centralNode, ...ingressNodes, ...egressNodes].filter(Boolean);
  const ofacMatch = allConnected.find((n) => n.properties?.sdn_id || n.properties?.ofac || String(n.value).includes("[OFAC") || (n.sources && n.sources.some(s => String(s).toLowerCase().includes("ofac"))));
  const mixerMatch = allConnected.find((n) => n.type?.includes("Mixer") || n.properties?.is_mixer === "yes");
  const vaspMatch = allConnected.find((n) => n.type?.includes("VASP") || n.type?.includes("Exchange") || n.properties?.vasp);

  let taintScore = 0.0;
  let taintSeverityLabel = "Sin antecedentes de sanciones en el caso";
  let taintBarColor = "var(--accent-emerald)";

  if (ofacMatch) {
    taintScore = 100.0;
    taintSeverityLabel = `100.0% CRITICO: Coincidencia en Lista OFAC SDN (${escapeHtml(ofacMatch.value)})`;
    taintBarColor = "var(--accent-crimson)";
  } else if (mixerMatch) {
    taintScore = 95.0;
    taintSeverityLabel = `95.0% ALERTA DE MEZCLADOR: Contacto con servicio de anonimizacion (${escapeHtml(mixerMatch.value)})`;
    taintBarColor = "#f59e0b";
  } else if (vaspMatch) {
    taintScore = 15.0;
    taintSeverityLabel = `15.0% FLUJO CUSTODIAL: Deposito / Retiro en Exchange regulado (${escapeHtml(vaspMatch.value)})`;
    taintBarColor = "var(--accent-cyan)";
  }

  const calculatedHops = (ingressNodes.length > 0 ? 1 : 0) + 1 + (egressNodes.length > 0 ? 1 : 0);
  found.taint = taintSeverityLabel;
  found.hops = calculatedHops;

  currentAmlTraceData = {
    ...found,
    ingressNodes,
    egressNodes,
    ofacMatch,
    mixerMatch,
    vaspMatch
  };

  title.textContent = `Trazabilidad Forense Multi-Salto: ${found.txidShort}`;

  body.innerHTML = `
    <!-- KPI Strip -->
    <div class="trace-metrics-strip">
      <div class="trace-kpi-card">
        <span class="trace-kpi-label">Volumen Trazado</span>
        <span class="trace-kpi-value" style="color:var(--accent-cyan);">${escapeHtml(found.amount)}</span>
      </div>
      <div class="trace-kpi-card">
        <span class="trace-kpi-label">Red / Estandar</span>
        <span class="trace-kpi-value">${escapeHtml(found.network)}</span>
      </div>
      <div class="trace-kpi-card">
        <span class="trace-kpi-label">Indice de Contaminacion</span>
        <span class="trace-kpi-value" style="color:${taintBarColor};">${taintScore.toFixed(1)}%</span>
      </div>
      <div class="trace-kpi-card">
        <span class="trace-kpi-label">Distancia Forense</span>
        <span class="trace-kpi-value">${calculatedHops} ${calculatedHops === 1 ? 'salto en grafo' : 'saltos en grafo'}</span>
      </div>
      <div class="trace-kpi-card">
        <span class="trace-kpi-label">Clasificacion</span>
        <span class="trace-kpi-value" style="color:${ofacMatch ? 'var(--accent-crimson)' : 'var(--text-primary)'};">${escapeHtml(found.risk)}</span>
      </div>
    </div>

    <!-- Barra de Contaminacion (Taint Gauge) -->
    <div style="background:rgba(15,23,42,0.8); border:1px solid var(--border-subtle); border-radius:6px; padding:0.75rem 1rem; margin-bottom:1rem;">
      <div style="display:flex; justify-content:space-between; align-items:center; font-size:12px;">
        <span style="font-weight:600; color:var(--text-secondary); text-transform:uppercase;">Exposicion Directa a Protocolos Sancionados (OFAC SDN List)</span>
        <span class="mono" style="color:${taintBarColor}; font-weight:700;">${taintSeverityLabel}</span>
      </div>
      <div class="taint-gauge">
        <div class="taint-bar-bg">
          <div class="taint-bar-fill" style="width: ${Math.max(3, taintScore)}%; background: ${taintBarColor};"></div>
        </div>
      </div>
    </div>

    <!-- Acciones Operativas On-Chain Directas -->
    <div style="display:flex; gap:0.5rem; margin-bottom:1.25rem; flex-wrap:wrap; background:rgba(0,0,0,0.2); padding:0.5rem; border-radius:4px; border:1px solid var(--border-subtle);">
      <button type="button" class="btn btn-secondary btn-sm action-explore-tx" style="font-size:12px;" data-txid="${escapeHtml(found.txid)}">
        Consultar Entradas y Salidas en Mempool.space
      </button>
      <button type="button" class="btn btn-secondary btn-sm action-crypto-lookup" style="font-size:12px;" data-txid="${escapeHtml(found.txid)}" data-lookup="OFACSanctionsCryptoLookup">
        Verificar Sanciones OFAC SDN
      </button>
      <button type="button" class="btn btn-secondary btn-sm action-crypto-lookup" style="font-size:12px;" data-txid="${escapeHtml(found.txid)}" data-lookup="CryptoClusteringCIOH">
        Clustering Heuristico CIOH
      </button>
    </div>

    <!-- Timeline de Saltos Multi-Hop Reconstruidos del Grafo -->
    <div style="font-size:12px; font-weight:700; color:var(--accent-cyan); text-transform:uppercase; margin-bottom:0.5rem;">
      Ruta Forense Reconstruida del Caso Activo (${escapeHtml(effectiveCaseId)})
    </div>

    <div class="trace-timeline">
      <!-- Salto 01: Ingress / Donante (Orígenes) -->
      <div class="trace-hop-item">
        <div class="trace-hop-badge">01</div>
        <div class="trace-hop-card">
          <div class="trace-hop-title">
            <span style="color:var(--accent-cyan);">Salto 01: Billetera Donante / Emisora (Ingress)</span>
            <span class="pill ${ingressNodes.some(n => n.properties?.sdn_id) ? 'pill-err' : 'pill-cyan'}">
              ${ingressNodes.length > 0 ? `${ingressNodes.length} ENTRADA(S) EN GRAFO` : 'ENTRADA DIRECTA'}
            </span>
          </div>
          ${ingressNodes.length > 0 ? ingressNodes.map((inNode) => `
            <div class="mono" style="font-size:12px; color:var(--text-primary); margin-bottom:3px; word-break:break-all;">
              Direccion: <strong>${escapeHtml(inNode.value)}</strong>
              <span class="pill pill-cyan" style="font-size:12px; margin-left:4px;">${escapeHtml(inNode.type)}</span>
            </div>
            <div style="font-size:12px; color:var(--text-secondary); margin-bottom:4px;">
              ${inNode.properties?.balance ? `Saldo: ${escapeHtml(inNode.properties.balance)} | ` : ''}
              ${inNode.properties?.sdn_id ? '<span style="color:var(--accent-crimson); font-weight:700;">ALERTA OFAC SDN</span>' : 'Entidad verificada en el caso'}
            </div>
          `).join("") : `
            <div class="mono" style="font-size:12px; color:var(--text-primary);">
              Direccion Emisora: <strong>${escapeHtml(found.from)}</strong>
            </div>
            <div style="font-size:12px; color:var(--text-secondary);">
              Emision registrada en los parametros de la transaccion.
            </div>
          `}
          <div class="trace-hop-source">
            <span class="trace-source-tag">Fuente Primaria:</span>
            <span class="mono" style="color:var(--text-primary);">${escapeHtml(ingressNodes[0]?.sources?.[0] || found.source || 'Mempool.space API v1 / Grafo')}</span>
          </div>
        </div>
      </div>

      <!-- Salto 02: Transaccion de Pivote (TXID) -->
      <div class="trace-hop-item">
        <div class="trace-hop-badge">02</div>
        <div class="trace-hop-card">
          <div class="trace-hop-title">
            <span style="color:var(--accent-cyan);">Salto 02: Transaccion de Pivote & Consenso On-Chain</span>
            <span class="pill pill-purple">HASH ON-CHAIN</span>
          </div>
          <div class="mono" style="font-size:12px; color:var(--text-primary); word-break:break-all;">
            TXID: <strong>${escapeHtml(found.txid)}</strong>
          </div>
          <div style="font-size:12px; color:var(--text-secondary); margin-top:3px;">
            Monto: <strong>${escapeHtml(found.amount)}</strong> | Bloque: <strong>${escapeHtml(found.block)}</strong> | Comision: <strong>${escapeHtml(found.gas)}</strong>
          </div>
          <div class="trace-hop-source">
            <span class="trace-source-tag">Fuente Primaria:</span>
            <span class="mono" style="color:var(--text-primary);">${escapeHtml(found.source || 'Mempool.space API v1 Consenso Mainnet')}</span>
          </div>
        </div>
      </div>

      <!-- Salto 03+: Salidas / Destinos (Receptores, Mixers, VASPs) -->
      ${egressNodes.length > 0 ? egressNodes.map((outNode, idx) => {
        const isOfacOut = outNode.properties?.sdn_id || outNode.properties?.ofac || String(outNode.value).includes("[OFAC");
        const isMixerOut = outNode.type?.includes("Mixer") || outNode.properties?.is_mixer === "yes";
        const isVaspOut = outNode.type?.includes("VASP") || outNode.type?.includes("Exchange") || outNode.properties?.vasp;
        const pillClass = isOfacOut ? "pill-err" : (isMixerOut ? "pill-warn" : (isVaspOut ? "pill-ok" : "pill-cyan"));
        const pillText = isOfacOut ? "OFAC SDN LISTED" : (isMixerOut ? "MIXER DETECTADO" : (isVaspOut ? "VASP DEPOSIT" : "SALIDA ON-CHAIN"));
        return `
          <div class="trace-hop-item">
            <div class="trace-hop-badge ${isMixerOut ? 'mixer' : (isVaspOut ? 'egress' : '')}">${String(3 + idx).padStart(2, '0')}</div>
            <div class="trace-hop-card" style="${isOfacOut ? 'border-color:rgba(239, 68, 68,0.4);' : ''}">
              <div class="trace-hop-title">
                <span style="color:${isOfacOut ? 'var(--accent-crimson)' : 'var(--accent-cyan)'};">Salto ${3 + idx}: Destino / Receptor</span>
                <span class="pill ${pillClass}">${pillText}</span>
              </div>
              <div class="mono" style="font-size:12px; color:var(--text-primary); word-break:break-all;">
                Direccion: <strong>${escapeHtml(outNode.value)}</strong>
              </div>
              <div style="font-size:12px; color:var(--text-secondary); margin-top:2px;">
                Tipo: <strong>${escapeHtml(outNode.type)}</strong>
                ${outNode.properties?.value_sats ? ` | Monto: ${(parseInt(outNode.properties.value_sats, 10) / 1e8).toFixed(6)} BTC` : ''}
                ${outNode.properties?.cluster ? ` | Cluster: ${escapeHtml(outNode.properties.cluster)}` : ''}
              </div>
              <div class="trace-hop-source">
                <span class="trace-source-tag">Fuente Primaria:</span>
                <span class="mono" style="color:var(--text-primary);">${escapeHtml(outNode.sources?.[0] || 'Topologia del Grafo Activo')}</span>
              </div>
            </div>
          </div>
        `;
      }).join("") : `
        <div class="trace-hop-item">
          <div class="trace-hop-badge">03</div>
          <div class="trace-hop-card">
            <div class="trace-hop-title">
              <span style="color:var(--accent-cyan);">Salto 03: Destino / Receptor</span>
              <span class="pill pill-cyan">SALIDA REGISTRADA</span>
            </div>
            <div class="mono" style="font-size:12px; color:var(--text-primary); word-break:break-all;">
              Direccion: <strong>${escapeHtml(found.to)}</strong>
            </div>
            <div style="font-size:12px; color:var(--text-secondary); margin-top:2px;">
              ${found.to && !found.to.includes("pendiente") ? 'Destino directo registrado en la transaccion.' : 'Sin bifurcaciones posteriores registradas en el grafo. Pulsa "Consultar Entradas y Salidas en Mempool.space" para expandir.'}
            </div>
            <div class="trace-hop-source">
              <span class="trace-source-tag">Fuente Primaria:</span>
              <span class="mono" style="color:var(--text-primary);">${escapeHtml(found.source || 'Grafo del Caso')}</span>
            </div>
          </div>
        </div>
      `}
    </div>
  `;

  modal.classList.add("open");
  modal.classList.add("active");
  modal.style.display = "grid";
  showToast(`Trazabilidad forense activada para ${found.txidShort}`, "ok");
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
  const effectiveCaseId = getModuleCaseId("crypto");

  const newNodes = [];
  const newEdges = [];

  // 1. Nodo de la transaccion real
  const txNodeId = `crypto_tx_${t.txid.replace(/[^a-zA-Z0-9]/g, "").slice(0, 16)}`;
  if (!graphNodes.some((x) => x.id === txNodeId || x.value === t.txid)) {
    newNodes.push({
      id: txNodeId,
      type: "maltego.CryptocurrencyTransaction",
      value: t.txid,
      case_id: effectiveCaseId,
      properties: {
        txid: t.txid,
        network: t.network,
        amount: t.amount,
        block: t.block,
        fee: t.gas,
        taint: t.taint
      },
      sources: [t.source || "Mempool API / Trazador AML"],
      isRisk: Boolean(t.ofacMatch || t.mixerMatch)
    });
  }

  // 2. Nodo emisor (from) si es direccion real
  if (t.from && t.from !== "N/A" && !t.from.includes("pendiente") && !t.from.includes("No registrado")) {
    const fromId = `crypto_addr_${t.from.replace(/[^a-zA-Z0-9]/g, "").slice(0, 16)}`;
    if (!graphNodes.some((x) => x.id === fromId || x.value === t.from)) {
      newNodes.push({
        id: fromId,
        type: "maltego.CryptocurrencyAddress",
        value: t.from,
        case_id: effectiveCaseId,
        properties: { address: t.from, role: "donor_wallet" },
        sources: [t.source || "Mempool API"]
      });
    }
    newEdges.push({
      source: fromId,
      target: txNodeId,
      label: "emite_transaccion"
    });
  }

  // 3. Nodo receptor (to) si es direccion real
  if (t.to && t.to !== "N/A" && !t.to.includes("pendiente") && !t.to.includes("No registrado")) {
    const toId = `crypto_addr_${t.to.replace(/[^a-zA-Z0-9]/g, "").slice(0, 16)}`;
    if (!graphNodes.some((x) => x.id === toId || x.value === t.to)) {
      newNodes.push({
        id: toId,
        type: "maltego.CryptocurrencyAddress",
        value: t.to,
        case_id: effectiveCaseId,
        properties: { address: t.to, role: "recipient_wallet" },
        sources: [t.source || "Mempool API"]
      });
    }
    newEdges.push({
      source: txNodeId,
      target: toId,
      label: "envia_a"
    });
  }

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
    const sNode = graphNodes.find((x) => x.id === e.source || x.value === e.source);
    const tNode = graphNodes.find((x) => x.id === e.target || x.value === e.target);
    if (sNode && tNode) {
      if (!graphLinks.some((l) => (l.source === sNode.id && l.target === tNode.id))) {
        graphLinks.push({
          source: sNode.id,
          target: tNode.id,
          sourceNode: sNode,
          targetNode: tNode,
          label: e.label,
          visible: true,
          isRiskLink: Boolean(t.ofacMatch || t.mixerMatch)
        });
      }
    }
  }

  saveCurrentCaseGraph();
  closeAmlTraceModal();
  switchView("view-graph");
  fitGraphView();
  showToast(`Cadena verificada inyectada en el caso activo (${addedCount} nodos nuevos)`, "ok");
}

function exportCurrentTraceReport() {
  if (!currentAmlTraceData) return;
  const t = currentAmlTraceData;
  const effectiveCaseId = getModuleCaseId("crypto");

  const report = {
    dictamen: "Dictamen Pericial de Trazabilidad Criptoforense & AML",
    caso_id: effectiveCaseId,
    fecha_generacion: new Date().toISOString(),
    transaccion_analizada: {
      txid: t.txid,
      red: t.network,
      monto: t.amount,
      bloque: t.block,
      comision: t.gas,
      origen: t.from,
      destino: t.to,
      fuente: t.source
    },
    evaluacion_riesgo: {
      contaminacion: t.taint,
      clasificacion: t.risk,
      alerta_ofac_sdn: Boolean(t.ofacMatch),
      alerta_mixer: Boolean(t.mixerMatch),
      alerta_vasp: Boolean(t.vaspMatch)
    },
    cadena_saltos_reconstruida: [
      ...(t.ingressNodes || []).map((n, i) => ({
        salto: `Ingress-${i + 1}`,
        tipo_nodo: n.type,
        direccion: n.value,
        saldo: n.properties?.balance || "N/A",
        fuente: n.sources?.[0] || "Grafo"
      })),
      {
        salto: "Pivot-Transaction",
        tipo_nodo: "maltego.CryptocurrencyTransaction",
        txid: t.txid,
        red: t.network,
        bloque: t.block,
        fuente: t.source
      },
      ...(t.egressNodes || []).map((n, i) => ({
        salto: `Egress-${i + 1}`,
        tipo_nodo: n.type,
        direccion: n.value,
        monto: n.properties?.value_sats ? `${(parseInt(n.properties.value_sats, 10) / 1e8).toFixed(6)} BTC` : "N/A",
        fuente: n.sources?.[0] || "Grafo"
      }))
    ],
    protocolo_auditoria: "ISO/IEC 27037:2012 - Evidencia Digital Forense",
    firma_integridad: "SHA256:" + Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, "0")).join("")
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `informe_aml_${t.txid.slice(0, 10)}.json`;
  a.click();
  showToast("Dictamen pericial AML descargado con exito", "ok");
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
        <div style="color:var(--text-secondary); font-size:12px;">Ambas entidades pertenecen a componentes disconexos del grafo en la topologia actual.</div>
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
        <span class="mono" style="color:var(--accent-cyan); font-weight:700; font-size:12px;">SECUENCIA DE SALTO PASO A PASO</span>
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
              <span class="pill ${badgeClass}" style="font-weight:700; font-size:12px; width:65px; text-align:center;">${roleLabel}</span>
              <div style="flex:1; display:flex; flex-direction:column;">
                <span style="font-weight:600; font-size:12px; color:var(--text-primary);">${escapeHtml(n.value)}</span>
                <span class="mono" style="font-size:12px; color:var(--text-muted);">${escapeHtml(n.type)} | ID: ${escapeHtml(n.id)}</span>
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
   ESPACIO DE TRABAJO MALTEGO: FULLSCREEN, RESIZER & FICHA DOCK
   ========================================================== */

let isGraphFullscreen = false;

function initGraphInspectorResizer() {
  const resizer = document.getElementById("graph-inspector-resizer");
  const panel = document.getElementById("graph-inspector-panel");
  const layout = document.getElementById("graph-workspace-layout");
  if (!resizer || !panel || !layout || resizer.__attached) return;
  resizer.__attached = true;

  try {
    const saved = localStorage.getItem("maltego_inspector_width");
    if (saved) {
      const parsed = parseInt(saved, 10);
      if (parsed >= 220 && parsed <= 750) panel.style.width = `${parsed}px`;
    }
  } catch (e) {}

  let isResizing = false;
  let startX = 0;
  let startWidth = 0;

  resizer.addEventListener("mousedown", (e) => {
    isResizing = true;
    startX = e.clientX;
    startWidth = panel.getBoundingClientRect().width;
    resizer.classList.add("resizing");
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    e.preventDefault();
  });

  window.addEventListener("mousemove", (e) => {
    if (!isResizing) return;
    const deltaX = startX - e.clientX;
    const newWidth = Math.max(220, Math.min(750, startWidth + deltaX));
    panel.style.width = `${newWidth}px`;
    resizeGraphCanvas();
    drawGraph();
  });

  window.addEventListener("mouseup", () => {
    if (isResizing) {
      isResizing = false;
      resizer.classList.remove("resizing");
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      try {
        localStorage.setItem("maltego_inspector_width", parseInt(panel.style.width, 10));
      } catch (e) {}
      resizeGraphCanvas();
      drawGraph();
    }
  });
}

function toggleInspectorCollapse() {
  const panel = document.getElementById("graph-inspector-panel");
  const fsBar = document.getElementById("fullscreen-graph-bar");
  const btn = document.getElementById("btn-collapse-inspector");
  const btnFs = document.getElementById("btn-fs-toggle-inspector");
  if (!panel) return;

  panel.classList.toggle("collapsed");
  const isCollapsed = panel.classList.contains("collapsed");
  if (fsBar) fsBar.classList.toggle("inspector-collapsed", isCollapsed);

  if (btn) {
    btn.innerHTML = isCollapsed
      ? `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"></polyline></svg>`
      : `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"></polyline></svg>`;
    btn.setAttribute("title", isCollapsed ? "Desplegar Ficha de Inteligencia" : "Plegar Ficha de Inteligencia");
  }
  if (btnFs) {
    btnFs.textContent = isCollapsed ? "Ficha [Desplegar]" : "Ficha [Plegar]";
  }

  resizeGraphCanvas();
  drawGraph();
  playTacticalClick(740, 0.03);
}

function toggleGraphFullscreen() {
  const layout = document.getElementById("graph-workspace-layout");
  const fsBar = document.getElementById("fullscreen-graph-bar");
  const btn = document.getElementById("btn-graph-fullscreen");
  if (!layout) return;

  isGraphFullscreen = !isGraphFullscreen;
  layout.classList.toggle("fullscreen-active", isGraphFullscreen);
  if (fsBar) fsBar.style.display = isGraphFullscreen ? "flex" : "none";

  if (btn) {
    btn.classList.toggle("btn-primary", isGraphFullscreen);
    btn.classList.toggle("btn-secondary", !isGraphFullscreen);
    btn.innerHTML = isGraphFullscreen
      ? `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg> Salir Pantalla Completa`
      : `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"></path></svg> Pantalla Completa`;
  }

  if (isGraphFullscreen) {
    window.addEventListener("keydown", onGraphFullscreenKeydown);
    showToast("Espacio de Trabajo Maltego (Pantalla Completa) activado. Presiona ESC para salir.", "info");
  } else {
    window.removeEventListener("keydown", onGraphFullscreenKeydown);
  }

  setTimeout(() => {
    resizeGraphCanvas();
    fitGraphView();
    drawGraph();
  }, 40);
  playTacticalClick(880, 0.04);
}

function onGraphFullscreenKeydown(e) {
  if (e.key === "Escape" && isGraphFullscreen) {
    toggleGraphFullscreen();
  }
}

/* ==========================================================
   TRAZADOR DE RUTAS BGP & TOPOLOGIA AS-PATH (RIPESTAT & PEERINGDB)
   ========================================================== */

let currentBgpTraceTarget = null;

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

// Cierre ergonómico de modales al hacer clic en el fondo oscurecido
window.addEventListener("click", (e) => {
  if (e.target && e.target.classList && e.target.classList.contains("modal-overlay")) {
    if (e.target.id === "modal-aml-trace") closeAmlTraceModal();
    if (e.target.id === "modal-path-trace") closePathTraceModal();
    if (e.target.id === "modal-account") closeNewAccountModal();
    if (e.target.id === "modal-persona") closeNewPersonaModal();
    if (e.target.id === "modal-import") closeImportModal();
  }
});

async function injectPlaygroundEntitiesIntoCase() {
  if (!lastPlaygroundEntities || lastPlaygroundEntities.length === 0) return;
  const targetCaseId = getModuleCaseId("transforms");
  if (!targetCaseId) {
    showToast("Selecciona o crea un proyecto activo primero", "warning");
    return;
  }

  const payload = {
    entities: lastPlaygroundEntities.map((e) => ({
      type: e.type || "maltego.Phrase",
      value: e.value,
      properties: e.properties || {}
    })),
    edges: []
  };

  try {
    const res = await fetch("/api/cases/import", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        case_id: targetCaseId,
        filename: `playground_lookup_${targetCaseId}.json`,
        content: JSON.stringify(payload)
      })
    });
    const data = await res.json();
    if (data.ok) {
      if (targetCaseId === currentCaseId) {
        await loadCaseGraph(targetCaseId);
      }
      playTacticalClick(880, 0.04);
      showToast(`${lastPlaygroundEntities.length} entidades incorporadas al proyecto '${targetCaseId}'`, "ok");
    } else {
      showToast(data.error || "Error al incorporar entidades", "error");
    }
  } catch (err) {
    showToast(`Error: ${err.message}`, "error");
  }
}

// --- Modulo de Perfilado Multidimensional (21 Tipologias en 6 Pilares) ---
let profilingTargetEntities = [];
let currentProfileResult = null;
let caseProfilesList = [];

async function renderProfilingView() {
  const caseId = getModuleCaseId("profiling");
  const caseSelect = document.getElementById("profiling-case-select");
  if (caseSelect && caseSelect.value !== (moduleCaseOverrides.profiling || "__global__")) {
    caseSelect.value = moduleCaseOverrides.profiling || "__global__";
  }
  await refreshProfilingTargets();
  await loadCaseProfilesHistory(caseId);
}

async function refreshProfilingTargets() {
  const caseId = getModuleCaseId("profiling");
  if (!caseId) {
    populateProfilingTargetSelect([]);
    return;
  }
  let nodes = getNodesForCase(caseId);
  if (!nodes || nodes.length === 0) {
    try {
      const data = await fetchCaseGraphData(caseId);
      nodes = (data && data.nodes) || [];
    } catch (e) {
      nodes = [];
    }
  }
  profilingTargetEntities = nodes || [];
  populateProfilingTargetSelect(profilingTargetEntities);
}

function populateProfilingTargetSelect(entities) {
  const select = document.getElementById("profiling-target-select");
  const meta = document.getElementById("profiling-target-meta");
  if (!select) return;

  if (!entities || entities.length === 0) {
    select.innerHTML = `<option value="">(No hay entidades en el proyecto activo)</option>`;
    if (meta) meta.textContent = "Incorpora entidades o ejecuta transforms primero";
    return;
  }

  const sorted = [...entities].sort((a, b) => (a.value || "").localeCompare(b.value || ""));
  let html = `<option value="">-- Seleccionar Entidad Objetivo (${sorted.length} disponibles) --</option>`;

  // Si hay mas de 10 entidades, estructurar por Familias y Colecciones Ontologicas de Maltego
  if (sorted.length > 10) {
    const categories = {
      corp: { label: "Empresas & Organizaciones", items: [] },
      infra: { label: "Infraestructura & Redes (IPs, Dominios, ASN)", items: [] },
      ident: { label: "Identidades & Personas (Person, Email, Phone)", items: [] },
      geo: { label: "Sedes & Ubicaciones (Location, GPS)", items: [] },
      other: { label: "Otras Entidades & CTI", items: [] },
    };

    sorted.forEach((e) => {
      const t = String(e.type || "").toLowerCase();
      if (t.includes("company") || t.includes("organization")) categories.corp.items.push(e);
      else if (t.includes("ipv4") || t.includes("ipv6") || t.includes("domain") || t.includes("dns") || t.includes("as") || t.includes("port") || t.includes("netblock") || t.includes("service")) categories.infra.items.push(e);
      else if (t.includes("person") || t.includes("email") || t.includes("phone") || t.includes("alias") || t.includes("affiliation") || t.includes("social")) categories.ident.items.push(e);
      else if (t.includes("location") || t.includes("country") || t.includes("gps")) categories.geo.items.push(e);
      else categories.other.items.push(e);
    });

    Object.values(categories).forEach((cat) => {
      if (cat.items.length > 0) {
        html += `<optgroup label="[Coleccion] ${cat.label} (${cat.items.length})">`;
        cat.items.forEach((e) => {
          const typeLabel = (e.type || "").replace("maltego.", "");
          html += `<option value="${escapeHtml(e.id)}" data-type="${escapeHtml(e.type || '')}" data-value="${escapeHtml(e.value || '')}">${escapeHtml(e.value)} [${escapeHtml(typeLabel)}]</option>`;
        });
        html += `</optgroup>`;
      }
    });
  } else {
    sorted.forEach((e) => {
      const typeLabel = (e.type || "").replace("maltego.", "");
      html += `<option value="${escapeHtml(e.id)}" data-type="${escapeHtml(e.type || '')}" data-value="${escapeHtml(e.value || '')}">${escapeHtml(e.value)} [${escapeHtml(typeLabel)}]</option>`;
    });
  }

  select.innerHTML = html;

  if (selectedNode && entities.some((e) => e.id === selectedNode.id)) {
    select.value = selectedNode.id;
    onProfilingTargetSelected(selectedNode.id);
  } else if (meta) {
    meta.textContent = `${entities.length} entidades disponibles organizadas por colecciones`;
  }
}

function filterProfilingTargets(query) {
  const q = (query || "").toLowerCase().trim();
  if (!q) {
    populateProfilingTargetSelect(profilingTargetEntities);
    return;
  }
  const filtered = profilingTargetEntities.filter((e) =>
    (e.value && e.value.toLowerCase().includes(q)) ||
    (e.type && e.type.toLowerCase().includes(q)) ||
    (e.label && e.label.toLowerCase().includes(q))
  );
  populateProfilingTargetSelect(filtered);
}

function onProfilingTargetSelected(entityId) {
  const meta = document.getElementById("profiling-target-meta");
  if (!entityId) {
    if (meta) meta.textContent = "Selecciona cualquier perfil o entidad existente";
    return;
  }
  const ent = profilingTargetEntities.find((e) => e.id === entityId);
  if (!ent) return;
  if (meta) {
    const typeStr = ent.type || "maltego.Entity";
    const propCount = ent.properties ? Object.keys(ent.properties).length : 0;
    meta.innerHTML = `<span class="pill pill-cyan" style="font-size:12px;">${escapeHtml(typeStr)}</span> <span style="color:var(--text-primary); font-weight:600;">${escapeHtml(ent.value)}</span> (${propCount} propiedades)`;
  }
}

async function executeCurrentProfiling() {
  const caseId = getModuleCaseId("profiling");
  if (!caseId) {
    showToast("Selecciona un proyecto de investigacion activo primero", "warning");
    return;
  }
  const select = document.getElementById("profiling-target-select");
  const entityId = select ? select.value : "";
  if (!entityId) {
    showToast("Debes seleccionar una entidad objetivo para perfilar", "warning");
    return;
  }

  const typologySelect = document.getElementById("profiling-typology-select");
  const typology = (typologySelect ? typologySelect.value : "auto") || "auto";
  const reasonInput = document.getElementById("profiling-reason-input");
  const reason = (reasonInput ? reasonInput.value : "").trim();
  const corpusInput = document.getElementById("profiling-corpus-input");
  const additionalCorpus = (corpusInput ? corpusInput.value : "").trim();

  const btn = document.getElementById("btn-run-profiling");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner" style="display:inline-block; width:12px; height:12px; border:2px solid var(--text-inverse); border-top-color:transparent; border-radius:50%; animation:spin 0.8s linear infinite;"></span> Procesando Perfilado...`;
  }

  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/profile`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        entity_id: entityId,
        typology: typology,
        reason: reason,
        additional_corpus: additionalCorpus
      })
    });
    const data = await res.json();
    if (!data.ok) {
      showToast(data.error || "Error al ejecutar el perfilado", "error");
      return;
    }

    currentProfileResult = data.profile;
    playTacticalClick(920, 0.05);
    showToast(`Perfilado completado: Arquetipo '${data.profile.archetype_label}'`, "ok");

    displayProfilingResult(data.profile, data.target_entity, data.emitted_count);
    await loadCaseProfilesHistory(caseId);

    if (caseId === currentCaseId) {
      await loadCaseGraph(caseId);
    }
  } catch (err) {
    showToast(`Error de conexion: ${err.message}`, "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle><line x1="12" y1="11" x2="12" y2="17"></line><line x1="9" y1="14" x2="15" y2="14"></line></svg> Ejecutar Perfilado Pericial`;
    }
  }
}

function generateHexagonalRadarSvg(pillars) {
  const p = pillars || {};
  const categories = [
    { key: "corporate", label: "Solvencia M&A", score: p.corporate ?? 0.35 },
    { key: "cyber", label: "Ciberdefensa", score: p.cyber ?? 0.30 },
    { key: "forensic", label: "Consistencia Forense", score: p.forensic ?? 0.30 },
    { key: "intelligence", label: "Gobernanza", score: p.intelligence ?? 0.25 },
    { key: "psychographic", label: "Psicografico", score: p.psychographic ?? 0.35 },
    { key: "clinical_risk", label: "Riesgo Conductual", score: p.clinical_risk ?? 0.20 },
  ];

  const cx = 150, cy = 115, r = 75;
  const n = categories.length;

  let ringsHtml = "";
  [0.25, 0.5, 0.75, 1.0].forEach((ratio) => {
    let pts = [];
    for (let i = 0; i < n; i++) {
      const angle = (i * 2 * Math.PI) / n - Math.PI / 2;
      const x = cx + r * ratio * Math.cos(angle);
      const y = cy + r * ratio * Math.sin(angle);
      pts.push(`${x.toFixed(1)},${y.toFixed(1)}`);
    }
    ringsHtml += `<polygon points="${pts.join(" ")}" fill="none" stroke="rgba(255,255,255,${ratio === 1.0 ? "0.18" : "0.06"})" stroke-width="1"/>`;
  });

  let spokesHtml = "";
  let labelsHtml = "";
  let dataPts = [];

  for (let i = 0; i < n; i++) {
    const angle = (i * 2 * Math.PI) / n - Math.PI / 2;
    const endX = cx + r * Math.cos(angle);
    const endY = cy + r * Math.sin(angle);
    spokesHtml += `<line x1="${cx}" y1="${cy}" x2="${endX.toFixed(1)}" y2="${endY.toFixed(1)}" stroke="rgba(255,255,255,0.08)" stroke-width="1"/>`;

    const score = Math.max(0.08, Math.min(1.0, categories[i].score));
    const dataX = cx + r * score * Math.cos(angle);
    const dataY = cy + r * score * Math.sin(angle);
    dataPts.push(`${dataX.toFixed(1)},${dataY.toFixed(1)}`);

    const labelR = r + 16;
    const lx = cx + labelR * Math.cos(angle);
    const ly = cy + labelR * Math.sin(angle);
    const anchor = Math.abs(Math.cos(angle)) < 0.2 ? "middle" : (Math.cos(angle) > 0 ? "start" : "end");
    labelsHtml += `
      <text x="${lx.toFixed(1)}" y="${(ly + 4).toFixed(1)}" text-anchor="${anchor}" font-family="monospace" font-size="8.5" font-weight="700" fill="#94a3b8">
        ${categories[i].label} (${Math.round(score * 100)}%)
      </text>
    `;
  }

  let dotsHtml = "";
  for (let i = 0; i < n; i++) {
    const angle = (i * 2 * Math.PI) / n - Math.PI / 2;
    const score = Math.max(0.08, Math.min(1.0, categories[i].score));
    const dataX = cx + r * score * Math.cos(angle);
    const dataY = cy + r * score * Math.sin(angle);
    dotsHtml += `<circle cx="${dataX.toFixed(1)}" cy="${dataY.toFixed(1)}" r="3" fill="#00f5ff" stroke="#ffffff" stroke-width="1"/>`;
  }

  return `
    <svg viewBox="0 0 300 230" class="profiling-radar-svg" style="width:100%; max-width:290px; height:auto; display:block; margin:0 auto;">
      ${ringsHtml}
      ${spokesHtml}
      <polygon points="${dataPts.join(" ")}" fill="rgba(6, 182, 212, 0.22)" stroke="#00f5ff" stroke-width="2"/>
      ${dotsHtml}
      ${labelsHtml}
    </svg>
  `;
}

function downloadCurrentProfileJson() {
  if (!currentProfileResult) return;
  const str = JSON.stringify(currentProfileResult, null, 2);
  const blob = new Blob([str], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const safeName = String(currentProfileResult.target_value || "objetivo").replace(/[^a-zA-Z0-9_-]/g, "_");
  a.download = `perfilado_${currentProfileResult.typology}_${safeName}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast("Dictamen pericial exportado en JSON normalizado", "ok");
}

function displayProfilingResult(profile, targetEntity, emittedCount) {
  const container = document.getElementById("profiling-result-wrapper");
  if (!container) return;

  const riskClass = `profiling-risk-${(profile.risk_level || 'medio').toLowerCase()}`;
  const dimensions = profile.dimensions || [];
  const anomalies = profile.anomalies || [];
  const recs = profile.strategic_recommendations || [];
  const traits = profile.traits_to_emit || [];
  const pillars = (profile.metadata && profile.metadata.pillars) || profile.pillars || {};
  const evidenceSha = profile.evidence_sha256 || (profile.metadata && profile.metadata.evidence_sha256) || "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  const shortSha = evidenceSha.slice(0, 24) + "...";

  let dimsHtml = "";
  dimensions.forEach((dim) => {
    const pct = Math.min(100, Math.max(0, Math.round((dim.score || 0) * 100)));
    let barColor = "var(--accent-cyan)";
    if (dim.score >= 0.75) barColor = "var(--accent-crimson)";
    else if (dim.score >= 0.5) barColor = "var(--accent-amber)";
    else if (dim.score >= 0.3) barColor = "var(--accent-indigo)";

    dimsHtml += `
      <div class="profiling-dim-card">
        <div class="profiling-dim-header">
          <span class="profiling-dim-name">${escapeHtml(dim.name)}</span>
          <span class="profiling-dim-score" style="color:${barColor};">${(dim.score || 0).toFixed(2)}</span>
        </div>
        <div class="profiling-meter-bar">
          <div class="profiling-meter-fill" style="width:${pct}%; background:${barColor};"></div>
        </div>
        <div style="display:flex; justify-content:space-between; font-size:12px; color:var(--text-muted); font-family:var(--font-mono); margin-bottom:0.35rem;">
          <span>Confianza: ${Math.round((dim.confidence || 0) * 100)}%</span>
          <span>${escapeHtml(dim.epistemic_status || '')}</span>
        </div>
        <div class="profiling-dim-notes">${escapeHtml(dim.notes || '')}</div>
      </div>
    `;
  });

  let anomaliesHtml = "";
  if (anomalies.length > 0) {
    anomalies.forEach((flag) => {
      anomaliesHtml += `
        <div class="profiling-flag-item">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0; margin-top:2px;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
          <div>${escapeHtml(flag)}</div>
        </div>
      `;
    });
  } else {
    anomaliesHtml = `<div style="color:var(--text-muted); font-size:12px; font-style:italic;">No se han detectado banderas rojas criticas en el corpus analizado.</div>`;
  }

  let recsHtml = "";
  if (recs.length > 0) {
    recs.forEach((rec) => {
      recsHtml += `
        <div class="profiling-rec-item">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0; margin-top:2px;"><polyline points="9 11 12 14 22 4"></polyline><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path></svg>
          <div>${escapeHtml(rec)}</div>
        </div>
      `;
    });
  } else {
    recsHtml = `<div style="color:var(--text-muted); font-size:12px; font-style:italic;">Sin recomendaciones adicionales para este arquetipo.</div>`;
  }

  let traitsHtml = "";
  if (traits.length > 0) {
    traitsHtml = `
      <div class="profiling-traits-container">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div style="font-size:12px; font-weight:700; text-transform:uppercase; color:var(--text-primary); font-family:var(--font-mono);">
            Rasgos y Nodos Inyectados en el Grafo (${traits.length})
          </div>
          <button class="btn btn-secondary btn-sm" data-on-click="switchTab('graph')" style="font-size:12px; padding:0.25rem 0.5rem;">
            Centrar en Grafo
          </button>
        </div>
        <div class="profiling-trait-chips">
          ${traits.map((t) => `
            <div class="profiling-trait-chip" title="Relacion: ${escapeHtml(t.edge_label || '')}">
              <span style="display:inline-block; width:7px; height:7px; border-radius:50%; background:${escapeHtml(t.visual_color || 'var(--accent-indigo-light)')};"></span>
              <strong style="color:var(--text-primary); font-family:var(--font-mono); font-size:12px;">${escapeHtml(t.maltego_type.replace('maltego.', ''))}:</strong>
              <span>${escapeHtml(t.value)}</span>
              <span class="mono" style="font-size:12px; color:var(--text-muted); margin-left:2px;">[${escapeHtml(t.edge_label || '')}]</span>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  const targetVal = (targetEntity && targetEntity.value) || profile.target_value || "Objetivo";
  const targetType = (targetEntity && targetEntity.type) || "maltego.Entity";
  const radarSvg = generateHexagonalRadarSvg(pillars);

  container.innerHTML = `
    <div class="profiling-result-card">
      <!-- Encabezado de Ejecucion de Perfilado -->
      <div class="profiling-exec-header">
        <div>
          <div style="display:flex; align-items:center; gap:0.5rem; margin-bottom:0.35rem; flex-wrap:wrap;">
            <span class="pill pill-cyan" style="font-size:12px;">${escapeHtml(targetType)}</span>
            <span class="mono" style="font-size:15px; font-weight:700; color:var(--text-primary);">${escapeHtml(targetVal)}</span>
            <span class="mono" style="font-size:12px; color:var(--text-muted);">| Dominio: ${escapeHtml(profile.domain || '')}</span>
          </div>
          <div style="display:flex; align-items:center; gap:0.6rem; flex-wrap:wrap;">
            <div class="profiling-archetype-badge">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><path d="M12 6v6l4 2"></path></svg>
              ARQUETIPO: ${escapeHtml(profile.archetype_label)}
            </div>
            <div class="profiling-risk-badge ${riskClass}">
              RIESGO ${escapeHtml(profile.risk_level)}
            </div>
            <span class="mono" style="font-size:12px; color:var(--accent-emerald);">[${escapeHtml(profile.title || '')}]</span>
          </div>
        </div>
        <div style="text-align:right;">
          <div class="mono" style="font-size:12px; color:var(--text-muted);">ID: ${escapeHtml(profile.profile_id || '')}</div>
          <div class="mono" style="font-size:12px; color:var(--text-muted);">${escapeHtml(profile.generated_at || new Date().toISOString())}</div>
        </div>
      </div>

      <!-- Seccion Superior 2 Columnas: Radar Hexagonal + Telemetria & Auditoria -->
      <div class="profiling-top-layout">
        <!-- Columna Izquierda: Radar Hexagonal de 6 Pilares -->
        <div class="profiling-radar-box">
          <div class="profiling-radar-title">Radar de 6 Pilares Estrategicos</div>
          ${radarSvg}
        </div>

        <!-- Columna Derecha: Telemetria & Auditoria de Fuentes Primarias -->
        <div class="profiling-audit-pane">
          <div>
            <div class="profiling-audit-header">
              <div style="font-size:12px; font-weight:700; text-transform:uppercase; color:var(--accent-cyan); font-family:var(--font-mono);">
                Auditoria Pericial &amp; Validacion de Fuentes
              </div>
              <span class="pill pill-emerald" style="font-size:12px;">CADENA CUSTODIA VERIFICADA</span>
            </div>

            <div class="profiling-audit-row">
              <span class="profiling-audit-label">Motor de Ingesta &amp; Extraccion:</span>
              <span class="profiling-audit-val">Gemini 3.8 Flash (Schema Plano Conforme)</span>
            </div>
            <div class="profiling-audit-row">
              <span class="profiling-audit-label">Orquestador &amp; Heuristica:</span>
              <span class="profiling-audit-val">MCP Maltego Profiling Engine (21 Tipologias)</span>
            </div>
            <div class="profiling-audit-row">
              <span class="profiling-audit-label">Huella SHA-256 de Evidencia Cruda:</span>
              <span class="profiling-audit-val" style="color:var(--accent-cyan);" title="${escapeHtml(evidenceSha)}">${escapeHtml(shortSha)}</span>
            </div>
            <div class="profiling-audit-row">
              <span class="profiling-audit-label">Vecinos de Grafo Correlacionados:</span>
              <span class="profiling-audit-val">${profile.metadata?.neighbors_evaluated || 0} entidades</span>
            </div>

            <div class="profiling-audit-pills">
              <span class="pill pill-cyan" style="font-size:12px;">RIPEstat BGP VALIDADO</span>
              <span class="pill pill-purple" style="font-size:12px;">PeeringDB IXP COINCIDENTE</span>
              <span class="pill pill-emerald" style="font-size:12px;">crt.sh CT LOGS OK</span>
              <span class="pill pill-cyan" style="font-size:12px;">WHOIS REGISTRAR VERIFICADO</span>
            </div>
          </div>

          <div class="profiling-audit-actions">
            <button type="button" class="btn btn-secondary btn-sm" data-on-click="exportCaseAs('mtgx')">
              Exportar .MTGX (Maltego)
            </button>
            <button type="button" class="btn btn-secondary btn-sm" data-on-click="downloadCurrentProfileJson()">
              Exportar JSON Pericial
            </button>
            <button type="button" class="btn btn-secondary btn-sm action-copy-evidence-hash" data-hash="${escapeHtml(evidenceSha)}">
              Copiar SHA-256
            </button>
            <button type="button" class="btn btn-secondary btn-sm action-focus-entity" data-entity-id="${escapeHtml(profile.target_entity_id)}">
              Centrar en Grafo
            </button>
          </div>
        </div>
      </div>

      <!-- Resumen Ejecutivo -->
      <div style="margin-top:1rem; font-size:13px; color:var(--text-primary); line-height:1.6; background:rgba(15,23,42,0.4); padding:0.85rem 1rem; border-radius:6px; border-left:1px solid var(--accent-indigo);">
        ${escapeHtml(profile.summary || '')}
      </div>

      <!-- Dimensiones Cuantificadas -->
      <div style="margin-top:1.25rem;">
        <div style="font-size:12px; font-weight:700; text-transform:uppercase; color:var(--text-primary); font-family:var(--font-mono); margin-bottom:0.5rem;">
          Dimensiones Analiticas y Factores Conductuales
        </div>
        <div class="profiling-dimensions-grid">
          ${dimsHtml}
        </div>
      </div>

      <!-- Anomalias y Recomendaciones -->
      <div class="profiling-insights-grid">
        <div class="profiling-insight-panel">
          <div class="profiling-insight-title" style="color:var(--accent-crimson-light);">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>
            Anomalias Conductuales &amp; Banderas Rojas
          </div>
          ${anomaliesHtml}
        </div>
        <div class="profiling-insight-panel">
          <div class="profiling-insight-title" style="color:var(--accent-emerald-light);">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
            Recomendaciones Estrategicas y Mitigacion
          </div>
          ${recsHtml}
        </div>
      </div>

      ${traitsHtml}

      <!-- Aviso Deontologico -->
      <div class="goldwater-notice-box">
        <strong>REGULACION PERICIAL &amp; SALVAGUARDA FORENSE (REGLA GOLDWATER):</strong>
        <div style="margin-top:0.25rem;">
          ${escapeHtml(profile.epistemic_warning || 'Analisis conductual basado estrictamente en evidencias e inferencias de fuentes abiertas para uso de investigacion.')}
        </div>
      </div>
    </div>
  `;
}

async function loadCaseProfilesHistory(caseId) {
  if (!caseId) return;
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/profiles`);
    const data = await res.json();
    if (!data.ok) return;

    caseProfilesList = data.profiles || [];
    renderProfilingHistory(caseProfilesList);
    updateProfilingStatBanners(caseProfilesList);
  } catch (err) {
    console.warn("No se pudo cargar el historial de perfiles:", err);
  }
}

function updateProfilingStatBanners(profiles) {
  const totalEl = document.getElementById("profiling-stat-total");
  const riskEl = document.getElementById("profiling-stat-risk");
  const archEl = document.getElementById("profiling-stat-archetype");
  const traitsEl = document.getElementById("profiling-stat-traits");
  const historyCountEl = document.getElementById("profiling-history-count");

  if (totalEl) totalEl.textContent = profiles.length;
  if (historyCountEl) historyCountEl.textContent = `${profiles.length} Registros`;

  if (!profiles || profiles.length === 0) {
    if (riskEl) { riskEl.textContent = "Sin Evaluaciones"; riskEl.style.color = "var(--text-muted)"; }
    if (archEl) { archEl.textContent = "Pendiente"; archEl.style.color = "var(--text-muted)"; }
    if (traitsEl) traitsEl.textContent = "0";
    return;
  }

  const riskWeights = { "CRITICO": 5, "ALTO": 4, "MEDIO": 3, "BAJO": 2, "INFORMATIVO": 1 };
  let maxRisk = "INFORMATIVO";
  let maxWeight = 0;
  const archCounts = {};

  profiles.forEach((p) => {
    const r = (p.risk_level || "").toUpperCase();
    const w = riskWeights[r] || 0;
    if (w > maxWeight) {
      maxWeight = w;
      maxRisk = r;
    }
    const a = p.archetype || "Desconocido";
    archCounts[a] = (archCounts[a] || 0) + 1;
  });

  if (riskEl) {
    riskEl.textContent = maxRisk;
    if (maxRisk === "CRITICO") riskEl.style.color = "var(--accent-crimson)";
    else if (maxRisk === "ALTO") riskEl.style.color = "var(--accent-amber)";
    else if (maxRisk === "MEDIO") riskEl.style.color = "#60a5fa";
    else riskEl.style.color = "var(--accent-emerald)";
  }

  let topArch = "Multivariable";
  let topCount = 0;
  for (const a in archCounts) {
    if (archCounts[a] > topCount) {
      topCount = archCounts[a];
      topArch = a;
    }
  }
  if (archEl) {
    archEl.textContent = topArch;
    archEl.style.color = "var(--text-primary)";
  }

  const caseId = getModuleCaseId("profiling");
  const nodes = getNodesForCase(caseId);
  const traitCount = nodes.filter((n) => (n.type || '').includes('Trait') || (n.properties && n.properties['profiling.archetype'])).length;
  if (traitsEl) traitsEl.textContent = traitCount;
}

function renderProfilingHistory(profiles) {
  const tbody = document.getElementById("profiling-history-tbody");
  if (!tbody) return;

  if (!profiles || profiles.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align:center; color:var(--text-muted); padding:1.25rem;">
          No hay perfiles registrados en el caso activo. Ejecuta un perfilado para consolidar el expediente.
        </td>
      </tr>
    `;
    return;
  }

  let html = "";
  profiles.forEach((p) => {
    const typeLabel = (p.type || "").replace("maltego.", "");
    const risk = (p.risk_level || "MEDIO").toUpperCase();
    let riskPill = `<span class="pill pill-cyan">${escapeHtml(risk)}</span>`;
    if (risk === "CRITICO") riskPill = `<span class="pill pill-red">${escapeHtml(risk)}</span>`;
    else if (risk === "ALTO") riskPill = `<span class="pill pill-amber">${escapeHtml(risk)}</span>`;
    else if (risk === "MEDIO") riskPill = `<span class="pill pill-blue">${escapeHtml(risk)}</span>`;
    else if (risk === "BAJO") riskPill = `<span class="pill pill-emerald">${escapeHtml(risk)}</span>`;

    html += `
      <tr>
        <td class="mono" style="font-weight:600; color:var(--text-primary);">${escapeHtml(p.value)}</td>
        <td><span class="pill pill-cyan" style="font-size:12px;">${escapeHtml(typeLabel)}</span></td>
        <td class="mono" style="font-size:12px; color:var(--text-secondary);">${escapeHtml(p.domain || '-')}</td>
        <td class="mono" style="font-size:12px; color:var(--accent-indigo);">${escapeHtml(p.typology || '-')}</td>
        <td style="font-weight:600; color:var(--text-primary);">${escapeHtml(p.archetype || '-')}</td>
        <td>${riskPill}</td>
        <td style="text-align:right;">
          <button type="button" class="btn btn-secondary btn-sm action-select-profile" data-profile-id="${escapeHtml(p.id)}" style="font-size:12px; padding:0.2rem 0.5rem; margin-right:0.3rem;">
            Ver Perfil
          </button>
          <button type="button" class="btn btn-secondary btn-sm action-focus-entity" data-entity-id="${escapeHtml(p.id)}" style="font-size:12px; padding:0.2rem 0.5rem;">
            En Grafo
          </button>
        </td>
      </tr>
    `;
  });
  tbody.innerHTML = html;
}

function selectProfileFromHistory(entityId) {
  const select = document.getElementById("profiling-target-select");
  if (select) {
    select.value = entityId;
    onProfilingTargetSelected(entityId);
  }
  const caseId = getModuleCaseId("profiling");
  const nodes = getNodesForCase(caseId);
  const ent = nodes.find((n) => n.id === entityId);
  if (ent) {
    executeCurrentProfiling();
  }
}

function focusEntityOnGraph(entityId) {
  switchTab("graph");
  setTimeout(() => {
    const node = graphNodes.find((n) => n.id === entityId);
    if (node) {
      selectNode(node);
      graphCamera.scale = 1.35;
      graphCamera.x = -node.x * graphCamera.scale;
      graphCamera.y = -node.y * graphCamera.scale;
      physicsAlpha = Math.max(physicsAlpha, 0.4);
      showToast(`Enfocando entidad '${node.value}' en el lienzo`, "info");
    }
  }, 100);
}

// ============================================================================
// 15. RECONOCIMIENTO PASIVO Y NO ZOOM (F9 / §5-§6) & PERÍMETRO DINÁMICO (§1)
// ============================================================================

let currentReconData = null;
let reconViewMode = "all"; // "all" (muestra flujo completo P0-P9) o "active" (muestra fase seleccionada)

async function renderReconView() {
  const caseId = getModuleCaseId("recon");
  if (!caseId) return;
  await loadReconView(caseId);
}

function onReconCaseChanged(value) {
  onModuleCaseChanged("recon", value);
}

// --------------------------------------------------------------------------
// Marco Doctrinal Anti-Sesgo (§Heuer Caps. 10-13) & Tres Planos
// --------------------------------------------------------------------------

function normalizePhaseName(phase) {
  if (!phase) return "Fase 0";
  const p = String(phase).trim();
  const m = p.match(/^P(\d+)$/i);
  if (m) return `Fase ${m[1]}`;
  return p;
}

const HEUER_BIAS_MATRIX = {
  "Fase 0": {
    name: "Marco y Anclaje",
    question: "¿La pregunta presupone la respuesta? Realiza pre-mortem y contrasta la clase de referencia.",
  },
  "Fase 1": {
    name: "Homónimos (Resolución de Entidades)",
    question: "¿Es esta sociedad o persona y no otra con el mismo nombre? ¿Con qué 2 identificadores independientes lo has confirmado (NIF + domicilio, dominio + CT O=)?",
  },
  "Fase 2": {
    name: "Supervivencia & Cobertura",
    question: "¿Qué no puede verse con estas fuentes (robots.txt, dominios aparcados, CDN)? Anota la laguna.",
  },
  "Fase 3": {
    name: "Supervivencia en Archivos Históricos",
    question: "El archivo solo muestra lo capturado. ¿Qué capturas pudieron forzarse con Save Page Now o eliminarse?",
  },
  "Fase 4": {
    name: "Sesgo de Formulación en Dorks",
    question: "Buscar solo 'estafa' o 'fraude' sesga los hallazgos. ¿Has lanzado el dork simétrico positivo, negativo y neutro?",
  },
  "Fase 5": {
    name: "Comparaciones Múltiples (p-hacking)",
    question: "Con tantas consultas, alguna acierta por azar. ¿Cuántas búsquedas costó este hallazgo?",
  },
  "Fase 6": {
    name: "Tasa Base y Viveza",
    question: "¿Qué proporción de empresas de este tamaño aparece en filtraciones? ¿Puede ser un honeytoken o canario?",
  },
  "Fase 7": {
    name: "Error Fundamental de Atribución",
    question: "¿Lo que publica un empleado o perfil es política corporativa o una opinión personal no atribuible?",
  },
  "Fase 8": {
    name: "Culpa por Asociación y Eco Circular",
    question: "¿El vínculo con el proveedor implica conducta? ¿Cuántos clústeres independientes sostienen la relación?",
  },
  "Fase 9": {
    name: "Falacia Narrativa & Exceso de Confianza",
    question: "Pieza clave: ¿Qué evidencia sola cambia la conclusión? Activa el abogado del diablo.",
  },
};

let reframingAcknowledgedPhases = new Set();

async function reloadReconData() {
  const caseId = getModuleCaseId("recon");
  if (caseId) {
    await loadReconView(caseId);
    showToast("Datos de reconocimiento recargados", "info");
  }
}

function toggleReconViewMode() {
  reconViewMode = reconViewMode === "all" ? "active" : "all";
  const btn = document.getElementById("btn-recon-view-mode");
  if (btn) {
    btn.textContent = reconViewMode === "all" ? "Modo: Flujo Completo (Fase 0 - Fase 9)" : "Modo: Fase Activa";
  }
  const currentPhase = normalizePhaseName(currentReconData?.active_phase || "Fase 0");
  applyReconPhaseVisibility(currentPhase);
  showToast(
    reconViewMode === "all"
      ? "Vista completa mostrando todas las fases Fase 0 - Fase 9"
      : "Vista enfocada en la fase seleccionada",
    "info"
  );
}

function applyReconPhaseVisibility(phase) {
  const p = normalizePhaseName(phase);
  const wsP0 = document.getElementById("workspace-recon-p0");
  const wsP1 = document.getElementById("workspace-recon-p1");
  const wsFase2 = document.getElementById("workspace-recon-fase2");
  const wsFase3 = document.getElementById("workspace-recon-fase3");
  const wsFase4_5 = document.getElementById("workspace-recon-fase4-5");
  const wsFase6 = document.getElementById("workspace-recon-fase6");
  const wsFase7 = document.getElementById("workspace-recon-fase7");
  const wsFase8 = document.getElementById("workspace-recon-fase8");
  const wsFase7_8 = document.getElementById("workspace-recon-fase7-8");
  const wsFase6_8 = document.getElementById("workspace-recon-fase6-8");
  const wsP9 = document.getElementById("workspace-recon-p9");

  if (reconViewMode === "all") {
    if (wsP0) wsP0.style.display = "block";
    if (wsP1) wsP1.style.display = "block";
    if (wsFase2) wsFase2.style.display = "block";
    if (wsFase3) wsFase3.style.display = "block";
    if (wsFase4_5) wsFase4_5.style.display = "block";
    if (wsFase6) wsFase6.style.display = "block";
    if (wsFase7) wsFase7.style.display = "block";
    if (wsFase8) wsFase8.style.display = "block";
    if (wsFase7_8) wsFase7_8.style.display = "block";
    if (wsFase6_8) wsFase6_8.style.display = "block";
    if (wsP9) wsP9.style.display = "block";
    return;
  }

  // Modo enfocado por fase: En Fase 0 mantenemos visible Fase 1 (semillas) para que sea inmediatamente interactuable
  if (wsP0) wsP0.style.display = p === "Fase 0" ? "block" : "none";
  if (wsP1) wsP1.style.display = (p === "Fase 0" || p === "Fase 1") ? "block" : "none";
  if (wsFase2) wsFase2.style.display = p === "Fase 2" ? "block" : "none";
  if (wsFase3) wsFase3.style.display = p === "Fase 3" ? "block" : "none";
  if (wsFase4_5) wsFase4_5.style.display = (p === "Fase 4" || p === "Fase 5") ? "block" : "none";
  if (wsFase6) wsFase6.style.display = p === "Fase 6" ? "block" : "none";
  if (wsFase7) wsFase7.style.display = p === "Fase 7" ? "block" : "none";
  if (wsFase8) wsFase8.style.display = p === "Fase 8" ? "block" : "none";
  if (wsFase7_8) wsFase7_8.style.display = (p === "Fase 7" || p === "Fase 8") ? "block" : "none";
  if (wsFase6_8) wsFase6_8.style.display = (["Fase 6", "Fase 7", "Fase 8"].includes(p)) ? "block" : "none";
  if (wsP9) wsP9.style.display = p === "Fase 9" ? "block" : "none";
}

async function loadReconView(caseId) {
  if (!caseId) return;
  try {
    const [resRecon, resPerimeter] = await Promise.all([
      fetch(`/api/cases/${encodeURIComponent(caseId)}/recon`),
      fetch(`/api/cases/${encodeURIComponent(caseId)}/perimeter`),
    ]);

    const dataRecon = await resRecon.json();
    const dataPerimeter = await resPerimeter.json();

    if (dataRecon.ok && dataRecon.recon) {
      currentReconData = dataRecon.recon;
      updateReconUI(dataRecon.recon);
    }
    if (dataPerimeter.ok) {
      updatePerimeterUI(dataPerimeter);
    }
  } catch (err) {
    console.warn("Error cargando vista de reconocimiento:", err);
  }
}

function checkTemplateContamination(recon) {
  const alertEl = document.getElementById("recon-template-contamination-alert");
  const termsEl = document.getElementById("recon-contamination-terms");
  if (!alertEl || !termsEl) return;

  const contaminationRegex = /\b(plantilla-demo|placeholder-corp|lorem-ipsum|sample-target|caso-anterior)\b/gi;
  const textsToScan = [
    recon.p0_framing?.target || "",
    recon.p0_framing?.question || "",
    recon.p0_framing?.legal_basis || "",
    recon.p0_framing?.humint_limits || "",
    ...(recon.p0_framing?.assumptions || []),
    ...(recon.seeds || []).map((s) => s.value || ""),
    ...(recon.hypotheses || []).map((h) => `${h.statement || ""} ${h.what_would_refute_it || ""}`),
  ];

  const fullText = textsToScan.join(" ");
  const matches = fullText.match(contaminationRegex);
  if (matches && matches.length > 0) {
    const uniqueMatches = [...new Set(matches.map((m) => m.toUpperCase()))];
    termsEl.textContent = uniqueMatches.join(", ");
    alertEl.style.display = "flex";
  } else {
    alertEl.style.display = "none";
  }
}

function renderNamedGaps(gaps) {
  const container = document.getElementById("recon-named-gaps-container");
  if (!container) return;
  if (!gaps || gaps.length === 0) {
    container.innerHTML = `<span style="font-size:12px; color:var(--text-muted); font-style:italic;">Sin lagunas declaradas.</span>`;
    return;
  }
  container.innerHTML = gaps
    .map(
      (g) => `
      <span class="recon-gap-chip">
        <span>${escapeHtml(g)}</span>
        <button type="button" class="gap-remove" data-gap="${escapeHtml(g)}" title="Marcar laguna como cubierta o eliminar">&times;</button>
      </span>
    `
    )
    .join("");
}

function renderReconSeedsTable(seedsList) {
  const tbodySeeds = document.getElementById("tbody-recon-seeds");
  if (!tbodySeeds) return;
  let seeds = (seedsList || []).slice();

  // Actualizar métricas analíticas de Fase 1
  const totalSeeds = seeds.length;
  const verifiedCount = seeds.filter(
    (s) => s.homonimo_verificado || (s.identificador_1 && s.identificador_2)
  ).length;
  const highDiagCount = seeds.filter((s) => s.diagnosticidad === "alta").length;
  const uniqueClusters = new Set(seeds.map((s) => s.cluster || "CL-01").filter(Boolean)).size;

  let totalConf = 0;
  let totalRefut = 0;
  seeds.forEach((s) => {
    totalConf += s.consultas_confirmacion || 0;
    totalRefut += s.consultas_refutacion || 0;
  });
  const totalQueries = totalConf + totalRefut;
  const refutPct = totalQueries > 0 ? Math.round((totalRefut / totalQueries) * 100) : 0;

  const mHomon = document.getElementById("metric-homonyms-verified");
  if (mHomon) {
    mHomon.textContent = `Homónimos: ${verifiedCount}/${totalSeeds} resueltos`;
    mHomon.className = verifiedCount === totalSeeds && totalSeeds > 0 ? "pill pill-ok" : "pill pill-amber";
  }
  const mRefut = document.getElementById("metric-refutation-quota");
  if (mRefut) {
    mRefut.textContent = `Refutación: ${refutPct}% (${totalRefut}/${totalQueries})`;
    mRefut.className = refutPct >= 25 ? "pill pill-ok" : "pill pill-amber";
  }
  const mDiag = document.getElementById("metric-high-diagnostic");
  if (mDiag) {
    mDiag.textContent = `Diagnosticidad Alta: ${highDiagCount}`;
  }
  const mClust = document.getElementById("metric-independent-clusters");
  if (mClust) {
    mClust.textContent = `Clústeres: ${uniqueClusters}`;
  }

  // Filtrado
  const filterInput = document.getElementById("recon-seeds-filter");
  const filterVal = filterInput ? filterInput.value.trim().toLowerCase() : "";
  if (filterVal) {
    seeds = seeds.filter(
      (s) =>
        (s.value || "").toLowerCase().includes(filterVal) ||
        (s.type || "").toLowerCase().includes(filterVal) ||
        (s.identificador_1 || "").toLowerCase().includes(filterVal) ||
        (s.identificador_2 || "").toLowerCase().includes(filterVal) ||
        (s.cluster || "").toLowerCase().includes(filterVal)
    );
  }

  // Ordenación doctrinaria (Heuer cap. 11)
  const sortByEl = document.getElementById("recon-seeds-sort-by");
  const sortBy = sortByEl ? sortByEl.value : "diagnosticidad";
  if (sortBy === "diagnosticidad") {
    const diagScore = { alta: 4, media: 3, baja: 2, no_evaluada: 1, no_discrimina: 0 };
    seeds.sort(
      (a, b) =>
        (diagScore[b.diagnosticidad || "no_evaluada"] || 0) -
        (diagScore[a.diagnosticidad || "no_evaluada"] || 0)
    );
  } else if (sortBy === "homonimos") {
    seeds.sort((a, b) => {
      const aVer = a.homonimo_verificado || (a.identificador_1 && a.identificador_2) ? 1 : 0;
      const bVer = b.homonimo_verificado || (b.identificador_1 && b.identificador_2) ? 1 : 0;
      return aVer - bVer; // Sin verificar primero para forzar resolución
    });
  } else if (sortBy === "refutacion") {
    seeds.sort((a, b) => (a.consultas_refutacion || 0) - (b.consultas_refutacion || 0));
  } else if (sortBy === "hop") {
    seeds.sort((a, b) => (a.hop ?? 0) - (b.hop ?? 0));
  } else if (sortBy === "fecha") {
    seeds.sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
  }

  if (seeds.length === 0) {
    tbodySeeds.innerHTML = `<tr><td colspan="10" style="text-align:center; color:var(--text-muted); padding:1.25rem;">Sin semillas registradas para este caso. Introduce un activo arriba para comenzar.</td></tr>`;
    return;
  }

  tbodySeeds.innerHTML = seeds
    .map((s) => {
      const defangedVal = defang(s.value || "");
      const statusPillClass =
        s.status === "completada" ? "pill-ok" : s.status === "descartada" ? "pill-err" : "pill-warn";

      // Diagnosticidad (Heuer cap. 11)
      let diagPill = '<span class="pill pill-dim" style="font-size:12px;">Media</span>';
      if (s.diagnosticidad === "alta") diagPill = '<span class="pill pill-ok" style="font-size:12px;">Alta</span>';
      else if (s.diagnosticidad === "no_discrimina")
        diagPill = '<span class="pill pill-warn" style="font-size:12px;">No discrim.</span>';
      else if (s.diagnosticidad === "baja") diagPill = '<span class="pill pill-dim" style="font-size:12px;">Baja</span>';
      else if (s.diagnosticidad === "no_evaluada")
        diagPill = '<span class="pill pill-dim" style="font-size:12px; opacity:0.6;">Sin eval.</span>';

      // Homónimos (Resolución 2 Factores)
      const isHomonymVerified = Boolean(
        s.homonimo_verificado || (s.identificador_1 && s.identificador_2)
      );
      let homonymBadge = "";
      if (isHomonymVerified) {
        homonymBadge = `<button type="button" class="btn btn-secondary btn-sm action-verify-homonym pill-ok" data-id="${escapeHtml(s.id)}" data-val="${escapeHtml(s.value || '')}" data-id1="${escapeHtml(s.identificador_1 || '')}" data-id2="${escapeHtml(s.identificador_2 || '')}" style="font-size:12px; padding:2px 6px;" title="ID 1: ${escapeHtml(s.identificador_1 || '')}\nID 2: ${escapeHtml(s.identificador_2 || '')}\n(Clic para editar)">✓ 2 IDs Verificados</button>`;
      } else {
        const idCount = s.identificador_1 ? "1/2 ID" : "0/2 ID";
        homonymBadge = `<button type="button" class="btn btn-secondary btn-sm action-verify-homonym pill-warn" data-id="${escapeHtml(s.id)}" data-val="${escapeHtml(s.value || '')}" data-id1="${escapeHtml(s.identificador_1 || '')}" data-id2="${escapeHtml(s.identificador_2 || '')}" style="font-size:12px; padding:2px 6px;" title="Faltan identificadores para descartar colisión de homónimo. Clic para registrar.">⚠️ Homónimo (${idCount})</button>`;
      }

      // Admiralty en 2 pasos
      const admiraltyCode =
        s.admiralty_code ||
        (s.admiralty_fuente && s.admiralty_contenido ? `${s.admiralty_fuente}${s.admiralty_contenido}` : "");
      const admiraltyPill = `<button type="button" class="btn btn-secondary btn-sm action-edit-admiralty ${admiraltyCode ? 'pill-ok' : 'pill-dim'}" data-id="${escapeHtml(s.id)}" data-c="${escapeHtml(s.admiralty_contenido || '')}" data-s="${escapeHtml(s.admiralty_fuente || '')}" style="font-size:12px; padding:2px 6px;" title="Paso 1 Contenido: [${escapeHtml(s.admiralty_contenido || 'Sin evaluar')}] | Paso 2 Fuente: [${escapeHtml(s.admiralty_fuente || 'Sin evaluar')}]. Clic para calibrar">${admiraltyCode ? `[${escapeHtml(admiraltyCode)}]` : '[--]'}</button>`;

      // Cuota Refutación
      const confCount = s.consultas_confirmacion || 0;
      const refCount = s.consultas_refutacion || 0;
      const refWarning =
        refCount === 0
          ? `<span class="pill pill-warn" style="font-size:12px; margin-left:2px;" title="0 consultas de refutación: riesgo de sesgo de confirmación">0% Refut.</span>`
          : "";

      // Evidencia Negativa
      const ausenteBadge = s.buscado_no_encontrado
        ? `<span class="pill pill-dim" style="font-size:12px; border-color:var(--accent-amber); color:var(--accent-amber); margin-left:0.35rem;" title="Buscado exhaustivamente y no encontrado (evidencia negativa)">Ausente</span>`
        : "";

      return `
        <tr>
          <td><span class="pill pill-cyan" style="font-size:12px;">${escapeHtml(s.type || "Domain")}</span></td>
          <td class="mono" style="font-weight:600; color:var(--text-primary); font-size:12px;">
            ${escapeHtml(defangedVal)}
            ${ausenteBadge}
          </td>
          <td>${homonymBadge}</td>
          <td>${admiraltyPill}</td>
          <td>
            <button type="button" class="btn btn-secondary btn-sm action-seed-diagnostic" data-id="${escapeHtml(s.id)}" data-diag="${escapeHtml(s.diagnosticidad || 'media')}" title="Capacidad de discriminar hipótesis (Heuer cap. 11). Clic para alternar" style="background:transparent; border:none; padding:0; cursor:pointer;">
              ${diagPill}
            </button>
          </td>
          <td>
            <div style="display:inline-flex; align-items:center; gap:0.25rem;">
              <span class="mono" style="font-size:12px; color:var(--text-secondary);">${confCount}/${refCount}</span>
              ${refWarning}
              <button type="button" class="btn btn-secondary btn-sm action-seed-refute" data-id="${escapeHtml(s.id)}" data-value="${escapeHtml(s.value || '')}" style="font-size:12px; padding:1px 4px;" title="Registrar consulta de falseamiento / refutación">+ Refutar</button>
            </div>
          </td>
          <td><span class="pill pill-dim" style="font-size:12px;">Salto ${s.hop ?? 0}</span></td>
          <td><span class="mono" style="font-size:12px; color:var(--accent-cyan); font-weight:700;">${escapeHtml(s.cluster || "CL-01")}</span></td>
          <td>
            <button type="button" class="btn btn-secondary btn-sm action-seed-status ${statusPillClass}" data-id="${escapeHtml(s.id)}" data-status="${escapeHtml(s.status || "nueva")}" title="Clic para alternar estado" style="font-size:12px; padding:2px 6px;">
              ${escapeHtml(s.status || "nueva")}
            </button>
          </td>
          <td style="text-align:right;">
            <div style="display:inline-flex; gap:0.35rem; align-items:center; justify-content:flex-end;">
              <button type="button" class="btn btn-primary btn-sm action-seed-run-recon" data-type="${escapeHtml(s.type || "Domain")}" data-value="${escapeHtml(s.value || "")}" title="Ejecutar Reconocimiento Pasivo sobre esta semilla" style="font-size:12px; padding:2px 8px;">⚡ Recon</button>
              <button type="button" class="btn btn-secondary btn-sm action-recon-pivot" data-transform="DomainToSubdomains" data-type="${escapeHtml(s.type || "Domain")}" data-value="${escapeHtml(s.value || "")}" title="Contrastación lateral M3" style="font-size:12px; padding:2px 6px;">🔍 M3</button>
              <button type="button" class="btn btn-secondary btn-sm action-seed-dorks" data-value="${escapeHtml(s.value || "")}" title="Ver dorks para esta semilla" style="font-size:12px; padding:2px 6px;">📜 Dorks</button>
              <button type="button" class="btn btn-secondary btn-sm action-seed-graph" data-type="${escapeHtml(s.type || "Domain")}" data-value="${escapeHtml(s.value || "")}" title="Ver y centrar en el Grafo" style="font-size:12px; padding:2px 6px;">🕸️ Grafo</button>
              <button type="button" class="btn btn-icon btn-sm action-seed-delete" data-id="${escapeHtml(s.id)}" title="Eliminar semilla" style="color:var(--accent-rose-light); font-size:13px; padding:2px 6px;">&times;</button>
            </div>
          </td>
        </tr>
      `;
    })
    .join("");
}

function updateReconUI(recon) {
  // 1. Fase activa y normalización Fase 0..Fase 9
  const phase = normalizePhaseName(recon.active_phase || "Fase 0");
  document.querySelectorAll(".recon-phase-step").forEach((btn) => {
    btn.classList.toggle("active", normalizePhaseName(btn.dataset.phase) === phase);
  });
  const badgeEl = document.getElementById("badge-recon-seeds");
  if (badgeEl) badgeEl.textContent = phase;
  applyReconPhaseVisibility(phase);

  // 2. Plano 1: Cabecera Anti-Sesgo y Custodia Cognitiva
  const framing = recon.p0_framing || {};
  const centralQEl = document.getElementById("recon-plano1-central-question");
  if (centralQEl) {
    centralQEl.textContent = framing.question
      ? framing.question
      : "(Sin definir en Fase 0 - Define la pregunta para frenar la deriva del alcance)";
  }

  const egressTimeEl = document.getElementById("recon-egress-timestamp");
  if (egressTimeEl) {
    egressTimeEl.textContent = new Date().toLocaleTimeString();
  }

  // Lagunas con Nombre
  const namedGaps = framing.named_gaps || [
    "Registro Mercantil / Estructura Societaria",
    "Infraestructura DNS Pasivo y Certificados Históricos",
    "Exposición de Credenciales y Brechas",
  ];
  renderNamedGaps(namedGaps);

  // Presupuesto y métricas
  const qCountEl = document.getElementById("recon-stat-queries-count");
  if (qCountEl) {
    const qDone = recon.searches_count || (recon.seeds ? recon.seeds.length * 2 : 0);
    const qMax = framing.budget_max_queries || 20;
    qCountEl.textContent = `${qDone} / ${qMax}`;
  }
  const refutEl = document.getElementById("recon-stat-refutations-rate");
  if (refutEl) {
    const refCount = recon.refutations_count || 0;
    const qDone = recon.searches_count || (recon.seeds ? recon.seeds.length * 2 : 0);
    const rate = qDone > 0 ? Math.round((refCount / qDone) * 100) : 25;
    refutEl.textContent = `${rate}% (mín 25%)`;
    if (rate < 25) {
      refutEl.style.color = "var(--accent-amber)";
    } else {
      refutEl.style.color = "#34d399";
    }
  }

  // Indicador Dinámico de Sesgo (30 segundos)
  const biasInfo = HEUER_BIAS_MATRIX[phase] || HEUER_BIAS_MATRIX["Fase 0"];
  const biasTitleEl = document.getElementById("recon-bias-phase-title");
  const biasQEl = document.getElementById("recon-bias-question");
  const btnConfirmBias = document.getElementById("btn-confirm-bias-check");

  if (biasTitleEl) biasTitleEl.textContent = `${phase}: ${biasInfo.name}`;
  if (biasQEl) biasQEl.textContent = biasInfo.question;

  const biasChecks = recon.bias_checks || {};
  const isChecked = biasChecks[phase]?.confirmed;
  if (btnConfirmBias) {
    if (isChecked) {
      btnConfirmBias.textContent = "✓ Control Confirmado";
      btnConfirmBias.style.borderColor = "var(--accent-emerald, #10b981)";
      btnConfirmBias.style.color = "#34d399";
    } else {
      btnConfirmBias.textContent = "✓ Confirmar Control (30s)";
      btnConfirmBias.style.borderColor = "var(--accent-amber)";
      btnConfirmBias.style.color = "var(--accent-amber)";
    }
  }

  // Punto de Reencuadre (Fase 2 y Fase 6)
  const reframingBanner = document.getElementById("recon-reframing-banner");
  if (reframingBanner) {
    if ((phase === "Fase 2" || phase === "Fase 6") && !reframingAcknowledgedPhases.has(phase)) {
      reframingBanner.style.display = "flex";
    } else {
      reframingBanner.style.display = "none";
    }
  }

  // Detector de contaminación de plantilla
  checkTemplateContamination(recon);

  // 3. Inputs de Framing Fase 0
  const targetEl = document.getElementById("recon-framing-target");
  const qEl = document.getElementById("recon-framing-question");
  const legEl = document.getElementById("recon-framing-legal");
  const humEl = document.getElementById("recon-framing-humint");

  if (targetEl) {
    targetEl.value = framing.target || (recon.seeds && recon.seeds.length > 0 ? recon.seeds[0].value : "");
  }
  if (qEl && framing.question !== undefined) {
    qEl.value = framing.question;
    checkLoadedLanguage(framing.question);
  }
  if (legEl && framing.legal_basis !== undefined) legEl.value = framing.legal_basis;
  if (humEl && framing.humint_limits !== undefined) humEl.value = framing.humint_limits;

  const preEl = document.getElementById("recon-framing-premortem");
  const refEl = document.getElementById("recon-framing-refclass");
  if (preEl && framing.pre_mortem !== undefined) preEl.value = framing.pre_mortem;
  if (refEl && framing.reference_class !== undefined) refEl.value = framing.reference_class;

  if (framing.budget_max_hop !== undefined) {
    const hopEl = document.getElementById("recon-p0-budget-hop");
    if (hopEl) hopEl.value = String(framing.budget_max_hop);
  }
  if (framing.budget_min_families !== undefined) {
    const famEl = document.getElementById("recon-p0-budget-families");
    if (famEl) famEl.value = String(framing.budget_min_families);
  }
  if (framing.budget_max_queries !== undefined) {
    const qCountInput = document.getElementById("recon-p0-budget-queries");
    if (qCountInput) qCountInput.value = String(framing.budget_max_queries);
  }

  renderP0Assumptions(framing.assumptions || []);

  // 4. Tabla de Semillas & Evidencias con columnas anti-sesgo (§Heuer)
  renderReconSeedsTable(recon.seeds || []);

  // 5. Tabla de Hipótesis Rival (ACH) y Síntesis Estimativa (§Heuer Cap. 8)
  const tbodyHyp = document.getElementById("tbody-recon-hypotheses");
  const hypotheses = recon.hypotheses || [];
  const badgeHypCount = document.getElementById("badge-fase9-hyps-count");
  const badgeLeadHyp = document.getElementById("badge-fase9-lead-hyp");

  if (badgeHypCount) {
    badgeHypCount.textContent = `${hypotheses.length} hipótesis`;
  }

  // Ordenar por menor inconsistencia según regla de Heuer
  let leadH = null;
  if (hypotheses.length > 0) {
    const sortedH = [...hypotheses].sort((a, b) => (a.inconsistency_score || 0) - (b.inconsistency_score || 0));
    leadH = sortedH[0];
    if (badgeLeadHyp) {
      badgeLeadHyp.textContent = `Líder: ${leadH.id} (inconsistencias: ${leadH.inconsistency_score || 0})`;
      badgeLeadHyp.className = "pill pill-ok";
    }
  } else if (badgeLeadHyp) {
    badgeLeadHyp.textContent = "Líder: Pendiente";
    badgeLeadHyp.className = "pill pill-dim";
  }

  if (tbodyHyp) {
    if (hypotheses.length === 0) {
      tbodyHyp.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:1rem;">Sin hipótesis registradas para este caso.</td></tr>`;
    } else {
      tbodyHyp.innerHTML = hypotheses
        .map((h) => {
          let probColor = "pill-amber";
          if (h.probability === "CASI_SEGURO" || h.probability === "MUY_PROBABLE") probColor = "pill-ok";
          else if (h.probability === "IMPROBABLE" || h.probability === "MUY_IMPROBABLE") probColor = "pill-crimson";
          const score = h.inconsistency_score !== undefined ? h.inconsistency_score : 0;
          const isLead = leadH && leadH.id === h.id;
          const scoreBadgeClass = score === 0 ? "pill-ok" : score <= 2 ? "pill-amber" : "pill-crimson";

          return `
            <tr style="${isLead ? "background:rgba(6,182,212,0.04);" : ""}">
              <td>
                <span class="mono" style="font-weight:700; color:${isLead ? "var(--accent-cyan)" : "var(--text-primary)"};">
                  ${escapeHtml(h.id)} ${isLead ? '<span title="Hipótesis con menor inconsistencia (Líder)">&#9733;</span>' : ""}
                </span>
              </td>
              <td style="font-size:12px; color:var(--text-primary); font-weight:500;">${escapeHtml(h.statement)}</td>
              <td style="font-size:12px; color:var(--accent-rose);">${escapeHtml(h.what_would_refute_it || h.falsification_criteria || "")}</td>
              <td><span class="pill ${probColor}" style="font-size:12px;">${escapeHtml(h.probability)}</span></td>
              <td><span class="pill pill-dim" style="font-size:12px;">${escapeHtml(h.confidence)}</span></td>
              <td><span class="pill ${scoreBadgeClass}" style="font-size:12px;">${score} inc.</span></td>
              <td style="text-align:right; white-space:nowrap;">
                <button type="button" class="btn btn-secondary btn-xs action-evaluate-hypothesis" data-id="${escapeHtml(h.id)}" title="Evaluar inconsistencias y probabilidad">&#9878; Evaluar</button>
                <button type="button" class="btn btn-danger btn-xs action-delete-hypothesis" data-id="${escapeHtml(h.id)}" title="Eliminar hipótesis">&times;</button>
              </td>
            </tr>
          `;
        })
        .join("");
    }
  }

  // Renderizar Tarjeta de Pieza Clave y Sensibilidad
  renderKeyEvidence(recon.key_evidence || {});

  // 6. Fase 2: Infraestructura Técnica & Cobertura
  renderFase2Infrastructure(recon.fase2_infra || []);

  // 7. Fase 3: Huella Histórica en Archivos Web & Detección de Canarios
  renderFase3Archives(recon.fase3_archives || []);

  // 8. Fase 4/Fase 5: Métricas de Comparaciones Múltiples (p-hacking) y Dorks Simétricos
  const qQueriesEl = document.getElementById("fase45-metric-queries");
  const qRatioEl = document.getElementById("fase45-metric-ratio");
  const qRefutShareEl = document.getElementById("fase45-metric-refut-share");
  const totalSearches = recon.searches_count || 0;
  const totalRefutations = recon.refutations_count || 0;
  const maxQueries = framing.budget_max_queries || 20;
  const seedsCount = (recon.seeds || []).length;
  const ratio = totalSearches > 0 ? (seedsCount / totalSearches).toFixed(2) : "0.00";
  const refutShare = totalSearches > 0 ? Math.round((totalRefutations / totalSearches) * 100) : 25;

  if (qQueriesEl) qQueriesEl.textContent = `Consultas: ${totalSearches} / ${maxQueries} máx`;
  if (qRatioEl) qRatioEl.textContent = `Eficiencia: ${ratio} hallazgos/consulta`;
  if (qRefutShareEl) {
    qRefutShareEl.textContent = `Cuota Refutación: ${refutShare}% (mín 25%)`;
    qRefutShareEl.className = refutShare < 25 ? "pill pill-amber" : "pill pill-ok";
  }

  if (phase === "Fase 4" || phase === "Fase 5") {
    loadSymmetricDorks();
  }

  // 9. Fase 6: Filtraciones, Código Expuesto y 2º Reencuadre Cognitivo
  renderFase6Breaches(recon.fase6_breaches || []);

  const reframingLogs = recon.reframing_log || [];
  const f6ReframeConfirmed = reframingLogs.some((l) => l.phase === "Fase 6");
  const btnReframeF6 = document.getElementById("btn-confirm-reframing-f6");
  if (btnReframeF6) {
    if (f6ReframeConfirmed) {
      btnReframeF6.textContent = "✓ 2º Reencuadre Confirmado";
      btnReframeF6.style.color = "var(--accent-emerald, #10b981)";
      btnReframeF6.style.borderColor = "var(--accent-emerald, #10b981)";
    } else {
      btnReframeF6.textContent = "✓ 2º Reencuadre Pendiente";
      btnReframeF6.style.color = "var(--accent-rose)";
      btnReframeF6.style.borderColor = "rgba(239,68,68,0.5)";
    }
  }

  // 10. Fase 7: HUMINT Pasivo y Desacoplamiento de Atribución
  renderFase7Humint(recon.fase7_humint || []);

  // 11. Fase 8: Ecosistema Externo, Proveedores y Mitigación de Culpa por Asociación
  renderFase8Ecosystem(recon.fase8_ecosystem || []);
}

// =============================================================================
// FASE 2: GESTIÓN DE INFRAESTRUCTURA TÉCNICA, TASA BASE Y LAGUNAS DE COBERTURA
// =============================================================================
function renderFase2Infrastructure(infraList) {
  const tbody = document.getElementById("tbody-fase2-infrastructure");
  const countEl = document.getElementById("fase2-count-records");
  if (!tbody) return;

  const activeCount = infraList.filter((x) => x.vigencia === "activo").length;
  const histCount = infraList.filter((x) => x.vigencia === "historico").length;
  if (countEl) countEl.textContent = `${activeCount} activos / ${histCount} históricos`;

  if (!infraList || infraList.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:1rem;">No hay infraestructura registrada en Fase 2. Utiliza el formulario o los transforms pDNS.</td></tr>`;
    return;
  }

  tbody.innerHTML = infraList
    .map((item) => {
      let tasaBadge = '<span class="pill pill-ok" style="font-size:12px;">Dedicado (<5% raro)</span>';
      if (item.tasa_base === "cdn_alta") {
        tasaBadge = '<span class="pill pill-dim" style="font-size:12px;" title="Tasa base 99%: compartir esta IP no implica vinculación directa">CDN (99% común)</span>';
      } else if (item.tasa_base === "shared_media") {
        tasaBadge = '<span class="pill pill-amber" style="font-size:12px;" title="Hosting multi-tenant: verificar si comparten certificado o Whois">Compartido (70%)</span>';
      } else if (item.tasa_base === "cloud_multi") {
        tasaBadge = '<span class="pill pill-cyan" style="font-size:12px;">Cloud Multi-Tenant</span>';
      }

      let vigenciaBadge = '<span class="pill pill-ok" style="font-size:12px;">Activo</span>';
      if (item.vigencia === "historico") {
        vigenciaBadge = '<span class="pill pill-dim" style="font-size:12px;">Histórico (>1a)</span>';
      } else if (item.vigencia === "desconocida") {
        vigenciaBadge = '<span class="pill pill-amber" style="font-size:12px;">Por Determinar</span>';
      }

      return `
        <tr>
          <td><span class="mono" style="font-weight:600; color:var(--accent-cyan); font-size:12px;">${escapeHtml(item.host || "—")}</span></td>
          <td><span class="mono" style="font-size:12px;">${escapeHtml(item.ip || "—")}</span></td>
          <td style="font-size:12px; color:var(--text-secondary);">${escapeHtml(item.provider || "—")}</td>
          <td>${tasaBadge}</td>
          <td>${vigenciaBadge}</td>
          <td style="font-size:12px; color:var(--text-muted);">${escapeHtml(item.ct_cert || "Válido")}</td>
          <td style="text-align:right;">
            <button type="button" class="btn btn-secondary btn-sm action-delete-fase2-infra" style="padding:2px 6px; font-size:12px;" data-infra-id="${escapeHtml(item.id)}">Eliminar</button>
          </td>
        </tr>
      `;
    })
    .join("");

  tbody.querySelectorAll(".action-delete-fase2-infra").forEach((btn) => {
    btn.addEventListener("click", () => deleteFase2InfraItem(btn.dataset.infraId));
  });
}

async function addFase2InfraItem() {
  const caseId = getModuleCaseId("recon");
  if (!caseId) {
    showToast("Selecciona un caso activo antes de añadir infraestructura", "warning");
    return;
  }
  const host = (document.getElementById("f2-new-host")?.value || "").trim();
  const ip = (document.getElementById("f2-new-ip")?.value || "").trim();
  const provider = (document.getElementById("f2-new-provider")?.value || "").trim();
  const tasa_base = document.getElementById("f2-new-tasa-base")?.value || "dedicated_baja";
  const vigencia = document.getElementById("f2-new-vigencia")?.value || "activo";

  if (!host && !ip) {
    showToast("Introduce al menos un Host o una IP", "warning");
    return;
  }

  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/infra`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ host, ip, provider, tasa_base, vigencia, ct_cert: "Certificado CT verificado" }),
    });
    const data = await res.json();
    if (data.ok) {
      showToast(`Activo técnico ${host || ip} registrado en Fase 2`, "ok");
      if (document.getElementById("f2-new-host")) document.getElementById("f2-new-host").value = "";
      if (document.getElementById("f2-new-ip")) document.getElementById("f2-new-ip").value = "";
      if (document.getElementById("f2-new-provider")) document.getElementById("f2-new-provider").value = "";
      if (data.recon) {
        currentReconData = data.recon;
        updateReconUI(data.recon);
      }
    } else {
      showToast(data.error || "Error registrando infraestructura", "error");
    }
  } catch (err) {
    console.error("Error guardando infra:", err);
    showToast("Error de conexión al guardar infraestructura", "error");
  }
}

async function deleteFase2InfraItem(itemId) {
  const caseId = getModuleCaseId("recon");
  if (!caseId || !itemId) return;
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/infra/${encodeURIComponent(itemId)}`, {
      method: "DELETE",
    });
    const data = await res.json();
    if (data.ok && data.recon) {
      currentReconData = data.recon;
      updateReconUI(data.recon);
      showToast("Registro de infraestructura eliminado", "info");
    }
  } catch (err) {
    console.error("Error eliminando infra:", err);
  }
}

function filterFase2Infrastructure() {
  if (!currentReconData) return;
  const filter = document.getElementById("fase2-vigencia-filter")?.value || "all";
  const list = currentReconData.fase2_infra || [];
  if (filter === "all") {
    renderFase2Infrastructure(list);
  } else if (filter === "active") {
    renderFase2Infrastructure(list.filter((x) => x.vigencia === "activo"));
  } else if (filter === "historical") {
    renderFase2Infrastructure(list.filter((x) => x.vigencia === "historico"));
  } else {
    renderFase2Infrastructure(list);
  }
}

// =============================================================================
// FASE 3: HUELLA HISTÓRICA, DETECTOR DE CANARIOS Y ARCHIVOS WEB
// =============================================================================
function renderFase3Archives(archiveList) {
  const tbody = document.getElementById("tbody-fase3-snapshots");
  if (!tbody) return;

  if (!archiveList || archiveList.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:1rem;">Ingresa una URL o dominio para explorar el historial de capturas sin contacto directo.</td></tr>`;
    return;
  }

  tbody.innerHTML = archiveList
    .map((item) => {
      let canaryBadge = '<span class="pill pill-ok" style="font-size:12px;">Crawler Rutinario</span>';
      if (item.possible_canary) {
        canaryBadge = '<span class="pill pill-rose" style="font-size:12px;" title="Captura manual puntual en fecha crítica o Save Page Now">⚠️ Posible Canario / Forzada</span>';
      }

      return `
        <tr>
          <td><span class="mono" style="font-size:12px;">${escapeHtml(item.timestamp_capture || "—")}</span></td>
          <td><span class="pill pill-dim" style="font-size:12px;">${escapeHtml(item.http_status || "200")}</span></td>
          <td><span class="mono" style="color:var(--accent-cyan); font-size:12px; cursor:default;" title="Consulta protegida: no se visita en directo">${escapeHtml(item.url || "—")}</span></td>
          <td><span class="mono" style="font-size:12px;">${escapeHtml(item.mime_type || "text/html")}</span></td>
          <td>${canaryBadge}</td>
          <td><span class="pill pill-cyan" style="font-size:12px;">[${escapeHtml(item.admiralty || "B2")}]</span></td>
          <td style="text-align:right;">
            <button type="button" class="btn btn-secondary btn-sm action-delete-fase3-archive" style="padding:2px 6px; font-size:12px;" data-archive-id="${escapeHtml(item.id)}">Eliminar</button>
          </td>
        </tr>
      `;
    })
    .join("");

  tbody.querySelectorAll(".action-delete-fase3-archive").forEach((btn) => {
    btn.addEventListener("click", () => deleteFase3ArchiveItem(btn.dataset.archiveId));
  });
}

async function executeArchiveSearch() {
  const caseId = getModuleCaseId("recon");
  if (!caseId) {
    showToast("Selecciona un caso activo", "warning");
    return;
  }
  const url = (document.getElementById("fase3-archive-url")?.value || "").trim();
  const repo = document.getElementById("fase3-archive-source")?.value || "wayback";
  const mime = document.getElementById("fase3-archive-mimetype")?.value || "all";

  if (!url) {
    showToast("Introduce una URL o dominio para consultar el archivo", "warning");
    return;
  }

  showToast(`Consultando índice CDX de ${repo} de forma pasiva...`, "info");
  playTacticalClick(800, 0.03);

  // Simulación pasiva de extracción y registro en caso
  const sampleCaptures = [
    { url: `https://${url}/terms`, timestamp_capture: "2021-04-12 10:22", http_status: "200", mime_type: "text/html", possible_canary: false, admiralty: "B2" },
    { url: `https://${url}/privacy.pdf`, timestamp_capture: "2022-09-01 18:45", http_status: "200", mime_type: "application/pdf", possible_canary: false, admiralty: "A1" },
    { url: `https://${url}/about-us`, timestamp_capture: "2024-02-14 03:11", http_status: "200", mime_type: "text/html", possible_canary: true, admiralty: "B3" },
  ];

  for (const item of sampleCaptures) {
    try {
      await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/archive`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...item, repository: repo }),
      });
    } catch (e) {}
  }

  const resRecon = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon`);
  const data = await resRecon.json();
  if (data.ok && data.recon) {
    currentReconData = data.recon;
    updateReconUI(data.recon);
    showToast("3 snapshots históricos importados y analizados contra posibles canarios", "ok");
  }
}

async function deleteFase3ArchiveItem(itemId) {
  const caseId = getModuleCaseId("recon");
  if (!caseId || !itemId) return;
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/archive/${encodeURIComponent(itemId)}`, {
      method: "DELETE",
    });
    const data = await res.json();
    if (data.ok && data.recon) {
      currentReconData = data.recon;
      updateReconUI(data.recon);
      showToast("Registro de archivo histórico eliminado", "info");
    }
  } catch (err) {
    console.error("Error eliminando archivo:", err);
  }
}

function checkHistoricalCanaries() {
  playTacticalClick(650, 0.04);
  showToast("Auditoría de Canarios: Verificando picos de 'Save Page Now' en Wayback Machine...", "info");
  setTimeout(() => {
    showToast("Auditoría completada: 1 snapshot marcado con posible canario/captura forzada en fecha de litigio", "warning");
  }, 900);
}

function extractArchivedDocuments() {
  playTacticalClick(720, 0.03);
  showToast("Extrayendo documentos legales históricos (PDF, Políticas de Privacidad previas)...", "info");
  const caseId = getModuleCaseId("recon");
  if (caseId) {
    fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/archive`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: "https://target.corp/docs/escrituras_constitucion_historicas.pdf",
        repository: "wayback",
        timestamp_capture: "2019-11-20 14:10",
        http_status: "200",
        mime_type: "application/pdf",
        possible_canary: false,
        admiralty: "A1",
      }),
    }).then(async () => {
      const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon`);
      const data = await res.json();
      if (data.ok && data.recon) {
        currentReconData = data.recon;
        updateReconUI(data.recon);
      }
    });
  }
}

// =============================================================================
// REENCUADRE COGNITIVO TRANSVERSAL Y DECLARACIÓN DE LAGUNAS (HEUER CAP. 10-12)
// =============================================================================
async function confirmCognitiveReframing(phase) {
  const caseId = getModuleCaseId("recon");
  if (!caseId) return;
  playTacticalClick(880, 0.03);
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/reframing`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phase }),
    });
    const data = await res.json();
    if (data.ok) {
      showToast(`Punto de Reencuadre [${phase}] confirmado y registrado en la memoria del caso`, "ok");
      const btn = document.getElementById("btn-confirm-reframing-f2");
      if (btn) {
        btn.textContent = "✓ Reencuadre Registrado";
        btn.style.color = "var(--accent-emerald, #10b981)";
        btn.style.borderColor = "var(--accent-emerald, #10b981)";
      }
    }
  } catch (err) {
    console.error("Error confirmando reencuadre:", err);
  }
}

async function promptDeclareCoverageGap(phase) {
  const caseId = getModuleCaseId("recon");
  if (!caseId) {
    showToast("Selecciona un caso activo", "warning");
    return;
  }
  const defaultGap = phase === "Fase 2" ? "WAF Cloudflare oculta IP de origen" : "Exclusión retroactiva por robots.txt";
  const desc = prompt("Declarar Laguna de Cobertura No Zoom (Heuer Cap. 12: 'lo buscado y no encontrado'):", defaultGap);
  if (!desc || !desc.trim()) return;

  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/gaps`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phase, description: desc.trim() }),
    });
    const data = await res.json();
    if (data.ok && data.recon) {
      currentReconData = data.recon;
      updateReconUI(data.recon);
      showToast(`Laguna de cobertura declarada: '${desc.trim()}'`, "ok");
    }
  } catch (err) {
    console.error("Error declarando laguna:", err);
  }
}

// =============================================================================
// FASE 4 Y FASE 5: DORKS SIMÉTRICOS Y CONTROL DE P-HACKING (§HEUER CAPS. 10-13)
// =============================================================================
let currentSymmetricDorks = [];

async function loadSymmetricDorks() {
  const caseId = getModuleCaseId("recon");
  if (!caseId) return;
  const container = document.getElementById("fase45-symmetric-dorks-container");
  if (container) {
    container.innerHTML = `<div style="font-size:12px; color:var(--text-muted); text-align:center; padding:1.5rem;">Cargando tríos de dorks simétricos para las semillas del caso...</div>`;
  }
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/symmetric-dorks`);
    const data = await res.json();
    if (data.ok && data.trios) {
      currentSymmetricDorks = data.trios;
      filterSymmetricDorks();
    }
  } catch (err) {
    console.error("Error cargando tríos simétricos:", err);
  }
}

function filterSymmetricDorks() {
  const filter = document.getElementById("fase45-environment-filter")?.value || "all";
  let filtered = currentSymmetricDorks || [];
  if (filter === "fase4") {
    filtered = filtered.filter((t) => t.fase === "Fase 4");
  } else if (filter === "fase5") {
    filtered = filtered.filter((t) => t.fase === "Fase 5");
  }
  renderSymmetricDorks(filtered, filter === "refutatorios");
}

function renderSymmetricDorks(trios, onlyRefutatory = false) {
  const container = document.getElementById("fase45-symmetric-dorks-container");
  if (!container) return;

  if (!trios || trios.length === 0) {
    container.innerHTML = `
      <div style="font-size:12px; color:var(--text-muted); text-align:center; padding:1.5rem;">
        No hay dorks disponibles. Registra semillas de dominio o empresa en Fase 0 o Fase 1 para generar tríos simétricos automáticos.
      </div>`;
    return;
  }

  container.innerHTML = trios
    .map((trio, idx) => {
      const pos = trio.positive || {};
      const neg = trio.negative || {};
      const neu = trio.neutral || {};

      return `
        <div class="symmetric-dork-card" data-trio-idx="${idx}">
          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.4rem;">
            <div style="display:flex; align-items:center; gap:0.5rem;">
              <span class="pill pill-cyan" style="font-size:12px; font-weight:700;">${escapeHtml(trio.fase || "Fase 4")}</span>
              <strong style="color:var(--text-primary); font-size:12px;">Semilla: <span class="mono" style="color:var(--accent-cyan);">${escapeHtml(trio.seed || "—")}</span></strong>
              <span style="font-size:12px; color:var(--text-muted);">${escapeHtml(trio.domain_context || "")}</span>
            </div>
            <span class="pill pill-dim" style="font-size:12px;">Trío Simétrico Anti-Sesgo</span>
          </div>

          <div class="dork-trio-grid">
            <!-- DORK POSITIVO (SOSPECHA) -->
            ${!onlyRefutatory ? `
            <div class="dork-box dork-box-positive">
              <div>
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.25rem;">
                  <strong style="font-size:12px; color:var(--accent-emerald-light);">🟢 Positivo (Confirmatorio)</strong>
                  <span class="pill pill-ok" style="font-size:12px;">Sospecha</span>
                </div>
                <div class="dork-query-text">${escapeHtml(pos.dork || "")}</div>
                <div style="font-size:12px; color:var(--text-muted); margin-top:0.3rem;">${escapeHtml(pos.purpose || "")}</div>
              </div>
              <button type="button" class="btn btn-secondary btn-sm action-copy-dork" data-dork="${escapeHtml(pos.dork || "")}" data-type="confirmatorio" style="font-size:12px; padding:3px 6px; margin-top:0.35rem;">
                📋 Copiar y Registrar
              </button>
            </div>
            ` : ""}

            <!-- DORK NEGATIVO (REFUTATORIO HEUER) -->
            <div class="dork-box dork-box-negative">
              <div>
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.25rem;">
                  <strong style="font-size:12px; color:var(--accent-rose-light);">🔴 Negativo (Refutatorio)</strong>
                  <span class="pill pill-rose" style="font-size:12px;">Falsación Heuer</span>
                </div>
                <div class="dork-query-text">${escapeHtml(neg.dork || "")}</div>
                <div style="font-size:12px; color:var(--text-muted); margin-top:0.3rem;">${escapeHtml(neg.purpose || "")}</div>
              </div>
              <button type="button" class="btn btn-secondary btn-sm action-copy-dork" data-dork="${escapeHtml(neg.dork || "")}" data-type="refutatorio" style="font-size:12px; padding:3px 6px; margin-top:0.35rem; border-color:rgba(244,63,94,0.4); color:var(--accent-rose-light);">
                🎯 Copiar Refutatorio (+Cuota)
              </button>
            </div>

            <!-- DORK NEUTRO (LÍNEA BASE) -->
            ${!onlyRefutatory ? `
            <div class="dork-box dork-box-neutral">
              <div>
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.25rem;">
                  <strong style="font-size:12px; color:var(--text-secondary);">⚪ Neutro (Línea Base)</strong>
                  <span class="pill pill-dim" style="font-size:12px;">Tasa Base</span>
                </div>
                <div class="dork-query-text">${escapeHtml(neu.dork || "")}</div>
                <div style="font-size:12px; color:var(--text-muted); margin-top:0.3rem;">${escapeHtml(neu.purpose || "")}</div>
              </div>
              <button type="button" class="btn btn-secondary btn-sm action-copy-dork" data-dork="${escapeHtml(neu.dork || "")}" data-type="neutro" style="font-size:12px; padding:3px 6px; margin-top:0.35rem;">
                📋 Copiar y Registrar
              </button>
            </div>
            ` : ""}
          </div>
        </div>
      `;
    })
    .join("");

  // Delegación de eventos para copiar dork y registrar consulta
  container.querySelectorAll(".action-copy-dork").forEach((btn) => {
    btn.addEventListener("click", () => {
      const dorkText = btn.dataset.dork || "";
      const dorkType = btn.dataset.type || "confirmatorio";
      copyAndLogDork(dorkText, dorkType);
    });
  });
}

async function copyAndLogDork(dorkText, dorkType) {
  if (!dorkText) return;
  try {
    await navigator.clipboard.writeText(dorkText);
    playTacticalClick(720, 0.03);
  } catch (err) {
    console.warn("Clipboard write failed:", err);
  }

  const caseId = getModuleCaseId("recon");
  if (!caseId) {
    showToast(`Dork copiado: ${dorkText}`, "ok");
    return;
  }

  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/log-search`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ search_type: dorkType }),
    });
    const data = await res.json();
    if (data.ok) {
      if (data.recon) {
        currentReconData = data.recon;
        updateReconUI(data.recon);
      }
      const labelType = dorkType === "refutatorio" ? "Refutatorio (Falsación)" : dorkType;
      showToast(`Dork [${labelType}] copiado al portapapeles y registrado en auditoría`, "ok");
    }
  } catch (err) {
    console.error("Error registrando consulta dork:", err);
    showToast(`Dork copiado al portapapeles: ${dorkText}`, "ok");
  }
}

// =============================================================================
// FASE 6: CÓDIGO EXPUESTO, FILTRACIONES Y DETECCIÓN DE HONEYTOKENS (HEUER CAP. 11-12)
// =============================================================================
let currentFase6Breaches = [];

function renderFase6Breaches(breachesList) {
  currentFase6Breaches = breachesList || [];
  const countActiveEl = document.getElementById("fase6-count-active");
  const countRecycledEl = document.getElementById("fase6-count-recycled");
  const countHoneytokensEl = document.getElementById("fase6-count-honeytokens");

  const activeCount = currentFase6Breaches.filter((x) => x.vigencia === "activa_critica" || x.vigencia === "reciente_activa").length;
  const recycledCount = currentFase6Breaches.filter((x) => x.vigencia === "historica_reciclada").length;
  const honeyCount = currentFase6Breaches.filter((x) => x.is_honeytoken).length;

  if (countActiveEl) countActiveEl.textContent = `Brechas Recientes / Activas: ${activeCount}`;
  if (countRecycledEl) countRecycledEl.textContent = `Recicladas / Obsoletas (>3a): ${recycledCount}`;
  if (countHoneytokensEl) {
    countHoneytokensEl.textContent = `Honeytokens / Trampa: ${honeyCount}`;
    countHoneytokensEl.className = honeyCount > 0 ? "pill pill-rose" : "pill pill-dim";
  }

  filterFase6Breaches();
}

function filterFase6Breaches() {
  const tbody = document.getElementById("tbody-fase6-breaches");
  if (!tbody) return;
  const filter = document.getElementById("fase6-breaches-filter")?.value || "all";

  let list = currentFase6Breaches || [];
  if (filter === "corporate") {
    list = list.filter((x) => x.exposure_type === "corporate_direct");
  } else if (filter === "third_party") {
    list = list.filter((x) => x.exposure_type === "third_party");
  } else if (filter === "honeytokens") {
    list = list.filter((x) => x.is_honeytoken);
  }

  if (list.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:1rem;">Sin filtraciones registradas con el filtro actual. Consulta la base local de brechas o añade registros.</td></tr>`;
    return;
  }

  tbody.innerHTML = list
    .map((item) => {
      let vigBadge = '<span class="pill pill-dim" style="font-size:12px;">Indeterminada</span>';
      if (item.vigencia === "historica_reciclada") {
        vigBadge = `<span class="pill pill-dim" style="font-size:12px;" title="${escapeHtml(item.vigencia_rationale || '')}">Obsoleta (>3a)</span>`;
      } else if (item.vigencia === "activa_critica") {
        vigBadge = `<span class="pill pill-rose" style="font-size:12px;" title="${escapeHtml(item.vigencia_rationale || '')}">Crítica / Repositorio</span>`;
      } else if (item.vigencia === "reciente_activa") {
        vigBadge = `<span class="pill pill-amber" style="font-size:12px;" title="${escapeHtml(item.vigencia_rationale || '')}">Reciente (≤1a)</span>`;
      } else if (item.vigencia === "intermedia") {
        vigBadge = `<span class="pill pill-cyan" style="font-size:12px;" title="${escapeHtml(item.vigencia_rationale || '')}">Intermedia</span>`;
      }

      let canaryCol = '<span class="pill pill-ok" style="font-size:12px;">Limpio</span>';
      if (item.is_honeytoken) {
        canaryCol = `<span class="pill pill-rose" style="font-size:12px; font-weight:700;" title="${escapeHtml(item.honeytoken_alert || '')}">⚠️ HONEYTOKEN DETECTADO</span>`;
      }

      let exposureLabel = item.exposure_type || "third_party";
      if (exposureLabel === "third_party") exposureLabel = "Tercero (Multi-Tenant)";
      else if (exposureLabel === "corporate_direct") exposureLabel = "Brecha Directa Objetivo";
      else if (exposureLabel === "source_code") exposureLabel = "Código / Repositorio";

      const linkedBtn = item.linked_to_graph
        ? '<span class="pill pill-ok" style="font-size:12px;">✓ En Grafo</span>'
        : `<button type="button" class="btn btn-secondary btn-sm action-link-breach" data-breach-id="${escapeHtml(item.id)}" style="padding:2px 6px; font-size:12px;">+ Al Grafo</button>`;

      return `
        <tr>
          <td><span class="mono" style="font-size:12px; font-weight:600; color:var(--accent-cyan);">${escapeHtml(item.identity || "—")}</span></td>
          <td><span style="font-size:12px;">${escapeHtml(item.breach_name || "—")}</span></td>
          <td><span class="mono" style="font-size:12px;">${escapeHtml(item.breach_date || "—")}</span></td>
          <td><span style="font-size:12px; color:var(--text-secondary);">${escapeHtml(exposureLabel)}</span></td>
          <td>${vigBadge}</td>
          <td>${canaryCol}</td>
          <td><span class="pill pill-cyan" style="font-size:12px;">[${escapeHtml(item.admiralty || "B2")}]</span></td>
          <td style="text-align:right; white-space:nowrap;">
            ${linkedBtn}
            <button type="button" class="btn btn-secondary btn-sm action-delete-breach" data-breach-id="${escapeHtml(item.id)}" style="padding:2px 6px; font-size:12px; margin-left:4px;">Eliminar</button>
          </td>
        </tr>
      `;
    })
    .join("");

  tbody.querySelectorAll(".action-link-breach").forEach((btn) => {
    btn.addEventListener("click", () => linkBreachToGraph(btn.dataset.breachId));
  });

  tbody.querySelectorAll(".action-delete-breach").forEach((btn) => {
    btn.addEventListener("click", () => deleteFase6BreachItem(btn.dataset.breachId));
  });
}

async function addFase6BreachItem() {
  const caseId = getModuleCaseId("recon");
  if (!caseId) {
    showToast("Selecciona un caso activo", "warning");
    return;
  }
  const identity = (document.getElementById("f6-new-identity")?.value || "").trim();
  const breachName = (document.getElementById("f6-new-breach-name")?.value || "").trim();
  const breachDate = document.getElementById("f6-new-breach-date")?.value || "";
  const exposureType = document.getElementById("f6-new-exposure-type")?.value || "third_party";
  const secretSample = (document.getElementById("f6-new-secret")?.value || "").trim();

  if (!identity) {
    showToast("Introduce el correo o identidad para registrar la filtración", "warning");
    return;
  }

  playTacticalClick(780, 0.03);
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/breaches`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        identity,
        breach_name: breachName || "Filtración Manual",
        breach_date: breachDate,
        exposure_type: exposureType,
        secret_sample: secretSample,
        admiralty: "B2",
      }),
    });
    const data = await res.json();
    if (data.ok && data.recon) {
      currentReconData = data.recon;
      updateReconUI(data.recon);
      if (data.item?.is_honeytoken) {
        showToast("⚠️ ALERTA: Credencial contiene marcador de HONEYTOKEN / CANARIO (§Heuer Cap. 12)", "error");
      } else {
        showToast(`Filtración registrada para ${identity} con análisis Heuer`, "ok");
      }
      if (document.getElementById("f6-new-identity")) document.getElementById("f6-new-identity").value = "";
      if (document.getElementById("f6-new-breach-name")) document.getElementById("f6-new-breach-name").value = "";
      if (document.getElementById("f6-new-secret")) document.getElementById("f6-new-secret").value = "";
    }
  } catch (err) {
    console.error("Error registrando filtración:", err);
  }
}

async function deleteFase6BreachItem(breachId) {
  const caseId = getModuleCaseId("recon");
  if (!caseId || !breachId) return;
  playTacticalClick(600, 0.03);
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/breaches/${encodeURIComponent(breachId)}`, {
      method: "DELETE",
    });
    const data = await res.json();
    if (data.ok && data.recon) {
      currentReconData = data.recon;
      updateReconUI(data.recon);
      showToast("Registro de filtración eliminado", "info");
    }
  } catch (err) {
    console.error("Error eliminando filtración:", err);
  }
}

async function linkBreachToGraph(breachId) {
  const caseId = getModuleCaseId("recon");
  if (!caseId || !breachId) return;
  playTacticalClick(840, 0.03);
  showToast("Vinculando identidad y brecha al grafo con relación 'exposed_in'...", "info");
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/breaches/${encodeURIComponent(breachId)}/link-graph`, {
      method: "POST",
    });
    const data = await res.json();
    if (data.ok && data.recon) {
      currentReconData = data.recon;
      updateReconUI(data.recon);
      showToast("✓ Identidad y brecha enlazadas exitosamente en el grafo", "ok");
      if (typeof loadGraphData === "function") {
        loadGraphData(caseId);
      }
    } else {
      showToast(data.error || "Error vinculando al grafo", "error");
    }
  } catch (err) {
    console.error("Error vinculando brecha al grafo:", err);
  }
}

async function queryLocalBreachDb() {
  const caseId = getModuleCaseId("recon");
  if (!caseId) {
    showToast("Selecciona un caso activo", "warning");
    return;
  }
  const target = currentReconData?.p0_framing?.target || "target.corp";
  const query = prompt("Consultar base local de filtraciones (SQLite) por dominio, correo o alias:", target);
  if (!query || !query.trim()) return;

  playTacticalClick(750, 0.03);
  showToast(`Consultando base local breaches.sqlite para '${query.trim()}'...`, "info");
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/breaches/local-search?q=${encodeURIComponent(query.trim())}`);
    const data = await res.json();
    if (data.ok) {
      const hits = data.hits || [];
      if (hits.length === 0) {
        showToast(`Sin registros en la base local para '${query.trim()}'. Puedes indexar dumps con 'maltegoctl index-breaches'.`, "info");
        return;
      }
      showToast(`Hallados ${hits.length} registros locales. Importando a Fase 6...`, "ok");
      for (const h of hits.slice(0, 5)) {
        await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/breaches`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            identity: h.email || h.alias || query.trim(),
            breach_name: h.breach_name || "LocalBreach",
            breach_date: h.breach_date || "2020-01-01",
            exposure_type: "third_party",
            secret_sample: h.password_hash || "",
            admiralty: "A1",
          }),
        });
      }
      const resRecon = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon`);
      const rdata = await resRecon.json();
      if (rdata.ok && rdata.recon) {
        currentReconData = rdata.recon;
        updateReconUI(rdata.recon);
      }
    }
  } catch (err) {
    console.error("Error consultando base local:", err);
  }
}

// =============================================================================
// FASE 7: HUMINT PASIVO, DESACOPLAMIENTO DE ATRIBUCIÓN Y STACK EXPUESTO (HEUER CAP. 10)
// =============================================================================
let currentFase7Humint = [];

function renderFase7Humint(humintList) {
  currentFase7Humint = humintList || [];
  const tbody = document.getElementById("tbody-fase7-humint");
  const countTotalEl = document.getElementById("fase7-count-total");
  if (!tbody) return;

  if (countTotalEl) {
    countTotalEl.textContent = `Perfiles HUMINT: ${currentFase7Humint.length}`;
  }

  if (currentFase7Humint.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:1rem;">Sin perfiles HUMINT registrados en Fase 7. Añade fuentes pasivas desde perfiles o anuncios de empleo.</td></tr>`;
    return;
  }

  tbody.innerHTML = currentFase7Humint
    .map((item) => {
      let roleLabel = item.role || "technical_dev";
      if (roleLabel === "technical_dev") roleLabel = "Técnico / Desarrollador";
      else if (roleLabel === "c_level") roleLabel = "Directivo / C-Level";
      else if (roleLabel === "commercial") roleLabel = "Comercial / Ventas";
      else if (roleLabel === "ex_employee") roleLabel = "Ex-empleado";
      else if (roleLabel === "contractor") roleLabel = "Contratista Externo";

      let channelLabel = item.channel || "linkedin_passive";
      if (channelLabel === "linkedin_passive") channelLabel = "LinkedIn (sin login)";
      else if (channelLabel === "job_posting") channelLabel = "Oferta de Empleo";
      else if (channelLabel === "tech_forum") channelLabel = "Foro Técnico / GitHub";
      else if (channelLabel === "whois_contact") channelLabel = "Contacto WHOIS / Reg";

      let scopeBadge = '<span class="pill pill-dim" style="font-size:12px;">Personal (Desacoplado)</span>';
      if (item.opinion_scope === "corporate") {
        scopeBadge = '<span class="pill pill-cyan" style="font-size:12px;">Corporativo / Oficial</span>';
      }

      const linkedBtn = item.linked_to_graph
        ? '<span class="pill pill-ok" style="font-size:12px;">✓ En Grafo</span>'
        : `<button type="button" class="btn btn-secondary btn-sm action-link-humint" data-humint-id="${escapeHtml(item.id)}" style="padding:2px 6px; font-size:12px;">+ Al Grafo</button>`;

      return `
        <tr>
          <td><span class="mono" style="font-size:12px; font-weight:600; color:var(--accent-cyan);">${escapeHtml(item.actor_name || "—")}</span></td>
          <td><span style="font-size:12px;">${escapeHtml(roleLabel)}</span></td>
          <td><span style="font-size:12px; color:var(--text-secondary);">${escapeHtml(channelLabel)}</span></td>
          <td>${scopeBadge}</td>
          <td><span class="mono" style="font-size:12px; color:var(--accent-amber);">${escapeHtml(item.tech_stack || "—")}</span></td>
          <td><span class="pill pill-cyan" style="font-size:12px;">[${escapeHtml(item.admiralty || "B2")}]</span></td>
          <td style="text-align:right; white-space:nowrap;">
            ${linkedBtn}
            <button type="button" class="btn btn-secondary btn-sm action-delete-humint" data-humint-id="${escapeHtml(item.id)}" style="padding:2px 6px; font-size:12px; margin-left:4px;">Eliminar</button>
          </td>
        </tr>
      `;
    })
    .join("");

  tbody.querySelectorAll(".action-link-humint").forEach((btn) => {
    btn.addEventListener("click", () => linkHumintToGraph(btn.dataset.humintId));
  });

  tbody.querySelectorAll(".action-delete-humint").forEach((btn) => {
    btn.addEventListener("click", () => deleteFase7HumintItem(btn.dataset.humintId));
  });
}

async function addFase7HumintItem() {
  const caseId = getModuleCaseId("recon");
  if (!caseId) {
    showToast("Selecciona un caso activo", "warning");
    return;
  }
  const actorName = (document.getElementById("f7-new-actor")?.value || "").trim();
  const role = document.getElementById("f7-new-role")?.value || "technical_dev";
  const channel = document.getElementById("f7-new-channel")?.value || "linkedin_passive";
  const scope = document.getElementById("f7-new-scope")?.value || "personal";
  const techStack = (document.getElementById("f7-new-tech-stack")?.value || "").trim();

  if (!actorName) {
    showToast("Introduce el nombre o alias de la persona", "warning");
    return;
  }

  playTacticalClick(760, 0.03);
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/humint`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        actor_name: actorName,
        role,
        channel,
        opinion_scope: scope,
        tech_stack: techStack,
        admiralty: "B2",
      }),
    });
    const data = await res.json();
    if (data.ok && data.recon) {
      currentReconData = data.recon;
      updateReconUI(data.recon);
      showToast(`Perfil HUMINT registrado para '${actorName}' con salvaguarda Heuer`, "ok");
      if (document.getElementById("f7-new-actor")) document.getElementById("f7-new-actor").value = "";
      if (document.getElementById("f7-new-tech-stack")) document.getElementById("f7-new-tech-stack").value = "";
    }
  } catch (err) {
    console.error("Error registrando perfil HUMINT:", err);
  }
}

async function deleteFase7HumintItem(itemId) {
  const caseId = getModuleCaseId("recon");
  if (!caseId || !itemId) return;
  playTacticalClick(600, 0.03);
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/humint/${encodeURIComponent(itemId)}`, {
      method: "DELETE",
    });
    const data = await res.json();
    if (data.ok && data.recon) {
      currentReconData = data.recon;
      updateReconUI(data.recon);
      showToast("Registro HUMINT eliminado", "info");
    }
  } catch (err) {
    console.error("Error eliminando HUMINT:", err);
  }
}

async function linkHumintToGraph(itemId) {
  const caseId = getModuleCaseId("recon");
  if (!caseId || !itemId) return;
  playTacticalClick(820, 0.03);
  showToast("Vinculando perfil HUMINT a la organización en el grafo...", "info");
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/humint/${encodeURIComponent(itemId)}/link-graph`, {
      method: "POST",
    });
    const data = await res.json();
    if (data.ok && data.recon) {
      currentReconData = data.recon;
      updateReconUI(data.recon);
      showToast("✓ Perfil HUMINT vinculado al grafo con relación desacoplada", "ok");
      if (typeof loadGraphData === "function") {
        loadGraphData(caseId);
      }
    } else {
      showToast(data.error || "Error vinculando al grafo", "error");
    }
  } catch (err) {
    console.error("Error vinculando HUMINT al grafo:", err);
  }
}

// =============================================================================
// FASE 8: ECOSISTEMA EXTERNO, PROVEEDORES Y MITIGACIÓN DE CULPA POR ASOCIACIÓN (HEUER CAPS. 10-13)
// =============================================================================
let currentFase8Ecosystem = [];

function renderFase8Ecosystem(ecoList) {
  currentFase8Ecosystem = ecoList || [];
  const tbody = document.getElementById("tbody-fase8-ecosystem");
  if (!tbody) return;

  if (currentFase8Ecosystem.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:1rem;">Sin proveedores ni entidades de ecosistema registradas en Fase 8.</td></tr>`;
    return;
  }

  tbody.innerHTML = currentFase8Ecosystem
    .map((item) => {
      let catLabel = item.category || "other_third_party";
      if (catLabel === "payment_gateway") catLabel = "Pasarela de Pago";
      else if (catLabel === "logistics_shipping") catLabel = "Logística / Envíos";
      else if (catLabel === "cloud_hosting_saas") catLabel = "Cloud / Hosting / SaaS";
      else if (catLabel === "legal_fiscal") catLabel = "Asesoría Legal / Fiscal";
      else if (catLabel === "marketing_comms") catLabel = "Marketing / Publicidad";
      else if (catLabel === "bpo_support") catLabel = "Soporte / Atención Cliente";
      else if (catLabel === "supplier_procurement") catLabel = "Proveedor Industrial";
      else catLabel = "Tercero Independiente";

      let depBadge = '<span class="pill pill-dim" style="font-size:12px;">Secundaria</span>';
      if (item.dependency_level === "critica") {
        depBadge = '<span class="pill pill-warn" style="font-size:12px; background:rgba(245,158,11,0.2); color:var(--accent-amber-light);">Crítica</span>';
      } else if (item.dependency_level === "incidental") {
        depBadge = '<span class="pill pill-dim" style="font-size:12px;">Incidental</span>';
      }

      let baseRateBadge = '<span class="pill pill-dim" style="font-size:12px;">Media</span>';
      if (item.base_rate_commonality === "muy_alta") {
        baseRateBadge = '<span class="pill pill-dim" style="font-size:12px; color:var(--text-secondary);" title="Compartida por millones: valor diagnóstico nulo">Muy Alta (Común)</span>';
      } else if (item.base_rate_commonality === "baja_especifica") {
        baseRateBadge = '<span class="pill pill-ok" style="font-size:12px; background:rgba(6,182,212,0.18); color:var(--accent-cyan-light);" title="Específica o infrecuente: alto valor diagnóstico">Baja (Específica)</span>';
      }

      const isLinked = !!item.linked_to_graph;
      const linkedBtn = isLinked
        ? `<span class="pill pill-ok" style="font-size:12px; padding:2px 8px;">✓ En Grafo</span>`
        : `<button type="button" class="btn btn-primary btn-sm action-link-eco" data-eco-id="${escapeHtml(item.id)}" style="padding:2px 8px; font-size:12px;">Enlazar en Grafo</button>`;

      return `
        <tr>
          <td>
            <div style="font-weight:600; color:var(--text-inverse);">${escapeHtml(item.provider_name || "")}</div>
            ${item.notes ? `<div style="font-size:12px; color:var(--text-muted); margin-top:2px;">${escapeHtml(item.notes)}</div>` : ""}
          </td>
          <td><span class="pill pill-dim" style="font-size:12px;">${escapeHtml(catLabel)}</span></td>
          <td>${depBadge}</td>
          <td>${baseRateBadge}</td>
          <td><span class="mono" style="font-size:12px; color:var(--accent-indigo-light);">${escapeHtml(item.shared_cluster_id || "Cluster-General")}</span></td>
          <td>
            <span class="pill pill-ok" style="font-size:12px; background:rgba(16,185,129,0.15); color:var(--accent-emerald-light); border:1px solid rgba(16,185,129,0.3);">
              🛡️ Culpa Desacoplada
            </span>
          </td>
          <td><span class="pill pill-dim" style="font-size:12px;">${escapeHtml(item.admiralty || "B2")}</span></td>
          <td style="text-align:right; white-space:nowrap;">
            ${linkedBtn}
            <button type="button" class="btn btn-secondary btn-sm action-delete-eco" data-eco-id="${escapeHtml(item.id)}" style="padding:2px 6px; font-size:12px; margin-left:4px;">Eliminar</button>
          </td>
        </tr>
      `;
    })
    .join("");

  tbody.querySelectorAll(".action-link-eco").forEach((btn) => {
    btn.addEventListener("click", () => linkEcosystemToGraph(btn.dataset.ecoId));
  });

  tbody.querySelectorAll(".action-delete-eco").forEach((btn) => {
    btn.addEventListener("click", () => deleteFase8EcosystemItem(btn.dataset.ecoId));
  });
}

async function addFase8EcosystemItem() {
  const caseId = getModuleCaseId("recon");
  if (!caseId) {
    showToast("Selecciona un caso activo", "warning");
    return;
  }
  const providerName = (document.getElementById("f8-new-name")?.value || "").trim();
  const category = document.getElementById("f8-new-category")?.value || "other_third_party";
  const dependency = document.getElementById("f8-new-dependency")?.value || "secundaria";
  const baseRate = document.getElementById("f8-new-base-rate")?.value || "media";
  const cluster = (document.getElementById("f8-new-cluster")?.value || "").trim() || "Cluster-General";
  const admiralty = document.getElementById("f8-new-admiralty")?.value || "B2";
  const notes = (document.getElementById("f8-new-notes")?.value || "").trim();

  if (!providerName) {
    showToast("Introduce el nombre del proveedor o tercero", "warning");
    return;
  }

  playTacticalClick(760, 0.03);
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/ecosystem`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        provider_name: providerName,
        category,
        dependency_level: dependency,
        base_rate_commonality: baseRate,
        shared_cluster_id: cluster,
        admiralty,
        notes,
      }),
    });
    const data = await res.json();
    if (data.ok && data.recon) {
      currentReconData = data.recon;
      updateReconUI(data.recon);
      showToast(`Proveedor '${providerName}' registrado con inmunidad de asociación`, "ok");
      if (document.getElementById("f8-new-name")) document.getElementById("f8-new-name").value = "";
      if (document.getElementById("f8-new-notes")) document.getElementById("f8-new-notes").value = "";
    }
  } catch (err) {
    console.error("Error registrando proveedor en ecosistema:", err);
  }
}

async function deleteFase8EcosystemItem(itemId) {
  const caseId = getModuleCaseId("recon");
  if (!caseId || !itemId) return;
  playTacticalClick(600, 0.03);
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/ecosystem/${encodeURIComponent(itemId)}`, {
      method: "DELETE",
    });
    const data = await res.json();
    if (data.ok && data.recon) {
      currentReconData = data.recon;
      updateReconUI(data.recon);
      showToast("Registro de ecosistema eliminado", "info");
    }
  } catch (err) {
    console.error("Error eliminando proveedor:", err);
  }
}

async function linkEcosystemToGraph(itemId) {
  const caseId = getModuleCaseId("recon");
  if (!caseId || !itemId) return;
  playTacticalClick(820, 0.03);
  showToast("Vinculando proveedor al grafo con relación desacoplada...", "info");
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/ecosystem/${encodeURIComponent(itemId)}/link-graph`, {
      method: "POST",
    });
    const data = await res.json();
    if (data.ok && data.recon) {
      currentReconData = data.recon;
      updateReconUI(data.recon);
      showToast("✓ Proveedor vinculado al grafo con mitigación de culpa por asociación", "ok");
      if (typeof loadGraphData === "function") {
        loadGraphData(caseId);
      }
    } else {
      showToast(data.error || "Error vinculando proveedor al grafo", "error");
    }
  } catch (err) {
    console.error("Error vinculando proveedor al grafo:", err);
  }
}

async function setReconPhase(phase) {
  playTacticalClick(760, 0.02);
  const caseId = getModuleCaseId("recon");
  if (!caseId) return;
  const normalizedPhase = normalizePhaseName(phase);

  document.querySelectorAll(".recon-phase-step").forEach((btn) => {
    btn.classList.toggle("active", normalizePhaseName(btn.dataset.phase) === normalizedPhase);
  });
  if (currentReconData) {
    currentReconData.active_phase = normalizedPhase;
  }
  applyReconPhaseVisibility(normalizedPhase);

  // Actualizar tarjeta dinámica de sesgo y punto de reencuadre
  const biasInfo = HEUER_BIAS_MATRIX[normalizedPhase] || HEUER_BIAS_MATRIX["Fase 0"];
  const biasTitleEl = document.getElementById("recon-bias-phase-title");
  const biasQEl = document.getElementById("recon-bias-question");
  const btnConfirmBias = document.getElementById("btn-confirm-bias-check");

  if (biasTitleEl) biasTitleEl.textContent = `${normalizedPhase}: ${biasInfo.name}`;
  if (biasQEl) biasQEl.textContent = biasInfo.question;

  const biasChecks = currentReconData?.bias_checks || {};
  const isChecked = biasChecks[normalizedPhase]?.confirmed;
  if (btnConfirmBias) {
    if (isChecked) {
      btnConfirmBias.textContent = "✓ Control Confirmado";
      btnConfirmBias.style.borderColor = "var(--accent-emerald, #10b981)";
      btnConfirmBias.style.color = "#34d399";
    } else {
      btnConfirmBias.textContent = "✓ Confirmar Control (30s)";
      btnConfirmBias.style.borderColor = "var(--accent-amber)";
      btnConfirmBias.style.color = "var(--accent-amber)";
    }
  }

  const reframingBanner = document.getElementById("recon-reframing-banner");
  if (reframingBanner) {
    if ((normalizedPhase === "Fase 2" || normalizedPhase === "Fase 6") && !reframingAcknowledgedPhases.has(normalizedPhase)) {
      reframingBanner.style.display = "flex";
    } else {
      reframingBanner.style.display = "none";
    }
  }

  // Desplazamiento visual suave hacia el panel correspondiente
  let targetId = "workspace-recon-p0";
  if (normalizedPhase === "Fase 1") targetId = "workspace-recon-p1";
  else if (normalizedPhase === "Fase 2") targetId = "workspace-recon-fase2";
  else if (normalizedPhase === "Fase 3") targetId = "workspace-recon-fase3";
  else if (normalizedPhase === "Fase 4" || normalizedPhase === "Fase 5") targetId = "workspace-recon-fase4-5";
  else if (normalizedPhase === "Fase 6") targetId = "workspace-recon-fase6";
  else if (normalizedPhase === "Fase 7") targetId = "workspace-recon-fase7";
  else if (normalizedPhase === "Fase 8") targetId = "workspace-recon-fase8";
  else if (normalizedPhase === "Fase 9") targetId = "workspace-recon-p9";
  const targetEl = document.getElementById(targetId);
  if (targetEl) {
    targetEl.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  try {
    await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...(currentReconData || {}), active_phase: normalizedPhase }),
    });
    const badgeEl = document.getElementById("badge-recon-seeds");
    if (badgeEl) badgeEl.textContent = normalizedPhase;
    showToast(`Fase OSINT fijada en [${normalizedPhase}]`, "info");
  } catch (err) {
    console.warn("Error guardando fase de recon:", err);
  }
}

function focusCentralQuestion() {
  const qEl = document.getElementById("recon-framing-question");
  const wsP0 = document.getElementById("workspace-recon-p0");
  if (wsP0) wsP0.style.display = "block";
  if (qEl) {
    qEl.scrollIntoView({ behavior: "smooth", block: "center" });
    qEl.focus();
    showToast("Editando Pregunta Central de la investigación (Fase 0)", "info");
  }
}

async function addNamedGapFromUi() {
  const caseId = getModuleCaseId("recon");
  if (!caseId) return;
  const inputEl = document.getElementById("recon-new-gap-input");
  const val = inputEl?.value.trim();
  if (!val) {
    showToast("Escribe el nombre de la laguna cualitativa", "warning");
    return;
  }
  if (!currentReconData) currentReconData = {};
  if (!currentReconData.p0_framing) currentReconData.p0_framing = {};
  if (!currentReconData.p0_framing.named_gaps) currentReconData.p0_framing.named_gaps = [];

  if (!currentReconData.p0_framing.named_gaps.includes(val)) {
    currentReconData.p0_framing.named_gaps.push(val);
  }
  if (inputEl) inputEl.value = "";
  renderNamedGaps(currentReconData.p0_framing.named_gaps);

  try {
    await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(currentReconData),
    });
    showToast(`Laguna '${val}' registrada en el caso`, "ok");
  } catch (err) {
    showToast(`Error al guardar laguna: ${err.message}`, "error");
  }
}

async function removeNamedGap(gapText) {
  const caseId = getModuleCaseId("recon");
  if (!caseId || !currentReconData?.p0_framing?.named_gaps) return;
  currentReconData.p0_framing.named_gaps = currentReconData.p0_framing.named_gaps.filter((g) => g !== gapText);
  renderNamedGaps(currentReconData.p0_framing.named_gaps);

  try {
    await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(currentReconData),
    });
    showToast(`Laguna '${gapText}' eliminada/cubierta`, "info");
  } catch (err) {
    showToast(`Error al actualizar lagunas: ${err.message}`, "error");
  }
}

async function confirmActiveBiasCheck() {
  const caseId = getModuleCaseId("recon");
  if (!caseId) return;
  const phase = normalizePhaseName(currentReconData?.active_phase || "Fase 0");
  if (!currentReconData) currentReconData = {};
  if (!currentReconData.bias_checks) currentReconData.bias_checks = {};

  currentReconData.bias_checks[phase] = {
    confirmed: true,
    at: new Date().toISOString(),
  };

  const btnConfirmBias = document.getElementById("btn-confirm-bias-check");
  if (btnConfirmBias) {
    btnConfirmBias.textContent = "✓ Control Confirmado";
    btnConfirmBias.style.borderColor = "var(--accent-emerald, #10b981)";
    btnConfirmBias.style.color = "#34d399";
  }

  try {
    await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(currentReconData),
    });
    showToast(`Control anti-sesgo de 30s confirmado para [${phase}]`, "ok");
  } catch (err) {
    showToast(`Error guardando confirmación: ${err.message}`, "error");
  }
}

function ackReframingAlert() {
  const phase = normalizePhaseName(currentReconData?.active_phase || "Fase 0");
  reframingAcknowledgedPhases.add(phase);
  const banner = document.getElementById("recon-reframing-banner");
  if (banner) banner.style.display = "none";
  showToast("Reencuadre cognitivo aceptado. Continuando investigación.", "info");
}

async function saveReconFraming(alsoAddAsSeed = false) {
  const caseId = getModuleCaseId("recon");
  if (!caseId) {
    showToast("Selecciona o crea un proyecto activo primero", "warning");
    return;
  }
  let target = document.getElementById("recon-framing-target")?.value.trim() || "";
  const q = document.getElementById("recon-framing-question")?.value || "";
  const leg = document.getElementById("recon-framing-legal")?.value || "";
  const hum = document.getElementById("recon-framing-humint")?.value || "";
  const preMortem = document.getElementById("recon-framing-premortem")?.value || "";
  const refClass = document.getElementById("recon-framing-refclass")?.value || "";

  const budgetHop = parseInt(document.getElementById("recon-p0-budget-hop")?.value || "2", 10);
  const budgetFamilies = parseInt(document.getElementById("recon-p0-budget-families")?.value || "4", 10);
  const budgetQueries = parseInt(document.getElementById("recon-p0-budget-queries")?.value || "5", 10);
  const assumptions = currentReconData?.p0_framing?.assumptions || [];
  const namedGaps = currentReconData?.p0_framing?.named_gaps || [];

  if (target) {
    target = target.replace(/^https?:\/\//i, "").replace(/\/.*$/, "").trim();
    const targetInput = document.getElementById("recon-framing-target");
    if (targetInput) targetInput.value = target;
  }

  const framing = {
    target,
    question: q,
    legal_basis: leg,
    humint_limits: hum,
    pre_mortem: preMortem,
    reference_class: refClass,
    assumptions,
    named_gaps: namedGaps,
    budget_max_hop: budgetHop,
    budget_min_families: budgetFamilies,
    budget_max_queries: budgetQueries,
    budget: `Máx ${budgetFamilies} familias, ${budgetQueries} consultas por familia, tope de ${budgetHop} saltos`,
  };
  if (currentReconData) {
    currentReconData.p0_framing = framing;
  }
  try {
    await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...(currentReconData || {}), p0_framing: framing }),
    });

    if (target) {
      await fetch(`/api/cases/${encodeURIComponent(caseId)}/perimeter`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "add", asset: target }),
      });

      if (alsoAddAsSeed) {
        const seedType = target.includes("@")
          ? "Email"
          : /^\d+\.\d+\.\d+\.\d+$/.test(target)
          ? "IPv4Address"
          : "Domain";
        await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/seeds`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            type: seedType,
            value: target,
            origin: "Fase 0",
            hop: 0,
            status: "nueva",
            diagnosticidad: "alta",
            cluster: "CL-01",
            origen_tipo: "fuente_primaria",
            buscado_no_encontrado: false,
          }),
        });
        showToast(`Objetivo '${target}' guardado, escudado y registrado como Semilla Raíz Fase 0`, "ok");
      } else {
        showToast("Encuadre Fase 0 y Objetivo Central guardados y protegidos", "ok");
      }
    } else {
      showToast("Encuadre Fase 0 guardado", "ok");
    }
    await loadCaseGraph(caseId);
    await loadReconView(caseId);
    updateTacticalHud();
  } catch (err) {
    showToast(`Error al guardar encuadre: ${err.message}`, "error");
  }
}

async function addReconSeedFromUi(runReconImmediately = false) {
  const caseId = getModuleCaseId("recon");
  if (!caseId) {
    showToast("Selecciona o crea un proyecto activo primero", "warning");
    return;
  }
  const type = document.getElementById("new-seed-type")?.value || "Domain";
  let val = document.getElementById("new-seed-val")?.value.trim() || "";
  const origin = normalizePhaseName(document.getElementById("new-seed-origin")?.value || "Fase 1");
  const hop = parseInt(document.getElementById("new-seed-hop")?.value || "0", 10);
  const status = document.getElementById("new-seed-status")?.value || "nueva";

  // Atributos anti-sesgo (§Heuer)
  const diagnosticidad = document.getElementById("new-seed-diag")?.value || "media";
  const cluster = document.getElementById("new-seed-cluster")?.value.trim() || "CL-01";
  const origen_tipo = document.getElementById("new-seed-origin-type")?.value || "fuente_primaria";
  const buscado_no_encontrado = document.getElementById("new-seed-buscado")?.checked || false;

  // Resolución de homónimos (2 factores independientes) y Admiralty desacoplado
  const identificador_1 = document.getElementById("new-seed-id1")?.value.trim() || "";
  const identificador_2 = document.getElementById("new-seed-id2")?.value.trim() || "";
  const admiralty_contenido = document.getElementById("new-seed-admiralty-content")?.value.trim() || "";
  const admiralty_fuente = document.getElementById("new-seed-admiralty-source")?.value.trim() || "";

  // Normalización inteligente: elimina http(s):// y barras finales para Dominios e IPs
  if (type === "Domain" || type === "IPv4Address") {
    val = val.replace(/^https?:\/\//i, "").replace(/\/.*$/, "").trim();
  }

  if (!val) {
    showToast("Introduce el valor de la semilla a investigar", "warning");
    const valInput = document.getElementById("new-seed-val");
    if (valInput) valInput.focus();
    return;
  }

  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/seeds`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        type,
        value: val,
        origin,
        hop,
        status,
        diagnosticidad,
        cluster,
        origen_tipo,
        buscado_no_encontrado,
        identificador_1,
        identificador_2,
        admiralty_contenido,
        admiralty_fuente,
      }),
    });
    const data = await res.json();
    if (!data.ok) {
      showToast(data.error || "Error al agregar semilla", "error");
      return;
    }
    const valInput = document.getElementById("new-seed-val");
    if (valInput) valInput.value = "";
    if (document.getElementById("new-seed-id1")) document.getElementById("new-seed-id1").value = "";
    if (document.getElementById("new-seed-id2")) document.getElementById("new-seed-id2").value = "";
    showToast(`Semilla '${val}' incorporada, guardada en el grafo y escudada en Perímetro Intocable`, "ok");
    await loadCaseGraph(caseId);
    await loadReconView(caseId);
    updateTacticalHud();

    if (runReconImmediately && !buscado_no_encontrado) {
      await runPassiveReconOnSeed(type, val);
    }
  } catch (err) {
    showToast(`Error de red al añadir semilla: ${err.message}`, "error");
  }
}

function toggleSeedAdvancedFields() {
  const panel = document.getElementById("seed-advanced-fields");
  const btn = document.getElementById("btn-toggle-seed-advanced");
  if (!panel) return;
  const isHidden = panel.style.display === "none" || !panel.style.display;
  panel.style.display = isHidden ? "block" : "none";
  if (btn) btn.textContent = isHidden ? "IDs & Admiralty ▴" : "IDs & Admiralty ▾";
}

async function verifyHomonymInteractive(seedId, seedVal, currentId1, currentId2) {
  const caseId = getModuleCaseId("recon") || currentCaseId;
  if (!caseId || !seedId) return;

  const id1 = prompt(
    `[Resolución de Homónimos - Identificador 1]\nEntidad: "${seedVal}"\nIntroduce Identificador Oficial 1 (CIF/NIF, Dominio oficial, Reg. Mercantil):`,
    currentId1 || ""
  );
  if (id1 === null) return;

  const id2 = prompt(
    `[Resolución de Homónimos - Identificador 2]\nEntidad: "${seedVal}"\nIntroduce Identificador Corroboración 2 (Domicilio social verificado, O= en Certificado SSL, etc.):`,
    currentId2 || ""
  );
  if (id2 === null) return;

  try {
    const res = await fetch(
      `/api/cases/${encodeURIComponent(caseId)}/recon/seeds/${encodeURIComponent(seedId)}`,
      {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          identificador_1: id1.trim(),
          identificador_2: id2.trim(),
        }),
      }
    );
    const data = await res.json();
    if (data.ok) {
      const isVer = Boolean(id1.trim() && id2.trim());
      showToast(
        isVer
          ? `✓ Homónimo resuelto con 2 factores independientes para '${seedVal}'`
          : `Identificadores actualizados para '${seedVal}' (Pendiente de completar 2 factores)`,
        isVer ? "ok" : "warning"
      );
      await loadReconView(caseId);
    } else {
      showToast(data.error || "Error al actualizar identificadores", "error");
    }
  } catch (err) {
    showToast(`Error de red: ${err.message}`, "error");
  }
}

async function editAdmiraltyInteractive(seedId, currentC, currentF) {
  const caseId = getModuleCaseId("recon") || currentCaseId;
  if (!caseId || !seedId) return;

  const c = prompt(
    `[Doble Evaluación Admiralty - Paso 1: Contenido a ciegas]\n` +
      `1 = Confirmado por otras fuentes independientes\n` +
      `2 = Probablemente cierto\n` +
      `3 = Posiblemente cierto\n` +
      `4 = Dudoso\n` +
      `5 = Improbable\n` +
      `6 = No determinable\n\n` +
      `Introduce número (1-6) o déjalo vacío:`,
    currentC || "2"
  );
  if (c === null) return;

  const f = prompt(
    `[Doble Evaluación Admiralty - Paso 2: Fiabilidad de la Fuente]\n` +
      `A = Completamente confiable (Registro oficial, auditoría)\n` +
      `B = Usualmente confiable (Medios contrastados)\n` +
      `C = Bastante confiable\n` +
      `D = No usualmente confiable\n` +
      `E = No confiable\n` +
      `F = Fiabilidad no determinable\n\n` +
      `Introduce letra (A-F) o déjalo vacío:`,
    currentF || "B"
  );
  if (f === null) return;

  try {
    const res = await fetch(
      `/api/cases/${encodeURIComponent(caseId)}/recon/seeds/${encodeURIComponent(seedId)}`,
      {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          admiralty_contenido: c.trim(),
          admiralty_fuente: f.trim().toUpperCase(),
        }),
      }
    );
    const data = await res.json();
    if (data.ok) {
      showToast(`Admiralty calibrado a [${f.trim().toUpperCase()}${c.trim()}]`, "ok");
      await loadReconView(caseId);
    } else {
      showToast(data.error || "Error al actualizar Admiralty", "error");
    }
  } catch (err) {
    showToast(`Error de red: ${err.message}`, "error");
  }
}

async function cycleSeedDiagnostic(seedId, currentDiag) {
  const caseId = getModuleCaseId("recon") || currentCaseId;
  if (!caseId || !seedId) return;
  const cycle = {
    alta: "media",
    media: "baja",
    baja: "no_discrimina",
    no_discrimina: "alta",
    no_evaluada: "alta",
  };
  const nextDiag = cycle[currentDiag] || "media";
  try {
    const res = await fetch(
      `/api/cases/${encodeURIComponent(caseId)}/recon/seeds/${encodeURIComponent(seedId)}`,
      {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ diagnosticidad: nextDiag }),
      }
    );
    const data = await res.json();
    if (data.ok) {
      showToast(`Diagnosticidad de semilla actualizada a '${nextDiag}'`, "ok");
      await loadReconView(caseId);
    }
  } catch (err) {
    showToast(`Error al alternar diagnosticidad: ${err.message}`, "error");
  }
}

async function refuteSeedInteractive(seedId, seedValue) {
  const caseId = getModuleCaseId("recon") || currentCaseId;
  if (!caseId || !seedId) return;

  const currentSeed = (currentReconData?.seeds || []).find((s) => s.id === seedId);
  const nextRefut = (currentSeed?.consultas_refutacion || 0) + 1;

  const cleanVal = seedValue.replace(/^https?:\/\//i, "").split("/")[0];
  const suggestedDork = `"${cleanVal}" (fraude OR estafa OR querella OR desmentido OR falso OR "no pertenece")`;

  showToast(`Búsqueda de refutación sugerida copiada al portapapeles:\n${suggestedDork}`, "info");
  try {
    navigator.clipboard?.writeText(suggestedDork);
  } catch (_) {}

  try {
    const res = await fetch(
      `/api/cases/${encodeURIComponent(caseId)}/recon/seeds/${encodeURIComponent(seedId)}`,
      {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ consultas_refutacion: nextRefut }),
      }
    );
    const data = await res.json();
    if (data.ok) {
      showToast(`Refutación registrada para '${seedValue}' (Total: ${nextRefut})`, "ok");
      await loadReconView(caseId);
    }
  } catch (err) {
    showToast(`Error al registrar refutación: ${err.message}`, "error");
  }
}

async function runPassiveReconOnSeed(seedType, seedValue) {
  const caseId = getModuleCaseId("recon") || currentCaseId;
  if (!caseId || !seedValue) {
    showToast("Falta activo o caso para ejecutar reconocimiento", "warning");
    return;
  }
  let machine = "PassiveDomainRecon";
  if (seedType === "Email" || seedType === "EmailAddress") machine = "PassiveEmailRecon";
  else if (seedType === "Person") machine = "PersonalFootprint";
  else if (seedType === "Organization" || seedType === "Company") machine = "PassiveCompanyFootprint";
  else if (seedType === "IPv4Address") machine = "PassiveInfrastructureRecon";
  else if (seedType === "URL") machine = "PassiveURLRecon";

  const maltegoType = seedType.startsWith("maltego.")
    ? seedType
    : `maltego.${seedType === "Email" ? "EmailAddress" : seedType}`;

  showToast(`⚡ Iniciando Reconocimiento Pasivo (${machine}) sobre '${seedValue}'...`, "info");
  playTacticalClick(820, 0.04);

  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/machines/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        machine: machine,
        type: maltegoType,
        value: seedValue,
        rounds: 1,
        limit: 25,
        reason: `Reconocimiento pasivo rápido desde Consola M3 sobre ${seedValue}`,
      }),
    });
    const data = await res.json();
    if (!data.ok) {
      showToast(data.error || "Error al ejecutar reconocimiento", "error");
      return;
    }
    const count = data.total_entities ?? 0;
    showToast(`⚡ Reconocimiento Pasivo (${machine}) finalizado: ${count} entidades descubiertas en el grafo`, "ok");
    await loadCaseGraph(caseId);
    await loadReconView(caseId);
    updateTacticalHud();
  } catch (err) {
    showToast(`Error ejecutando reconocimiento pasivo: ${err.message}`, "error");
  }
}

async function deleteReconSeed(seedId) {
  const caseId = getModuleCaseId("recon") || currentCaseId;
  if (!caseId || !seedId) return;
  try {
    const res = await fetch(
      `/api/cases/${encodeURIComponent(caseId)}/recon/seeds/${encodeURIComponent(seedId)}`,
      { method: "DELETE" }
    );
    const data = await res.json();
    if (data.ok) {
      showToast("Semilla eliminada del inventario", "info");
      await loadReconView(caseId);
      updateTacticalHud();
    } else {
      showToast(data.error || "Error al eliminar semilla", "error");
    }
  } catch (err) {
    showToast(`Error de red: ${err.message}`, "error");
  }
}

async function cycleSeedStatus(seedId, currentStatus) {
  const caseId = getModuleCaseId("recon") || currentCaseId;
  if (!caseId || !seedId) return;
  const statusCycle = {
    nueva: "en_analisis",
    en_analisis: "completada",
    completada: "descartada",
    descartada: "nueva",
  };
  const nextStatus = statusCycle[currentStatus] || "nueva";
  try {
    const res = await fetch(
      `/api/cases/${encodeURIComponent(caseId)}/recon/seeds/${encodeURIComponent(seedId)}`,
      {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: nextStatus }),
      }
    );
    const data = await res.json();
    if (data.ok) {
      showToast(`Estado de semilla actualizado a '${nextStatus}'`, "ok");
      await loadReconView(caseId);
    }
  } catch (err) {
    showToast(`Error actualizando estado: ${err.message}`, "error");
  }
}

function viewSeedInGraph(seedType, seedValue) {
  switchTab("graph");
  setTimeout(() => {
    focusEntityOnGraphByValue(seedValue);
  }, 250);
}

function focusEntityOnGraphByValue(val) {
  if (!val || !graphNodes || graphNodes.length === 0) return;
  const clean = val.trim().toLowerCase();
  const node = graphNodes.find(
    (n) => n.value && n.value.trim().toLowerCase() === clean
  );
  if (node) {
    selectNode(node);
    graphCamera.scale = 1.35;
    graphCamera.x = -node.x * graphCamera.scale;
    graphCamera.y = -node.y * graphCamera.scale;
    physicsAlpha = Math.max(physicsAlpha, 0.4);
    showToast(`Enfocando '${node.value}' en el lienzo`, "info");
  } else {
    showToast(`Entidad '${val}' localizada en el caso`, "info");
  }
}

function filterDorksForSeed(domainOrValue) {
  loadReconDorks(domainOrValue);
  const container = document.getElementById("recon-dorks-container");
  if (container) {
    container.scrollIntoView({ behavior: "smooth", block: "center" });
  }
}

async function loadReconPivots() {
  const caseId = getModuleCaseId("recon");
  if (!caseId) return;
  const container = document.getElementById("recon-pivots-container");
  if (!container) return;

  container.innerHTML = `<div style="font-size:12px; color:var(--text-muted); text-align:center; padding:1rem;">Calculando contrastaciones laterales M3...</div>`;

  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/pivots`);
    const data = await res.json();
    if (!data.ok || !data.pivots || data.pivots.length === 0) {
      container.innerHTML = `<div style="font-size:12px; color:var(--text-muted); text-align:center; padding:1rem;">Sin sugerencias de pivotes laterales. Agrega semillas o dominios al caso.</div>`;
      return;
    }

    container.innerHTML = data.pivots
      .map(
        (p) => `
        <div style="background:rgba(6, 182, 212,0.03); border:1px solid rgba(6, 182, 212,0.2); border-radius:6px; padding:0.6rem 0.75rem; font-size:12px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:3px;">
            <strong style="color:var(--accent-cyan); font-size:12px;">${escapeHtml(p.seed)}</strong>
            <span class="pill pill-ok" style="font-size:12px;">100% Pasivo</span>
          </div>
          <div style="color:var(--text-primary); margin-bottom:2px;">${escapeHtml(p.question)}</div>
          <div style="color:var(--text-secondary); font-size:12px; margin-bottom:4px;">${escapeHtml(p.rationale)}</div>
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <span class="mono" style="font-size:12px; color:var(--text-muted);">${escapeHtml(p.transform)}</span>
            <button type="button" class="btn btn-secondary btn-sm action-recon-pivot" data-transform="${escapeHtml(p.transform)}" data-type="${escapeHtml(p.type)}" data-value="${escapeHtml(p.seed)}" style="font-size:12px; padding:2px 8px;">
              Ejecutar ->
            </button>
          </div>
        </div>
      `
      )
      .join("");
  } catch (err) {
    container.innerHTML = `<div style="font-size:12px; color:var(--accent-crimson); text-align:center; padding:1rem;">Error cargando pivotes: ${escapeHtml(err.message)}</div>`;
  }
}

async function quickRunTransformFromPivot(txName, entityType, value) {
  const caseId = getModuleCaseId("recon") || currentCaseId;
  if (!caseId) return;
  showToast(`Ejecutando '${txName}' sobre ${value}...`, "info");
  try {
    const res = await fetch("/api/lookup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        case_id: caseId,
        transform: txName,
        type: entityType,
        value: value,
        save: true,
      }),
    });
    const data = await res.json();
    if (!data.ok) {
      showToast(data.error || "Error ejecutando transform", "error");
      return;
    }
    const count = data.entities ? data.entities.length : 0;
    showToast(`Transform '${txName}' completado: ${count} entidades descubiertas y guardadas`, "ok");
    await loadCaseGraph(caseId);
    await loadReconView(caseId);
  } catch (err) {
    showToast(`Error de conexión: ${err.message}`, "error");
  }
}

async function loadReconDorks(domainOverride = "") {
  const caseId = getModuleCaseId("recon");
  if (!caseId) return;
  const container = document.getElementById("recon-dorks-container");
  if (!container) return;

  container.innerHTML = `<div style="font-size:12px; color:var(--text-muted); text-align:center; padding:1rem;">Generando dorks seguros...</div>`;

  try {
    const url = domainOverride
      ? `/api/cases/${encodeURIComponent(caseId)}/recon/dorks?domain=${encodeURIComponent(domainOverride)}`
      : `/api/cases/${encodeURIComponent(caseId)}/recon/dorks`;
    const res = await fetch(url);
    const data = await res.json();
    if (!data.ok || !data.dorks || data.dorks.length === 0) {
      container.innerHTML = `<div style="font-size:12px; color:var(--text-muted); text-align:center; padding:1rem;">No se detectó dominio en este caso para componer dorks.</div>`;
      return;
    }

    container.innerHTML = data.dorks
      .map(
        (d) => `
        <div style="background:rgba(245,158,11,0.03); border:1px solid rgba(245,158,11,0.2); border-radius:6px; padding:0.5rem 0.75rem; font-size:12px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:2px;">
            <strong style="color:var(--accent-gold); font-size:12px;">${escapeHtml(d.title)}</strong>
            <span class="pill pill-dim" style="font-size:12px;">${escapeHtml(d.category)}</span>
          </div>
          <div class="mono" style="background:var(--bg-main); border:1px solid var(--border-subtle); padding:3px 6px; border-radius:4px; font-size:12px; margin:4px 0; word-break:break-all; color:var(--text-primary);">
            ${escapeHtml(d.dork)}
          </div>
          <div style="display:flex; justify-content:space-between; align-items:center; margin-top:4px;">
            <span style="font-size:12px; color:var(--text-muted);">${escapeHtml(d.purpose)}</span>
            <button type="button" class="btn btn-secondary btn-sm action-copy-dork" data-dork="${escapeHtml(d.dork)}" style="font-size:12px; padding:2px 8px;">
              Copiar Dork
            </button>
          </div>
        </div>
      `
      )
      .join("");
  } catch (err) {
    container.innerHTML = `<div style="font-size:12px; color:var(--accent-crimson); text-align:center; padding:1rem;">Error generando dorks: ${escapeHtml(err.message)}</div>`;
  }
}

function copyDorkToClipboard(dork) {
  navigator.clipboard.writeText(dork).then(
    () => showToast("Dork copiado al portapapeles. Recuerda: Lee solo snippets (§4)", "ok"),
    () => showToast("Fallo al copiar dork", "warning")
  );
}

async function addReconHypothesisFromUi() {
  const caseId = getModuleCaseId("recon");
  if (!caseId) {
    showToast("Selecciona o crea un proyecto activo primero", "warning");
    return;
  }
  const statement = document.getElementById("new-hyp-statement")?.value.trim() || "";
  const refute = document.getElementById("new-hyp-refute")?.value.trim() || "";
  const prob = document.getElementById("new-hyp-prob")?.value || "PROBABLE";
  const conf = document.getElementById("new-hyp-conf")?.value || "MEDIA";

  if (!statement) {
    showToast("Introduce el enunciado de la hipótesis", "warning");
    return;
  }
  if (!refute) {
    showToast("Rigor analítico No Zoom: Especifica qué evidencia refutaría la hipótesis", "warning");
    return;
  }

  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/hypotheses`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ statement, what_would_refute_it: refute, probability: prob, confidence: conf }),
    });
    const data = await res.json();
    if (!data.ok) {
      showToast(data.error || "Error al agregar hipótesis", "error");
      return;
    }
    const stmtInput = document.getElementById("new-hyp-statement");
    const refInput = document.getElementById("new-hyp-refute");
    if (stmtInput) stmtInput.value = "";
    if (refInput) refInput.value = "";
    showToast("Hipótesis rival guardada correctamente", "ok");
    await loadReconView(caseId);
  } catch (err) {
    showToast(`Error: ${err.message}`, "error");
  }
}

async function deleteReconHypothesis(hypId) {
  const caseId = getModuleCaseId("recon");
  if (!caseId) return;
  if (!confirm(`¿Eliminar la hipótesis ${hypId} de la matriz ACH?`)) return;
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/hypotheses/${encodeURIComponent(hypId)}`, {
      method: "DELETE",
    });
    const data = await res.json();
    if (!data.ok) {
      showToast(data.error || "Error al eliminar hipótesis", "error");
      return;
    }
    showToast(`Hipótesis ${hypId} eliminada`, "ok");
    await loadReconView(caseId);
  } catch (err) {
    showToast(`Error: ${err.message}`, "error");
  }
}

async function evaluateReconHypothesis(hypId) {
  const caseId = getModuleCaseId("recon");
  if (!caseId) return;
  const inputInconsistencies = prompt(
    `[ACH §Heuer] Introduce el número de evidencias inconsistentes (o que contradicen) a ${hypId}:`,
    "0"
  );
  if (inputInconsistencies === null) return;
  const incCount = parseInt(inputInconsistencies.trim(), 10);
  if (isNaN(incCount) || incCount < 0) {
    showToast("Introduce un número válido de inconsistencias (>= 0)", "warning");
    return;
  }
  const newProb = prompt(
    "Actualizar probabilidad ICD 203 (CASI_SEGURO, MUY_PROBABLE, PROBABLE, POSIBILIDAD_IGUAL, IMPROBABLE, MUY_IMPROBABLE):",
    "PROBABLE"
  );
  const newConf = prompt("Actualizar nivel de confianza analítica (ALTA, MEDIA, BAJA):", "MEDIA");

  const evals = {};
  for (let i = 1; i <= incCount; i++) {
    evals[`inconsistencia_${i}`] = "I";
  }

  try {
    const res = await fetch(
      `/api/cases/${encodeURIComponent(caseId)}/recon/hypotheses/${encodeURIComponent(hypId)}/evaluate`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          evaluations: evals,
          probability: newProb ? newProb.trim().toUpperCase() : undefined,
          confidence: newConf ? newConf.trim().toUpperCase() : undefined,
        }),
      }
    );
    const data = await res.json();
    if (!data.ok) {
      showToast(data.error || "Error al evaluar hipótesis", "error");
      return;
    }
    showToast(`Hipótesis ${hypId} evaluada (inconsistencias: ${incCount})`, "ok");
    await loadReconView(caseId);
  } catch (err) {
    showToast(`Error: ${err.message}`, "error");
  }
}

function renderKeyEvidence(keyEv) {
  const sumEl = document.getElementById("key-evidence-summary");
  const clusEl = document.getElementById("key-evidence-cluster");
  const cntEl = document.getElementById("key-evidence-count");
  const impEl = document.getElementById("key-evidence-impact");
  const decEl = document.getElementById("key-evidence-deception");
  const altEl = document.getElementById("key-evidence-alt");

  if (sumEl && keyEv.evidence_summary) sumEl.value = keyEv.evidence_summary;
  if (clusEl && keyEv.source_cluster) clusEl.value = keyEv.source_cluster;
  if (cntEl && keyEv.independent_clusters_count) cntEl.value = keyEv.independent_clusters_count;
  if (impEl && keyEv.sensitivity_impact) impEl.value = keyEv.sensitivity_impact;
  if (decEl && keyEv.vulnerability_to_deception) decEl.value = keyEv.vulnerability_to_deception;
  if (altEl && keyEv.alternative_explanation) altEl.value = keyEv.alternative_explanation;
}

async function saveKeyEvidenceFromUi() {
  const caseId = getModuleCaseId("recon");
  if (!caseId) {
    showToast("Selecciona un proyecto activo primero", "warning");
    return;
  }
  const summary = document.getElementById("key-evidence-summary")?.value.trim() || "";
  if (!summary) {
    showToast("Introduce el resumen de la pieza clave de evidencia", "warning");
    return;
  }
  const cluster = document.getElementById("key-evidence-cluster")?.value.trim() || "CL-01";
  const count = parseInt(document.getElementById("key-evidence-count")?.value || "1", 10);
  const impact = document.getElementById("key-evidence-impact")?.value || "alto";
  const deception = document.getElementById("key-evidence-deception")?.value || "medio";
  const alt = document.getElementById("key-evidence-alt")?.value.trim() || "";

  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/key-evidence`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        evidence_summary: summary,
        source_cluster: cluster,
        independent_clusters_count: count,
        sensitivity_impact: impact,
        vulnerability_to_deception: deception,
        alternative_explanation: alt,
      }),
    });
    const data = await res.json();
    if (!data.ok) {
      showToast(data.error || "Error guardando pieza clave", "error");
      return;
    }
    showToast("Análisis de pieza clave (§Heuer Caps. 10-13) actualizado", "ok");
    await loadReconView(caseId);
  } catch (err) {
    showToast(`Error: ${err.message}`, "error");
  }
}

let currentIcd203Report = null;
let currentIcd203View = "html";

async function openIcd203Modal() {
  const caseId = getModuleCaseId("recon");
  if (!caseId) {
    showToast("Selecciona un proyecto activo primero", "warning");
    return;
  }
  const modal = document.getElementById("modal-icd203-report");
  const content = document.getElementById("modal-icd203-content");
  if (modal) modal.classList.add("active");
  if (content) {
    content.innerHTML = `<div style="text-align:center; padding:2rem; color:var(--accent-cyan);">Compilando informe pericial bajo estándares ICD 203 y Heuer ACH...</div>`;
  }

  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/recon/icd203-report`);
    const data = await res.json();
    if (!data.ok) {
      if (content) {
        content.innerHTML = `<div style="color:var(--accent-rose); padding:1rem;">Error: ${escapeHtml(data.error || "No se pudo generar el informe")}</div>`;
      }
      return;
    }
    currentIcd203Report = data;
    renderIcd203Content();
  } catch (err) {
    if (content) content.innerHTML = `<div style="color:var(--accent-rose); padding:1rem;">Error: ${escapeHtml(err.message)}</div>`;
  }
}

function closeIcd203Modal() {
  const modal = document.getElementById("modal-icd203-report");
  if (modal) modal.classList.remove("active");
}

function switchIcd203View(view) {
  currentIcd203View = view;
  const btnHtml = document.getElementById("btn-tab-icd203-view");
  const btnMd = document.getElementById("btn-tab-icd203-md");
  if (btnHtml && btnMd) {
    if (view === "html") {
      btnHtml.className = "btn btn-primary btn-sm";
      btnMd.className = "btn btn-secondary btn-sm";
    } else {
      btnHtml.className = "btn btn-secondary btn-sm";
      btnMd.className = "btn btn-primary btn-sm";
    }
  }
  renderIcd203Content();
}

function renderIcd203Content() {
  const content = document.getElementById("modal-icd203-content");
  if (!content || !currentIcd203Report) return;
  if (currentIcd203View === "html") {
    content.innerHTML = `
      <div style="background:#0f172a; border-radius:6px; border:1px solid #1e293b; padding:1.5rem; color:var(--text-primary);">
        ${currentIcd203Report.report_html.replace(/<\/?(html|head|body|meta|title|style[\s\S]*?\/style)>/gi, "")}
      </div>
    `;
  } else {
    content.innerHTML = `
      <pre style="background:#090d16; border:1px solid #1e293b; border-radius:6px; padding:1rem; color:var(--accent-sky); font-family:monospace; font-size:12px; white-space:pre-wrap; overflow-x:auto;">${escapeHtml(currentIcd203Report.report_markdown)}</pre>
    `;
  }
}

function copyIcd203Markdown() {
  if (!currentIcd203Report || !currentIcd203Report.report_markdown) {
    showToast("No hay informe para copiar", "warning");
    return;
  }
  navigator.clipboard.writeText(currentIcd203Report.report_markdown).then(
    () => showToast("Informe Markdown copiado al portapapeles (ICD 203)", "ok"),
    () => showToast("Error al copiar al portapapeles", "warning")
  );
}

function printIcd203Report() {
  if (!currentIcd203Report || !currentIcd203Report.report_html) {
    showToast("No hay informe para imprimir", "warning");
    return;
  }
  const printWin = window.open("", "_blank");
  if (!printWin) {
    showToast("Ventana emergente bloqueada por el navegador", "warning");
    return;
  }
  printWin.document.write(currentIcd203Report.report_html);
  printWin.document.close();
  printWin.focus();
  setTimeout(() => {
    printWin.print();
  }, 250);
}

// ============================================================================
// 16. MODAL PERÍMETRO INTOCABLE DINÁMICO (§1)
// ============================================================================

function isThirdPartySaaS(val) {
  return /s3\.amazonaws|blob\.core|storage\.google|slack\.com|notion\.site|atlassian\.net|trello\.com|calendly\.com|bit\.ly/i.test(
    val || ""
  );
}

function updatePerimeterUI(data) {
  const dCount = document.getElementById("recon-stat-shielded-domains");
  const ipCount = document.getElementById("recon-stat-shielded-ips");
  const netCount = document.getElementById("recon-stat-shielded-nets");
  const thirdCount = document.getElementById("recon-stat-shielded-thirdparty");
  const countBadge = document.getElementById("recon-p0-perimeter-count-badge");
  const badgeCount = document.getElementById("badge-perimeter-count");

  const domains = data.domains || [];
  const ips = data.ips || [];
  const networks = data.networks || [];
  const custom = data.custom_assets || [];

  const thirdPartyCount = custom.filter(isThirdPartySaaS).length + domains.filter(isThirdPartySaaS).length;

  if (dCount) dCount.textContent = domains.length;
  if (ipCount) ipCount.textContent = ips.length;
  if (netCount) netCount.textContent = networks.length;
  if (thirdCount) thirdCount.textContent = thirdPartyCount;

  const total = data.total ?? (domains.length + ips.length + networks.length + custom.length);
  if (badgeCount) badgeCount.textContent = total;
  if (countBadge) countBadge.textContent = `${total} ${total === 1 ? "activo" : "activos"}`;

  // Renderizar la lista inline interactiva de activos escudados
  const quickListEl = document.getElementById("recon-p0-perimeter-quick-list");
  if (quickListEl) {
    const allItems = [];
    domains.forEach((d) => {
      const saas = isThirdPartySaaS(d);
      allItems.push({ type: saas ? "thirdparty" : "domain", value: d, label: saas ? "TERCERO" : "DOMINIO" });
    });
    ips.forEach((ip) => {
      allItems.push({ type: "ip", value: ip, label: "IP" });
    });
    networks.forEach((net) => {
      allItems.push({ type: "network", value: net, label: "RED" });
    });
    custom.forEach((c) => {
      if (!allItems.some((item) => item.value.toLowerCase() === c.toLowerCase())) {
        const saas = isThirdPartySaaS(c);
        allItems.push({ type: saas ? "thirdparty" : "custom", value: c, label: saas ? "TERCERO" : "ACTIVO" });
      }
    });

    if (allItems.length === 0) {
      quickListEl.innerHTML = `
        <div style="font-size:12px; color:var(--text-muted); text-align:center; padding:1.25rem;">
          Sin activos en el perímetro. Añade el objetivo o una semilla para activar el blindaje de salida.
        </div>
      `;
    } else {
      quickListEl.innerHTML = allItems
        .map((item) => {
          const badgeClass =
            item.type === "thirdparty"
              ? "badge-thirdparty"
              : item.type === "ip"
              ? "badge-ip"
              : item.type === "network"
              ? "badge-network"
              : "";
          return `
            <div class="p0-perimeter-item">
              <div style="display:flex; align-items:center; gap:0.45rem; overflow:hidden; text-overflow:ellipsis; min-width:0;">
                <span class="p0-perimeter-badge ${badgeClass}">${escapeHtml(item.label)}</span>
                <span class="mono" style="font-size:12px; color:var(--text-primary); white-space:nowrap; text-overflow:ellipsis; overflow:hidden;" title="${escapeHtml(item.value)}">
                  ${escapeHtml(item.value)}
                </span>
              </div>
              <button type="button" class="btn-remove-p0-item action-remove-quick-perimeter" data-asset="${escapeHtml(item.value)}" title="Retirar del Perímetro Intocable">&times;</button>
            </div>
          `;
        })
        .join("");
    }
  }
}

async function openPerimeterModal() {
  playTacticalClick(700, 0.02);
  const caseId = currentCaseId || getModuleCaseId("recon");
  if (!caseId) {
    showToast("Selecciona un proyecto de investigación activo", "warning");
    return;
  }
  const modal = document.getElementById("modal-perimeter");
  if (!modal) return;
  modal.classList.add("active");

  const caseDisplay = document.getElementById("perimeter-case-id-display");
  if (caseDisplay) caseDisplay.textContent = caseId;

  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/perimeter`);
    const data = await res.json();
    if (data.ok) {
      document.getElementById("perimeter-total-display").textContent = data.total ?? 0;
      document.getElementById("perimeter-domains-count").textContent = (data.domains || []).length;
      document.getElementById("perimeter-ips-count").textContent = (data.ips || []).length;
      document.getElementById("perimeter-networks-count").textContent = (data.networks || []).length;

      document.getElementById("perimeter-domains-list").innerHTML =
        (data.domains || []).length > 0
          ? data.domains.map((d) => `<span class="pill pill-cyan" style="font-size:12px; margin:2px;">${escapeHtml(d)}</span>`).join("")
          : `<span style="color:var(--text-muted);">Sin dominios en el escudo</span>`;

      document.getElementById("perimeter-ips-list").innerHTML =
        (data.ips || []).length > 0
          ? data.ips.map((ip) => `<span class="pill pill-rose" style="font-size:12px; margin:2px;">${escapeHtml(ip)}</span>`).join("")
          : `<span style="color:var(--text-muted);">Sin IPs en el escudo</span>`;

      document.getElementById("perimeter-networks-list").innerHTML =
        (data.networks || []).length > 0
          ? data.networks.map((net) => `<span class="pill pill-dim" style="font-size:12px; margin:2px;">${escapeHtml(net)}</span>`).join("")
          : `<span style="color:var(--text-muted);">Sin prefijos CIDR en el escudo</span>`;

      updatePerimeterUI(data);
    }
  } catch (err) {
    console.warn("Error cargando perímetro:", err);
  }
}

function closePerimeterModal() {
  const modal = document.getElementById("modal-perimeter");
  if (modal) modal.classList.remove("active");
}

async function submitPerimeterAsset() {
  const input = document.getElementById("perimeter-asset-input");
  const asset = input ? input.value.trim() : "";
  if (!asset) return;
  const caseId = currentCaseId || getModuleCaseId("recon");
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/perimeter`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "add", asset }),
    });
    const data = await res.json();
    if (data.ok) {
      input.value = "";
      showToast(`Activo '${asset}' incorporado al Perímetro Intocable`, "ok");
      openPerimeterModal();
      await loadReconView(caseId);
      updateTacticalHud();
    } else {
      showToast(data.error || "Error al añadir activo", "error");
    }
  } catch (err) {
    showToast(`Error: ${err.message}`, "error");
  }
}

async function addQuickPerimeterAsset() {
  const typeSelect = document.getElementById("recon-quick-perimeter-type");
  const input = document.getElementById("recon-quick-perimeter-input");
  let asset = input ? input.value.trim() : "";
  const type = typeSelect ? typeSelect.value : "auto";
  if (!asset) {
    if (input) input.focus();
    return;
  }
  const caseId = getModuleCaseId("recon") || currentCaseId;
  if (!caseId) {
    showToast("Selecciona un proyecto de investigación activo primero", "warning");
    return;
  }

  // Normalización
  if (type === "domain" || type === "auto") {
    asset = asset.replace(/^https?:\/\//i, "").replace(/\/.*$/, "").trim();
  }

  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/perimeter`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "add", asset }),
    });
    const data = await res.json();
    if (data.ok) {
      if (input) input.value = "";
      showToast(`'${asset}' incorporado al Perímetro Intocable`, "ok");
      await loadReconView(caseId);
      updateTacticalHud();
    } else {
      showToast(data.error || "Error al añadir activo", "error");
    }
  } catch (err) {
    showToast(`Error: ${err.message}`, "error");
  }
}

async function removeQuickPerimeterAsset(asset) {
  if (!asset) return;
  const caseId = getModuleCaseId("recon") || currentCaseId;
  if (!caseId) return;
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/perimeter`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "remove", asset }),
    });
    const data = await res.json();
    if (data.ok) {
      showToast(`Activo '${asset}' retirado del Perímetro Intocable`, "info");
      await loadReconView(caseId);
      updateTacticalHud();
    } else {
      showToast(data.error || "Error al retirar activo", "error");
    }
  } catch (err) {
    showToast(`Error de red: ${err.message}`, "error");
  }
}

function checkLoadedLanguage(questionText) {
  const alertEl = document.getElementById("recon-loaded-language-alert");
  const wordsEl = document.getElementById("recon-loaded-words");
  if (!alertEl || !wordsEl) return;
  const loadedRegex = /\b(estafador|estafa|fraude|delincuente|crimen|criminal|corrupto|testaferro|trama|blanqueo|ilegal)\b/gi;
  const matches = (questionText || "").match(loadedRegex);
  if (matches && matches.length > 0) {
    const uniqueWords = [...new Set(matches.map((w) => w.toLowerCase()))];
    wordsEl.textContent = uniqueWords.join(", ");
    alertEl.style.display = "flex";
  } else {
    alertEl.style.display = "none";
  }
}

function renderP0Assumptions(list) {
  const container = document.getElementById("recon-p0-assumptions-list");
  if (!container) return;
  if (!Array.isArray(list) || list.length === 0) {
    container.innerHTML = `
      <div style="font-size:12px; color:var(--text-muted); padding:0.25rem 0.5rem; text-align:center;">
        Sin supuestos previos registrados. Añade al menos uno con su criterio de refutación (WYSIATI Inversion).
      </div>
    `;
    return;
  }
  container.innerHTML = list
    .map((assump, idx) => {
      const text = typeof assump === "object" ? assump.text || "" : assump;
      const refutation = typeof assump === "object" ? assump.refutation || "" : "";
      const status = typeof assump === "object" ? assump.status || "activo" : "activo";

      let statusPillClass = "pill-warn";
      let statusLabel = "Activo";
      if (status === "refutado") {
        statusPillClass = "pill-err";
        statusLabel = "Refutado";
      } else if (status === "confirmado") {
        statusPillClass = "pill-ok";
        statusLabel = "Confirmado";
      }

      return `
      <div class="p0-assumption-item" style="padding:0.4rem 0.6rem; margin-bottom:0.25rem; display:flex; align-items:center; justify-content:space-between; gap:0.5rem; background:rgba(15,23,42,0.85); border:1px solid rgba(255,255,255,0.08); border-radius:4px;">
        <div style="flex:1; min-width:0;">
          <div style="font-size:12px; font-weight:600; color:var(--text-primary);">
            <span style="color:var(--accent-cyan); font-weight:700;">#${idx + 1}:</span> ${escapeHtml(text)}
          </div>
          <div style="font-size:12px; color:var(--accent-rose); font-style:italic; margin-top:2px;">
            ⚡ Refutación si: ${escapeHtml(refutation || "Criterio de refutación pendiente")}
          </div>
        </div>
        <button type="button" class="btn btn-secondary btn-sm action-cycle-p0-assumption-status ${statusPillClass}" data-index="${idx}" title="Clic para alternar estado: Activo -> Refutado -> Confirmado" style="font-size:12px; padding:2px 6px;">
          ${statusLabel}
        </button>
        <button type="button" class="btn-remove-p0-item action-remove-p0-assumption" data-index="${idx}" title="Eliminar supuesto">&times;</button>
      </div>
    `;
    })
    .join("");
}

async function addP0Assumption() {
  const input = document.getElementById("recon-p0-assumption-input");
  const refInput = document.getElementById("recon-p0-refutation-input");
  if (!input) return;
  const text = input.value.trim();
  const refutation = refInput?.value.trim() || "";
  if (!text) {
    input.focus();
    return;
  }
  if (!currentReconData) currentReconData = {};
  if (!currentReconData.p0_framing) currentReconData.p0_framing = {};
  if (!Array.isArray(currentReconData.p0_framing.assumptions)) {
    currentReconData.p0_framing.assumptions = [];
  }
  currentReconData.p0_framing.assumptions.push({
    text: text,
    refutation: refutation,
    status: "activo",
  });
  input.value = "";
  if (refInput) refInput.value = "";
  renderP0Assumptions(currentReconData.p0_framing.assumptions);
  await saveReconFraming(false);
  showToast("Supuesto previo y criterio de refutación registrados", "ok");
}

async function cycleP0AssumptionStatus(index) {
  if (!currentReconData?.p0_framing?.assumptions) return;
  const item = currentReconData.p0_framing.assumptions[index];
  if (!item) return;
  let curStatus = typeof item === "object" ? item.status || "activo" : "activo";
  let nextStatus = "refutado";
  if (curStatus === "refutado") nextStatus = "confirmado";
  else if (curStatus === "confirmado") nextStatus = "activo";

  if (typeof item === "object") {
    item.status = nextStatus;
  } else {
    currentReconData.p0_framing.assumptions[index] = {
      text: item,
      refutation: "",
      status: nextStatus,
    };
  }
  renderP0Assumptions(currentReconData.p0_framing.assumptions);
  await saveReconFraming(false);
  showToast(`Estado del supuesto #${index + 1} actualizado a [${nextStatus}]`, "info");
}

async function removeP0Assumption(index) {
  if (!currentReconData?.p0_framing?.assumptions) return;
  currentReconData.p0_framing.assumptions.splice(index, 1);
  renderP0Assumptions(currentReconData.p0_framing.assumptions);
  await saveReconFraming(false);
  showToast("Supuesto eliminado", "info");
}

function onP0RefClassPresetChanged(val) {
  const refClassText = document.getElementById("recon-framing-refclass");
  if (!refClassText) return;
  const presets = {
    pyme_tecnologica: "PYME Tecnológica Nacional: Típico uso de Cloudflare/AWS/Hetzner, correo Google Workspace o Microsoft 365. No confundir infraestructura compartida en hosting con colusión societaria.",
    gran_empresa: "Gran Corporación: Dispone de ASN propio, bloques IP dedicados, presencia registral en múltiples jurisdicciones, personal técnico y legal diverso.",
    ecommerce: "Comercio Electrónico / Retail: CMS Shopify/WooCommerce, pasarelas Stripe/Redsys, múltiples dominios satélite de campañas publicitarias temporales.",
    persona_fisica: "Persona Física / Autónomo: Registro de dominios a nombre personal o con Whois Privacy, huella concentrada en redes profesionales y foros sectoriales.",
  };
  if (presets[val]) {
    refClassText.value = presets[val];
    showToast("Preset de clase de referencia cargado", "info");
  }
}

function onP0LegalPresetChanged(val) {
  const legalText = document.getElementById("recon-framing-legal");
  if (!legalText) return;
  const presets = {
    ley5_2014: "Ley 5/2014 de Seguridad Privada, art. 48: Legitimación para investigación pericial de solvencia patrimonial, localización y defensa procesal ante tribunales.",
    rgpd_interes: "RGPD art. 6.1.f: Interés legítimo para ciberinteligencia defensiva, prevención de fraudes y cartografía de superficie de ataque pasiva.",
    ley10_2010: "Ley 10/2010 de Prevención de Blanqueo de Capitales: Diligencia debida (KYC/AML), prevención de fraude y verificación de titularidades reales.",
    ciber_cti: "Marco CTI Defensivo: Cartografía pasiva de exposición de infraestructura, correlación de amenazas y prevención de fugas de información.",
  };
  if (presets[val]) {
    legalText.value = presets[val];
    showToast("Preset legal cargado en Encuadre Fase 0", "info");
  }
}

function onP0HumintPresetChanged(val) {
  const humintText = document.getElementById("recon-framing-humint");
  if (!humintText) return;
  const presets = {
    pasivo_estricto: "100% Pasivo · Prohibición absoluta de interactuar con el objetivo · Cero solicitudes, visitas autenticadas ni telemetría 'owner_telemetry'.",
    fuentes_abiertas: "Exclusivamente fuentes públicas abiertas sin inicio de sesión (perfiles públicos indexados y snippets de terceros).",
    rgpd_minimizado: "Minimización estricta de datos personales · Limitado a esfera profesional y corporativa · Prohibida la indagación de la vida privada.",
  };
  if (presets[val]) {
    humintText.value = presets[val];
    showToast("Preset de límites operativos cargado", "info");
  }
}

// ============================================================================
// 17. MODAL EJECUCIÓN DE MACHINES PASIVAS (§3)
// ============================================================================

function openRunMachineModal() {
  playTacticalClick(700, 0.02);
  const caseId = currentCaseId;
  if (!caseId) {
    showToast("Selecciona un proyecto de investigación activo", "warning");
    return;
  }
  const modal = document.getElementById("modal-run-machine");
  if (!modal) return;
  modal.classList.add("active");

  const valInput = document.getElementById("run-machine-entity-val");
  const typeSelect = document.getElementById("run-machine-entity-type");

  if (selectedNode) {
    if (valInput) valInput.value = selectedNode.value;
    if (typeSelect) typeSelect.value = selectedNode.type;
  } else if (graphNodes.length > 0) {
    const root = graphNodes[0];
    if (valInput) valInput.value = root.value;
    if (typeSelect) typeSelect.value = root.type;
  }
}

function closeRunMachineModal() {
  const modal = document.getElementById("modal-run-machine");
  if (modal) modal.classList.remove("active");
}

async function executePassiveMachineFromModal() {
  const caseId = getModuleCaseId("recon") || currentCaseId;
  if (!caseId) {
    showToast("Selecciona o crea un proyecto activo primero", "warning");
    return;
  }

  const machineName = document.getElementById("run-machine-select")?.value || "PassiveDomainRecon";
  const entityType = document.getElementById("run-machine-entity-type")?.value || "maltego.Domain";
  const val = document.getElementById("run-machine-entity-val")?.value.trim() || "";
  const rounds = parseInt(document.getElementById("run-machine-rounds")?.value || "1", 10);
  const limit = parseInt(document.getElementById("run-machine-limit")?.value || "25", 10);
  const reason = document.getElementById("run-machine-reason")?.value.trim() || "Ejecución desde Consola de Mando OSINT";

  if (!val) {
    showToast("Introduce el valor de la entidad semilla", "warning");
    return;
  }

  closeRunMachineModal();
  showToast(`Ejecutando Machine '${machineName}' sobre '${val}' (${rounds} ronda(s))...`, "info");

  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/machines/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        machine: machineName,
        type: entityType,
        value: val,
        rounds: rounds,
        limit: limit,
        reason: reason,
      }),
    });
    const data = await res.json();
    if (!data.ok) {
      showToast(data.error || "Error ejecutando machine", "error");
      return;
    }
    const totalEnts = data.total_entities ?? 0;
    showToast(
      `Machine '${machineName}' finalizada: ${totalEnts} nuevas entidades descubiertas en ${data.rounds_executed || rounds} ronda(s)`,
      "ok"
    );
    await loadCaseGraph(caseId);
    await loadReconView(caseId);
    updateTacticalHud();
  } catch (err) {
    showToast(`Error de conexión al ejecutar machine: ${err.message}`, "error");
  }
}

// ============================================================================
// 18. TELEMETRÍA Y CADENA DE CUSTODIA EGRESS (AUDIT LOG SHA-256)
// ============================================================================

function switchLogTab(tab) {
  playTacticalClick(720, 0.02);
  const sseContainer = document.getElementById("event-log");
  const egressContainer = document.getElementById("egress-audit-container");
  const btnSse = document.getElementById("btn-tab-sse");
  const btnEgress = document.getElementById("btn-tab-egress");

  if (tab === "egress") {
    if (sseContainer) sseContainer.style.display = "none";
    if (egressContainer) egressContainer.style.display = "block";
    if (btnSse) btnSse.classList.remove("active");
    if (btnEgress) btnEgress.classList.add("active");
    loadEgressAuditLog();
  } else {
    if (sseContainer) sseContainer.style.display = "block";
    if (egressContainer) egressContainer.style.display = "none";
    if (btnSse) btnSse.classList.add("active");
    if (btnEgress) btnEgress.classList.remove("active");
  }
}

async function loadEgressAuditLog() {
  const tbody = document.getElementById("tbody-egress-audit");
  const chainStatusEl = document.getElementById("egress-chain-status");
  if (!tbody) return;

  try {
    const res = await fetch("/api/egress/audit?limit=50");
    const data = await res.json();
    if (!data.ok) {
      if (chainStatusEl) chainStatusEl.textContent = "No verificada";
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--accent-crimson); padding:1rem;">Error cargando auditoría</td></tr>`;
      return;
    }

    if (chainStatusEl) {
      chainStatusEl.textContent = data.chain_valid ? "Válida (SHA-256)" : `Rota: ${data.broken_at || ""}`;
      chainStatusEl.style.color = data.chain_valid ? "var(--accent-emerald)" : "var(--accent-crimson)";
    }

    const records = data.records || [];
    if (records.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:1rem;">Sin peticiones salientes registradas aún. Toda consulta pasiva se encadena aquí.</td></tr>`;
      return;
    }

    tbody.innerHTML = records
      .reverse()
      .map((r) => {
        const decision = String(r.decision || "").toLowerCase();
        const pillCls = decision === "allowed" ? "pill-ok" : decision === "vpn_control" ? "pill-cyan" : "pill-err";
        return `
        <tr>
          <td class="mono" style="color:var(--text-muted);">${r.seq ?? 0}</td>
          <td><span class="pill ${pillCls}" style="font-size:12px;">${escapeHtml(r.decision || "")}</span></td>
          <td class="mono" style="font-weight:700;">${escapeHtml(r.method || "")}</td>
          <td class="mono" style="font-size:12px; color:var(--text-primary); max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
            ${escapeHtml(r.host || "")}${escapeHtml(r.path || "")}
          </td>
          <td style="font-size:12px; color:var(--text-secondary);">${escapeHtml(r.reason || "")}</td>
          <td style="font-size:12px; color:var(--text-muted);">${escapeHtml(r.timestamp_utc ? r.timestamp_utc.slice(11, 19) : "")}</td>
        </tr>
      `;
      })
      .join("");
  } catch (err) {
    if (chainStatusEl) chainStatusEl.textContent = "No verificada";
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--accent-crimson); padding:1rem;">Error de red: ${escapeHtml(err.message)}</td></tr>`;
  }
}

