/* Anillo de egreso Mullvad (Centro de Mando).
 *
 * Regla de honestidad: nada de lo que se pinta aquí sale del navegador. Todo estado viene de GET /api/egress/ring
 * (atestación del servidor fechada) y caduca a los 15 s. El estado inicial es siempre "Comprobando…".
 * Nunca se recibe ni se muestra la IP real ni la geolocalización del operador.
 * Las peticiones POST llevan X-CSRF-Token gracias al fetch parcheado de dashboard.js.
 */
(() => {
  "use strict";

  const POLL_MS = 5000;
  const STALE_MS = 15000;
  const CITY_ES = {
    Copenhagen: "Copenhague", Tallinn: "Tallin", Paris: "París", Berlin: "Berlín", Dusseldorf: "Düsseldorf",
    Frankfurt: "Fráncfort", Amsterdam: "Ámsterdam", Gothenburg: "Gotemburgo", Stockholm: "Estocolmo",
    Zurich: "Zúrich", London: "Londres", "New York, NY": "Nueva York", "San Jose, CA": "San José",
  };
  const ICONS = {
    shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>',
    lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>',
    alert: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3 2 21h20L12 3z"/><path d="M12 10v4M12 17h.01"/></svg>',
    spin: '<svg class="ring-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.2-8.56"/></svg>',
    off: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/></svg>',
  };

  // Textos llanos por estado (el estado lo decide el servidor; aquí solo se explica).
  const STATES = {
    checking: { tone: "neutral", icon: "spin", hud: "COMPROBANDO", primary: null,
      title: "Comprobando el anillo de egreso…",
      sub: () => "Consultando el daemon local y la comprobación externa. Hasta confirmarlo, el MCP no envía consultas." },
    stale: { tone: "neutral", icon: "spin", hud: "SIN CONFIRMAR", primary: "recheck",
      title: "Estado sin confirmar",
      sub: () => "La última comprobación tiene más de 15 s. Mientras no se confirme, trátalo como bloqueado." },
    protected: { tone: "ok", icon: "shield", hud: "PROTEGIDO", primary: "disconnect",
      title: "Protegido: tráfico por servidores propios de Mullvad",
      sub: (r) => `${r.entry ? `Entrada en ${city(r.entry)} y salida` : "Salida"} en ${city(r.exit)}. El MCP solo puede salir por este túnel.` },
    connecting: { tone: "info", icon: "spin", hud: "CONECTANDO", primary: null,
      title: "Cambiando de estado…",
      sub: () => "Las consultas esperan hasta que el túnel esté verificado." },
    unverified: { tone: "warn", icon: "alert", hud: "SIN VERIFICAR", primary: "recheck",
      title: "Conectado, pendiente de verificar",
      sub: () => "El túnel está activo, pero la comprobación externa no confirma la salida. El MCP sigue bloqueado." },
    blocked: { tone: "neutral", icon: "lock", hud: "BLOQUEADO", primary: "connect",
      title: "Bloqueado: no sale ninguna consulta",
      sub: () => "Mullvad está desconectado y el bloqueo sin VPN está activo. Es un estado seguro, pero no se puede investigar." },
    rented: { tone: "bad", icon: "alert", hud: "SERVIDOR NO PROPIO", primary: "reconnect",
      title: "Servidor no propio: consultas bloqueadas",
      sub: (r) => `El servidor actual (${host(r.exit) || host(r.entry) || "desconocido"}) no es propio de Mullvad. El MCP rechaza las consultas hasta usar uno propio.` },
    unlocked: { tone: "bad", icon: "alert", hud: "SIN BLOQUEO", primary: "connect",
      title: "Peligro: el bloqueo sin VPN está desactivado",
      sub: () => "Otras aplicaciones y los agentes pueden salir con tu IP real. El MCP sigue bloqueado. Actívalo en la app de Mullvad o con el script del anillo 1." },
    daemon: { tone: "bad", icon: "off", hud: "SIN DAEMON", primary: "recheck",
      title: "No se puede hablar con Mullvad",
      sub: (r) => `${r.reason || "El servicio de Mullvad no responde."} El MCP bloquea todas las consultas.` },
    account: { tone: "bad", icon: "off", hud: "SIN CUENTA", primary: "recheck",
      title: "Cuenta de Mullvad sin sesión o caducada",
      sub: () => "Inicia sesión o renueva la cuenta en la app de Mullvad. Esta interfaz nunca pide ni muestra el número de cuenta." },
    error: { tone: "bad", icon: "alert", hud: "ERROR", primary: "recheck",
      title: "Mullvad está en estado de error",
      sub: () => "El daemon está bloqueando el tráfico. No se ha enviado ninguna consulta. Revisa la app de Mullvad." },
    unreachable: { tone: "bad", icon: "off", hud: "SIN RESPUESTA", primary: "recheck",
      title: "El servidor del panel no responde",
      sub: () => "No se pudo consultar el estado del anillo. Trátalo como bloqueado." },
  };
  const PRIMARY = {
    connect: ["Conectar", "btn-primary"],
    disconnect: ["Desconectar…", "ring-btn-danger"],
    reconnect: ["Reconectar", "btn-primary"],
    recheck: ["Volver a comprobar", "btn-secondary"],
  };
  const CHECKS = [
    ["daemon", "Daemon de Mullvad", () => "Servicio local, binario firmado por Mullvad VPN AB"],
    ["lockdown", "Bloqueo sin VPN", () => "Si el túnel cae, el equipo entero se queda sin red"],
    ["entry", "Entrada propia", (r) => (r.entry ? `${host(r.entry)} · ${city(r.entry)}` : r.exit ? "Sin multihop: entrada = salida" : "—")],
    ["exit", "Salida propia", (r) => (r.exit ? `${host(r.exit)} · ${r.exit.owned ? city(r.exit) : "no propio"}` : "—")],
    ["remote", "Comprobación externa", () => "am.i.mullvad.net confirma la salida por Mullvad"],
    ["gate", "Compuerta del MCP", () => "Solo vía el proxy interno 10.64.0.1:1080, dentro del túnel"],
  ];
  const UP_STATES = new Set(["protected", "unverified", "rented", "connecting"]);
  const NA_WHEN_DOWN = new Set(["entry", "exit", "remote"]);

  const S = { data: null, fetchedAt: 0, busy: false, timer: null, lastState: "", relays: null };
  const $ = (id) => document.getElementById(id);

  function host(relay) { return relay && typeof relay.hostname === "string" ? relay.hostname : ""; }
  function city(relay) {
    if (!relay) return "—";
    const c = typeof relay.city === "string" ? relay.city : "";
    return CITY_ES[c] || c || host(relay) || "—";
  }
  function esc(v) {
    return String(v ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]);
  }

  function currentState() {
    if (!S.data) return S.fetchedAt ? "unreachable" : "checking";
    const ring = S.data.ring || {};
    const age = Date.now() - S.fetchedAt;
    if (age > STALE_MS) return "stale";
    return STATES[ring.state] ? ring.state : "error";
  }

  function render(announce) {
    const panel = $("ring-panel");
    const stKey = currentState();
    const st = STATES[stKey];
    const ring = (S.data && S.data.ring) || {};
    const control = (S.data && S.data.control) || { enabled: false, reason: "" };

    // HUD global (visible en todas las vistas)
    const hud = $("hud-egress");
    if (hud) {
      hud.innerHTML = `<span class="ring-tone-${st.tone}" aria-hidden="true">●</span> EGRESO: ${esc(st.hud)}`;
      hud.dataset.tone = st.tone;
    }
    if (!panel) return;

    const icon = $("ring-icon");
    icon.className = `ring-status-icon ring-tone-${st.tone}`;
    icon.innerHTML = ICONS[st.icon];
    $("ring-title-text").textContent = st.title;
    $("ring-sub").textContent = st.sub(ring);

    // Acción principal según estado (oculta en solo lectura)
    const p = $("ring-primary");
    const act = control.enabled || st.primary === "recheck" ? st.primary : null;
    if (act) {
      p.hidden = false;
      p.textContent = PRIMARY[act][0];
      p.className = `btn ${PRIMARY[act][1]}`;
      p.dataset.act = act;
    } else {
      p.hidden = true;
      p.dataset.act = "";
    }
    const busy = S.busy || Boolean(S.data && S.data.busy);
    p.disabled = busy;
    p.setAttribute("aria-busy", busy ? "true" : "false");
    $("ring-menu-btn").disabled = busy;

    // Ruta del tráfico
    const up = UP_STATES.has(stKey);
    const path = $("ring-path");
    if (up) {
      const hops = [
        ["Origen", "Este equipo", "IP real oculta"],
        ...(ring.entry ? [["Entrada", host(ring.entry), `${city(ring.entry)} · ${ring.entry.owned ? "propio" : "NO propio"}`]] : []),
        ["Salida", host(ring.exit) || "—", ring.exit ? `${city(ring.exit)} · ${ring.exit.owned ? "propio" : "NO propio"}` : "—"],
        ["Destino", "Internet", "solo proveedores permitidos"],
      ];
      path.innerHTML = hops
        .map((h) => `<div class="ring-hop"><small>${esc(h[0])}</small><strong>${esc(h[1])}</strong><span>${esc(h[2])}</span></div>`)
        .join('<span class="ring-arrow" aria-hidden="true">→</span>');
    } else {
      path.innerHTML =
        '<div class="ring-hop"><small>Origen</small><strong>Este equipo</strong><span>IP real oculta</span></div>' +
        '<span class="ring-arrow ring-arrow-cut" aria-hidden="true">✕</span>' +
        '<div class="ring-hop"><small>Destino</small><strong>Internet</strong><span>sin salida</span></div>';
    }

    // Comprobaciones
    const checksById = Object.fromEntries((ring.checks || []).map((c) => [c.id, Boolean(c.ok)]));
    $("ring-checks").innerHTML = CHECKS.map(([id, label, detail]) => {
      let mark = "pend";
      if (S.data && stKey !== "stale" && stKey !== "unreachable") {
        if (checksById[id]) mark = "ok";
        else if (!up && NA_WHEN_DOWN.has(id)) mark = "na";
        else mark = "fail";
      }
      const m = { ok: ["✓", "ring-check-ok", "correcto"], fail: ["✕", "ring-check-bad", "fallo"],
        pend: ["…", "", "pendiente"], na: ["–", "", "no aplica"] }[mark];
      return `<li class="ring-check ${m[1]}"><span class="ring-mark" aria-hidden="true">${m[0]}</span>` +
        `<span><span class="sr-only">${m[2]}: </span>${esc(label)}<span class="ring-detail">${esc(detail(ring))}</span></span></li>`;
    }).join("");

    // Consecuencias y solo lectura
    const cons = $("ring-consequence");
    if (stKey === "protected" && control.enabled) {
      cons.hidden = false;
      cons.textContent = "Desconectar no pasa a salida directa: bloquea todas las consultas del MCP y, con el bloqueo sin VPN, también la red de los agentes y de su LLM.";
    } else {
      cons.hidden = true;
    }
    const ro = $("ring-readonly");
    ro.hidden = control.enabled || !S.data;
    ro.textContent = control.reason ? `Solo lectura: ${control.reason}` : "";

    const when = ring.checked_at ? new Date(ring.checked_at * 1000) : null;
    $("ring-checked-at").textContent = when
      ? `Comprobado a las ${when.toLocaleTimeString("es-ES")} por el servidor · caduca a los 15 s`
      : "Aún sin comprobar";
    const rel = ring.relays || {};
    $("ring-relays-meta").textContent = rel.count
      ? `${rel.count} servidores propios y online (${rel.source === "live" ? "lista viva" : rel.source === "cache" ? "lista en caché" : "instantánea empaquetada"})`
      : "";

    if (announce && stKey !== S.lastState) $("ring-live").textContent = st.title;
    S.lastState = stKey;
  }

  async function refresh() {
    if (document.body.dataset.auth !== "authenticated" && document.body.dataset.auth !== "disabled") {
      // Sin sesión no hay estado: no se inventa nada.
      return;
    }
    try {
      const res = await fetch("/api/egress/ring", { headers: { Accept: "application/json" } });
      if (res.status === 401) return;
      const data = await res.json();
      if (data && data.ok) {
        S.data = data;
        S.fetchedAt = Date.now();
      }
    } catch (_e) {
      S.data = null;
      S.fetchedAt = S.fetchedAt || Date.now();
    }
    render(true);
  }

  function schedule() {
    clearInterval(S.timer);
    S.timer = setInterval(() => {
      if (!document.hidden) refresh();
      else render(false);
    }, POLL_MS);
  }

  // ---------------------------------------------------------------------------------------------- acciones
  async function post(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body || {}),
    });
    let data = {};
    try { data = await res.json(); } catch (_e) { data = { ok: false, error: `Respuesta inválida (${res.status})` }; }
    return { status: res.status, data };
  }

  async function runOp(label, fn) {
    if (S.busy) return;
    S.busy = true;
    $("ring-live").textContent = label;
    render(false);
    try {
      const { status, data } = await fn();
      if (data && data.ring) {
        S.data = data;
        S.fetchedAt = Date.now();
      }
      if (status >= 400 || !data.ok) {
        notify(data.error || `La operación falló (${status}).`, "error");
      }
      return { status, data };
    } catch (_e) {
      notify("No se pudo contactar con el servidor del panel.", "error");
      return { status: 0, data: {} };
    } finally {
      S.busy = false;
      render(true);
      refresh();
    }
  }

  function notify(msg, kind) {
    if (typeof window.showToast === "function") window.showToast(msg, kind === "error" ? "error" : "ok");
    $("ring-live").textContent = msg;
  }

  // Diálogo de confirmación con reautenticación (contraseña de hace < 5 min en el servidor).
  function confirmReduce(title, text, okLabel) {
    return new Promise((resolve) => {
      const d = $("ring-dlg-auth");
      const needPw = !(S.data && S.data.reauth_fresh);
      $("ring-auth-h").textContent = title;
      $("ring-auth-p").textContent = text;
      $("ring-auth-ok").textContent = okLabel;
      $("ring-auth-pw").value = "";
      $("ring-auth-err").textContent = "";
      $("ring-auth-pw-row").hidden = !needPw;
      $("ring-auth-pw").required = needPw;
      const form = $("ring-auth-form");
      const done = (v) => {
        form.onsubmit = null;
        $("ring-auth-cancel").onclick = null;
        d.oncancel = null;
        if (d.open) d.close();
        resolve(v);
      };
      $("ring-auth-cancel").onclick = () => done(null);
      d.oncancel = () => done(null);
      form.onsubmit = (e) => {
        e.preventDefault();
        done({ password: needPw ? $("ring-auth-pw").value : "" });
      };
      d.showModal();
      (needPw ? $("ring-auth-pw") : $("ring-auth-ok")).focus();
    });
  }

  async function withReauth(title, text, okLabel, url, body) {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const answer = await confirmReduce(title, text, okLabel);
      if (!answer) return;
      const r = await runOp(title, () => post(url, { ...body, password: answer.password }));
      if (!(r.data && r.data.reauth_required)) return;
      text = `${r.data.error || "Contraseña incorrecta."} ${r.data.remaining_attempts != null ? `Quedan ${r.data.remaining_attempts} intentos.` : ""}`;
      if (r.status === 429) return;
    }
  }

  async function loadRelays() {
    if (S.relays) return S.relays;
    const res = await fetch("/api/egress/ring/relays");
    const data = await res.json();
    S.relays = Array.isArray(data.relays) ? data.relays : [];
    return S.relays;
  }

  async function pickRelay(role) {
    const relays = await loadRelays();
    const ring = (S.data && S.data.ring) || {};
    const cur = host(role === "exit" ? ring.exit : ring.entry);
    const other = host(role === "exit" ? ring.entry : ring.exit);
    return new Promise((resolve) => {
      const d = $("ring-dlg-relay");
      $("ring-relay-h").textContent = role === "exit" ? "Servidor de salida" : "Servidor de entrada (multihop)";
      const draw = (q) => {
        const needle = q.trim().toLowerCase();
        const groups = {};
        relays
          .filter((r) => !needle || [r.hostname, r.country, r.city, CITY_ES[r.city] || ""].join(" ").toLowerCase().includes(needle))
          .forEach((r) => { (groups[`${r.country} · ${CITY_ES[r.city] || r.city}`] ||= []).push(r); });
        const keys = Object.keys(groups);
        $("ring-relay-list").innerHTML = keys.length
          ? keys.map((g) => `<div class="ring-relay-group">${esc(g)}</div>` + groups[g].map((r) => {
              const isOther = r.hostname === other;
              return `<label class="ring-relay"><input type="radio" name="ring-relay" value="${esc(r.hostname)}"` +
                `${r.hostname === cur ? " checked" : ""}${isOther ? " disabled" : ""}>` +
                `<span class="mono">${esc(r.hostname)}</span>` +
                (isOther ? `<span class="ring-tag">en uso como ${role === "exit" ? "entrada" : "salida"}</span>` : "") +
                "</label>";
            }).join("")).join("")
          : `<p class="ring-empty">Ningún servidor propio coincide con «${esc(q)}».</p>`;
      };
      draw("");
      $("ring-relay-q").value = "";
      $("ring-relay-q").oninput = (e) => draw(e.target.value);
      $("ring-relay-meta").textContent = `${relays.length} servidores propios y online. El servidor revalida la elección antes de aplicarla.`;
      const form = $("ring-relay-form");
      const done = (v) => {
        form.onsubmit = null;
        d.oncancel = null;
        if (d.open) d.close();
        resolve(v);
      };
      $("ring-relay-cancel").onclick = () => done(null);
      d.oncancel = () => done(null);
      form.onsubmit = (e) => {
        e.preventDefault();
        const v = new FormData(form).get("ring-relay");
        done(v && v !== cur ? String(v) : null);
      };
      d.showModal();
      $("ring-relay-q").focus();
    });
  }

  const ACT = {
    connect: () => runOp("Conectando…", () => post("/api/egress/ring/connect")),
    reconnect: () => runOp("Reconectando…", () => post("/api/egress/ring/connect")),
    recheck: () => refresh(),
    disconnect: () => withReauth(
      "¿Desconectar Mullvad?",
      "El MCP cierra primero su compuerta. Después Mullvad se desconecta y, con el bloqueo sin VPN activo, todo el equipo queda sin red: también los agentes. Nunca se pasa a salida directa.",
      "Desconectar y bloquear",
      "/api/egress/ring/disconnect",
      {},
    ),
    exit: async () => {
      const h = await pickRelay("exit");
      if (!h) return;
      await withReauth("Cambiar servidor de salida", `Nuevo servidor de salida: ${h}. Durante el cambio el MCP bloquea las consultas.`, "Cambiar", "/api/egress/ring/relay", { role: "exit", hostname: h });
    },
    entry: async () => {
      const h = await pickRelay("entry");
      if (!h) return;
      await withReauth("Cambiar servidor de entrada", `Nuevo servidor de entrada: ${h}. Durante el cambio el MCP bloquea las consultas.`, "Cambiar", "/api/egress/ring/relay", { role: "entry", hostname: h });
    },
    audit: () => {
      const btn = document.querySelector(".action-switch-log-egress");
      if (btn) {
        btn.click();
        btn.scrollIntoView({ block: "nearest" });
        btn.focus();
      }
    },
  };

  // ---------------------------------------------------------------------------------------------- menú accesible
  function initMenu() {
    const menu = $("ring-menu");
    const mbtn = $("ring-menu-btn");
    const items = () => [...menu.querySelectorAll('[role="menuitem"]:not(:disabled)')];
    const open = () => {
      const st = currentState();
      const control = (S.data && S.data.control) || {};
      const live = control.enabled && ["protected", "rented", "unverified"].includes(st);
      menu.querySelector('[data-act="reconnect"]').disabled = !live;
      menu.querySelector('[data-act="exit"]').disabled = !live;
      menu.querySelector('[data-act="entry"]').disabled = !live;
      menu.hidden = false;
      mbtn.setAttribute("aria-expanded", "true");
      const first = items()[0];
      if (first) first.focus();
    };
    const close = (focusBtn) => {
      menu.hidden = true;
      mbtn.setAttribute("aria-expanded", "false");
      if (focusBtn) mbtn.focus();
    };
    mbtn.addEventListener("click", () => (menu.hidden ? open() : close(true)));
    menu.addEventListener("keydown", (e) => {
      const it = items();
      const i = it.indexOf(document.activeElement);
      if (e.key === "ArrowDown") { e.preventDefault(); it[(i + 1) % it.length].focus(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); it[(i - 1 + it.length) % it.length].focus(); }
      else if (e.key === "Home") { e.preventDefault(); it[0].focus(); }
      else if (e.key === "End") { e.preventDefault(); it[it.length - 1].focus(); }
      else if (e.key === "Escape") { e.preventDefault(); close(true); }
      else if (e.key === "Tab") { close(false); }
    });
    menu.addEventListener("click", (e) => {
      const b = e.target.closest("[data-act]");
      if (!b || b.disabled) return;
      close(false);
      ACT[b.dataset.act]();
    });
    document.addEventListener("click", (e) => {
      if (!menu.hidden && !menu.contains(e.target) && e.target !== mbtn) close(false);
    });
  }

  function init() {
    if (!$("ring-panel")) return;
    initMenu();
    $("ring-primary").addEventListener("click", () => {
      const a = $("ring-primary").dataset.act;
      if (a && ACT[a]) ACT[a]();
    });
    const hud = $("hud-egress");
    if (hud) {
      hud.addEventListener("click", () => {
        if (typeof window.switchTab === "function") window.switchTab("overview");
        const target = $("ring-primary").hidden ? $("ring-menu-btn") : $("ring-primary");
        $("ring-panel").scrollIntoView({ block: "start" });
        target.focus();
      });
    }
    document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
    render(false);
    refresh();
    schedule();
  }

  window.EgressRing = { refresh, render: () => render(false) };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
