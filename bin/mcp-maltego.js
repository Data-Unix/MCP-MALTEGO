#!/usr/bin/env node
/**
 * mcp-maltego: lanzador npm del servidor MCP de Maltego (Python).
 *
 *   npx mcp-maltego                    servidor MCP por stdio (lo que configuran los agentes)
 *   npx mcp-maltego --transport http   servidor Streamable HTTP en 127.0.0.1:8000/mcp
 *   npx mcp-maltego ctl <comando>      maltegoctl (inspect, lookup, transforms, import-entities, index-breaches, export, mtz)
 *   npx mcp-maltego bridge <comando>   puente de transforms locales para Maltego Desktop
 *   npx mcp-maltego doctor             comprueba requisitos, auto-instala uv si falta y prepara el entorno
 *   npx mcp-maltego setup [opciones]   despliegue autónomo (runtime, ~/.maltego-mcp/.env, .mtz y comandos globales en PATH)
 *     --mode global|local|npx|http     modo de despliegue (por defecto: global, ejecutable desde cualquier ruta)
 *     --client all|claude|gemini|codex|copilot|cursor  muestra configuración lista para el cliente elegido
 *     --bin-dir <ruta>                 directorio donde instalar los shims globales (por defecto: ~/.local/bin)
 *
 * Requisito único: uv (https://docs.astral.sh/uv/). Si no está instalado, mcp-maltego intenta instalarlo de forma
 * autónoma en ~/.maltego-mcp/bin. uv descarga Python 3.12 si hace falta e instala las dependencias exactas de
 * uv.lock en un entorno por versión dentro de ~/.maltego-mcp (no escribe en node_modules).
 * MCP_MALTEGO_UV permite indicar la ruta de uv: ejecuta ese binario, así que solo debe apuntar a un uv de confianza.
 * stdout se reserva al protocolo MCP: todos los mensajes del lanzador van a stderr.
 */
"use strict";

const { spawn, spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const PKG_ROOT = path.resolve(__dirname, "..");
const BIN_SCRIPT = path.join(PKG_ROOT, "bin", "mcp-maltego.js");
const PKG = JSON.parse(fs.readFileSync(path.join(PKG_ROOT, "package.json"), "utf8"));
const IS_WIN = process.platform === "win32";

const COMMANDS = { ctl: "maltegoctl", bridge: "maltego-mcp-bridge" };
const SHIM_ENTRIES = [
  { name: "mcp-maltego", subargs: "" },
  { name: "maltego-mcp", subargs: "" },
  { name: "maltegoctl", subargs: "ctl" },
  { name: "maltego-mcp-bridge", subargs: "bridge" },
];

function home(env = process.env) {
  return env.MALTEGO_MCP_HOME || path.join(os.homedir(), ".maltego-mcp");
}

function defaultGlobalBinDir(env = process.env) {
  const h = env.USERPROFILE || env.HOME || os.homedir();
  return path.join(h, ".local", "bin");
}

function isFile(p) {
  try {
    return Boolean(p) && fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

function uvCandidates(env = process.env) {
  const exe = IS_WIN ? "uv.exe" : "uv";
  const list = [];
  if (env.MCP_MALTEGO_UV) list.push(env.MCP_MALTEGO_UV);
  for (const dir of (env.PATH || "").split(path.delimiter)) {
    if (dir) list.push(path.join(dir, exe));
  }
  const h = env.HOME || env.USERPROFILE || os.homedir();
  list.push(
    path.join(home(env), "bin", exe),
    path.join(h, ".local", "bin", exe),
    path.join(h, ".cargo", "bin", exe),
  );
  if (IS_WIN && env.LOCALAPPDATA) list.push(path.join(env.LOCALAPPDATA, "uv", exe));
  return list;
}

function findUv(env = process.env) {
  return uvCandidates(env).find(isFile);
}

function hasInPath(binName, env = process.env) {
  return (env.PATH || "")
    .split(path.delimiter)
    .some((dir) => dir && isFile(path.join(dir, binName)));
}

function installHint() {
  return IS_WIN
    ? 'powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"'
    : "curl -LsSf https://astral.sh/uv/install.sh | sh";
}

/** Instala uv automáticamente en <home>/bin si falta y hay herramientas de sistema disponibles. */
function ensureUv(env = process.env) {
  const existing = findUv(env);
  if (existing || env.MCP_MALTEGO_NO_AUTO_UV === "1") return existing;
  const requiredTool = IS_WIN ? "powershell.exe" : "curl";
  if (!hasInPath(requiredTool, env)) return undefined;
  const targetDir = path.join(home(env), "bin");
  try {
    fs.mkdirSync(targetDir, { recursive: true });
  } catch {
    return undefined;
  }
  process.stderr.write(`mcp-maltego: instalando uv automáticamente en ${targetDir}...\n`);
  const installEnv = { ...env, UV_INSTALL_DIR: targetDir, UV_NO_MODIFY_PATH: "1" };
  const cmd = IS_WIN ? "powershell.exe" : "sh";
  const cmdArgs = IS_WIN
    ? ["-NoProfile", "-ExecutionPolicy", "ByPass", "-Command", "irm https://astral.sh/uv/install.ps1 | iex"]
    : ["-c", "curl -LsSf https://astral.sh/uv/install.sh | sh"];
  spawnSync(cmd, cmdArgs, { env: installEnv, stdio: ["ignore", "pipe", "pipe"], timeout: 120000 });
  return findUv(env);
}

/** Construye la invocación de uv (exportado para tests). */
function buildInvocation(argv, env = process.env) {
  let command = "maltego-mcp";
  let args = argv.slice();
  if (args[0] && COMMANDS[args[0]]) {
    command = COMMANDS[args[0]];
    args = args.slice(1);
  }
  const venv = path.join(home(env), "runtime", `v${PKG.version}`);
  // --no-config: ignora uv.toml/pyproject del directorio desde el que lanza el cliente MCP (aislamiento).
  const uvArgs = ["run", "--quiet", "--no-config", "--frozen", "--no-dev", "--project", PKG_ROOT, command, ...args];
  if (command === "maltegoctl" && args[0] === "mtz" && !args.includes("--repo")) {
    uvArgs.push("--repo", PKG_ROOT);
  }
  return {
    uvArgs,
    env: { ...env, UV_PROJECT_ENVIRONMENT: venv, PYTHONUTF8: "1", PYTHONIOENCODING: "utf-8" },
  };
}

function ensureEnvTemplate(homeDir) {
  const envFile = path.join(homeDir, ".env");
  if (isFile(envFile)) return { path: envFile, created: false };
  fs.mkdirSync(homeDir, { recursive: true });
  const content = [
    "# MCP Maltego — claves opcionales de proveedores (con plan gratuito).",
    "# Este fichero está fuera de cualquier repositorio y lo cargan automáticamente todos los agentes.",
    "VIRUSTOTAL_API_KEY=",
    "SHODAN_API_KEY=",
    "HUNTER_API_KEY=",
    "GREYNOISE_API_KEY=",
    "SECURITYTRAILS_API_KEY=",
    "TATUM_API_KEY=",
    "CENSYS_API_ID=",
    "CENSYS_API_SECRET=",
    "HIBP_API_KEY=",
    "GITHUB_TOKEN=",
    "REDDIT_SESSION_COOKIE=",
    "TOR_SOCKS_PROXY=",
    "",
  ].join("\n");
  fs.writeFileSync(envFile, content, { encoding: "utf8", mode: 0o600 });
  return { path: envFile, created: true };
}

function ensureAccountsTemplate(homeDir) {
  const accFile = path.join(homeDir, "accounts.toml");
  if (isFile(accFile)) return { path: accFile, created: false };
  fs.mkdirSync(homeDir, { recursive: true });
  const content = [
    "# MCP Maltego — Cuentas de redes sociales y Sock Puppets (~/.maltego-mcp/accounts.toml)",
    "# Genera perfiles operativos con: maltegoctl accounts generate-persona --save",
    "",
    "# [[accounts]]",
    '# platform = "github"',
    '# username = "sockpuppet_sec_01"',
    '# token = "<token_personal>"',
    "# enabled = true",
    "",
  ].join("\n");
  fs.writeFileSync(accFile, content, { encoding: "utf8", mode: 0o600 });
  return { path: accFile, created: true };
}

/**
 * Crea lanzadores globales multiplataforma (mcp-maltego, maltego-mcp, maltegoctl, maltego-mcp-bridge)
 * en `binDir` (~/.local/bin) para poder ejecutar el MCP y su CLI desde cualquier ruta o terminal.
 */
function installGlobalShims(binDir = defaultGlobalBinDir(), isWin = IS_WIN) {
  fs.mkdirSync(binDir, { recursive: true });
  const created = [];
  for (const entry of SHIM_ENTRIES) {
    const sub = entry.subargs ? ` ${entry.subargs}` : "";
    if (isWin) {
      const cmdPath = path.join(binDir, `${entry.name}.cmd`);
      const cmdContent = `@echo off\r\nnode "${BIN_SCRIPT}"${sub} %*\r\n`;
      fs.writeFileSync(cmdPath, cmdContent, "utf8");
      const ps1Path = path.join(binDir, `${entry.name}.ps1`);
      const psSub = entry.subargs ? `"${entry.subargs}" ` : "";
      const ps1Content = `& node "${BIN_SCRIPT}" ${psSub}@args\r\nexit $LASTEXITCODE\r\n`;
      fs.writeFileSync(ps1Path, ps1Content, "utf8");
      created.push(cmdPath, ps1Path);
    } else {
      const shPath = path.join(binDir, entry.name);
      const shContent = `#!/usr/bin/env sh\nexec node "${BIN_SCRIPT}"${sub} "$@"\n`;
      fs.writeFileSync(shPath, shContent, { encoding: "utf8", mode: 0o755 });
      try {
        fs.chmodSync(shPath, 0o755);
      } catch {
        // Ignorar en sistemas de ficheros sin permisos POSIX
      }
      created.push(shPath);
    }
  }
  return { binDir, files: created };
}

/** Asegura que `binDir` esté en el PATH de usuario (Windows User PATH + perfiles PowerShell o POSIX rc). */
function ensureUserPath(binDir = defaultGlobalBinDir(), env = process.env, isWin = IS_WIN) {
  const pathList = (env.PATH || "").split(path.delimiter).map((p) => p.trim().toLowerCase());
  const alreadyInProcess = pathList.includes(binDir.toLowerCase());
  const updated = [];

  if (isWin) {
    if (hasInPath("powershell.exe", env) && env.MCP_MALTEGO_SKIP_WIN_USER_PATH !== "1") {
      const psCmd = [
        `$target = '${binDir.replace(/'/g, "''")}'`,
        "$u = [Environment]::GetEnvironmentVariable('Path', 'User')",
        "$parts = if ($u) { $u -split ';' } else { @() }",
        "if (-not ($parts | Where-Object { $_.TrimEnd('\\') -ieq $target.TrimEnd('\\') })) {",
        "  $newPath = (($parts + $target) | Where-Object { $_ }) -join ';'",
        "  [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')",
        "}",
      ].join("; ");
      spawnSync("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "ByPass", "-Command", psCmd], {
        stdio: "ignore",
        timeout: 15000,
      });
      updated.push("User PATH (Windows Registry)");
    }
    const homeUser = env.USERPROFILE || os.homedir();
    const psProfiles = [
      path.join(homeUser, "Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1"),
      path.join(homeUser, "Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
    ];
    const marker = "# mcp-maltego global bin";
    const snippet = `\r\n${marker}\r\nif ($env:PATH -notlike "*${binDir}*") { $env:PATH = "${binDir};$env:PATH" }\r\n`;
    for (const prof of psProfiles) {
      try {
        fs.mkdirSync(path.dirname(prof), { recursive: true });
        const existing = isFile(prof) ? fs.readFileSync(prof, "utf8") : "";
        if (!existing.includes(marker) && !existing.includes(binDir)) {
          fs.writeFileSync(prof, existing + snippet, "utf8");
          updated.push(prof);
        }
      } catch {
        // Ignorar si Documents está protegido por Controlled Folder Access
      }
    }
  } else {
    const homeUser = env.HOME || os.homedir();
    const rcFiles = [path.join(homeUser, ".bashrc"), path.join(homeUser, ".zshrc"), path.join(homeUser, ".profile")];
    const marker = "# mcp-maltego global bin";
    const line = `\n${marker}\nexport PATH="${binDir}:$PATH"\n`;
    for (const rc of rcFiles) {
      try {
        if (isFile(rc) || rc.endsWith(".profile")) {
          const existing = isFile(rc) ? fs.readFileSync(rc, "utf8") : "";
          if (!existing.includes(marker) && !existing.includes(binDir)) {
            fs.writeFileSync(rc, existing + line, "utf8");
            updated.push(rc);
          }
        }
      } catch {
        // Ignorar errores de escritura en perfiles opcionales
      }
    }
  }
  return { binDir, alreadyInProcess, updated };
}

function parseSetupOptions(argv) {
  let mode = "global";
  let client = "all";
  let binDir = "";
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--no-global" || a === "--local") mode = "local";
    else if (a === "--global") mode = "global";
    else if (a === "--http") mode = "http";
    else if (a === "--mode" && argv[i + 1]) {
      mode = argv[i + 1].toLowerCase();
      i += 1;
    } else if (a.startsWith("--mode=")) {
      mode = a.split("=", 2)[1].toLowerCase();
    } else if (a === "--client" && argv[i + 1]) {
      client = argv[i + 1].toLowerCase();
      i += 1;
    } else if (a.startsWith("--client=")) {
      client = a.split("=", 2)[1].toLowerCase();
    } else if (a === "--bin-dir" && argv[i + 1]) {
      binDir = argv[i + 1];
      i += 1;
    } else if (a.startsWith("--bin-dir=")) {
      binDir = a.split("=", 2)[1];
    }
  }
  if (!["global", "local", "npx", "http"].includes(mode)) mode = "global";
  return { mode, client, binDir };
}

function clientConfigSnippet(client = "all", mode = "global") {
  const cmdBlock =
    mode === "global"
      ? `{ "mcpServers": { "maltego": { "command": "mcp-maltego" } } }`
      : `{ "mcpServers": { "maltego": { "command": "npx", "args": ["-y", "mcp-maltego"] } } }`;
  const lines = [
    "Opciones de despliegue y uso desde cualquier ruta (Windows PowerShell, macOS y Linux):",
    "  [1] CLI global (cualquier directorio):   maltegoctl transforms | maltego-mcp | mcp-maltego doctor",
    "  [2] Lanzador autónomo npm (sin instalar): npx -y mcp-maltego",
    "  [3] Servidor remoto Streamable HTTP:      mcp-maltego --transport http --port 8000",
  ];
  if (client === "all" || client === "claude") {
    lines.push("  • Claude Code:   claude mcp add maltego -- npx -y mcp-maltego");
  }
  if (client === "all" || client === "codex") {
    lines.push("  • Codex CLI:     codex mcp add maltego -- npx -y mcp-maltego");
  }
  if (client === "all" || client === "gemini" || client === "cursor" || client === "copilot") {
    lines.push(`  • JSON estándar: ${cmdBlock}`);
  }
  return lines.join("\n");
}

function doctor(runSetup = false, setupArgv = []) {
  const out = (msg) => process.stderr.write(msg + "\n");
  const opts = parseSetupOptions(setupArgv);
  const homeDir = home();
  out(`mcp-maltego ${PKG.version}`);
  out(`  paquete:  ${PKG_ROOT}`);
  out(`  datos:    ${homeDir}`);
  out(`  node:     ${process.version} (${process.platform}/${process.arch})`);
  const uv = ensureUv();
  if (!uv) {
    out("  uv:       NO ENCONTRADO");
    out(`  Instálalo con:  ${installHint()}`);
    return 1;
  }
  const v = spawnSync(uv, ["--version"], { encoding: "utf8" });
  out(`  uv:       ${uv} (${(v.stdout || "").trim() || "versión desconocida"})`);
  const { uvArgs, env } = buildInvocation(["ctl", "transforms"]);
  const runEnv = { ...env, MCP_MALTEGO_UV: uv };
  out("  Preparando el entorno Python (la primera vez puede tardar un minuto)...");
  const r = spawnSync(uv, uvArgs, { env: runEnv, encoding: "utf8" });
  if (r.status !== 0) {
    out("  Python:   ERROR\n" + (r.stderr || "").trim());
    return 1;
  }
  const transforms = (r.stdout || "").split("\n").filter((l) => l.trim() && !l.startsWith("TRANSFORM")).length;
  out(`  Python:   OK (${transforms} líneas de inventario de transforms)`);
  if (runSetup) {
    const tpl = ensureEnvTemplate(homeDir);
    out(`  .env:     ${tpl.path} (${tpl.created ? "creado" : "ya existía"})`);
    const accTpl = ensureAccountsTemplate(homeDir);
    out(`  cuentas:  ${accTpl.path} (${accTpl.created ? "creado" : "ya existía"})`);
    const mtzInv = buildInvocation(["ctl", "mtz"]);
    const mtzRes = spawnSync(uv, mtzInv.uvArgs, { env: { ...mtzInv.env, MCP_MALTEGO_UV: uv }, encoding: "utf8" });
    if (mtzRes.status === 0) {
      out(`  Maltego:  ${path.join(homeDir, "maltego-mcp-local.mtz")} listo para importar`);
    }
    if (opts.mode === "global" || opts.mode === "http") {
      const targetBin = opts.binDir || defaultGlobalBinDir();
      const shims = installGlobalShims(targetBin);
      const pathStatus = ensureUserPath(targetBin);
      out(`  CLI PATH: ${shims.binDir} (comandos: mcp-maltego, maltego-mcp, maltegoctl, maltego-mcp-bridge)`);
      if (IS_WIN && !pathStatus.alreadyInProcess) {
        out(
          `  PowerShell (sesión actual): $env:PATH = "${targetBin};$env:PATH" (en nuevas terminales ya está activo)`,
        );
      }
    }
    out("\n" + clientConfigSnippet(opts.client, opts.mode));
  }
  out("\nTodo listo. Configura tu agente con: npx -y mcp-maltego (o ejecuta 'maltegoctl transforms' desde cualquier ruta)");
  return 0;
}

function main() {
  const argv = process.argv.slice(2);
  if (argv[0] === "--version" || argv[0] === "-v") {
    process.stdout.write(`${PKG.version}\n`);
    return;
  }
  if (argv[0] === "doctor" || argv[0] === "setup") {
    process.exitCode = doctor(argv[0] === "setup", argv.slice(1));
    return;
  }
  const uv = ensureUv();
  if (!uv) {
    process.stderr.write(
      `mcp-maltego necesita uv y no lo encuentra.\nInstálalo con:\n  ${installHint()}\n` +
        "y vuelve a abrir la terminal (o define MCP_MALTEGO_UV con la ruta completa de uv).\n",
    );
    process.exit(127);
  }
  const { uvArgs, env } = buildInvocation(argv);
  const child = spawn(uv, uvArgs, { stdio: "inherit", env: { ...env, MCP_MALTEGO_UV: uv } });
  for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => child.kill(sig));
  child.on("exit", (code, signal) => process.exit(signal ? 1 : (code ?? 0)));
  child.on("error", (err) => {
    process.stderr.write(`No se pudo lanzar uv (${err.message}).\n`);
    process.exit(127);
  });
}

if (require.main === module) {
  main();
}

module.exports = {
  buildInvocation,
  findUv,
  ensureUv,
  ensureEnvTemplate,
  installGlobalShims,
  ensureUserPath,
  parseSetupOptions,
  clientConfigSnippet,
  COMMANDS,
};
