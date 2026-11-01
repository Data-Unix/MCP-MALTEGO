#!/usr/bin/env node
/**
 * mcp-maltego: lanzador npm del servidor MCP de Maltego (Python).
 *
 *   npx mcp-maltego                    servidor MCP por stdio (lo que configuran los agentes)
 *   npx mcp-maltego --transport http   servidor Streamable HTTP en 127.0.0.1:8000/mcp
 *   npx mcp-maltego ctl <comando>      maltegoctl (inspect, lookup, transforms, import-entities, export, mtz)
 *   npx mcp-maltego bridge <comando>   puente de transforms locales para Maltego Desktop
 *   npx mcp-maltego doctor             comprueba requisitos, auto-instala uv si falta y prepara el entorno
 *   npx mcp-maltego setup              prepara entorno Python, plantilla ~/.maltego-mcp/.env y .mtz para Maltego
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
const PKG = JSON.parse(fs.readFileSync(path.join(PKG_ROOT, "package.json"), "utf8"));
const IS_WIN = process.platform === "win32";

const COMMANDS = { ctl: "maltegoctl", bridge: "maltego-mcp-bridge" };

function home(env = process.env) {
  return env.MALTEGO_MCP_HOME || path.join(os.homedir(), ".maltego-mcp");
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
    "",
  ].join("\n");
  fs.writeFileSync(envFile, content, { encoding: "utf8", mode: 0o600 });
  return { path: envFile, created: true };
}

function doctor(runSetup = false) {
  const out = (msg) => process.stderr.write(msg + "\n");
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
    const mtzInv = buildInvocation(["ctl", "mtz"]);
    const mtzRes = spawnSync(uv, mtzInv.uvArgs, { env: { ...mtzInv.env, MCP_MALTEGO_UV: uv }, encoding: "utf8" });
    if (mtzRes.status === 0) {
      out(`  Maltego:  ${path.join(homeDir, "maltego-mcp-local.mtz")} listo para importar`);
    }
  }
  out("Todo listo. Configura tu agente con: npx -y mcp-maltego");
  return 0;
}

function main() {
  const argv = process.argv.slice(2);
  if (argv[0] === "--version" || argv[0] === "-v") {
    process.stdout.write(`${PKG.version}\n`);
    return;
  }
  if (argv[0] === "doctor" || argv[0] === "setup") {
    process.exitCode = doctor(argv[0] === "setup");
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

module.exports = { buildInvocation, findUv, ensureUv, ensureEnvTemplate, COMMANDS };
