#!/usr/bin/env node
/**
 * mcp-maltego: lanzador npm del servidor MCP de Maltego (Python).
 *
 *   npx mcp-maltego                    servidor MCP por stdio (lo que configuran los agentes)
 *   npx mcp-maltego --transport http   servidor Streamable HTTP en 127.0.0.1:8000/mcp
 *   npx mcp-maltego ctl <comando>      maltegoctl (inspect, lookup, transforms, import-entities, export, mtz)
 *   npx mcp-maltego bridge <comando>   puente de transforms locales para Maltego Desktop
 *   npx mcp-maltego doctor             comprueba requisitos y rutas
 *
 * Requisito único: uv (https://docs.astral.sh/uv/). uv descarga Python 3.12 si hace falta e instala las
 * dependencias exactas de uv.lock en un entorno por versión dentro de ~/.maltego-mcp (no escribe en node_modules).
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

function home() {
  return process.env.MALTEGO_MCP_HOME || path.join(os.homedir(), ".maltego-mcp");
}

function uvCandidates() {
  const exe = IS_WIN ? "uv.exe" : "uv";
  const list = [];
  if (process.env.MCP_MALTEGO_UV) list.push(process.env.MCP_MALTEGO_UV);
  for (const dir of (process.env.PATH || "").split(path.delimiter)) {
    if (dir) list.push(path.join(dir, exe));
  }
  list.push(path.join(os.homedir(), ".local", "bin", exe), path.join(os.homedir(), ".cargo", "bin", exe));
  if (IS_WIN && process.env.LOCALAPPDATA) list.push(path.join(process.env.LOCALAPPDATA, "uv", exe));
  return list;
}

function findUv() {
  return uvCandidates().find((p) => {
    try {
      return fs.statSync(p).isFile();
    } catch {
      return false;
    }
  });
}

function installHint() {
  return IS_WIN
    ? 'powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"'
    : "curl -LsSf https://astral.sh/uv/install.sh | sh";
}

/** Construye la invocación de uv (exportado para tests). */
function buildInvocation(argv, env = process.env) {
  let command = "maltego-mcp";
  let args = argv.slice();
  if (args[0] && COMMANDS[args[0]]) {
    command = COMMANDS[args[0]];
    args = args.slice(1);
  }
  const venv = path.join(env.MALTEGO_MCP_HOME || home(), "runtime", `v${PKG.version}`);
  const uvArgs = ["run", "--quiet", "--frozen", "--no-dev", "--project", PKG_ROOT, command, ...args];
  if (command === "maltegoctl" && args[0] === "mtz" && !args.includes("--repo")) {
    uvArgs.push("--repo", PKG_ROOT);
  }
  return {
    uvArgs,
    env: { ...env, UV_PROJECT_ENVIRONMENT: venv, PYTHONUTF8: "1", PYTHONIOENCODING: "utf-8" },
  };
}

function doctor() {
  const out = (msg) => process.stderr.write(msg + "\n");
  out(`mcp-maltego ${PKG.version}`);
  out(`  paquete:  ${PKG_ROOT}`);
  out(`  datos:    ${home()}`);
  out(`  node:     ${process.version} (${process.platform}/${process.arch})`);
  const uv = findUv();
  if (!uv) {
    out("  uv:       NO ENCONTRADO");
    out(`  Instálalo con:  ${installHint()}`);
    return 1;
  }
  const v = spawnSync(uv, ["--version"], { encoding: "utf8" });
  out(`  uv:       ${uv} (${(v.stdout || "").trim() || "versión desconocida"})`);
  const { uvArgs, env } = buildInvocation(["ctl", "transforms"]);
  out("  Preparando el entorno Python (la primera vez puede tardar un minuto)...");
  const r = spawnSync(uv, uvArgs, { env, encoding: "utf8" });
  if (r.status !== 0) {
    out("  Python:   ERROR\n" + (r.stderr || "").trim());
    return 1;
  }
  const transforms = (r.stdout || "").split("\n").filter((l) => l.trim() && !l.startsWith("TRANSFORM")).length;
  out(`  Python:   OK (${transforms} líneas de inventario de transforms)`);
  out("Todo listo. Configura tu agente con: npx -y mcp-maltego");
  return 0;
}

function main() {
  const argv = process.argv.slice(2);
  if (argv[0] === "--version" || argv[0] === "-v") {
    process.stdout.write(`${PKG.version}\n`);
    return;
  }
  if (argv[0] === "doctor") {
    process.exitCode = doctor();
    return;
  }
  const uv = findUv();
  if (!uv) {
    process.stderr.write(
      `mcp-maltego necesita uv y no lo encuentra.\nInstálalo con:\n  ${installHint()}\n` +
        "y vuelve a abrir la terminal (o define MCP_MALTEGO_UV con la ruta completa de uv).\n",
    );
    process.exit(127);
  }
  const { uvArgs, env } = buildInvocation(argv);
  const child = spawn(uv, uvArgs, { stdio: "inherit", env });
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

module.exports = { buildInvocation, findUv, COMMANDS };
