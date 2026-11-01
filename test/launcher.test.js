"use strict";
// Tests del lanzador npm (node --test). No necesitan red ni uv.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { buildInvocation, findUv, ensureEnvTemplate, COMMANDS } = require("../bin/mcp-maltego.js");

const ROOT = path.resolve(__dirname, "..");
const BIN = path.join(ROOT, "bin", "mcp-maltego.js");
const PKG = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));

test("servidor por defecto con entorno fijado por versión", () => {
  const { uvArgs, env } = buildInvocation(["--transport", "http"], { MALTEGO_MCP_HOME: "/tmp/h" });
  assert.deepEqual(uvArgs, ["run", "--quiet", "--no-config", "--frozen", "--no-dev", "--project", ROOT, "maltego-mcp", "--transport", "http"]);
  assert.equal(env.UV_PROJECT_ENVIRONMENT, path.join("/tmp/h", "runtime", `v${PKG.version}`));
  assert.equal(env.PYTHONUTF8, "1");
});

test("subcomandos ctl y bridge", () => {
  assert.equal(buildInvocation(["ctl", "inspect", "a.mtgx"]).uvArgs.slice(7).join(" "), "maltegoctl inspect a.mtgx");
  assert.equal(buildInvocation(["bridge", "local", "x"]).uvArgs[7], "maltego-mcp-bridge");
  assert.deepEqual(Object.keys(COMMANDS).sort(), ["bridge", "ctl"]);
});

test("mtz apunta al paquete instalado", () => {
  const { uvArgs } = buildInvocation(["ctl", "mtz"]);
  assert.deepEqual(uvArgs.slice(-2), ["--repo", ROOT]);
  assert.ok(!buildInvocation(["ctl", "mtz", "--repo", "x"]).uvArgs.includes(ROOT + "x"));
});

test("--version no necesita uv", () => {
  const r = spawnSync(process.execPath, [BIN, "--version"], { encoding: "utf8" });
  assert.equal(r.status, 0);
  assert.equal(r.stdout.trim(), PKG.version);
});

test("sin uv da instrucciones y código 127, sin tocar stdout", () => {
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), "nouv-"));
  const env = { PATH: empty, HOME: empty, USERPROFILE: empty, LOCALAPPDATA: empty };
  const r = spawnSync(process.execPath, [BIN], { encoding: "utf8", env });
  assert.equal(r.status, 127);
  assert.equal(r.stdout, "");
  assert.match(r.stderr, /necesita uv/);
});

test("server.json y package.json coherentes", () => {
  const server = JSON.parse(fs.readFileSync(path.join(ROOT, "server.json"), "utf8"));
  assert.equal(server.name, PKG.mcpName);
  assert.equal(server.version, PKG.version);
  assert.equal(server.packages[0].identifier, PKG.name);
  assert.equal(server.packages[0].version, PKG.version);
  assert.ok(server.description.length <= 100);
});

test("findUv localiza uv en MALTEGO_MCP_HOME/bin y ensureEnvTemplate no sobrescribe", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-home-"));
  const binDir = path.join(tmp, "bin");
  fs.mkdirSync(binDir, { recursive: true });
  const exe = process.platform === "win32" ? "uv.exe" : "uv";
  const fakeUv = path.join(binDir, exe);
  fs.writeFileSync(fakeUv, "fake");
  const env = { MALTEGO_MCP_HOME: tmp, PATH: "", HOME: tmp, USERPROFILE: tmp, LOCALAPPDATA: "" };
  assert.equal(findUv(env), fakeUv);
  const first = ensureEnvTemplate(tmp);
  assert.equal(first.created, true);
  fs.writeFileSync(first.path, "SHODAN_API_KEY=123\n");
  const second = ensureEnvTemplate(tmp);
  assert.equal(second.created, false);
  assert.match(fs.readFileSync(first.path, "utf8"), /SHODAN_API_KEY=123/);
});
