# Installing mcp-maltego (guide for AI agents)

This file helps an AI coding agent (Cline, Claude, Cursor, Copilot, Gemini, Codex, …)
install and configure **mcp-maltego** automatically. `mcp-maltego` is a Model Context
Protocol (MCP) server that brings Maltego OSINT — transforms, reconnaissance Machines,
link-graph analysis and native `.mtgx` — to any MCP client.

## Requirements

- Node.js 18 or newer (for `npx`).
- No API keys are required for the core (33 keyless transforms). `uv` and the Python 3.12
  runtime are installed automatically on first run into `~/.maltego-mcp`.

## Quick install (recommended)

Run the one-command setup. It prepares the runtime, the `~/.maltego-mcp/.env` template,
the Maltego Desktop bridge and the CLI launchers:

```bash
npx -y mcp-maltego setup
```

## MCP client configuration (stdio)

Add this server to the MCP configuration of the client:

```json
{
  "mcpServers": {
    "maltego": {
      "command": "npx",
      "args": ["-y", "mcp-maltego"]
    }
  }
}
```

A ready-to-paste config for a specific client can be printed with:

```bash
npx -y mcp-maltego setup --client claude   # claude | gemini | codex | copilot | cursor | all
```

## Verify the installation

Ask the agent:

> Investigate example.com, give me the summary of the case and export it for Maltego.

The server runs real transforms and returns a case summary. No API key is needed for this.

## Optional API keys

Provider transforms (VirusTotal, Shodan, SecurityTrails, Censys, Hunter.io, Have I Been
Pwned, GreyNoise, Tatum) activate only when you add the corresponding key to
`~/.maltego-mcp/.env`. They are never required to start.

## Links

- Repository: https://github.com/Data-Unix/MCP-MALTEGO
- npm package: https://www.npmjs.com/package/mcp-maltego
- Usage guide: [docs/USO.md](docs/USO.md)
- Maltego integration: [docs/MALTEGO.md](docs/MALTEGO.md)
