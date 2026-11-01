# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-11-01

### Added
- **20 MCP tools** covering cases, entities, links, transforms, Machines, an investigation copilot and import/export.
- **30 built-in transforms**: 18 keyless (DNS over HTTPS, RDAP/WHOIS, crt.sh, Team Cymru ASN, profile lookup,
  email/URL parsing) and 12 provider transforms enabled by API key (VirusTotal, Shodan, SecurityTrails, Censys,
  Hunter.io, Have I Been Pwned, GreyNoise, Tatum).
- **Machines**: DomainRecon, InfrastructureRecon, EmailRecon, CompanyFootprint, PersonalFootprint, URLRecon and
  custom Machines in TOML, with recursive rounds and cost budgets.
- **Copilot**: procedural memory per case, provenance, explainable scoring, next-best-action and outcome learning.
- **Maltego Desktop integration**: local transforms bridge (open case, neighbours, save), native `.mtgx` with
  hierarchical/radial/force layouts and embedded memory, ontology import from your Maltego (`.mtz`).
- **Reports** in Markdown and self-contained HTML.
- **`maltegoctl`** CLI: inspect `.mtgx`, quick lookups, transforms, ontology import, export, `.mtz` generation.
- **npm package `mcp-maltego`**: `npx -y mcp-maltego` runs the server (Python runtime managed by uv).
- Automatic MCP registration for Claude Code, Copilot CLI, Gemini CLI, Qwen Code, Codex, Cursor and OpenCode.

### Security
- OSINT data treated as untrusted; XML parsed with defusedxml; bounded archive reads (zip-bomb safe); API keys
  never logged; CSV formula-injection protection.

## [0.1.0] - 2026-10-31

### Added
- First MCP server skeleton, graph backends (memory and Cosmos DB Gremlin), Maltego TRX protocol support.

[0.2.0]: https://github.com/Data-Unix/MCP-MALTEGO/releases/tag/v0.2.0
[0.1.0]: https://github.com/Data-Unix/MCP-MALTEGO/commits/v0.1.0
