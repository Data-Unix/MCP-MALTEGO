# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **MCP directory metadata**: `smithery.yaml` (stdio launch descriptor for one-click install on Smithery) and `glama.json` (maintainer declaration for Glama.ai), plus MCP Registry and Glama score badges in both READMEs. Discoverability metadata only; no runtime or behavior changes.
- **Multi-Case Isolation & Modular Project Scoping**: Global project selector synchronized in the Topbar and live graph canvas, paired with per-module focus selectors (defaulting to `[Follow Active Case]`), strictly preventing cross-contamination between independent forensic cases.
- **Forensic Case Deletion & Atomic Purging**: Interactive confirmation modal for secure deletion of ad-hoc or temporary investigations, atomic purging of entities, edges, and step history from the graph store via `DELETE /api/cases/{case_id}`, and local cache/evidence destruction with automatic fallback.
- **Cryptoforensics & Blockchain AML Traceability**: Native cryptocurrency ontology (`maltego.CryptoCluster`, `maltego.VASPExchange`, `maltego.MixerContract`, `maltego.DeFiBridge`), multi-hop transaction flow tracing, peeling chain and tumbler heuristics, OFAC SDN sanctions screening, and VASP deposit touchpoint detection.
- **Universal Table Suite & HUD Notifications**: Table density controls (compact, normal, expanded), pagination, expandable accordion detail cards, and persistent tactical HUD notification system.

### Fixed
- **CI Pipeline & Cross-Platform Ruff Formatting**: Aligned `AGENTS.md` verification guidelines with GitHub Actions workflow, enforcing `ruff format --check .` across Ubuntu, Windows, and macOS runners.

## [0.2.0] - 2026-11-01

### Added
- **20 MCP tools** covering cases, entities, links, transforms, Machines, an investigation copilot and import/export.
- **40 built-in transforms**: 28 keyless (DNS over HTTPS, RDAP/WHOIS with ARIN fallback, crt.sh + CertSpotter,
  HackerTarget, urlscan.io, Shodan InternetDB, Team Cymru & RIPE Stat ASN/netblocks, Gravatar, GitHub profile details,
  AlienVault OTX hash pulses, semantic breach router `BreachSemanticPivot` over local SQLite + HIBP k-Anonymity +
  XposedOrNot, HUMINT behavioral profiler `AnalyzeSubjectBehavior`, multi-network profile lookup, email/URL parsing) and
  12 provider transforms enabled by API key (VirusTotal, Shodan, SecurityTrails, Censys, Hunter.io, Have I Been Pwned,
  GreyNoise, Tatum).
- **HUMINT & Multi-Agent Swarm capabilities**: native `humint.*` ontology (`humint.Alias`, `humint.Organization`,
  `humint.LocationHistory`, `humint.PsychologicalTrait`), `PersonaFootprint` Machine, cross-platform pseudonym
  correlation (`osint_link_entities(action="correlate")`), subject behavioral timeline and anomaly detection
  (`osint_get_timeline(mode="subject")`), weighted/annotated links, dynamic `.mtgx` visual styles (`<mtg:Style>`,
  `<mtg:Notes>`, dashed hypothesis links), and multi-agent case `fork`/`delegate`/`merge` with optimistic locking.
- **Dynamic `~/.maltego-mcp/.env` configuration** loaded automatically outside the repository by all agents, CLI and
  Maltego Desktop bridge.
- **Machines**: DomainRecon, InfrastructureRecon, EmailRecon, CompanyFootprint, PersonalFootprint, PersonaFootprint,
  URLRecon, ThreatSweep, ASNToNetblocks and custom Machines in TOML, with recursive rounds and cost budgets.
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
