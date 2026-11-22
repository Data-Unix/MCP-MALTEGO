# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-11-22

### Added
- **Plaintext & Vague Prompt Orchestration + Real-Time VS Code ↔ Web Dashboard Sync**:
  - Natural-language seed extraction (`extract_seed_from_plaintext`) in `osint_investigate`: accepts vague or conversational prompts from VS Code agents (Claude Code, GitHub Copilot, Cursor, Gemini CLI, Codex), extracts the target entity and type, creates the case, executes the full non-intrusive active & passive reconnaissance workflow, auto-exports `report_html` and `.mcpcase`, and returns a complete Executive Pericial Report inline.
  - Cross-process real-time event bus (`~/.maltego-mcp/events.jsonl` + `~/.maltego-mcp/active_case`): every MCP tool execution in external `stdio` processes streams live via Server-Sent Events (`/api/events` and `/api/events/poll`) to `maltegoctl dashboard`, automatically switching to or refreshing the active case, graph canvas, P0–P9 reconnaissance phases, and 21-typology Pericial Profiles.
  - Project-level `.github/copilot-instructions.md` and synchronized agent/skill definitions across `.agents/`, `.claude/`, `.gemini/`, `.qwen/`, `.github/agents/`, and `.codex/`.
- **63 Built-in Transforms (51 Keyless + 12 Provider) & 16 Predefined Machines**:
  - Added keyless passive & historical reconnaissance transforms: `WaybackCDXSearch`, `WaybackSnapshotExtract`, `ArquivoCDXSearch`, `CommonCrawlCDXSearch`, `AnubisSubdomains`, `CTOrgToCertificates`, `BOEEntityToRecords`, `GLEIFCompanyToStructure`, `GitHubDomainToLeaks`, `GitHubAliasToCommitEmails`, `KeybaseAliasToProofs`, `HudsonRockStealerCheck`, `IPToPassiveContext`, `SocialAliasDeepRecon`, `DeepDarkCTISearch`, `OnionPassivePivot`, `CisaKevToVulnerabilities`, `UrlhausHostToThreats`, `MempoolAddressToTransactions`, `MempoolTxToInputsOutputs`, `CryptoClusteringCIOH`, `OFACSanctionsCryptoLookup`, and `CryptoAddressToExchange`.
  - Added 5 strict-passive Machines (`PassiveDomainRecon`, `PassiveInfrastructureRecon`, `PassiveEmailRecon`, `PassiveURLRecon`, `PassiveCompanyFootprint`) alongside `DarkWebFootprint`, `CryptoFlowRecon`, `PersonaFootprint`, `DomainRecon`, `InfrastructureRecon`, `EmailRecon`, `CompanyFootprint` (expanded to accept `maltego.Domain`, `maltego.Organization`, and `maltego.Company`), `PersonalFootprint`, `URLRecon`, `ThreatSweep`, and `ASNToNetblocks`.
  - Enabled all non-intrusive active and passive transforms by default (`MALTEGO_MCP_ALLOW_ACTIVE=1`, `MALTEGO_MCP_MODE=active`) with anti-burst throttling (`CHAIN_CONCURRENCY = 3`).
- **21-Typology Multidimensional Pericial Profiling Engine & Objective Validity (§4.4)**:
  - `osint_manage_entity(action="profile")` evaluates 21 forensic typologies across a 6-pillar radar (`investor`, `company_due_diligence`, `device`, `geographic`, `criminal`, `victimology`, `cyberbullying`, `political`, `psychographic`, `clinical`, etc.).
  - Automatic calculation of Objective Asset Validity (`OBSERVADO_RECIENTE`, `HISTORICO`, `MENCIONADO_SIN_FECHA`) and integration into report section `§ 03B`.
- **P0–P9 Anti-Bias Reconnaissance Module & ACH / ICD 203 Synthesis**:
  - Step-by-step implementation of Richards J. Heuer Jr.'s cognitive tradecraft (*Psychology of Intelligence Analysis*, ch. 10–13) with dynamic Untouchable Perimeter (§1), symmetric refutational dorking (§4–5), canary/honeytoken detection (§6), HUMINT attribution decoupling (§7), 3 competing ACH hypotheses with ICD 203 probability scales (§9), automatic graph-to-dossier synchronization (`sync_case_recon_from_graph`), and report section `§ 03C`.
- **Tamper-Evident `.mcpcase` Forensic Format**: Native `.mcpcase` container with cryptographic SHA-256 integrity seal, procedural ledger, and round-trip import/export (`osint_export_case(format="mcpcase")`, `osint_import_graph`).
- **Optional Rust Native Core (`maltego_core_rs`)**: PyO3/Maturin Rust extension (`rust/`, `scripts/build_native.py`) providing GIL-free Fruchterman-Reingold layout and string similarity with bit-exact parity against the pure-Python fallback.
- **Impeccable Design System & Dashboard UX**: Consolidated design specification (`PRODUCT.md`, `DESIGN.md`), 60 FPS resizable/dockable sidebar, sticky phase navigation bar, Multi-Case Isolation & Modular Project Scoping, Forensic Case Deletion & Atomic Purging (`DELETE /api/cases/{case_id}`), Cryptoforensics & Blockchain AML Traceability, and Universal Table Suite.
- **MCP Directory Metadata**: `smithery.yaml`, `glama.json`, `llms-install.md`, and MCP Registry / Glama badges in `README.md` and `README.es.md`.

### Security
- **Centralized Egress Guard, PEP 578 Runtime Audit Hook & Mandatory Mullvad Double-Attestation Ring**:
  - All outbound HTTP traffic is routed exclusively through `egress.py`, blocking intrusive endpoints (such as VirusTotal POST or `/analyse` submissions) and enforcing chained SHA-256 audit logging (`audit.log`).
  - Mandatory Mullvad VPN Ring (`mullvad.py`, `web_ring.py`) routing via internal tunnel proxy `socks5h://10.64.0.1:1080` with fail-closed dual attestation (local Authenticode-verified daemon + remote `am.i.mullvad.net` over owned relays) and PEP 578 socket/DNS audit hook.
  - Web Control Center hardened with PBKDF2-HMAC-SHA256 (600,000 iterations) session authentication (`auth.py`), CSRF validation, DNS-rebinding protection without TOCTOU, strict Content Security Policy (`script-src 'self'`, zero inline event handlers), and automatic IOC defanging in reports.
  - Automated Zero-Leak privacy test suite (`tests/test_privacy_and_realtime_vscode.py`) and pre-push audit (`scripts/verify_pre_push.py`).

### Fixed
- **CI Pipeline & Cross-Platform Ruff Formatting**: Aligned `AGENTS.md` verification guidelines with GitHub Actions workflow, enforcing `ruff format --check .` and excluding compiled native extensions (`*.pyd`, `*.so`) from `npm pack`.

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

[0.3.0]: https://github.com/Data-Unix/MCP-MALTEGO/releases/tag/v0.3.0
[0.2.0]: https://github.com/Data-Unix/MCP-MALTEGO/releases/tag/v0.2.0
[0.1.0]: https://github.com/Data-Unix/MCP-MALTEGO/commits/v0.1.0
