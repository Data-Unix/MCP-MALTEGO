# Security policy

## Reporting a vulnerability
Please report vulnerabilities privately through **GitHub → Security → Report a vulnerability** on this
repository. Do not open public issues for security problems. You will get an acknowledgement within 7 days.

## Design notes
- Data collected from OSINT sources is treated as untrusted: it is cleaned, truncated and presented to the model as
  data, never as instructions.
- XML from transforms and `.mtgx`/`.mtz` archives is parsed with `defusedxml` and bounded reads (XXE and zip-bomb safe).
- Agents can only run transforms declared in the catalog; they never supply URLs (SSRF protection).
- API keys are read from environment variables, are never written to disk by the server and never logged.
- The HTTP transport refuses non-loopback hosts unless `--allow-remote-unauthenticated` is passed explicitly.

## Repository hardening (maintainers)
Automated in this repository:
- `.gitignore` excludes secrets, case data (`data/`, `exports/`, `imports/`, `*.mtgx`, `*.mtz`) and local agent state.
- CI job `security`: gitleaks over the full git history, pip-audit on locked dependencies, and a check that the npm
  package contains no sensitive files.
- Dependabot for uv, npm and GitHub Actions; CODEOWNERS; workflows with least-privilege `permissions` and
  `persist-credentials: false`.
- Releases are published only from GitHub Actions (npm Trusted Publishing / provenance when the repository is public).

To configure in GitHub settings (cannot be set from code):
- Branch protection / ruleset for `main`: require PR, 1 approval, code-owner review, passing checks (`CI`), no force
  push, no deletion.
- Code security: secret scanning + push protection, Dependabot alerts and security updates, private vulnerability
  reporting.
- Actions: "Read repository contents" as default workflow permission; require approval for workflows from forks.
- npm: 2FA on the account; after the first publish, Trusted Publishing and "disallow tokens".

## Responsible use
This tool queries public sources. You are responsible for complying with the law, the terms of service of each
data provider and data-protection regulations (e.g. GDPR) in your jurisdiction.
