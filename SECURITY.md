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

## Responsible use
This tool queries public sources. You are responsible for complying with the law, the terms of service of each
data provider and data-protection regulations (e.g. GDPR) in your jurisdiction.
