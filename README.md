# secintel-mcp

[![CI](https://github.com/blonde-almond/secintel-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/blonde-almond/secintel-mcp/actions/workflows/ci.yml)

A [Model Context Protocol](https://modelcontextprotocol.io) server that gives AI
agents the lookups a security analyst reaches for every day: how urgent is this
CVE, is this dependency vulnerable, and what indicators are in this report.

It uses only free public data sources and needs no API keys.

```
You:    How worried should I be about CVE-2021-44228?
Agent:  → triage_cve("CVE-2021-44228")
        P1 — patch immediately. It is in CISA's Known Exploited Vulnerabilities
        catalogue with known ransomware use, CVSS 10.0, EPSS 0.94.
```

## Tools

| Tool | What it does | Source |
| --- | --- | --- |
| `triage_cve` | Rates a CVE P1–P4 from severity, exploit probability and known exploitation, with the reasons | NVD + EPSS + KEV |
| `lookup_cve` | Description, CVSS score and vector, CWEs, dates, references | [NVD](https://nvd.nist.gov/developers/vulnerabilities) |
| `epss_score` | Probability of exploitation in the next 30 days, and percentile | [FIRST EPSS](https://www.first.org/epss/api) |
| `check_kev` | Whether the CVE is known to be exploited, remediation due date, ransomware flag | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| `query_package_vulns` | Known vulnerabilities and fixed versions for an open-source package | [OSV.dev](https://osv.dev) |
| `extract_iocs` | Pulls URLs, domains, IPs, emails, hashes and CVE IDs out of free text (handles defanged input) | local |
| `defang` | Rewrites indicators so they are safe to paste (`hxxp`, `[.]`) | local |

### Triage policy

`triage_cve` puts evidence of exploitation ahead of raw severity:

| Priority | Rule | Suggested action |
| --- | --- | --- |
| **P1** | In the CISA KEV catalogue | Patch or mitigate immediately |
| **P2** | EPSS ≥ 0.10, or CVSS ≥ 9.0 | Next emergency / expedited change window |
| **P3** | CVSS ≥ 7.0, or EPSS ≥ 0.01 | Normal patch cycle |
| **P4** | Everything else | Routine maintenance |

The thresholds live in [`src/secintel_mcp/triage.py`](src/secintel_mcp/triage.py)
and are meant to be changed to match your own policy. The result is a starting
point: it does not know whether the affected product is deployed or reachable
in your environment. If one source is unavailable the tool still answers from
the others and lists what failed in `source_errors`.

## Install

Requires Python 3.11+.

```bash
git clone https://github.com/blonde-almond/secintel-mcp.git
cd secintel-mcp
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Use it

### Claude Desktop, Claude Code, or any stdio MCP client

Add the server to your client's MCP configuration (for Claude Desktop this is
`claude_desktop_config.json`; a copy is in [`examples/`](examples/)):

```json
{
  "mcpServers": {
    "secintel": {
      "command": "/absolute/path/to/secintel-mcp/.venv/bin/secintel-mcp"
    }
  }
}
```

With Claude Code: `claude mcp add secintel -- /absolute/path/to/.venv/bin/secintel-mcp`

### Over HTTP

```bash
secintel-mcp --transport streamable-http --port 8000
# MCP endpoint: http://127.0.0.1:8000/mcp
```

The HTTP transport binds to loopback by default and **has no authentication**.
To reach it from another machine, put it behind a reverse proxy that handles
TLS and authentication rather than binding it to a public interface.

### Configuration

| Variable | Purpose |
| --- | --- |
| `NVD_API_KEY` | Optional. A free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) raises the NVD rate limit from 5 to 50 requests per 30 seconds. |
| `SECINTEL_TRANSPORT`, `SECINTEL_HOST`, `SECINTEL_PORT` | Defaults for the matching command-line flags. |

## Security design

An MCP server is code that a language model can drive, so its inputs should be
treated as untrusted. This one is built accordingly:

- **No server-side request forgery.** Every outbound request goes to one of four
  hard-coded hosts. Tool arguments are only ever sent as validated query
  parameters or JSON fields, never used to build a URL, and redirects are not
  followed.
- **Strict input validation.** CVE IDs, ecosystems, package names and versions
  are checked against allow-list patterns before any request is made.
- **Bounded work.** Requests have timeouts, responses have a size cap, text
  inputs have a length cap, and result lists are truncated.
- **Minimal untrusted text.** Upstream records are trimmed to the needed fields
  and descriptions are length-limited, and the server instructions tell the
  agent to treat returned text as data. This reduces, but cannot eliminate, the
  risk of prompt injection through vulnerability descriptions.
- **Read-only.** No tool writes files, runs commands or changes any system.
- **No secrets required.** The optional NVD key is read from the environment and
  sent only to the NVD.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## Development

```bash
pip install -e ".[dev]"
pytest          # all tests run offline against a fake upstream
ruff check .
ruff format .
```

```
src/secintel_mcp/
  server.py    MCP tool definitions and the command-line entry point
  clients.py   NVD, EPSS, KEV and OSV clients, validation, caching
  triage.py    The P1–P4 prioritisation policy
  iocs.py      Indicator extraction, defang and refang
```

## Limitations

- IPv6 addresses are not extracted.
- Domain extraction is pattern-based. It skips common file extensions
  (`setup.exe`, `archive.zip`) but will sometimes match things that are not
  indicators, and it does not check that a TLD exists.
- Caches are in memory and per process: 15 minutes for CVE and EPSS lookups,
  6 hours for the KEV catalogue.
- Without an NVD API key, heavy use will hit the NVD rate limit.

## Licence

[MIT](LICENSE)
