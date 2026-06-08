# MCPTROTTER — MCP Pentest Tool

<p align="center">
  <img src="docs/mcptrotter.jpeg" alt="MCPTROTTER" width="420"/>
</p>

<p align="center">
  28 automated security checks for any MCP server. Pure Python, no AI required.
</p>

<p align="center">
  <img src="https://github.com/gurudeepmallam-cmd/mcppt/actions/workflows/ci.yml/badge.svg" alt="CI"/>
  <img src="https://img.shields.io/pypi/pyversions/mcppt" alt="Python"/>
  <img src="https://img.shields.io/github/license/gurudeepmallam-cmd/mcppt" alt="License"/>
</p>

---

## What it is

MCPTROTTER is a command-line security scanner for [MCP (Model Context Protocol)](https://modelcontextprotocol.io) servers. It runs 28 automated checks across authentication, injection, SSRF, replay, session entropy, transport misconfiguration, tool poisoning, rug pulls, and more — covering the full OWASP MCP Top 10.

It works against any MCP server using Streamable HTTP transport. No Kali Linux, no Docker, no external API key needed for the core scan.

For the full risk catalog — CVSS scores, attack scenarios, proof-of-concept payloads, and remediation for all 28 checks — see [OPERATOR_GUIDE.md](OPERATOR_GUIDE.md).

---

## Install

### From source (recommended)

```bash
git clone https://github.com/gurudeepmallam-cmd/mcppt
cd mcppt/mcppt_tool
pip install -e .
```

### Or install dependencies directly

```bash
pip install rich flask
```

The scanner itself (`mcppt/core.py`, `mcppt/checks.py`) uses only the Python standard library. `rich` is for the interactive shell UI. `flask` is only needed for the local demo server.

Requires Python 3.10+.

---

## Quick start

### Interactive shell

```bash
cd mcppt_tool
python -m mcppt.cli
```

Inside the shell:

```
target https://your-mcp-server.com/mcp     set target URL
token  eyJ...                              bearer token (if required)
token2 eyJ...                              second token for IDOR/tenant checks
noverify                                   skip SSL (self-signed certs)
proxy  http://127.0.0.1:8080               route through Burp Suite
status                                     confirm config before scanning
list                                       enumerate tools the server exposes
scan                                       run all 28 checks
findings                                   colour-coded results table
report pentest_report.md                   export full markdown report
```

### One-liner (CI/CD or scripted scans)

```bash
python -m mcppt.cli scan \
  --url https://your-mcp-server.com/mcp \
  --token eyJ... \
  --no-verify \
  --output report.md
```

### Targeted check groups

```bash
# Authentication and access control only
python -m mcppt.cli scan --url ... --checks auth,scope,idor,jwt_audit

# Injection surface
python -m mcppt.cli scan --url ... --checks injection,stored,poison_all,tool_poisoning,cmd_injection

# Infrastructure
python -m mcppt.cli scan --url ... --checks headers,error_disclosure,ssrf,path_traversal,secret_scan,oauth_discovery

# Protocol-level
python -m mcppt.cli scan --url ... --checks replay,session,rate,rug_pull,tool_shadowing,resources,sampling
```

### Manual tool call

```bash
python -m mcppt.cli call \
  --url https://your-mcp-server.com/mcp \
  --token eyJ... \
  --tool get_user \
  --args '{"id": 1}'
```

---

## All 28 Checks

| # | Check | Max Severity | What it tests |
|---|-------|-------------|---------------|
| 1 | `enum` | MEDIUM | `tools/list` accessible without auth |
| 2 | `auth` | CRITICAL | Tool calls succeed with no/invalid token |
| 3 | `idor` | HIGH | Cross-user resource access (requires `--token2`) |
| 4 | `injection` | HIGH | Prompt injection payloads reflected in responses |
| 5 | `schema` | MEDIUM | Type confusion, oversized input, null bypass |
| 6 | `ssrf` | CRITICAL | Cloud metadata URLs accepted in tool parameters |
| 7 | `publish` | CRITICAL | Destructive tool callable without confirmation gate |
| 8 | `rate` | LOW | No rate limiting on tool calls |
| 9 | `stored` | CRITICAL | Write injection payload, read back unescaped |
| 10 | `scope` | HIGH | JWT scope claims not enforced; RBAC bypass via token2 |
| 11 | `replay` | CRITICAL | Same request accepted twice — no nonce or timestamp |
| 12 | `context_overflow` | HIGH | 50K–100K char payloads accepted — LLM context risk |
| 13 | `poison_all` | CRITICAL | Injection payload appears in every response JSON field |
| 14 | `tenant` | CRITICAL | Token2 reads token1's data — isolation broken |
| 15 | `session` | HIGH | Weak or sequential session IDs (CVE-2025-6515 pattern) |
| 16 | `rug_pull` | CRITICAL | Tool descriptions change between `tools/list` calls |
| 17 | `headers` | HIGH | CORS wildcard, missing CSP/HSTS/X-Content-Type, Server header |
| 18 | `error_disclosure` | MEDIUM | Stack traces, file paths, DB credentials in error responses |
| 19 | `tool_poisoning` | CRITICAL | Hidden Unicode (U+200B/202E) and injection patterns in tool descriptions |
| 20 | `resources` | HIGH | `resources/list` and `prompts/list` accessible without auth |
| 21 | `cmd_injection` | CRITICAL | Shell metacharacters (`;id`, `$(id)`) execute in tool parameters |
| 22 | `path_traversal` | CRITICAL | `../../../etc/passwd` accepted in file/path parameters |
| 23 | `jwt_audit` | CRITICAL | `alg=none`, no `exp`, sensitive claims, expired token accepted |
| 24 | `oauth_discovery` | LOW | `/.well-known/oauth-authorization-server` and OIDC endpoints exposed |
| 25 | `secret_scan` | CRITICAL | AWS keys, GitHub PATs, DB connection strings in tool responses |
| 26 | `tool_shadowing` | CRITICAL | Duplicate tool names, homoglyphs, name/description mismatch |
| 27 | `sampling` | CRITICAL | `sampling/createMessage` accessible without auth |
| 28 | `schema_leak` | LOW | Sensitive enum values and internal field names in tool schemas |

Full details — CVSS vectors, attack scenarios, PoC payloads, and remediation guidance — are in [OPERATOR_GUIDE.md](OPERATOR_GUIDE.md).

---

## Output

**Live TUI** — Rich-based streaming output while the scan runs. Findings panel updates in real time, colour-coded by severity.

**Markdown report** (`--output report.md`) — pentest-ready finding list with details, evidence, and severity table. Paste directly into an engagement report.

**JSON report** (`--output report.json`) — machine-readable output for CI/CD pipeline integration or ticketing system import.

**AI analysis** (optional) — add an Anthropic or OpenAI key to generate an attack chain narrative, top-3 priorities, and an executive risk summary from the findings:

```
ai claude  sk-ant-api03-...
analyze
```

---

## Demo server

A deliberately vulnerable MCP server is included for testing and development:

```bash
# Terminal 1 — start the demo server
cd mcppt_tool
python vuln_server.py
# Listening on http://127.0.0.1:8888/mcp

# Terminal 2 — scan it
python -m mcppt.cli scan \
  --url http://127.0.0.1:8888/mcp \
  --token valid-token-abc123 \
  --token2 other-token-xyz789

# Or run the automated smoke test (verifies all 28 checks fire)
python smoke_test.py
```

The demo server simulates all 28 weaknesses safely — no real command execution, no real file reads, no real URL fetches. Expected smoke test result: 17/17 assertions pass, 70+ findings across all severity levels.

---

## Burp Suite integration

Route all MCPTROTTER traffic through Burp Suite for manual review, Repeater iteration, or Intruder fuzzing:

```bash
python -m mcppt.cli scan \
  --url https://your-mcp-server.com/mcp \
  --proxy http://127.0.0.1:8080 \
  --no-verify \
  --token eyJ...
```

Every JSON-RPC call — all 28 checks — appears in Burp's HTTP history with full request/response. Use Repeater to iterate on any finding manually, or Intruder to fuzz tool parameters with a wordlist.

---

## Architecture

```
mcppt_tool/
├── mcppt/
│   ├── core.py      — JSON-RPC transport (urllib, stdlib only, no external deps)
│   ├── checks.py    — 28 check functions + thread-safe ScanState
│   ├── shell.py     — interactive shell (rich TUI)
│   ├── cli.py       — scan / list / call subcommands
│   └── report.py    — JSON + Markdown report generation
├── vuln_server.py   — demo vulnerable MCP server (Flask)
├── smoke_test.py    — automated test: starts vuln_server, runs scan, asserts findings
└── OPERATOR_GUIDE.md — full risk catalog for all 28 checks
```

The scanner is pure stdlib — `urllib`, `ssl`, `json`, `re`. The `rich` dependency is only for the shell TUI. `flask` is only for the demo server. Running `scan` in a pipeline needs neither.

---

## Development

```bash
git clone https://github.com/gurudeepmallam-cmd/mcppt
cd mcppt/mcppt_tool
pip install -e ".[ai,ui]"
pip install pytest ruff

# Run all tests
pytest tests/

# Smoke test (starts demo server, runs full 28-check scan, exits 0 on pass)
python smoke_test.py

# Lint
ruff check mcppt/
```

---

## License

MIT — see [LICENSE](LICENSE).

---

## Author

**Gurudeep Mallam** — Security Researcher, Bugtrotter

- GitHub: [github.com/gurudeepmallam-cmd](https://github.com/gurudeepmallam-cmd)
- LinkedIn: [Mallam Gurudeep](https://in.linkedin.com/in/mallam-gurudeep-7734941aa)
- Email: gurudeep.mallam@gmail.com
