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

## AI API key setup

The core scanner needs no API key. The `analyze` command is optional and sends your findings to an LLM for an attack narrative and executive summary.

**Get a key:**
- Anthropic (Claude): [console.anthropic.com](https://console.anthropic.com) → API Keys → Create key. Starts with `sk-ant-api03-`
- OpenAI (GPT-4o): [platform.openai.com](https://platform.openai.com) → API keys → Create. Starts with `sk-`

**Use it inside the interactive shell:**
```
# After running scan:
ai claude  sk-ant-api03-xxxxxxxxxxxx     ← paste your Anthropic key
analyze

# Or with OpenAI:
ai openai  sk-xxxxxxxxxxxx
analyze
```

**Or via environment variable (recommended for scripted use):**
```bash
export ANTHROPIC_API_KEY=sk-ant-api03-...
python -m mcppt.cli scan --url https://target.com/mcp --token eyJ...
# then in shell: analyze
```

The key is used only for that session — it is never stored to disk.

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

## Use MCPTROTTER as an MCP server

MCPTROTTER can flip roles — instead of scanning MCP servers, it can *become* one. This lets Claude Desktop, Claude Code, or any MCP client call MCPTROTTER as a tool and trigger scans from inside an AI conversation.

**Start MCPTROTTER in server mode:**
```bash
cd mcppt_tool
python -m mcppt.cli serve-mcp          # default port 8899
python -m mcppt.cli serve-mcp --port 9000
```

**Add it to Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "mcptrotter": {
      "command": "python",
      "args": ["-m", "mcppt.cli", "serve-mcp", "--port", "8899"],
      "cwd": "/path/to/mcppt_tool"
    }
  }
}
```

**Once registered, Claude can call these tools directly:**
```
scan_target   → runs full scan against any MCP URL, returns findings JSON
list_tools    → enumerates tools on a target MCP server
call_tool     → calls a specific tool on any MCP server
get_checks    → lists all 28 available checks with descriptions
```

So you can say to Claude: *"Scan https://target.com/mcp for security issues"* — and Claude calls MCPTROTTER's `scan_target` tool, gets the findings back as structured JSON, and reasons over them.

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

## Try it now — no target needed

MCPTROTTER ships with a fully vulnerable demo MCP server (`vuln_server.py`) that simulates all 28 weaknesses safely — no real command execution, no real file reads, no cloud calls. It's designed specifically so you can run a complete scan, see every check fire, and understand exactly what the tool does before pointing it at a real target.

```bash
# Terminal 1 — start the vulnerable demo server
cd mcppt_tool
python vuln_server.py
# Listening on http://127.0.0.1:8888/mcp

# Terminal 2 — scan it
python -m mcppt.cli scan \
  --url http://127.0.0.1:8888/mcp \
  --token valid-token-abc123 \
  --token2 other-token-xyz789

# Or run the automated smoke test — starts the server, scans, asserts all 28 checks fire
python smoke_test.py
# Expected: 17/17 assertions pass, 70+ findings across all severity levels
```

The demo server intentionally fails every single check — CORS wildcard, auth bypass, stored injection, command injection, rug pull, tool poisoning with hidden Unicode, weak session IDs, replay attacks, SSRF, path traversal, secret leaks, and more. It's the fastest way to see the full capability of the tool end to end.

---

## Part of Bugtrotter

MCPTROTTER was built by **[Gurudeep Mallam](https://github.com/gurudeepmallam-cmd)** as part of **Bugtrotter** — a private red team and application security platform built from the ground up for modern attack surfaces: AI agents, MCP deployments, enterprise Active Directory, web applications, APIs, and networks.

Bugtrotter is not a generic scanner rebranded for AI. It is a full-engagement security platform covering every phase from recon to final report. Here is what it does:

**Manual Penetration Testing**
- **Web application pentesting** — full manual assessment: authentication, session management, injection, access control, business logic, client-side attacks
- **API security testing** — REST, GraphQL, MCP — endpoint enumeration, broken object level auth, mass assignment, rate limiting, schema abuse
- **Active Directory** — full kill chain from external foothold to domain admin: Kerberoasting, AS-REP roasting, ADCS ESC abuse, DCSync, cross-domain Golden Ticket. [Read the AD + Claude Code + MCP pipeline →](https://medium.com/@gurudeep.mallam/i-built-an-ai-driven-active-directory-attack-pipeline-using-claude-code-mcp-heres-how-it-works-b3b1f8841770)
- **Network pentesting** — infrastructure scanning, service enumeration, lateral movement, pivoting, internal network compromise
- **Red teaming** — full adversary simulation: initial access, persistence, privilege escalation, exfiltration — end-to-end kill chain across the entire target environment

**Application Security (Code-Level)**
- **SAST (Static Application Security Testing)** — source code analysis to identify vulnerabilities before deployment: injection flaws, hardcoded secrets, insecure crypto, dangerous function usage, and logic errors across Python, JavaScript, and more
- **DAST (Dynamic Application Security Testing)** — live application testing with business logic abuse at its core. Bugtrotter leverages **Burp Suite MCP** to drive intelligent, context-aware dynamic testing — not just automated fuzzing, but real attacker-style business logic exploitation: price manipulation, privilege escalation flows, multi-step workflow abuse, and state-based vulnerabilities that no scanner catches automatically

**AI-Native Security**
- **MCP security assessments** — MCPTROTTER is the public-facing automated scanner; the full Bugtrotter toolkit adds manual exploitation, chained attack playbooks across connected MCP tools, and client-ready reporting
- **AI agent red teaming** — prompt injection chains, tool poisoning, context window manipulation, agent hijacking across multi-agent pipelines
- **LLM integration security** — testing the full stack from model to MCP tool to backend, finding where the AI layer introduces risk that traditional testing misses

**MCPTROTTER + Bugtrotter = full coverage.** MCPTROTTER gives you the automated 28-check baseline in two minutes. Bugtrotter layers on top: manual chaining of findings into demonstrated exploit chains, custom payloads for the specific MCP implementation, cross-tool attack paths (e.g. SSRF → credential theft → lateral movement through connected tools), SAST review of the server-side code, and DAST with Burp Suite MCP driving business logic abuse — all delivered as a full engagement report.

If you are running an MCP deployment and want it fully assessed, or want the complete Bugtrotter toolkit applied to your environment, reach out directly.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Author

**Gurudeep Mallam** — Security Researcher, Bugtrotter

- GitHub: [github.com/gurudeepmallam-cmd](https://github.com/gurudeepmallam-cmd)
- LinkedIn: [Mallam Gurudeep](https://in.linkedin.com/in/mallam-gurudeep-7734941aa)
- Email: gurudeep.mallam@gmail.com
