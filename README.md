# MCPTROTTER — MCP Security Framework

<p align="center">
  <img src="https://raw.githubusercontent.com/gurudeepmallam-cmd/mcppt/main/docs/mcptrotter.jpeg" alt="MCPTROTTER" width="380"/>
</p>

<p align="center">
  <img src="https://img.shields.io/pypi/v/mcppt?label=PyPI&color=orange"/>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue"/>
  <img src="https://img.shields.io/badge/checks-31-red"/>
  <img src="https://img.shields.io/badge/license-MIT-green"/>
  <img src="https://img.shields.io/badge/part%20of-Bugtrotter-black"/>
</p>

<p align="center">
  <b>by <a href="https://github.com/gurudeepmallam-cmd">Gurudeep Mallam</a> &nbsp;·&nbsp;
  <a href="https://in.linkedin.com/in/mallam-gurudeep-7734941aa">LinkedIn</a></b>
</p>

---

## What it is

MCPTROTTER is a **security framework** for testing MCP (Model Context Protocol) servers. It works two ways:

**Manual exploration** — connect to any MCP server and interact with it the way an attacker would. Call tools directly, inspect schemas, fuzz parameters, read resources, send raw JSON-RPC methods. No scan needed. You control every request.

**Automated scanning** — run 31 security checks in under 60 seconds. Auth bypass, stored injection, replay attacks, session entropy, tenant isolation, tool poisoning, command injection, and more.

Both modes route through Burp Suite so you see every request in HTTP History and can follow up in Repeater.

---

## Install

**From PyPI (recommended):**
```bash
pip install mcppt
```

**From source:**
```bash
git clone https://github.com/gurudeepmallam-cmd/mcppt
cd mcppt/mcppt_tool
pip install -e .
```

Requires Python 3.10+.

---

## Quick start — try it right now (no target needed)

MCPTROTTER ships with a deliberately vulnerable demo server that fires every check.

**Terminal 1 — start the demo server:**
```bash
cd mcppt_tool
python test_server.py
```
```
=======================================================
  Vulnerable MCP Test Server
  URL:   http://127.0.0.1:8888/mcp
  Token: valid-token-abc123
=======================================================
```

**Terminal 2 — open the interactive shell:**
```bash
mcppt
```

```
  __  __   ___  ___  _____ ____   ___ _____ _____ ___ ___
 |  \/  | / __|| _ \|_   _|  _ \ / _ \_   _|_   _| __| _ \
 | |\/| || (__|  _/ | | |   /  | (_) || |   | | | _||   /
 |_|  |_| \___||_|  |_| |_|_\  \___/ |_|   |_| |___|_|_\

  MCP Pentest Framework  v3.0  --  31 checks  +  manual exploration

  by Gurudeep Mallam

  Quick start:  target <url>  →  connect  →  list  →  scan
  Manual test:  call <tool> <args>  |  raw <method>  |  fuzz <tool> <param> <type>
```

**Paste these commands one by one:**
```
target http://127.0.0.1:8888/mcp
token  valid-token-abc123
connect
list
scan
findings
report demo.md
```

---

## Expected output — demo server scan

Running `scan` with token set produces this (under 60 seconds):

```
Duration: ~45s   Findings: 6 CRITICAL  6 HIGH  13 MEDIUM  3 LOW
```

| Severity | Check | Finding |
|---|---|---|
| CRITICAL | `auth` | Auth bypass on `get_notes` — no token required |
| CRITICAL | `auth` | Auth bypass on `get_notes` — invalid token accepted |
| CRITICAL | `publish` | `publish_report` callable without confirmation gate |
| CRITICAL | `stored` | Stored injection confirmed: `save_note` → `get_notes` unescaped |
| CRITICAL | `replay` | Replay confirmed on WRITE tool `publish_report` |
| CRITICAL | `poison_all` | Injection marker reflected in `result.content[0].text` |
| HIGH | `injection` | Prompt injection reflected in `publish_report.title` |
| HIGH | `replay` | Replay confirmed on `get_notes` |
| HIGH | `session` | Short session ID (3 chars): `108` |
| HIGH | `session` | Non-UUID/non-hex session format: `108` |
| HIGH | `session` | Near-sequential IDs (diffs=[1,7,1,1]) — low entropy |
| MEDIUM | `enum` | `tools/list` accessible without Authorization header |
| MEDIUM | `schema` | Multiple fields accept wrong types (string/int/null bypass) |
| MEDIUM | `context_overflow` | 10,000-char payload accepted without truncation |
| LOW | `rate` | No rate limiting — 30/30 requests in 1.5s |
| LOW | `headers` | Missing: X-Content-Type-Options, CSP, X-Frame-Options |
| LOW | `headers` | Server header leaks: `Werkzeug/3.1.8 Python/3.13.5` |

> **Without a token set**, only the rate limiting check fires. Always run `token <value>` before `scan`.

---

## All commands

### Setup
```
target  <url>          Set MCP server URL
token   <bearer>       Set primary auth token
token2  <bearer>       Set second user token (IDOR / scope / tenant checks)
noverify               Toggle SSL verification skip (needed for self-signed certs)
proxy   <url|off>      Set Burp proxy:  proxy http://127.0.0.1:8080
verbose                Toggle raw HTTP request/response logging
status                 Show current session configuration
```

### Manual exploration
```
connect                Test connection + show server name, version, capabilities
list                   List all tools the server exposes (names, schemas, params)
inspect <tool>         Show full JSON schema for a specific tool
call <tool> [json]     Call any tool directly with your own arguments
                         call get_notes
                         call get_user {"id": 1}
                         call save_note {"text": "test injection payload"}
raw <method> [params]  Send any raw JSON-RPC method
                         raw tools/list
                         raw resources/list
                         raw sampling/createMessage {...}
resources [read <uri>] List resources or read a specific URI
prompts [get <name>]   List prompts or get a specific prompt
headers                Show HTTP response headers from the last request
```

### Targeted testing
```
fuzz <tool> <param> <type|file>   Fuzz a specific tool parameter

  Built-in wordlists:
    sqli        SQL injection payloads
    xss         XSS and template injection
    traversal   Path traversal (../etc/passwd, encoded variants)
    cmd         OS command injection (; id, $(id), | whoami)
    ssrf        SSRF targets (169.254.169.254, localhost)
    ssti        Server-side template injection
    inject      Prompt injection payloads for LLM tools

  Custom:  fuzz read_file path /path/to/payloads.txt

  Examples:
    fuzz get_user id sqli
    fuzz save_note text inject
    fuzz read_file path traversal
```

### Automated scan
```
scan                   Run all 31 checks
scan auth ssrf idor    Run specific checks only
scan stored injection  Mix and match any check names
```

### Findings
```
note <sev> <check> <title> [| detail]   Manually log a finding
                         note HIGH manual_test Input reflected | seen in 500 response
findings               Colour-coded findings table (scan + manual notes)
clear                  Clear findings and tool cache
report out.md          Export Markdown report
report out.json        Export JSON report
```

### AI analysis (optional)
```
ai claude  sk-ant-...  Configure Claude for analysis
ai openai  sk-...      Configure OpenAI GPT-4o
analyze                Attack narrative + remediation priority from findings
```

---

## One-liner (non-interactive / CI)

```bash
# Full scan, save Markdown report
mcppt scan --url https://target.com/mcp --token eyJ... --output report.md

# With second token (enables IDOR, scope, tenant checks)
mcppt scan --url https://target.com/mcp --token t1 --token2 t2 --output report.md

# Through Burp proxy, skip SSL
mcppt scan --url https://target.com/mcp --token eyJ... --proxy http://127.0.0.1:8080 --no-verify

# Targeted checks only
mcppt scan --url https://target.com/mcp --token eyJ... --checks auth,ssrf,stored,idor
```

---

## Burp Suite integration — step by step

Route every MCPTROTTER request through Burp to inspect, replay, and fuzz manually.

### Step 1 — Set up Burp listener

Burp Suite → **Proxy → Proxy Settings**

Confirm the listener is `127.0.0.1:8080` (it is by default). No changes needed.

### Step 2 — Run through proxy

Inside the shell:
```
proxy    http://127.0.0.1:8080
noverify
scan
```

Or as a one-liner:
```bash
mcppt scan --url https://target.com/mcp --token eyJ... --proxy http://127.0.0.1:8080 --no-verify
```

`noverify` / `--no-verify` is required because Burp intercepts TLS with its own certificate.

### Step 3 — See requests in HTTP History

Burp → **Proxy → HTTP History**

Every MCP tool call appears as a `POST /mcp` request. You'll see `initialize`, `tools/list`, `tools/call` for each check. Manual commands (`call`, `raw`, `fuzz`) also appear here — every request MCPTROTTER makes goes through Burp.

### Step 4 — Send to Repeater for manual testing

Right-click any request → **Send to Repeater** (`Ctrl+R`).

```
POST /mcp HTTP/1.1
Host: target.com
Authorization: Bearer eyJ...
Content-Type: application/json

{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_notes","arguments":{}}}
```

Change `"id": 2` to `"id": 1` to test IDOR. Swap the token to another user's. Modify `"name"` to call a different tool.

If you get a session error, copy the `initialize` request from HTTP History into Repeater first, send it, and copy the `mcp-session-id` header value into your target request.

### Step 5 — Fuzz with Intruder

Right-click any Repeater request → **Send to Intruder**. Highlight the parameter value, click **Add §**, load a wordlist, run the attack.

---

## All 31 checks

| # | Check | Severity | What it tests |
|---|---|---|---|
| 1 | `enum` | MEDIUM | `tools/list` accessible without auth |
| 2 | `auth` | CRITICAL | Tool calls succeed with no/invalid token |
| 3 | `idor` | HIGH | Cross-user resource access (needs `token2`) |
| 4 | `injection` | HIGH | Prompt injection payloads reflected in responses |
| 5 | `schema` | MEDIUM | Type confusion, null bypass, oversized input |
| 6 | `ssrf` | CRITICAL | Cloud metadata URLs accepted in tool parameters |
| 7 | `publish` | CRITICAL | Destructive tool callable without confirmation gate |
| 8 | `rate` | LOW | No rate limiting on tool calls |
| 9 | `stored` | CRITICAL | Write injection payload, read back unescaped |
| 10 | `scope` | HIGH | Read-only token reaches write tools |
| 11 | `replay` | CRITICAL | Same request accepted twice — no nonce |
| 12 | `context_overflow` | HIGH | 50K–100K char payload accepted without truncation |
| 13 | `poison_all` | CRITICAL | Injection payload appears in every response field |
| 14 | `tenant` | CRITICAL | Token2 reads token1 data — isolation broken |
| 15 | `session` | HIGH | Weak or sequential session IDs |
| 16 | `rug_pull` | CRITICAL | Tool descriptions change between `tools/list` calls |
| 17 | `headers` | HIGH | CORS wildcard, missing CSP/HSTS, Server header leak |
| 18 | `error_disclosure` | MEDIUM | Stack traces, file paths, DB credentials in errors |
| 19 | `tool_poisoning` | CRITICAL | Hidden Unicode (U+200B/202E) in tool descriptions |
| 20 | `resources` | HIGH | `resources/list` or `prompts/list` without auth |
| 21 | `cmd_injection` | CRITICAL | Shell metacharacters (`;id`, `$(id)`) in parameters |
| 22 | `path_traversal` | CRITICAL | `../../../etc/passwd` in file/path parameters |
| 23 | `jwt_audit` | CRITICAL | `alg=none`, no `exp`, expired token accepted |
| 24 | `oauth_discovery` | LOW | `/.well-known/oauth-authorization-server` exposed |
| 25 | `secret_scan` | CRITICAL | AWS keys, GitHub PATs, DB strings in tool responses |
| 26 | `tool_shadowing` | CRITICAL | Duplicate tool names, homoglyphs, name/desc mismatch |
| 27 | `sampling` | CRITICAL | `sampling/createMessage` accessible without auth |
| 28 | `schema_leak` | LOW | Sensitive field names / enum values in tool schemas |
| 29 | `http_method_confusion` | MEDIUM | GET/DELETE/PUT/PATCH accepted on MCP endpoint |
| 30 | `protocol_downgrade` | MEDIUM | Old protocol versions accepted, server version leaked |
| 31 | `batch_injection` | MEDIUM | JSON-RPC batch requests, unusual method name injection |

---

## MCPTROTTER vs manual testing — what you save

| Task | Manual in Burp | MCPTROTTER |
|---|---|---|
| Test auth bypass on every tool | 10–30 min | `scan auth` — 5s |
| Test stored injection (write + read) | 20 min | `scan stored` — 3s |
| Check all response fields for injection | 30+ min | `scan poison_all` — 5s |
| Verify session ID entropy | 10 min | `scan session` — 2s |
| Check replay on every tool | 20 min | `scan replay` — 5s |
| Full 31-check assessment | 3–6 hours | `scan` — under 60s |
| Inspect tool schema before testing | 5 min reading docs | `inspect <tool>` — instant |
| Call a tool with custom payload | Set up in Burp Repeater | `call <tool> {"param": "payload"}` |
| Fuzz a parameter with 50 payloads | Intruder setup + run | `fuzz <tool> <param> sqli` — 30s |
| Test any JSON-RPC method directly | Build request in Repeater | `raw <method> <params>` |

MCPTROTTER gives you the baseline in under 60 seconds and puts every request in Burp HTTP History. You spend your time on what matters: manually verifying findings in Repeater and chaining them into a demonstrated attack path.

---

## Part of Bugtrotter

MCPTROTTER is the public automated scanner extracted from **Bugtrotter** — a full red team and application security platform built for modern attack surfaces.

### What Bugtrotter adds on top of MCPTROTTER

| Capability | MCPTROTTER | Bugtrotter |
|---|---|---|
| Automated MCP scan (31 checks) | ✓ | ✓ |
| Manual tool exploration framework | ✓ | ✓ |
| Chained exploit paths across tools | — | ✓ Full attack chain |
| SAST review of MCP server code | — | ✓ |
| Burp Suite MCP — business logic abuse | — | ✓ AI-driven |
| AI agent red teaming | — | ✓ Multi-agent pipelines |
| Active Directory kill chain | — | ✓ External → DA |
| Web / API / network pentesting | — | ✓ Full engagement |
| Final pentest report | Markdown export | Engagement-grade report |

**MCPTROTTER inside Bugtrotter:**

In Bugtrotter, MCPTROTTER runs as a registered MCP server. Claude Code or Claude Desktop calls it directly:

```
"Scan https://target.com/mcp for security issues and prioritise findings"
→ Claude calls scan_target tool
→ MCPTROTTER runs all 31 checks
→ Findings returned as structured JSON to Claude
→ Claude reasons over them, chains the critical ones, drafts the report section
```

No copy-paste. No context switching. The scan output feeds straight into the AI-driven engagement workflow — SSRF finding becomes an SSRF exploit attempt, auth bypass becomes a credential theft chain, stored injection becomes a demonstrated prompt hijack.

---

## Use MCPTROTTER as an MCP server itself

MCPTROTTER can expose its scan capability as tools that any MCP client (Claude Desktop, MCP Inspector, another agent) can call.

```bash
mcppt serve-mcp --port 8899
```

Add to Claude Desktop config (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "mcptrotter": {
      "command": "mcppt",
      "args": ["serve-mcp", "--port", "8899"]
    }
  }
}
```

Tools exposed:
- `scan_target` — full scan, returns findings JSON
- `list_tools` — enumerate tools on any MCP server
- `call_tool` — call any tool on any MCP server
- `get_checks` — list all 31 checks with descriptions

---

## Author

**Gurudeep Mallam** — Security Researcher

- GitHub: [github.com/gurudeepmallam-cmd](https://github.com/gurudeepmallam-cmd)
- LinkedIn: [Mallam Gurudeep](https://in.linkedin.com/in/mallam-gurudeep-7734941aa)
- Email: gurudeep.mallam@gmail.com

---

## License

MIT
