# MCPTROTTER — MCP Pentest Tool

<p align="center">
  <img src="https://raw.githubusercontent.com/gurudeepmallam-cmd/mcppt/main/docs/mcptrotter.jpeg" alt="MCPTROTTER" width="380"/>
</p>

<p align="center">
  <img src="https://img.shields.io/pypi/v/mcppt?label=PyPI&color=orange"/>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue"/>
  <img src="https://img.shields.io/badge/checks-28-red"/>
  <img src="https://img.shields.io/badge/license-MIT-green"/>
  <img src="https://img.shields.io/badge/part%20of-Bugtrotter-black"/>
</p>

<p align="center">
  <b>by <a href="https://github.com/gurudeepmallam-cmd">Gurudeep Mallam</a> &nbsp;·&nbsp;
  <a href="https://in.linkedin.com/in/mallam-gurudeep-7734941aa">LinkedIn</a></b>
</p>

---

## What it does

MCPTROTTER is a command-line security scanner for **MCP (Model Context Protocol)** servers. Point it at any MCP endpoint and it runs 28 automated checks across:

- Authentication bypass and token abuse
- Prompt injection (direct, stored, poison-all fields)
- SSRF, command injection, path traversal
- Session entropy and replay attacks
- Tenant isolation and IDOR
- Tool poisoning and rug pulls
- Transport misconfigurations and secret leaks

Works against any MCP server using Streamable HTTP transport (POST + SSE response). Integrates with Burp Suite for manual follow-up. Exports pentest-ready Markdown reports.

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

You'll see:
```
  __  __   ___  ___  _____ ____   ___ _____ _____ ___ ___
 |  \/  | / __|| _ \|_   _|  _ \ / _ \_   _|_   _| __| _ \
 | |\/| || (__|  _/ | | |   /  | (_) || |   | | | _||   /
 |_|  |_| \___||_|  |_| |_|_\  \___/ |_|   |_| |___|_|_\

  MCP Pentest Tool  v2.1  --  16 automated security checks

  by Gurudeep Mallam
  github  : https://github.com/gurudeepmallam-cmd
  linkedin: https://in.linkedin.com/in/mallam-gurudeep-7734941aa

  type 'help' for commands, 'exit' to quit

mcppt>
```

**Paste these commands one by one:**
```
target http://127.0.0.1:8888/mcp
token  valid-token-abc123
status
scan
findings
report demo.md
```

---

## Expected output — demo server scan

Running `scan` with token set produces this (6.7 seconds):

```
Duration: 6.7s   Findings: 6 CRITICAL  6 HIGH  13 MEDIUM  3 LOW
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

## All commands (interactive shell)

```
Setup
  target  <url>          Set MCP server URL
  token   <bearer>       Set primary auth token
  token2  <bearer>       Set second user token (IDOR / scope / tenant checks)
  noverify               Toggle SSL verification skip (needed for self-signed certs)
  proxy   <url|off>      Set Burp proxy:  proxy http://127.0.0.1:8080
  status                 Show current config before scanning

Enumerate
  list                   List all tools the server exposes (names, params, descriptions)
  call <tool> [json]     Manually call any tool
                           call get_notes
                           call get_user {"id": 1}
                           call save_note {"text": "hello"}

Scan
  scan                   Run all checks
  scan auth ssrf idor    Run specific checks only
  scan stored injection  Mix and match any check names

Results
  findings               Colour-coded findings table
  clear                  Clear findings from last scan
  report out.md          Export Markdown report
  report out.json        Export JSON report

AI analysis (optional — paste your key first)
  ai claude  sk-ant-...  Configure Claude for analysis
  ai openai  sk-...      Configure OpenAI GPT-4o
  analyze                Attack narrative + remediation priority from findings

Shell
  help                   Full command reference
  exit                   Quit
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

### Step 2 — Run scan through proxy

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

Every MCP tool call appears as a `POST /mcp` request. Each row shows the JSON-RPC method and the response. You'll see one row per check — `initialize`, `tools/list`, `tools/call` for each tool tested.

Click any row to see the full request and response body:

```
POST /mcp HTTP/1.1
Host: target.com
Authorization: Bearer eyJ...
Content-Type: application/json

{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_notes","arguments":{}}}
```

### Step 4 — Send to Repeater for manual testing

In HTTP History, right-click any request → **Send to Repeater** (or `Ctrl+R`).

Switch to the **Repeater** tab. You'll see the exact request MCPTROTTER sent.

**To keep the connection alive and replay successfully:**

1. Check the **Host** field matches your target (e.g. `127.0.0.1` port `8888` for demo server, or your real target host/port)
2. If targeting HTTP (not HTTPS), make sure the **lock icon** in Repeater shows unlocked — click it to toggle if needed
3. The MCP session ID in `mcp-session-id` header may expire — if you get a session error, re-initialize:
   - Copy the `initialize` request from HTTP History into Repeater first
   - Send it, copy the `mcp-session-id` from the response header
   - Paste it into the header of your target request
4. Click **Send** — response appears on the right

**Modifying requests in Repeater:**

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
  "name":"get_user",
  "arguments":{"id": 2}
}}
```

Change `"id": 2` to `"id": 1` to test IDOR. Change the token in Authorization to another user's token. Modify `"name"` to call a different tool. Repeater sends exactly what you write.

### Step 5 — Fuzz with Intruder

Right-click a request in Repeater → **Send to Intruder**.

Highlight the value you want to fuzz (e.g. a tool parameter), click **Add §**. Load a wordlist (Burp's built-in fuzzing strings, or a custom injection list). Run the attack and sort by response length or status code to spot anomalies.

---

## All 28 checks

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

---

## MCPTROTTER vs manual testing — what you save

| Task | Manual in Burp | MCPTROTTER |
|---|---|---|
| Test auth bypass on every tool | 10–30 min | `scan auth` — 5s |
| Test stored injection (write + read) | 20 min | `scan stored` — 3s |
| Check all response fields for injection | 30+ min | `scan poison_all` — 5s |
| Verify session ID entropy | 10 min | `scan session` — 2s |
| Check replay on every tool | 20 min | `scan replay` — 5s |
| Full 28-check assessment | 3–6 hours | `scan` — 30s |

MCPTROTTER gives you the baseline in 30 seconds. You spend your time on what matters: manually verifying findings in Burp Repeater and chaining them into a demonstrated attack path.

---

## Part of Bugtrotter

MCPTROTTER is the public automated scanner extracted from **Bugtrotter** — a full red team and application security platform built for modern attack surfaces.

### What Bugtrotter adds on top of MCPTROTTER

| Capability | MCPTROTTER | Bugtrotter |
|---|---|---|
| Automated MCP scan (28 checks) | ✓ | ✓ |
| Manual finding verification | You do it in Burp | Guided playbooks |
| Chained exploit paths across tools | — | ✓ Full attack chain |
| SAST review of MCP server code | — | ✓ |
| Burp Suite MCP — business logic abuse | — | ✓ AI-driven |
| AI agent red teaming | — | ✓ Multi-agent pipelines |
| Active Directory kill chain | — | ✓ External → DA |
| Web / API / network pentesting | — | ✓ Full engagement |
| Final pentest report | Markdown export | Engagement-grade report |

**MCPTROTTER in fingertips inside Bugtrotter:**

In Bugtrotter, MCPTROTTER runs as a registered MCP server. Claude Code or Claude Desktop calls it directly:

```
"Scan https://target.com/mcp for security issues and prioritise findings"
→ Claude calls scan_target tool
→ MCPTROTTER runs all 28 checks
→ Findings returned as structured JSON to Claude
→ Claude reasons over them, chains the critical ones, drafts the report section
```

No copy-paste. No context switching. The scan output feeds straight into the AI-driven engagement workflow — SSRF finding becomes an SSRF exploit attempt, auth bypass becomes a credential theft chain, stored injection becomes a demonstrated prompt hijack.

That's the difference: MCPTROTTER finds the candidates in 30 seconds. Bugtrotter turns the candidates into proven, chained, client-ready findings.

---

## Use MCPTROTTER as an MCP server itself

MCPTROTTER can become an MCP server — exposing its scan capability as tools that any MCP client (Claude Desktop, MCP Inspector, another agent) can call.

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
- `get_checks` — list all 28 checks with descriptions

Inspect with MCP Inspector:
```bash
npx @modelcontextprotocol/inspector http://127.0.0.1:8899/mcp
```

---

## Author

**Gurudeep Mallam** — Security Researcher

- GitHub: [github.com/gurudeepmallam-cmd](https://github.com/gurudeepmallam-cmd)
- LinkedIn: [Mallam Gurudeep](https://in.linkedin.com/in/mallam-gurudeep-7734941aa)
- Email: gurudeep.mallam@gmail.com

---

## License

MIT
