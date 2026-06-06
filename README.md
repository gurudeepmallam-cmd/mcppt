# MCPPT — MCP Pentest Tool

> **16 automated security checks for any MCP server. No AI required. Pure Python.**

```
pip install mcppt
mcppt scan --url https://your-mcp-server.com/mcp --token eyJ...
```

![CI](https://github.com/gurudeepmallam-cmd/mcppt/actions/workflows/ci.yml/badge.svg)
![PyPI](https://img.shields.io/pypi/v/mcppt)
![Python](https://img.shields.io/pypi/pyversions/mcppt)
![License](https://img.shields.io/github/license/gurudeepmallam-cmd/mcppt)

---

## What is MCPPT?

MCPPT is a standalone command-line security tester for [MCP (Model Context Protocol)](https://modelcontextprotocol.io) servers. It runs 16 automated checks covering authentication, injection, IDOR, SSRF, session security, and AI-specific attack surfaces — with a live Rich TUI and optional JSON/Markdown report output.

**No AI dependency.** All checks are deterministic HTTP probes. Works against any MCP server using Streamable HTTP transport.

---

## Install

```bash
pip install mcppt
```

Requires Python 3.10+. The only dependency is `rich`.

---

## Usage

### Full security scan (live TUI)

```bash
# Full scan — all 16 checks
mcppt scan --url https://target.com/mcp --token eyJ...

# Two-user checks (IDOR, scope bypass, tenant isolation)
mcppt scan --url https://target.com/mcp --token <user1> --token2 <user2>

# Skip SSL verification (self-signed / staging certs)
mcppt scan --url https://target.com/mcp --token eyJ... --no-verify

# Route through Burp Suite for manual review
mcppt scan --url https://target.com/mcp --token eyJ... --proxy http://127.0.0.1:8080

# Run specific checks only
mcppt scan --url https://target.com/mcp --token eyJ... --checks auth,idor,ssrf

# Save report
mcppt scan --url https://target.com/mcp --token eyJ... --output report.md
mcppt scan --url https://target.com/mcp --token eyJ... --output report.json
```

### Enumerate tools

```bash
mcppt list --url https://target.com/mcp
mcppt list --url https://target.com/mcp --token eyJ...
```

### Call a tool manually

```bash
mcppt call --url https://target.com/mcp --token eyJ... --tool get_user --args '{"id": 1}'
```

---

## 16 Security Checks

| # | Check | Severity | What it tests |
|---|-------|----------|---------------|
| 1 | `enum` | MEDIUM | `tools/list` accessible without auth |
| 2 | `auth` | CRITICAL | Tool calls succeed with no/invalid token |
| 3 | `idor` | HIGH | Cross-user resource access (needs `--token2`) |
| 4 | `injection` | HIGH | Prompt injection payloads reflected in responses |
| 5 | `schema` | MEDIUM | Type confusion, oversized input, null bypass |
| 6 | `ssrf` | CRITICAL | Cloud metadata URLs accepted in tool params |
| 7 | `publish` | CRITICAL | Destructive tool callable without confirmation gate |
| 8 | `rate` | LOW | No rate limiting on tool calls |
| 9 | `stored` | CRITICAL | Stored prompt injection: write payload → read back unescaped |
| 10 | `scope` | HIGH | Read-only JWT token reaches write tools; RBAC bypass |
| 11 | `replay` | HIGH | Identical request accepted twice — no nonce/timestamp |
| 12 | `context_overflow` | HIGH | 50K–100K char payloads accepted → LLM context truncation |
| 13 | `poison_all` | CRITICAL | Injection payload in any response field, not just content |
| 14 | `tenant` | CRITICAL | Token2 reads token1's data — tenant isolation broken |
| 15 | `session` | HIGH | Weak/sequential session IDs (CVE-2025-6515 pattern) |
| 16 | `rug_pull` | CRITICAL | Tool descriptions change mid-session after `tools/list_changed` |

---

## TUI Output

```
┌──────────────────────────────────────────────────────────────────────┐
│  MCPPT  v2.0  ──  MCP Pentest Tool                                   │
│  Target  https://target.com/mcp   ·   Auth  token provided           │
├────────────────────────┬─────────────────────────────────────────────┤
│  Findings              │  Live Output                                 │
│  🔴 CRITICAL  2        │  [CHECK] [2/16] Auth bypass                  │
│  🟠 HIGH      3        │    [PASS] 'get_forms' correctly rejected      │
│  🟡 MEDIUM    1        │  [CHECK] [3/16] IDOR                         │
│  🔵 LOW       1        │    [HIGH] Possible IDOR on get_item(id=1)     │
│                        │  [CHECK] [4/16] Prompt injection             │
│  🔴 Auth bypass on...  │    [PASS] search.query — not reflected        │
│  🟠 Possible IDOR...   │  [CHECK] [5/16] Schema validation             │
│  🟠 Replay confirm...  │    [MED ] Schema bypass: update_form...       │
├────────────────────────┴─────────────────────────────────────────────┤
│  ████████████████░░░░░░░░░░░░░░░░░░░░  8/16  ·  22s  ·  schema      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Report Output

**JSON** (`--output report.json`):
```json
{
  "tool": "MCPPT",
  "version": "2.0.0",
  "target": "https://target.com/mcp",
  "elapsed_seconds": 47.3,
  "summary": { "CRITICAL": 2, "HIGH": 3, "MEDIUM": 1, "LOW": 1 },
  "findings": [
    {
      "check": "auth",
      "severity": "CRITICAL",
      "title": "Auth bypass on 'get_user' (no token)",
      "detail": "Tool executed without valid credentials"
    }
  ]
}
```

**Markdown** (`--output report.md`): full pentest report with findings, details, and remediation table — ready to paste into a bug report or engagement report.

---

## Supported MCP Transport

- **Streamable HTTP** (POST + SSE response) — the current MCP spec
- Handles both plain JSON and SSE-wrapped (`data: {...}`) responses
- Session ID tracking via `mcp-session-id` header

> stdio-based MCP servers are not supported directly — wrap them with a proxy or test via their HTTP adapter.

---

## Architecture

```
mcppt/
├── core.py     — JSON-RPC transport (urllib, no external deps)
├── checks.py   — 16 check functions + ScanState (thread-safe)
├── tui.py      — Rich live TUI (findings panel + live log + progress)
├── cli.py      — scan / list / call subcommands
└── report.py   — JSON + Markdown report generation
```

All checks update a shared `ScanState` object. The TUI renders from state on a 4 Hz refresh loop while the scan runs in a background thread.

---

## Development

```bash
git clone https://github.com/gurudeepmallam-cmd/mcppt
cd mcppt
pip install -e .
pip install pytest pytest-mock ruff
pytest tests/
ruff check mcppt/
```

---

## Releasing a new version

1. Bump `version` in `pyproject.toml` and `mcppt/__init__.py`
2. Commit and push
3. `git tag v2.1.0 && git push --tags`
4. CI builds, publishes to PyPI, and creates a GitHub Release automatically

---

## License

MIT — see [LICENSE](LICENSE).

---

## Author

**Gurudeep Mallam** · [github.com/gurudeepmallam-cmd](https://github.com/gurudeepmallam-cmd)

*Built during MCP security research on real-world enterprise MCP deployments.*
