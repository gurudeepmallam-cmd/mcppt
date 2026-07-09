"""
MCPTROTTER MCP Server — expose mcptrotter as an MCP server.

Two transports:
  stdio (default / Claude Code)
    mcppt serve-mcp --stdio
    Add to .mcp.json:
      "mcptrotter": { "type": "stdio", "command": "mcppt", "args": ["serve-mcp", "--stdio"] }

  HTTP + SSE (Burp Inspector / external clients)
    mcppt serve-mcp --port 8899
    Connect via:  http://127.0.0.1:8899/mcp
"""
from __future__ import annotations

import json
import sys
import threading
from collections import Counter
from typing import Optional

# ── Tool definitions ──────────────────────────────────────────────────────────

MCPPT_TOOLS = [
    {
        "name": "scan_mcp_server",
        "description": (
            "Run MCPTROTTER security scan against any MCP server. "
            "Runs up to 28 automated checks covering: auth bypass, prompt injection, "
            "SSRF, IDOR, stored injection, rug-pull, path traversal, secret leakage, "
            "JWT weaknesses, session entropy, command injection, and more. "
            "Returns structured findings with severity, check, title, and detail. "
            "Available checks: enum auth idor injection schema ssrf publish rate stored "
            "scope replay context_overflow poison_all tenant session rug_pull "
            "headers error_disclosure tool_poisoning resources cmd_injection "
            "path_traversal jwt_audit oauth_discovery secret_scan tool_shadowing "
            "sampling schema_leak — or pass 'all'."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url":       {"type": "string",  "description": "Target MCP server URL (required)"},
                "token":     {"type": "string",  "description": "Bearer token for authenticated scans (optional)"},
                "token2":    {"type": "string",  "description": "Second user token for IDOR/scope/tenant checks (optional)"},
                "checks":    {"type": "string",  "description": "Comma-separated checks or 'all' (default: all)"},
                "no_verify": {"type": "boolean", "description": "Skip SSL certificate verification (default: false)"},
                "proxy":     {"type": "string",  "description": "HTTP proxy URL e.g. http://127.0.0.1:8080 for Burp routing (optional)"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "quick_scan",
        "description": (
            "Run only the highest-impact MCPTROTTER checks (CRITICAL/HIGH severity). "
            "Checks: auth, ssrf, injection, stored, idor, poison_all, publish, rug_pull, tenant. "
            "Faster than a full scan — good for quick triage during pentests."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url":       {"type": "string",  "description": "Target MCP server URL (required)"},
                "token":     {"type": "string",  "description": "Bearer token (optional)"},
                "token2":    {"type": "string",  "description": "Second user token for IDOR/tenant checks (optional)"},
                "no_verify": {"type": "boolean", "description": "Skip SSL verification (default: false)"},
                "proxy":     {"type": "string",  "description": "Burp proxy URL (optional)"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "enumerate_mcp_tools",
        "description": (
            "List all tools exposed by a target MCP server with their schemas. "
            "Also checks whether enumeration requires authentication. "
            "Useful for reconnaissance before a targeted attack."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url":       {"type": "string",  "description": "Target MCP server URL"},
                "token":     {"type": "string",  "description": "Bearer token (optional)"},
                "no_verify": {"type": "boolean", "description": "Skip SSL verification"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "call_mcp_tool",
        "description": (
            "Call a specific tool on a target MCP server with custom arguments. "
            "Useful for manual exploitation: test specific payloads, verify IDOR, "
            "replay modified requests, or explore undocumented parameters."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url":       {"type": "string",  "description": "Target MCP server URL"},
                "token":     {"type": "string",  "description": "Bearer token (optional)"},
                "tool_name": {"type": "string",  "description": "Name of the tool to call"},
                "args":      {"type": "object",  "description": "JSON arguments for the tool (default: {})"},
                "no_verify": {"type": "boolean", "description": "Skip SSL verification"},
                "proxy":     {"type": "string",  "description": "Burp proxy URL (optional)"},
            },
            "required": ["url", "tool_name"],
        },
    },
    {
        "name": "check_auth",
        "description": (
            "Test specifically whether a target MCP server enforces authentication. "
            "Tries: no token, invalid token, expired-format token, and with valid token. "
            "Returns: requires_auth (bool), auth_bypass (bool), detail."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url":       {"type": "string",  "description": "Target MCP server URL"},
                "token":     {"type": "string",  "description": "Valid token to confirm auth works (optional)"},
                "no_verify": {"type": "boolean", "description": "Skip SSL verification"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "check_ssrf",
        "description": (
            "Test specifically for SSRF in all string parameters of all tools on the target MCP server. "
            "Injects cloud metadata URLs (AWS IMDSv1/v2, GCP, Azure) and internal IP ranges. "
            "Returns: vulnerable_tools, payloads_that_succeeded, evidence."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url":       {"type": "string",  "description": "Target MCP server URL"},
                "token":     {"type": "string",  "description": "Bearer token (optional)"},
                "no_verify": {"type": "boolean", "description": "Skip SSL verification"},
                "proxy":     {"type": "string",  "description": "Burp proxy to capture SSRF hits (optional)"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "list_checks",
        "description": (
            "Return all 28 MCPTROTTER security checks with ID, severity, and description. "
            "Use this to understand what scan_mcp_server tests before running a scan."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
]

ALL_CHECKS_INFO = [
    # Original 16
    {"id": "enum",             "severity": "MEDIUM",   "description": "tools/list accessible without auth"},
    {"id": "auth",             "severity": "CRITICAL", "description": "Tool calls succeed with no/invalid token"},
    {"id": "idor",             "severity": "HIGH",     "description": "Cross-user resource access (needs token2)"},
    {"id": "injection",        "severity": "HIGH",     "description": "Prompt injection payloads reflected in responses"},
    {"id": "schema",           "severity": "MEDIUM",   "description": "Type confusion, oversized input, null bypass"},
    {"id": "ssrf",             "severity": "CRITICAL", "description": "Cloud metadata URLs fetched via tool params"},
    {"id": "publish",          "severity": "CRITICAL", "description": "Destructive tool without confirmation gate"},
    {"id": "rate",             "severity": "LOW",      "description": "No rate limiting on tool calls (30 rapid requests)"},
    {"id": "stored",           "severity": "CRITICAL", "description": "Stored prompt injection: write→read unescaped"},
    {"id": "scope",            "severity": "HIGH",     "description": "Read-only token reaches write tools"},
    {"id": "replay",           "severity": "HIGH",     "description": "Same request accepted twice, no nonce/idempotency"},
    {"id": "context_overflow", "severity": "HIGH",     "description": "100K-char payload accepted → LLM context hijack"},
    {"id": "poison_all",       "severity": "CRITICAL", "description": "Injection marker appears in any response field"},
    {"id": "tenant",           "severity": "CRITICAL", "description": "Token2 reads token1 data (tenant isolation broken)"},
    {"id": "session",          "severity": "HIGH",     "description": "Weak/sequential session IDs (CVE-2025-6515 pattern)"},
    {"id": "rug_pull",         "severity": "CRITICAL", "description": "Tool descriptions change between list calls"},
    # v2.2 additions (10 new)
    {"id": "headers",          "severity": "MEDIUM",   "description": "CORS wildcard, missing CSP/HSTS, Server header leak"},
    {"id": "error_disclosure", "severity": "MEDIUM",   "description": "Stack traces / file paths in error responses"},
    {"id": "tool_poisoning",   "severity": "HIGH",     "description": "Zero-width Unicode / variation selectors in tool descriptions"},
    {"id": "resources",        "severity": "HIGH",     "description": "resources/list unauthenticated + path traversal via URI"},
    {"id": "cmd_injection",    "severity": "CRITICAL", "description": "Shell metacharacters in string params → OS command output"},
    {"id": "path_traversal",   "severity": "HIGH",     "description": "../../etc/passwd in file/path/src params"},
    {"id": "jwt_audit",        "severity": "HIGH",     "description": "alg=none, weak HS256, no exp, long lifetime, expired accepted"},
    {"id": "oauth_discovery",  "severity": "LOW",      "description": "/.well-known/oauth-authorization-server exposed"},
    {"id": "secret_scan",      "severity": "CRITICAL", "description": "AWS keys / GitHub PATs / API keys in tool responses"},
    {"id": "tool_shadowing",   "severity": "HIGH",     "description": "Duplicate names, homoglyphs, dangerous name patterns"},
    # v2.3 additions
    {"id": "sampling",         "severity": "HIGH",     "description": "sampling/createMessage accessible without auth"},
    {"id": "schema_leak",      "severity": "MEDIUM",   "description": "Sensitive enum values / internal fields in tool schemas"},
]

QUICK_CHECKS = [
    "enum", "auth", "ssrf", "injection", "stored",
    "idor", "poison_all", "publish", "rug_pull", "tenant",
    "cmd_injection", "secret_scan",
]


# ── Core scan runner ──────────────────────────────────────────────────────────

def _run_scan_sync(url: str, token: Optional[str], token2: Optional[str],
                   checks: list, no_verify: bool, proxy: Optional[str]) -> dict:
    from .core import configure
    from .checks import ScanState, run_scan

    configure(no_verify=no_verify, proxy=proxy)
    state = ScanState(url=url, token=token, token2=token2,
                      checks_total=len(checks))

    t = threading.Thread(target=run_scan, args=(state, checks), daemon=True)
    t.start()
    t.join(timeout=180)

    counts = Counter(f.severity for f in state.findings)
    return {
        "target":          url,
        "elapsed_seconds": round(state.elapsed, 1),
        "checks_run":      state.checks_done,
        "summary": {
            "CRITICAL": counts.get("CRITICAL", 0),
            "HIGH":     counts.get("HIGH",     0),
            "MEDIUM":   counts.get("MEDIUM",   0),
            "LOW":      counts.get("LOW",      0),
            "total":    len(state.findings),
        },
        "findings": [
            {
                "check":    f.check,
                "severity": f.severity,
                "title":    f.title,
                "detail":   f.detail,
            }
            for f in state.findings
        ],
    }


# ── Tool handlers ─────────────────────────────────────────────────────────────

def _handle_scan_mcp_server(args: dict) -> str:
    checks_raw = args.get("checks", "all")
    if checks_raw == "all":
        from .cli import CHECKS as ALL
        checks = ALL
    else:
        checks = [c.strip() for c in checks_raw.split(",")]

    result = _run_scan_sync(
        url=args.get("url", ""),
        token=args.get("token") or None,
        token2=args.get("token2") or None,
        checks=checks,
        no_verify=bool(args.get("no_verify", False)),
        proxy=args.get("proxy") or None,
    )
    return json.dumps(result, indent=2)


def _handle_quick_scan(args: dict) -> str:
    result = _run_scan_sync(
        url=args.get("url", ""),
        token=args.get("token") or None,
        token2=args.get("token2") or None,
        checks=QUICK_CHECKS,
        no_verify=bool(args.get("no_verify", False)),
        proxy=args.get("proxy") or None,
    )
    result["note"] = "Quick scan: only CRITICAL/HIGH-priority checks run"
    return json.dumps(result, indent=2)


def _handle_enumerate_mcp_tools(args: dict) -> str:
    from .core import configure, mcp_init, rpc

    configure(no_verify=bool(args.get("no_verify", False)))
    url   = args.get("url", "")
    token = args.get("token") or None

    # Try without auth first
    mcp_init(url, None)
    r_no_auth = rpc(url, "tools/list", {}, token=None)
    no_auth_works = r_no_auth["status"] == 200

    # Try with auth
    if token:
        from .core import reset_session
        reset_session()
        mcp_init(url, token)
        r_auth = rpc(url, "tools/list", {}, token=token)
        tools = r_auth["body"].get("result", {}).get("tools", []) if r_auth["status"] == 200 else []
    else:
        tools = r_no_auth["body"].get("result", {}).get("tools", []) if no_auth_works else []

    return json.dumps({
        "url":                    url,
        "requires_auth_for_list": not no_auth_works,
        "tool_count":             len(tools),
        "tools":                  tools,
    }, indent=2)


def _handle_call_mcp_tool(args: dict) -> str:
    from .core import configure, mcp_init, rpc

    url   = args.get("url", "")
    token = args.get("token") or None

    configure(
        no_verify=bool(args.get("no_verify", False)),
        proxy=args.get("proxy") or None,
    )
    mcp_init(url, token)
    r = rpc(url, "tools/call",
            {"name": args.get("tool_name", ""), "arguments": args.get("args", {})},
            token=token)
    return json.dumps(r, indent=2)


def _handle_check_auth(args: dict) -> str:
    from .core import configure, mcp_init, rpc, reset_session

    url   = args.get("url", "")
    token = args.get("token") or None
    configure(no_verify=bool(args.get("no_verify", False)))

    results = {}

    for label, tok in [("no_token", None), ("bad_token", "invalid_token_test")]:
        reset_session()
        mcp_init(url, tok)
        r = rpc(url, "tools/list", {}, token=tok)
        results[label] = {"status": r["status"], "has_tools": bool(
            r["body"].get("result", {}).get("tools")
        )}

    if token:
        reset_session()
        mcp_init(url, token)
        r = rpc(url, "tools/list", {}, token=token)
        results["valid_token"] = {"status": r["status"], "has_tools": bool(
            r["body"].get("result", {}).get("tools")
        )}

    auth_bypass = (
        results.get("no_token",  {}).get("has_tools", False) or
        results.get("bad_token", {}).get("has_tools", False)
    )

    return json.dumps({
        "url":          url,
        "auth_bypass":  auth_bypass,
        "requires_auth": not auth_bypass,
        "detail":       results,
        "verdict": (
            "CRITICAL: tools/list accessible without authentication"
            if auth_bypass else
            "PASS: authentication enforced on tools/list"
        ),
    }, indent=2)


def _handle_check_ssrf(args: dict) -> str:
    from .core import configure, mcp_init, rpc

    url   = args.get("url", "")
    token = args.get("token") or None
    configure(
        no_verify=bool(args.get("no_verify", False)),
        proxy=args.get("proxy") or None,
    )

    SSRF_PAYLOADS = [
        "http://169.254.169.254/latest/meta-data/",          # AWS IMDSv1
        "http://169.254.169.254/metadata/instance",           # Azure IMDS
        "http://metadata.google.internal/computeMetadata/v1/",# GCP
        "http://0.0.0.0/",
        "http://127.0.0.1/",
    ]

    mcp_init(url, token)
    r = rpc(url, "tools/list", {}, token=token)
    tools = r["body"].get("result", {}).get("tools", []) if r["status"] == 200 else []

    hits = []
    for tool in tools:
        props = tool.get("inputSchema", {}).get("properties", {})
        url_params = [k for k, v in props.items()
                      if any(kw in k.lower() for kw in ("url", "uri", "endpoint", "host", "src", "target"))]
        for param in url_params:
            for payload in SSRF_PAYLOADS:
                r2 = rpc(url, "tools/call",
                         {"name": tool.get("name"), "arguments": {param: payload}},
                         token=token)
                body_str = json.dumps(r2.get("body", {}))
                if any(indicator in body_str for indicator in
                       ["ami-id", "instance-id", "computeMetadata", "Azure",
                        "169.254", "metadata"]):
                    hits.append({
                        "tool":    tool.get("name"),
                        "param":   param,
                        "payload": payload,
                        "evidence": body_str[:300],
                    })

    return json.dumps({
        "url":     url,
        "vulnerable": bool(hits),
        "hits":    hits,
        "verdict": (
            "CRITICAL: SSRF confirmed — cloud metadata reached via MCP tool params"
            if hits else
            "PASS: no SSRF indicators detected in tested parameters"
        ),
    }, indent=2)


def _handle_list_checks() -> str:
    return json.dumps(ALL_CHECKS_INFO, indent=2)


# ── Message dispatcher ────────────────────────────────────────────────────────

def _dispatch(method: str, params: dict, req_id: int) -> dict:
    def _ok(text: str) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": text}]},
        }

    def _err(msg: str, code: int = -32601) -> dict:
        return {"jsonrpc": "2.0", "id": req_id,
                "error": {"code": code, "message": msg}}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mcptrotter", "version": "3.1.0"},
            },
        }

    if method in ("notifications/initialized", "notifications/tools/list_changed"):
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": MCPPT_TOOLS}}

    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments", {})

        handlers = {
            "scan_mcp_server":     lambda: _handle_scan_mcp_server(args),
            "quick_scan":          lambda: _handle_quick_scan(args),
            "enumerate_mcp_tools": lambda: _handle_enumerate_mcp_tools(args),
            "call_mcp_tool":       lambda: _handle_call_mcp_tool(args),
            "check_auth":          lambda: _handle_check_auth(args),
            "check_ssrf":          lambda: _handle_check_ssrf(args),
            "list_checks":         lambda: _handle_list_checks(),
        }

        if name not in handlers:
            return _err(f"Unknown tool: {name}")

        try:
            result_text = handlers[name]()
            return _ok(result_text)
        except Exception as exc:
            return _err(f"Tool error: {exc}", code=-32603)

    return _err(f"Unknown method: {method}")


# ── stdio transport ───────────────────────────────────────────────────────────

def serve_stdio() -> None:
    """
    Stdio transport — recommended for Claude Code .mcp.json integration.

    Add to .mcp.json:
      "mcptrotter": {
        "type": "stdio",
        "command": "mcppt",
        "args": ["serve-mcp", "--stdio"]
      }
    """
    print("[mcptrotter] stdio MCP server starting", file=sys.stderr, flush=True)

    while True:
        try:
            line = sys.stdin.readline()
        except (EOFError, KeyboardInterrupt):
            break

        if not line:
            break

        line = line.strip()
        if not line:
            continue

        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        method  = msg.get("method", "")
        params  = msg.get("params", {})
        req_id  = msg.get("id", 0)

        response = _dispatch(method, params, req_id)

        # Notifications have no id — don't reply
        if msg.get("id") is None and method.startswith("notifications/"):
            continue

        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


# ── HTTP + SSE transport ──────────────────────────────────────────────────────

def serve_http(port: int = 8899) -> None:
    """
    HTTP Streamable-HTTP transport — for MCP Inspector / external clients.

    Connect via: http://127.0.0.1:{port}/mcp
    """
    from flask import Flask, request, Response

    http_app = Flask(__name__)

    def _sse_wrap(body: dict) -> Response:
        return Response(
            f"event: message\ndata: {json.dumps(body)}\n\n",
            mimetype="text/event-stream",
        )

    @http_app.route("/mcp", methods=["POST"])
    def mcp_endpoint():
        body    = request.get_json(force=True, silent=True) or {}
        method  = body.get("method", "")
        params  = body.get("params", {})
        req_id  = body.get("id", 1)
        resp_body = _dispatch(method, params, req_id)
        resp = _sse_wrap(resp_body)
        resp.headers["mcp-session-id"] = "mcptrotter-http-001"
        return resp

    print("=" * 55)
    print("  MCPTROTTER MCP Server (HTTP)")
    print(f"  Endpoint : http://127.0.0.1:{port}/mcp")
    print(f"  Inspector: npx @modelcontextprotocol/inspector http://127.0.0.1:{port}/mcp")
    print("=" * 55)
    http_app.run(host="127.0.0.1", port=port, debug=False)


# ── Entry point ───────────────────────────────────────────────────────────────

def serve(port: int = 8899, stdio: bool = False) -> None:
    if stdio:
        serve_stdio()
    else:
        serve_http(port)
