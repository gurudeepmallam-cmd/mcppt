"""
MCPPT MCP Server mode — expose MCPPT itself as an MCP server.

Run:  mcppt serve-mcp [--port 8899]

Any MCP client (Claude Desktop, MCP Inspector, another Claude agent)
can then call MCPPT tools:
  - scan_target      → run security scan, returns findings JSON
  - list_tools       → enumerate tools on a target MCP server
  - call_tool        → call a specific tool on a target MCP server
  - get_checks       → list all 16 available checks with descriptions
"""
from __future__ import annotations

import json
import threading

from flask import Flask, request, Response

app = Flask(__name__)

MCPPT_TOOLS = [
    {
        "name": "scan_target",
        "description": (
            "Run MCPPT security scan against an MCP server. "
            "Returns findings with severity, check name, title, and detail. "
            "Checks: enum,auth,idor,injection,schema,ssrf,publish,rate,stored,"
            "scope,replay,context_overflow,poison_all,tenant,session,rug_pull,all"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url":       {"type": "string", "description": "Target MCP server URL"},
                "token":     {"type": "string", "description": "Bearer token (optional)"},
                "token2":    {"type": "string", "description": "Second user token for IDOR/scope checks (optional)"},
                "checks":    {"type": "string", "description": "Comma-separated checks or 'all' (default: all)"},
                "no_verify": {"type": "boolean","description": "Skip SSL cert verification (default: false)"},
                "proxy":     {"type": "string", "description": "HTTP proxy URL e.g. http://127.0.0.1:8080 (optional)"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "list_tools",
        "description": "Enumerate tools and schemas from a target MCP server.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url":       {"type": "string", "description": "Target MCP server URL"},
                "token":     {"type": "string", "description": "Bearer token (optional)"},
                "no_verify": {"type": "boolean","description": "Skip SSL cert verification"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "call_tool",
        "description": "Call a specific tool on a target MCP server and return the response.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url":       {"type": "string", "description": "Target MCP server URL"},
                "token":     {"type": "string", "description": "Bearer token (optional)"},
                "tool_name": {"type": "string", "description": "Name of the tool to call"},
                "args":      {"type": "object", "description": "JSON arguments for the tool"},
                "no_verify": {"type": "boolean","description": "Skip SSL cert verification"},
            },
            "required": ["url", "tool_name"],
        },
    },
    {
        "name": "get_checks",
        "description": "Return the list of all 16 MCPPT security checks with descriptions.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
]

CHECKS_INFO = [
    {"id": "enum",             "severity": "MEDIUM",   "description": "tools/list accessible without auth"},
    {"id": "auth",             "severity": "CRITICAL", "description": "Tool calls succeed with no/invalid token"},
    {"id": "idor",             "severity": "HIGH",     "description": "Cross-user resource access (needs token2)"},
    {"id": "injection",        "severity": "HIGH",     "description": "Prompt injection payloads reflected"},
    {"id": "schema",           "severity": "MEDIUM",   "description": "Type confusion, oversized input, null bypass"},
    {"id": "ssrf",             "severity": "CRITICAL", "description": "Cloud metadata URLs fetched via tool params"},
    {"id": "publish",          "severity": "CRITICAL", "description": "Destructive tool without confirmation gate"},
    {"id": "rate",             "severity": "LOW",      "description": "No rate limiting on tool calls"},
    {"id": "stored",           "severity": "CRITICAL", "description": "Stored prompt injection: write→read unescaped"},
    {"id": "scope",            "severity": "HIGH",     "description": "Read-only token reaches write tools"},
    {"id": "replay",           "severity": "HIGH",     "description": "Same request accepted twice, no nonce"},
    {"id": "context_overflow", "severity": "HIGH",     "description": "100K-char payload → LLM context truncation"},
    {"id": "poison_all",       "severity": "CRITICAL", "description": "Injection in any response field (CyberArk)"},
    {"id": "tenant",           "severity": "CRITICAL", "description": "Token2 reads token1 data (isolation broken)"},
    {"id": "session",          "severity": "HIGH",     "description": "Weak/sequential session IDs (CVE-2025-6515)"},
    {"id": "rug_pull",         "severity": "CRITICAL", "description": "Tool descriptions change mid-session"},
]

_session_id = "mcppt-server-session-001"


def _sse(body: dict) -> Response:
    return Response(
        f"event: message\ndata: {json.dumps(body)}\n\n",
        mimetype="text/event-stream",
    )


def _text_result(text: str) -> dict:
    return {"result": {"content": [{"type": "text", "text": text}]}}


# ── tool handlers ─────────────────────────────────────────────────────────────

def _handle_scan_target(args: dict, req_id: int) -> Response:
    from .core import configure
    from .checks import ScanState, run_scan

    url      = args.get("url", "")
    token    = args.get("token") or None
    token2   = args.get("token2") or None
    checks   = [c.strip() for c in args.get("checks", "all").split(",")]
    no_verify= bool(args.get("no_verify", False))
    proxy    = args.get("proxy") or None

    configure(no_verify=no_verify, proxy=proxy)
    state = ScanState(url=url, token=token, token2=token2)

    t = threading.Thread(target=run_scan, args=(state, checks), daemon=True)
    t.start()
    t.join(timeout=120)

    findings_data = [
        {"check": f.check, "severity": f.severity, "title": f.title, "detail": f.detail}
        for f in state.findings
    ]
    from collections import Counter
    counts = Counter(f.severity for f in state.findings)
    result = {
        "target": url,
        "elapsed_seconds": round(state.elapsed, 1),
        "summary": {
            "CRITICAL": counts.get("CRITICAL", 0),
            "HIGH":     counts.get("HIGH", 0),
            "MEDIUM":   counts.get("MEDIUM", 0),
            "LOW":      counts.get("LOW", 0),
            "total":    len(state.findings),
        },
        "findings": findings_data,
    }
    return _sse({"jsonrpc": "2.0", "id": req_id, **_text_result(json.dumps(result, indent=2))})


def _handle_list_tools(args: dict, req_id: int) -> Response:
    from .core import configure, mcp_init, rpc

    url      = args.get("url", "")
    token    = args.get("token") or None
    no_verify= bool(args.get("no_verify", False))

    configure(no_verify=no_verify)
    mcp_init(url, token)
    r = rpc(url, "tools/list", {}, token=token)
    tools = r["body"].get("result", {}).get("tools", []) if r["status"] == 200 else []
    return _sse({"jsonrpc": "2.0", "id": req_id, **_text_result(json.dumps(tools, indent=2))})


def _handle_call_tool(args: dict, req_id: int) -> Response:
    from .core import configure, mcp_init, rpc

    url       = args.get("url", "")
    token     = args.get("token") or None
    tool_name = args.get("tool_name", "")
    tool_args = args.get("args", {})
    no_verify = bool(args.get("no_verify", False))

    configure(no_verify=no_verify)
    mcp_init(url, token)
    r = rpc(url, "tools/call", {"name": tool_name, "arguments": tool_args}, token=token)
    return _sse({"jsonrpc": "2.0", "id": req_id, **_text_result(json.dumps(r, indent=2))})


def _handle_get_checks(req_id: int) -> Response:
    return _sse({"jsonrpc": "2.0", "id": req_id, **_text_result(json.dumps(CHECKS_INFO, indent=2))})


# ── MCP endpoint ──────────────────────────────────────────────────────────────

@app.route("/mcp", methods=["POST"])
def mcp_endpoint():
    body    = request.get_json(force=True, silent=True) or {}
    method  = body.get("method", "")
    params  = body.get("params", {})
    req_id  = body.get("id", 1)

    if method == "initialize":
        resp = _sse({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mcppt", "version": "2.1.0"},
            },
        })
        resp.headers["mcp-session-id"] = _session_id
        return resp

    if method in ("notifications/initialized", "notifications/tools/list_changed"):
        return _sse({"jsonrpc": "2.0", "id": req_id, "result": {}})

    if method == "tools/list":
        return _sse({"jsonrpc": "2.0", "id": req_id, "result": {"tools": MCPPT_TOOLS}})

    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments", {})
        if name == "scan_target":
            return _handle_scan_target(args, req_id)
        if name == "list_tools":
            return _handle_list_tools(args, req_id)
        if name == "call_tool":
            return _handle_call_tool(args, req_id)
        if name == "get_checks":
            return _handle_get_checks(req_id)
        return _sse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool: {name}"}})

    return _sse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown method: {method}"}})


# ── launcher ──────────────────────────────────────────────────────────────────

def serve(port: int = 8899):
    print("=" * 55)
    print("  MCPPT MCP Server")
    print(f"  Endpoint: http://127.0.0.1:{port}/mcp")
    print()
    print("  Add to Claude Desktop config:")
    print('  {')
    print('    "mcpServers": {')
    print('      "mcppt": {')
    print('        "command": "mcppt",')
    print('        "args": ["serve-mcp"]')
    print('      }')
    print('    }')
    print('  }')
    print()
    print("  Or use with MCP Inspector:")
    print(f"  npx @modelcontextprotocol/inspector http://127.0.0.1:{port}/mcp")
    print("=" * 55)
    app.run(host="127.0.0.1", port=port, debug=False)
