#!/usr/bin/env python3
"""
Vulnerable test MCP server for MCPPT local testing.

Intentional weaknesses (so MCPPT findings fire):
  MEDIUM  — tools/list works without auth
  CRITICAL— get_notes callable without token
  HIGH    — replay: same req_id accepted twice
  HIGH    — no rate limiting (30 requests all succeed)
  HIGH    — session IDs are sequential integers (weak entropy)
  MEDIUM  — schema: accepts wrong types
  HIGH    — stored injection: write payload → read back unescaped
  CRITICAL— tenant: token2 reads token1's notes
  MEDIUM  — rug_pull: tool list unchanged (PASS)

Run:  python test_server.py
      → listening on http://127.0.0.1:8888/mcp

Scan: mcppt scan --url http://127.0.0.1:8888/mcp --checks all
"""

import json
import threading
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

# ── Shared state ──────────────────────────────────────────────────────────────
_notes: list = []               # shared across ALL tokens (tenant isolation broken)
_session_counter = 100          # sequential session IDs
_session_lock = threading.Lock()

VALID_TOKEN = "valid-token-abc123"

TOOLS = [
    {
        "name": "get_notes",
        "description": "Return all saved notes",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "save_note",
        "description": "Save a note with a text field",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Note content"},
                "tag":  {"type": "string", "description": "Optional tag"},
            },
            "required": ["text"],
        },
    },
    {
        "name": "get_user",
        "description": "Get user profile by id",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "integer", "description": "User ID"}},
            "required": ["id"],
        },
    },
    {
        "name": "publish_report",
        "description": "Publish a report immediately (no confirmation gate)",
        "inputSchema": {
            "type": "object",
            "properties": {"title": {"type": "string"}, "content": {"type": "string"}},
            "required": ["title"],
        },
    },
]


# ── Transport helpers ─────────────────────────────────────────────────────────

def sse_wrap(body: dict) -> Response:
    """Wrap JSON body in SSE format."""
    data = json.dumps(body)
    return Response(f"event: message\ndata: {data}\n\n", mimetype="text/event-stream")


def _get_session() -> str:
    global _session_counter
    with _session_lock:
        sid = str(_session_counter)
        _session_counter += 1
    return sid


# ── MCP endpoint ──────────────────────────────────────────────────────────────

@app.route("/mcp", methods=["POST"])
def mcp():
    global _notes

    body = request.get_json(force=True, silent=True) or {}
    method  = body.get("method", "")
    params  = body.get("params", {})
    req_id  = body.get("id", 1)
    token   = request.headers.get("Authorization", "").replace("Bearer ", "")

    # ── initialize ────────────────────────────────────────────────────────────
    if method == "initialize":
        sid = _get_session()
        resp = sse_wrap({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "vuln-test-server", "version": "1.0"},
            },
        })
        resp.headers["mcp-session-id"] = sid
        return resp

    if method == "notifications/initialized":
        return sse_wrap({"jsonrpc": "2.0", "id": req_id, "result": {}})

    # ── tools/list — NO auth required (intentional MEDIUM finding) ────────────
    if method == "tools/list":
        return sse_wrap({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": TOOLS},
        })

    if method == "notifications/tools/list_changed":
        return sse_wrap({"jsonrpc": "2.0", "id": req_id, "result": {}})

    # ── tools/call ────────────────────────────────────────────────────────────
    if method == "tools/call":
        tool_name = params.get("name", "")
        args      = params.get("arguments", {})

        # get_notes — NO auth check (intentional CRITICAL auth bypass)
        if tool_name == "get_notes":
            return sse_wrap({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(_notes)}]
                },
            })

        # save_note — requires auth, stores unescaped (stored injection surface)
        if tool_name == "save_note":
            if not token or token != VALID_TOKEN:
                return sse_wrap({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": 401, "message": "Unauthorized"},
                })
            text = args.get("text", "")
            tag  = args.get("tag", "")
            # Store raw — no sanitization (stored injection + poison_all)
            _notes.append({"text": text, "tag": tag, "token": token[:8]})
            return sse_wrap({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": "saved"}]},
            })

        # get_user — requires auth, accepts any integer (schema ok, no IDOR guard)
        if tool_name == "get_user":
            if not token or token != VALID_TOKEN:
                return sse_wrap({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": 401, "message": "Unauthorized"},
                })
            uid = args.get("id", 0)
            # Same data for every user ID + every token (IDOR surface)
            return sse_wrap({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{
                        "type": "text",
                        "text": json.dumps({"id": uid, "name": "Alice", "role": "user"}),
                    }]
                },
            })

        # publish_report — no auth, no confirmation gate (CRITICAL)
        if tool_name == "publish_report":
            title   = args.get("title", "untitled")
            content = args.get("content", "")
            return sse_wrap({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Published: {title}"}]
                },
            })

        # unknown tool
        return sse_wrap({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
        })

    # unknown method
    return sse_wrap({
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Unknown method: {method}"},
    })


if __name__ == "__main__":
    print("=" * 55)
    print("  Vulnerable MCP Test Server")
    print("  URL:   http://127.0.0.1:8888/mcp")
    print("  Token: valid-token-abc123")
    print()
    print("  Scan with:")
    print("  mcppt scan --url http://127.0.0.1:8888/mcp \\")
    print("    --token valid-token-abc123 --checks all")
    print("=" * 55)
    app.run(host="127.0.0.1", port=8888, debug=False)
