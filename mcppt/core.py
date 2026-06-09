"""Low-level JSON-RPC transport for MCP Streamable HTTP servers.

Uses requests for proxy support (Burp CONNECT tunneling works correctly).
"""
from __future__ import annotations

import base64
import json
import warnings
from typing import Optional

import requests
from requests.exceptions import RequestException

_SESSION_ID: Optional[str] = None
_SESSION: requests.Session = requests.Session()
_LAST_HEADERS: dict = {}  # response headers from most recent rpc() call
_VERBOSE: bool = False


def configure(no_verify: bool = False, proxy: Optional[str] = None) -> None:
    global _SESSION
    _SESSION = requests.Session()
    if proxy:
        _SESSION.proxies = {"http": proxy, "https": proxy}
    _SESSION.verify = not no_verify
    if no_verify:
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass


def reset_session() -> None:
    global _SESSION_ID
    _SESSION_ID = None


def get_session_id() -> Optional[str]:
    return _SESSION_ID


def set_session_id(sid: Optional[str]) -> None:
    global _SESSION_ID
    _SESSION_ID = sid


def get_last_headers() -> dict:
    return _LAST_HEADERS


def rpc(
    url: str,
    method: str,
    params: dict,
    token: Optional[str] = None,
    req_id: int = 1,
) -> dict:
    global _SESSION_ID, _LAST_HEADERS
    payload = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if _SESSION_ID:
        headers["mcp-session-id"] = _SESSION_ID

    if _VERBOSE:
        print(f"\n[VERBOSE] --> {method}  id={req_id}")
        print(f"[VERBOSE] headers: {headers}")
        print(f"[VERBOSE] body: {json.dumps(payload)[:300]}")

    try:
        resp = _SESSION.post(url, json=payload, headers=headers, timeout=15)
        _LAST_HEADERS = dict(resp.headers)
        sid = resp.headers.get("mcp-session-id")
        if sid and not _SESSION_ID:
            _SESSION_ID = sid
        body = _parse_sse(resp.text)
        if _VERBOSE:
            print(f"[VERBOSE] <-- HTTP {resp.status_code}")
            print(f"[VERBOSE] resp headers: {dict(resp.headers)}")
            print(f"[VERBOSE] body: {json.dumps(body)[:300]}")
        return {"status": resp.status_code, "body": body}
    except RequestException as e:
        return {"status": 0, "body": {"error": str(e)}}
    except Exception as e:
        return {"status": 0, "body": {"error": str(e)}}


def _parse_sse(raw: str) -> dict:
    """Parse MCP response — handles both plain JSON and SSE event-stream."""
    raw = raw.strip()
    if not raw:
        return {"error": "Empty response"}

    data_lines = [line[5:].strip() for line in raw.splitlines() if line.startswith("data:")]
    if data_lines:
        # Each data: line is a complete JSON-RPC object.
        # Find the one that carries result or error (not a notification).
        for line in data_lines:
            if not line:
                continue
            try:
                obj = json.loads(line)
                if "result" in obj or "error" in obj:
                    return obj
            except Exception:
                pass
        # Fall back: return the last data line parsed as-is
        for line in reversed(data_lines):
            try:
                return json.loads(line)
            except Exception:
                pass
        return {"raw_sse": data_lines[0][:500]}

    # Plain JSON (no SSE wrapping)
    try:
        return json.loads(raw)
    except Exception:
        return {"raw": raw[:500]}


def mcp_init(url: str, token: Optional[str]) -> bool:
    reset_session()
    r = rpc(
        url,
        "initialize",
        {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcppt", "version": "3.0"},
        },
        token=token,
    )
    if r["status"] == 200 and "result" in r["body"]:
        rpc(url, "notifications/initialized", {}, token=token, req_id=2)
        return True
    return False


def decode_jwt(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        return json.loads(
            base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
        )
    except Exception:
        return {}


def jsonrpc_succeeded(body: dict) -> bool:
    """True if the response indicates actual tool execution, not an auth rejection."""
    if "result" not in body:
        return False
    content_text = "".join(
        i.get("text", "").lower() for i in body["result"].get("content", [])
    )
    AUTH_KEYWORDS = [
        "unauthorized", "forbidden", "401", "403", "access denied",
        "not authenticated", "invalid token", "token expired",
    ]
    return not any(k in content_text for k in AUTH_KEYWORDS)


def is_auth_error(body: dict) -> bool:
    err = body.get("error", {})
    code = err.get("code", 0)
    msg = str(err.get("message", "")).lower()
    AUTH_KEYWORDS = [
        "unauthorized", "forbidden", "authentication",
        "not authenticated", "invalid token", "access denied",
    ]
    return code in (401, 403) or any(k in msg for k in AUTH_KEYWORDS)
