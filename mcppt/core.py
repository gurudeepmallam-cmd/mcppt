"""Low-level JSON-RPC transport for MCP Streamable HTTP servers."""
from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from typing import Any, Optional

_SESSION_ID: Optional[str] = None
_SSL_CTX: Optional[ssl.SSLContext] = None
_PROXY_HANDLER: Any = None


def configure(no_verify: bool = False, proxy: Optional[str] = None) -> None:
    global _SSL_CTX, _PROXY_HANDLER
    if no_verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        _SSL_CTX = ctx
    else:
        _SSL_CTX = None
    _PROXY_HANDLER = (
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}) if proxy else None
    )


def reset_session() -> None:
    global _SESSION_ID
    _SESSION_ID = None


def get_session_id() -> Optional[str]:
    return _SESSION_ID


def set_session_id(sid: Optional[str]) -> None:
    global _SESSION_ID
    _SESSION_ID = sid


def rpc(
    url: str,
    method: str,
    params: dict,
    token: Optional[str] = None,
    req_id: int = 1,
) -> dict:
    global _SESSION_ID
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
    ).encode()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if _SESSION_ID:
        headers["mcp-session-id"] = _SESSION_ID

    try:
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        if _PROXY_HANDLER:
            extra = (
                urllib.request.HTTPSHandler(context=_SSL_CTX)
                if _SSL_CTX
                else urllib.request.HTTPSHandler()
            )
            opener = urllib.request.build_opener(_PROXY_HANDLER, extra)
        elif _SSL_CTX:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=_SSL_CTX)
            )
        else:
            opener = urllib.request.build_opener()

        with opener.open(req, timeout=15) as resp:
            sid = resp.headers.get("mcp-session-id")
            if sid and not _SESSION_ID:
                _SESSION_ID = sid
            return {
                "status": resp.status,
                "body": _parse_sse(resp.read().decode(errors="replace")),
            }
    except urllib.error.HTTPError as e:
        try:
            body = _parse_sse(e.read().decode(errors="replace"))
        except Exception:
            body = {"raw": str(e)}
        return {"status": e.code, "body": body}
    except Exception as e:
        return {"status": 0, "body": {"error": str(e)}}


def _parse_sse(raw: str) -> dict:
    raw = raw.strip()
    if not raw:
        return {"error": "Empty response"}
    data_lines = [
        line[5:].strip() for line in raw.splitlines() if line.startswith("data:")
    ]
    if data_lines:
        try:
            return json.loads("\n".join(data_lines))
        except Exception:
            return {"raw_sse": "\n".join(data_lines)}
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
            "clientInfo": {"name": "mcppt", "version": "2.0"},
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
