"""Unit tests for mcppt.core — no network required."""
import json
import pytest
from unittest.mock import patch, MagicMock
from mcppt.core import (
    _parse_sse,
    decode_jwt,
    jsonrpc_succeeded,
    is_auth_error,
    configure,
    reset_session,
)


# ── _parse_sse ────────────────────────────────────────────────────────────────

def test_parse_sse_plain_json():
    raw = '{"jsonrpc":"2.0","result":{"tools":[]}}'
    assert _parse_sse(raw) == {"jsonrpc": "2.0", "result": {"tools": []}}


def test_parse_sse_event_stream():
    raw = "event: message\ndata: {\"id\":1,\"result\":{}}\n"
    assert _parse_sse(raw) == {"id": 1, "result": {}}


def test_parse_sse_empty():
    assert _parse_sse("") == {"error": "Empty response"}


def test_parse_sse_invalid_json():
    result = _parse_sse("not json")
    assert "raw" in result


# ── decode_jwt ────────────────────────────────────────────────────────────────

def test_decode_jwt_valid():
    import base64
    payload = base64.urlsafe_b64encode(b'{"sub":"1","scope":"read"}').decode().rstrip("=")
    token = f"header.{payload}.sig"
    claims = decode_jwt(token)
    assert claims["scope"] == "read"
    assert claims["sub"] == "1"


def test_decode_jwt_not_jwt():
    assert decode_jwt("notajwt") == {}


def test_decode_jwt_malformed():
    assert decode_jwt("a.b") == {}


# ── jsonrpc_succeeded ─────────────────────────────────────────────────────────

def test_jsonrpc_succeeded_true():
    body = {"result": {"content": [{"type": "text", "text": "some data"}]}}
    assert jsonrpc_succeeded(body) is True


def test_jsonrpc_succeeded_false_no_result():
    assert jsonrpc_succeeded({"error": {"code": 401}}) is False


def test_jsonrpc_succeeded_false_auth_in_content():
    body = {"result": {"content": [{"type": "text", "text": "Unauthorized access"}]}}
    assert jsonrpc_succeeded(body) is False


def test_jsonrpc_succeeded_false_forbidden():
    body = {"result": {"content": [{"type": "text", "text": "403 forbidden"}]}}
    assert jsonrpc_succeeded(body) is False


# ── is_auth_error ─────────────────────────────────────────────────────────────

def test_is_auth_error_401_code():
    assert is_auth_error({"error": {"code": 401, "message": ""}}) is True


def test_is_auth_error_403_code():
    assert is_auth_error({"error": {"code": 403, "message": ""}}) is True


def test_is_auth_error_by_message():
    assert is_auth_error({"error": {"code": 400, "message": "Unauthorized"}}) is True


def test_is_auth_error_false():
    assert is_auth_error({"error": {"code": 400, "message": "Missing field"}}) is False


# ── configure ─────────────────────────────────────────────────────────────────

def test_configure_no_verify():
    import mcppt.core as core
    configure(no_verify=True)
    assert core._SESSION.verify is False
    configure(no_verify=False)
    assert core._SESSION.verify is True


def test_configure_proxy():
    import mcppt.core as core
    configure(proxy="http://127.0.0.1:8080")
    assert core._SESSION.proxies.get("http") == "http://127.0.0.1:8080"
    configure(proxy=None)
    assert not core._SESSION.proxies


# ── reset_session ─────────────────────────────────────────────────────────────

def test_reset_session():
    import mcppt.core as core
    core._SESSION_ID = "some-session"
    reset_session()
    assert core._SESSION_ID is None
