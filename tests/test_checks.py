"""Unit tests for mcppt.checks — mocks all network calls."""
import json
import pytest
from unittest.mock import patch, MagicMock

from mcppt.checks import ScanState, _minimal_args, Finding


# ── ScanState ─────────────────────────────────────────────────────────────────

def make_state(**kwargs) -> ScanState:
    return ScanState(
        url="http://mock.local/mcp",
        token="test-token",
        token2=kwargs.get("token2"),
    )


def test_state_finding_appended():
    state = make_state()
    state.finding("enum", "MEDIUM", "Test finding", "detail")
    assert len(state.findings) == 1
    assert state.findings[0].severity == "MEDIUM"
    assert state.findings[0].title == "Test finding"


def test_state_ok_logged():
    state = make_state()
    state.ok("All good")
    assert any("All good" in line for line in state.log_lines)


def test_state_info_logged():
    state = make_state()
    state.info("Some info")
    assert any("Some info" in line for line in state.log_lines)


def test_state_finish_check_increments():
    state = make_state()
    assert state.checks_done == 0
    state.finish_check()
    assert state.checks_done == 1


def test_state_start_check_sets_current():
    state = make_state()
    state.start_check("auth", "[2/16] Auth bypass")
    assert state.current_check == "auth"


# ── _minimal_args ─────────────────────────────────────────────────────────────

def test_minimal_args_string():
    schema = {"name": {"type": "string"}}
    assert _minimal_args(schema, ["name"]) == {"name": "test"}


def test_minimal_args_integer():
    schema = {"id": {"type": "integer"}}
    assert _minimal_args(schema, ["id"]) == {"id": 1}


def test_minimal_args_boolean():
    schema = {"enabled": {"type": "boolean"}}
    assert _minimal_args(schema, ["enabled"]) == {"enabled": True}


def test_minimal_args_nullable_type():
    schema = {"value": {"type": ["string", "null"]}}
    assert _minimal_args(schema, ["value"]) == {"value": "test"}


def test_minimal_args_empty_required():
    schema = {"opt": {"type": "string"}}
    assert _minimal_args(schema, []) == {}


# ── check_enum ────────────────────────────────────────────────────────────────

@patch("mcppt.checks.mcp_init")
@patch("mcppt.checks.rpc")
def test_check_enum_exposed(mock_rpc, mock_init):
    mock_init.return_value = True
    mock_rpc.return_value = {
        "status": 200,
        "body": {"result": {"tools": [{"name": "get_data"}, {"name": "write_data"}]}},
    }
    state = make_state()
    from mcppt.checks import check_enum
    tools = check_enum(state)
    assert len(state.findings) == 1
    assert state.findings[0].severity == "MEDIUM"
    assert len(tools) == 2


@patch("mcppt.checks.mcp_init")
@patch("mcppt.checks.rpc")
def test_check_enum_requires_auth(mock_rpc, mock_init):
    mock_init.return_value = True

    def side_effect(url, method, params, token=None, req_id=1):
        if token is None:
            return {"status": 401, "body": {"error": {"code": 401}}}
        return {
            "status": 200,
            "body": {"result": {"tools": [{"name": "get_data"}]}},
        }

    mock_rpc.side_effect = side_effect
    state = make_state()
    from mcppt.checks import check_enum
    tools = check_enum(state)
    assert len(state.findings) == 0
    assert any("PASS" in line for line in state.log_lines)


# ── check_rate ────────────────────────────────────────────────────────────────

@patch("mcppt.checks.rpc")
def test_check_rate_no_limit(mock_rpc):
    mock_rpc.return_value = {"status": 200, "body": {}}
    state = make_state()
    from mcppt.checks import check_rate
    check_rate(state)
    assert any(f.severity == "LOW" for f in state.findings)


@patch("mcppt.checks.rpc")
def test_check_rate_limit_triggered(mock_rpc):
    calls = [0]

    def side_effect(*args, **kwargs):
        calls[0] += 1
        if calls[0] >= 5:
            return {"status": 429, "body": {}}
        return {"status": 200, "body": {}}

    mock_rpc.side_effect = side_effect
    state = make_state()
    from mcppt.checks import check_rate
    check_rate(state)
    assert len(state.findings) == 0
    assert any("PASS" in line for line in state.log_lines)


# ── check_idor (no token2) ────────────────────────────────────────────────────

def test_check_idor_skips_without_token2():
    state = make_state()
    from mcppt.checks import check_idor
    check_idor(state, [{"name": "get_item", "inputSchema": {"properties": {}, "required": []}}])
    assert len(state.findings) == 0
    assert any("Skipping" in line for line in state.log_lines)
