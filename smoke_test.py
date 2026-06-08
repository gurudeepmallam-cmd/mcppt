#!/usr/bin/env python3
"""
MCPTROTTER Smoke Test — v2.3
=============================
Starts the vuln_server, runs MCPTROTTER against it, asserts expected findings.

Usage:
    pip install flask
    python smoke_test.py

Exit codes:
    0 — all expected findings confirmed
    1 — one or more expected findings missing
"""

import sys
import socket
import time
import threading
from collections import Counter

# Force UTF-8 output on Windows to avoid cp1252 UnicodeEncodeError for → ×
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ── Colours ───────────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def _ok(msg):   print(f"  {GREEN}PASS{RESET}  {msg}")
def _fail(msg): print(f"  {RED}FAIL{RESET}  {msg}")
def _info(msg): print(f"  {CYAN}INFO{RESET}  {msg}")


# ── Dynamic free port — avoids conflicts from previous zombie Flask servers ───

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


_TEST_PORT = _free_port()


# ── Start vuln server in background ──────────────────────────────────────────

def _start_server():
    import vuln_server
    # Reset module-level state so every run starts clean
    vuln_server._notes.clear()
    vuln_server._session_counter = 100
    vuln_server._tools_call_count = 0

    t = threading.Thread(
        target=lambda: vuln_server.app.run(
            host="127.0.0.1", port=_TEST_PORT, debug=False, use_reloader=False
        ),
        daemon=True,
    )
    t.start()

    # Poll until the port is actually accepting connections (max 10 s)
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", _TEST_PORT), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)
    else:
        print(f"{RED}ERROR: vuln_server failed to start on port {_TEST_PORT}{RESET}")
        sys.exit(2)

    _info(f"Vulnerable demo server started on http://127.0.0.1:{_TEST_PORT}/mcp")


# ── Run MCPTROTTER programmatically ──────────────────────────────────────────

def _run_scan():
    from mcppt.core import configure
    from mcppt.checks import ScanState, run_scan

    configure(no_verify=False)
    state = ScanState(
        url=f"http://127.0.0.1:{_TEST_PORT}/mcp",
        token="valid-token-abc123",
        token2="other-token-xyz789",
        checks_total=28,
    )
    run_scan(state, ["all"])
    return state


# ── Expected findings ─────────────────────────────────────────────────────────

# Each tuple: (check_name, severity, keyword_in_title)
EXPECTED = [
    ("enum",             "MEDIUM",   "tools/list"),
    ("auth",             "CRITICAL", "bypass"),
    ("injection",        "HIGH",     "injection"),
    ("ssrf",             "CRITICAL", "SSRF"),
    ("publish",          "CRITICAL", "confirmation"),
    ("stored",           "CRITICAL", "injection"),
    ("session",          "HIGH",     "session"),
    ("rug_pull",         "CRITICAL", "description"),
    ("headers",          "HIGH",     "CORS"),
    ("error_disclosure", "MEDIUM",   "leak"),
    ("tool_poisoning",   "CRITICAL", "Unicode"),
    ("resources",        "HIGH",     "auth"),
    ("cmd_injection",    "CRITICAL", "injection"),
    ("path_traversal",   "CRITICAL", "traversal"),
    ("secret_scan",      "CRITICAL", "Secret"),
    ("tool_shadowing",   "CRITICAL", "Duplicate"),
    ("sampling",         "CRITICAL", "sampling"),
]


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print()
    print(f"{BOLD}{'=' * 58}{RESET}")
    print(f"{BOLD}  MCPTROTTER Smoke Test  v2.3{RESET}")
    print(f"{BOLD}{'=' * 58}{RESET}")
    print()

    _start_server()
    _info("Running MCPTROTTER scan (all 28 checks)...")
    print()

    state = _run_scan()

    findings = state.findings
    c = Counter(f.severity for f in findings)

    print()
    print(f"{BOLD}  Scan complete — {state.elapsed:.1f}s — {len(findings)} findings{RESET}")
    print(f"  {RED}CRITICAL:{c['CRITICAL']}{RESET}  {YELLOW}HIGH:{c['HIGH']}{RESET}  "
          f"MEDIUM:{c['MEDIUM']}  {CYAN}LOW:{c['LOW']}{RESET}")
    print()
    print(f"{BOLD}  All findings:{RESET}")
    for f in findings:
        sev_color = RED if f.severity == "CRITICAL" else YELLOW if f.severity == "HIGH" else ""
        print(f"    [{sev_color}{f.severity:<8}{RESET}] [{f.check:<20}] {f.title[:60]}")

    print()
    print(f"{BOLD}  Asserting expected findings:{RESET}")
    print()

    passed = 0
    failed = 0

    for check, severity, keyword in EXPECTED:
        matched = [
            f for f in findings
            if f.check == check
            and f.severity == severity
            and keyword.lower() in f.title.lower()
        ]
        if matched:
            _ok(f"[{check}] {severity} — '{keyword}' confirmed")
            passed += 1
        else:
            # Try partial match (check fires but keyword differs)
            partial = [f for f in findings if f.check == check]
            if partial:
                _fail(f"[{check}] Expected {severity}/'{keyword}' — got: {partial[0].severity}/{partial[0].title[:50]}")
            else:
                _fail(f"[{check}] No finding at all — check may not be firing")
            failed += 1

    print()
    print(f"{BOLD}  {'=' * 54}{RESET}")
    if failed == 0:
        print(f"  {GREEN}{BOLD}ALL {passed} EXPECTED FINDINGS CONFIRMED — PASS{RESET}")
    else:
        print(f"  {RED}{BOLD}{failed} MISSING / {passed} CONFIRMED — FAIL{RESET}")
    print(f"  {'=' * 54}")
    print()

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
