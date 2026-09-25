"""
MCPPT vs OWASP MCP Top 10 — Coverage Map
==========================================
Maps all 43 MCPPT checks against the OWASP MCP Top 10 (2025 beta)
and the MCP-38 threat taxonomy (arXiv:2603.18063).

Run standalone:
    python coverage_map.py

Also importable:
    from benchmark.coverage_map import COVERAGE_MAP, print_coverage, export_coverage_json
"""
from __future__ import annotations

import json
from pathlib import Path

# ── OWASP MCP Top 10 (2025 beta) ──────────────────────────────────────────────
# Source: https://owasp.org/www-project-mcp-top-10
OWASP_MCP_TOP10 = {
    "MCP1":  "Prompt Injection",
    "MCP2":  "Excessive Permissions and Broken Access Control",
    "MCP3":  "Data Exfiltration via Tool Output",
    "MCP4":  "Insecure Tool Design",
    "MCP5":  "Server-Side Request Forgery (SSRF) via Tool Calls",
    "MCP6":  "Insecure Authentication and Session Management",
    "MCP7":  "Sensitive Data Exposure",
    "MCP8":  "Tool Confusion and Shadowing",
    "MCP9":  "Insufficient Logging and Auditing",
    "MCP10": "Insecure Network Transport",
}

# ── MCP-38 Threat Taxonomy categories (arXiv:2603.18063) ─────────────────────
MCP38_CATEGORIES = {
    "T1":  "Prompt/Instruction Injection",
    "T2":  "Tool Poisoning (metadata manipulation)",
    "T3":  "Rug Pull (post-approval redefinition)",
    "T4":  "Authentication and Authorization bypass",
    "T5":  "Data Exfiltration",
    "T6":  "SSRF and Server-Side Network Attacks",
    "T7":  "Insecure Transport (TLS/plaintext)",
    "T8":  "Session Entropy and Fixation",
    "T9":  "Client-Side Context Injection",
    "T10": "Sandboxing and Isolation Escape",
    "T11": "Protocol Abuse (JSON-RPC level)",
    "T12": "Information Disclosure",
    "T13": "Cross-Tenant Data Exposure",
}

# ── Coverage mapping ───────────────────────────────────────────────────────────
# Each check maps to:
#   owasp     : list of OWASP MCP Top 10 IDs
#   mcp38     : list of MCP-38 taxonomy IDs
#   surface   : "server" | "tls" | "client" | "sandbox"
#   covered   : True (engine fires a check) | False (gap)
#   notes     : optional detail

COVERAGE_MAP: list[dict] = [
    # ── Authentication & Session ───────────────────────────────────────────────
    {"check": "enum",              "owasp": ["MCP6"],         "mcp38": ["T4"],      "surface": "server",  "covered": True,  "notes": "tools/list without auth"},
    {"check": "auth",              "owasp": ["MCP2", "MCP6"], "mcp38": ["T4"],      "surface": "server",  "covered": True,  "notes": "tool call with no/invalid token"},
    {"check": "scope",             "owasp": ["MCP2"],         "mcp38": ["T4"],      "surface": "server",  "covered": True,  "notes": "read-only token reaches write tools"},
    {"check": "session",           "owasp": ["MCP6"],         "mcp38": ["T8"],      "surface": "server",  "covered": True,  "notes": "weak/sequential session IDs"},
    {"check": "replay",            "owasp": ["MCP6"],         "mcp38": ["T4"],      "surface": "server",  "covered": True,  "notes": "no nonce/timestamp protection"},
    {"check": "rate",              "owasp": ["MCP4"],         "mcp38": ["T11"],     "surface": "server",  "covered": True,  "notes": "no rate limiting"},
    {"check": "jwt_audit",         "owasp": ["MCP6"],         "mcp38": ["T4"],      "surface": "server",  "covered": True,  "notes": "alg:none, HS256, no exp"},
    {"check": "oauth_discovery",   "owasp": ["MCP6"],         "mcp38": ["T12"],     "surface": "server",  "covered": True,  "notes": "OAuth metadata exposure"},
    # ── Injection ──────────────────────────────────────────────────────────────
    {"check": "injection",         "owasp": ["MCP1"],         "mcp38": ["T1"],      "surface": "server",  "covered": True,  "notes": "prompt injection via string params"},
    {"check": "stored",            "owasp": ["MCP1"],         "mcp38": ["T1"],      "surface": "server",  "covered": True,  "notes": "stored prompt injection write→read"},
    {"check": "context_overflow",  "owasp": ["MCP1"],         "mcp38": ["T1"],      "surface": "server",  "covered": True,  "notes": "100K-char context truncation"},
    {"check": "poison_all",        "owasp": ["MCP1"],         "mcp38": ["T1"],      "surface": "server",  "covered": True,  "notes": "injection in all response fields"},
    {"check": "cmd_injection",     "owasp": ["MCP4"],         "mcp38": ["T1"],      "surface": "server",  "covered": True,  "notes": "OS command injection"},
    {"check": "path_traversal",    "owasp": ["MCP4"],         "mcp38": ["T1", "T5"],"surface": "server",  "covered": True,  "notes": "path traversal to filesystem"},
    # ── Tool Poisoning & Rug Pull ──────────────────────────────────────────────
    {"check": "tool_poisoning",    "owasp": ["MCP8"],         "mcp38": ["T2"],      "surface": "server",  "covered": True,  "notes": "Unicode steganography + injection in desc"},
    {"check": "tool_shadowing",    "owasp": ["MCP8"],         "mcp38": ["T2"],      "surface": "server",  "covered": True,  "notes": "duplicate names + homoglyphs"},
    {"check": "rug_pull",          "owasp": ["MCP8"],         "mcp38": ["T3"],      "surface": "server",  "covered": True,  "notes": "tool desc change mid-session"},
    {"check": "publish",           "owasp": ["MCP4"],         "mcp38": ["T2"],      "surface": "server",  "covered": True,  "notes": "destructive tool without confirmation gate"},
    {"check": "sampling",          "owasp": ["MCP4"],         "mcp38": ["T5"],      "surface": "server",  "covered": True,  "notes": "sampling/createMessage without auth"},
    {"check": "resources",         "owasp": ["MCP7"],         "mcp38": ["T5"],      "surface": "server",  "covered": True,  "notes": "resources/list without auth"},
    {"check": "secret_scan",       "owasp": ["MCP7"],         "mcp38": ["T5"],      "surface": "server",  "covered": True,  "notes": "credentials in tool responses"},
    # ── Access Control ─────────────────────────────────────────────────────────
    {"check": "idor",              "owasp": ["MCP2"],         "mcp38": ["T4"],      "surface": "server",  "covered": True,  "notes": "cross-user resource access"},
    {"check": "tenant",            "owasp": ["MCP2"],         "mcp38": ["T13"],     "surface": "server",  "covered": True,  "notes": "cross-tenant data isolation failure"},
    # ── SSRF ───────────────────────────────────────────────────────────────────
    {"check": "ssrf",              "owasp": ["MCP5"],         "mcp38": ["T6"],      "surface": "server",  "covered": True,  "notes": "cloud metadata URL fetch"},
    # ── Protocol / Headers ─────────────────────────────────────────────────────
    {"check": "schema",            "owasp": ["MCP4"],         "mcp38": ["T11"],     "surface": "server",  "covered": True,  "notes": "schema type bypass"},
    {"check": "headers",           "owasp": ["MCP10"],        "mcp38": ["T7"],      "surface": "server",  "covered": True,  "notes": "CORS wildcard + missing security headers"},
    {"check": "error_disclosure",  "owasp": ["MCP7"],         "mcp38": ["T12"],     "surface": "server",  "covered": True,  "notes": "stack trace / path in error"},
    {"check": "schema_leak",       "owasp": ["MCP7"],         "mcp38": ["T12"],     "surface": "server",  "covered": True,  "notes": "sensitive field names in schema"},
    {"check": "http_method_confusion", "owasp": ["MCP4"],     "mcp38": ["T11"],     "surface": "server",  "covered": True,  "notes": "non-POST methods accepted"},
    {"check": "protocol_downgrade","owasp": ["MCP4", "MCP10"],"mcp38": ["T11"],     "surface": "server",  "covered": True,  "notes": "old protocol version + capability disclosure"},
    {"check": "batch_injection",   "owasp": ["MCP4"],         "mcp38": ["T11"],     "surface": "server",  "covered": True,  "notes": "JSON-RPC batch + method injection"},
    # ── TLS / Transport (new surface) ─────────────────────────────────────────
    {"check": "tls_cert",          "owasp": ["MCP10"],        "mcp38": ["T7"],      "surface": "tls",     "covered": True,  "notes": "expired/self-signed/mismatched cert"},
    {"check": "tls_version",       "owasp": ["MCP10"],        "mcp38": ["T7"],      "surface": "tls",     "covered": True,  "notes": "TLS 1.0/1.1 acceptance + weak ciphers"},
    {"check": "transport_plaintext","owasp": ["MCP10"],       "mcp38": ["T7"],      "surface": "tls",     "covered": True,  "notes": "HTTP plaintext endpoint"},
    {"check": "tls_cipher",        "owasp": ["MCP10"],        "mcp38": ["T7"],      "surface": "tls",     "covered": True,  "notes": "EXPORT/RC4/NULL cipher suites"},
    # ── Client-Side (new surface) ─────────────────────────────────────────────
    {"check": "client_annotations",       "owasp": ["MCP4"],  "mcp38": ["T9"],      "surface": "client",  "covered": True,  "notes": "missing destructiveHint / readOnlyHint"},
    {"check": "client_context_injection", "owasp": ["MCP1"],  "mcp38": ["T9"],      "surface": "client",  "covered": True,  "notes": "injection in tool results targeting client LLM"},
    {"check": "client_init_injection",    "owasp": ["MCP1"],  "mcp38": ["T9"],      "surface": "client",  "covered": True,  "notes": "initialize instructions field injection (SPEC-1)"},
    {"check": "client_credential_exposure","owasp": ["MCP7"], "mcp38": ["T5", "T9"],"surface": "client",  "covered": True,  "notes": "credentials in initialize / tool responses"},
    # ── Sandboxing (new surface) ──────────────────────────────────────────────
    {"check": "sandbox_env_leak",         "owasp": ["MCP7"],  "mcp38": ["T10"],     "surface": "sandbox", "covered": True,  "notes": "process environment variables exposed"},
    {"check": "sandbox_process_info",     "owasp": ["MCP7"],  "mcp38": ["T10"],     "surface": "sandbox", "covered": True,  "notes": "/proc/self data accessible"},
    {"check": "sandbox_network_scope",    "owasp": ["MCP5"],  "mcp38": ["T10", "T6"],"surface": "sandbox","covered": True,  "notes": "Docker bridge / K8s internal SSRF"},
    {"check": "sandbox_filesystem_scope", "owasp": ["MCP4"],  "mcp38": ["T10"],     "surface": "sandbox", "covered": True,  "notes": "chroot/jail escape via file read"},
    # ── Known gaps (not yet in engine) ────────────────────────────────────────
    {"check": "mcp_logging_audit",  "owasp": ["MCP9"], "mcp38": [],          "surface": "server",  "covered": False, "notes": "No server-side audit log check — gap"},
    {"check": "supply_chain",       "owasp": ["MCP8"], "mcp38": ["T2"],      "surface": "server",  "covered": False, "notes": "Malicious package in MCP server dependencies — gap"},
    {"check": "mutual_tls",         "owasp": ["MCP10"],"mcp38": ["T7"],      "surface": "tls",     "covered": False, "notes": "mTLS client certificate enforcement — gap"},
]


def owasp_coverage_summary() -> dict[str, dict]:
    """Return per-OWASP-category: covered + gap check counts."""
    summary: dict[str, dict] = {cat: {"covered": [], "gaps": []} for cat in OWASP_MCP_TOP10}
    for row in COVERAGE_MAP:
        for cat in row["owasp"]:
            if cat in summary:
                key = "covered" if row["covered"] else "gaps"
                summary[cat][key].append(row["check"])
    return summary


def mcp38_coverage_summary() -> dict[str, dict]:
    summary: dict[str, dict] = {cat: {"covered": [], "gaps": []} for cat in MCP38_CATEGORIES}
    for row in COVERAGE_MAP:
        for cat in row["mcp38"]:
            if cat in summary:
                key = "covered" if row["covered"] else "gaps"
                summary[cat][key].append(row["check"])
    return summary


def print_coverage():
    print("\n" + "=" * 72)
    print("  MCPPT Coverage vs OWASP MCP Top 10")
    print("=" * 72)
    owasp = owasp_coverage_summary()
    for cat_id, label in OWASP_MCP_TOP10.items():
        info = owasp[cat_id]
        n_covered = len(info["covered"])
        n_gaps    = len(info["gaps"])
        pct = 100 * n_covered // (n_covered + n_gaps) if (n_covered + n_gaps) > 0 else 0
        status = "FULL" if n_gaps == 0 else f"PARTIAL ({pct}%)"
        print(f"\n  {cat_id}: {label}")
        print(f"    Status  : {status}")
        if info["covered"]:
            print(f"    Covered : {', '.join(info['covered'])}")
        if info["gaps"]:
            print(f"    Gaps    : {', '.join(info['gaps'])}")

    print("\n" + "=" * 72)
    print("  MCPPT Coverage vs MCP-38 Threat Taxonomy")
    print("=" * 72)
    mcp38 = mcp38_coverage_summary()
    for cat_id, label in MCP38_CATEGORIES.items():
        info = mcp38[cat_id]
        n_covered = len(info["covered"])
        n_gaps    = len(info["gaps"])
        pct = 100 * n_covered // (n_covered + n_gaps) if (n_covered + n_gaps) > 0 else 0
        status = "FULL" if n_gaps == 0 else ("PARTIAL" if n_covered > 0 else "GAP")
        print(f"\n  {cat_id}: {label}")
        print(f"    Status  : {status} ({n_covered} checks cover this)")
        if info["gaps"]:
            print(f"    Gaps    : {', '.join(info['gaps'])}")

    total_covered = sum(1 for r in COVERAGE_MAP if r["covered"])
    total_gaps    = sum(1 for r in COVERAGE_MAP if not r["covered"])
    print(f"\n  Total checks: {total_covered} covered + {total_gaps} gap(s) = {len(COVERAGE_MAP)}\n")


def export_coverage_json(out_path: str | None = None) -> str:
    data = {
        "owasp_mcp_top10": OWASP_MCP_TOP10,
        "mcp38_categories": MCP38_CATEGORIES,
        "coverage_map": COVERAGE_MAP,
        "owasp_summary": {
            k: {"title": v, **owasp_coverage_summary()[k]}
            for k, v in OWASP_MCP_TOP10.items()
        },
        "mcp38_summary": {
            k: {"title": v, **mcp38_coverage_summary()[k]}
            for k, v in MCP38_CATEGORIES.items()
        },
    }
    js = json.dumps(data, indent=2)
    if out_path:
        Path(out_path).write_text(js, encoding="utf-8")
    return js


if __name__ == "__main__":
    print_coverage()
    out = Path(__file__).parent / "coverage_map.json"
    export_coverage_json(str(out))
    print(f"[coverage_map] JSON written to {out}")
