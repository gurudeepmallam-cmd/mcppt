#!/usr/bin/env python3
"""
MCPPT Benchmark Runner — Precision / Recall / FPR Evaluator
=============================================================
Runs the mcppt detection engine against each server in the labeled corpus,
then computes per-check and per-surface statistics.

Usage
-----
    # Run against seeded server S1 only (start seeded_server.py first)
    python benchmark_runner.py --server S1 --url http://127.0.0.1:8899/mcp \\
        --token valid-token-abc123 --token2 other-token-xyz789

    # Run against all servers defined in corpus_labels.json
    python benchmark_runner.py --all

    # Just show coverage map vs OWASP MCP Top 10
    python benchmark_runner.py --coverage-only

Output
------
  benchmark_results/
    results_<server_id>.json   — raw detection results
    stats_<server_id>.json     — per-check P/R/FPR for one server
    aggregate_stats.json       — aggregate across all evaluated servers
    report_<timestamp>.md      — human-readable dissertation report
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

# Ensure mcppt package is importable when running from benchmark/
_pkg_root = Path(__file__).resolve().parent.parent
if str(_pkg_root) not in sys.path:
    sys.path.insert(0, str(_pkg_root))

from mcppt.checks import ScanState, run_scan, ALL_CHECKS
from mcppt.core import configure

LABELS_FILE = Path(__file__).parent / "corpus_labels.json"
OUT_DIR     = Path(__file__).parent.parent / "benchmark_results"

# ── Surface groupings (matches dissertation scope) ─────────────────────────────
SURFACES = {
    "auth_session":   ["enum", "auth", "idor", "scope", "replay", "session", "tenant", "rate"],
    "injection":      ["injection", "schema", "stored", "context_overflow", "poison_all",
                       "cmd_injection", "path_traversal", "ssrf"],
    "tool_poisoning": ["publish", "rug_pull", "tool_poisoning", "tool_shadowing",
                       "sampling", "resources", "secret_scan"],
    "protocol":       ["headers", "error_disclosure", "schema_leak", "jwt_audit",
                       "oauth_discovery", "http_method_confusion", "protocol_downgrade",
                       "batch_injection", "client_context_injection"],
    "tls_transport":  ["tls_cert", "tls_version", "transport_plaintext", "tls_cipher"],
    "client_side":    ["client_annotations", "client_context_injection",
                       "client_init_injection", "client_credential_exposure"],
    "sandboxing":     ["sandbox_env_leak", "sandbox_process_info",
                       "sandbox_network_scope", "sandbox_filesystem_scope"],
}


# ── Run scan against a single server ──────────────────────────────────────────

def run_against_server(url: str, token: str | None, token2: str | None,
                       proxy: str | None = None, no_verify: bool = False) -> list[dict]:
    configure(no_verify=no_verify, proxy=proxy)
    state = ScanState(url=url, token=token, token2=token2)
    run_scan(state, ["all"])
    return [
        {"check": f.check, "severity": f.severity, "title": f.title, "detail": f.detail}
        for f in state.findings
    ]


# ── Compute P / R / FPR for one server ────────────────────────────────────────

def compute_stats(server_id: str, detected: list[dict], labels: dict[str, dict]) -> dict:
    """
    For each check with a ground-truth label, classify as:
      TP — check flagged AND vulnerability present
      FP — check flagged BUT vulnerability absent
      FN — check NOT flagged AND vulnerability present
      TN — check NOT flagged AND vulnerability absent

    Returns per-check and per-surface precision/recall/FPR.
    """
    detected_checks = {d["check"] for d in detected}

    per_check: dict[str, dict] = {}
    for check_name, label in labels.items():
        if label.get("severity") == "N/A":
            per_check[check_name] = {"result": "N/A", "reason": "not applicable to this server type"}
            continue

        present   = label.get("present", False)
        detected_flag = check_name in detected_checks

        if present and detected_flag:
            result = "TP"
        elif not present and detected_flag:
            result = "FP"
        elif present and not detected_flag:
            result = "FN"
        else:
            result = "TN"

        per_check[check_name] = {
            "result":   result,
            "present":  present,
            "detected": detected_flag,
            "severity": label.get("severity", "?"),
            "notes":    label.get("notes", ""),
        }

    # Aggregate surface-level metrics
    surface_stats: dict[str, dict] = {}
    for surface, checks in SURFACES.items():
        tp = fp = fn = tn = 0
        for c in checks:
            r = per_check.get(c, {}).get("result", "N/A")
            if r == "TP": tp += 1
            elif r == "FP": fp += 1
            elif r == "FN": fn += 1
            elif r == "TN": tn += 1
        precision = tp / (tp + fp) if (tp + fp) > 0 else None
        recall    = tp / (tp + fn) if (tp + fn) > 0 else None
        fpr       = fp / (fp + tn) if (fp + tn) > 0 else None
        f1        = (2 * precision * recall / (precision + recall)
                     if precision is not None and recall is not None
                     and (precision + recall) > 0 else None)
        surface_stats[surface] = {
            "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "precision": round(precision, 4) if precision is not None else None,
            "recall":    round(recall, 4)    if recall    is not None else None,
            "fpr":       round(fpr, 4)       if fpr       is not None else None,
            "f1":        round(f1, 4)        if f1        is not None else None,
        }

    # Overall
    all_results = [v["result"] for v in per_check.values() if v.get("result") not in ("N/A", None)]
    tp_all = all_results.count("TP")
    fp_all = all_results.count("FP")
    fn_all = all_results.count("FN")
    tn_all = all_results.count("TN")
    overall_precision = tp_all / (tp_all + fp_all) if (tp_all + fp_all) > 0 else None
    overall_recall    = tp_all / (tp_all + fn_all) if (tp_all + fn_all) > 0 else None
    overall_fpr       = fp_all / (fp_all + tn_all) if (fp_all + tn_all) > 0 else None

    return {
        "server_id":    server_id,
        "overall": {
            "TP": tp_all, "FP": fp_all, "FN": fn_all, "TN": tn_all,
            "precision": round(overall_precision, 4) if overall_precision is not None else None,
            "recall":    round(overall_recall, 4)    if overall_recall    is not None else None,
            "fpr":       round(overall_fpr, 4)       if overall_fpr       is not None else None,
        },
        "per_surface": surface_stats,
        "per_check":   per_check,
    }


# ── Aggregate across multiple servers ─────────────────────────────────────────

def aggregate_stats(all_stats: list[dict]) -> dict:
    surfaces = list(SURFACES.keys())
    agg: dict[str, dict] = {}
    for surface in surfaces:
        tp = fp = fn = tn = 0
        for s in all_stats:
            ss = s.get("per_surface", {}).get(surface, {})
            tp += ss.get("TP", 0)
            fp += ss.get("FP", 0)
            fn += ss.get("FN", 0)
            tn += ss.get("TN", 0)
        precision = tp / (tp + fp) if (tp + fp) > 0 else None
        recall    = tp / (tp + fn) if (tp + fn) > 0 else None
        fpr       = fp / (fp + tn) if (fp + tn) > 0 else None
        f1        = (2 * precision * recall / (precision + recall)
                     if precision and recall and (precision + recall) > 0 else None)
        agg[surface] = {
            "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "precision": round(precision, 4) if precision is not None else None,
            "recall":    round(recall, 4)    if recall    is not None else None,
            "fpr":       round(fpr, 4)       if fpr       is not None else None,
            "f1":        round(f1, 4)        if f1        is not None else None,
        }

    # Overall
    tp = sum(s["overall"]["TP"] for s in all_stats)
    fp = sum(s["overall"]["FP"] for s in all_stats)
    fn = sum(s["overall"]["FN"] for s in all_stats)
    tn = sum(s["overall"]["TN"] for s in all_stats)
    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    recall    = tp / (tp + fn) if (tp + fn) > 0 else None
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else None
    f1        = (2 * precision * recall / (precision + recall)
                 if precision and recall and (precision + recall) > 0 else None)
    return {
        "servers_evaluated": [s["server_id"] for s in all_stats],
        "overall": {
            "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "precision": round(precision, 4) if precision is not None else None,
            "recall":    round(recall, 4)    if recall    is not None else None,
            "fpr":       round(fpr, 4)       if fpr       is not None else None,
            "f1":        round(f1, 4)        if f1        is not None else None,
        },
        "per_surface": agg,
    }


# ── Markdown report generator ──────────────────────────────────────────────────

def make_report(agg: dict, all_stats: list[dict]) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# MCPPT Benchmark Report",
        f"**Generated:** {ts}  ",
        f"**Servers evaluated:** {', '.join(agg['servers_evaluated'])}  ",
        f"**Total checks:** {len(ALL_CHECKS)} (31 original + 12 new-surface)  ",
        "",
        "---",
        "",
        "## Overall Results",
        "",
        "| Metric | Value |",
        "|--------|-------|",
    ]
    ov = agg["overall"]
    lines += [
        f"| True Positives (TP)  | {ov['TP']}  |",
        f"| False Positives (FP) | {ov['FP']}  |",
        f"| False Negatives (FN) | {ov['FN']}  |",
        f"| True Negatives (TN)  | {ov['TN']}  |",
        f"| **Precision**        | **{ov['precision']}** |",
        f"| **Recall**           | **{ov['recall']}** |",
        f"| **FPR**              | **{ov['fpr']}** |",
        f"| **F1**               | **{ov.get('f1', '—')}** |",
        "",
        "---",
        "",
        "## Per-Surface Results",
        "",
        "| Surface | TP | FP | FN | TN | Precision | Recall | FPR | F1 |",
        "|---------|----|----|----|----|-----------|--------|-----|----|",
    ]
    for surf, m in agg["per_surface"].items():
        lines.append(
            f"| {surf} | {m['TP']} | {m['FP']} | {m['FN']} | {m['TN']} "
            f"| {m['precision']} | {m['recall']} | {m['fpr']} | {m.get('f1','—')} |"
        )

    lines += ["", "---", "", "## Per-Server Details", ""]
    for s in all_stats:
        lines += [
            f"### Server {s['server_id']}",
            "",
            "| Check | Present | Detected | Result |",
            "|-------|---------|----------|--------|",
        ]
        for check, info in s["per_check"].items():
            if info.get("result") == "N/A":
                continue
            lines.append(
                f"| {check} | {'✓' if info.get('present') else '✗'} "
                f"| {'✓' if info.get('detected') else '✗'} "
                f"| **{info.get('result','?')}** |"
            )
        lines.append("")

    return "\n".join(lines)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="MCPPT Benchmark Runner")
    parser.add_argument("--server",  help="Server ID from corpus_labels.json (e.g. S1)")
    parser.add_argument("--url",     help="Override URL for the target server")
    parser.add_argument("--token",   help="Auth token for the target server")
    parser.add_argument("--token2",  help="Second token for IDOR/tenant tests")
    parser.add_argument("--proxy",   help="Burp proxy URL")
    parser.add_argument("--no-verify", action="store_true", help="Skip SSL verification")
    parser.add_argument("--all",     action="store_true", help="Run all corpus servers with known URLs")
    parser.add_argument("--coverage-only", action="store_true",
                        help="Print OWASP MCP Top 10 coverage map only")
    parser.add_argument("--output-dir", default=str(OUT_DIR))
    args = parser.parse_args()

    if args.coverage_only:
        from benchmark.coverage_map import print_coverage
        print_coverage()
        return

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    labels_data = json.loads(LABELS_FILE.read_text(encoding="utf-8"))

    all_stats: list[dict] = []

    # Determine which servers to run
    if args.all:
        servers_to_run = [
            sid for sid in labels_data
            if not sid.startswith("_") and labels_data[sid].get("port")
        ]
    elif args.server:
        servers_to_run = [args.server]
    else:
        parser.print_help()
        return

    for server_id in servers_to_run:
        meta = labels_data.get(server_id)
        if not meta:
            print(f"[WARN] Server {server_id} not in corpus_labels.json — skipping")
            continue

        # URL override takes precedence; fall back to localhost + port
        url   = args.url   or (f"http://127.0.0.1:{meta.get('port')}/mcp" if meta.get("port") else None)
        token = args.token or meta.get("token")
        token2= args.token2 or meta.get("token2")

        if not url:
            print(f"[SKIP] {server_id}: no URL defined — use --url to override")
            continue

        print(f"\n[BENCH] Running {server_id} ({meta['name']}) → {url}")
        t0 = time.time()

        try:
            detected = run_against_server(
                url=url, token=token, token2=token2,
                proxy=args.proxy, no_verify=args.no_verify,
            )
        except Exception as e:
            print(f"[ERROR] {server_id}: {e}")
            continue

        elapsed = time.time() - t0
        print(f"[BENCH] {server_id}: {len(detected)} findings in {elapsed:.1f}s")

        # Save raw detections
        raw_path = out_dir / f"results_{server_id}.json"
        raw_path.write_text(json.dumps(detected, indent=2), encoding="utf-8")

        # Compute stats
        stats = compute_stats(server_id, detected, meta.get("ground_truth", {}))
        stats_path = out_dir / f"stats_{server_id}.json"
        stats_path.write_text(json.dumps(stats, indent=2), encoding="utf-8")

        ov = stats["overall"]
        print(f"[STATS] P={ov['precision']}  R={ov['recall']}  FPR={ov['fpr']}  "
              f"(TP={ov['TP']} FP={ov['FP']} FN={ov['FN']} TN={ov['TN']})")
        all_stats.append(stats)

    if all_stats:
        agg = aggregate_stats(all_stats)
        agg_path = out_dir / "aggregate_stats.json"
        agg_path.write_text(json.dumps(agg, indent=2), encoding="utf-8")
        print(f"\n[AGGREGATE] P={agg['overall']['precision']}  R={agg['overall']['recall']}  "
              f"FPR={agg['overall']['fpr']}")

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_md = make_report(agg, all_stats)
        rpt_path = out_dir / f"report_{ts}.md"
        rpt_path.write_text(report_md, encoding="utf-8")
        print(f"[REPORT] Written to {rpt_path}")
    else:
        print("[BENCH] No servers evaluated.")


if __name__ == "__main__":
    main()
