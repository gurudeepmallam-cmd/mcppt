"""MCPTROTTER — Streamlit Web UI"""
import io
import json
import tempfile
import threading
import time
from collections import Counter
from typing import Optional

import streamlit as st

# ── page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="MCPTROTTER",
    page_icon="🔴",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── theme ─────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
/* dark background */
.stApp { background-color: #0d1117; color: #e6edf3; }
section[data-testid="stSidebar"] { background-color: #161b22; }

/* metric cards */
div[data-testid="metric-container"] {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 12px 16px;
}

/* severity badges */
.badge-critical { background:#da3633; color:#fff; padding:2px 8px; border-radius:4px; font-size:0.8rem; font-weight:700; }
.badge-high     { background:#d29922; color:#fff; padding:2px 8px; border-radius:4px; font-size:0.8rem; font-weight:700; }
.badge-medium   { background:#9e6a03; color:#fff; padding:2px 8px; border-radius:4px; font-size:0.8rem; font-weight:700; }
.badge-low      { background:#1f6feb; color:#fff; padding:2px 8px; border-radius:4px; font-size:0.8rem; font-weight:700; }

/* finding card */
.finding-card {
    background: #161b22;
    border-left: 4px solid #da3633;
    border-radius: 4px;
    padding: 10px 14px;
    margin-bottom: 8px;
}
.finding-card.high   { border-left-color: #d29922; }
.finding-card.medium { border-left-color: #9e6a03; }
.finding-card.low    { border-left-color: #1f6feb; }

/* log box */
.log-box {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 10px;
    font-family: monospace;
    font-size: 0.78rem;
    max-height: 300px;
    overflow-y: auto;
    color: #8b949e;
}

/* buttons */
.stButton > button {
    background: #da3633 !important;
    color: white !important;
    border: none !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
}
.stButton > button:hover { background: #b91c1c !important; }

/* tab labels */
button[data-baseweb="tab"] { color: #8b949e !important; }
button[data-baseweb="tab"][aria-selected="true"] { color: #e6edf3 !important; border-bottom-color: #da3633 !important; }

/* progress bar */
.stProgress > div > div > div { background-color: #da3633; }
</style>
""", unsafe_allow_html=True)

# ── helpers ───────────────────────────────────────────────────────────────────

SEV_ORDER   = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_COLORS  = {"CRITICAL": "#da3633", "HIGH": "#d29922", "MEDIUM": "#9e6a03", "LOW": "#1f6feb"}
SEV_CLASS   = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

ALL_CHECKS = [
    "enum", "auth", "idor", "injection", "schema", "ssrf", "publish",
    "rate", "stored", "scope", "replay", "context_overflow",
    "poison_all", "tenant", "session", "rug_pull",
]

CHECK_DESC = {
    "enum":             "tools/list accessible without auth",
    "auth":             "Tool calls succeed with no/invalid token",
    "idor":             "Cross-user resource access (needs token2)",
    "injection":        "Prompt injection payloads reflected",
    "schema":           "Type confusion / null bypass",
    "ssrf":             "Cloud metadata URLs fetched via tool params",
    "publish":          "Destructive tool without confirmation gate",
    "rate":             "No rate limiting on tool calls",
    "stored":           "Stored prompt injection: write→read unescaped",
    "scope":            "Read-only token reaches write tools",
    "replay":           "Same request accepted twice (no nonce)",
    "context_overflow": "100K-char payload → LLM context truncation",
    "poison_all":       "Injection in any response field (CyberArk)",
    "tenant":           "Token2 reads token1 data (isolation broken)",
    "session":          "Weak/sequential session IDs (CVE-2025-6515)",
    "rug_pull":         "Tool descriptions change mid-session",
}


def _badge(sev: str) -> str:
    cls = SEV_CLASS.get(sev, "low")
    return f'<span class="badge-{cls}">{sev}</span>'


def _finding_card(f) -> str:
    cls = SEV_CLASS.get(f.severity, "low")
    return (
        f'<div class="finding-card {cls}">'
        f'  {_badge(f.severity)} &nbsp; <strong>{f.title}</strong>'
        f'  <br><small style="color:#8b949e">[{f.check}] &nbsp; {f.detail}</small>'
        f'</div>'
    )


def _init_state():
    defaults = {
        "scan_state":  None,
        "scanning":    False,
        "scan_thread": None,
        "tools_cache": [],
        "call_result": None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


# ── sidebar ───────────────────────────────────────────────────────────────────

def _sidebar() -> dict:
    with st.sidebar:
        st.markdown("## MCPTROTTER")
        st.markdown("<small style='color:#8b949e'>MCP Pentest Tool v2.1</small>", unsafe_allow_html=True)
        st.markdown("---")

        url = st.text_input(
            "Target URL",
            placeholder="https://target.com/mcp",
            help="MCP server endpoint",
        )
        token = st.text_input(
            "Bearer Token",
            type="password",
            placeholder="eyJ... (optional)",
        )
        token2 = st.text_input(
            "Token 2  (IDOR/scope/tenant)",
            type="password",
            placeholder="second user token (optional)",
        )
        proxy = st.text_input(
            "Burp Proxy",
            placeholder="http://127.0.0.1:8080 (optional)",
        )
        no_verify = st.toggle("Skip SSL verification", value=False)

        st.markdown("---")
        st.markdown("**Checks**")
        select_all = st.checkbox("All checks", value=True)
        if select_all:
            selected = ALL_CHECKS
        else:
            selected = st.multiselect(
                "Select checks",
                options=ALL_CHECKS,
                format_func=lambda c: f"{c} — {CHECK_DESC[c]}",
                default=ALL_CHECKS,
            )

        st.markdown("---")
        st.markdown(
            "<small style='color:#8b949e'>"
            "by <b>Gurudeep Mallam</b><br>"
            "<a href='https://github.com/gurudeepmallam-cmd' style='color:#58a6ff'>GitHub</a>"
            " &nbsp;|&nbsp; "
            "<a href='https://in.linkedin.com/in/mallam-gurudeep-7734941aa' style='color:#58a6ff'>LinkedIn</a>"
            "</small>",
            unsafe_allow_html=True,
        )

    return {
        "url":       url.strip(),
        "token":     token.strip() or None,
        "token2":    token2.strip() or None,
        "proxy":     proxy.strip() or None,
        "no_verify": no_verify,
        "checks":    selected,
    }


# ── scan tab ──────────────────────────────────────────────────────────────────

def _tab_scan(cfg: dict):
    st.markdown("### Security Scan")

    if not cfg["url"]:
        st.info("Enter the target MCP server URL in the sidebar to begin.")
        return

    st.markdown(f"**Target:** `{cfg['url']}`")

    col_btn, col_stop = st.columns([1, 5])
    with col_btn:
        start = st.button("SCAN", use_container_width=True,
                          disabled=st.session_state.scanning)

    if start and not st.session_state.scanning:
        _start_scan(cfg)

    # ── live progress ─────────────────────────────────────────────────────────

    state = st.session_state.scan_state

    if st.session_state.scanning and state is not None:
        done  = state.checks_done
        total = max(state.checks_total, 1)
        pct   = done / total

        st.progress(pct, text=f"Running `{state.current_check}` ...  {done}/{total} checks")

        log_placeholder = st.empty()
        log_html = "<div class='log-box'>" + "<br>".join(
            _colorise_log(l) for l in state.log_lines[-30:]
        ) + "</div>"
        log_placeholder.markdown(log_html, unsafe_allow_html=True)

        if not state.done:
            time.sleep(0.4)
            st.rerun()
        else:
            st.session_state.scanning = False
            st.rerun()

    # ── results ───────────────────────────────────────────────────────────────

    if state is not None and state.done:
        counts = Counter(f.severity for f in state.findings)

        st.success(f"Scan complete — {len(state.findings)} findings in {state.elapsed:.1f}s")
        st.markdown("---")

        # summary metrics
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("CRITICAL", counts.get("CRITICAL", 0), delta=None)
        c2.metric("HIGH",     counts.get("HIGH",     0), delta=None)
        c3.metric("MEDIUM",   counts.get("MEDIUM",   0), delta=None)
        c4.metric("LOW",      counts.get("LOW",      0), delta=None)

        st.markdown("---")

        if state.findings:
            st.markdown("#### Findings")
            for sev in SEV_ORDER:
                group = [f for f in state.findings if f.severity == sev]
                if group:
                    with st.expander(f"{sev}  ({len(group)})", expanded=(sev in ("CRITICAL", "HIGH"))):
                        for f in group:
                            st.markdown(_finding_card(f), unsafe_allow_html=True)

            st.markdown("---")
            st.markdown("#### Export Report")
            r1, r2 = st.columns(2)

            md_content = _build_markdown(state)
            r1.download_button(
                "Download Markdown",
                data=md_content,
                file_name="mcptrotter_report.md",
                mime="text/markdown",
            )

            json_content = _build_json(state)
            r2.download_button(
                "Download JSON",
                data=json_content,
                file_name="mcptrotter_report.json",
                mime="application/json",
            )
        else:
            st.success("No findings detected. Target looks clean.")


def _start_scan(cfg: dict):
    from mcppt.checks import ScanState, run_scan
    from mcppt.core import configure

    configure(no_verify=cfg["no_verify"], proxy=cfg["proxy"])

    checks = cfg["checks"] or ALL_CHECKS
    total  = len(checks)

    state = ScanState(
        url=cfg["url"],
        token=cfg["token"],
        token2=cfg["token2"],
        checks_total=total,
    )
    st.session_state.scan_state = state
    st.session_state.scanning   = True

    t = threading.Thread(target=run_scan, args=(state, checks), daemon=True)
    t.start()
    st.session_state.scan_thread = t


def _colorise_log(line: str) -> str:
    line = line.replace("<", "&lt;").replace(">", "&gt;")
    if "CRIT" in line:
        return f'<span style="color:#da3633">{line}</span>'
    if "HIGH" in line:
        return f'<span style="color:#d29922">{line}</span>'
    if "MED"  in line:
        return f'<span style="color:#9e6a03">{line}</span>'
    if "LOW"  in line:
        return f'<span style="color:#1f6feb">{line}</span>'
    if "PASS" in line:
        return f'<span style="color:#3fb950">{line}</span>'
    if "CHECK" in line:
        return f'<span style="color:#e6edf3">{line}</span>'
    return line


# ── explore tab ───────────────────────────────────────────────────────────────

def _tab_explore(cfg: dict):
    st.markdown("### Explore MCP Server")

    if not cfg["url"]:
        st.info("Enter the target URL in the sidebar.")
        return

    st.markdown(f"**Target:** `{cfg['url']}`")

    if st.button("List Tools"):
        _do_list_tools(cfg)

    tools = st.session_state.tools_cache
    if tools:
        st.markdown(f"**{len(tools)} tools found:**")
        for t in tools:
            name  = t.get("name", "?")
            desc  = t.get("description", "").split("\n")[0][:100]
            props = t.get("inputSchema", {}).get("properties", {})
            req   = t.get("inputSchema", {}).get("required", [])

            with st.expander(f"`{name}` — {desc}"):
                if props:
                    rows = [
                        {"Field": f, "Type": m.get("type", "any"),
                         "Required": "yes" if f in req else "",
                         "Description": m.get("description", "")[:80]}
                        for f, m in props.items()
                    ]
                    st.table(rows)
                else:
                    st.caption("No parameters.")

        st.markdown("---")
        st.markdown("#### Call a Tool")
        tool_names = [t.get("name", "?") for t in tools]
        chosen = st.selectbox("Tool", tool_names)
        raw_args = st.text_area("Arguments (JSON)", value="{}", height=80)
        if st.button("Call"):
            _do_call_tool(cfg, chosen, raw_args)

        if st.session_state.call_result is not None:
            st.markdown("**Response:**")
            st.json(st.session_state.call_result)


def _do_list_tools(cfg: dict):
    from mcppt.core import configure, mcp_init, rpc
    configure(no_verify=cfg["no_verify"], proxy=cfg["proxy"])
    try:
        mcp_init(cfg["url"], cfg["token"])
        r = rpc(cfg["url"], "tools/list", {}, token=cfg["token"])
        tools = r["body"].get("result", {}).get("tools", []) if r["status"] == 200 else []
        st.session_state.tools_cache = tools
        if not tools:
            st.warning(f"No tools returned (HTTP {r['status']})")
    except Exception as e:
        st.error(f"Error: {e}")


def _do_call_tool(cfg: dict, tool_name: str, raw_args: str):
    from mcppt.core import configure, mcp_init, rpc
    configure(no_verify=cfg["no_verify"], proxy=cfg["proxy"])
    try:
        tool_args = json.loads(raw_args)
    except json.JSONDecodeError as e:
        st.error(f"Invalid JSON: {e}")
        return
    try:
        mcp_init(cfg["url"], cfg["token"])
        r = rpc(cfg["url"], "tools/call",
                {"name": tool_name, "arguments": tool_args},
                token=cfg["token"])
        st.session_state.call_result = r
    except Exception as e:
        st.error(f"Error: {e}")


# ── checks tab ────────────────────────────────────────────────────────────────

def _tab_checks():
    st.markdown("### All 16 Security Checks")
    st.markdown(
        "MCPTROTTER runs these checks against any MCP server. "
        "Select specific ones from the sidebar to run a targeted scan."
    )

    SEV_META = {
        "CRITICAL": ("#da3633", "Direct compromise or data exfiltration possible"),
        "HIGH":     ("#d29922", "Significant security control bypass"),
        "MEDIUM":   ("#9e6a03", "Notable weakness, requires manual verification"),
        "LOW":      ("#1f6feb", "Informational / hardening recommendation"),
    }

    CHECK_SEV = {
        "enum":             "MEDIUM",
        "auth":             "CRITICAL",
        "idor":             "HIGH",
        "injection":        "HIGH",
        "schema":           "MEDIUM",
        "ssrf":             "CRITICAL",
        "publish":          "CRITICAL",
        "rate":             "LOW",
        "stored":           "CRITICAL",
        "scope":            "HIGH",
        "replay":           "HIGH",
        "context_overflow": "HIGH",
        "poison_all":       "CRITICAL",
        "tenant":           "CRITICAL",
        "session":          "HIGH",
        "rug_pull":         "CRITICAL",
    }

    for sev in SEV_ORDER:
        color, label = SEV_META[sev]
        st.markdown(
            f'<div style="border-left:4px solid {color};padding:4px 12px;margin-bottom:4px;">'
            f'<b style="color:{color}">{sev}</b> — <small style="color:#8b949e">{label}</small>'
            f'</div>',
            unsafe_allow_html=True,
        )
        for check, s in CHECK_SEV.items():
            if s == sev:
                st.markdown(
                    f"&nbsp;&nbsp;&nbsp; `{check}` — {CHECK_DESC[check]}"
                )
        st.markdown("")


# ── report helpers ────────────────────────────────────────────────────────────

def _build_markdown(state) -> str:
    from mcppt.report import save_markdown
    with tempfile.NamedTemporaryFile(suffix=".md", delete=False, mode="w", encoding="utf-8") as f:
        path = f.name
    save_markdown(state, path)
    with open(path, encoding="utf-8") as f:
        content = f.read()
    return content


def _build_json(state) -> str:
    from mcppt.report import save_json
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w", encoding="utf-8") as f:
        path = f.name
    save_json(state, path)
    with open(path, encoding="utf-8") as f:
        content = f.read()
    return content


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    _init_state()
    cfg = _sidebar()

    st.markdown(
        "<h1 style='color:#da3633;font-family:monospace;letter-spacing:2px'>"
        "MCPTROTTER"
        "</h1>"
        "<p style='color:#8b949e;margin-top:-12px'>"
        "MCP Pentest Tool &nbsp;·&nbsp; 16 automated security checks &nbsp;·&nbsp; v2.1"
        "</p>",
        unsafe_allow_html=True,
    )
    st.markdown("---")

    tab_scan, tab_explore, tab_checks = st.tabs(["Scan", "Explore", "Checks Reference"])

    with tab_scan:
        _tab_scan(cfg)

    with tab_explore:
        _tab_explore(cfg)

    with tab_checks:
        _tab_checks()


if __name__ == "__main__":
    main()
