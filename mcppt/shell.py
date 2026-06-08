"""MCPPT Interactive Shell — gobuster/ffuf-style REPL."""
from __future__ import annotations

import cmd
import json
import re
import threading
import time
from collections import Counter
from typing import Optional

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console(legacy_windows=False, force_terminal=True, highlight=False)


# ── helpers ───────────────────────────────────────────────────────────────────

def _strip(markup: str) -> str:
    return re.sub(r"\[/?[^\[\]]*\]", "", markup)


def _print_findings(findings: list) -> None:
    if not findings:
        console.print("  [dim]No findings yet.[/]")
        return
    counts = Counter(f.severity for f in findings)
    console.print(
        f"\n  [bold red]CRITICAL {counts.get('CRITICAL',0)}[/]  "
        f"[bold yellow]HIGH {counts.get('HIGH',0)}[/]  "
        f"[yellow]MEDIUM {counts.get('MEDIUM',0)}[/]  "
        f"[cyan]LOW {counts.get('LOW',0)}[/]"
    )
    tbl = Table(box=box.SIMPLE, header_style="bold dim", show_header=True)
    tbl.add_column("#",        width=4,  justify="right")
    tbl.add_column("Severity", width=10)
    tbl.add_column("Check",    width=16)
    tbl.add_column("Title")
    SEV = {"CRITICAL": "bold red", "HIGH": "bold yellow", "MEDIUM": "yellow", "LOW": "cyan"}
    for i, f in enumerate(findings, 1):
        s = SEV.get(f.severity, "white")
        tbl.add_row(str(i), f"[{s}]{f.severity}[/]", f"[dim]{f.check}[/]", f.title)
    console.print(tbl)


# ── shell ─────────────────────────────────────────────────────────────────────

class MCPPTShell(cmd.Cmd):
    intro = ""
    prompt = "\n[mcppt]> "

    def __init__(self):
        super().__init__()
        self.url:       Optional[str] = None
        self.token:     Optional[str] = None
        self.token2:    Optional[str] = None
        self.no_verify: bool          = False
        self.proxy:     Optional[str] = None
        self.findings:  list          = []
        self.tools_cache: list        = []
        self.ai_key:    Optional[str] = None
        self.ai_provider: str         = "claude"

    # ── prompt override (add colour) ──────────────────────────────────────────

    def cmdloop(self, intro=None):
        _banner()
        try:
            while True:
                try:
                    console.print(
                        f"\n[bold red]mcppt[/][dim]>[/] ",
                        end="",
                    )
                    line = input()
                except EOFError:
                    break
                if line.strip():
                    self.onecmd(line.strip())
        except KeyboardInterrupt:
            console.print("\n[dim]Use 'exit' to quit.[/]")

    # ── target ────────────────────────────────────────────────────────────────

    def do_target(self, arg: str):
        """Set MCP server URL.  target https://your-server.com/mcp"""
        arg = arg.strip()
        if not arg:
            console.print(f"  [dim]Current target:[/] {self.url or '[not set]'}")
            return
        self.url = arg
        console.print(f"  [green]Target set:[/] {self.url}")

    # ── token ─────────────────────────────────────────────────────────────────

    def do_token(self, arg: str):
        """Set primary bearer token.  token eyJ..."""
        arg = arg.strip()
        if not arg:
            console.print(f"  [dim]Token:[/] {'***set***' if self.token else '[not set]'}")
            return
        self.token = arg
        console.print(f"  [green]Token set[/] ({len(arg)} chars)")

    def do_token2(self, arg: str):
        """Set second user token for IDOR/scope/tenant checks.  token2 eyJ..."""
        arg = arg.strip()
        if not arg:
            console.print(f"  [dim]Token2:[/] {'***set***' if self.token2 else '[not set]'}")
            return
        self.token2 = arg
        console.print(f"  [green]Token2 set[/] ({len(arg)} chars)")

    # ── noverify / proxy ──────────────────────────────────────────────────────

    def do_noverify(self, _):
        """Toggle SSL certificate verification skip."""
        self.no_verify = not self.no_verify
        state = "[yellow]DISABLED[/]" if self.no_verify else "[green]enabled[/]"
        console.print(f"  SSL verify: {state}")

    def do_proxy(self, arg: str):
        """Set or clear Burp proxy.  proxy http://127.0.0.1:8080  |  proxy off"""
        arg = arg.strip()
        if arg in ("off", "none", "clear", ""):
            self.proxy = None
            console.print("  [dim]Proxy cleared[/]")
        else:
            self.proxy = arg
            console.print(f"  [green]Proxy set:[/] {self.proxy}")

    # ── status ────────────────────────────────────────────────────────────────

    def do_status(self, _):
        """Show current configuration."""
        console.print()
        console.print(f"  [dim]Target  [/] {self.url or '[bold red]not set[/]'}")
        console.print(f"  [dim]Token   [/] {'***' if self.token else '[yellow]not set[/]'}")
        console.print(f"  [dim]Token2  [/] {'***' if self.token2 else '[dim]not set[/]'}")
        console.print(f"  [dim]SSL     [/] {'[yellow]verify OFF[/]' if self.no_verify else 'verify on'}")
        console.print(f"  [dim]Proxy   [/] {self.proxy or 'none'}")
        console.print(f"  [dim]AI      [/] {self.ai_provider + ' (key set)' if self.ai_key else '[dim]not configured[/]'}")
        console.print(f"  [dim]Findings[/] {len(self.findings)}")

    # ── scan ──────────────────────────────────────────────────────────────────

    def do_scan(self, arg: str):
        """Run security scan.  scan [checks]   e.g. scan all  |  scan auth ssrf idor"""
        if not self.url:
            console.print("  [red]Set target first:[/]  target https://your-server.com/mcp")
            return

        from .core import configure
        from .checks import ScanState, run_scan, ALL_CHECKS

        configure(no_verify=self.no_verify, proxy=self.proxy)

        parts = arg.strip().split() if arg.strip() else ["all"]
        checks = parts if parts[0] != "all" else ["all"]
        run_all = "all" in checks
        total = len(ALL_CHECKS) if run_all else len([c for c in checks if c in ALL_CHECKS])

        state = ScanState(
            url=self.url,
            token=self.token,
            token2=self.token2,
            checks_total=total,
        )

        console.print(f"\n  [bold]Scanning[/] [cyan]{self.url}[/]  checks=[yellow]{','.join(checks)}[/]")
        console.print("  [dim]─────────────────────────────────[/]")

        seen = [0]

        def _stream():
            while not state.done:
                with state._lock:
                    new = state.log_lines[seen[0]:]
                    seen[0] = len(state.log_lines)
                for line in new:
                    clean = _strip(line)
                    if "CHECK" in clean:
                        console.print(f"  [bold white]{clean.replace('[CHECK]','').strip()}[/]")
                    elif "PASS" in clean:
                        console.print(f"  [green]  PASS[/] {clean.replace('[PASS]','').strip()}")
                    elif "INFO" in clean:
                        console.print(f"  [dim]  INFO {clean.replace('[INFO]','').strip()}[/]")
                    elif "CRIT" in clean:
                        console.print(f"  [bold red]  CRIT[/] {clean.replace('CRIT','').strip()}")
                    elif "HIGH" in clean:
                        console.print(f"  [bold yellow]  HIGH[/] {clean.replace('HIGH','').strip()}")
                    elif "MED" in clean:
                        console.print(f"  [yellow]   MED[/] {clean.replace('MED ','').strip()}")
                    elif "LOW" in clean:
                        console.print(f"  [cyan]   LOW[/] {clean.replace('LOW ','').strip()}")
                time.sleep(0.1)

        t = threading.Thread(target=run_scan, args=(state, checks), daemon=True)
        s = threading.Thread(target=_stream, daemon=True)
        t.start(); s.start()
        t.join(); time.sleep(0.3); s.join(timeout=1)

        self.findings = state.findings
        counts = Counter(f.severity for f in state.findings)
        console.print(f"\n  [dim]─────────────────────────────────[/]")
        console.print(
            f"  Done in {state.elapsed:.1f}s  |  "
            f"[bold red]{counts.get('CRITICAL',0)} CRITICAL[/]  "
            f"[bold yellow]{counts.get('HIGH',0)} HIGH[/]  "
            f"[yellow]{counts.get('MEDIUM',0)} MEDIUM[/]  "
            f"[cyan]{counts.get('LOW',0)} LOW[/]"
        )
        if state.findings:
            console.print("  [dim]Run 'findings' to see details, 'analyze' for AI analysis.[/]")

    # ── list ──────────────────────────────────────────────────────────────────

    def do_list(self, _):
        """Enumerate tools on the target MCP server."""
        if not self.url:
            console.print("  [red]Set target first.[/]")
            return
        from .core import configure, mcp_init, rpc
        configure(no_verify=self.no_verify, proxy=self.proxy)
        mcp_init(self.url, self.token)
        r = rpc(self.url, "tools/list", {}, token=self.token)
        tools = r["body"].get("result", {}).get("tools", []) if r["status"] == 200 else []
        if not tools:
            console.print(f"  [yellow]No tools returned (HTTP {r['status']})[/]")
            return
        self.tools_cache = tools
        console.print(f"\n  [bold]{len(tools)} tools[/] on [cyan]{self.url}[/]\n")
        for t in tools:
            name = t.get("name", "?")
            desc = t.get("description", "").split("\n")[0][:70]
            props = t.get("inputSchema", {}).get("properties", {})
            req   = t.get("inputSchema", {}).get("required", [])
            args_str = "  ".join(
                f"[{'red' if f in req else 'dim'}]{f}[/]({m.get('type','?')})"
                for f, m in props.items()
            )
            console.print(f"  [bold cyan]{name}[/]  [dim]{desc}[/]")
            if args_str:
                console.print(f"    args: {args_str}")

    # ── call ──────────────────────────────────────────────────────────────────

    def do_call(self, arg: str):
        """Call a tool.  call <tool_name> [json_args]
        Examples:
          call get_notes
          call get_user {"id": 1}
          call save_note {"text": "hello"}"""
        if not self.url:
            console.print("  [red]Set target first.[/]")
            return
        parts = arg.strip().split(None, 1)
        if not parts:
            console.print("  [dim]Usage: call <tool_name> [json_args][/]")
            return
        tool_name = parts[0]
        raw_args  = parts[1] if len(parts) > 1 else "{}"
        try:
            tool_args = json.loads(raw_args)
        except json.JSONDecodeError as e:
            console.print(f"  [red]Invalid JSON:[/] {e}")
            return

        from .core import configure, mcp_init, rpc
        configure(no_verify=self.no_verify, proxy=self.proxy)
        mcp_init(self.url, self.token)
        r = rpc(self.url, "tools/call", {"name": tool_name, "arguments": tool_args}, token=self.token)
        status_col = "green" if r["status"] == 200 else "red"
        console.print(f"\n  [{status_col}]HTTP {r['status']}[/]  tool=[cyan]{tool_name}[/]")

        body    = r["body"]
        result  = body.get("result", {})
        content = result.get("content", [])
        if content:
            for item in content:
                if item.get("type") == "text":
                    try:
                        parsed = json.loads(item["text"])
                        console.print_json(json.dumps(parsed))
                    except Exception:
                        console.print(f"  {item['text']}")
        elif "error" in body:
            console.print(f"  [red]Error:[/] {body['error']}")
        else:
            console.print_json(json.dumps(body))

    # ── findings ──────────────────────────────────────────────────────────────

    def do_findings(self, _):
        """Show all findings from the last scan."""
        _print_findings(self.findings)

    def do_clear(self, _):
        """Clear current findings."""
        self.findings = []
        console.print("  [dim]Findings cleared.[/]")

    # ── report ────────────────────────────────────────────────────────────────

    def do_report(self, arg: str):
        """Export findings to file.  report [filename]
        Examples:
          report               → report.md (default)
          report out.json      → JSON format
          report pentest.md    → Markdown"""
        if not self.findings:
            console.print("  [yellow]No findings to export. Run 'scan' first.[/]")
            return
        from .report import save_json, save_markdown
        from .checks import ScanState
        state = ScanState(url=self.url or "unknown", token=self.token, token2=self.token2)
        state.findings = self.findings

        path = arg.strip() or "report.md"
        p = save_json(state, path) if path.endswith(".json") else save_markdown(state, path)
        console.print(f"  [green]Report saved:[/] {p}")

    # ── AI ────────────────────────────────────────────────────────────────────

    def do_ai(self, arg: str):
        """Set AI provider + API key for finding analysis.
        Usage:
          ai claude  sk-ant-api03-...       → Claude (default)
          ai openai  sk-...                 → OpenAI GPT-4
          ai off                            → disable AI"""
        parts = arg.strip().split(None, 1)
        if not parts or parts[0] == "off":
            self.ai_key = None
            console.print("  [dim]AI analysis disabled.[/]")
            return
        if len(parts) == 1:
            # just a key, assume claude
            self.ai_provider = "claude"
            self.ai_key = parts[0]
        else:
            self.ai_provider = parts[0].lower()
            self.ai_key = parts[1]
        console.print(f"  [green]AI set:[/] {self.ai_provider}  key=***{self.ai_key[-6:]}")

    def do_analyze(self, _):
        """Send findings to Claude/OpenAI for attack narrative + remediation priority."""
        if not self.findings:
            console.print("  [yellow]No findings. Run 'scan' first.[/]")
            return
        if not self.ai_key:
            console.print("  [yellow]No AI key. Run: ai claude sk-ant-...[/]")
            return

        findings_text = "\n".join(
            f"- [{f.severity}] [{f.check}] {f.title}: {f.detail}"
            for f in self.findings
        )
        prompt = f"""You are a security analyst reviewing findings from an automated MCP server security scan.

Target: {self.url}

Findings:
{findings_text}

Provide:
1. Attack chain narrative — how an attacker would chain these findings together
2. Top 3 findings to fix first (with one-line reason why)
3. Overall risk rating (CRITICAL / HIGH / MEDIUM / LOW) with one sentence justification

Be concise. Use bullet points. No preamble."""

        console.print("\n  [dim]Sending to AI for analysis...[/]")
        try:
            response = _call_ai(self.ai_provider, self.ai_key, prompt)
            console.print(f"\n[bold]AI Analysis ({self.ai_provider})[/]")
            console.rule(style="dim")
            console.print(response)
            console.rule(style="dim")
        except Exception as e:
            console.print(f"  [red]AI error:[/] {e}")

    # ── help ──────────────────────────────────────────────────────────────────

    def do_help(self, _):
        console.print("""
[bold]MCPPT Interactive Shell[/]  --  commands:

  [bold cyan]Setup[/]
    target  <url>          Set MCP server URL
    token   <bearer>       Set primary auth token
    token2  <bearer>       Set second token (IDOR/scope/tenant checks)
    noverify               Toggle SSL verification skip
    proxy   <url|off>      Set/clear Burp proxy
    status                 Show current configuration

  [bold cyan]Scan[/]
    scan [checks]          Run security scan
                           Examples:
                             scan               (all 16 checks)
                             scan auth ssrf
                             scan idor scope tenant
                           Checks: enum auth idor injection schema ssrf publish
                                   rate stored scope replay context_overflow
                                   poison_all tenant session rug_pull
                                   headers error_disclosure tool_poisoning
                                   resources cmd_injection path_traversal
                                   jwt_audit oauth_discovery secret_scan
                                   tool_shadowing

  [bold cyan]Explore[/]
    list                   Enumerate tools + schemas
    call <tool> [json]     Call a tool manually
                           Examples:
                             call get_notes
                             call get_user {"id": 1}

  [bold cyan]Results[/]
    findings               Show findings from last scan
    clear                  Clear findings
    report [file.md|.json] Export report (default: report.md)

  [bold cyan]AI Analysis[/]
    ai claude  <sk-ant-key>   Configure Claude for analysis
    ai openai  <sk-key>       Configure OpenAI GPT-4
    ai off                    Disable AI
    analyze                   Analyze findings with AI

  [bold cyan]Shell[/]
    help                   This menu
    exit / quit / q        Exit
""")

    def do_exit(self, _):
        """Exit the shell."""
        console.print("\n  [dim]Bye.[/]\n")
        return True

    do_quit = do_exit
    do_q    = do_exit

    def default(self, line: str):
        console.print(f"  [red]Unknown command:[/] {line.split()[0]}  (type 'help')")


# ── AI backend ────────────────────────────────────────────────────────────────

def _call_ai(provider: str, key: str, prompt: str) -> str:
    if provider == "claude":
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=key)
            msg = client.messages.create(
                model="claude-opus-4-8",
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )
            return msg.content[0].text
        except ImportError:
            raise RuntimeError("Install anthropic SDK:  pip install anthropic")

    elif provider in ("openai", "gpt"):
        try:
            from openai import OpenAI
            client = OpenAI(api_key=key)
            resp = client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1024,
            )
            return resp.choices[0].message.content
        except ImportError:
            raise RuntimeError("Install openai SDK:  pip install openai")

    else:
        raise RuntimeError(f"Unknown provider '{provider}'. Use: claude  or  openai")


# ── banner ────────────────────────────────────────────────────────────────────

def _banner():
    _ART = [
        r"  __  __   ___  ___  _____ ____   ___ _____ _____ ___ ___",
        r" |  \/  | / __|| _ \|_   _|  _ \ / _ \_   _|_   _| __| _ \ ",
        r" | |\/| || (__|  _/ | | |   /  | (_) || |   | | | _||   /",
        r" |_|  |_| \___||_|  |_| |_|_\  \___/ |_|   |_| |___|_|_\ ",
    ]
    console.print()
    for line in _ART:
        console.print(Text(line, style="bold red"))
    console.print()
    console.print(Text("  MCP Pentest Tool  v2.3  --  28 automated security checks", style="dim"))
    console.print()
    console.print(Text("  by Gurudeep Mallam", style="bold white"))
    console.print(Text("  github  : https://github.com/gurudeepmallam-cmd", style="dim cyan"))
    console.print(Text("  linkedin: https://in.linkedin.com/in/mallam-gurudeep-7734941aa", style="dim cyan"))
    console.print()
    console.print(Text("  type 'help' for commands, 'exit' to quit", style="dim"))
    console.print()


def launch_shell():
    MCPPTShell().cmdloop()
