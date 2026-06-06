"""Rich live TUI for MCPPT scan display."""
from __future__ import annotations

import time
import threading
from collections import Counter
from typing import Optional, Callable

from rich import box
from rich.columns import Columns
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .checks import ScanState

console = Console()

SEV_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
}
SEV_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
}

_scan_start: float = 0.0


# ── Layout builders ───────────────────────────────────────────────────────────

def _header(url: str, token: Optional[str]) -> Panel:
    auth = "[green]token provided[/]" if token else "[yellow]unauthenticated[/]"
    t = Text()
    t.append("MCPPT", style="bold red")
    t.append("  v2.0  ──  MCP Pentest Tool\n", style="white")
    t.append("Target  ", style="dim")
    t.append(url, style="bold cyan")
    t.append(f"   ·   Auth  {auth}")
    return Panel(t, style="red", padding=(0, 2))


def _findings_panel(state: ScanState) -> Panel:
    counts = Counter(f.severity for f in state.findings)

    summary = Table(show_header=False, box=None, padding=(0, 1))
    summary.add_column(width=14)
    summary.add_column(justify="right", width=4)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        n = counts.get(sev, 0)
        style = SEV_STYLE[sev] if n else "dim"
        summary.add_row(f"{SEV_ICON[sev]} {sev}", f"[{style}]{n}[/]")

    details = Text()
    for f in state.findings[-12:]:
        s = SEV_STYLE.get(f.severity, "white")
        details.append(f"\n{SEV_ICON.get(f.severity,'')} ", style=s)
        details.append(f.title[:52], style=s)

    return Panel(Group(summary, details), title="[bold]Findings[/]", border_style="red")


def _log_panel(state: ScanState) -> Panel:
    lines = state.log_lines[-28:]
    t = Text()
    for line in lines:
        t.append(line + "\n")
    return Panel(t, title="[bold]Live Output[/]", border_style="dim white")


def _footer(state: ScanState) -> Panel:
    done = state.checks_done
    total = max(state.checks_total, 1)
    pct = done / total
    filled = int(pct * 38)
    bar = "[green]" + "█" * filled + "[/][dim]" + "░" * (38 - filled) + "[/]"
    elapsed = int(state.elapsed) if state.done else int(time.time() - _scan_start)
    status = "[green]Complete ✓[/]" if state.done else f"[yellow]{state.current_check}[/]"
    t = Text.from_markup(f"{bar}  {done}/{total}  ·  {elapsed}s  ·  {status}")
    return Panel(t, style="dim", padding=(0, 1))


# ── Main entry point ──────────────────────────────────────────────────────────

def run_tui(state: ScanState, scan_fn: Callable, *args) -> None:
    """Run scan_fn(*args) in a background thread, render live TUI until done."""
    global _scan_start
    _scan_start = time.time()

    thread = threading.Thread(target=scan_fn, args=args, daemon=True)
    thread.start()

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=5),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["body"].split_row(
        Layout(name="findings", ratio=2),
        Layout(name="log",      ratio=3),
    )

    with Live(layout, refresh_per_second=4, console=console, screen=False):
        while not state.done:
            _update(layout, state)
            time.sleep(0.25)
        _update(layout, state)  # final render

    thread.join(timeout=5)
    _print_summary(state)


def _update(layout: Layout, state: ScanState) -> None:
    layout["header"].update(_header(state.url, state.token))
    layout["body"]["findings"].update(_findings_panel(state))
    layout["body"]["log"].update(_log_panel(state))
    layout["footer"].update(_footer(state))


# ── Post-scan summary ─────────────────────────────────────────────────────────

def _print_summary(state: ScanState) -> None:
    counts = Counter(f.severity for f in state.findings)
    console.print()
    console.rule("[bold red]SCAN COMPLETE[/]")
    console.print(f"  [dim]Target:[/]   [cyan]{state.url}[/]")
    console.print(
        f"  [dim]Duration:[/] {state.elapsed:.1f}s   "
        f"[dim]Findings:[/] "
        f"[bold red]{counts.get('CRITICAL',0)} CRITICAL[/]  "
        f"[bold yellow]{counts.get('HIGH',0)} HIGH[/]  "
        f"[yellow]{counts.get('MEDIUM',0)} MEDIUM[/]  "
        f"[cyan]{counts.get('LOW',0)} LOW[/]"
    )

    if state.findings:
        console.print()
        tbl = Table(box=box.SIMPLE, header_style="bold dim", show_header=True)
        tbl.add_column("Severity", width=10)
        tbl.add_column("Check",    width=16)
        tbl.add_column("Title")
        for f in state.findings:
            s = SEV_STYLE.get(f.severity, "white")
            tbl.add_row(f"[{s}]{f.severity}[/]", f"[dim]{f.check}[/]", f.title)
        console.print(tbl)
    else:
        console.print("\n  [green]✓ All checks passed — no findings detected.[/]\n")

    console.rule(style="dim")
