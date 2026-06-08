"""MCPPT CLI — entry point for `mcppt` command."""
from __future__ import annotations

import argparse
import json
import sys

from .core import configure, mcp_init, rpc

CHECKS = [
    "enum", "auth", "idor", "injection", "schema", "ssrf", "publish",
    "rate", "stored", "scope", "replay", "context_overflow", "poison_all",
    "tenant", "session", "rug_pull",
    "headers", "error_disclosure", "tool_poisoning", "resources",
    "cmd_injection", "path_traversal", "jwt_audit", "oauth_discovery",
    "secret_scan", "tool_shadowing",
    "sampling", "schema_leak",
]

EPILOG = """
commands:
  scan        Run all/selected security checks with live TUI
  list        Enumerate tools and parameter schemas
  call        Call a single tool with custom JSON args
  shell       Launch interactive REPL (default when run with no args)
  serve-mcp   Expose MCPTROTTER itself as an MCP server

examples:
  mcppt                                               <- interactive shell
  mcppt scan --url https://target.com/mcp --token eyJ...
  mcppt scan --url https://target.com/mcp --token t1 --token2 t2 --checks idor,scope
  mcppt scan --url https://target.com/mcp --no-verify --output report.md
  mcppt scan --url https://target.com/mcp --proxy http://127.0.0.1:8080 --checks all
  mcppt list --url https://target.com/mcp --token eyJ...
  mcppt call --url https://target.com/mcp --token eyJ... --tool get_user --args '{"id":1}'
  mcppt serve-mcp --port 8899
"""


# ── scan ──────────────────────────────────────────────────────────────────────

def cmd_scan(args: argparse.Namespace) -> None:
    from .checks import ScanState, run_scan, ALL_CHECKS
    from .tui import run_tui
    from .report import save_json, save_markdown

    configure(no_verify=args.no_verify, proxy=args.proxy or None)

    checks = [c.strip() for c in args.checks.split(",")]
    run_all = "all" in checks
    total = len(ALL_CHECKS) if run_all else len([c for c in checks if c in ALL_CHECKS])

    state = ScanState(
        url=args.url,
        token=args.token or None,
        token2=args.token2 or None,
        checks_total=total,
    )

    run_tui(state, run_scan, state, checks)

    if args.output:
        p = (
            save_markdown(state, args.output)
            if args.output.endswith(".md")
            else save_json(state, args.output)
        )
        print(f"\n  Report saved → {p}")


# ── list ──────────────────────────────────────────────────────────────────────

def cmd_list(args: argparse.Namespace) -> None:
    from rich import box
    from rich.console import Console
    from rich.table import Table

    configure(no_verify=args.no_verify, proxy=args.proxy or None)
    console = Console()

    mcp_init(args.url, args.token or None)
    r = rpc(args.url, "tools/list", {}, token=args.token or None)
    if r["status"] != 200:
        console.print(f"[red]tools/list failed: HTTP {r['status']}[/]")
        sys.exit(1)

    tools = r["body"].get("result", {}).get("tools", [])
    if not tools:
        console.print("[yellow]No tools returned.[/]")
        return

    console.print(f"\n[bold]{len(tools)} tools on [cyan]{args.url}[/][/]\n")
    for t in tools:
        name = t.get("name", "?")
        desc = t.get("description", "").split("\n")[0][:80]
        props = t.get("inputSchema", {}).get("properties", {})
        required = t.get("inputSchema", {}).get("required", [])

        console.print(f"[bold cyan]{name}[/]  [dim]{desc}[/]")
        if props:
            tbl = Table(show_header=True, box=box.SIMPLE, header_style="bold dim", padding=(0, 1))
            tbl.add_column("Field")
            tbl.add_column("Type")
            tbl.add_column("Req", width=4)
            tbl.add_column("Description")
            for field, meta in props.items():
                req = "[red]*[/]" if field in required else ""
                tbl.add_row(
                    field,
                    meta.get("type", "any"),
                    req,
                    meta.get("description", "")[:70],
                )
            console.print(tbl)
        console.print()


# ── call ──────────────────────────────────────────────────────────────────────

def cmd_call(args: argparse.Namespace) -> None:
    from rich.console import Console

    configure(no_verify=args.no_verify, proxy=args.proxy or None)
    console = Console()

    try:
        tool_args = json.loads(args.args)
    except json.JSONDecodeError as e:
        console.print(f"[red]Invalid JSON args: {e}[/]")
        sys.exit(1)

    mcp_init(args.url, args.token or None)
    console.print(f"\nCalling [cyan]{args.tool}[/] on [cyan]{args.url}[/]...")
    r = rpc(
        args.url,
        "tools/call",
        {"name": args.tool, "arguments": tool_args},
        token=args.token or None,
    )
    status_style = "green" if r["status"] == 200 else "red"
    console.print(f"[{status_style}]HTTP {r['status']}[/]")

    body = r["body"]
    result = body.get("result", {})
    content = result.get("content", [])
    if content:
        for item in content:
            if item.get("type") == "text":
                try:
                    console.print_json(json.dumps(json.loads(item["text"])))
                except Exception:
                    console.print(item["text"])
    elif "error" in body:
        console.print(f"[red]Error:[/] {body['error']}")
    else:
        console.print_json(json.dumps(body))


# ── arg parsing ───────────────────────────────────────────────────────────────

def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--url",       required=True,  help="MCP server endpoint URL")
    p.add_argument("--token",     default=None,   help="Bearer token (primary)")
    p.add_argument("--no-verify", action="store_true", help="Skip SSL certificate verification")
    p.add_argument("--proxy",     default=None,   help="Proxy URL  e.g. http://127.0.0.1:8080")


def _ensure_utf8() -> None:
    """Reconfigure stdout/stderr to UTF-8 on Windows so Rich box-drawing chars encode."""
    import sys, io
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def cmd_shell(_args=None) -> None:
    from .shell import launch_shell
    launch_shell()


def cmd_serve_mcp(args: argparse.Namespace) -> None:
    from .server import serve
    serve(port=args.port)


def main() -> None:
    _ensure_utf8()
    parser = argparse.ArgumentParser(
        prog="mcppt",
        description="MCPTROTTER v2.3 — MCP Pentest Tool  |  28 automated security checks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", help="Run security scan (live TUI)")
    _add_common(p_scan)
    p_scan.add_argument("--token2",  default=None, help="Second user token (IDOR/scope/tenant checks)")
    p_scan.add_argument("--checks",  default="all",
                        help=f"Comma-separated checks or 'all'.  Options: {','.join(CHECKS)}")
    p_scan.add_argument("--output",  default=None,
                        help="Save report to file  (report.json  or  report.md)")

    # list
    p_list = sub.add_parser("list", help="Enumerate tools and schemas")
    _add_common(p_list)

    # call
    p_call = sub.add_parser("call", help="Call a single tool")
    _add_common(p_call)
    p_call.add_argument("--tool", required=True, help="Tool name to call")
    p_call.add_argument("--args", default="{}", help="JSON arguments  (default: {})")

    # shell
    sub.add_parser("shell", help="Launch interactive REPL (gobuster/ffuf-style)")

    # serve-mcp
    p_serve = sub.add_parser("serve-mcp", help="Expose MCPTROTTER as an MCP server")
    p_serve.add_argument("--port", type=int, default=8899, help="Port to listen on (default: 8899)")

    args = parser.parse_args()

    # default: no subcommand → launch interactive shell
    if not args.command:
        cmd_shell()
        return

    dispatch = {
        "scan":      cmd_scan,
        "list":      cmd_list,
        "call":      cmd_call,
        "shell":     cmd_shell,
        "serve-mcp": cmd_serve_mcp,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
