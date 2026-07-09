# -*- coding: utf-8 -*-
# ruff: noqa  — intentionally Python 2/3 compatible for Jython (Burp Suite)
"""
MCPTROTTER Burp Suite Extension
================================
Adds an MCPTROTTER tab to Burp Suite for scanning MCP servers directly
from within Burp's UI.

Installation (one-time setup):
  1.  pip install mcppt                     (system Python 3 — NOT Jython)
  2.  Burp → Extender → Options → Python Environment → point to jython-standalone.jar
      Download from: https://repo1.maven.org/maven2/org/python/jython-standalone/
  3.  Burp → Extender → Extensions → Add → Extension type: Python → select this file
  4.  The MCPTROTTER tab appears in Burp's main tab bar.

Or use the CLI to copy this file to any directory:
  mcppt install-burp-ext [--dir /path/to/dir]

Author: Gurudeep Mallam  |  https://github.com/gurudeepmallam-cmd/mcppt
"""
from __future__ import print_function, unicode_literals

import json
import os
import re
import subprocess
import sys
import tempfile
import threading

# ── Burp / Java imports (only available inside Burp Suite) ────────────────────

try:
    from burp import IBurpExtender, ITab, IContextMenuFactory
    from javax.swing import (
        JButton, JCheckBox, JLabel, JMenuItem, JPanel, JPasswordField,
        JScrollPane, JSplitPane, JTabbedPane, JTextArea, JTextField,
        Box, BoxLayout, BorderFactory, SwingUtilities,
    )
    from java.awt import BorderLayout, Color, Dimension, FlowLayout, Font
    from java.awt.event import ActionListener
    from java.lang import String as JString
    from java.util import ArrayList
    _INSIDE_BURP = True
except ImportError:
    _INSIDE_BURP = False
    # Stub base classes so the file can be imported for testing/install outside Burp
    class IBurpExtender(object): pass
    class ITab(object): pass
    class IContextMenuFactory(object): pass
    class ActionListener(object): pass


VERSION = "3.1.0"
EXT_NAME = "MCPTROTTER"

ANSI_RE = re.compile(
    r"\x1b\[[0-9;]*[a-zA-Z]"    # CSI sequences  e.g. \x1b[32m
    r"|\x1b[()=]"               # character set
    r"|\r"                       # carriage return
)

ALL_CHECKS = [
    "enum", "auth", "idor", "injection", "schema", "ssrf", "publish",
    "rate", "stored", "scope", "replay", "context_overflow", "poison_all",
    "tenant", "session", "rug_pull",
    "headers", "error_disclosure", "tool_poisoning", "resources",
    "cmd_injection", "path_traversal", "jwt_audit", "oauth_discovery",
    "secret_scan", "tool_shadowing", "sampling", "schema_leak",
]

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def _strip_ansi(s):
    return ANSI_RE.sub("", s)


def _find_python3():
    """Return a usable 'python3' command or fall back to 'python'."""
    for cmd in ["python3", "python", "py"]:
        try:
            out = subprocess.check_output(
                [cmd, "--version"], stderr=subprocess.STDOUT
            )
            if b"3." in out:
                return cmd
        except Exception:
            pass
    return "python3"


def _get_password(field):
    """Convert JPasswordField.getPassword() char[] to a plain Python str."""
    try:
        return str(JString(field.getPassword()))
    except Exception:
        try:
            return "".join(chr(int(c)) for c in field.getPassword())
        except Exception:
            return ""


# ── Swing helpers ──────────────────────────────────────────────────────────────

def _dark(r, g, b):
    return Color(r, g, b)


BG      = _dark(0x0d, 0x11, 0x17)
FG      = _dark(0xe6, 0xed, 0xf3)
DIM     = _dark(0x8b, 0x94, 0x9e)
RED     = _dark(0xda, 0x36, 0x33)
YELLOW  = _dark(0xd2, 0x99, 0x22)
BLUE    = _dark(0x1f, 0x6f, 0xeb)
GREEN   = _dark(0x3f, 0xb9, 0x50)
PANEL   = _dark(0x16, 0x1b, 0x22)


def _text_area():
    ta = JTextArea()
    ta.setEditable(False)
    ta.setBackground(BG)
    ta.setForeground(FG)
    ta.setFont(Font("Monospaced", Font.PLAIN, 11))
    ta.setLineWrap(True)
    ta.setWrapStyleWord(True)
    return ta


# ── Main extension class ───────────────────────────────────────────────────────

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    """Entry point: Burp calls registerExtenderCallbacks on load."""

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName(EXT_NAME)

        self._python3 = _find_python3()
        self._scan_thread = None
        self._tmp_report  = None

        # Build the Swing UI on the EDT
        SwingUtilities.invokeLater(self._build_ui)

    # ── ITab ──────────────────────────────────────────────────────────────────

    def getTabCaption(self):
        return EXT_NAME

    def getUiComponent(self):
        return self._main_panel

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        self._main_panel = JPanel(BorderLayout())
        self._main_panel.setBackground(BG)

        self._main_panel.add(self._header_panel(), BorderLayout.NORTH)

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        split.setDividerLocation(290)
        split.setBackground(BG)
        split.setLeftComponent(self._config_panel())
        split.setRightComponent(self._results_panel())
        self._main_panel.add(split, BorderLayout.CENTER)

        self._callbacks.addSuiteTab(self)
        self._callbacks.registerContextMenuFactory(self)
        print("[{0}] v{1} loaded — MCP Pentest Tool".format(EXT_NAME, VERSION))

    def _header_panel(self):
        p = JPanel(FlowLayout(FlowLayout.LEFT, 12, 6))
        p.setBackground(PANEL)
        title = JLabel("{0}  v{1}  —  MCP Pentest Tool".format(EXT_NAME, VERSION))
        title.setFont(Font("Monospaced", Font.BOLD, 15))
        title.setForeground(RED)
        p.add(title)
        sub = JLabel("31 automated MCP security checks  |  pip install mcppt")
        sub.setFont(Font("Monospaced", Font.PLAIN, 11))
        sub.setForeground(DIM)
        p.add(sub)
        return p

    def _config_panel(self):
        outer = JPanel()
        outer.setLayout(BoxLayout(outer, BoxLayout.Y_AXIS))
        outer.setBackground(PANEL)
        outer.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        def _label(text):
            lbl = JLabel(text)
            lbl.setForeground(DIM)
            lbl.setFont(Font("Monospaced", Font.PLAIN, 11))
            return lbl

        def _field(placeholder=""):
            tf = JTextField(placeholder, 28)
            tf.setBackground(BG)
            tf.setForeground(FG)
            tf.setCaretColor(FG)
            tf.setFont(Font("Monospaced", Font.PLAIN, 11))
            tf.setMaximumSize(Dimension(270, 26))
            return tf

        def _pwd_field():
            pf = JPasswordField(28)
            pf.setBackground(BG)
            pf.setForeground(FG)
            pf.setCaretColor(FG)
            pf.setFont(Font("Monospaced", Font.PLAIN, 11))
            pf.setMaximumSize(Dimension(270, 26))
            return pf

        def _gap(n=6):
            return Box.createRigidArea(Dimension(0, n))

        self._url_field    = _field("https://target.com/mcp")
        self._token_field  = _pwd_field()
        self._token2_field = _pwd_field()
        self._proxy_field  = _field("http://127.0.0.1:8080")
        self._python_field = _field(self._python3)

        for lbl, widget in [
            ("Target MCP URL",         self._url_field),
            ("Bearer Token (optional)", self._token_field),
            ("Token2 — IDOR/Scope",     self._token2_field),
            ("Burp Proxy (optional)",   self._proxy_field),
            ("Python 3 path",           self._python_field),
        ]:
            outer.add(_label(lbl))
            outer.add(widget)
            outer.add(_gap())

        # SSL toggle
        self._ssl_cb = JCheckBox("Skip SSL verification", True)
        self._ssl_cb.setBackground(PANEL)
        self._ssl_cb.setForeground(FG)
        self._ssl_cb.setFont(Font("Monospaced", Font.PLAIN, 11))
        outer.add(self._ssl_cb)
        outer.add(_gap(10))

        # Checks
        outer.add(_label("Checks:"))
        self._all_checks_cb = JCheckBox("All 28 checks (recommended)", True)
        self._all_checks_cb.setBackground(PANEL)
        self._all_checks_cb.setForeground(FG)
        self._all_checks_cb.setFont(Font("Monospaced", Font.PLAIN, 11))
        outer.add(self._all_checks_cb)
        outer.add(_gap(4))

        self._check_boxes = {}
        for c in ALL_CHECKS:
            cb = JCheckBox(c, False)
            cb.setBackground(PANEL)
            cb.setForeground(DIM)
            cb.setFont(Font("Monospaced", Font.PLAIN, 10))
            self._check_boxes[c] = cb
            outer.add(cb)

        outer.add(_gap(12))

        self._scan_btn = JButton("SCAN")
        self._scan_btn.setBackground(RED)
        self._scan_btn.setForeground(Color.WHITE)
        self._scan_btn.setFont(Font("Monospaced", Font.BOLD, 13))
        self._scan_btn.setMaximumSize(Dimension(270, 34))
        self._scan_btn.addActionListener(_ScanListener(self))
        outer.add(self._scan_btn)
        outer.add(_gap(4))

        # Status label
        self._status_lbl = JLabel("Ready.")
        self._status_lbl.setForeground(DIM)
        self._status_lbl.setFont(Font("Monospaced", Font.PLAIN, 10))
        outer.add(self._status_lbl)
        outer.add(Box.createVerticalGlue())

        return JScrollPane(outer)

    def _results_panel(self):
        self._result_tabs = JTabbedPane()
        self._result_tabs.setBackground(BG)
        self._result_tabs.setForeground(FG)

        self._findings_area = _text_area()
        self._findings_area.setText(
            "Run a scan to see findings here.\n\n"
            "Quick start:\n"
            "  1. Enter target MCP URL in the left panel\n"
            "  2. Optionally add a Bearer token\n"
            "  3. Click SCAN\n\n"
            "Tip: right-click any request in Proxy history\n"
            "     and choose 'Send to MCPTROTTER' to populate\n"
            "     the target URL automatically."
        )

        self._log_area = _text_area()
        self._log_area.setForeground(DIM)

        self._report_area = _text_area()

        self._result_tabs.addTab("Findings", JScrollPane(self._findings_area))
        self._result_tabs.addTab("Scan Log", JScrollPane(self._log_area))
        self._result_tabs.addTab("Report",   JScrollPane(self._report_area))

        return self._result_tabs

    # ── Scan logic ────────────────────────────────────────────────────────────

    def _start_scan(self):
        url    = self._url_field.getText().strip()
        token  = _get_password(self._token_field).strip()
        token2 = _get_password(self._token2_field).strip()
        proxy  = self._proxy_field.getText().strip()
        py3    = self._python_field.getText().strip() or self._python3

        if not url or url == "https://target.com/mcp":
            self._log_line("ERROR: Enter a valid target MCP URL.")
            return

        # Temp file for JSON report
        fd, self._tmp_report = tempfile.mkstemp(suffix=".json", prefix="mcppt_")
        os.close(fd)

        cmd = [py3, "-m", "mcppt.cli", "scan",
               "--url", url,
               "--output", self._tmp_report]
        if token:
            cmd += ["--token", token]
        if token2:
            cmd += ["--token2", token2]
        if proxy:
            cmd += ["--proxy", proxy]
        if self._ssl_cb.isSelected():
            cmd.append("--no-verify")

        if not self._all_checks_cb.isSelected():
            sel = [c for c, cb in self._check_boxes.items() if cb.isSelected()]
            if sel:
                cmd += ["--checks", ",".join(sel)]

        self._log_area.setText("")
        self._findings_area.setText("")
        self._report_area.setText("")
        self._log_line("Target : " + url)
        self._log_line("Command: " + " ".join(cmd))
        self._log_line("-" * 60)
        self._set_status("Scanning…")

        def _run():
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                for raw in proc.stdout:
                    try:
                        line = raw.decode("utf-8", errors="replace").rstrip()
                    except Exception:
                        line = str(raw).rstrip()
                    line = _strip_ansi(line)
                    if line:
                        captured = line
                        SwingUtilities.invokeLater(
                            lambda l=captured: self._log_line(l)
                        )
                proc.wait()
            except Exception as exc:
                err = str(exc)
                SwingUtilities.invokeLater(
                    lambda e=err: self._log_line(
                        "ERROR: " + e + "\n\nMake sure mcppt is installed:\n  pip install mcppt"
                    )
                )
            finally:
                SwingUtilities.invokeLater(self._scan_finished)

        self._scan_thread = threading.Thread(target=_run)
        self._scan_thread.setDaemon(True)
        self._scan_thread.start()

    def _scan_finished(self):
        self._scan_btn.setText("SCAN")
        self._scan_btn.setEnabled(True)

        try:
            self._load_json_report()
        except Exception as exc:
            self._log_line("Could not parse JSON report: " + str(exc))
            self._set_status("Scan complete (report parse error).")
            return

        try:
            if self._tmp_report and os.path.exists(self._tmp_report):
                os.remove(self._tmp_report)
        except Exception:
            pass
        self._tmp_report = None

    def _load_json_report(self):
        if not self._tmp_report or not os.path.exists(self._tmp_report):
            self._set_status("Scan complete.")
            return

        with open(self._tmp_report, "r") as fh:
            data = json.load(fh)

        findings = data.get("findings", [])
        summary  = data.get("summary", {})
        elapsed  = data.get("elapsed_seconds", 0)
        target   = data.get("target", "")

        # ── Findings tab ──────────────────────────────────────────────────────
        lines = [
            "=" * 62,
            "  MCPTROTTER SCAN RESULTS",
            "  Target  : " + target,
            "  Duration: {0:.1f}s   |   Total findings: {1}".format(
                elapsed, len(findings)
            ),
            "=" * 62,
            "",
            "  CRITICAL : {CRITICAL}   HIGH : {HIGH}   MEDIUM : {MEDIUM}   LOW : {LOW}".format(
                **summary
            ),
            "",
        ]

        if not findings:
            lines.append("  No findings — all checks passed.")
        else:
            for sev in SEV_ORDER:
                group = [f for f in findings if f.get("severity") == sev]
                if not group:
                    continue
                lines.append("── {0} ({1}) ──".format(sev, len(group)))
                for f in group:
                    lines.append(
                        "  [{0}] {1}".format(f.get("check", "?"), f.get("title", ""))
                    )
                    lines.append(
                        "        " + f.get("detail", "")[:100]
                    )
                lines.append("")

        self._findings_area.setText("\n".join(lines))

        # ── Report tab ────────────────────────────────────────────────────────
        rpt = [
            "# MCPTROTTER Scan Report",
            "",
            "**Target:** `{0}`".format(target),
            "**Duration:** {0:.1f}s".format(elapsed),
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "| --- | --- |",
        ]
        for sev in SEV_ORDER:
            rpt.append("| {0} | {1} |".format(sev, summary.get(sev, 0)))
        rpt += ["", "## Findings", ""]

        if not findings:
            rpt.append("_No findings detected._")
        else:
            for i, f in enumerate(findings, 1):
                rpt += [
                    "### {0}. [{1}] {2}".format(i, f.get("severity", "?"), f.get("title", "")),
                    "",
                    "**Check:** `{0}`  ".format(f.get("check", "")),
                    "",
                    f.get("detail", ""),
                    "",
                    "---",
                    "",
                ]

        rpt += [
            "",
            "_Generated by MCPTROTTER v{0}  |  https://github.com/gurudeepmallam-cmd/mcppt_".format(VERSION),
        ]
        self._report_area.setText("\n".join(rpt))

        total = len(findings)
        crit  = summary.get("CRITICAL", 0)
        high  = summary.get("HIGH", 0)
        status = "Scan complete — {0} finding(s)  [CRIT:{1}  HIGH:{2}]".format(
            total, crit, high
        )
        self._set_status(status)
        self._result_tabs.setSelectedIndex(0)   # switch to Findings tab

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _log_line(self, text):
        self._log_area.append(text + "\n")

    def _set_status(self, text):
        self._status_lbl.setText(text)

    # ── IContextMenuFactory — right-click proxy history ───────────────────────

    def createMenuItems(self, invocation):
        menu = ArrayList()
        msgs = invocation.getSelectedMessages()
        if not msgs:
            return menu
        item = JMenuItem("Send to MCPTROTTER")
        item.addActionListener(_MenuListener(self, msgs[0]))
        menu.add(item)
        return menu

    def _set_url_from_request(self, message):
        try:
            req  = self._helpers.analyzeRequest(message)
            url  = str(req.getUrl())
            self._url_field.setText(url)
            self._log_line("Target set from proxy: " + url)
        except Exception as exc:
            self._log_line("Could not extract URL: " + str(exc))


# ── Action listeners (must be separate classes for Jython compat) ─────────────

class _ScanListener(ActionListener):
    def __init__(self, ext):
        self.ext = ext

    def actionPerformed(self, event):
        self.ext._scan_btn.setText("Scanning…")
        self.ext._scan_btn.setEnabled(False)
        self.ext._start_scan()


class _MenuListener(ActionListener):
    def __init__(self, ext, message):
        self.ext     = ext
        self.message = message

    def actionPerformed(self, event):
        self.ext._set_url_from_request(self.message)
