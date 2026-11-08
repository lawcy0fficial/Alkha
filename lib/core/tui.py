#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

lib.core.tui
------------
Opt-in "modern" terminal rendering layer, styled after the minimal,
low-noise CLI aesthetic of agentic coding assistants: a plain header
instead of ASCII art, single-accent-color status lines with tree
connectors for sub-detail, and compact spinners instead of blocks of
progress text.

This module is 100% additive:
    - the classic banner() / dataToStdout() call sites in sqlmap.py and
      throughout lib/ are untouched;
    - everything here still funnels through lib.core.common.dataToStdout,
      so --disable-coloring, non-TTY output, and REST-API stdout
      redirection (StdDbOut) all keep working exactly as before;
    - it is only activated by the --modern-ui flag (checked the same
      lightweight way sqlmap.py already checks --deprecations, before
      full option parsing), so default behavior is 100% unchanged.
"""

import itertools
import re
import sys
import threading
import time

from lib.core.common import dataToStdout
from lib.core.settings import IS_TTY, VERSION_STRING, PROJECT_NAME

RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"
ACCENT = "\033[36m"     # cyan - single accent color, not a rainbow of levels
GOOD = "\033[32m"
WARN = "\033[33m"
BAD = "\033[31m"

ICON_STEP = "●"
ICON_DONE = "✓"
ICON_FAIL = "✗"
ICON_WARN = "!"
CONNECTOR = "⎿"


def _tty():
    return IS_TTY


def _style(text, code):
    if not _tty():
        return text
    return "%s%s%s" % (code, text, RESET)


STYLE_COLORS = {"accent": ACCENT, "good": GOOD, "warn": WARN, "bad": BAD, "dim": DIM, "bold": BOLD}


def style(text, kind="accent"):
    """Public one-off styling helper for external callers (e.g. alkha_agent.py's
    interactive confirm prompt) that need a styled string without a step()/panel()
    shape - keeps the color palette in one place instead of every caller
    re-declaring its own ANSI codes."""
    return _style(text, STYLE_COLORS.get(kind, ACCENT))


def render_banner():
    """
    Modern replacement for lib.core.common.banner(): a compact single
    header line instead of the ASCII-art BANNER block, still routed
    through dataToStdout so coloring-disable / non-tty stripping applies.

    Branded as Alkha - this build's own name for the combination of the
    unmodified sqlmap engine (still cited by its real version string, an
    attribution requirement of sqlmap's GPLv2 license, not just courtesy)
    plus the agentic/modern-UI layers documented in doc/NEXTGEN.md.
    """
    title = _style(PROJECT_NAME, BOLD + ACCENT)
    engine = _style(VERSION_STRING, DIM)
    dataToStdout("%s  ·  %s\n\n" % (title, engine), forceOutput=True)


def render_welcome_panel(model=None, ollama_host=None, target=None, goal=None, workdir=None):
    """
    A fuller startup panel for alkha_agent.py - title, engine
    attribution, run context (model/target/goal), and a couple of quick
    tips - in the same boxed-panel language as panel()/step() elsewhere
    in this module, not a copy of any other product's specific colors,
    glyphs, or mascot. Only ever shown from alkha_agent.py, never from
    sqlmap.py's own --modern-ui path (which keeps the compact single-line
    render_banner() above).
    """
    width = 61
    top = "╭" + "─" * (width - 2) + "╮"
    bottom = "╰" + "─" * (width - 2) + "╯"

    def _row(text=""):
        # pad to width accounting for ANSI codes not counting toward
        # visible width; strip codes for length math only
        visible_len = len(re.sub(r"\033\[[0-9;]*m", "", text))
        pad = max(0, (width - 4) - visible_len)
        dataToStdout("%s %s%s %s\n" % (_style("│", DIM), text, " " * pad, _style("│", DIM)), forceOutput=True)

    def _clip(s, budget):
        return s if len(s) <= budget else s[:budget - 1] + "…"

    dataToStdout(_style(top, DIM) + "\n", forceOutput=True)
    _row(_style("Alkha", BOLD + ACCENT) + _style(" - autonomous SQL & NoSQL injection agent", DIM))
    _row()
    _row(_style("engine", DIM) + "  %s" % VERSION_STRING)
    if model:
        model_line = "%s%s" % (model, " via %s" % ollama_host if ollama_host else "")
        _row(_style("model ", DIM) + "  %s" % _clip(model_line, width - 14))
    if target:
        _row(_style("target", DIM) + "  %s" % _clip(target, width - 14))
    if workdir:
        _row(_style("workdir", DIM) + " %s" % _clip(workdir, width - 14))
    if goal:
        _row()
        _row(_style("goal", DIM) + "    %s" % _clip(goal, width - 14))
    dataToStdout(_style(bottom, DIM) + "\n\n", forceOutput=True)


def render_startup_lines(legal_disclaimer, start_time_str):
    dataToStdout(_style("!", WARN) + " %s\n" % legal_disclaimer, forceOutput=True)
    dataToStdout(_style(CONNECTOR, DIM) + _style(" starting %s\n\n", DIM) % start_time_str, forceOutput=True)


def step(text, status="running"):
    """
    A single status line, e.g.:
        ● testing connection to the target URL
        ✓ target is reachable
        ✗ target refused connection
    status: "running" | "done" | "fail" | "warn"
    """
    icon, color = {
        "running": (ICON_STEP, ACCENT),
        "done": (ICON_DONE, GOOD),
        "fail": (ICON_FAIL, BAD),
        "warn": (ICON_WARN, WARN),
    }.get(status, (ICON_STEP, ACCENT))

    dataToStdout("%s %s\n" % (_style(icon, color), text), forceOutput=True)


def substep(text):
    """An indented tree-connector line under the most recent step()."""
    dataToStdout("  %s %s\n" % (_style(CONNECTOR, DIM), _style(text, DIM)), forceOutput=True)


def kv_table(pairs, indent=2):
    """Compact aligned key: value block, e.g. for scan summary output."""
    if not pairs:
        return

    width = max(len(k) for k, _ in pairs)
    pad = " " * indent

    for k, v in pairs:
        dataToStdout("%s%s%s  %s\n" % (
            pad, _style(k.ljust(width), DIM), _style(":", DIM), v
        ), forceOutput=True)


def iteration_rule(n, max_n, elapsed_seconds):
    """
    A subtle divider marking the start of a new plan->act->observe loop
    turn, e.g.:
        ── iteration 3/40 · 00:47 elapsed ──────────────────────────
    Deliberately dim/low-contrast (this is a rhythm marker for scanning
    the log after the fact, not something that should compete with the
    step()/substep() lines it separates) and clipped to a fixed width so
    it never wraps oddly regardless of iteration count width.
    """
    label = " iteration %d/%d · %s elapsed " % (n, max_n, _format_elapsed(elapsed_seconds))
    width = 61
    fill = max(0, width - len(label) - 2)
    line = "──%s%s" % (label, "─" * fill)
    dataToStdout(_style(line, DIM) + "\n", forceOutput=True)


def _format_elapsed(seconds):
    seconds = int(seconds or 0)
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    return "%d:%02d:%02d" % (h, m, s) if h else "%02d:%02d" % (m, s)


def state_line(facts_summary):
    """
    A compact single-line "what we know so far" recap, printed only when
    the structured findings actually changed this turn (see
    AgentPlanner.step()'s facts_before/facts_after diff) - not on every
    turn, which would just be noise repeating what the last observation
    already showed. Multi-line facts_summary() output is flattened with
    ' · ' separators to keep this to one line; the full multi-line form
    is still what goes into the system prompt for the model itself.
    """
    if not facts_summary or facts_summary == "(nothing confirmed yet)":
        return
    flat = " · ".join(line.strip() for line in facts_summary.splitlines() if line.strip())
    dataToStdout("  %s %s\n" % (_style("state", DIM), _style(flat, DIM)), forceOutput=True)


def render_final_report(report):
    """
    Richer replacement for a bare notes-only panel: pulls the structured
    findings dict (AgentMemory.to_report_dict()) apart into a scannable
    summary - DBMS/banner/user/injection points up top (the "did we find
    something" headline), then databases/tables/dumped-table counts, then
    any notes/grounding-check caveats last (as a distinct, clearly-labeled
    block so a caveat is never mistaken for a confirmed finding). Falls
    back gracefully for an in-progress or evidence-free run - every field
    is optional, this never assumes a complete/successful scan shape.
    """
    findings = report.get("findings") or {}
    out = []

    def kv(label, value):
        out.append("%s %s" % (_style((label + ":").ljust(18), DIM), value))

    if findings.get("dbms"):
        kv("dbms", findings["dbms"])
    if findings.get("banner"):
        kv("banner", _clip_line(findings["banner"], 70))
    if findings.get("current_user"):
        dba_suffix = " (DBA)" if findings.get("is_dba") else ""
        kv("user", "%s%s" % (findings["current_user"], dba_suffix))
    if findings.get("current_db"):
        kv("current db", findings["current_db"])
    if findings.get("hostname"):
        kv("hostname", findings["hostname"])

    os_command_results = findings.get("os_command_results") or []
    if os_command_results:
        # the single most significant finding this codebase can produce -
        # styled BAD (red) same as an "open" nosql_access entry, and for
        # the same reason: a confirmed positive finding, not a caveat.
        kv("os command exec", _style("CONFIRMED - %d command(s) run" % len(os_command_results), BAD))
        kv("  most recent output", _clip_line(os_command_results[-1], 70))

    file_read_results = findings.get("file_read_results") or []
    if file_read_results:
        kv("file read", _style("CONFIRMED - %d file(s) read from DBMS host" % len(file_read_results), BAD))

    injection_points = findings.get("injection_points") or []
    if injection_points:
        kv("injection points", str(len(injection_points)))
        for point in injection_points[:5]:
            out.append("  %s %s=%s" % (_style(CONNECTOR, DIM),
                                        point.get("place", "?"), point.get("parameter", "?")))
        if len(injection_points) > 5:
            out.append("  %s (+%d more)" % (_style(CONNECTOR, DIM), len(injection_points) - 5))
    else:
        kv("injection points", _style("none confirmed", WARN))

    nosql_access = findings.get("nosql_access") or []
    if nosql_access:
        out.append("")
        for access in nosql_access:
            label = "%s:%s" % (access.get("host"), access.get("port"))
            backend_label = {"mongodb": "MongoDB", "redis": "Redis", "elasticsearch": "Elasticsearch",
                              "couchdb": "CouchDB"}.get(access.get("backend"), access.get("backend") or "NoSQL")
            if access.get("status") == "open":
                # the single most serious finding a NoSQL engagement can
                # produce - styled BAD (red), deliberately distinct from
                # notes/caveats' WARN (yellow): this is a confirmed
                # positive finding, not a caveat about the run itself,
                # and from the other end, deliberately NOT folded into
                # findings["notes"] for exactly that reason (see
                # AgentMemory.record_action's nosql_scan_target handling).
                db_count_suffix = (", %s db(s)" % access.get("database_count")
                                    if access.get("database_count") is not None else "")
                kv("nosql access", _style("%s - OPEN, no authentication required (%s %s%s)" % (
                    label, backend_label, access.get("version") or "unknown version", db_count_suffix), BAD))
            else:
                kv("nosql access", "%s (%s) - %s" % (label, backend_label, access.get("status")))

    databases = findings.get("databases") or []
    tables = findings.get("tables") or {}
    dumped = findings.get("dumped_tables") or []
    if databases or tables or dumped:
        out.append("")
        if databases:
            kv("databases", ", ".join(databases[:10]) + (" …" if len(databases) > 10 else ""))
        if tables:
            table_count = sum(len(v or []) for v in tables.values())
            kv("tables", "%d across %d database(s)" % (table_count, len(tables)))
        if dumped:
            kv("tables dumped", str(len(dumped)))

    notes = findings.get("notes") or []
    if notes:
        out.append("")
        out.append(_style("notes / caveats:", WARN))
        for note in notes:
            out.append("  %s %s" % (_style(CONNECTOR, DIM), note))

    if not out:
        # unreachable in practice (the injection-points kv above always adds
        # at least one line, even when it's just "none confirmed") - kept as
        # a defensive fallback in case that invariant ever changes, not as
        # a path this function's tests should expect to hit.
        out = ["(no findings recorded - see JSON report for the raw transcript)"]

    out.append("")
    out.append(_style("duration: %s" % _format_elapsed(report.get("duration_seconds")), DIM))

    panel("final report", out)


def _clip_line(s, budget):
    s = str(s)
    return s if len(s) <= budget else s[:budget - 1] + "…"


def panel(title, lines):
    """A lightweight boxed panel for a final summary/report."""
    top = "╭─ %s " % title
    top += "─" * max(0, 59 - len(top)) + "╮"
    bottom = "╰" + "─" * (len(top) - 2) + "╯"

    dataToStdout(_style(top, DIM) + "\n", forceOutput=True)
    for line in lines:
        dataToStdout("%s\n" % line, forceOutput=True)
    dataToStdout(_style(bottom, DIM) + "\n", forceOutput=True)


class ModernProgressBar(object):
    """
    Modern-styled sibling of lib.utils.progress.ProgressBar with the
    identical constructor signature and public interface (progress(),
    draw(), __str__), used as a drop-in replacement via
    lib.utils.progress.get_progress_bar() when --modern-ui is active.

    The percent/ETA math below is a deliberate line-for-line match of
    the classic implementation (lib/utils/progress.py) - copied, not
    reimplemented from scratch, specifically to avoid introducing a new
    numeric bug in code that runs live during actual data extraction
    (blind inference, UNION-based and error-based dumping). Only the
    rendered string differs: a block-fill bar in the single accent color
    instead of the classic ASCII "[====>   ]" bracket style.
    """

    def __init__(self, minValue=0, maxValue=10, totalWidth=None):
        from lib.core.data import conf as _conf

        self._min = int(minValue)
        self._max = int(maxValue)
        self._span = max(self._max - self._min, 0.001)
        self._width = totalWidth if totalWidth else _conf.progressWidth
        self._amount = 0
        self._start = None
        self._percent = 0
        self.update()

    @staticmethod
    def _convertSeconds(value):
        seconds = value
        minutes = seconds // 60
        seconds = seconds - (minutes * 60)
        return "%.2d:%.2d" % (minutes, seconds)

    def update(self, newAmount=0):
        if newAmount < self._min:
            newAmount = self._min
        elif newAmount > self._max:
            newAmount = self._max

        self._amount = newAmount

        diffFromMin = float(self._amount - self._min)
        percentDone = (diffFromMin / float(self._span)) * 100.0
        percentDone = round(percentDone)
        self._percent = min(100, int(percentDone))

        barWidth = max(10, self._width - 40)
        filled = int(round((self._percent / 100.0) * barWidth))
        self._bar = "█" * filled + "░" * (barWidth - filled)

    def progress(self, newAmount):
        if self._start is None or newAmount > self._max:
            self._start = time.time()
            eta = None
        else:
            delta = time.time() - self._start
            eta = (self._max - self._min) * (1.0 * delta / newAmount) - delta

        self.update(newAmount)
        self.draw(eta)

    def draw(self, eta=None):
        eta_str = self._convertSeconds(int(eta)) if eta is not None else "??:??"
        line = "\r%s %s%% %s %d/%d  %s" % (
            _style(ICON_STEP, ACCENT),
            self._percent,
            _style(self._bar, ACCENT),
            self._amount, self._max,
            _style("ETA %s" % eta_str, DIM),
        )
        dataToStdout(line, forceOutput=True)

        if self._amount >= self._max:
            dataToStdout("\r%s\r" % (" " * self._width), forceOutput=True)
            from lib.core.data import kb as _kb
            _kb.prependFlag = False

    def __str__(self):
        return self._bar


class Spinner(object):
    """
    Minimal in-place spinner for long-running blocking calls (e.g.
    waiting on a request). Only animates on a real TTY - on non-tty
    output (piped/logged) it stays silent to avoid spamming logs,
    matching how dataToStdout already treats \\r-prefixed data.
    """

    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, text):
        self.text = text
        self._stop_event = threading.Event()
        self._thread = None

    def _spin(self):
        for frame in itertools.cycle(self.FRAMES):
            if self._stop_event.is_set():
                break
            dataToStdout("\r%s %s" % (_style(frame, ACCENT), self.text), forceOutput=True, coloring=False)
            time.sleep(0.08)

    def __enter__(self):
        if _tty():
            self._thread = threading.Thread(target=self._spin)
            self._thread.daemon = True
            self._thread.start()
        else:
            dataToStdout("%s...\n" % self.text, forceOutput=True)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._thread:
            self._stop_event.set()
            self._thread.join(timeout=1)
            dataToStdout("\r%s\r" % (" " * (len(self.text) + 4)), forceOutput=True, coloring=False)


# ---------------------------------------------------------------------------
# Logging handler: every logger.info()/warning()/critical() call across the
# ENTIRE codebase (checks.py, controller.py, all DBMS plugins, ...) goes
# through lib.core.log.LOGGER_HANDLER. Rather than editing dozens of
# individual call sites (high regression risk, hard to fully verify without
# live network access to run a real scan), we swap in an alternate handler
# at this one chokepoint. This class is intentionally self-contained
# (no import of lib.core.common) so it stays free of the
# common -> data -> log import chain and can be constructed at any point
# after logging is set up - see swap_log_handler() below, invoked from
# sqlmap.py's main() only when --modern-ui is passed. The classic
# LOGGER_HANDLER in lib/core/log.py is completely untouched otherwise.
# ---------------------------------------------------------------------------

import logging

_LEVEL_STYLE = {
    "DEBUG": ("·", DIM),
    "INFO": (ICON_STEP, ACCENT),
    "WARNING": (ICON_WARN, WARN),
    "ERROR": (ICON_FAIL, BAD),
    "CRITICAL": (ICON_FAIL, BAD),
    "PAYLOAD": ("→", DIM),
    "TRAFFIC OUT": ("↑", DIM),
    "TRAFFIC IN": ("↓", DIM),
}


class ModernLogHandler(logging.StreamHandler):
    """
    Renders each log record as "<dim time> <accent icon> message" instead
    of the classic "\\r[HH:MM:SS] [LEVEL] message" + regex-based ANSI
    post-processing (thirdparty/ansistrm). One color per level, no
    per-substring quote highlighting - consistent with the rest of the
    modern-ui minimal aesthetic.
    """

    def __init__(self, stream=None):
        logging.StreamHandler.__init__(self, stream or sys.stdout)

    def format(self, record):
        icon, color = _LEVEL_STYLE.get(record.levelname, (ICON_STEP, ACCENT))
        ts = time.strftime("%H:%M:%S", time.localtime(record.created))
        message = record.getMessage()
        return "\r%s %s %s" % (_style(ts, DIM), _style(icon, color), message)


def swap_log_handler():
    """
    Replaces lib.core.log's classic handler with ModernLogHandler on the
    same logger instance, preserving level filtering. Safe to call more
    than once. Only ever invoked when --modern-ui was passed.
    """
    from lib.core.log import LOGGER, LOGGER_HANDLER

    LOGGER.removeHandler(LOGGER_HANDLER)

    if not any(isinstance(h, ModernLogHandler) for h in LOGGER.handlers):
        LOGGER.addHandler(ModernLogHandler())
