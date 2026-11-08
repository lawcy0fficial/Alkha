#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import io
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from lib.core import tui


def _captured(fn, *args, **kwargs):
    """
    tui.py writes through lib.core.common.dataToStdout, which ultimately
    writes to sys.stdout - capture it directly rather than mocking
    dataToStdout itself, so these tests exercise the real write path
    (including ANSI-code wrapping, if IS_TTY happens to be true in
    whatever environment runs the suite) rather than a stand-in for it.
    Styled substrings survive intact even when colored - _style() wraps
    a whole substring in codes rather than interleaving them character
    by character - so plain substring assertions hold either way.
    """
    buf = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = buf
    try:
        fn(*args, **kwargs)
    finally:
        sys.stdout = old_stdout
    return buf.getvalue()


class TestFormatElapsed(unittest.TestCase):
    def test_seconds_only(self):
        self.assertEqual(tui._format_elapsed(47), "00:47")

    def test_minutes_and_seconds(self):
        self.assertEqual(tui._format_elapsed(125), "02:05")

    def test_hours_included_once_past_an_hour(self):
        self.assertEqual(tui._format_elapsed(3725), "1:02:05")

    def test_none_and_zero_do_not_crash(self):
        self.assertEqual(tui._format_elapsed(None), "00:00")
        self.assertEqual(tui._format_elapsed(0), "00:00")


class TestIterationRule(unittest.TestCase):
    def test_shows_iteration_count_and_elapsed_time(self):
        out = _captured(tui.iteration_rule, 3, 40, 47)
        self.assertIn("3/40", out)
        self.assertIn("00:47", out)

    def test_does_not_crash_on_edge_iteration_numbers(self):
        _captured(tui.iteration_rule, 1, 40, 0)
        _captured(tui.iteration_rule, 40, 40, 3600)
        _captured(tui.iteration_rule, 999, 40, 0)  # over budget, shouldn't happen but shouldn't crash either


class TestStateLine(unittest.TestCase):
    def test_prints_flattened_single_line(self):
        out = _captured(tui.state_line, "DBMS: MySQL\nCurrent user: root")
        self.assertIn("DBMS: MySQL", out)
        self.assertIn("Current user: root", out)
        # flattened to one line with a separator, not the original newline
        self.assertNotIn("MySQL\nCurrent", out)

    def test_nothing_confirmed_yet_prints_nothing(self):
        out = _captured(tui.state_line, "(nothing confirmed yet)")
        self.assertEqual(out, "")

    def test_empty_string_prints_nothing(self):
        out = _captured(tui.state_line, "")
        self.assertEqual(out, "")

    def test_none_does_not_crash(self):
        out = _captured(tui.state_line, None)
        self.assertEqual(out, "")


class TestRenderFinalReport(unittest.TestCase):
    def _report(self, **findings_overrides):
        findings = {
            "dbms": None, "banner": None, "current_user": None, "current_db": None,
            "hostname": None, "is_dba": None, "injection_points": [], "databases": [],
            "tables": {}, "dumped_tables": [], "nosql_access": [],
            "os_command_results": [], "file_read_results": [], "notes": [],
        }
        findings.update(findings_overrides)
        return {"goal": "g", "target": "t", "duration_seconds": 12.3, "findings": findings}

    def test_full_successful_report_shows_all_sections(self):
        report = self._report(
            dbms="MySQL >= 5.0.12", current_user="root", is_dba=True,
            injection_points=[{"place": "GET", "parameter": "id"}],
            databases=["information_schema", "webapp"],
            tables={"webapp": ["users", "orders"]},
            dumped_tables=[{"users": []}],
        )
        out = _captured(tui.render_final_report, report)
        self.assertIn("MySQL >= 5.0.12", out)
        self.assertIn("root (DBA)", out)
        self.assertIn("GET=id", out)
        self.assertIn("information_schema", out)
        self.assertIn("webapp", out)
        self.assertIn("tables dumped", out)
        self.assertIn("00:12", out)

    def test_empty_findings_falls_back_gracefully(self):
        report = self._report()
        out = _captured(tui.render_final_report, report)
        # every field is None/empty - the only line that always renders
        # regardless is the injection-points headline, showing plainly
        # that nothing was confirmed rather than an empty/blank panel.
        self.assertIn("none confirmed", out)
        self.assertIn("00:12", out)

    def test_no_injection_points_shows_none_confirmed(self):
        report = self._report()
        out = _captured(tui.render_final_report, report)
        self.assertIn("none confirmed", out)

    def test_notes_rendered_as_distinct_caveats_block(self):
        report = self._report(
            injection_points=[{"place": "GET", "parameter": "id"}],
            notes=["GROUNDING CHECK: something looked off"],
        )
        out = _captured(tui.render_final_report, report)
        self.assertIn("notes / caveats", out)
        self.assertIn("GROUNDING CHECK: something looked off", out)

    def test_many_injection_points_are_truncated_with_a_count(self):
        points = [{"place": "GET", "parameter": "p%d" % i} for i in range(8)]
        report = self._report(injection_points=points)
        out = _captured(tui.render_final_report, report)
        self.assertIn("+3 more", out)

    def test_missing_findings_key_does_not_crash(self):
        report = {"goal": "g", "target": "t", "duration_seconds": 0}
        out = _captured(tui.render_final_report, report)
        self.assertIn("none confirmed", out)

    def test_open_nosql_access_is_shown_prominently(self):
        report = self._report(nosql_access=[
            {"host": "10.0.0.5", "port": 27017, "status": "open", "version": "5.0.9", "database_count": 3},
        ])
        out = _captured(tui.render_final_report, report)
        self.assertIn("10.0.0.5:27017", out)
        self.assertIn("OPEN", out)
        self.assertIn("5.0.9", out)

    def test_auth_required_nosql_access_is_shown_without_alarm_styling(self):
        report = self._report(nosql_access=[
            {"host": "10.0.0.6", "port": 27017, "status": "auth_required", "version": None, "database_count": None},
        ])
        out = _captured(tui.render_final_report, report)
        self.assertIn("10.0.0.6:27017", out)
        self.assertIn("auth_required", out)
        self.assertNotIn("OPEN", out)

    def test_multiple_nosql_access_entries_all_render(self):
        report = self._report(nosql_access=[
            {"host": "10.0.0.5", "port": 27017, "status": "open", "version": "5.0.9", "database_count": 3},
            {"host": "10.0.0.6", "port": 27017, "status": "auth_required", "version": None, "database_count": None},
        ])
        out = _captured(tui.render_final_report, report)
        self.assertIn("10.0.0.5:27017", out)
        self.assertIn("10.0.0.6:27017", out)

    def test_no_nosql_access_entries_shows_no_nosql_section(self):
        report = self._report()
        out = _captured(tui.render_final_report, report)
        self.assertNotIn("nosql access", out)

    def test_os_command_results_shown_prominently(self):
        report = self._report(os_command_results=["uid=0(root) gid=0(root)"])
        out = _captured(tui.render_final_report, report)
        self.assertIn("CONFIRMED", out)
        self.assertIn("1 command(s) run", out)
        self.assertIn("uid=0(root) gid=0(root)", out)

    def test_file_read_results_shown_prominently(self):
        report = self._report(file_read_results=["root:x:0:0:root:/root:/bin/bash"])
        out = _captured(tui.render_final_report, report)
        self.assertIn("CONFIRMED", out)
        self.assertIn("1 file(s) read", out)

    def test_no_os_command_results_shows_no_section(self):
        report = self._report()
        out = _captured(tui.render_final_report, report)
        self.assertNotIn("os command exec", out)


if __name__ == "__main__":
    unittest.main()
