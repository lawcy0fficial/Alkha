#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from lib.ai.tools import ToolExecutor, tool_names, TOOL_SPECS


class FakeEngine(object):
    def __init__(self):
        self.start_scan_calls = []
        self.fake_log_messages = []

    def start_scan(self, taskid, opts):
        self.start_scan_calls.append(dict(opts))
        return {"success": True, "opts_sent": opts}

    def stop_scan(self, taskid):
        return {"success": True}

    def scan_status(self, taskid):
        return {"status": "terminated"}

    def scan_data(self, taskid):
        return {"success": True, "data": []}

    def scan_log(self, taskid, start=None, end=None):
        return {"success": True, "log": [{"time": "12:00:00", "level": "CRITICAL", "message": m}
                                          for m in self.fake_log_messages]}


class TestToolExecutor(unittest.TestCase):
    def setUp(self):
        self.engine = FakeEngine()
        self.ex = ToolExecutor(self.engine, "t1")

    def test_set_target_then_configure_then_start_merges_options(self):
        self.ex.execute("set_target", {"url": "http://x/a.php?id=1"})
        self.ex.execute("configure_scan", {"options": {"level": 3, "risk": 2}})
        result = self.ex.execute("start_scan", {})
        self.assertTrue(result["ok"])
        sent = self.engine.start_scan_calls[-1]
        self.assertEqual(sent["url"], "http://x/a.php?id=1")
        self.assertEqual(sent["level"], 3)
        self.assertEqual(sent["risk"], 2)

    def test_configure_scan_drops_invalid_option_with_suggestion(self):
        result = self.ex.execute("configure_scan", {"options": {"level": 3, "riskLevel": 5}})
        self.assertNotIn("riskLevel", result["options"])
        self.assertEqual(result["options"]["level"], 3)
        self.assertIn("warnings", result)
        self.assertIn("risk", result["warnings"][0])

    def test_list_databases_sets_getDbs_and_clears_it_after(self):
        self.ex.execute("list_databases", {})
        sent = self.engine.start_scan_calls[-1]
        self.assertTrue(sent["getDbs"])
        # should not leak into subsequent unrelated calls
        self.assertNotIn("getDbs", self.ex.current_options())

    def test_list_tables_with_and_without_db_filter(self):
        self.ex.execute("list_tables", {"db": "testdb"})
        sent = self.engine.start_scan_calls[-1]
        self.assertTrue(sent["getTables"])
        self.assertEqual(sent["db"], "testdb")

    def test_list_columns_requires_db_and_table(self):
        result = self.ex.execute("list_columns", {"db": "testdb"})
        self.assertFalse(result["ok"])
        self.assertIn("requires both", result["error"])

        result = self.ex.execute("list_columns", {"db": "testdb", "table": "users"})
        self.assertTrue(result["ok"])
        sent = self.engine.start_scan_calls[-1]
        self.assertEqual(sent["tbl"], "users")

    def test_dump_table_requires_db_and_table(self):
        result = self.ex.execute("dump_table", {"table": "users"})
        self.assertFalse(result["ok"])

        result = self.ex.execute("dump_table", {"db": "testdb", "table": "users"})
        self.assertTrue(result["ok"])
        sent = self.engine.start_scan_calls[-1]
        self.assertTrue(sent["dumpTable"])

    def test_dump_table_with_columns_where_and_range(self):
        result = self.ex.execute("dump_table", {
            "db": "testdb", "table": "users",
            "columns": "username,password", "where": "id=1",
            "start_row": 1, "stop_row": 5,
        })
        self.assertTrue(result["ok"])
        sent = self.engine.start_scan_calls[-1]
        self.assertEqual(sent["col"], "username,password")
        self.assertEqual(sent["dumpWhere"], "id=1")
        self.assertEqual(sent["limitStart"], 1)
        self.assertEqual(sent["limitStop"], 5)

    def test_dump_table_without_optional_args_omits_them(self):
        result = self.ex.execute("dump_table", {"db": "testdb", "table": "users"})
        sent = self.engine.start_scan_calls[-1]
        for key in ("col", "dumpWhere", "limitStart", "limitStop"):
            self.assertNotIn(key, sent)

    def test_os_cmd_requires_command_string(self):
        result = self.ex.execute("os_cmd", {})
        self.assertFalse(result["ok"])

        for bad_command in (42, ["whoami"], {"a": 1}, True, ""):
            result = self.ex.execute("os_cmd", {"command": bad_command})
            self.assertFalse(result["ok"], "command=%r should be rejected" % (bad_command,))

    def test_os_cmd_sets_the_real_sqlmap_option_and_starts_a_scan(self):
        result = self.ex.execute("os_cmd", {"command": "whoami"})
        self.assertTrue(result["ok"])
        sent = self.engine.start_scan_calls[-1]
        self.assertEqual(sent["osCmd"], "whoami")

    def test_file_read_requires_path_string(self):
        result = self.ex.execute("file_read", {})
        self.assertFalse(result["ok"])

        for bad_path in (42, ["/etc/passwd"], {"a": 1}, True, ""):
            result = self.ex.execute("file_read", {"path": bad_path})
            self.assertFalse(result["ok"], "path=%r should be rejected" % (bad_path,))

    def test_file_read_sets_the_real_sqlmap_option_and_starts_a_scan(self):
        result = self.ex.execute("file_read", {"path": "/etc/passwd"})
        self.assertTrue(result["ok"])
        sent = self.engine.start_scan_calls[-1]
        self.assertEqual(sent["fileRead"], "/etc/passwd")

    def test_search_data_requires_query(self):
        result = self.ex.execute("search_data", {})
        self.assertFalse(result["ok"])

    def test_search_data_default_searches_tables(self):
        result = self.ex.execute("search_data", {"query": "pass"})
        self.assertTrue(result["ok"])
        sent = self.engine.start_scan_calls[-1]
        self.assertTrue(sent["search"])
        self.assertEqual(sent["tbl"], "pass")
        self.assertNotIn("col", sent)

    def test_search_data_in_columns_mode(self):
        result = self.ex.execute("search_data", {"query": "email", "in_columns": True})
        sent = self.engine.start_scan_calls[-1]
        self.assertEqual(sent["col"], "email")
        self.assertNotIn("tbl", sent)

    def test_set_target_with_headers(self):
        result = self.ex.execute("set_target", {"url": "http://x/a.php?id=1", "headers": "X-Custom: *"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["options"]["headers"], "X-Custom: *")

    def test_set_target_without_headers_omits_key(self):
        result = self.ex.execute("set_target", {"url": "http://x/a.php?id=1"})
        self.assertNotIn("headers", result["options"])

    def test_list_tamper_scripts_returns_nonempty_catalog(self):
        result = self.ex.execute("list_tamper_scripts", {"query": "mysql"})
        self.assertTrue(result["ok"])
        self.assertIn("mysql", result["catalog"].lower())

    def test_recommend_tamper_for_dbms_requires_dbms_arg(self):
        result = self.ex.execute("recommend_tamper_for_dbms", {})
        self.assertFalse(result["ok"])

    def test_recommend_tamper_for_dbms_returns_targeted_suggestion(self):
        result = self.ex.execute("recommend_tamper_for_dbms", {"dbms": "MySQL"})
        self.assertTrue(result["ok"])
        self.assertIn("space2mysqlblank", result["dbms_specific"])
        self.assertIn("space2mysqlblank", result["suggestion"])

    def test_crawl_target_sets_crawl_depth(self):
        self.ex.execute("set_target", {"url": "http://x/"})
        result = self.ex.execute("crawl_target", {"depth": 3})
        self.assertTrue(result["ok"])
        sent = self.engine.start_scan_calls[-1]
        self.assertEqual(sent["crawlDepth"], 3)
        self.assertEqual(sent["url"], "http://x/")

    def test_crawl_target_defaults_depth_to_two(self):
        result = self.ex.execute("crawl_target", {})
        sent = self.engine.start_scan_calls[-1]
        self.assertEqual(sent["crawlDepth"], 2)

    def test_crawl_target_with_forms(self):
        result = self.ex.execute("crawl_target", {"forms": True})
        sent = self.engine.start_scan_calls[-1]
        self.assertTrue(sent["forms"])

    def test_crawl_target_without_forms_key_absent(self):
        result = self.ex.execute("crawl_target", {})
        sent = self.engine.start_scan_calls[-1]
        self.assertNotIn("forms", sent)

    def test_finish_returns_summary(self):
        result = self.ex.execute("finish", {"summary": "done"})
        self.assertTrue(result["finished"])
        self.assertEqual(result["summary"], "done")

    def test_unknown_tool_returns_error_not_exception(self):
        result = self.ex.execute("not_a_real_tool", {})
        self.assertFalse(result["ok"])

    def test_check_waf_status_detects_real_log_phrase(self):
        self.engine.fake_log_messages = [
            "testing connection to the target URL",
            "checking if the target is protected by some kind of WAF/IPS",
            "heuristics detected that the target is protected by some kind of WAF/IPS",
        ]
        result = self.ex.execute("check_waf_status", {})
        self.assertTrue(result["ok"])
        self.assertTrue(result["waf_detected"])
        self.assertTrue(result["checked"])

    def test_check_waf_status_clean_when_checked_but_not_detected(self):
        self.engine.fake_log_messages = [
            "checking if the target is protected by some kind of WAF/IPS",
            "testing if GET parameter 'id' is dynamic",
        ]
        result = self.ex.execute("check_waf_status", {})
        self.assertTrue(result["checked"])
        self.assertFalse(result["waf_detected"])

    def test_check_waf_status_unknown_when_not_yet_checked(self):
        self.engine.fake_log_messages = []
        result = self.ex.execute("check_waf_status", {})
        self.assertFalse(result["checked"])
        self.assertFalse(result["waf_detected"])

    def test_diagnose_detection_failure_page_instability(self):
        self.engine.fake_log_messages = [
            "target URL content is not stable (i.e. content differs). sqlmap will base the page comparison on a sequence matcher",
        ]
        result = self.ex.execute("diagnose_detection_failure", {})
        self.assertTrue(result["ok"])
        self.assertTrue(any("unstable" in s for s in result["signals"]))
        self.assertTrue(any("string" in s for s in result["suggestions"]))

    def test_diagnose_detection_failure_waf_detected(self):
        self.engine.fake_log_messages = [
            "heuristics detected that the target is protected by some kind of WAF/IPS",
        ]
        result = self.ex.execute("diagnose_detection_failure", {})
        self.assertTrue(any("WAF" in s for s in result["signals"]))
        self.assertTrue(any("escalate_attack" in s for s in result["suggestions"]))

    def test_diagnose_detection_failure_negative_heuristic_only(self):
        self.engine.fake_log_messages = [
            "heuristic (basic) test shows that GET parameter 'id' might not be injectable",
        ]
        result = self.ex.execute("diagnose_detection_failure", {})
        self.assertTrue(any("heuristic" in s for s in result["signals"]))

    def test_diagnose_detection_failure_positive_heuristic_not_flagged_as_negative(self):
        self.engine.fake_log_messages = [
            "heuristic (basic) test shows that GET parameter 'id' might be injectable",
        ]
        result = self.ex.execute("diagnose_detection_failure", {})
        # a positive heuristic message contains the substring "might be
        # injectable" but must NOT trigger the "probably not injectable"
        # signal - regression guard for the same substring-overlap class
        # of bug as check_waf_status's fix.
        self.assertFalse(any("heuristic" in s and "not injectable" in s for s in result["signals"]))

    def test_diagnose_detection_failure_no_signals_falls_back_cleanly(self):
        self.engine.fake_log_messages = ["testing connection to the target URL"]
        result = self.ex.execute("diagnose_detection_failure", {})
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["signals"]), 1)
        self.assertEqual(len(result["suggestions"]), 1)

    def test_escalate_attack_advances_through_rungs_with_real_options(self):
        self.ex.execute("set_target", {"url": "http://x/a.php?id=1"})

        r1 = self.ex.execute("escalate_attack", {})
        self.assertEqual(r1["rung"], "baseline")
        sent1 = self.engine.start_scan_calls[-1]
        self.assertEqual(sent1["level"], 1)

        r2 = self.ex.execute("escalate_attack", {})
        self.assertNotEqual(r2["rung"], r1["rung"])
        sent2 = self.engine.start_scan_calls[-1]
        self.assertEqual(sent2["level"], 3)
        # url from set_target should persist across escalation calls
        self.assertEqual(sent2["url"], "http://x/a.php?id=1")

    def test_escalate_attack_eventually_exhausts(self):
        for _ in range(3):
            self.ex.execute("escalate_attack", {})
        while True:
            result = self.ex.execute("escalate_attack", {})
            if result.get("exhausted"):
                break
        final = self.ex.execute("escalate_attack", {})
        self.assertTrue(final["exhausted"])

    def test_repeat_identical_start_scan_configuration_warns(self):
        self.ex.execute("configure_scan", {"options": {"level": 1, "risk": 1}})
        r1 = self.ex.execute("start_scan", {})
        self.assertNotIn("warning", r1)

        r2 = self.ex.execute("start_scan", {})
        self.assertIn("warning", r2)
        self.assertIn("already tried", r2["warning"])

    def test_changed_configuration_does_not_warn(self):
        self.ex.execute("configure_scan", {"options": {"level": 1, "risk": 1}})
        self.ex.execute("start_scan", {})
        self.ex.execute("configure_scan", {"options": {"level": 3}})
        r3 = self.ex.execute("start_scan", {})
        self.assertNotIn("warning", r3)

    def test_every_tool_spec_name_is_handled(self):
        # catches drift between TOOL_SPECS (what the model is told exists)
        # and ToolExecutor.execute (what actually runs) - a name present
        # in one but not the other is a real bug the model would hit live.
        handled_but_needs_args = {
            "list_columns": {"db": "d", "table": "t"},
            "dump_table": {"db": "d", "table": "t"},
            "search_data": {"query": "pass"},
        }
        for spec in TOOL_SPECS:
            name = spec["name"]
            args = handled_but_needs_args.get(name, {})
            result = self.ex.execute(name, args)
            self.assertIsInstance(result, dict, "%s did not return a dict" % name)
            self.assertIn("ok", result, "%s response missing 'ok' key" % name)


class TestMalformedArgsRobustness(unittest.TestCase):
    """
    `args` is untrusted model output (parsed from the planning model's
    JSON/tool-call reply) - a malformed or hallucinated reply can hand
    execute() a list, string, number, or None instead of a dict, or a
    dict whose values are the wrong type. Every tool must return a
    normal {"ok": False, ...} response for this, never raise - an
    uncaught exception here crashes the entire autonomous run (see
    planner.step(), which does not wrap this call in try/except).

    Found via targeted fuzzing across every TOOL_SPECS name with a
    battery of malformed shapes (~500 tool/shape combinations, 0
    crashes after the fix - previously 111 crashes across 5 distinct
    root causes before lib/ai/tools.py, lib/ai/option_validator.py,
    and lib/ai/tamper_catalog.py were hardened).
    """

    MALFORMED_ARGS_SHAPES = [
        None, [], {}, "just a string", 12345, 3.14, True,
        ["a", "b", "c"], [{"url": "http://x"}],
        {"url": None}, {"url": 12345}, {"url": []}, {"url": {}},
        {"host": 12345}, {"target": 3.14}, {"host": []},
        {"port": "not a number"}, {"port": []}, {"port": {"$ne": 1}},
        {"depth": "two"}, {"depth": []}, {"depth": {}},
        {"start_row": "abc"}, {"stop_row": []},
        {"options": "not a dict"}, {"options": None}, {"options": [1, 2, 3]},
        {"options": {"level": "not a number", "risk": None, "tamper": 12345}},
        {"query": 3.14}, {"query": []}, {"query": {"nested": True}},
        {"dbms": 42}, {"dbms": []}, {"dbms": {"a": 1}},
    ]

    def setUp(self):
        self.engine = FakeEngine()

    def test_no_tool_ever_raises_on_any_malformed_shape(self):
        crashes = []
        for spec in TOOL_SPECS:
            name = spec["name"]
            for args in self.MALFORMED_ARGS_SHAPES:
                ex = ToolExecutor(self.engine, "t1")
                try:
                    result = ex.execute(name, args)
                except Exception as e:
                    crashes.append((name, args, type(e).__name__, str(e)))
                    continue
                if not (isinstance(result, dict) and "ok" in result):
                    crashes.append((name, args, "BadReturnShape", repr(result)[:80]))

        if crashes:
            self.fail("%d tool/malformed-args combinations crashed or returned a malformed "
                      "response instead of {\"ok\": False, ...}:\n" % len(crashes) +
                      "\n".join("  %s(%r) -> %s: %s" % c for c in crashes[:20]))

    def test_non_dict_args_returns_controlled_error_not_none_default(self):
        # a non-dict `args` must be REJECTED with a clear error, not silently
        # treated as {} (which would hide the malformed-reply signal from the
        # planner instead of surfacing it as an observation the model can see
        # and self-correct from).
        ex = ToolExecutor(self.engine, "t1")
        result = ex.execute("set_target", "not a dict")
        self.assertFalse(result["ok"])
        self.assertIn("error", result)

    def test_none_args_still_treated_as_empty_dict(self):
        # None is the normal "no args" case (e.g. finish/check_status called
        # with nothing) - unlike other non-dict shapes, this must NOT be
        # rejected.
        ex = ToolExecutor(self.engine, "t1")
        result = ex.execute("check_status", None)
        self.assertTrue(result["ok"])


if __name__ == "__main__":
    unittest.main()
