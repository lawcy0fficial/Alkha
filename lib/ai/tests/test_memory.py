#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from lib.ai.memory import AgentMemory
from lib.core.enums import CONTENT_TYPE


class TestFindingsExtraction(unittest.TestCase):
    """
    Regression tests for the CONTENT_TYPE-grounded parser. An earlier
    version of this parser used a guessed heuristic (type == 0 for
    injection points, string-matching "dbms" in a stringified int for
    DBMS) that only accidentally half-worked. These tests pin the
    correct behavior against the real shapes each content type is
    dumped with (lib/core/dump.py).
    """

    def _mem(self):
        return AgentMemory(goal="test", target="http://example.com")

    def test_techniques_yields_injection_points_and_dbms(self):
        mem = self._mem()
        mem.record_action("get_findings", {}, {"ok": True, "data": {"data": [
            {"type": CONTENT_TYPE.TECHNIQUES, "value": [{"place": "GET", "parameter": "id", "dbms": "MySQL"}]},
        ]}})
        self.assertEqual(mem.findings["injection_points"], [{"place": "GET", "parameter": "id"}])
        self.assertEqual(mem.findings["dbms"], "MySQL")

    def test_dbms_fingerprint_and_banner(self):
        mem = self._mem()
        mem.record_action("get_findings", {}, {"ok": True, "data": {"data": [
            {"type": CONTENT_TYPE.DBMS_FINGERPRINT, "value": "MySQL 5.7"},
            {"type": CONTENT_TYPE.BANNER, "value": "5.7.31-community"},
        ]}})
        self.assertEqual(mem.findings["dbms"], "MySQL 5.7")
        self.assertEqual(mem.findings["banner"], "5.7.31-community")

    def test_dbs_tables_dedupe_and_accumulate(self):
        mem = self._mem()
        mem.record_action("get_findings", {}, {"ok": True, "data": {"data": [
            {"type": CONTENT_TYPE.DBS, "value": ["testdb", "testdb", "otherdb"]},
            {"type": CONTENT_TYPE.TABLES, "value": {"testdb": ["users"]}},
        ]}})
        self.assertEqual(sorted(mem.findings["databases"]), ["otherdb", "testdb"])
        self.assertEqual(mem.findings["tables"], {"testdb": ["users"]})

        # a second, later call should accumulate, not overwrite
        mem.record_action("get_findings", {}, {"ok": True, "data": {"data": [
            {"type": CONTENT_TYPE.TABLES, "value": {"testdb": ["orders"]}},
        ]}})
        self.assertEqual(sorted(mem.findings["tables"]["testdb"]), ["orders", "users"])

    def test_is_dba_and_current_user(self):
        mem = self._mem()
        mem.record_action("get_findings", {}, {"ok": True, "data": {"data": [
            {"type": CONTENT_TYPE.CURRENT_USER, "value": "root@localhost"},
            {"type": CONTENT_TYPE.IS_DBA, "value": True},
        ]}})
        self.assertEqual(mem.findings["current_user"], "root@localhost")
        self.assertTrue(mem.findings["is_dba"])

    def test_unrelated_content_types_ignored_without_crashing(self):
        mem = self._mem()
        mem.record_action("get_findings", {}, {"ok": True, "data": {"data": [
            {"type": CONTENT_TYPE.SQL_QUERY, "value": "SELECT 1"},
            {"type": 9999, "value": "unknown future type"},
        ]}})
        # should not raise, and should not pollute any known bucket
        self.assertEqual(mem.findings["databases"], [])
        self.assertIsNone(mem.findings["dbms"])

    def test_os_cmd_content_type_populates_os_command_results(self):
        mem = self._mem()
        mem.record_action("get_findings", {}, {"ok": True, "data": {"data": [
            {"type": CONTENT_TYPE.OS_CMD, "value": "uid=0(root) gid=0(root)"},
        ]}})
        self.assertEqual(mem.findings["os_command_results"], ["uid=0(root) gid=0(root)"])

    def test_file_read_content_type_populates_file_read_results(self):
        mem = self._mem()
        mem.record_action("get_findings", {}, {"ok": True, "data": {"data": [
            {"type": CONTENT_TYPE.FILE_READ, "value": "root:x:0:0:root:/root:/bin/bash"},
        ]}})
        self.assertEqual(mem.findings["file_read_results"], ["root:x:0:0:root:/root:/bin/bash"])

    def test_multiple_os_cmd_results_all_kept(self):
        mem = self._mem()
        mem.record_action("get_findings", {}, {"ok": True, "data": {"data": [
            {"type": CONTENT_TYPE.OS_CMD, "value": "whoami output"},
        ]}})
        mem.record_action("get_findings", {}, {"ok": True, "data": {"data": [
            {"type": CONTENT_TYPE.OS_CMD, "value": "id output"},
        ]}})
        self.assertEqual(mem.findings["os_command_results"], ["whoami output", "id output"])

    def test_facts_summary_surfaces_os_command_execution_prominently(self):
        mem = self._mem()
        self.assertEqual(mem.facts_summary(), "(nothing confirmed yet)")
        mem.record_action("get_findings", {}, {"ok": True, "data": {"data": [
            {"type": CONTENT_TYPE.OS_CMD, "value": "uid=0(root)"},
        ]}})
        summary = mem.facts_summary()
        self.assertIn("OS COMMAND EXECUTION CONFIRMED", summary)
        self.assertIn("uid=0(root)", summary)


class TestGroundingCheck(unittest.TestCase):
    def test_clean_when_success_claim_matches_evidence(self):
        mem = AgentMemory(goal="test", target="http://example.com")
        mem.record_action("get_findings", {}, {"ok": True, "data": {"data": [
            {"type": CONTENT_TYPE.TECHNIQUES, "value": [{"place": "GET", "parameter": "id", "dbms": "MySQL"}]},
        ]}})
        self.assertEqual(mem.grounding_check("The id parameter is injectable, MySQL confirmed."), [])

    def test_flags_success_claim_without_evidence(self):
        mem = AgentMemory(goal="test", target="http://example.com")
        caveats = mem.grounding_check("The id parameter is injectable and vulnerable.")
        self.assertEqual(len(caveats), 1)
        self.assertIn("no injection point was actually recorded", caveats[0])

    def test_flags_failure_claim_despite_evidence(self):
        mem = AgentMemory(goal="test", target="http://example.com")
        mem.record_action("get_findings", {}, {"ok": True, "data": {"data": [
            {"type": CONTENT_TYPE.TECHNIQUES, "value": [{"place": "GET", "parameter": "id", "dbms": "MySQL"}]},
        ]}})
        caveats = mem.grounding_check("No vulnerability found, target appears not injectable.")
        self.assertEqual(len(caveats), 1)
        self.assertIn("DO contain", caveats[0])

    def test_correct_dbms_claim_is_clean(self):
        mem = AgentMemory(goal="test", target="http://example.com")
        mem.record_action("get_findings", {}, {"ok": True, "data": {"data": [
            {"type": CONTENT_TYPE.TECHNIQUES, "value": [{"place": "GET", "parameter": "id", "dbms": "MySQL"}]},
        ]}})
        self.assertEqual(mem.grounding_check("MySQL backend confirmed."), [])

    def test_wrong_dbms_claim_is_flagged(self):
        mem = AgentMemory(goal="test", target="http://example.com")
        mem.record_action("get_findings", {}, {"ok": True, "data": {"data": [
            {"type": CONTENT_TYPE.TECHNIQUES, "value": [{"place": "GET", "parameter": "id", "dbms": "MySQL"}]},
        ]}})
        caveats = mem.grounding_check("PostgreSQL backend confirmed.")
        self.assertEqual(len(caveats), 1)
        self.assertIn("PostgreSQL", caveats[0])
        self.assertIn("MySQL", caveats[0])

    def test_dbms_claim_with_none_fingerprinted_is_flagged(self):
        # regression test: an earlier version of this check silently
        # passed this exact scenario, because Python's "" in "oracle"
        # (empty findings["dbms"]) is always True, defeating the
        # mismatch comparison - this pins the fix.
        mem = AgentMemory(goal="test", target="http://example.com")
        caveats = mem.grounding_check("Likely Oracle based on error patterns.")
        self.assertEqual(len(caveats), 1)
        self.assertIn("Oracle", caveats[0])
        self.assertIn("unverified", caveats[0])

    def test_no_dbms_mentioned_is_clean(self):
        mem = AgentMemory(goal="test", target="http://example.com")
        mem.record_action("get_findings", {}, {"ok": True, "data": {"data": [
            {"type": CONTENT_TYPE.TECHNIQUES, "value": [{"place": "GET", "parameter": "id", "dbms": "MySQL"}]},
        ]}})
        self.assertEqual(mem.grounding_check("The id parameter is injectable."), [])

    def test_correct_table_claim_is_clean(self):
        mem = AgentMemory(goal="test", target="http://example.com")
        mem.record_action("get_findings", {}, {"ok": True, "data": {"data": [
            {"type": CONTENT_TYPE.TABLES, "value": {"maindb": ["users", "orders"]}},
        ]}})
        self.assertEqual(mem.grounding_check("Found table users with password data."), [])

    def test_unsupported_table_claim_is_flagged(self):
        mem = AgentMemory(goal="test", target="http://example.com")
        mem.record_action("get_findings", {}, {"ok": True, "data": {"data": [
            {"type": CONTENT_TYPE.TABLES, "value": {"maindb": ["users", "orders"]}},
        ]}})
        caveats = mem.grounding_check("Found table secrets with password data.")
        self.assertEqual(len(caveats), 1)
        self.assertIn("secrets", caveats[0])

    def test_table_claim_without_any_tables_known_does_not_false_positive(self):
        # conservative by design: with zero known tables, we can't tell
        # inference from enumeration, so this should NOT fire - avoiding
        # false alarms on every summary that happens to mention a table
        # name in prose without any findings context at all.
        mem = AgentMemory(goal="test", target="http://example.com")
        self.assertEqual(mem.grounding_check("Found table users with password data."), [])

    def test_word_containing_table_or_db_as_a_substring_is_not_a_false_claim(self):
        # regression: the named-entity regex previously had no word boundary,
        # so "table" inside "injec[table]" matched as if the summary named
        # a specific database/table - caught via an end-to-end demo run
        # with a realistic summary sentence, not a hand-picked unit test
        # string built to avoid the bug.
        mem = AgentMemory(goal="test", target="http://example.com")
        mem.record_action("get_findings", {}, {"ok": True, "data": {"data": [
            {"type": CONTENT_TYPE.TECHNIQUES, "value": [{"place": "GET", "parameter": "id", "dbms": "MySQL"}]},
        ]}})
        caveats = mem.grounding_check(
            "The id parameter is injectable via boolean-based blind and UNION query on MySQL, "
            "confirmed by get_findings."
        )
        self.assertEqual(caveats, [])


class TestOsCommandGroundingCheck(unittest.TestCase):
    """
    The highest-severity claim this codebase can validate deserves the
    same anti-hallucination coverage as the injection-claim tests above,
    not a thinner version just because it was added later.
    """

    def test_flags_os_command_claim_without_evidence(self):
        mem = AgentMemory(goal="test", target="http://example.com")
        caveats = mem.grounding_check("Achieved full OS command execution on the DBMS host.")
        self.assertEqual(len(caveats), 1)
        self.assertIn("no command output was actually recorded", caveats[0])

    def test_clean_when_os_command_claim_matches_evidence(self):
        mem = AgentMemory(goal="test", target="http://example.com")
        mem.record_action("get_findings", {}, {"ok": True, "data": {"data": [
            {"type": CONTENT_TYPE.OS_CMD, "value": "uid=0(root)"},
        ]}})
        caveats = mem.grounding_check("Achieved OS command execution - confirmed via whoami output.")
        self.assertEqual(caveats, [])

    def test_no_false_positive_on_unrelated_summary(self):
        mem = AgentMemory(goal="test", target="http://example.com")
        caveats = mem.grounding_check("The scan completed with no findings of interest.")
        self.assertEqual(caveats, [])


class TestFactsSummary(unittest.TestCase):
    def test_empty_before_any_findings(self):
        mem = AgentMemory(goal="test", target="http://example.com")
        self.assertEqual(mem.facts_summary(), "(nothing confirmed yet)")

    def test_reflects_recorded_findings(self):
        mem = AgentMemory(goal="test", target="http://example.com")
        mem.record_action("get_findings", {}, {"ok": True, "data": {"data": [
            {"type": CONTENT_TYPE.DBMS_FINGERPRINT, "value": "MySQL"},
            {"type": CONTENT_TYPE.DBS, "value": ["testdb"]},
        ]}})
        summary = mem.facts_summary()
        self.assertIn("MySQL", summary)
        self.assertIn("testdb", summary)


class TestMalformedInputRobustness(unittest.TestCase):
    """
    `grounding_check`'s summary and `note`'s text are untrusted model
    output - the tool specs describe them as strings, but a hallucinated
    reply can hand either a number, list, dict, or bool instead. Neither
    must crash: grounding_check() is called from the "finish" path (the
    one action every run ends on), and a note's stored text later gets
    "\n".join()'d into the CLI's final report (alkha_agent.py) - a crash
    in either place takes down the run at the very last step.

    _merge_engine_findings is fed by sqlmap's own REST API response
    rather than the model, but is hardened the same way for defense in
    depth against a malformed/intercepted response (a proxy or WAF
    mangling the JSON, a network hiccup).
    """

    def test_grounding_check_accepts_non_string_summary(self):
        mem = AgentMemory(goal="test", target="http://example.com")
        for bad_summary in (42, 3.14, True, ["a", "b"], {"a": 1}, None):
            try:
                mem.grounding_check(bad_summary)
            except Exception as e:
                self.fail("grounding_check(%r) raised %s: %s" % (bad_summary, type(e).__name__, e))

    def test_note_with_non_string_text_is_coerced_and_joinable(self):
        mem = AgentMemory(goal="test", target="http://example.com")
        for bad_text in (12345, ["x"], {"a": 1}, None, True, 3.14):
            mem.record_action("note", {"text": bad_text}, {"ok": True})
        for note in mem.findings["notes"]:
            self.assertIsInstance(note, str)
        # this is the exact call alkha_agent.py makes to render the final
        # report - it must never raise TypeError on a non-string note.
        try:
            "\n".join(mem.findings["notes"])
        except Exception as e:
            self.fail("\"\\n\".join(notes) raised %s: %s" % (type(e).__name__, e))

    def test_merge_engine_findings_skips_non_dict_items_without_crashing(self):
        mem = AgentMemory(goal="test", target="http://example.com")
        bad_items = [None, 42, "str", ["x"], {}]
        try:
            mem._merge_engine_findings(bad_items)
        except Exception as e:
            self.fail("_merge_engine_findings raised %s: %s" % (type(e).__name__, e))

    def test_merge_engine_findings_skips_non_list_tables_value_instead_of_iterating_chars(self):
        mem = AgentMemory(goal="test", target="http://example.com")
        mem._merge_engine_findings([{"type": CONTENT_TYPE.TABLES, "value": {"db1": "not_a_list"}}])
        # must NOT have silently split the string into single-character
        # "table names" (the bug this regression test catches)
        self.assertEqual(mem.findings["tables"].get("db1"), [])


class TestNosqlFindingsExtraction(unittest.TestCase):
    """
    record_action() previously had no handling at all for nosql_* tool
    results - a successful nosql_test_injection or nosql_enumerate call
    never reached findings["injection_points"]/["databases"]/["tables"],
    the only place grounding_check() looks to validate a finish summary's
    claims. Found via TestNosqlAgentEndToEnd in test_planner_integration.py
    actually running a full NoSQL-only agent loop, not by testing this
    file or grounding_check() in isolation - each alone looked correct.
    """

    def test_successful_nosql_test_injection_populates_injection_points(self):
        mem = AgentMemory(goal="test", target="http://x/lookup?id=1")
        mem.record_action("nosql_test_injection", {"url": "http://x/lookup?id=1", "param": "id"},
                           {"ok": True, "likely_injectable": True, "baseline": {}, "anomalous_payloads": []})
        self.assertEqual(mem.findings["injection_points"], [{"place": "nosql", "parameter": "id"}])

    def test_grounding_check_no_longer_false_flags_a_confirmed_nosql_finding(self):
        mem = AgentMemory(goal="test", target="http://x/lookup?id=1")
        mem.record_action("nosql_test_injection", {"url": "http://x/lookup?id=1", "param": "id"},
                           {"ok": True, "likely_injectable": True, "baseline": {}, "anomalous_payloads": []})
        caveats = mem.grounding_check("The id parameter is vulnerable to NoSQL operator injection.")
        self.assertEqual(caveats, [])

    def test_unsuccessful_or_not_injectable_result_does_not_populate_findings(self):
        mem = AgentMemory(goal="test", target="http://x/lookup?id=1")
        mem.record_action("nosql_test_injection", {"url": "http://x/lookup?id=1", "param": "id"},
                           {"ok": True, "likely_injectable": False, "baseline": {}, "anomalous_payloads": []})
        mem.record_action("nosql_test_injection", {"url": "http://x/lookup?id=1", "param": "id"},
                           {"ok": False, "error": "connection refused"})
        self.assertEqual(mem.findings["injection_points"], [])

    def test_duplicate_nosql_findings_are_not_appended_twice(self):
        mem = AgentMemory(goal="test", target="http://x/lookup?id=1")
        result = {"ok": True, "likely_injectable": True, "baseline": {}, "anomalous_payloads": []}
        mem.record_action("nosql_test_injection", {"url": "http://x/lookup?id=1", "param": "id"}, result)
        mem.record_action("nosql_test_injection", {"url": "http://x/lookup?id=1", "param": "id"}, result)
        self.assertEqual(len(mem.findings["injection_points"]), 1)

    def test_successful_nosql_enumerate_populates_databases_and_tables(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("nosql_enumerate", {"host": "x"}, {
            "ok": True,
            "result": {"databases": {"app": ["users", "orders"], "empty_db": []}, "users_found": []},
        })
        self.assertIn("app", mem.findings["databases"])
        self.assertIn("empty_db", mem.findings["databases"])
        self.assertEqual(set(mem.findings["tables"]["app"]), {"users", "orders"})
        self.assertNotIn("empty_db", mem.findings["tables"])

    def test_failed_nosql_enumerate_does_not_populate_findings(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("nosql_enumerate", {"host": "x"}, {"ok": False, "error": "auth required"})
        self.assertEqual(mem.findings["databases"], [])
        self.assertEqual(mem.findings["tables"], {})

    def test_successful_nosql_dump_collection_populates_dumped_tables(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("nosql_dump_collection", {"host": "x", "database": "app", "collection": "users"},
                           {"ok": True, "documents": [{"u": "admin"}, {"u": "bob"}], "count": 2})
        self.assertEqual(mem.findings["dumped_tables"], [{"backend": "mongodb", "database": "app", "collection": "users", "count": 2}])

    def test_facts_summary_reflects_a_successful_nosql_dump(self):
        mem = AgentMemory(goal="test", target="http://x")
        self.assertEqual(mem.facts_summary(), "(nothing confirmed yet)")
        mem.record_action("nosql_dump_collection", {"host": "x", "database": "app", "collection": "users"},
                           {"ok": True, "documents": [], "count": 0})
        self.assertIn("Tables dumped so far: 1", mem.facts_summary())

    def test_failed_nosql_dump_collection_does_not_populate_findings(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("nosql_dump_collection", {"host": "x", "database": "app", "collection": "users"},
                           {"ok": False, "error": "connection refused"})
        self.assertEqual(mem.findings["dumped_tables"], [])

    def test_successful_nosql_scan_target_populates_nosql_access(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("nosql_scan_target", {"host": "10.0.0.5", "port": 27017},
                           {"ok": True, "result": {"status": "open", "version": "5.0.9", "database_count": 3}})
        self.assertEqual(mem.findings["nosql_access"], [
            {"backend": "mongodb", "host": "10.0.0.5", "port": 27017, "status": "open", "version": "5.0.9", "database_count": 3},
        ])

    def test_open_nosql_access_is_surfaced_prominently_in_facts_summary(self):
        mem = AgentMemory(goal="test", target="http://x")
        self.assertEqual(mem.facts_summary(), "(nothing confirmed yet)")
        mem.record_action("nosql_scan_target", {"host": "10.0.0.5", "port": 27017},
                           {"ok": True, "result": {"status": "open", "version": "5.0.9", "database_count": 3}})
        summary = mem.facts_summary()
        self.assertIn("ANONYMOUS ACCESS", summary)
        self.assertIn("10.0.0.5:27017", summary)

    def test_auth_required_nosql_access_is_recorded_but_unremarkable(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("nosql_scan_target", {"host": "10.0.0.6"},
                           {"ok": True, "result": {"status": "auth_required", "version": None}})
        self.assertEqual(mem.findings["nosql_access"], [
            {"backend": "mongodb", "host": "10.0.0.6", "port": 27017, "status": "auth_required", "version": None, "database_count": None},
        ])
        summary = mem.facts_summary()
        self.assertIn("auth_required", summary)
        self.assertNotIn("ANONYMOUS ACCESS", summary)

    def test_failed_nosql_scan_target_does_not_populate_findings(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("nosql_scan_target", {"host": "10.0.0.7"}, {"ok": False, "error": "timeout"})
        self.assertEqual(mem.findings["nosql_access"], [])

    def test_repeated_scans_of_the_same_host_are_both_kept_not_deduped(self):
        # a host can legitimately be scanned more than once (e.g.
        # re-checking after remediation) - each call is a distinct,
        # independent observation worth keeping, matching dumped_tables'
        # append-only convention.
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("nosql_scan_target", {"host": "10.0.0.5"},
                           {"ok": True, "result": {"status": "open", "version": "5.0.9", "database_count": 3}})
        mem.record_action("nosql_scan_target", {"host": "10.0.0.5"},
                           {"ok": True, "result": {"status": "auth_required", "version": None}})
        self.assertEqual(len(mem.findings["nosql_access"]), 2)


class TestRedisFindingsExtraction(unittest.TestCase):
    """
    Same class of gap as TestNosqlFindingsExtraction above, for the newer
    redis_* tool family - added proactively this time (see doc/ALKHA.md
    §19) rather than needing an end-to-end run to discover it, applying
    the lesson from §17/§18 up front.
    """

    def test_successful_redis_scan_target_populates_nosql_access_as_redis_backend(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("redis_scan_target", {"host": "10.0.0.9", "port": 6379},
                           {"ok": True, "result": {"status": "open", "version": "7.2.4", "mode": "standalone"}})
        self.assertEqual(mem.findings["nosql_access"], [
            {"backend": "redis", "host": "10.0.0.9", "port": 6379, "status": "open",
             "version": "7.2.4", "database_count": None},
        ])

    def test_open_redis_access_is_labeled_redis_not_mongodb_in_facts_summary(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("redis_scan_target", {"host": "10.0.0.9"},
                           {"ok": True, "result": {"status": "open", "version": "7.2.4"}})
        summary = mem.facts_summary()
        self.assertIn("Redis 7.2.4", summary)
        self.assertNotIn("MongoDB", summary)
        # Redis has no database_count concept - must not print a stray
        # ", None database(s)" or similar artifact of the shared field
        self.assertNotIn("None database", summary)

    def test_mongo_and_redis_access_can_coexist_and_are_labeled_correctly(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("nosql_scan_target", {"host": "10.0.0.5"},
                           {"ok": True, "result": {"status": "open", "version": "5.0.9", "database_count": 3}})
        mem.record_action("redis_scan_target", {"host": "10.0.0.9"},
                           {"ok": True, "result": {"status": "open", "version": "7.2.4"}})
        summary = mem.facts_summary()
        self.assertIn("MongoDB 5.0.9", summary)
        self.assertIn("Redis 7.2.4", summary)

    def test_failed_redis_scan_target_does_not_populate_findings(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("redis_scan_target", {"host": "10.0.0.9"}, {"ok": False, "error": "timeout"})
        self.assertEqual(mem.findings["nosql_access"], [])

    def test_successful_redis_dump_keys_populates_dumped_tables(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("redis_dump_keys", {"host": "10.0.0.9", "keys": ["a", "b", "c"]},
                           {"ok": True, "entries": [{"key": "a", "type": "string", "value": "1"}], "count": 3})
        self.assertEqual(mem.findings["dumped_tables"], [{"backend": "redis", "host": "10.0.0.9", "count": 3}])

    def test_facts_summary_reflects_a_successful_redis_dump(self):
        mem = AgentMemory(goal="test", target="http://x")
        self.assertEqual(mem.facts_summary(), "(nothing confirmed yet)")
        mem.record_action("redis_dump_keys", {"host": "10.0.0.9", "keys": ["a"]},
                           {"ok": True, "entries": [], "count": 1})
        self.assertIn("Tables dumped so far: 1", mem.facts_summary())

    def test_failed_redis_dump_keys_does_not_populate_findings(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("redis_dump_keys", {"host": "10.0.0.9", "keys": ["a"]},
                           {"ok": False, "error": "connection refused"})
        self.assertEqual(mem.findings["dumped_tables"], [])


class TestElasticsearchFindingsExtraction(unittest.TestCase):
    """Third backend, same pattern as TestRedisFindingsExtraction - see doc/ALKHA.md §20."""

    def test_successful_elasticsearch_scan_target_populates_nosql_access(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("elasticsearch_scan_target", {"host": "10.0.0.7", "port": 9200},
                           {"ok": True, "result": {"status": "open", "version": "8.11.3",
                                                     "cluster_name": "prod-cluster", "index_count": 5}})
        self.assertEqual(mem.findings["nosql_access"], [
            {"backend": "elasticsearch", "host": "10.0.0.7", "port": 9200, "status": "open",
             "version": "8.11.3", "database_count": 5},
        ])

    def test_open_elasticsearch_access_is_labeled_correctly_in_facts_summary(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("elasticsearch_scan_target", {"host": "10.0.0.7"},
                           {"ok": True, "result": {"status": "open", "version": "8.11.3", "index_count": 5}})
        summary = mem.facts_summary()
        self.assertIn("Elasticsearch 8.11.3", summary)
        self.assertIn("5 database(s)", summary)

    def test_all_three_backends_can_coexist_and_are_labeled_correctly(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("nosql_scan_target", {"host": "10.0.0.5"},
                           {"ok": True, "result": {"status": "open", "version": "5.0.9", "database_count": 3}})
        mem.record_action("redis_scan_target", {"host": "10.0.0.9"},
                           {"ok": True, "result": {"status": "open", "version": "7.2.4"}})
        mem.record_action("elasticsearch_scan_target", {"host": "10.0.0.7"},
                           {"ok": True, "result": {"status": "open", "version": "8.11.3", "index_count": 5}})
        summary = mem.facts_summary()
        self.assertIn("MongoDB 5.0.9", summary)
        self.assertIn("Redis 7.2.4", summary)
        self.assertIn("Elasticsearch 8.11.3", summary)

    def test_failed_elasticsearch_scan_target_does_not_populate_findings(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("elasticsearch_scan_target", {"host": "10.0.0.7"}, {"ok": False, "error": "timeout"})
        self.assertEqual(mem.findings["nosql_access"], [])

    def test_successful_elasticsearch_dump_index_populates_dumped_tables(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("elasticsearch_dump_index", {"host": "10.0.0.7", "index": "users"},
                           {"ok": True, "documents": [{"username": "admin"}], "count": 1})
        self.assertEqual(mem.findings["dumped_tables"], [
            {"backend": "elasticsearch", "host": "10.0.0.7", "index": "users", "count": 1},
        ])

    def test_facts_summary_reflects_a_successful_elasticsearch_dump(self):
        mem = AgentMemory(goal="test", target="http://x")
        self.assertEqual(mem.facts_summary(), "(nothing confirmed yet)")
        mem.record_action("elasticsearch_dump_index", {"host": "10.0.0.7", "index": "users"},
                           {"ok": True, "documents": [], "count": 3})
        self.assertIn("Tables dumped so far: 1", mem.facts_summary())

    def test_failed_elasticsearch_dump_index_does_not_populate_findings(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("elasticsearch_dump_index", {"host": "10.0.0.7", "index": "users"},
                           {"ok": False, "error": "index_not_found_exception"})
        self.assertEqual(mem.findings["dumped_tables"], [])


class TestCouchDBFindingsExtraction(unittest.TestCase):
    """Fourth backend, same pattern as TestElasticsearchFindingsExtraction - see doc/ALKHA.md §21."""

    def test_successful_couchdb_scan_target_populates_nosql_access(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("couchdb_scan_target", {"host": "10.0.0.8", "port": 5984},
                           {"ok": True, "result": {"status": "open", "version": "3.3.3", "database_count": 3}})
        self.assertEqual(mem.findings["nosql_access"], [
            {"backend": "couchdb", "host": "10.0.0.8", "port": 5984, "status": "open",
             "version": "3.3.3", "database_count": 3},
        ])

    def test_open_couchdb_access_is_labeled_correctly_in_facts_summary(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("couchdb_scan_target", {"host": "10.0.0.8"},
                           {"ok": True, "result": {"status": "open", "version": "3.3.3", "database_count": 3}})
        summary = mem.facts_summary()
        self.assertIn("CouchDB 3.3.3", summary)
        self.assertIn("3 database(s)", summary)

    def test_all_four_backends_can_coexist_and_are_labeled_correctly(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("nosql_scan_target", {"host": "10.0.0.5"},
                           {"ok": True, "result": {"status": "open", "version": "5.0.9", "database_count": 3}})
        mem.record_action("redis_scan_target", {"host": "10.0.0.9"},
                           {"ok": True, "result": {"status": "open", "version": "7.2.4"}})
        mem.record_action("elasticsearch_scan_target", {"host": "10.0.0.7"},
                           {"ok": True, "result": {"status": "open", "version": "8.11.3", "index_count": 5}})
        mem.record_action("couchdb_scan_target", {"host": "10.0.0.8"},
                           {"ok": True, "result": {"status": "open", "version": "3.3.3", "database_count": 3}})
        summary = mem.facts_summary()
        self.assertIn("MongoDB 5.0.9", summary)
        self.assertIn("Redis 7.2.4", summary)
        self.assertIn("Elasticsearch 8.11.3", summary)
        self.assertIn("CouchDB 3.3.3", summary)

    def test_failed_couchdb_scan_target_does_not_populate_findings(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("couchdb_scan_target", {"host": "10.0.0.8"}, {"ok": False, "error": "timeout"})
        self.assertEqual(mem.findings["nosql_access"], [])

    def test_successful_couchdb_dump_database_populates_dumped_tables(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("couchdb_dump_database", {"host": "10.0.0.8", "database": "customers"},
                           {"ok": True, "documents": [{"_id": "c1"}], "count": 1})
        self.assertEqual(mem.findings["dumped_tables"], [
            {"backend": "couchdb", "host": "10.0.0.8", "database": "customers", "count": 1},
        ])

    def test_facts_summary_reflects_a_successful_couchdb_dump(self):
        mem = AgentMemory(goal="test", target="http://x")
        self.assertEqual(mem.facts_summary(), "(nothing confirmed yet)")
        mem.record_action("couchdb_dump_database", {"host": "10.0.0.8", "database": "customers"},
                           {"ok": True, "documents": [], "count": 2})
        self.assertIn("Tables dumped so far: 1", mem.facts_summary())

    def test_failed_couchdb_dump_database_does_not_populate_findings(self):
        mem = AgentMemory(goal="test", target="http://x")
        mem.record_action("couchdb_dump_database", {"host": "10.0.0.8", "database": "customers"},
                           {"ok": False, "error": "not_found"})
        self.assertEqual(mem.findings["dumped_tables"], [])


if __name__ == "__main__":
    unittest.main()
