#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from lib.ai.option_validator import validate_options, valid_option_names


class TestOptionValidator(unittest.TestCase):
    def test_valid_option_names_is_nonempty_and_contains_known_options(self):
        names = valid_option_names()
        self.assertGreater(len(names), 100)
        for known in ("level", "risk", "url", "getDbs", "getTables", "dumpTable", "tamper"):
            self.assertIn(known, names)

    def test_all_valid_options_pass_through_unchanged(self):
        clean, errors = validate_options({"level": 3, "risk": 2, "getDbs": True})
        self.assertEqual(clean, {"level": 3, "risk": 2, "getDbs": True})
        self.assertEqual(errors, [])

    def test_second_order_options_accepted(self):
        # regression test: secondUrl is how the agent gets second-order
        # SQLi support (see doc/ALKHA.md) - it's accepted through
        # configure_scan's generic option path (no dedicated tool), so
        # this pins that it stays a recognized option name.
        clean, errors = validate_options({"secondUrl": "http://example.com/render.php"})
        self.assertEqual(clean, {"secondUrl": "http://example.com/render.php"})
        self.assertEqual(errors, [])

    def test_typo_dropped_with_suggestion(self):
        clean, errors = validate_options({"riskLevel": 5})
        self.assertEqual(clean, {})
        self.assertEqual(len(errors), 1)
        self.assertIn("risk", errors[0])

    def test_nonsense_key_dropped_without_crashing(self):
        clean, errors = validate_options({"totallyMadeUpOptionXYZ": 1})
        self.assertEqual(clean, {})
        self.assertEqual(len(errors), 1)

    def test_mixed_valid_and_invalid(self):
        clean, errors = validate_options({"level": 3, "dbName": "foo", "getDbs": True})
        self.assertEqual(clean, {"level": 3, "getDbs": True})
        self.assertEqual(len(errors), 1)

    def test_empty_input(self):
        clean, errors = validate_options({})
        self.assertEqual(clean, {})
        self.assertEqual(errors, [])

    def test_none_input_does_not_crash(self):
        clean, errors = validate_options(None)
        self.assertEqual(clean, {})
        self.assertEqual(errors, [])

    def test_non_dict_input_does_not_crash(self):
        # `options` is untrusted model-supplied input for configure_scan - a
        # hallucinated string/list argument must be rejected with a clear
        # error, not raise AttributeError on .items().
        for bad_options in ("not a dict", [1, 2, 3], 42, 3.14, True):
            clean, errors = validate_options(bad_options)
            self.assertEqual(clean, {})
            self.assertEqual(len(errors), 1)
            self.assertIn("not an object/dict", errors[0])


class TestDangerousOptionsBlockedFromConfigureScan(unittest.TestCase):
    """
    Regression coverage for a real, serious gap: every one of these is a
    genuine sqlmap option name (present in optDict, so it would
    otherwise pass valid_option_names()'s check) that reaches operating-
    system, filesystem, or Windows-registry access - lib/ai/safety.py's
    HIGH_RISK_ACTIONS already reserved names for exactly this class of
    action (os_shell, os_cmd, file_write, file_read, registry_write),
    but that gating only ever applied at the tool-name level, never
    accounting for configure_scan's generic option pass-through being a
    side door to the same capabilities with NO gating at all - before
    this fix, configure_scan({"options": {"osCmd": "whoami"}}) followed
    by start_scan reached real OS command execution with zero safety
    check. See doc/ALKHA.md §22 for the full writeup.
    """

    DANGEROUS_OPTIONS = ("fileWrite", "fileDest", "osShell", "osPwn", "osSmb", "osBof",
                         "regRead", "regAdd", "regDel", "fileRead", "osCmd")

    def test_every_dangerous_option_is_rejected_not_silently_dropped(self):
        for option in self.DANGEROUS_OPTIONS:
            clean, errors = validate_options({option: "x"})
            self.assertNotIn(option, clean, "%s must not reach clean_options" % option)
            self.assertEqual(len(errors), 1, "%s must produce exactly one clear error" % option)

    def test_dangerous_options_are_confirmed_to_be_real_sqlmap_options(self):
        # the whole point of this test class: these names must actually
        # exist in sqlmap's real option schema (otherwise this is testing
        # nothing - a typo'd/fake option name would be rejected anyway by
        # the ordinary "unknown option" path, not because of the
        # blocklist at all).
        from lib.ai.option_validator import valid_option_names
        for option in self.DANGEROUS_OPTIONS:
            self.assertIn(option, valid_option_names(), "%s should be a real sqlmap option for this "
                                                          "test to actually verify anything" % option)

    def test_os_cmd_and_file_read_error_messages_point_to_the_dedicated_tool(self):
        _, errors = validate_options({"osCmd": "whoami"})
        self.assertIn("os_cmd tool", errors[0])
        _, errors = validate_options({"fileRead": "/etc/passwd"})
        self.assertIn("file_read tool", errors[0])

    def test_mixing_dangerous_and_safe_options_only_drops_the_dangerous_one(self):
        clean, errors = validate_options({"osCmd": "whoami", "level": 3, "risk": 2})
        self.assertEqual(clean, {"level": 3, "risk": 2})
        self.assertEqual(len(errors), 1)


if __name__ == "__main__":
    unittest.main()
