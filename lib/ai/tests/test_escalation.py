#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from lib.ai.escalation import EscalationLadder, LADDER, technique_isolation_rungs
from lib.ai.option_validator import validate_options


class TestEscalationLadder(unittest.TestCase):
    def test_every_rung_uses_only_real_option_names(self):
        # every rung's options dict must pass option_validator cleanly -
        # a typo here would silently break escalation for real users.
        for rung in LADDER + technique_isolation_rungs():
            clean, errors = validate_options(rung["options"])
            self.assertEqual(errors, [], "rung '%s' has invalid options: %s" % (rung["label"], errors))
            self.assertEqual(clean, rung["options"])

    def test_rungs_strictly_broaden_or_add_evasion_never_narrow(self):
        # level/risk should never decrease rung over rung in the main ladder
        last_level, last_risk = 0, 0
        for rung in LADDER:
            level = rung["options"].get("level", last_level)
            risk = rung["options"].get("risk", last_risk)
            self.assertGreaterEqual(level, last_level, "rung '%s' decreased level" % rung["label"])
            self.assertGreaterEqual(risk, last_risk, "rung '%s' decreased risk" % rung["label"])
            last_level, last_risk = level, risk

    def test_ladder_never_touches_dangerous_options(self):
        dangerous = {"evalCode", "osShell", "osCmd", "osPwn", "osSmb", "osBof",
                     "regRead", "regAdd", "regDel", "fileWrite", "fileDest"}
        for rung in LADDER + technique_isolation_rungs():
            self.assertTrue(dangerous.isdisjoint(rung["options"].keys()),
                             "rung '%s' touches a dangerous option" % rung["label"])

    def test_next_rung_advances_in_order(self):
        ladder = EscalationLadder()
        first = ladder.next_rung()
        second = ladder.next_rung()
        self.assertEqual(first["label"], "baseline")
        self.assertNotEqual(first["label"], second["label"])

    def test_exhausts_after_all_rungs(self):
        ladder = EscalationLadder()
        expected_count = len(LADDER) + len(technique_isolation_rungs())
        seen = 0
        while True:
            rung = ladder.next_rung()
            if rung is None:
                break
            seen += 1
        self.assertEqual(seen, expected_count)

    def test_technique_isolation_covers_all_six_letters(self):
        rungs = technique_isolation_rungs()
        letters = sorted(r["options"]["technique"] for r in rungs)
        self.assertEqual(letters, sorted(["B", "T", "E", "U", "S", "Q"]))

    def test_current_label_reflects_position(self):
        ladder = EscalationLadder()
        self.assertIsNone(ladder.current_label())
        ladder.next_rung()
        self.assertEqual(ladder.current_label(), "baseline")


if __name__ == "__main__":
    unittest.main()
