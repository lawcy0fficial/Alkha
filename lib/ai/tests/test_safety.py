#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from lib.ai.safety import SafetyPolicy, ScopeViolation, BudgetExceeded


class TestSafetyPolicy(unittest.TestCase):
    def test_safe_action_in_scope_allowed(self):
        sp = SafetyPolicy(allowed_hosts=["example.com"])
        sp.start()
        self.assertTrue(sp.authorize("set_target", {"url": "http://example.com/x"}))

    def test_out_of_scope_host_raises(self):
        sp = SafetyPolicy(allowed_hosts=["example.com"])
        sp.start()
        with self.assertRaises(ScopeViolation):
            sp.authorize("set_target", {"url": "http://evil.com/x"})

    def test_high_risk_without_confirm_callback_fails_safe(self):
        sp = SafetyPolicy(allowed_hosts=["example.com"])
        sp.start()
        self.assertFalse(sp.authorize("dump_all", {}))

    def test_high_risk_with_yolo_allowed(self):
        sp = SafetyPolicy(allowed_hosts=["example.com"], yolo=True)
        sp.start()
        self.assertTrue(sp.authorize("dump_all", {}))
        self.assertTrue(sp.authorize("dump_table", {"db": "x", "table": "y"}))

    def test_high_risk_with_confirm_callback_respects_answer(self):
        sp_yes = SafetyPolicy(allowed_hosts=["example.com"], confirm_callback=lambda n, a: True)
        sp_yes.start()
        self.assertTrue(sp_yes.authorize("dump_all", {}))

        sp_no = SafetyPolicy(allowed_hosts=["example.com"], confirm_callback=lambda n, a: False)
        sp_no.start()
        self.assertFalse(sp_no.authorize("dump_all", {}))

    def test_iteration_budget_enforced_once_per_tick(self):
        # regression test for the double-tick bug caught during development:
        # authorize() must NOT also tick the budget - only the caller's
        # explicit tick() per loop iteration should count.
        sp = SafetyPolicy(allowed_hosts=["example.com"], max_iterations=3)
        sp.start()

        sp.tick()
        sp.authorize("set_target", {"url": "http://example.com/x"})
        sp.tick()
        sp.authorize("set_target", {"url": "http://example.com/x"})
        sp.tick()
        sp.authorize("set_target", {"url": "http://example.com/x"})

        with self.assertRaises(BudgetExceeded):
            sp.tick()

    def test_wall_clock_budget_enforced(self):
        sp = SafetyPolicy(allowed_hosts=["example.com"], max_wall_clock=0)
        sp.start()
        import time
        time.sleep(0.01)
        with self.assertRaises(BudgetExceeded):
            sp.tick()

    def test_safe_actions_never_require_confirmation(self):
        sp = SafetyPolicy(allowed_hosts=["example.com"])  # no confirm_callback, not yolo
        sp.start()
        for action in ("configure_scan", "start_scan", "check_status", "get_findings",
                       "list_databases", "list_tables", "list_columns", "list_tamper_scripts"):
            self.assertTrue(sp.authorize(action, {}), "%s should not require confirmation" % action)


class TestMalformedArgsRobustness(unittest.TestCase):
    """
    `args` reaching authorize() is untrusted model output - a malformed or
    hallucinated planning-model reply can hand this a list, string, number,
    or None instead of a dict, or a dict whose url/target/host value isn't
    a string. This must fail SAFE (raise ScopeViolation, the same path as
    an out-of-scope host - refused, not crashed) rather than let a raw
    AttributeError/TypeError escape and take down the whole autonomous
    run - step() only catches ScopeViolation around this call.
    """

    MALFORMED_ARGS_SHAPES = [
        None, [], "just a string", 12345, 3.14, True,
        ["a", "b", "c"], [{"url": "http://x"}],
        {"url": 12345}, {"url": {"a": 1}}, {"url": 3.14}, {"url": True},
        {"host": 12345}, {"target": 3.14}, {"host": ["x"]}, {"target": {"a": 1}},
    ]

    def test_every_action_rejects_every_malformed_shape_as_scope_violation(self):
        sp = SafetyPolicy(allowed_hosts=["example.com"])
        for action in ("set_target", "dump_all", "dump_table", "nosql_dump_collection", "finish"):
            for args in self.MALFORMED_ARGS_SHAPES:
                with self.assertRaises(ScopeViolation, msg="%s(%r) should raise ScopeViolation, "
                                                            "not crash" % (action, args)):
                    sp.authorize(action, args)

    def test_none_is_a_safe_default_not_a_crash(self):
        # authorize() itself is always called with a dict by the planner in
        # practice (args defaults to {} upstream) - but verify the boundary
        # explicitly since None is the most natural "malformed" value a
        # refactor could accidentally introduce.
        sp = SafetyPolicy(allowed_hosts=["example.com"])
        with self.assertRaises(ScopeViolation):
            sp.authorize("dump_all", None)

    def test_well_formed_args_are_unaffected_by_the_hardening(self):
        sp = SafetyPolicy(allowed_hosts=["example.com"])
        sp.start()
        self.assertTrue(sp.authorize("set_target", {"url": "http://example.com/a.php"}))
        with self.assertRaises(ScopeViolation):
            sp.authorize("set_target", {"url": "http://evil.example.org/a.php"})


if __name__ == "__main__":
    unittest.main()
