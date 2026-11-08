#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

alkha_agent.py is an entry-point script (not a package module) - loaded
here via importlib.util the same way any other test file would need to,
since it can't be `import`ed as a normal dotted module from a script
outside the repo root without sys.path tricks that would be fragile
across environments. This isolates EventRenderer's spinner-lifecycle
logic (the actual thing worth testing) from real terminal/thread
behavior by substituting a fake Spinner that just records calls.
"""

import importlib.util
import os
import sys
import unittest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, _REPO_ROOT)

_spec = importlib.util.spec_from_file_location("alkha_agent", os.path.join(_REPO_ROOT, "alkha_agent.py"))
alkha_agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(alkha_agent)


class _FakeSpinner(object):
    """Records lifecycle calls instead of touching a real thread/terminal."""

    instances = []

    def __init__(self, text):
        self.text = text
        self.entered = False
        self.exited = False
        _FakeSpinner.instances.append(self)

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.exited = True


class TestEventRendererSpinnerLifecycle(unittest.TestCase):
    def setUp(self):
        _FakeSpinner.instances = []
        self._real_spinner = alkha_agent.Spinner
        alkha_agent.Spinner = _FakeSpinner

    def tearDown(self):
        alkha_agent.Spinner = self._real_spinner

    def test_thinking_start_starts_exactly_one_spinner(self):
        renderer = alkha_agent.EventRenderer()
        renderer("thinking_start", None)
        self.assertEqual(len(_FakeSpinner.instances), 1)
        self.assertTrue(_FakeSpinner.instances[0].entered)
        self.assertFalse(_FakeSpinner.instances[0].exited)

    def test_any_other_event_stops_the_active_spinner(self):
        renderer = alkha_agent.EventRenderer()
        renderer("thinking_start", None)
        renderer("thought", "some thought")
        self.assertTrue(_FakeSpinner.instances[0].exited)

    def test_second_thinking_start_stops_the_first_spinner_not_just_replaces_it(self):
        # the retry-backoff path in planner.py's _chat_with_retry can emit
        # "thinking_start" again while the previous one from the same
        # step() call is still conceptually active - must not leak a
        # background thread/spinner instance.
        renderer = alkha_agent.EventRenderer()
        renderer("thinking_start", None)
        first = _FakeSpinner.instances[0]
        renderer("thinking_start", None)
        second = _FakeSpinner.instances[1]

        self.assertTrue(first.exited)
        self.assertTrue(second.entered)
        self.assertFalse(second.exited)

    def test_action_and_observation_events_do_not_raise(self):
        renderer = alkha_agent.EventRenderer()
        renderer("iteration_start", {"n": 1, "max_n": 40, "elapsed": 0})
        renderer("thinking_start", None)
        renderer("thought", "checking things")
        renderer("action", {"name": "set_target", "args": {"url": "http://x"}})
        renderer("observation", {"ok": True, "message": "done"})
        renderer("state", "DBMS: MySQL")
        renderer("warning", "something to watch")
        renderer("done", {"findings": {}})
        # no assertion beyond "didn't raise" - this exercises every event
        # kind through the real (non-Spinner) tui.py rendering functions

    def test_no_spinner_active_is_a_safe_noop_to_stop(self):
        renderer = alkha_agent.EventRenderer()
        renderer("thought", "no spinner was ever started")  # must not raise


if __name__ == "__main__":
    unittest.main()
