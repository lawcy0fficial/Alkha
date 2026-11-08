#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Integration tests for AgentPlanner's full plan->act->observe loop. Uses
in-process fake OllamaClient/EngineClient objects rather than real
HTTPServer-backed mocks (as used for manual verification during
development - see doc/ALKHA.md) so these run fast and don't depend on
binding local ports, while still exercising the real planner, tools,
memory, and safety code together rather than each in isolation.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from lib.ai.planner import AgentPlanner
from lib.ai.safety import SafetyPolicy
from lib.ai.knowledge_base import KnowledgeBase
from lib.core.enums import CONTENT_TYPE


class FakeOllamaJsonFallback(object):
    """Simulates a model with no native tool-calling: replies with JSON
    embedded in `content`, scripted turn by turn."""

    def __init__(self, script):
        self.script = script
        self.calls = 0

    def chat(self, messages, tools=None, json_mode=False):
        i = min(self.calls, len(self.script) - 1)
        self.calls += 1
        return {"role": "assistant", "content": json.dumps(self.script[i])}


class FakeOllamaNativeTools(object):
    """Simulates a model with native tool-calling support."""

    def __init__(self, script):
        self.script = script
        self.calls = 0
        self.saw_tools_param = False

    def chat(self, messages, tools=None, json_mode=False):
        if tools:
            self.saw_tools_param = True
        i = min(self.calls, len(self.script) - 1)
        self.calls += 1
        call = self.script[i]
        return {
            "role": "assistant",
            "content": "",
            "tool_calls": [{"function": {"name": call["name"], "arguments": call["args"]}}],
        }


class FakeEngine(object):
    def __init__(self, findings_data=None):
        self._findings_data = findings_data or []
        self.taskid = "faketask"

    def new_task(self):
        return self.taskid

    def start_scan(self, taskid, opts):
        return {"success": True}

    def stop_scan(self, taskid):
        return {"success": True}

    def scan_status(self, taskid):
        return {"status": "terminated"}

    def scan_data(self, taskid):
        return {"success": True, "data": self._findings_data}

    def scan_log(self, taskid, start=None, end=None):
        return {"success": True, "log": []}


class TestPlannerJsonFallback(unittest.TestCase):
    def test_full_loop_completes_via_json_content_parsing(self):
        script = [
            {"thought": "set target", "action": {"name": "set_target", "args": {"url": "http://x/a.php?id=1"}}},
            {"thought": "start", "action": {"name": "start_scan", "args": {}}},
            {"thought": "check", "action": {"name": "get_findings", "args": {}}},
            {"thought": "done", "action": {"name": "finish", "args": {"summary": "enumerated"}}},
        ]
        engine = FakeEngine()
        ollama = FakeOllamaJsonFallback(script)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://x/a.php?id=1",
            use_native_tools=False, knowledge_base=KnowledgeBase(path=kb_path),
        )
        report = planner.run()

        self.assertEqual(ollama.calls, 4)
        self.assertEqual(report["findings"]["notes"], [])  # no grounding caveats, no unexpected notes
        os.remove(kb_path) if os.path.exists(kb_path) else None


class TestPlannerNativeToolCalling(unittest.TestCase):
    def test_full_loop_completes_via_native_tool_calls(self):
        script = [
            {"name": "set_target", "args": {"url": "http://x/a.php?id=1"}},
            {"name": "list_tables", "args": {"db": "testdb"}},
            {"name": "check_status", "args": {}},
            {"name": "finish", "args": {"summary": "native tool-calling worked"}},
        ]
        engine = FakeEngine()
        ollama = FakeOllamaNativeTools(script)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://x/a.php?id=1",
            use_native_tools=True, knowledge_base=KnowledgeBase(path=kb_path),
        )
        report = planner.run()

        self.assertTrue(ollama.saw_tools_param, "planner should have sent the native tool schema")
        self.assertEqual(ollama.calls, 4)
        os.remove(kb_path) if os.path.exists(kb_path) else None


class TestPlannerGroundingIntegration(unittest.TestCase):
    def test_hallucinated_success_gets_caveat_and_is_not_persisted_to_kb(self):
        # model checks status (satisfies the hard finish-gate) but never
        # calls get_findings, then just claims success anyway - the
        # grounding check (not the hard gate) should catch this specific
        # gap: "evidence was gathered" != "the evidence supports the claim"
        script = [
            {"thought": "set target", "action": {"name": "set_target", "args": {"url": "http://x/a.php?id=1"}}},
            {"thought": "check status", "action": {"name": "check_status", "args": {}}},
            {"thought": "confident", "action": {"name": "finish", "args": {"summary": "The id parameter is injectable, MySQL confirmed."}}},
        ]
        engine = FakeEngine()
        ollama = FakeOllamaJsonFallback(script)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)
        kb = KnowledgeBase(path=kb_path)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://x/a.php?id=1",
            use_native_tools=False, knowledge_base=kb,
        )
        report = planner.run()

        notes = report["findings"]["notes"]
        # Two distinct, both-legitimate caveats fire for this scenario:
        # the success claim itself has no recorded injection-point evidence,
        # AND the named DBMS ("MySQL") was never actually fingerprinted -
        # both are real gaps in this hallucinated summary, not a single one.
        self.assertEqual(len(notes), 2)
        self.assertTrue(any("no injection point was actually" in n for n in notes))
        self.assertTrue(any("MySQL" in n and "unverified" in n for n in notes))
        self.assertIn("GROUNDING CHECK", notes[0])

        # a hallucinated, ungrounded success must not poison future runs
        self.assertIsNone(kb.lookup("http://x/a.php?id=1"))

        os.remove(kb_path) if os.path.exists(kb_path) else None

    def test_grounded_success_is_persisted_to_kb(self):
        script = [
            {"thought": "set target", "action": {"name": "set_target", "args": {"url": "http://x/a.php?id=1"}}},
            {"thought": "check", "action": {"name": "get_findings", "args": {}}},
            {"thought": "confirmed", "action": {"name": "finish", "args": {"summary": "id parameter is injectable, MySQL confirmed with evidence."}}},
        ]
        engine = FakeEngine(findings_data=[
            {"type": CONTENT_TYPE.TECHNIQUES, "value": [{"place": "GET", "parameter": "id", "dbms": "MySQL"}]},
        ])
        ollama = FakeOllamaJsonFallback(script)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)
        kb = KnowledgeBase(path=kb_path)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://x/a.php?id=1",
            use_native_tools=False, knowledge_base=kb,
        )
        report = planner.run()

        self.assertEqual(report["findings"]["notes"], [])
        record = kb.lookup("http://x/a.php?id=1")
        self.assertIsNotNone(record)
        self.assertEqual(record["dbms"], "MySQL")

        os.remove(kb_path) if os.path.exists(kb_path) else None

    def test_grounded_success_with_non_string_tamper_value_does_not_crash(self):
        # configure_scan's options dict is untrusted model output -
        # validate_options() only checks that "tamper" is a real sqlmap
        # option *name*, not that its value is the string the model was
        # supposed to send. A hallucinated non-string tamper value
        # previously crashed AttributeError on tamper.split(",") right on
        # this successful-finish path, as the run tried to persist its
        # genuinely grounded evidence to the knowledge base.
        script = [
            {"thought": "set target", "action": {"name": "set_target", "args": {"url": "http://x/a.php?id=1"}}},
            {"thought": "configure", "action": {"name": "configure_scan", "args": {"options": {"tamper": 12345}}}},
            {"thought": "check", "action": {"name": "get_findings", "args": {}}},
            {"thought": "confirmed", "action": {"name": "finish", "args": {"summary": "id parameter is injectable, MySQL confirmed with evidence."}}},
        ]
        engine = FakeEngine(findings_data=[
            {"type": CONTENT_TYPE.TECHNIQUES, "value": [{"place": "GET", "parameter": "id", "dbms": "MySQL"}]},
        ])
        ollama = FakeOllamaJsonFallback(script)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)
        kb = KnowledgeBase(path=kb_path)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://x/a.php?id=1",
            use_native_tools=False, knowledge_base=kb,
        )
        try:
            report = planner.run()
        except Exception as e:
            self.fail("run() crashed on a non-string tamper value: %s: %s" % (type(e).__name__, e))

        self.assertEqual(report["findings"]["notes"], [])
        record = kb.lookup("http://x/a.php?id=1")
        self.assertIsNotNone(record)
        self.assertEqual(record["tamper"], [])  # non-string value discarded, not stored garbled

        os.remove(kb_path) if os.path.exists(kb_path) else None


class TestOsCmdAgentIntegration(unittest.TestCase):
    """
    Full agent-loop coverage for os_cmd/file_read, the same standard as
    TestPlannerGroundingIntegration above. Uses FakeEngine (not a live
    SQL-injection target) since the actual SQL-injection-driven
    OS-command-execution chain is inherited, unmodified sqlmap
    functionality, already battle-tested by the upstream project - no
    real vulnerable, privilege-escalatable DBMS is available in this
    sandbox to build a live target against (unlike the NoSQL modules,
    which speak a protocol simple enough to fake convincingly). What's
    actually new here - the wiring: does os_cmd correctly set sqlmap's
    real osCmd option, does the resulting CONTENT_TYPE.OS_CMD data item
    correctly reach findings, does it correctly gate HIGH_RISK, does
    grounding_check correctly validate the claim - is exactly what this
    test covers; the REST API's own non-interactive-batch-mode handling
    of --os-cmd's underlying technique was verified by reading
    sqlmap's actual source (lib/takeover/abstraction.py's runCmd(),
    lib/utils/api.py forcing conf.batch=True, lib/core/dicts.py's
    PART_RUN_CONTENT_TYPES mapping "osCmd" to CONTENT_TYPE.OS_CMD), not
    re-derived here.
    """

    def test_full_agent_loop_confirms_os_command_execution(self):
        script = [
            {"thought": "set target", "action": {"name": "set_target", "args": {"url": "http://x/a.php?id=1"}}},
            {"thought": "run whoami", "action": {"name": "os_cmd", "args": {"command": "whoami"}}},
            {"thought": "check output", "action": {"name": "get_findings", "args": {}}},
            {"thought": "confirmed", "action": {"name": "finish",
                                                 "args": {"summary": "Achieved OS command execution on the "
                                                                      "DBMS host - whoami returned 'root'."}}},
        ]
        engine = FakeEngine(findings_data=[{"type": CONTENT_TYPE.OS_CMD, "value": "root"}])
        ollama = FakeOllamaJsonFallback(script)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)

        # os_cmd is HIGH_RISK - yolo=True stands in for --agent-yolo.
        safety = SafetyPolicy(allowed_hosts=["x"], yolo=True)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://x/a.php?id=1",
            use_native_tools=False, knowledge_base=KnowledgeBase(path=kb_path), safety_policy=safety,
        )
        report = planner.run()

        self.assertEqual(report["findings"]["os_command_results"], ["root"])
        self.assertEqual(report["findings"]["notes"], [])  # accurate claim, no grounding caveats

        os.remove(kb_path) if os.path.exists(kb_path) else None

    def test_os_cmd_refused_without_yolo(self):
        script = [
            {"thought": "set target", "action": {"name": "set_target", "args": {"url": "http://x/a.php?id=1"}}},
            {"thought": "try whoami", "action": {"name": "os_cmd", "args": {"command": "whoami"}}},
        ]
        engine = FakeEngine()
        ollama = FakeOllamaJsonFallback(script)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://x/a.php?id=1",
            use_native_tools=False,
        )
        planner.step()  # set_target
        planner.step()  # the os_cmd attempt, no yolo

        tool_events = [e for e in planner.memory.events if e["role"] == "tool"]
        os_cmd_event = next(e for e in tool_events if e["content"]["action"] == "os_cmd")
        result = os_cmd_event["content"]["result"]
        self.assertFalse(result["ok"])
        self.assertEqual(planner.memory.findings["os_command_results"], [])

    def test_hallucinated_os_command_claim_gets_caveat(self):
        # the model claims code execution it never actually achieved -
        # the same hallucination-guard standard as the SQL-injection
        # grounding tests above, applied to the highest-severity claim
        # this codebase can make.
        script = [
            {"thought": "set target", "action": {"name": "set_target", "args": {"url": "http://x/a.php?id=1"}}},
            {"thought": "check status", "action": {"name": "check_status", "args": {}}},
            {"thought": "confident", "action": {"name": "finish",
                                                 "args": {"summary": "Achieved full OS command execution."}}},
        ]
        engine = FakeEngine()
        ollama = FakeOllamaJsonFallback(script)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://x/a.php?id=1",
            use_native_tools=False,
        )
        report = planner.run()

        notes = report["findings"]["notes"]
        self.assertTrue(any("no command output was actually recorded" in n for n in notes))


class TestPlannerSafetyIntegration(unittest.TestCase):
    def test_scope_violation_stops_the_action_but_not_the_run(self):
        script = [
            {"thought": "oops wrong host", "action": {"name": "set_target", "args": {"url": "http://evil.com/x"}}},
            {"thought": "recover", "action": {"name": "finish", "args": {"summary": "aborted: out of scope"}}},
        ]
        engine = FakeEngine()
        ollama = FakeOllamaJsonFallback(script)
        safety = SafetyPolicy(allowed_hosts=["x"])  # only "x" (the real target host) is in scope

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://x/a.php?id=1",
            use_native_tools=False, safety_policy=safety, knowledge_base=KnowledgeBase(path=kb_path),
        )
        report = planner.run()  # should not raise

        self.assertIsNotNone(report)
        os.remove(kb_path) if os.path.exists(kb_path) else None


class FakeOllamaFailsThenSucceeds(object):
    """Fails with OllamaError for the first N calls, then behaves like
    FakeOllamaJsonFallback - for testing _chat_with_retry."""

    def __init__(self, script, fail_count):
        self.script = script
        self.fail_count = fail_count
        self.calls = 0

    def chat(self, messages, tools=None, json_mode=False):
        self.calls += 1
        if self.calls <= self.fail_count:
            from lib.ai.ollama_client import OllamaError
            raise OllamaError("simulated transient failure #%d" % self.calls)
        i = min(self.calls - self.fail_count - 1, len(self.script) - 1)
        return {"role": "assistant", "content": json.dumps(self.script[i])}


class FakeOllamaAlwaysFails(object):
    def __init__(self):
        self.calls = 0

    def chat(self, messages, tools=None, json_mode=False):
        self.calls += 1
        from lib.ai.ollama_client import OllamaError
        raise OllamaError("simulated permanent failure")


class TestChatRetryWithBackoff(unittest.TestCase):
    def _make_planner(self, ollama, max_retries=3, backoff_base=1.0):
        engine = FakeEngine()
        sleeps = []

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://x/a.php?id=1",
            use_native_tools=False, knowledge_base=KnowledgeBase(path=kb_path),
            max_ollama_retries=max_retries, retry_backoff_base=backoff_base,
            sleep_fn=lambda s: sleeps.append(s),
        )
        return planner, sleeps, kb_path

    def test_succeeds_after_transient_failures_within_retry_budget(self):
        # uses "note" rather than "finish" as the terminal action - finish
        # is correctly gated behind having called an observation-gathering
        # action first (see _has_gathered_evidence), which is a separate
        # concern from what this test verifies (chat-level retry behavior).
        script = [{"thought": "ok", "action": {"name": "note", "args": {"text": "recovered"}}}]
        ollama = FakeOllamaFailsThenSucceeds(script, fail_count=2)
        planner, sleeps, kb_path = self._make_planner(ollama, max_retries=3)

        finished = planner.step()  # single step should succeed after 2 internal retries

        self.assertFalse(finished)  # "note" doesn't end the run, only confirms the step succeeded
        self.assertEqual(ollama.calls, 3)  # 2 failures + 1 success
        self.assertEqual(len(sleeps), 2)
        os.remove(kb_path) if os.path.exists(kb_path) else None

    def test_backoff_grows_exponentially(self):
        script = [{"thought": "ok", "action": {"name": "finish", "args": {"summary": "recovered"}}}]
        ollama = FakeOllamaFailsThenSucceeds(script, fail_count=3)
        planner, sleeps, kb_path = self._make_planner(ollama, max_retries=3, backoff_base=1.0)

        planner.step()

        self.assertEqual(sleeps, [1.0, 2.0, 4.0])
        os.remove(kb_path) if os.path.exists(kb_path) else None

    def test_raises_planner_error_after_exhausting_retries(self):
        from lib.ai.planner import PlannerError

        ollama = FakeOllamaAlwaysFails()
        planner, sleeps, kb_path = self._make_planner(ollama, max_retries=2)

        with self.assertRaises(PlannerError):
            planner.step()

        self.assertEqual(ollama.calls, 3)  # initial attempt + 2 retries
        os.remove(kb_path) if os.path.exists(kb_path) else None

    def test_run_survives_transient_failure_mid_loop(self):
        # run() should complete normally even if an early step() needed
        # internal retries - the failure shouldn't propagate up as a
        # run-ending PlannerError if it was ultimately recovered from.
        script = [
            {"thought": "set", "action": {"name": "set_target", "args": {"url": "http://x/a.php?id=1"}}},
            {"thought": "check", "action": {"name": "check_status", "args": {}}},
            {"thought": "done", "action": {"name": "finish", "args": {"summary": "ok"}}},
        ]
        ollama = FakeOllamaFailsThenSucceeds(script, fail_count=1)
        planner, sleeps, kb_path = self._make_planner(ollama, max_retries=3)

        report = planner.run()

        self.assertEqual(report["findings"]["notes"], [])
        os.remove(kb_path) if os.path.exists(kb_path) else None


class FakeOllamaRepeating(object):
    """Always returns the exact same action, to test stuck-loop detection."""

    def __init__(self, name, args):
        self.name = name
        self.args = args
        self.calls = 0

    def chat(self, messages, tools=None, json_mode=False):
        self.calls += 1
        content = json.dumps({"thought": "trying again", "action": {"name": self.name, "args": self.args}})
        return {"role": "assistant", "content": content}


class TestStuckLoopDetection(unittest.TestCase):
    def test_identical_repeated_action_gets_blocked(self):
        engine = FakeEngine()
        ollama = FakeOllamaRepeating("check_status", {})

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)

        warnings = []
        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://x/a.php?id=1",
            use_native_tools=False, knowledge_base=KnowledgeBase(path=kb_path),
            stuck_action_threshold=3,
            on_event=lambda kind, payload: warnings.append(payload) if kind == "warning" else None,
        )

        for _ in range(5):
            planner.step()

        stuck_warnings = [w for w in warnings if "Blocked repeated action" in str(w)]
        self.assertGreater(len(stuck_warnings), 0)
        os.remove(kb_path) if os.path.exists(kb_path) else None

    def test_different_args_each_time_never_blocked(self):
        engine = FakeEngine()

        class VaryingOllama(object):
            def __init__(self):
                self.calls = 0

            def chat(self, messages, tools=None, json_mode=False):
                self.calls += 1
                content = json.dumps({"thought": "varying", "action": {
                    "name": "get_logs", "args": {"start": self.calls}  # different every time
                }})
                return {"role": "assistant", "content": content}

        ollama = VaryingOllama()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)

        warnings = []
        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://x/a.php?id=1",
            use_native_tools=False, knowledge_base=KnowledgeBase(path=kb_path),
            stuck_action_threshold=3,
            on_event=lambda kind, payload: warnings.append(payload) if kind == "warning" else None,
        )

        for _ in range(5):
            planner.step()

        stuck_warnings = [w for w in warnings if "Blocked repeated action" in str(w)]
        self.assertEqual(len(stuck_warnings), 0)
        os.remove(kb_path) if os.path.exists(kb_path) else None


class TestHardFinishGate(unittest.TestCase):
    def test_finish_without_any_evidence_gathering_is_blocked(self):
        engine = FakeEngine()
        script = [
            {"thought": "set", "action": {"name": "set_target", "args": {"url": "http://x/a.php?id=1"}}},
            {"thought": "premature", "action": {"name": "finish", "args": {"summary": "done already"}}},
        ]
        ollama = FakeOllamaJsonFallback(script)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://x/a.php?id=1",
            use_native_tools=False, knowledge_base=KnowledgeBase(path=kb_path),
        )

        finished_step1 = planner.step()  # set_target
        finished_step2 = planner.step()  # finish attempt - should be blocked

        self.assertFalse(finished_step1)
        self.assertFalse(finished_step2)  # blocked, not accepted
        os.remove(kb_path) if os.path.exists(kb_path) else None

    def test_finish_after_check_status_is_allowed(self):
        engine = FakeEngine()
        script = [
            {"thought": "set", "action": {"name": "set_target", "args": {"url": "http://x/a.php?id=1"}}},
            {"thought": "check", "action": {"name": "check_status", "args": {}}},
            {"thought": "now finish", "action": {"name": "finish", "args": {"summary": "done"}}},
        ]
        ollama = FakeOllamaJsonFallback(script)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://x/a.php?id=1",
            use_native_tools=False, knowledge_base=KnowledgeBase(path=kb_path),
        )

        planner.step()  # set_target
        planner.step()  # check_status
        finished = planner.step()  # finish - should be allowed now

        self.assertTrue(finished)
        os.remove(kb_path) if os.path.exists(kb_path) else None

    def test_finish_after_nosql_test_injection_is_allowed(self):
        # regression: nosql_* tools previously didn't count toward the hard
        # finish gate at all - a pure-NoSQL engagement (never touching
        # get_findings/check_status/get_logs) could never finish cleanly
        # and would always burn its full iteration/time budget instead.
        # Uses a mocked probe() rather than the live target, since this
        # test is about the finish-gate mechanism, not injection detection
        # itself - see TestNosqlAgentEndToEnd for the real-target version.
        from unittest.mock import patch

        engine = FakeEngine()
        script = [
            {"thought": "set", "action": {"name": "set_target", "args": {"url": "http://x/lookup?id=1"}}},
            {"thought": "test", "action": {"name": "nosql_test_injection",
                                            "args": {"url": "http://x/lookup?id=1", "param": "id"}}},
            {"thought": "finish", "action": {"name": "finish", "args": {"summary": "done, NoSQL injectable"}}},
        ]
        ollama = FakeOllamaJsonFallback(script)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://x/lookup?id=1",
            use_native_tools=False, knowledge_base=KnowledgeBase(path=kb_path),
        )

        fake_probe_result = {"likely_injectable": True, "baseline": {}, "findings": []}
        with patch("lib.nosql.injection_probe.probe", return_value=fake_probe_result):
            planner.step()  # set_target
            planner.step()  # nosql_test_injection
            finished = planner.step()  # finish - should be allowed

        self.assertTrue(finished)
        os.remove(kb_path) if os.path.exists(kb_path) else None


class TestFinishRequiresEvidence(unittest.TestCase):
    def test_finish_without_any_observation_gathering_is_blocked(self):
        script = [{"thought": "confident", "action": {"name": "finish", "args": {"summary": "done"}}}]
        engine = FakeEngine()
        ollama = FakeOllamaJsonFallback(script)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)

        warnings = []
        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://x/a.php?id=1",
            use_native_tools=False, knowledge_base=KnowledgeBase(path=kb_path),
            on_event=lambda kind, payload: warnings.append(payload) if kind == "warning" else None,
        )

        finished = planner.step()

        self.assertFalse(finished)
        self.assertTrue(any("Blocked finish" in str(w) for w in warnings))
        os.remove(kb_path) if os.path.exists(kb_path) else None

    def test_finish_after_get_findings_is_allowed(self):
        script = [
            {"thought": "check", "action": {"name": "get_findings", "args": {}}},
            {"thought": "done", "action": {"name": "finish", "args": {"summary": "nothing found"}}},
        ]
        engine = FakeEngine()
        ollama = FakeOllamaJsonFallback(script)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://x/a.php?id=1",
            use_native_tools=False, knowledge_base=KnowledgeBase(path=kb_path),
        )

        planner.step()  # get_findings
        finished = planner.step()  # finish - should now be allowed

        self.assertTrue(finished)
        os.remove(kb_path) if os.path.exists(kb_path) else None

    def test_finish_after_check_status_is_allowed(self):
        script = [
            {"thought": "check", "action": {"name": "check_status", "args": {}}},
            {"thought": "done", "action": {"name": "finish", "args": {"summary": "nothing running"}}},
        ]
        engine = FakeEngine()
        ollama = FakeOllamaJsonFallback(script)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://x/a.php?id=1",
            use_native_tools=False, knowledge_base=KnowledgeBase(path=kb_path),
        )

        planner.step()
        finished = planner.step()

        self.assertTrue(finished)
        os.remove(kb_path) if os.path.exists(kb_path) else None


class FakeOllamaScripted(object):
    def __init__(self, replies):
        self.replies = list(replies)

    def chat(self, messages, tools=None, json_mode=True):
        return self.replies.pop(0) if self.replies else {"content": ""}


class TestMalformedReplyRobustness(unittest.TestCase):
    """
    A model reply is untrusted, unvalidated-by-construction output - a
    malformed or hallucinated reply can have "action" be a string/number/
    list instead of an object, "args" likewise, or a native tool_calls
    entry missing/misshaping "function". step() must treat every one of
    these the same way it already treats a plain unparseable reply
    (emit a warning, record a nudge-to-retry observation, return False)
    rather than let an AttributeError/TypeError escape and crash the
    whole autonomous run - previously _parse_reply() assumed every one
    of these shapes without checking, and every case below did crash it.
    """

    MALFORMED_REPLIES = [
        {"content": '{"thought": "x", "action": "not_a_dict"}'},
        {"content": '{"thought": "x", "action": 12345}'},
        {"content": '{"thought": "x", "action": [1,2,3]}'},
        {"content": '{"thought": "x", "action": null}'},
        {"content": '{"action": {"name": "note", "args": "not_a_dict"}}'},
        {"content": '{"action": {"name": "note", "args": [1,2,3]}}'},
        {"content": '{"action": {"name": "note", "args": 42}}'},
        {"tool_calls": [{"function": "not_a_dict"}]},
        {"tool_calls": ["not_a_dict"]},
        {"tool_calls": [{"function": {"name": "note", "arguments": "not json {{{"}}]},
        {"tool_calls": [{"function": {}}]},
        {"tool_calls": []},
        {"content": "not json at all"},
        {"content": ""},
        {},
    ]

    def test_parse_reply_never_raises_and_never_returns_non_dict_args(self):
        for reply in self.MALFORMED_REPLIES:
            # _parse_reply doesn't touch self, so this exercises the pure
            # parsing logic directly without needing a full planner.
            name, args, thought, record = AgentPlanner._parse_reply(None, reply)
            self.assertTrue(args is None or isinstance(args, dict),
                             "reply %r produced non-dict args: %r" % (reply, args))

    def test_full_step_never_raises_on_any_malformed_reply(self):
        for reply in self.MALFORMED_REPLIES:
            engine = FakeEngine()
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
                kb_path = f.name
            os.remove(kb_path)

            planner = AgentPlanner(
                engine, engine.new_task(), FakeOllamaScripted([reply]),
                goal="test goal", target="http://x/a.php?id=1",
                knowledge_base=KnowledgeBase(path=kb_path),
            )
            try:
                finished = planner.step()
            except Exception as e:
                self.fail("reply %r crashed step() with %s: %s" % (reply, type(e).__name__, e))
            self.assertFalse(finished, "a malformed reply should never count as finishing")
            os.remove(kb_path) if os.path.exists(kb_path) else None

    def test_valid_native_tool_call_with_json_string_arguments_still_works(self):
        # some models return `arguments` as a JSON-encoded string rather than
        # a native object - this is NOT malformed, must keep working.
        reply = {"tool_calls": [{"function": {"name": "note", "arguments": '{"text": "hi"}'}}]}
        name, args, thought, record = AgentPlanner._parse_reply(None, reply)
        self.assertEqual(name, "note")
        self.assertEqual(args, {"text": "hi"})


class TestNosqlAgentEndToEnd(unittest.TestCase):
    """
    Every prior NoSQL-related test exercises one layer at a time: probe()
    directly against a live target (test_nosql.py's
    TestInjectionProbeLiveIntegration), mongo_client.py against a fake
    in-memory pymongo (test_mongo_client_fake_server.py), or
    ToolExecutor.execute("nosql_*", ...) directly with a mocked engine
    (test_nosql.py's TestNosqlToolWiring). None of them verify the actual
    thing an operator relies on: that the autonomous agent LOOP - a
    scripted model deciding to call nosql_test_injection, safety checking
    that call, the tool executing it for real, the observation feeding
    back into the model's next decision, and grounding_check validating
    the final summary - works end to end for the NoSQL path the same way
    TestPlannerJsonFallback/TestPlannerGroundingIntegration already prove
    it does for the SQL path.

    Skipped automatically if the operator-injection live target (see
    lib/ai/tests/live_targets/operator_injection_target.py) isn't running
    on 127.0.0.1:9380, same pattern as test_nosql.py's live-integration
    tests - this genuinely needs a real HTTP server, not a mock.
    """

    def _require_live_target(self):
        import socket
        try:
            socket.create_connection(("127.0.0.1", 9380), timeout=1).close()
        except OSError:
            self.skipTest("operator-injection test target not running on 127.0.0.1:9380")

    def test_full_agent_loop_confirms_real_nosql_injection(self):
        self._require_live_target()

        script = [
            {"thought": "Set the target.",
             "action": {"name": "set_target", "args": {"url": "http://127.0.0.1:9380/lookup?id=999"}}},
            {"thought": "Test the id parameter for NoSQL operator injection.",
             "action": {"name": "nosql_test_injection",
                        "args": {"url": "http://127.0.0.1:9380/lookup?id=999", "param": "id"}}},
            {"thought": "Confirmed injectable via response-content anomaly, wrapping up.",
             "action": {"name": "finish",
                        "args": {"summary": "The id parameter at /lookup is vulnerable to NoSQL "
                                             "operator injection - a bracket-syntax payload changed "
                                             "the response from not-found to found."}}},
        ]
        engine = FakeEngine()  # unused by the nosql_* tools, but AgentPlanner always wants one
        ollama = FakeOllamaJsonFallback(script)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal",
            target="http://127.0.0.1:9380/lookup?id=999",
            use_native_tools=False, knowledge_base=KnowledgeBase(path=kb_path),
        )

        report = planner.run()

        # the tool actually ran probe() for real against the live target and
        # got a genuine positive result, not a mocked/assumed one
        tool_events = [e for e in planner.memory.events if e["role"] == "tool"]
        nosql_event = next(e for e in tool_events if e["content"]["action"] == "nosql_test_injection")
        result = nosql_event["content"]["result"]
        self.assertTrue(result["ok"])
        self.assertTrue(result["likely_injectable"])

        # the finish summary was accurate, so grounding_check should raise
        # no caveats - a genuinely successful, evidence-backed NoSQL finding
        self.assertEqual(report["findings"]["notes"], [])

        os.remove(kb_path) if os.path.exists(kb_path) else None

    def test_full_agent_loop_with_only_scan_target_finds_open_access_and_finishes(self):
        # a pure "is this instance even authenticated" engagement - no
        # test_injection, no enumerate, just nosql_scan_target - exercises
        # the finish-gate fix and the nosql_access findings-merge fix
        # together, end to end. Uses a mocked scan_anonymous_access rather
        # than the live HTTP targets (those model MongoDB-behind-a-web-app
        # injection, not a direct MongoDB connection - no real mongod is
        # available in this sandbox, same constraint documented for
        # test_mongo_client_fake_server.py).
        from unittest.mock import patch

        script = [
            {"thought": "Set the target.",
             "action": {"name": "set_target", "args": {"url": "http://10.0.0.5:27017"}}},
            {"thought": "Check whether this MongoDB instance requires authentication.",
             "action": {"name": "nosql_scan_target", "args": {"host": "10.0.0.5", "port": 27017}}},
            {"thought": "Confirmed open access, wrapping up.",
             "action": {"name": "finish",
                        "args": {"summary": "The MongoDB instance at 10.0.0.5:27017 allows fully "
                                             "anonymous access with no authentication required."}}},
        ]
        engine = FakeEngine()
        ollama = FakeOllamaJsonFallback(script)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://10.0.0.5:27017",
            use_native_tools=False, knowledge_base=KnowledgeBase(path=kb_path),
        )

        fake_scan_result = {"status": "open", "version": "5.0.9", "database_count": 3}
        with patch("lib.nosql.mongo_client.scan_anonymous_access", return_value=fake_scan_result):
            report = planner.run()

        self.assertEqual(report["findings"]["nosql_access"], [
            {"backend": "mongodb", "host": "10.0.0.5", "port": 27017, "status": "open",
             "version": "5.0.9", "database_count": 3},
        ])
        # finish gate correctly treated nosql_scan_target as evidence, so
        # the run completed cleanly rather than burning its full budget
        self.assertEqual(report["findings"]["notes"], [])

        os.remove(kb_path) if os.path.exists(kb_path) else None

    def test_safety_refuses_nosql_call_against_out_of_scope_host(self):
        self._require_live_target()

        # the model tries to pivot to a host never authorized for this run -
        # SafetyPolicy must refuse this the same way it would for a sqlmap
        # action, even though nosql_test_injection never touches the sqlmap
        # REST engine at all. Drives step() directly rather than run() to
        # completion: a refused call correctly gathers no evidence, so a
        # subsequent finish would correctly be blocked by the hard finish
        # gate too - that's a second, separate mechanism working as
        # intended, not something this test needs to route around.
        engine = FakeEngine()
        ollama = FakeOllamaJsonFallback([
            {"thought": "Set the target.",
             "action": {"name": "set_target", "args": {"url": "http://127.0.0.1:9380/lookup?id=999"}}},
            {"thought": "Try a completely different host.",
             "action": {"name": "nosql_test_injection",
                        "args": {"url": "http://evil.example.org/lookup?id=999", "param": "id"}}},
        ])

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal",
            target="http://127.0.0.1:9380/lookup?id=999",
            use_native_tools=False, knowledge_base=KnowledgeBase(path=kb_path),
        )

        planner.step()  # set_target
        planner.step()  # the out-of-scope nosql_test_injection attempt

        tool_events = [e for e in planner.memory.events if e["role"] == "tool"]
        nosql_event = next(e for e in tool_events if e["content"]["action"] == "nosql_test_injection")
        result = nosql_event["content"]["result"]

        # refused, and critically never actually ran probe() against the
        # unauthorized host - a scope check that fires only after the
        # request already went out would be worthless.
        self.assertFalse(result["ok"])
        self.assertIn("scope", result["error"].lower())
        self.assertNotIn("likely_injectable", result)

        os.remove(kb_path) if os.path.exists(kb_path) else None


class TestRedisAgentEndToEnd(unittest.TestCase):
    """
    Same standard as TestNosqlAgentEndToEnd above, for Redis: drives a
    real AgentPlanner.run() against the real fake_redis_server.py (real
    RESP2 protocol over a real socket, not a mock), applying the lesson
    from §17 (an end-to-end run finds wiring bugs no per-layer test
    catches) proactively this time rather than after the fact.
    """

    def _require_live_server(self, port):
        import socket
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
        except OSError:
            self.skipTest("fake redis server not running on 127.0.0.1:%d" % port)

    def test_full_agent_loop_confirms_real_redis_open_access_and_dumps_keys(self):
        self._require_live_server(9382)

        script = [
            {"thought": "Set the target.",
             "action": {"name": "set_target", "args": {"url": "http://127.0.0.1:9382"}}},
            {"thought": "Check whether this Redis instance requires authentication.",
             "action": {"name": "redis_scan_target", "args": {"host": "127.0.0.1", "port": 9382}}},
            {"thought": "Enumerate keys.",
             "action": {"name": "redis_enumerate_keys", "args": {"host": "127.0.0.1", "port": 9382}}},
            {"thought": "Dump a couple of interesting-looking keys.",
             "action": {"name": "redis_dump_keys",
                        "args": {"host": "127.0.0.1", "port": 9382, "keys": ["session:abc123", "user:42"]}}},
            {"thought": "Confirmed, wrapping up.",
             "action": {"name": "finish",
                        "args": {"summary": "The Redis instance at 127.0.0.1:9382 allows fully anonymous "
                                             "access with no authentication required, and contains "
                                             "session and user data readable by anyone."}}},
        ]
        engine = FakeEngine()
        ollama = FakeOllamaJsonFallback(script)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)

        # redis_dump_keys is correctly gated as HIGH_RISK (matching
        # nosql_dump_collection's severity - see lib/ai/safety.py's
        # HIGH_RISK_ACTIONS) - yolo=True here is the test's stand-in for
        # --agent-yolo, needed for the dump to actually proceed rather
        # than sit blocked pending operator confirmation.
        safety = SafetyPolicy(allowed_hosts=["127.0.0.1"], yolo=True)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://127.0.0.1:9382",
            use_native_tools=False, knowledge_base=KnowledgeBase(path=kb_path), safety_policy=safety,
        )

        report = planner.run()

        # the tools actually ran the real RESP2 protocol against the live
        # fake server and got genuine positive results, not mocked ones
        tool_events = {e["content"]["action"]: e["content"]["result"] for e in planner.memory.events
                       if e["role"] == "tool"}
        self.assertTrue(tool_events["redis_scan_target"]["ok"])
        self.assertEqual(tool_events["redis_scan_target"]["result"]["status"], "open")
        self.assertTrue(tool_events["redis_dump_keys"]["ok"])
        self.assertEqual(tool_events["redis_dump_keys"]["count"], 2)

        # findings-merge and finish-gate fixes both worked: nosql_access
        # was populated (as a redis-backend entry), the run passed the
        # finish gate cleanly, and the accurate summary produced no
        # grounding-check caveats
        self.assertEqual(report["findings"]["nosql_access"][0]["backend"], "redis")
        self.assertEqual(report["findings"]["nosql_access"][0]["status"], "open")
        self.assertEqual(len(report["findings"]["dumped_tables"]), 1)
        self.assertEqual(report["findings"]["notes"], [])

        os.remove(kb_path) if os.path.exists(kb_path) else None

    def test_safety_refuses_redis_dump_against_out_of_scope_host(self):
        self._require_live_server(9382)

        engine = FakeEngine()
        ollama = FakeOllamaJsonFallback([
            {"thought": "Set the target.",
             "action": {"name": "set_target", "args": {"url": "http://127.0.0.1:9382"}}},
            {"thought": "Try a completely different host.",
             "action": {"name": "redis_dump_keys",
                        "args": {"host": "evil.example.org", "port": 6379, "keys": ["flag"]}}},
        ])

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://127.0.0.1:9382",
            use_native_tools=False, knowledge_base=KnowledgeBase(path=kb_path),
        )

        planner.step()  # set_target
        planner.step()  # the out-of-scope redis_dump_keys attempt

        tool_events = [e for e in planner.memory.events if e["role"] == "tool"]
        redis_event = next(e for e in tool_events if e["content"]["action"] == "redis_dump_keys")
        result = redis_event["content"]["result"]

        self.assertFalse(result["ok"])
        self.assertIn("scope", result["error"].lower())
        self.assertEqual(planner.memory.findings["dumped_tables"], [])

        os.remove(kb_path) if os.path.exists(kb_path) else None


class TestElasticsearchAgentEndToEnd(unittest.TestCase):
    """Third backend, same standard as TestNosqlAgentEndToEnd/TestRedisAgentEndToEnd -
    a real AgentPlanner.run() against the real fake_elasticsearch_server.py."""

    def _require_live_server(self, port):
        import socket
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
        except OSError:
            self.skipTest("fake elasticsearch server not running on 127.0.0.1:%d" % port)

    def test_full_agent_loop_confirms_real_elasticsearch_open_access_and_dumps_index(self):
        self._require_live_server(9384)

        script = [
            {"thought": "Set the target.",
             "action": {"name": "set_target", "args": {"url": "http://127.0.0.1:9384"}}},
            {"thought": "Check whether this Elasticsearch instance requires authentication.",
             "action": {"name": "elasticsearch_scan_target", "args": {"host": "127.0.0.1", "port": 9384}}},
            {"thought": "Enumerate indices.",
             "action": {"name": "elasticsearch_enumerate_indices", "args": {"host": "127.0.0.1", "port": 9384}}},
            {"thought": "Dump the users index.",
             "action": {"name": "elasticsearch_dump_index",
                        "args": {"host": "127.0.0.1", "port": 9384, "index": "users"}}},
            {"thought": "Confirmed, wrapping up.",
             "action": {"name": "finish",
                        "args": {"summary": "The Elasticsearch instance at 127.0.0.1:9384 allows fully "
                                             "anonymous access with no authentication required, exposing "
                                             "a users index with plaintext email addresses."}}},
        ]
        engine = FakeEngine()
        ollama = FakeOllamaJsonFallback(script)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)

        # elasticsearch_dump_index is HIGH_RISK, same as redis_dump_keys -
        # yolo=True stands in for --agent-yolo so the dump actually runs.
        safety = SafetyPolicy(allowed_hosts=["127.0.0.1"], yolo=True)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://127.0.0.1:9384",
            use_native_tools=False, knowledge_base=KnowledgeBase(path=kb_path), safety_policy=safety,
        )

        report = planner.run()

        tool_events = {e["content"]["action"]: e["content"]["result"] for e in planner.memory.events
                       if e["role"] == "tool"}
        self.assertTrue(tool_events["elasticsearch_scan_target"]["ok"])
        self.assertEqual(tool_events["elasticsearch_scan_target"]["result"]["status"], "open")
        self.assertTrue(tool_events["elasticsearch_dump_index"]["ok"])
        self.assertEqual(tool_events["elasticsearch_dump_index"]["count"], 3)

        self.assertEqual(report["findings"]["nosql_access"][0]["backend"], "elasticsearch")
        self.assertEqual(report["findings"]["nosql_access"][0]["status"], "open")
        self.assertEqual(len(report["findings"]["dumped_tables"]), 1)
        self.assertEqual(report["findings"]["notes"], [])

        os.remove(kb_path) if os.path.exists(kb_path) else None

    def test_safety_refuses_elasticsearch_dump_against_out_of_scope_host(self):
        self._require_live_server(9384)

        engine = FakeEngine()
        ollama = FakeOllamaJsonFallback([
            {"thought": "Set the target.",
             "action": {"name": "set_target", "args": {"url": "http://127.0.0.1:9384"}}},
            {"thought": "Try a completely different host.",
             "action": {"name": "elasticsearch_dump_index",
                        "args": {"host": "evil.example.org", "port": 9200, "index": "flag"}}},
        ])

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://127.0.0.1:9384",
            use_native_tools=False, knowledge_base=KnowledgeBase(path=kb_path),
        )

        planner.step()  # set_target
        planner.step()  # the out-of-scope elasticsearch_dump_index attempt

        tool_events = [e for e in planner.memory.events if e["role"] == "tool"]
        es_event = next(e for e in tool_events if e["content"]["action"] == "elasticsearch_dump_index")
        result = es_event["content"]["result"]

        self.assertFalse(result["ok"])
        self.assertIn("scope", result["error"].lower())
        self.assertEqual(planner.memory.findings["dumped_tables"], [])

        os.remove(kb_path) if os.path.exists(kb_path) else None


class TestCouchDBAgentEndToEnd(unittest.TestCase):
    """Fourth backend, same standard as the other three - a real AgentPlanner.run()
    against the real fake_couchdb_server.py."""

    def _require_live_server(self, port):
        import socket
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
        except OSError:
            self.skipTest("fake couchdb server not running on 127.0.0.1:%d" % port)

    def test_full_agent_loop_confirms_real_couchdb_open_access_and_dumps_database(self):
        self._require_live_server(9386)

        script = [
            {"thought": "Set the target.",
             "action": {"name": "set_target", "args": {"url": "http://127.0.0.1:9386"}}},
            {"thought": "Check whether this CouchDB instance requires authentication.",
             "action": {"name": "couchdb_scan_target", "args": {"host": "127.0.0.1", "port": 9386}}},
            {"thought": "Enumerate databases.",
             "action": {"name": "couchdb_enumerate_databases", "args": {"host": "127.0.0.1", "port": 9386}}},
            {"thought": "Dump the customers database.",
             "action": {"name": "couchdb_dump_database",
                        "args": {"host": "127.0.0.1", "port": 9386, "database": "customers"}}},
            {"thought": "Confirmed, wrapping up.",
             "action": {"name": "finish",
                        "args": {"summary": "The CouchDB instance at 127.0.0.1:9386 allows fully "
                                             "anonymous access with no authentication required, "
                                             "exposing a customers database with plaintext emails."}}},
        ]
        engine = FakeEngine()
        ollama = FakeOllamaJsonFallback(script)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)

        # couchdb_dump_database is HIGH_RISK, same as the other three dump
        # tools - yolo=True stands in for --agent-yolo so it actually runs.
        safety = SafetyPolicy(allowed_hosts=["127.0.0.1"], yolo=True)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://127.0.0.1:9386",
            use_native_tools=False, knowledge_base=KnowledgeBase(path=kb_path), safety_policy=safety,
        )

        report = planner.run()

        tool_events = {e["content"]["action"]: e["content"]["result"] for e in planner.memory.events
                       if e["role"] == "tool"}
        self.assertTrue(tool_events["couchdb_scan_target"]["ok"])
        self.assertEqual(tool_events["couchdb_scan_target"]["result"]["status"], "open")
        self.assertTrue(tool_events["couchdb_dump_database"]["ok"])
        self.assertEqual(tool_events["couchdb_dump_database"]["count"], 2)  # design doc filtered out

        self.assertEqual(report["findings"]["nosql_access"][0]["backend"], "couchdb")
        self.assertEqual(report["findings"]["nosql_access"][0]["status"], "open")
        self.assertEqual(len(report["findings"]["dumped_tables"]), 1)
        self.assertEqual(report["findings"]["notes"], [])

        os.remove(kb_path) if os.path.exists(kb_path) else None

    def test_safety_refuses_couchdb_dump_against_out_of_scope_host(self):
        self._require_live_server(9386)

        engine = FakeEngine()
        ollama = FakeOllamaJsonFallback([
            {"thought": "Set the target.",
             "action": {"name": "set_target", "args": {"url": "http://127.0.0.1:9386"}}},
            {"thought": "Try a completely different host.",
             "action": {"name": "couchdb_dump_database",
                        "args": {"host": "evil.example.org", "port": 5984, "database": "flag"}}},
        ])

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            kb_path = f.name
        os.remove(kb_path)

        planner = AgentPlanner(
            engine, engine.new_task(), ollama, goal="test goal", target="http://127.0.0.1:9386",
            use_native_tools=False, knowledge_base=KnowledgeBase(path=kb_path),
        )

        planner.step()  # set_target
        planner.step()  # the out-of-scope couchdb_dump_database attempt

        tool_events = [e for e in planner.memory.events if e["role"] == "tool"]
        couch_event = next(e for e in tool_events if e["content"]["action"] == "couchdb_dump_database")
        result = couch_event["content"]["result"]

        self.assertFalse(result["ok"])
        self.assertIn("scope", result["error"].lower())
        self.assertEqual(planner.memory.findings["dumped_tables"], [])

        os.remove(kb_path) if os.path.exists(kb_path) else None


if __name__ == "__main__":
    unittest.main()
