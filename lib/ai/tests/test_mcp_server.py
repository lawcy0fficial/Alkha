#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Unit-level tests for McpServer.handle_line() - feeds JSON-RPC lines
directly against an in-memory stdout (io.StringIO) and a FakeEngine, no
real subprocess or stdio needed. See test_mcp_server_e2e.py for the
real-subprocess, real-protocol-over-real-pipes version of this
coverage, matching this project's established two-layer testing
pattern (protocol-level unit tests + live end-to-end).
"""

import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from lib.ai.mcp_server import McpServer, tool_list_for_mcp, build_default_safety_policy
from lib.ai.tools import TOOL_SPECS


class FakeEngine(object):
    def __init__(self):
        self.taskid = "faketask"
        self.stopped = False

    def new_task(self):
        return self.taskid

    def start_scan(self, taskid, opts):
        return {"success": True}

    def stop_scan(self, taskid):
        self.stopped = True
        return {"success": True}

    def scan_status(self, taskid):
        return {"status": "terminated"}

    def scan_data(self, taskid):
        return {"success": True, "data": []}

    def scan_log(self, taskid, start=None, end=None):
        return {"success": True, "log": []}


def _server(yolo=False, allowed_hosts=("example.com",)):
    engine = FakeEngine()
    safety = build_default_safety_policy(list(allowed_hosts), yolo=yolo)
    safety.start()
    stdout = io.StringIO()
    server = McpServer(engine, engine.new_task(), safety, stdin=io.StringIO(""), stdout=stdout)
    return server, stdout


def _last_message(stdout):
    lines = [l for l in stdout.getvalue().splitlines() if l.strip()]
    return json.loads(lines[-1])


class TestInitializeHandshake(unittest.TestCase):
    def test_initialize_returns_protocol_version_and_server_info(self):
        server, stdout = _server()
        server.handle_line(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}))
        msg = _last_message(stdout)
        self.assertEqual(msg["id"], 1)
        self.assertIn("protocolVersion", msg["result"])
        self.assertEqual(msg["result"]["serverInfo"]["name"], "alkha")
        self.assertIn("tools", msg["result"]["capabilities"])

    def test_notifications_initialized_produces_no_response(self):
        server, stdout = _server()
        server.handle_line(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        self.assertEqual(stdout.getvalue(), "")

    def test_ping_responds_with_empty_result(self):
        server, stdout = _server()
        server.handle_line(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}))
        msg = _last_message(stdout)
        self.assertEqual(msg["result"], {})


class TestMalformedInputRobustness(unittest.TestCase):
    """
    Input here is a raw line from an external process over stdio -
    about as untrusted as input gets in this codebase. Every case below
    must degrade gracefully (a JSON-RPC error, or silent drop for
    genuinely unparseable/id-less input per JSON-RPC convention), never
    crash the server process or write anything malformed to stdout.
    """

    def test_malformed_json_is_silently_dropped(self):
        server, stdout = _server()
        server.handle_line("not json at all {{{")
        self.assertEqual(stdout.getvalue(), "")

    def test_json_non_object_top_level_is_silently_dropped(self):
        server, stdout = _server()
        server.handle_line("[1, 2, 3]")
        server.handle_line("42")
        server.handle_line("null")
        self.assertEqual(stdout.getvalue(), "")

    def test_unknown_method_returns_json_rpc_error(self):
        server, stdout = _server()
        server.handle_line(json.dumps({"jsonrpc": "2.0", "id": 5, "method": "not/a/real/method"}))
        msg = _last_message(stdout)
        self.assertEqual(msg["id"], 5)
        self.assertIn("error", msg)
        self.assertEqual(msg["error"]["code"], -32601)

    def test_unknown_method_as_notification_produces_no_response(self):
        server, stdout = _server()
        server.handle_line(json.dumps({"jsonrpc": "2.0", "method": "not/a/real/method"}))
        self.assertEqual(stdout.getvalue(), "")

    def test_tools_call_with_missing_name_does_not_crash(self):
        server, stdout = _server()
        server.handle_line(json.dumps({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                                        "params": {"arguments": {}}}))
        msg = _last_message(stdout)
        self.assertTrue(msg["result"]["isError"])

    def test_tools_call_with_non_object_arguments_is_rejected_not_crashed(self):
        server, stdout = _server()
        for bad_args in ("a string", 42, ["a", "list"], None):
            server.handle_line(json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                                            "params": {"name": "check_status", "arguments": bad_args}}))
            msg = _last_message(stdout)
            if bad_args is None:
                # None is the normal "no arguments supplied" case, same as
                # the planner's own args-defaults-to-{} convention
                continue
            self.assertTrue(msg["result"]["isError"], "bad_args=%r should be rejected" % (bad_args,))

    def test_tools_call_params_missing_entirely_does_not_crash(self):
        server, stdout = _server()
        server.handle_line(json.dumps({"jsonrpc": "2.0", "id": 8, "method": "tools/call"}))
        msg = _last_message(stdout)
        self.assertTrue(msg["result"]["isError"])


class TestToolsList(unittest.TestCase):
    def test_returns_every_tool_spec_with_a_schema(self):
        server, stdout = _server()
        server.handle_line(json.dumps({"jsonrpc": "2.0", "id": 9, "method": "tools/list"}))
        msg = _last_message(stdout)
        names = {t["name"] for t in msg["result"]["tools"]}
        self.assertEqual(names, {spec["name"] for spec in TOOL_SPECS})
        for tool in msg["result"]["tools"]:
            self.assertIn("inputSchema", tool)
            self.assertEqual(tool["inputSchema"]["type"], "object")

    def test_required_args_are_marked_required_in_schema(self):
        tools = {t["name"]: t for t in tool_list_for_mcp()}
        self.assertIn("url", tools["set_target"]["inputSchema"]["required"])

    def test_no_generic_shell_or_exec_tool_exists(self):
        # the one invariant this whole feature must never violate - see
        # lib/ai/mcp_server.py's and lib/ai/tools.py's module docstrings.
        # os_cmd is NOT a violation of this: it's one specific, named
        # action mapped to sqlmap's own pre-existing --os-cmd feature,
        # HIGH_RISK-gated exactly like dump_table (see
        # test_os_cmd_and_file_read_are_high_risk_gated below) - what
        # must never exist is a generic/unrestricted execute-anything
        # tool, which these names would represent.
        names = {spec["name"] for spec in TOOL_SPECS}
        for forbidden in ("shell", "exec", "run_command", "run_shell", "execute_command", "eval"):
            self.assertNotIn(forbidden, names)

    def test_os_cmd_and_file_read_are_high_risk_gated(self):
        # confirms the two intentionally-added OS/filesystem-reaching
        # tools are gated the same way dump_table is, not reachable
        # without yolo/confirmation - see lib/ai/safety.py.
        from lib.ai.safety import HIGH_RISK_ACTIONS
        self.assertIn("os_cmd", HIGH_RISK_ACTIONS)
        self.assertIn("file_read", HIGH_RISK_ACTIONS)


class TestSafetyIntegration(unittest.TestCase):
    """
    The whole point of this server is that it never bypasses
    lib/ai/safety.py - these tests exist to prove that claim, not just
    assert it in a docstring.
    """

    def test_high_risk_action_refused_without_yolo(self):
        server, stdout = _server(yolo=False)
        server.handle_line(json.dumps({"jsonrpc": "2.0", "id": 10, "method": "tools/call",
                                        "params": {"name": "dump_table",
                                                    "args": {}, "arguments": {"db": "d", "table": "t"}}}))
        msg = _last_message(stdout)
        self.assertTrue(msg["result"]["isError"])
        self.assertIn("high-risk", msg["result"]["content"][0]["text"].lower())

    def test_high_risk_action_allowed_with_yolo(self):
        server, stdout = _server(yolo=True)
        server.handle_line(json.dumps({"jsonrpc": "2.0", "id": 11, "method": "tools/call",
                                        "params": {"name": "dump_table",
                                                    "arguments": {"db": "d", "table": "t"}}}))
        msg = _last_message(stdout)
        self.assertFalse(msg["result"]["isError"])

    def test_out_of_scope_host_is_refused(self):
        server, stdout = _server(allowed_hosts=["example.com"])
        server.handle_line(json.dumps({"jsonrpc": "2.0", "id": 12, "method": "tools/call",
                                        "params": {"name": "set_target",
                                                    "arguments": {"url": "http://evil.example.org/a.php"}}}))
        msg = _last_message(stdout)
        self.assertTrue(msg["result"]["isError"])
        self.assertIn("scope", msg["result"]["content"][0]["text"].lower())

    def test_in_scope_host_is_allowed(self):
        server, stdout = _server(allowed_hosts=["example.com"])
        server.handle_line(json.dumps({"jsonrpc": "2.0", "id": 13, "method": "tools/call",
                                        "params": {"name": "set_target",
                                                    "arguments": {"url": "http://example.com/a.php"}}}))
        msg = _last_message(stdout)
        self.assertFalse(msg["result"]["isError"])

    def test_iteration_budget_exceeded_is_reported_as_tool_error(self):
        server, stdout = _server()
        server.safety.max_iterations = 1
        server.handle_line(json.dumps({"jsonrpc": "2.0", "id": 14, "method": "tools/call",
                                        "params": {"name": "check_status", "arguments": {}}}))
        server.handle_line(json.dumps({"jsonrpc": "2.0", "id": 15, "method": "tools/call",
                                        "params": {"name": "check_status", "arguments": {}}}))
        msg = _last_message(stdout)
        self.assertTrue(msg["result"]["isError"])


class TestToolCallResultShape(unittest.TestCase):
    def test_successful_call_result_is_valid_json_in_text_content(self):
        server, stdout = _server()
        server.handle_line(json.dumps({"jsonrpc": "2.0", "id": 16, "method": "tools/call",
                                        "params": {"name": "check_status", "arguments": {}}}))
        msg = _last_message(stdout)
        self.assertFalse(msg["result"]["isError"])
        payload = json.loads(msg["result"]["content"][0]["text"])
        self.assertTrue(payload["ok"])


if __name__ == "__main__":
    unittest.main()
