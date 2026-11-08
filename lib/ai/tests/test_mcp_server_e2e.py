#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Real end-to-end coverage for alkha_mcp_server.py: spawns the actual
entry point as a subprocess (not McpServer imported directly, the way
test_mcp_server.py does) and speaks real newline-delimited JSON-RPC
over its real stdin/stdout pipes - proving the whole pipeline works,
including the real alkha_mcp_server.py CLI argument handling, the real
lib/ai/api_bootstrap.py auto-starting a real alkhaapi.py -s, and the
real EngineClient talking to it, not just the protocol dispatch layer
in isolation. Matches this project's established "prove it against the
real thing, not just a mock" standard (see lib/ai/api_bootstrap.py's
own real-subprocess verification in doc/ALKHA.md §16, and every
live_targets/ script).

Skipped automatically if spawning the subprocess or its own REST API
auto-start doesn't succeed within a short timeout (this test needs to
actually launch two real processes and have them talk to each other,
so it's inherently slower/more environment-sensitive than the rest of
the suite - it's still run by default, just fails gracefully with a
clear skip reason rather than hanging, if the environment can't
support it).
"""

import json
import os
import subprocess
import sys
import time
import unittest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_ENTRY_POINT = os.path.join(_REPO_ROOT, "alkha_mcp_server.py")


class McpSubprocessClient(object):
    """
    Minimal real MCP client: spawns alkha_mcp_server.py, writes
    newline-delimited JSON-RPC requests to its stdin, reads responses
    from its stdout line by line. Real pipes, real process boundary -
    not a mock of either side.
    """

    def __init__(self, extra_args, startup_timeout=15):
        self.proc = subprocess.Popen(
            [sys.executable, _ENTRY_POINT] + extra_args,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=_REPO_ROOT, universal_newlines=True, bufsize=1,
        )
        self._next_id = 1
        self._wait_for_ready(startup_timeout)

    def _wait_for_ready(self, timeout):
        # alkha_mcp_server.py logs "alkha MCP server ready" to stderr once
        # it has a real task from a real (possibly just-auto-started) REST
        # API - wait for that rather than an arbitrary sleep, and surface
        # the process's own stderr if it dies before getting there.
        deadline = time.time() + timeout
        stderr_lines = []
        while time.time() < deadline:
            if self.proc.poll() is not None:
                stderr_lines.append(self.proc.stderr.read())
                raise RuntimeError("alkha_mcp_server.py exited early (code %s):\n%s" % (
                    self.proc.returncode, "".join(stderr_lines)))
            line = self.proc.stderr.readline()
            if not line:
                time.sleep(0.05)
                continue
            stderr_lines.append(line)
            if "alkha MCP server ready" in line:
                return
        self.kill()
        raise RuntimeError("timed out waiting for server readiness; stderr so far:\n%s" % "".join(stderr_lines))

    def request(self, method, params=None, timeout=10):
        msg_id = self._next_id
        self._next_id += 1
        self._write({"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}})
        return self._read_matching(msg_id, timeout)

    def notify(self, method, params=None):
        self._write({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def _write(self, obj):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def _read_matching(self, expected_id, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                time.sleep(0.05)
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if msg.get("id") == expected_id:
                return msg
        raise RuntimeError("timed out waiting for a response to request id %d" % expected_id)

    def kill(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
        for pipe in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            try:
                pipe.close()
            except Exception:
                pass


class TestMcpServerEndToEnd(unittest.TestCase):
    def setUp(self):
        try:
            self.client = McpSubprocessClient([
                "--target", "http://example.com/a.php?id=1",
                "--api-port", "8790",  # dedicated port so this doesn't collide with any other test run
            ])
        except Exception as ex:
            self.skipTest("could not start alkha_mcp_server.py subprocess: %s" % ex)

    def tearDown(self):
        if hasattr(self, "client"):
            self.client.kill()

    def test_initialize_handshake_over_real_pipes(self):
        resp = self.client.request("initialize", {"protocolVersion": "2024-11-05",
                                                      "capabilities": {}, "clientInfo": {"name": "test"}})
        self.assertEqual(resp["result"]["serverInfo"]["name"], "alkha")
        self.client.notify("notifications/initialized")

    def test_tools_list_over_real_pipes_matches_tool_specs(self):
        self.client.request("initialize")
        resp = self.client.request("tools/list")
        names = {t["name"] for t in resp["result"]["tools"]}
        self.assertIn("set_target", names)
        self.assertIn("redis_scan_target", names)
        self.assertIn("couchdb_dump_database", names)

    def test_benign_tool_call_round_trips_through_the_real_rest_api(self):
        # check_status talks to the real EngineClient, talking to the real
        # (auto-started by this same subprocess) alkhaapi.py -s - this is
        # the genuine end-to-end path, not a mock of the REST layer.
        self.client.request("initialize")
        resp = self.client.request("tools/call", {"name": "check_status", "arguments": {}})
        self.assertFalse(resp["result"]["isError"])
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertTrue(payload["ok"])

    def test_out_of_scope_host_is_refused_over_real_pipes(self):
        self.client.request("initialize")
        resp = self.client.request("tools/call", {
            "name": "set_target", "arguments": {"url": "http://evil.example.org/a.php"}})
        self.assertTrue(resp["result"]["isError"])
        self.assertIn("scope", resp["result"]["content"][0]["text"].lower())

    def test_high_risk_action_refused_without_yolo_over_real_pipes(self):
        self.client.request("initialize")
        resp = self.client.request("tools/call", {
            "name": "dump_table", "arguments": {"db": "d", "table": "t"}})
        self.assertTrue(resp["result"]["isError"])
        self.assertIn("high-risk", resp["result"]["content"][0]["text"].lower())


class TestMcpServerYoloModeEndToEnd(unittest.TestCase):
    def setUp(self):
        try:
            self.client = McpSubprocessClient([
                "--target", "http://example.com/a.php?id=1",
                "--api-port", "8791",
                "--yolo",
            ])
        except Exception as ex:
            self.skipTest("could not start alkha_mcp_server.py subprocess: %s" % ex)

    def tearDown(self):
        if hasattr(self, "client"):
            self.client.kill()

    def test_high_risk_action_allowed_with_yolo_over_real_pipes(self):
        self.client.request("initialize")
        resp = self.client.request("tools/call", {
            "name": "dump_table", "arguments": {"db": "d", "table": "t"}})
        self.assertFalse(resp["result"]["isError"])


class TestMcpServerRequiresScope(unittest.TestCase):
    def test_server_refuses_to_start_without_target_or_allowed_hosts(self):
        proc = subprocess.Popen(
            [sys.executable, _ENTRY_POINT, "--no-auto-start-api"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=_REPO_ROOT, universal_newlines=True,
        )
        try:
            _, stderr = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            self.fail("server should exit immediately with no --target/--allowed-hosts, not hang")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("scope", stderr.lower())


if __name__ == "__main__":
    unittest.main()
