#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from lib.ai.api_bootstrap import ApiBootstrapError, ensure_server_running, find_alkhaapi_path, shutdown


class _FakeProc(object):
    """Stands in for subprocess.Popen without spawning a real process."""

    def __init__(self, exits_immediately=False, returncode=1, output=""):
        self.pid = 4242
        self.terminated = False
        self.killed = False
        self._waited = False
        self._exits_immediately = exits_immediately
        self.returncode = returncode if exits_immediately else None
        self._output = output
        self.stdout = _FakeStdout(output)

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = 0

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        self._waited = True
        return self.returncode


class _FakeStdout(object):
    def __init__(self, text):
        self._text = text

    def read(self):
        return self._text


def _fake_popen_factory(fake_proc):
    def _popen(cmd, **kwargs):
        return fake_proc
    return _popen


class TestFindAlkhaapiPath(unittest.TestCase):
    def test_resolves_to_repository_root(self):
        path = find_alkhaapi_path()
        self.assertTrue(path.endswith(os.path.join("", "alkhaapi.py")))
        # lib/ai/api_bootstrap.py -> lib/ai -> lib -> repo root
        expected_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "api_bootstrap.py")))))
        self.assertEqual(os.path.normpath(path), os.path.normpath(os.path.join(expected_root, "alkhaapi.py")))


class TestEnsureServerRunning(unittest.TestCase):
    def setUp(self):
        # ensure_server_running checks the path actually exists before spawning
        # anything (a real safety property, not just an implementation detail),
        # so tests that get past the "already reachable" short-circuit need a
        # real (if empty/unused) file on disk to point alkhaapi_path at.
        self._tmp = tempfile.NamedTemporaryFile(prefix="fake_alkhaapi_", suffix=".py", delete=False)
        self._tmp.close()
        self.fake_alkhaapi_path = self._tmp.name

    def tearDown(self):
        try:
            os.unlink(self.fake_alkhaapi_path)
        except OSError:
            pass

    def test_already_reachable_returns_none_and_spawns_nothing(self):
        calls = []

        def popen_fn(cmd, **kwargs):
            calls.append(cmd)
            raise AssertionError("should not spawn a process when the port is already open")

        result = ensure_server_running(
            "127.0.0.1", 8775,
            port_check_fn=lambda host, port, timeout=1.0: True,
            popen_fn=popen_fn,
        )

        self.assertIsNone(result)
        self.assertEqual(calls, [])

    def test_non_loopback_host_with_nothing_listening_raises_clear_error(self):
        with self.assertRaises(ApiBootstrapError) as ctx:
            ensure_server_running(
                "10.0.0.5", 8775,
                port_check_fn=lambda host, port, timeout=1.0: False,
                popen_fn=lambda cmd, **kwargs: (_ for _ in ()).throw(AssertionError("must not spawn")),
            )

        self.assertIn("not a loopback address", str(ctx.exception))
        self.assertIn("10.0.0.5", str(ctx.exception))

    def test_missing_alkhaapi_path_raises_before_spawning(self):
        with self.assertRaises(ApiBootstrapError) as ctx:
            ensure_server_running(
                "127.0.0.1", 8775,
                port_check_fn=lambda host, port, timeout=1.0: False,
                popen_fn=lambda cmd, **kwargs: (_ for _ in ()).throw(AssertionError("must not spawn")),
                alkhaapi_path="/definitely/not/a/real/path/alkhaapi.py",
            )

        self.assertIn("not found", str(ctx.exception))

    def test_spawns_and_returns_proc_once_port_opens(self):
        fake_proc = _FakeProc()
        # first port check (pre-spawn) says closed; every check after spawning says open
        checks = {"n": 0}

        def port_check_fn(host, port, timeout=1.0):
            checks["n"] += 1
            return checks["n"] > 1

        result = ensure_server_running(
            "127.0.0.1", 8775,
            port_check_fn=port_check_fn,
            popen_fn=_fake_popen_factory(fake_proc),
            alkhaapi_path=self.fake_alkhaapi_path,
            poll_interval=0,
        )

        self.assertIs(result, fake_proc)

    def test_process_exiting_early_raises_with_captured_output(self):
        fake_proc = _FakeProc(exits_immediately=True, returncode=3, output="Traceback: boom")

        with self.assertRaises(ApiBootstrapError) as ctx:
            ensure_server_running(
                "127.0.0.1", 8775,
                port_check_fn=lambda host, port, timeout=1.0: False,
                popen_fn=_fake_popen_factory(fake_proc),
                alkhaapi_path=self.fake_alkhaapi_path,
                poll_interval=0,
            )

        self.assertIn("exit code 3", str(ctx.exception))
        self.assertIn("boom", str(ctx.exception))

    def test_timeout_terminates_process_and_raises(self):
        fake_proc = _FakeProc()  # never exits, port never opens

        with self.assertRaises(ApiBootstrapError) as ctx:
            ensure_server_running(
                "127.0.0.1", 8775,
                port_check_fn=lambda host, port, timeout=1.0: False,
                popen_fn=_fake_popen_factory(fake_proc),
                alkhaapi_path=self.fake_alkhaapi_path,
                startup_timeout=0.05,
                poll_interval=0.01,
            )

        self.assertIn("Timed out", str(ctx.exception))
        self.assertTrue(fake_proc.terminated)

    def test_username_password_and_flags_are_passed_through(self):
        captured = {}

        def popen_fn(cmd, **kwargs):
            captured["cmd"] = cmd
            return _FakeProc()

        checks = {"n": 0}

        def port_check_fn(host, port, timeout=1.0):
            checks["n"] += 1
            return checks["n"] > 1

        ensure_server_running(
            "127.0.0.1", 8775, username="bob", password="s3cret",
            insecure=True, allow_dangerous_options=True,
            port_check_fn=port_check_fn,
            popen_fn=popen_fn,
            alkhaapi_path=self.fake_alkhaapi_path,
            poll_interval=0,
        )

        cmd = captured["cmd"]
        self.assertIn("--username", cmd)
        self.assertIn("bob", cmd)
        self.assertIn("--password", cmd)
        self.assertIn("s3cret", cmd)
        self.assertIn("--insecure-api", cmd)
        self.assertIn("--allow-dangerous-options", cmd)

    def test_on_event_receives_progress_messages(self):
        events = []
        fake_proc = _FakeProc()
        checks = {"n": 0}

        def port_check_fn(host, port, timeout=1.0):
            checks["n"] += 1
            return checks["n"] > 1

        ensure_server_running(
            "127.0.0.1", 8775,
            port_check_fn=port_check_fn,
            popen_fn=_fake_popen_factory(fake_proc),
            alkhaapi_path=self.fake_alkhaapi_path,
            poll_interval=0,
            on_event=events.append,
        )

        self.assertTrue(any("auto-starting" in e for e in events))
        self.assertTrue(any("up at" in e for e in events))


class TestShutdown(unittest.TestCase):
    def test_none_is_a_safe_noop(self):
        shutdown(None)  # must not raise

    def test_already_exited_process_is_left_alone(self):
        fake_proc = _FakeProc(exits_immediately=True, returncode=0)
        shutdown(fake_proc)
        self.assertFalse(fake_proc.terminated)

    def test_running_process_is_terminated(self):
        fake_proc = _FakeProc()
        shutdown(fake_proc)
        self.assertTrue(fake_proc.terminated)

    def test_falls_back_to_kill_if_terminate_does_not_finish_in_time(self):
        fake_proc = _FakeProc()

        def wait(timeout=None):
            raise Exception("simulated hang")

        fake_proc.wait = wait
        shutdown(fake_proc)
        self.assertTrue(fake_proc.killed)


if __name__ == "__main__":
    unittest.main()
