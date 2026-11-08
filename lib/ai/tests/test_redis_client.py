#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Two layers of coverage, matching this project's established pattern for
the NoSQL modules:
1. Protocol-level unit tests for _encode_command/_read_reply directly -
   no server needed, exercises the RESP2 implementation itself.
2. Live-integration tests against the real fake_redis_server.py, the
   same "prove it against something actually speaking the protocol"
   standard as lib/ai/tests/test_nosql.py's
   TestInjectionProbeLiveIntegration and
   test_mongo_client_fake_server.py's FakeMongoEnvironment approach.
   Unlike the Mongo tests, this one needs no fake-module sys.modules
   trickery at all - redis_client.py has no external dependency to
   fake out, so these tests exercise the exact code that runs in
   production, talking real RESP2 over a real socket to a real
   (if minimal) server.

Skipped automatically (same pattern as test_nosql.py's live tests) if
the fake Redis server isn't running on the expected ports.
"""

import io
import os
import socket
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from lib.nosql import redis_client as rc

_OPEN_PORT = 9382
_AUTH_PORT = 9383


def _port_open(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        return True
    except OSError:
        return False


class TestRespProtocolEncoding(unittest.TestCase):
    def test_encode_command_matches_resp2_spec(self):
        self.assertEqual(rc._encode_command("PING"), b"*1\r\n$4\r\nPING\r\n")
        self.assertEqual(rc._encode_command("GET", "foo"), b"*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n")

    def test_encode_command_handles_bytes_and_non_string_args(self):
        self.assertEqual(rc._encode_command("SET", "k", 42), b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$2\r\n42\r\n")


class TestRespReplyParsing(unittest.TestCase):
    def _reply_from(self, raw_bytes):
        return rc._read_reply(io.BufferedReader(io.BytesIO(raw_bytes)))

    def test_simple_string(self):
        self.assertEqual(self._reply_from(b"+PONG\r\n"), "PONG")

    def test_error_raises_rediserror(self):
        with self.assertRaises(rc.RedisError) as ctx:
            self._reply_from(b"-NOAUTH Authentication required.\r\n")
        self.assertIn("NOAUTH", str(ctx.exception))

    def test_integer(self):
        self.assertEqual(self._reply_from(b":1000\r\n"), 1000)

    def test_bulk_string(self):
        self.assertEqual(self._reply_from(b"$6\r\nfoobar\r\n"), "foobar")

    def test_nil_bulk_string(self):
        self.assertIsNone(self._reply_from(b"$-1\r\n"))

    def test_array(self):
        self.assertEqual(self._reply_from(b"*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n"), ["foo", "bar"])

    def test_nil_array(self):
        self.assertIsNone(self._reply_from(b"*-1\r\n"))

    def test_nested_array(self):
        raw = b"*2\r\n$1\r\n0\r\n*2\r\n$1\r\na\r\n$1\r\nb\r\n"
        self.assertEqual(self._reply_from(raw), ["0", ["a", "b"]])

    def test_empty_stream_raises_unavailable(self):
        with self.assertRaises(rc.RedisUnavailable):
            self._reply_from(b"")

    def test_unrecognized_type_byte_raises_unavailable(self):
        with self.assertRaises(rc.RedisUnavailable):
            self._reply_from(b"!weird\r\n")


class TestParseInfo(unittest.TestCase):
    def test_parses_key_value_lines_and_skips_headers_and_blanks(self):
        raw = "# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\n\r\n# Clients\r\nconnected_clients:1\r\n"
        self.assertEqual(rc._parse_info(raw), {
            "redis_version": "7.2.4", "redis_mode": "standalone", "connected_clients": "1",
        })

    def test_empty_or_none_input_returns_empty_dict(self):
        self.assertEqual(rc._parse_info(""), {})
        self.assertEqual(rc._parse_info(None), {})


@unittest.skipUnless(_port_open(_OPEN_PORT), "fake redis server not running on 127.0.0.1:%d" % _OPEN_PORT)
class TestLiveOpenInstance(unittest.TestCase):
    def test_scan_anonymous_access_reports_open_with_version(self):
        result = rc.scan_anonymous_access("127.0.0.1", _OPEN_PORT)
        self.assertEqual(result["status"], "open")
        self.assertEqual(result["version"], "7.2.4")
        self.assertEqual(result["mode"], "standalone")

    def test_enumerate_keys_returns_the_fake_dataset(self):
        result = rc.enumerate_keys("127.0.0.1", _OPEN_PORT)
        self.assertEqual(set(result["keys"]),
                          {"session:abc123", "queue:jobs", "tags:active", "user:42", "leaderboard"})
        self.assertFalse(result["truncated"])

    def test_enumerate_keys_respects_limit_and_reports_truncation(self):
        result = rc.enumerate_keys("127.0.0.1", _OPEN_PORT, limit=2)
        self.assertEqual(len(result["keys"]), 2)
        self.assertTrue(result["truncated"])

    def test_dump_keys_reads_every_type_correctly(self):
        results = {d["key"]: d for d in rc.dump_keys("127.0.0.1", _OPEN_PORT, [
            "session:abc123", "queue:jobs", "tags:active", "user:42", "leaderboard", "nonexistent",
        ])}
        self.assertEqual(results["session:abc123"], {"key": "session:abc123", "type": "string", "value": "user_id=42"})
        self.assertEqual(results["queue:jobs"]["value"], ["job1", "job2", "job3"])
        self.assertEqual(set(results["tags:active"]["value"]), {"urgent", "billing"})
        self.assertEqual(results["user:42"]["value"], {"name": "alice", "role": "admin"})
        self.assertEqual(results["leaderboard"]["value"], [("alice", "100"), ("bob", "90")])
        self.assertEqual(results["nonexistent"], {"key": "nonexistent", "type": "none", "value": None})

    def test_get_server_info_returns_parsed_dict(self):
        info = rc.get_server_info("127.0.0.1", _OPEN_PORT)
        self.assertEqual(info["redis_version"], "7.2.4")


@unittest.skipUnless(_port_open(_AUTH_PORT), "fake redis server not running on 127.0.0.1:%d" % _AUTH_PORT)
class TestLiveAuthRequiredInstance(unittest.TestCase):
    def test_scan_anonymous_access_reports_auth_required(self):
        result = rc.scan_anonymous_access("127.0.0.1", _AUTH_PORT)
        self.assertEqual(result["status"], "auth_required")
        self.assertIsNone(result["version"])


class TestUnreachableInstance(unittest.TestCase):
    def test_scan_anonymous_access_reports_unreachable_for_a_closed_port(self):
        # port 9 is "discard" - reliably closed/refused in any sandboxed
        # environment, no live-target dependency needed for this one
        result = rc.scan_anonymous_access("127.0.0.1", 9)
        self.assertEqual(result["status"], "unreachable")


if __name__ == "__main__":
    unittest.main()
