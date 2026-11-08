#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Live-integration tests against the real fake_elasticsearch_server.py -
same "prove it against something actually speaking the real response
shapes" standard as test_redis_client.py and test_nosql.py's
TestInjectionProbeLiveIntegration. No mocking needed here at all
(unlike the MongoDB tests, which need a fake pymongo since
mongo_client.py depends on that package) - elasticsearch_client.py is
plain stdlib HTTP, so these tests exercise the exact code that runs in
production.

Skipped automatically if the fake server isn't running on the expected
ports.
"""

import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from lib.nosql import elasticsearch_client as ec

_OPEN_PORT = 9384
_AUTH_PORT = 9385


def _port_open(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        return True
    except OSError:
        return False


@unittest.skipUnless(_port_open(_OPEN_PORT), "fake elasticsearch server not running on 127.0.0.1:%d" % _OPEN_PORT)
class TestLiveOpenInstance(unittest.TestCase):
    def test_scan_anonymous_access_reports_open_with_version_and_index_count(self):
        result = ec.scan_anonymous_access("127.0.0.1", _OPEN_PORT)
        self.assertEqual(result["status"], "open")
        self.assertEqual(result["version"], "8.11.3")
        self.assertEqual(result["cluster_name"], "fake-cluster")
        self.assertEqual(result["index_count"], 2)

    def test_enumerate_indices_returns_the_fake_dataset(self):
        indices = ec.enumerate_indices("127.0.0.1", _OPEN_PORT)
        names = {i["index"] for i in indices}
        self.assertEqual(names, {"users", "orders"})
        users = next(i for i in indices if i["index"] == "users")
        self.assertEqual(users["docs_count"], "3")

    def test_dump_index_returns_plain_source_documents(self):
        docs = ec.dump_index("127.0.0.1", _OPEN_PORT, "users")
        self.assertEqual(len(docs), 3)
        self.assertIn({"username": "admin", "email": "admin@example.com"}, docs)
        # _id/_score metadata must be stripped - only _source content
        for doc in docs:
            self.assertNotIn("_id", doc)
            self.assertNotIn("_score", doc)

    def test_dump_index_respects_limit(self):
        docs = ec.dump_index("127.0.0.1", _OPEN_PORT, "orders", limit=1)
        self.assertEqual(len(docs), 1)

    def test_dump_index_for_nonexistent_index_raises_clear_error(self):
        with self.assertRaises(ec.ElasticsearchUnavailable):
            ec.dump_index("127.0.0.1", _OPEN_PORT, "nonexistent_index")

    def test_get_server_info_returns_parsed_root_response(self):
        info = ec.get_server_info("127.0.0.1", _OPEN_PORT)
        self.assertEqual(info["cluster_name"], "fake-cluster")
        self.assertEqual(info["version"]["number"], "8.11.3")


@unittest.skipUnless(_port_open(_AUTH_PORT), "fake elasticsearch server not running on 127.0.0.1:%d" % _AUTH_PORT)
class TestLiveAuthRequiredInstance(unittest.TestCase):
    def test_scan_anonymous_access_reports_auth_required(self):
        result = ec.scan_anonymous_access("127.0.0.1", _AUTH_PORT)
        self.assertEqual(result["status"], "auth_required")
        self.assertIsNone(result["version"])

    def test_enumerate_indices_returns_empty_list_not_a_crash(self):
        # enumerate_indices() assumes access is already known open (see its
        # docstring) - called against an auth-required instance anyway, it
        # should degrade to an empty list, not raise
        self.assertEqual(ec.enumerate_indices("127.0.0.1", _AUTH_PORT), [])


class TestUnreachableInstance(unittest.TestCase):
    def test_scan_anonymous_access_reports_unreachable_for_a_closed_port(self):
        result = ec.scan_anonymous_access("127.0.0.1", 9)  # "discard" - reliably closed
        self.assertEqual(result["status"], "unreachable")


if __name__ == "__main__":
    unittest.main()
