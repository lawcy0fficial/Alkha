#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Live-integration tests against the real fake_couchdb_server.py - same
standard as test_elasticsearch_client.py: plain stdlib HTTP, no mocking
needed, these tests exercise the exact code that runs in production.

Skipped automatically if the fake server isn't running on the expected
ports.
"""

import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from lib.nosql import couchdb_client as cc

_OPEN_PORT = 9386
_AUTH_PORT = 9387


def _port_open(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        return True
    except OSError:
        return False


@unittest.skipUnless(_port_open(_OPEN_PORT), "fake couchdb server not running on 127.0.0.1:%d" % _OPEN_PORT)
class TestLiveOpenInstance(unittest.TestCase):
    def test_scan_anonymous_access_reports_open_with_version_and_db_count(self):
        result = cc.scan_anonymous_access("127.0.0.1", _OPEN_PORT)
        self.assertEqual(result["status"], "open")
        self.assertEqual(result["version"], "3.3.3")
        self.assertEqual(result["database_count"], 3)

    def test_enumerate_databases_returns_the_fake_dataset(self):
        self.assertEqual(set(cc.enumerate_databases("127.0.0.1", _OPEN_PORT)),
                          {"_users", "customers", "invoices"})

    def test_dump_database_returns_documents_and_filters_out_design_docs(self):
        docs = cc.dump_database("127.0.0.1", _OPEN_PORT, "customers")
        self.assertEqual(len(docs), 2)  # 3 rows in the fake dataset, 1 is a _design/ doc
        ids = {d["_id"] for d in docs}
        self.assertEqual(ids, {"c1", "c2"})
        self.assertNotIn("_design/by_name", ids)
        alice = next(d for d in docs if d["_id"] == "c1")
        self.assertEqual(alice["email"], "alice@example.com")

    def test_dump_database_respects_limit(self):
        docs = cc.dump_database("127.0.0.1", _OPEN_PORT, "customers", limit=1)
        self.assertLessEqual(len(docs), 1)

    def test_dump_database_for_nonexistent_database_raises_clear_error(self):
        with self.assertRaises(cc.CouchDBUnavailable):
            cc.dump_database("127.0.0.1", _OPEN_PORT, "nonexistent_db")

    def test_get_server_info_returns_parsed_root_response(self):
        info = cc.get_server_info("127.0.0.1", _OPEN_PORT)
        self.assertEqual(info["couchdb"], "Welcome")
        self.assertEqual(info["version"], "3.3.3")


@unittest.skipUnless(_port_open(_AUTH_PORT), "fake couchdb server not running on 127.0.0.1:%d" % _AUTH_PORT)
class TestLiveAuthRequiredInstance(unittest.TestCase):
    def test_scan_anonymous_access_reports_auth_required(self):
        result = cc.scan_anonymous_access("127.0.0.1", _AUTH_PORT)
        self.assertEqual(result["status"], "auth_required")
        self.assertIsNone(result["version"])

    def test_enumerate_databases_returns_empty_list_not_a_crash(self):
        self.assertEqual(cc.enumerate_databases("127.0.0.1", _AUTH_PORT), [])


class TestUnreachableInstance(unittest.TestCase):
    def test_scan_anonymous_access_reports_unreachable_for_a_closed_port(self):
        result = cc.scan_anonymous_access("127.0.0.1", 9)  # "discard" - reliably closed
        self.assertEqual(result["status"], "unreachable")


if __name__ == "__main__":
    unittest.main()
