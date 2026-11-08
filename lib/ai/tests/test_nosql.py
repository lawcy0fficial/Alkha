#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from lib.nosql.injection_probe import (
    _build_url_with_operator, _build_url_with_param, probe,
    OPERATOR_PAYLOADS, WHERE_PAYLOADS,
)
from lib.nosql import mongo_client
from lib.ai.tools import ToolExecutor
from lib.ai.safety import SafetyPolicy


class TestUrlBuilding(unittest.TestCase):
    def test_operator_injection_url(self):
        url = _build_url_with_operator("http://x/a.php?id=1", "id", "$ne", "1")
        self.assertIn("id%5B%24ne%5D=1", url)
        self.assertNotIn("id=1", url)  # original param replaced, not appended alongside

    def test_operator_injection_preserves_other_params(self):
        url = _build_url_with_operator("http://x/a.php?id=1&other=2", "id", "$ne", "1")
        self.assertIn("other=2", url)

    def test_param_value_replacement(self):
        url = _build_url_with_param("http://x/a.php?id=1", "id", "injected")
        self.assertIn("id=injected", url)


class TestPayloadRobustness(unittest.TestCase):
    def test_where_string_breakout_has_truthy_leading_fragment(self):
        # regression test: an earlier version of this payload was "' || '1'=='1"
        # - a bare leading quote with nothing before it, which evaluates to an
        # empty (falsy) string on the left of || in both JS and Python, so
        # "'' || <anything>" never actually breaks out regardless of target.
        # Confirmed live against a real $where-vulnerable target where this
        # silently missed a confirmed-real bypass - see doc/NEXTGEN.md.
        breakout = next(p for p in WHERE_PAYLOADS if p["name"] == "OR-true string breakout")
        # the value must have non-quote, non-empty content before the first "||"
        prefix = breakout["value"].split("||")[0].strip().strip("'")
        self.assertTrue(prefix, "leading fragment before '||' must be non-empty/truthy")

    def test_all_payloads_have_required_fields(self):
        for payload in OPERATOR_PAYLOADS:
            self.assertIn("name", payload)
            self.assertIn("operator", payload)
            self.assertIn("value", payload)
            self.assertIn("category", payload)
        for payload in WHERE_PAYLOADS:
            self.assertIn("name", payload)
            self.assertIn("value", payload)
            self.assertIn("category", payload)


class TestMongoClientGracefulDegradation(unittest.TestCase):
    """
    Without pymongo installed (the case in this sandbox - see
    lib/nosql/mongo_client.py's module docstring for why), every public
    function must fail with a clear MongoUnavailable, not an
    ImportError or AttributeError from deep inside the module.
    """

    def test_scan_anonymous_access_without_pymongo(self):
        if mongo_client.PYMONGO_AVAILABLE:
            self.skipTest("pymongo is available in this environment - degradation path not exercised")
        with self.assertRaises(mongo_client.MongoUnavailable):
            mongo_client.scan_anonymous_access("127.0.0.1")

    def test_enumerate_databases_without_pymongo(self):
        if mongo_client.PYMONGO_AVAILABLE:
            self.skipTest("pymongo is available in this environment - degradation path not exercised")
        with self.assertRaises(mongo_client.MongoUnavailable):
            mongo_client.enumerate_databases("127.0.0.1")

    def test_dump_collection_without_pymongo(self):
        if mongo_client.PYMONGO_AVAILABLE:
            self.skipTest("pymongo is available in this environment - degradation path not exercised")
        with self.assertRaises(mongo_client.MongoUnavailable):
            mongo_client.dump_collection("127.0.0.1", 27017, "db", "coll")


class FakeEngine(object):
    pass


class TestNosqlToolWiring(unittest.TestCase):
    def setUp(self):
        self.ex = ToolExecutor(FakeEngine(), "t1")

    def test_nosql_scan_target_requires_host(self):
        result = self.ex.execute("nosql_scan_target", {})
        self.assertFalse(result["ok"])

    def test_nosql_enumerate_requires_host(self):
        result = self.ex.execute("nosql_enumerate", {})
        self.assertFalse(result["ok"])

    def test_nosql_search_collections_requires_host_and_keyword(self):
        result = self.ex.execute("nosql_search_collections", {"host": "x"})
        self.assertFalse(result["ok"])

    def test_nosql_dump_collection_requires_host_db_collection(self):
        result = self.ex.execute("nosql_dump_collection", {"host": "x"})
        self.assertFalse(result["ok"])

    def test_nosql_test_injection_requires_url_and_param(self):
        result = self.ex.execute("nosql_test_injection", {"url": "http://x/a"})
        self.assertFalse(result["ok"])

    def test_missing_pymongo_fails_gracefully_not_with_a_crash(self):
        if mongo_client.PYMONGO_AVAILABLE:
            self.skipTest("pymongo is available in this environment - degradation path not exercised")
        result = self.ex.execute("nosql_scan_target", {"host": "127.0.0.1"})
        self.assertFalse(result["ok"])
        self.assertIn("pymongo", result["error"])


class TestNosqlSafetyIntegration(unittest.TestCase):
    def test_nosql_dump_collection_is_high_risk(self):
        sp = SafetyPolicy(allowed_hosts=["example.com"])
        sp.start()
        self.assertFalse(sp.authorize("nosql_dump_collection", {"host": "example.com"}))

    def test_nosql_enumerate_is_safe_no_confirmation_needed(self):
        sp = SafetyPolicy(allowed_hosts=["example.com"])
        sp.start()
        self.assertTrue(sp.authorize("nosql_enumerate", {"host": "example.com"}))

    def test_nosql_tools_respect_host_scope_check(self):
        sp = SafetyPolicy(allowed_hosts=["example.com"])
        sp.start()
        from lib.ai.safety import ScopeViolation
        with self.assertRaises(ScopeViolation):
            sp.authorize("nosql_enumerate", {"host": "evil.com"})


class TestInjectionProbeLiveIntegration(unittest.TestCase):
    """
    These two exercise the real probe() function against genuinely
    vulnerable local targets, mirroring the manual verification done
    during development (doc/NEXTGEN.md) - skipped automatically if the
    targets aren't running, since they need real HTTP servers rather
    than being pure unit tests.
    """

    def test_operator_injection_detection(self):
        import socket
        try:
            socket.create_connection(("127.0.0.1", 9380), timeout=1).close()
        except OSError:
            self.skipTest("operator-injection test target not running on 127.0.0.1:9380")

        result = probe("http://127.0.0.1:9380/lookup?id=999", "id")
        self.assertTrue(result["likely_injectable"])

    def test_where_injection_detection(self):
        import socket
        try:
            socket.create_connection(("127.0.0.1", 9381), timeout=1).close()
        except OSError:
            self.skipTest("$where-injection test target not running on 127.0.0.1:9381")

        result = probe("http://127.0.0.1:9381/login?username=nobody", "username")
        self.assertTrue(result["likely_injectable"])


if __name__ == "__main__":
    unittest.main()
