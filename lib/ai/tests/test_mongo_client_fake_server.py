#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Exercises lib/nosql/mongo_client.py's actual functions against the
in-memory fake pymongo/bson in lib/ai/tests/fake_pymongo.py.

IMPORTANT - read fake_pymongo.py's module docstring: this proves the
code's logic behaves correctly against a plausible fake, not that it's
been verified against a real MongoDB server (no mongod/pymongo/network
available in this sandbox - see mongo_client.py's own module
docstring for the same caveat, unchanged by this file's existence).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from lib.ai.tests.fake_pymongo import FakeMongoEnvironment


class TestScanAnonymousAccess(unittest.TestCase):
    def test_open_instance_reports_status_open_with_version_and_db_count(self):
        with FakeMongoEnvironment(databases={"app": {"collections": {"users": []}},
                                              "logs": {"collections": {}}},
                                   server_info={"version": "7.0.1-fake"}):
            from lib.nosql import mongo_client
            result = mongo_client.scan_anonymous_access("127.0.0.1")

        self.assertEqual(result["status"], "open")
        self.assertEqual(result["version"], "7.0.1-fake")
        self.assertEqual(result["database_count"], 2)

    def test_auth_required_instance_reports_status_auth_required(self):
        with FakeMongoEnvironment(databases={"app": {"collections": {}}},
                                   requires_auth=True,
                                   valid_username="admin", valid_password="s3cret"):
            from lib.nosql import mongo_client
            result = mongo_client.scan_anonymous_access("127.0.0.1")

        self.assertEqual(result["status"], "auth_required")

    def test_correct_credentials_are_not_reported_as_auth_required(self):
        # scan_anonymous_access() itself never passes credentials (that's the
        # point - it tests *anonymous* access), so this should still come
        # back auth_required even though valid credentials exist for the
        # instance; enumerate_databases() (below) is what actually uses them.
        with FakeMongoEnvironment(databases={"app": {"collections": {}}},
                                   requires_auth=True,
                                   valid_username="admin", valid_password="s3cret"):
            from lib.nosql import mongo_client
            result = mongo_client.scan_anonymous_access("127.0.0.1")

        self.assertEqual(result["status"], "auth_required")


class TestEnumerateDatabases(unittest.TestCase):
    def test_lists_databases_and_their_collections(self):
        with FakeMongoEnvironment(databases={
            "app": {"collections": {"users": [{"_id": 1, "name": "alice"}], "orders": []}},
            "config": {"collections": {"settings": []}},
        }):
            from lib.nosql import mongo_client
            result = mongo_client.enumerate_databases("127.0.0.1")

        self.assertEqual(set(result["databases"].keys()), {"app", "config"})
        self.assertEqual(set(result["databases"]["app"]), {"users", "orders"})
        self.assertEqual(result["users_found"], [])

    def test_system_users_collection_is_extracted_as_a_finding(self):
        with FakeMongoEnvironment(databases={
            "admin": {"collections": {"system.users": [
                {"user": "root", "pwd": "5f4dcc3b5aa765d61d8327deb882cf99"},
                {"user": "no_pwd_field_here"},  # should be skipped, not crash
            ]}},
        }):
            from lib.nosql import mongo_client
            result = mongo_client.enumerate_databases("127.0.0.1")

        self.assertEqual(len(result["users_found"]), 1)
        self.assertEqual(result["users_found"][0]["user"], "root")
        self.assertEqual(result["users_found"][0]["database"], "admin")

    def test_a_database_that_cannot_be_enumerated_is_recorded_as_none_not_a_crash(self):
        with FakeMongoEnvironment(databases={
            "app": {"collections": {"users": []}},
            "restricted": {"collections": None},  # simulates a permissions edge case
        }):
            from lib.nosql import mongo_client
            result = mongo_client.enumerate_databases("127.0.0.1")

        self.assertEqual(result["databases"]["app"], ["users"])
        self.assertIsNone(result["databases"]["restricted"])

    def test_raises_mongo_unavailable_with_clear_message_when_listing_fails(self):
        with FakeMongoEnvironment(databases={"app": {"collections": {}}},
                                   requires_auth=True,
                                   valid_username="admin", valid_password="s3cret"):
            from lib.nosql import mongo_client
            with self.assertRaises(mongo_client.MongoUnavailable) as ctx:
                mongo_client.enumerate_databases("127.0.0.1")  # no credentials passed

        self.assertIn("credentials", str(ctx.exception))

    def test_correct_credentials_succeed_against_an_authed_instance(self):
        with FakeMongoEnvironment(databases={"app": {"collections": {"users": []}}},
                                   requires_auth=True,
                                   valid_username="admin", valid_password="s3cret"):
            from lib.nosql import mongo_client
            result = mongo_client.enumerate_databases("127.0.0.1", username="admin", password="s3cret")

        self.assertEqual(list(result["databases"].keys()), ["app"])


class TestDumpCollection(unittest.TestCase):
    def test_returns_all_matching_documents_as_plain_dicts(self):
        docs = [{"_id": "a1", "role": "admin"}, {"_id": "a2", "role": "user"}]
        with FakeMongoEnvironment(databases={"app": {"collections": {"users": docs}}}):
            from lib.nosql import mongo_client
            result = mongo_client.dump_collection("127.0.0.1", 27017, "app", "users")

        self.assertEqual(len(result), 2)
        self.assertEqual({d["_id"] for d in result}, {"a1", "a2"})

    def test_query_filter_narrows_results_mirroring_dump_table_semantics(self):
        docs = [{"_id": "a1", "role": "admin"}, {"_id": "a2", "role": "user"}]
        with FakeMongoEnvironment(databases={"app": {"collections": {"users": docs}}}):
            from lib.nosql import mongo_client
            result = mongo_client.dump_collection("127.0.0.1", 27017, "app", "users", query={"role": "admin"})

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["role"], "admin")

    def test_limit_is_respected(self):
        docs = [{"_id": str(i)} for i in range(10)]
        with FakeMongoEnvironment(databases={"app": {"collections": {"users": docs}}}):
            from lib.nosql import mongo_client
            result = mongo_client.dump_collection("127.0.0.1", 27017, "app", "users", limit=3)

        self.assertEqual(len(result), 3)

    def test_non_json_native_values_survive_the_bson_conversion_round_trip(self):
        # mirrors the real reason bson_doc_to_plain exists: ObjectId/datetime/
        # etc. aren't natively JSON-serializable, so the fake's json.dumps(...,
        # default=str) fallback (standing in for bson.json_util's real
        # BSON-aware encoding) needs to actually get exercised, not just
        # imported.
        class FakeObjectId(object):
            def __str__(self):
                return "507f1f77bcf86cd799439011"

        docs = [{"_id": FakeObjectId(), "name": "alice"}]
        with FakeMongoEnvironment(databases={"app": {"collections": {"users": docs}}}):
            from lib.nosql import mongo_client
            result = mongo_client.dump_collection("127.0.0.1", 27017, "app", "users")

        self.assertEqual(result[0]["_id"], "507f1f77bcf86cd799439011")
        self.assertEqual(result[0]["name"], "alice")


class TestSearchCollections(unittest.TestCase):
    def test_finds_matching_collection_names_across_every_database(self):
        with FakeMongoEnvironment(databases={
            "app": {"collections": {"users": [], "user_sessions": [], "orders": []}},
            "analytics": {"collections": {"user_events": []}},
        }):
            from lib.nosql import mongo_client
            matches = mongo_client.search_collections("127.0.0.1", 27017, "user")

        pairs = {(m["database"], m["collection"]) for m in matches}
        self.assertEqual(pairs, {
            ("app", "users"), ("app", "user_sessions"), ("analytics", "user_events"),
        })

    def test_case_insensitive_and_no_match_returns_empty_list(self):
        with FakeMongoEnvironment(databases={"app": {"collections": {"Users": []}}}):
            from lib.nosql import mongo_client
            matches = mongo_client.search_collections("127.0.0.1", 27017, "USER")
            no_matches = mongo_client.search_collections("127.0.0.1", 27017, "nonexistent")

        self.assertEqual(len(matches), 1)
        self.assertEqual(no_matches, [])

    def test_a_database_that_cannot_be_enumerated_is_skipped_not_fatal(self):
        with FakeMongoEnvironment(databases={
            "app": {"collections": {"users": []}},
            "restricted": {"collections": None},
        }):
            from lib.nosql import mongo_client
            matches = mongo_client.search_collections("127.0.0.1", 27017, "user")

        self.assertEqual([(m["database"], m["collection"]) for m in matches], [("app", "users")])


class TestGetServerInfo(unittest.TestCase):
    def test_returns_version_debug_and_bits(self):
        with FakeMongoEnvironment(databases={}, server_info={"version": "6.0.9-fake", "debug": True, "bits": 64}):
            from lib.nosql import mongo_client
            info = mongo_client.get_server_info("127.0.0.1", 27017)

        self.assertEqual(info, {"version": "6.0.9-fake", "debug": True, "bits": 64})


if __name__ == "__main__":
    unittest.main()
