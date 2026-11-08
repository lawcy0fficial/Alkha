#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from lib.ai.tamper_catalog import load_catalog, render_catalog_for_prompt, recommend_for_dbms


class TestTamperCatalog(unittest.TestCase):
    def test_catalog_loads_real_scripts(self):
        catalog = load_catalog()
        self.assertGreater(len(catalog), 50)  # sqlmap ships 70+ tamper scripts
        names = [c["name"] for c in catalog]
        self.assertIn("space2comment", names)

    def test_every_entry_has_nonempty_name_and_description(self):
        for entry in load_catalog():
            self.assertTrue(entry["name"])
            self.assertTrue(entry["description"])

    def test_render_without_query_returns_full_catalog(self):
        text = render_catalog_for_prompt()
        self.assertIn("space2comment", text)

    def test_render_with_query_filters(self):
        text = render_catalog_for_prompt("mysql")
        self.assertIn("mysql", text.lower())
        # something clearly unrelated shouldn't appear
        self.assertNotIn("space2comment:", text)

    def test_render_with_no_matches_returns_clear_message(self):
        text = render_catalog_for_prompt("nonexistent_keyword_zzz")
        self.assertIn("no matching", text.lower())


class TestRecommendForDbms(unittest.TestCase):
    def test_mysql_returns_dbms_specific_scripts_first(self):
        rec = recommend_for_dbms("MySQL >= 5.0.12")
        self.assertIn("space2mysqlblank", rec["specific"])
        self.assertGreater(len(rec["generic"]), 0)
        # a script restricted to a different DBMS must not appear as MySQL-specific
        self.assertNotIn("space2mssqlblank", rec["specific"])

    def test_mssql_returns_its_own_specific_scripts(self):
        rec = recommend_for_dbms("Microsoft SQL Server 2019")
        self.assertIn("space2mssqlblank", rec["specific"])
        self.assertNotIn("space2mysqlblank", rec["specific"])

    def test_unknown_dbms_falls_back_to_generic_only(self):
        rec = recommend_for_dbms("SomeMadeUpDatabase")
        self.assertEqual(rec["specific"], [])
        self.assertGreater(len(rec["generic"]), 0)

    def test_none_dbms_returns_generic_only(self):
        rec = recommend_for_dbms(None)
        self.assertEqual(rec["specific"], [])
        self.assertGreater(len(rec["generic"]), 0)

    def test_every_catalog_entry_has_dbms_key(self):
        for entry in load_catalog():
            self.assertIn("dbms", entry)
            self.assertIsInstance(entry["dbms"], list)

    def test_non_string_query_does_not_crash_render(self):
        # `query` is untrusted model-supplied input for list_tamper_scripts -
        # a hallucinated number/list/dict argument must degrade gracefully
        # (coerced to its string form), not raise AttributeError on .lower().
        for bad_query in (3.14, 42, ["mysql"], {"a": 1}, True):
            result = render_catalog_for_prompt(bad_query)
            self.assertIsInstance(result, str)

    def test_non_string_dbms_name_does_not_crash_recommend(self):
        for bad_dbms in (42, 3.14, ["MySQL"], {"a": 1}, True):
            rec = recommend_for_dbms(bad_dbms)
            self.assertEqual(rec["specific"], [])
            self.assertGreater(len(rec["generic"]), 0)


if __name__ == "__main__":
    unittest.main()
