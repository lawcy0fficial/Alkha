#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from lib.ai.knowledge_base import KnowledgeBase


class TestKnowledgeBase(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.remove(self.path)  # KnowledgeBase should create it fresh

    def tearDown(self):
        if os.path.exists(self.path):
            os.remove(self.path)

    def test_lookup_on_empty_store_returns_none(self):
        kb = KnowledgeBase(path=self.path)
        self.assertIsNone(kb.lookup("http://example.com/x"))

    def test_record_then_lookup_same_instance(self):
        kb = KnowledgeBase(path=self.path)
        kb.record_success("http://example.com/a.php?id=1", dbms="MySQL",
                           injection_points=[{"place": "GET", "parameter": "id"}])
        record = kb.lookup("http://example.com/other.php")
        self.assertEqual(record["dbms"], "MySQL")

    def test_persists_across_separate_instances(self):
        # Simulates two genuinely separate agent runs (separate processes
        # in reality) - a second KnowledgeBase instance pointed at the
        # same path must see what the first one wrote.
        kb1 = KnowledgeBase(path=self.path)
        kb1.record_success("http://example.com/a.php?id=1", dbms="PostgreSQL")

        kb2 = KnowledgeBase(path=self.path)
        record = kb2.lookup("http://example.com/")
        self.assertEqual(record["dbms"], "PostgreSQL")

    def test_file_permissions_locked_to_owner_only(self):
        kb = KnowledgeBase(path=self.path)
        kb.record_success("http://example.com/x", dbms="MySQL")
        mode = stat.S_IMODE(os.stat(self.path).st_mode)
        self.assertEqual(mode, 0o600)

    def test_second_success_merges_tamper_scripts_not_overwrites(self):
        kb = KnowledgeBase(path=self.path)
        kb.record_success("http://example.com/x", dbms="MySQL", tamper=["space2comment"])
        kb.record_success("http://example.com/x", dbms="MySQL", tamper=["charunicodeencode"])
        record = kb.lookup("http://example.com/x")
        self.assertEqual(sorted(record["tamper"]), ["charunicodeencode", "space2comment"])

    def test_different_hosts_keyed_separately(self):
        kb = KnowledgeBase(path=self.path)
        kb.record_success("http://a.example.com/x", dbms="MySQL")
        kb.record_success("http://b.example.com/x", dbms="PostgreSQL")
        self.assertEqual(kb.lookup("http://a.example.com/")["dbms"], "MySQL")
        self.assertEqual(kb.lookup("http://b.example.com/")["dbms"], "PostgreSQL")

    def test_render_for_prompt_none_when_no_record(self):
        kb = KnowledgeBase(path=self.path)
        self.assertIsNone(kb.render_for_prompt("http://unseen.example.com/"))

    def test_render_for_prompt_includes_key_fields(self):
        kb = KnowledgeBase(path=self.path)
        kb.record_success("http://example.com/x", dbms="MySQL",
                           injection_points=[{"place": "GET", "parameter": "id"}],
                           tamper=["space2comment"])
        text = kb.render_for_prompt("http://example.com/x")
        self.assertIn("MySQL", text)
        self.assertIn("space2comment", text)


if __name__ == "__main__":
    unittest.main()
