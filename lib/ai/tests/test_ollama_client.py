#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

import lib.ai.ollama_client as ollama_client_module
from lib.ai.ollama_client import OllamaClient, OllamaError, extract_json_block


class _FakeResponse(object):
    def __init__(self, text):
        self._text = text.encode("utf-8")

    def read(self):
        return self._text


def _patched_urlopen(raw_response_text):
    def _urlopen(req, timeout=None):
        return _FakeResponse(raw_response_text)
    return _urlopen


class TestOllamaClientResponseShapeHardening(unittest.TestCase):
    """
    Ollama's /api/chat and /api/tags always respond with a JSON object in
    practice, but chat() previously did `"error" in parsed` then
    `parsed.get(...)` assuming that unconditionally - a bare JSON
    number/null crashed the first with TypeError, a list/string crashed
    the second with AttributeError. Same class of gap as
    EngineClient._request() (test_engine_client.py), same fix.
    """

    def setUp(self):
        self._real_urlopen = ollama_client_module.urlopen

    def tearDown(self):
        ollama_client_module.urlopen = self._real_urlopen

    def _client_with_response(self, raw_text):
        ollama_client_module.urlopen = _patched_urlopen(raw_text)
        return OllamaClient(host="http://127.0.0.1:11434")

    def test_json_array_response_raises_clear_error(self):
        client = self._client_with_response("[1, 2, 3]")
        with self.assertRaises(OllamaError) as ctx:
            client.chat([{"role": "user", "content": "hi"}])
        self.assertIn("Unexpected JSON shape", str(ctx.exception))

    def test_null_response_raises_clear_error(self):
        client = self._client_with_response("null")
        with self.assertRaises(OllamaError):
            client.chat([{"role": "user", "content": "hi"}])

    def test_bare_number_response_raises_clear_error(self):
        client = self._client_with_response("42")
        with self.assertRaises(OllamaError):
            client.chat([{"role": "user", "content": "hi"}])

    def test_bare_string_response_raises_clear_error(self):
        client = self._client_with_response('"just a string"')
        with self.assertRaises(OllamaError):
            client.chat([{"role": "user", "content": "hi"}])

    def test_well_formed_object_response_is_unaffected(self):
        client = self._client_with_response('{"message": {"role": "assistant", "content": "hi there"}}')
        message = client.chat([{"role": "user", "content": "hi"}])
        self.assertEqual(message["content"], "hi there")

    def test_error_field_still_raises_as_before(self):
        client = self._client_with_response('{"error": "model not found"}')
        with self.assertRaises(OllamaError) as ctx:
            client.chat([{"role": "user", "content": "hi"}])
        self.assertIn("model not found", str(ctx.exception))

    def test_non_json_response_still_raises_as_before(self):
        client = self._client_with_response("<html>not json</html>")
        with self.assertRaises(OllamaError) as ctx:
            client.chat([{"role": "user", "content": "hi"}])
        self.assertIn("Non-JSON response", str(ctx.exception))


class TestListModelsRobustness(unittest.TestCase):
    def setUp(self):
        self._real_urlopen = ollama_client_module.urlopen

    def tearDown(self):
        ollama_client_module.urlopen = self._real_urlopen

    def _client_with_response(self, raw_text):
        ollama_client_module.urlopen = _patched_urlopen(raw_text)
        return OllamaClient(host="http://127.0.0.1:11434")

    def test_well_formed_response_returns_model_names(self):
        client = self._client_with_response('{"models": [{"name": "llama3.1"}, {"name": "qwen2.5"}]}')
        self.assertEqual(client.list_models(), ["llama3.1", "qwen2.5"])

    def test_non_json_response_returns_empty_list(self):
        client = self._client_with_response("not json")
        self.assertEqual(client.list_models(), [])

    def test_non_dict_top_level_returns_empty_list_not_a_crash(self):
        client = self._client_with_response("[1, 2, 3]")
        self.assertEqual(client.list_models(), [])

    def test_models_key_not_a_list_returns_empty_list_not_a_crash(self):
        client = self._client_with_response('{"models": "not a list"}')
        self.assertEqual(client.list_models(), [])

    def test_models_list_with_non_dict_entries_skips_them_not_a_crash(self):
        client = self._client_with_response('{"models": ["not_a_dict", {"name": "llama3.1"}, 42]}')
        self.assertEqual(client.list_models(), ["llama3.1"])

    def test_missing_models_key_returns_empty_list(self):
        client = self._client_with_response("{}")
        self.assertEqual(client.list_models(), [])


class TestExtractJsonBlock(unittest.TestCase):
    """
    `text` traces back to reply.get("content", "") in planner.py's
    _parse_reply() - reply is Ollama's own response dict, so a
    non-string "content" value (a malformed Ollama response, or a proxy
    mangling the field) previously crashed re.search with TypeError here
    instead of being treated as "nothing to extract."
    """

    def test_non_string_values_return_none_not_a_crash(self):
        for bad in (42, 3.14, True, ["a"], {"a": 1}, None):
            self.assertIsNone(extract_json_block(bad))

    def test_empty_string_returns_none(self):
        self.assertIsNone(extract_json_block(""))

    def test_plain_json_object_is_extracted(self):
        self.assertEqual(extract_json_block('{"a": 1}'), {"a": 1})

    def test_json_inside_markdown_fence_is_extracted(self):
        text = 'Here you go:\n```json\n{"a": 1}\n```\nHope that helps.'
        self.assertEqual(extract_json_block(text), {"a": 1})

    def test_json_embedded_in_prose_without_fence_is_extracted(self):
        text = 'Sure, the action is {"a": 1} as requested.'
        self.assertEqual(extract_json_block(text), {"a": 1})

    def test_no_json_present_returns_none(self):
        self.assertIsNone(extract_json_block("just some plain prose with no JSON at all"))


if __name__ == "__main__":
    unittest.main()
