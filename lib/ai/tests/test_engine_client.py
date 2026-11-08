#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

import lib.ai.engine_client as engine_client_module
from lib.ai.engine_client import EngineClient, EngineError


class _FakeResponse(object):
    def __init__(self, text):
        self._text = text.encode("utf-8")

    def read(self):
        return self._text


def _patched_urlopen(raw_response_text):
    def _urlopen(req, timeout=None):
        return _FakeResponse(raw_response_text)
    return _urlopen


class TestEngineClientResponseShapeHardening(unittest.TestCase):
    """
    sqlmap's REST API always responds with a JSON object in practice, but
    every EngineClient method does r.get(...) assuming that unconditionally.
    A technically-valid-but-unexpected top-level JSON shape (an array, bare
    string/number, null) - from a proxy/WAF mangling the response, or a
    future API change - must surface as a clear EngineError, not an
    AttributeError from whichever .get() call happens to touch it first.
    """

    def setUp(self):
        self._real_urlopen = engine_client_module.urlopen

    def tearDown(self):
        engine_client_module.urlopen = self._real_urlopen

    def _client_with_response(self, raw_text):
        engine_client_module.urlopen = _patched_urlopen(raw_text)
        return EngineClient(host="127.0.0.1", port=8775)

    def test_json_array_response_raises_clear_engine_error(self):
        client = self._client_with_response("[1, 2, 3]")
        with self.assertRaises(EngineError) as ctx:
            client.new_task()
        self.assertIn("Unexpected JSON shape", str(ctx.exception))

    def test_bare_string_response_raises_clear_engine_error(self):
        client = self._client_with_response('"just a string"')
        with self.assertRaises(EngineError):
            client.scan_status("t1")

    def test_null_response_raises_clear_engine_error(self):
        client = self._client_with_response("null")
        with self.assertRaises(EngineError):
            client.scan_data("t1")

    def test_bare_number_response_raises_clear_engine_error(self):
        client = self._client_with_response("42")
        with self.assertRaises(EngineError):
            client.get_options("t1")

    def test_well_formed_object_response_is_unaffected(self):
        client = self._client_with_response('{"success": true, "taskid": "abc123"}')
        taskid = client.new_task()
        self.assertEqual(taskid, "abc123")

    def test_non_json_response_still_raises_engine_error_as_before(self):
        client = self._client_with_response("<html>not json</html>")
        with self.assertRaises(EngineError) as ctx:
            client.new_task()
        self.assertIn("Non-JSON response", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
