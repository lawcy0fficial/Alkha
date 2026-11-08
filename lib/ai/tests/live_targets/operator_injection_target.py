#!/usr/bin/env python

"""
Standalone throwaway HTTP server reproducing the Express.js/`qs`
bracket-parsing NoSQL operator-injection pattern (a `?id=999` param
becomes exploitable as `?id[$ne]=1` when a framework auto-parses
bracket query-string syntax straight into a MongoDB query filter).

Not part of the shipped product - this exists purely so
lib/ai/tests/test_nosql.py's TestInjectionProbeLiveIntegration can
exercise the real lib/nosql/injection_probe.py `probe()` function
against a genuinely running, genuinely vulnerable-in-this-specific-way
target on 127.0.0.1:9380, instead of that test being permanently
skipped for lack of anything to point it at.

Run standalone: `python lib/ai/tests/live_targets/operator_injection_target.py`
"""

from __future__ import print_function

import re
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, unquote_plus

USERS = [{"id": "1", "name": "root"}, {"id": "2", "name": "alice"}]

_BRACKET_KEY = re.compile(r"^([^\[\]]+)\[(\$[a-zA-Z]+)\]$")


def _parse_query(raw_query):
    """Minimal stand-in for a framework (e.g. Express + `qs`) that turns
    `id[$ne]=1` into {"id": {"$ne": "1"}} instead of treating it as an
    opaque string - the actual root cause of this injection class."""
    parsed = {}
    for part in raw_query.split("&"):
        if not part:
            continue
        key, _, value = part.partition("=")
        key, value = unquote_plus(key), unquote_plus(value)
        m = _BRACKET_KEY.match(key)
        if m:
            field, op = m.groups()
            parsed.setdefault(field, {})[op] = value
        else:
            parsed[key] = value
    return parsed


def _matches(actual, condition):
    if isinstance(condition, dict):
        for op, val in condition.items():
            if op == "$ne" and str(actual) == str(val):
                return False
            if op == "$gt" and not (str(actual) > str(val)):
                return False
            if op == "$regex" and not re.search(val, str(actual)):
                return False
            if op == "$exists" and val.lower() not in ("true", "1"):
                return False
        return True
    return str(actual) == str(condition)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # keep test output quiet

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/lookup":
            self.send_response(404)
            self.end_headers()
            return

        params = _parse_query(parsed.query)
        condition = params.get("id")

        match = None
        if condition is not None:
            for user in USERS:
                if _matches(user["id"], condition):
                    match = user
                    break

        if match:
            body = ("FOUND: %s" % match["name"]).encode("utf-8")
            self.send_response(200)
        else:
            body = b"NOT FOUND"
            self.send_response(404)

        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run(port=9380):
    server = HTTPServer(("127.0.0.1", port), Handler)
    print("operator-injection target listening on 127.0.0.1:%d" % port)
    server.serve_forever()


if __name__ == "__main__":
    run(int(sys.argv[1]) if len(sys.argv) > 1 else 9380)
