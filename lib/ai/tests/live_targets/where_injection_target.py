#!/usr/bin/env python

"""
Standalone throwaway HTTP server reproducing a MongoDB $where-clause
string-concatenation injection (an app builds a `$where` filter like
`this.username == '<value>'` by concatenating unsanitized input, so a
value containing a quote can break out of the string literal and
inject arbitrary boolean JS logic).

Not part of the shipped product - exists purely so
lib/ai/tests/test_nosql.py's TestInjectionProbeLiveIntegration can
exercise the real lib/nosql/injection_probe.py `probe()` function
against a genuinely running, genuinely vulnerable-in-this-specific-way
target on 127.0.0.1:9381 (distinct vulnerability class from the
operator-injection target on 9380 - a real $where-vulnerable app is
not necessarily also vulnerable to bracket-operator injection, and
vice versa, which is why these are two separate targets rather than
one covering both).

This doesn't run a real JS interpreter - it recognizes the same
handful of documented breakout patterns lib/nosql/injection_probe.py
ships as WHERE_PAYLOADS and reproduces the login-bypass outcome a real
`$where` evaluation of `this.username == '<value>'` would actually
produce for each, which is what the probe's response-diffing logic is
verified against.

Run standalone: `python lib/ai/tests/live_targets/where_injection_target.py`
"""

from __future__ import print_function

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

KNOWN_USERS = {"admin"}


def _breakout_outcome(value):
    """Returns True/False if `value` matches a recognized $where breakout
    pattern (mirroring what `this.username == '<value>'` would actually
    evaluate to once the string literal is broken out of), or None if it's
    just an ordinary (non-breaking) username string.

    The app-side template supplies the closing quote itself
    (`"this.username == '" + value + "'"`) - a payload like
    `x' || 'a'=='a` only becomes the valid, always-true expression
    `this.username == 'x' || 'a'=='a'` once that trailing quote from the
    template is appended, so pattern-matching must be done against
    `value + "'"`, not the raw payload text alone."""
    reconstructed = value + "'"
    if "||" in reconstructed and ("=='a'" in reconstructed or "1==1" in reconstructed):
        return True
    if "return true" in reconstructed:
        return True
    if "return false" in reconstructed:
        return False
    return None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/login":
            self.send_response(404)
            self.end_headers()
            return

        qs = parse_qs(parsed.query, keep_blank_values=True)
        username = (qs.get("username") or [""])[0]

        outcome = _breakout_outcome(username)

        if outcome is True:
            body = b"WELCOME, admin! session=abc123"
        elif outcome is False:
            body = b"ACCESS DENIED (explicit false-payload path evaluated)"
        elif username in KNOWN_USERS:
            body = ("WELCOME, %s!" % username).encode("utf-8")
        else:
            body = b"ACCESS DENIED"

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run(port=9381):
    server = HTTPServer(("127.0.0.1", port), Handler)
    print("$where-injection target listening on 127.0.0.1:%d" % port)
    server.serve_forever()


if __name__ == "__main__":
    run(int(sys.argv[1]) if len(sys.argv) > 1 else 9381)
