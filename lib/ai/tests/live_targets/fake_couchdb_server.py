#!/usr/bin/env python

"""
Standalone throwaway HTTP server mimicking just enough of the real
CouchDB REST API (GET /, GET /_all_dbs, GET /<db>/_all_docs) to
live-test lib/nosql/couchdb_client.py - not part of the shipped
product, matching the pattern of the other live_targets/ scripts.

Run standalone: `python lib/ai/tests/live_targets/fake_couchdb_server.py <port> [--auth-required]`
"""

from __future__ import print_function

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

_FAKE_DBS = ["_users", "customers", "invoices"]

_FAKE_DOCS = {
    "customers": [
        {"_id": "_design/by_name", "_rev": "1-abc", "views": {}},  # design doc - must be filtered out
        {"_id": "c1", "_rev": "1-aaa", "name": "Alice Example", "email": "alice@example.com"},
        {"_id": "c2", "_rev": "1-bbb", "name": "Bob Example", "email": "bob@example.com"},
    ],
    "invoices": [
        {"_id": "i1", "_rev": "1-ccc", "amount": 199.99, "customer": "c1"},
    ],
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _write_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if getattr(self.server, "auth_required", False):
            self._write_json(401, {"error": "unauthorized", "reason": "You are not authorized to access this db."})
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            self._write_json(200, {
                "couchdb": "Welcome", "version": "3.3.3",
                "vendor": {"name": "The Apache Software Foundation"},
            })
        elif path == "/_all_dbs":
            self._write_json(200, _FAKE_DBS)
        elif path.endswith("/_all_docs"):
            db = path.split("/")[1]
            if db not in _FAKE_DOCS:
                self._write_json(404, {"error": "not_found", "reason": "Database does not exist."})
                return
            limit = int(parse_qs(parsed.query).get("limit", ["25"])[0])
            docs = _FAKE_DOCS[db][:limit]
            rows = [{"id": d["_id"], "key": d["_id"], "value": {"rev": d["_rev"]}, "doc": d} for d in docs]
            self._write_json(200, {"total_rows": len(_FAKE_DOCS[db]), "offset": 0, "rows": rows})
        else:
            self._write_json(404, {"error": "not_found", "reason": "missing"})


def run(port, auth_required=False):
    server = HTTPServer(("127.0.0.1", port), Handler)
    server.auth_required = auth_required
    print("fake couchdb server (%s) listening on 127.0.0.1:%d" % (
        "auth required" if auth_required else "open", port))
    server.serve_forever()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9386
    run(port, auth_required="--auth-required" in sys.argv)
