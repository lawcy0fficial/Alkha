#!/usr/bin/env python

"""
Standalone throwaway HTTP server mimicking just enough of the real
Elasticsearch/OpenSearch REST API (GET /, GET /_cluster/health, GET
/_cat/indices?format=json, GET /<index>/_search) to live-test
lib/nosql/elasticsearch_client.py against something genuinely speaking
the real response shapes - not part of the shipped product, matching
the pattern of the other live_targets/ scripts in this directory.

Run standalone: `python lib/ai/tests/live_targets/fake_elasticsearch_server.py <port> [--auth-required]`
"""

from __future__ import print_function

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

_FAKE_INDICES = [
    {"index": "users", "health": "yellow", "docs.count": "3", "store.size": "12kb"},
    {"index": "orders", "health": "yellow", "docs.count": "2", "store.size": "8kb"},
]

_FAKE_DOCS = {
    "users": [
        {"_id": "1", "_score": 1.0, "_source": {"username": "admin", "email": "admin@example.com"}},
        {"_id": "2", "_score": 1.0, "_source": {"username": "alice", "email": "alice@example.com"}},
        {"_id": "3", "_score": 1.0, "_source": {"username": "bob", "email": "bob@example.com"}},
    ],
    "orders": [
        {"_id": "1", "_score": 1.0, "_source": {"item": "widget", "total": 19.99}},
        {"_id": "2", "_score": 1.0, "_source": {"item": "gadget", "total": 49.99}},
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
            self._write_json(401, {"error": {"type": "security_exception",
                                               "reason": "missing authentication credentials"}})
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            self._write_json(200, {
                "name": "fake-node-1", "cluster_name": "fake-cluster",
                "version": {"number": "8.11.3", "build_flavor": "default"},
                "tagline": "You Know, for Search",
            })
        elif path == "/_cluster/health":
            self._write_json(200, {"cluster_name": "fake-cluster", "status": "yellow",
                                     "number_of_nodes": 1, "active_shards": 4})
        elif path == "/_cat/indices" and parse_qs(parsed.query).get("format") == ["json"]:
            self._write_json(200, _FAKE_INDICES)
        elif path.endswith("/_search"):
            index = path.split("/")[1]
            if index not in _FAKE_DOCS:
                # matches real Elasticsearch/OpenSearch: searching a
                # nonexistent index is a 404, not an empty result set
                self._write_json(404, {"error": {"type": "index_not_found_exception",
                                                   "reason": "no such index [%s]" % index}})
                return
            size = int(parse_qs(parsed.query).get("size", ["10"])[0])
            docs = _FAKE_DOCS[index]
            self._write_json(200, {
                "took": 1, "timed_out": False,
                "hits": {"total": {"value": len(docs)}, "hits": docs[:size]},
            })
        else:
            self._write_json(404, {"error": {"type": "index_not_found_exception", "reason": "no such index"}})


def run(port, auth_required=False):
    server = HTTPServer(("127.0.0.1", port), Handler)
    server.auth_required = auth_required
    print("fake elasticsearch server (%s) listening on 127.0.0.1:%d" % (
        "auth required" if auth_required else "open", port))
    server.serve_forever()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9384
    run(port, auth_required="--auth-required" in sys.argv)
