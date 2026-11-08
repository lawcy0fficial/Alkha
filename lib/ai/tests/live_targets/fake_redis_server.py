#!/usr/bin/env python

"""
Standalone throwaway RESP2-speaking TCP server for live-testing
lib/nosql/redis_client.py - not part of the shipped product. Understands
just enough of the real Redis protocol (PING, INFO, SCAN, TYPE, GET,
LRANGE, SMEMBERS, HGETALL, ZRANGE) to exercise every function in that
module against a genuinely running, genuinely speaking-the-real-protocol
server, the same way lib/ai/tests/live_targets/*_injection_target.py do
for the HTTP-based NoSQL work.

Two modes, selected by the port passed on the command line matching one
of the two constants below - mirrors having two separate target scripts
(operator_injection_target.py / where_injection_target.py) without
needing two near-duplicate files for what's fundamentally one small
protocol implementation with a single behavioral difference (does PING
require auth first or not).

Run standalone: `python lib/ai/tests/live_targets/fake_redis_server.py <port> [--auth-required]`
"""

from __future__ import print_function

import socketserver
import sys

_CRLF = b"\r\n"

_FAKE_DATA = {
    "session:abc123": ("string", "user_id=42"),
    "queue:jobs": ("list", ["job1", "job2", "job3"]),
    "tags:active": ("set", ["urgent", "billing"]),
    "user:42": ("hash", {"name": "alice", "role": "admin"}),
    "leaderboard": ("zset", [("alice", "100"), ("bob", "90")]),
}


def _encode_simple(s):
    return b"+" + s.encode("utf-8") + _CRLF


def _encode_error(s):
    return b"-" + s.encode("utf-8") + _CRLF


def _encode_bulk(s):
    if s is None:
        return b"$-1" + _CRLF
    data = s.encode("utf-8") if isinstance(s, str) else s
    return b"$%d" % len(data) + _CRLF + data + _CRLF


def _encode_int(n):
    return b":%d" % n + _CRLF


def _encode_array(items):
    if items is None:
        return b"*-1" + _CRLF
    out = [b"*%d" % len(items) + _CRLF]
    for item in items:
        out.append(_encode_one(item))
    return b"".join(out)


def _encode_one(item):
    if item is None or isinstance(item, str):
        return _encode_bulk(item)
    if isinstance(item, int):
        return _encode_int(item)
    if isinstance(item, (list, tuple)):
        return _encode_array(list(item))
    return _encode_bulk(str(item))


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            cmd = self._read_command()
            if cmd is None:
                return
            self._dispatch(cmd)

    def _read_command(self):
        line = self.rfile.readline()
        if not line:
            return None
        if not line.startswith(b"*"):
            return None
        count = int(line[1:].strip())
        args = []
        for _ in range(count):
            length_line = self.rfile.readline()
            length = int(length_line[1:].strip())
            data = self.rfile.read(length)
            self.rfile.read(2)
            args.append(data.decode("utf-8", "replace"))
        return args

    def _dispatch(self, cmd):
        name = cmd[0].upper()
        auth_required = getattr(self.server, "auth_required", False)

        if auth_required and name not in ("AUTH", "HELLO"):
            self.wfile.write(_encode_error("NOAUTH Authentication required."))
            return

        if name == "PING":
            self.wfile.write(_encode_simple("PONG"))
        elif name == "INFO":
            info = (
                "# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\n"
                "# Clients\r\nconnected_clients:1\r\n"
            )
            self.wfile.write(_encode_bulk(info))
        elif name == "SCAN":
            # single-batch fake: always returns everything and cursor "0"
            # (a real server paginates; this fake doesn't need to for the
            # client's cursor-loop logic to be exercised - it just needs
            # to see a well-formed [cursor, keys] reply and stop cleanly)
            self.wfile.write(_encode_array(["0", list(_FAKE_DATA.keys())]))
        elif name == "TYPE":
            key = cmd[1]
            entry = _FAKE_DATA.get(key)
            self.wfile.write(_encode_simple(entry[0] if entry else "none"))
        elif name == "GET":
            entry = _FAKE_DATA.get(cmd[1])
            self.wfile.write(_encode_bulk(entry[1] if entry and entry[0] == "string" else None))
        elif name == "LRANGE":
            entry = _FAKE_DATA.get(cmd[1])
            self.wfile.write(_encode_array(entry[1] if entry and entry[0] == "list" else []))
        elif name == "SMEMBERS":
            entry = _FAKE_DATA.get(cmd[1])
            self.wfile.write(_encode_array(entry[1] if entry and entry[0] == "set" else []))
        elif name == "HGETALL":
            entry = _FAKE_DATA.get(cmd[1])
            flat = []
            if entry and entry[0] == "hash":
                for k, v in entry[1].items():
                    flat.extend([k, v])
            self.wfile.write(_encode_array(flat))
        elif name == "ZRANGE":
            entry = _FAKE_DATA.get(cmd[1])
            flat = []
            if entry and entry[0] == "zset":
                for member, score in entry[1]:
                    flat.extend([member, score])
            self.wfile.write(_encode_array(flat))
        else:
            self.wfile.write(_encode_error("ERR unknown command '%s'" % name))


def run(port, auth_required=False):
    server = socketserver.ThreadingTCPServer(("127.0.0.1", port), Handler)
    server.auth_required = auth_required
    print("fake redis server (%s) listening on 127.0.0.1:%d" % (
        "auth required" if auth_required else "open", port))
    server.serve_forever()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9382
    run(port, auth_required="--auth-required" in sys.argv)
