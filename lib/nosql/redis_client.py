#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Redis anonymous-access detection, key enumeration, and value dumping.
An exposed Redis instance with no `requirepass` set (or with
`protected-mode no` on a non-loopback bind) is one of the most commonly
reported real-world misconfigurations in bug bounty programs - Redis
has no authentication by default, and its RESP wire protocol is simple
enough to implement directly here with no external dependency (unlike
lib/nosql/mongo_client.py, which needs the pymongo package because
MongoDB's wire protocol is not something to reimplement by hand).

This is a from-scratch RESP2 client, not a port of any existing tool's
code - Redis speaks a simple text protocol (see
https://redis.io/docs/latest/develop/reference/protocol-spec/), so
there's no NoSQLMap-style prior art to port the way mongo_client.py
had. `_send_command`/`_read_reply` below implement just enough of RESP2
to issue commands and parse simple-string/error/integer/bulk-string/
array replies - not the full protocol (no RESP3, no pub/sub, no
pipelining), which is all this module needs.

Deliberately NOT implemented, on purpose, matching the same scoping
principle mongo_client.py's module docstring documents for MongoDB
(and the same reason sqlmap's os-shell/os-cmd are blocked by default -
see lib/ai/safety.py): this is a data-enumeration and dumping module,
not a remote-code-execution one. Specifically excluded:
    - Writing an SSH public key or cron job via CONFIG SET dir/dbfilename
      + SAVE (the classic unauthenticated-Redis-to-RCE technique) -
      this achieves code execution on the target host, not data
      exfiltration, and is out of scope the same way sqlmap's
      out-of-band OS command execution is opt-in and heavily gated,
      not something this data-focused module reaches for.
    - MODULE LOAD (loading a malicious .so to gain RCE) - same reasoning.
    - Replication-based attacks (REPLICAOF pointing the target at an
      attacker-controlled master to inject arbitrary data/commands) -
      same reasoning; this is an active-manipulation technique, not
      read-only enumeration.
    - FLUSHALL/FLUSHDB, or any other destructive/write command - this
      module only ever reads.
Anonymous-access detection, key enumeration, and read-only value
dumping (the direct analogue of mongo_client.py's dump_collection, or
sqlmap's own dump_table) is the full scope here.
"""

import socket


class RedisUnavailable(Exception):
    pass


_CRLF = b"\r\n"


def _encode_command(*args):
    """Encodes a command as a RESP2 array of bulk strings, e.g. ("GET", "foo") ->
    b"*2\\r\\n$3\\r\\nGET\\r\\n$3\\r\\nfoo\\r\\n"."""
    parts = [b"*%d" % len(args)]
    for arg in args:
        if isinstance(arg, bytes):
            data = arg
        else:
            data = str(arg).encode("utf-8", "replace")
        parts.append(b"$%d" % len(data))
        parts.append(data)
    return _CRLF.join(parts) + _CRLF


def _read_line(sock_file):
    line = sock_file.readline()
    if not line:
        raise RedisUnavailable("connection closed while reading a reply")
    return line.rstrip(b"\r\n")


def _read_reply(sock_file):
    """Reads and parses exactly one RESP2 reply. Returns a Python str/int/list/None
    (None for a RESP nil bulk string or nil array), or raises RedisError for a RESP
    error reply ("-ERR ..." etc.) so callers can branch on auth-required vs. a real
    error without string-matching a returned value themselves."""
    prefix = sock_file.read(1)
    if not prefix:
        raise RedisUnavailable("connection closed while reading a reply")

    if prefix == b"+":
        return _read_line(sock_file).decode("utf-8", "replace")

    if prefix == b"-":
        raise RedisError(_read_line(sock_file).decode("utf-8", "replace"))

    if prefix == b":":
        return int(_read_line(sock_file))

    if prefix == b"$":
        length = int(_read_line(sock_file))
        if length == -1:
            return None
        data = sock_file.read(length)
        sock_file.read(2)  # trailing CRLF
        return data.decode("utf-8", "replace")

    if prefix == b"*":
        count = int(_read_line(sock_file))
        if count == -1:
            return None
        return [_read_reply(sock_file) for _ in range(count)]

    raise RedisUnavailable("unrecognized RESP reply type byte: %r" % prefix)


class RedisError(Exception):
    """A RESP error reply (e.g. "NOAUTH Authentication required.") - distinct from
    RedisUnavailable (a connection/protocol problem), so callers can tell "the
    server answered, and said no" from "the server never answered at all"."""
    pass


def _connect(host, port, timeout):
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as ex:
        raise RedisUnavailable(str(ex))
    return sock, sock.makefile("rb")


def _command(sock, sock_file, *args):
    sock.sendall(_encode_command(*args))
    return _read_reply(sock_file)


def scan_anonymous_access(host, port=6379, timeout=4):
    """
    Checks whether a Redis instance at host:port allows unauthenticated
    access. Returns a dict: {"status": one of "open"/"auth_required"/
    "error"/"unreachable", "version": Redis server version string or
    None, "mode": standalone/cluster/sentinel or None}.
    """
    try:
        sock, sock_file = _connect(host, port, timeout)
    except RedisUnavailable as ex:
        return {"status": "unreachable", "version": None, "mode": None, "detail": str(ex)}

    try:
        try:
            pong = _command(sock, sock_file, "PING")
        except RedisError as ex:
            if "NOAUTH" in str(ex).upper():
                return {"status": "auth_required", "version": None, "mode": None}
            return {"status": "error", "version": None, "mode": None, "detail": str(ex)}

        if pong != "PONG":
            return {"status": "error", "version": None, "mode": None,
                     "detail": "unexpected PING reply: %r" % pong}

        version, mode = None, None
        try:
            info = _command(sock, sock_file, "INFO", "server")
            info_dict = _parse_info(info)
            version = info_dict.get("redis_version")
            mode = info_dict.get("redis_mode")
        except RedisError:
            pass  # PING succeeded (so access IS open) but INFO happened to be restricted - rare, non-fatal

        return {"status": "open", "version": version, "mode": mode}
    except RedisUnavailable as ex:
        return {"status": "unreachable", "version": None, "mode": None, "detail": str(ex)}
    finally:
        sock.close()


def _parse_info(raw):
    """Parses Redis's INFO command output (colon-separated "key:value" lines,
    "#"-prefixed section headers, blank lines) into a flat dict."""
    result = {}
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        result[key] = value
    return result


def enumerate_keys(host, port=6379, pattern="*", limit=1000, timeout=4):
    """
    Enumerates keys matching `pattern` via cursor-based SCAN (not the
    blocking KEYS command - SCAN is the documented-safe way to iterate
    a potentially large keyspace without stalling the server for other
    clients, which matters since this may be someone else's production
    instance). Stops once `limit` keys have been collected or the
    server signals iteration is complete (cursor back to "0").

    Returns a dict: {"keys": [...], "truncated": bool, "total_returned": int}.
    Raises RedisUnavailable if the connection fails, RedisError if
    authentication is required (callers should call scan_anonymous_access
    first to check).
    """
    sock, sock_file = _connect(host, port, timeout)
    try:
        keys = []
        cursor = "0"
        while True:
            reply = _command(sock, sock_file, "SCAN", cursor, "MATCH", pattern, "COUNT", "100")
            cursor, batch = reply[0], reply[1]
            keys.extend(batch)
            if len(keys) >= limit or cursor == "0":
                break
        truncated = len(keys) > limit
        return {"keys": keys[:limit], "truncated": truncated, "total_returned": min(len(keys), limit)}
    finally:
        sock.close()


_DUMP_HANDLERS = {
    "string": lambda sock, sock_file, key: _command(sock, sock_file, "GET", key),
    "list": lambda sock, sock_file, key: _command(sock, sock_file, "LRANGE", key, "0", "-1"),
    "set": lambda sock, sock_file, key: _command(sock, sock_file, "SMEMBERS", key),
    "hash": lambda sock, sock_file, key: _pairs_to_dict(_command(sock, sock_file, "HGETALL", key)),
    "zset": lambda sock, sock_file, key: _pairs_to_tuples(
        _command(sock, sock_file, "ZRANGE", key, "0", "-1", "WITHSCORES")),
}


def _pairs_to_dict(flat_list):
    return dict(zip(flat_list[0::2], flat_list[1::2]))


def _pairs_to_tuples(flat_list):
    return list(zip(flat_list[0::2], flat_list[1::2]))


def dump_keys(host, port, keys, timeout=4):
    """
    Reads the value of each key in `keys`, using the right read command
    for its type (TYPE first, then GET/LRANGE/SMEMBERS/HGETALL/ZRANGE as
    appropriate) - the direct analogue of mongo_client.py's
    dump_collection() or sqlmap's own dump_table. Read-only: never
    SET/DEL/EXPIRE/FLUSH* anything.

    Returns a list of {"key", "type", "value"} dicts. A key whose type
    isn't one of the five above (a Redis Stream, HyperLogLog, or a
    module-defined type) gets {"type": <that type>, "value": None} rather
    than being skipped silently, so a caller can see it exists without
    this module needing a handler for every possible type.
    """
    sock, sock_file = _connect(host, port, timeout)
    try:
        results = []
        for key in keys:
            key_type = _command(sock, sock_file, "TYPE", key)
            handler = _DUMP_HANDLERS.get(key_type)
            value = handler(sock, sock_file, key) if handler else None
            results.append({"key": key, "type": key_type, "value": value})
        return results
    finally:
        sock.close()


def get_server_info(host, port=6379, timeout=4):
    """Returns the full parsed INFO dict (all sections) - version, mode, memory
    usage, connected clients, keyspace stats, etc."""
    sock, sock_file = _connect(host, port, timeout)
    try:
        raw = _command(sock, sock_file, "INFO")
        return _parse_info(raw)
    finally:
        sock.close()
