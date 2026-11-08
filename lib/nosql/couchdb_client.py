#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

CouchDB anonymous-access detection, database enumeration, and document
dumping via CouchDB's plain HTTP+JSON REST API. Like
lib/nosql/elasticsearch_client.py (and unlike lib/nosql/mongo_client.py,
which needs the pymongo package for MongoDB's binary wire protocol),
this needs only stdlib HTTP - CouchDB has been an HTTP-native document
store since its first release.

Deliberately excluded, on purpose, matching the same scoping principle
documented in mongo_client.py's/redis_client.py's/elasticsearch_client.py's
module docstrings (and the reason sqlmap's own os-shell/os-cmd are
opt-in and heavily gated - see lib/ai/safety.py): this is a data-
enumeration and read-only dumping module, not a remote-code-execution
one. Specifically excluded:
    - The CVE-2017-12635 / CVE-2017-12636 technique chain (a type-
      confusion bug in how CouchDB validated a new user document's
      "roles" field let a non-admin register themselves as an admin,
      then abuse the admin-only `_config/os_daemons` endpoint to add an
      arbitrary shell command as a persistent "daemon" CouchDB itself
      launches - a real, well-documented unauthenticated-to-RCE chain
      against unpatched CouchDB). This module never writes to `_users`
      or `_config` at all.
    - Any other write to `_config` (CouchDB's runtime configuration is
      itself an admin-only HTTP API - writing to it is a configuration-
      manipulation/RCE surface, not data enumeration).
    - Any destructive or write call - `DELETE`, `PUT`, `_bulk_docs`,
      `_compact`. This module only ever issues `GET` requests.
Anonymous-access detection, `_all_dbs` enumeration, and `_all_docs`-
based read-only document dumping (the direct analogue of
mongo_client.py's dump_collection(), redis_client.py's dump_keys(), or
elasticsearch_client.py's dump_index()) is the full scope here.
"""

import json

try:
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError
except ImportError:
    from urllib2 import Request, urlopen, HTTPError, URLError


class CouchDBUnavailable(Exception):
    pass


def _get(host, port, path, timeout):
    url = "http://%s:%d%s" % (host, port, path)
    req = Request(url, headers={"Accept": "application/json"})
    try:
        resp = urlopen(req, timeout=timeout)
        return resp.getcode(), resp.read().decode("utf-8", "replace")
    except HTTPError as ex:
        try:
            body = ex.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        return ex.code, body
    except URLError as ex:
        raise CouchDBUnavailable(str(ex.reason if hasattr(ex, "reason") else ex))
    except OSError as ex:
        raise CouchDBUnavailable(str(ex))


def scan_anonymous_access(host, port=5984, timeout=4):
    """
    Checks whether a CouchDB instance at host:port allows unauthenticated
    access to `_all_dbs` (the standard "is this instance wide open"
    check - a properly secured CouchDB 2.x+ install requires admin
    credentials for this). Returns a dict: {"status": one of "open"/
    "auth_required"/"error"/"unreachable", "version": CouchDB's reported
    version string or None, "database_count": int or None}.
    """
    try:
        status, body = _get(host, port, "/_all_dbs", timeout)
    except CouchDBUnavailable as ex:
        return {"status": "unreachable", "version": None, "database_count": None, "detail": str(ex)}

    if status in (401, 403):
        return {"status": "auth_required", "version": None, "database_count": None}

    if status != 200:
        return {"status": "error", "version": None, "database_count": None,
                 "detail": "unexpected HTTP status %d" % status}

    try:
        databases = json.loads(body)
    except ValueError:
        return {"status": "error", "version": None, "database_count": None,
                 "detail": "response was not valid JSON"}

    if not isinstance(databases, list):
        return {"status": "error", "version": None, "database_count": None,
                 "detail": "unexpected JSON shape (expected an array, got %s)" % type(databases).__name__}

    version = None
    try:
        info = get_server_info(host, port, timeout)
        version = info.get("version")
    except Exception:
        pass  # _all_dbs answered fine (so access IS open) - the root endpoint being restricted is rare, non-fatal

    return {"status": "open", "version": version, "database_count": len(databases)}


def enumerate_databases(host, port=5984, timeout=4):
    """
    Lists databases via GET /_all_dbs. Returns a list of database name
    strings. A non-open access status (401/403/non-200) surfaces as an
    empty list rather than an exception, since scan_anonymous_access()
    is the function that should be used to distinguish "no databases"
    from "not authorized" - this one assumes you already know access is
    open (matching elasticsearch_client.py's enumerate_indices()
    convention).
    """
    status, body = _get(host, port, "/_all_dbs", timeout)
    if status != 200:
        return []

    try:
        parsed = json.loads(body)
    except ValueError:
        return []

    return [name for name in parsed if isinstance(name, str)] if isinstance(parsed, list) else []


def dump_database(host, port, database, limit=100, timeout=4):
    """
    Reads up to `limit` documents from `database` via GET /<database>/
    _all_docs?include_docs=true&limit=<limit>. Returns a list of each
    row's `doc` dict (a CouchDB document already contains its own
    "_id"/"_rev" fields as genuine document content, unlike
    Elasticsearch's separate `_id`/`_score` wrapper metadata - so unlike
    elasticsearch_client.py's dump_index(), nothing needs stripping
    here). Design-doc rows (id starting with "_design/") are skipped -
    they're CouchDB's own view/index definitions, not application data,
    the same reasoning mongo_client.py's enumerate_databases() has no
    special case for MongoDB's own system collections needing one here
    (CouchDB's equivalent just needs an explicit filter since
    `_all_docs` returns them interleaved with real documents).
    """
    status, body = _get(host, port, "/%s/_all_docs?include_docs=true&limit=%d" % (database, limit), timeout)
    if status != 200:
        raise CouchDBUnavailable("GET /%s/_all_docs returned HTTP %d: %s" % (database, status, body[:300]))

    try:
        parsed = json.loads(body)
    except ValueError:
        raise CouchDBUnavailable("non-JSON response from /%s/_all_docs" % database)

    if not isinstance(parsed, dict):
        raise CouchDBUnavailable("unexpected JSON shape from /%s/_all_docs" % database)

    rows = parsed.get("rows")
    if not isinstance(rows, list):
        return []

    docs = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        doc = row.get("doc")
        if isinstance(doc, dict) and not str(doc.get("_id", "")).startswith("_design/"):
            docs.append(doc)
    return docs


def get_server_info(host, port=5984, timeout=4):
    """Returns the parsed root-endpoint response (couchdb welcome string,
    version, vendor info) - the CouchDB analogue of mongo_client.py's/
    redis_client.py's/elasticsearch_client.py's get_server_info()."""
    status, body = _get(host, port, "/", timeout)
    if status != 200:
        raise CouchDBUnavailable("GET / returned HTTP %d" % status)
    try:
        parsed = json.loads(body)
    except ValueError:
        raise CouchDBUnavailable("non-JSON response from /")
    if not isinstance(parsed, dict):
        raise CouchDBUnavailable("unexpected JSON shape from / (expected an object)")
    return parsed
