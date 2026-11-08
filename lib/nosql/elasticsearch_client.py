#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Elasticsearch/OpenSearch anonymous-access detection, index enumeration,
and document dumping via the plain HTTP+JSON REST API both engines
expose (identical enough for this module's purposes - OpenSearch is a
fork of Elasticsearch 7.10 and kept the same `_cat`/`_search` surface).
An exposed instance with no security plugin enabled is a very commonly
reported real-world finding: unlike MongoDB or Redis, Elasticsearch
speaks HTTP+JSON natively, so - like lib/nosql/injection_probe.py, and
unlike lib/nosql/mongo_client.py, which needs the pymongo package for
MongoDB's binary wire protocol - this module needs only stdlib HTTP,
no client library.

Deliberately excluded, on purpose, matching the same scoping principle
documented in mongo_client.py's and redis_client.py's module
docstrings (and the reason sqlmap's own os-shell/os-cmd are opt-in and
heavily gated - see lib/ai/safety.py): this is a data-enumeration and
read-only dumping module, not a remote-code-execution one. Specifically
excluded:
    - Any use of the scripting engine (`_scripts`, `script` fields in a
      search body, `_update_by_query` with an inline script). Elasticsearch
      has real, documented CVEs where its scripting engines (old Groovy/
      MVEL sandboxes) allowed remote code execution via crafted scripts -
      using scripting at all here would be reaching for exactly that
      class of technique, not data enumeration.
    - `_snapshot`/`_reindex` with a `remote` source (can be used to read
      from or write to other systems/URLs reachable from the cluster,
      i.e. as an SSRF/exfiltration primitive beyond this instance).
    - Any destructive or write call - `DELETE`, `_delete_by_query`,
      `_update`, `PUT` to create/modify an index or document. This module
      only ever issues `GET` requests.
Anonymous-access detection, `_cat/indices` enumeration, and `_search`-
based read-only document dumping (the direct analogue of
mongo_client.py's dump_collection() or sqlmap's own dump_table) is the
full scope here.
"""

import json

try:
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError
except ImportError:
    from urllib2 import Request, urlopen, HTTPError, URLError


class ElasticsearchUnavailable(Exception):
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
        raise ElasticsearchUnavailable(str(ex.reason if hasattr(ex, "reason") else ex))
    except OSError as ex:
        raise ElasticsearchUnavailable(str(ex))


def scan_anonymous_access(host, port=9200, timeout=4):
    """
    Checks whether an Elasticsearch/OpenSearch instance at host:port
    allows unauthenticated access. Returns a dict: {"status": one of
    "open"/"auth_required"/"error"/"unreachable", "version": the
    engine's reported version string or None, "cluster_name": str or
    None, "index_count": int or None (from a follow-up _cat/indices
    call, best-effort - absence of this doesn't downgrade "open")}.
    """
    try:
        status, body = _get(host, port, "/", timeout)
    except ElasticsearchUnavailable as ex:
        return {"status": "unreachable", "version": None, "cluster_name": None,
                 "index_count": None, "detail": str(ex)}

    if status in (401, 403):
        return {"status": "auth_required", "version": None, "cluster_name": None, "index_count": None}

    if status != 200:
        return {"status": "error", "version": None, "cluster_name": None, "index_count": None,
                 "detail": "unexpected HTTP status %d" % status}

    try:
        parsed = json.loads(body)
    except ValueError:
        return {"status": "error", "version": None, "cluster_name": None, "index_count": None,
                 "detail": "response was not valid JSON"}

    if not isinstance(parsed, dict):
        return {"status": "error", "version": None, "cluster_name": None, "index_count": None,
                 "detail": "unexpected JSON shape (expected an object, got %s)" % type(parsed).__name__}

    version = (parsed.get("version") or {}).get("number") if isinstance(parsed.get("version"), dict) else None
    cluster_name = parsed.get("cluster_name")

    index_count = None
    try:
        indices = enumerate_indices(host, port, timeout)
        index_count = len(indices)
    except Exception:
        pass  # root endpoint answered fine (so access IS open) - _cat/indices being restricted doesn't change that

    return {"status": "open", "version": version, "cluster_name": cluster_name, "index_count": index_count}


def enumerate_indices(host, port=9200, timeout=4):
    """
    Lists indices via GET /_cat/indices?format=json. Returns a list of
    {"index", "health", "docs_count", "store_size"} dicts. Raises
    ElasticsearchUnavailable on a connection failure; a non-open access
    status (401/403/non-200) surfaces as an empty list rather than an
    exception, since scan_anonymous_access() is the function that
    should be used to distinguish "nothing here" from "not authorized" -
    this one assumes you already know access is open.
    """
    status, body = _get(host, port, "/_cat/indices?format=json", timeout)
    if status != 200:
        return []

    try:
        parsed = json.loads(body)
    except ValueError:
        return []

    if not isinstance(parsed, list):
        return []

    result = []
    for entry in parsed:
        if not isinstance(entry, dict):
            continue
        result.append({
            "index": entry.get("index"), "health": entry.get("health"),
            "docs_count": entry.get("docs.count"), "store_size": entry.get("store.size"),
        })
    return result


def dump_index(host, port, index, limit=100, timeout=4):
    """
    Reads up to `limit` documents from `index` via a plain GET /<index>/
    _search?size=<limit> (no query body, no scripting - see this
    module's docstring for why scripting is explicitly out of scope).
    Returns a list of each hit's `_source` dict (the actual document
    content, with Elasticsearch's own `_id`/`_score` metadata stripped
    out - callers that want those can read them from the raw response
    themselves; the analogue of mongo_client.py's dump_collection()
    returning plain documents rather than raw BSON).
    """
    status, body = _get(host, port, "/%s/_search?size=%d" % (index, limit), timeout)
    if status != 200:
        raise ElasticsearchUnavailable("GET /%s/_search returned HTTP %d: %s" % (index, status, body[:300]))

    try:
        parsed = json.loads(body)
    except ValueError:
        raise ElasticsearchUnavailable("non-JSON response from /%s/_search" % index)

    if not isinstance(parsed, dict):
        raise ElasticsearchUnavailable("unexpected JSON shape from /%s/_search" % index)

    hits = ((parsed.get("hits") or {}).get("hits")) or []
    if not isinstance(hits, list):
        return []

    return [hit.get("_source", {}) for hit in hits if isinstance(hit, dict)]


def get_server_info(host, port=9200, timeout=4):
    """Returns the parsed root-endpoint response (name, cluster_name,
    version dict, tagline) - the Elasticsearch/OpenSearch analogue of
    mongo_client.py's/redis_client.py's get_server_info()."""
    status, body = _get(host, port, "/", timeout)
    if status != 200:
        raise ElasticsearchUnavailable("GET / returned HTTP %d" % status)
    try:
        parsed = json.loads(body)
    except ValueError:
        raise ElasticsearchUnavailable("non-JSON response from /")
    if not isinstance(parsed, dict):
        raise ElasticsearchUnavailable("unexpected JSON shape from / (expected an object)")
    return parsed
