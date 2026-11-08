#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

EngineClient wraps sqlmap's existing REST-JSON API (lib/utils/api.py,
normally launched via `alkhaapi.py -s`). The AI agent NEVER touches
lib/controller, lib/core/option, or the plugins directly - every action
it takes goes through this same HTTP interface a human operator (or the
existing alkhaapi.py --client) would use. That is what keeps this an
additive layer: the detection/exploitation engine is completely unmodified.
"""

import json
import time

try:
    from urllib.request import Request, urlopen
    from urllib.error import URLError, HTTPError
except ImportError:
    from urllib2 import Request, urlopen, URLError, HTTPError


class EngineError(Exception):
    pass


class EngineClient(object):
    def __init__(self, host="127.0.0.1", port=8775, username=None, password=None, timeout=15):
        self.base = "http://%s:%d" % (host, port)
        self.username = username
        self.password = password
        self.timeout = timeout

    def _request(self, method, path, payload=None):
        url = "%s%s" % (self.base, path)
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = Request(url, data=data, method=method) if data or method == "POST" else Request(url)

        if data:
            req.add_header("Content-Type", "application/json")

        if self.username and self.password:
            import base64
            token = base64.b64encode(("%s:%s" % (self.username, self.password)).encode("utf-8")).decode("ascii")
            req.add_header("Authorization", "Basic %s" % token)

        try:
            resp = urlopen(req, timeout=self.timeout)
            raw = resp.read().decode("utf-8", "replace")
        except HTTPError as ex:
            raise EngineError("sqlmap API HTTP %s on %s: %s" % (ex.code, path, ex.read().decode("utf-8", "replace")))
        except URLError as ex:
            raise EngineError(
                "Could not reach sqlmap REST API at %s (%s). Start it first with: "
                "python alkhaapi.py -s" % (self.base, ex.reason)
            )

        try:
            parsed = json.loads(raw)
        except ValueError:
            raise EngineError("Non-JSON response from sqlmap API on %s: %s" % (path, raw[:300]))

        if not isinstance(parsed, dict):
            # sqlmap's REST API always responds with a JSON object in
            # practice - but every caller below does r.get(...) assuming
            # that unconditionally, so a technically-valid-but-unexpected
            # top-level shape (an array, bare string/number, null) from a
            # proxy/WAF mangling the response, or a future API change,
            # should surface as a clear EngineError here rather than an
            # AttributeError at whichever call site happens to touch it
            # first.
            raise EngineError("Unexpected JSON shape from sqlmap API on %s (expected an object, got %s): %s" % (
                path, type(parsed).__name__, raw[:300]))

        return parsed

    # -- task lifecycle -----------------------------------------------------

    def new_task(self):
        r = self._request("GET", "/task/new")
        if not r.get("success"):
            raise EngineError("Failed to create task: %s" % r)
        return r["taskid"]

    def delete_task(self, taskid):
        return self._request("GET", "/task/%s/delete" % taskid)

    # -- options --------------------------------------------------------

    def set_options(self, taskid, options):
        """options: dict of sqlmap option-name -> value, e.g. {"url": "...", "level": 3}"""
        return self._request("POST", "/option/%s/set" % taskid, options)

    def get_options(self, taskid):
        return self._request("GET", "/option/%s/list" % taskid)

    # -- scan control -----------------------------------------------------

    def start_scan(self, taskid, options):
        r = self._request("POST", "/scan/%s/start" % taskid, options)
        if not r.get("success"):
            raise EngineError("Failed to start scan: %s" % r)
        return r

    def stop_scan(self, taskid):
        return self._request("GET", "/scan/%s/stop" % taskid)

    def kill_scan(self, taskid):
        return self._request("GET", "/scan/%s/kill" % taskid)

    def scan_status(self, taskid):
        return self._request("GET", "/scan/%s/status" % taskid)

    def scan_data(self, taskid):
        return self._request("GET", "/scan/%s/data" % taskid)

    def scan_log(self, taskid, start=None, end=None):
        if start is not None and end is not None:
            return self._request("GET", "/scan/%s/log/%s/%s" % (taskid, start, end))
        return self._request("GET", "/scan/%s/log" % taskid)

    # -- convenience --------------------------------------------------------

    def wait_until_idle(self, taskid, poll_interval=2, timeout=None, on_poll=None):
        """
        Blocks (with periodic callback) until the running scan finishes.
        on_poll(status_dict) is invoked on every poll so a caller can stream
        progress into a UI without duplicating the polling loop.
        """
        start_time = time.time()

        while True:
            status = self.scan_status(taskid)

            if on_poll:
                on_poll(status)

            if status.get("status") != "running":
                return status

            if timeout and (time.time() - start_time) > timeout:
                raise EngineError("Timed out waiting for scan %s to finish" % taskid)

            time.sleep(poll_interval)
