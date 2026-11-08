#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Guardrails for the autonomous agent loop. These do NOT limit sqlmap's
capabilities (nothing here touches the engine) - they limit what the
*LLM* is allowed to trigger on its own, so a fully autonomous run stays
inside the scope and budget the operator actually authorized.

These defaults are deliberately conservative but every one of them is a
constructor argument / CLI flag - an operator running an authorized
engagement can widen or disable them (e.g. --agent-yolo). The point is
that autonomy is opt-out per-guardrail, not that any guardrail is hidden
or unconfigurable.
"""

import re

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

# Actions the agent can take without per-step human confirmation even in
# autonomous mode, because they are read-only / non-destructive against
# the target or purely local bookkeeping.
SAFE_ACTIONS = {
    "set_target", "configure_scan", "start_scan", "check_status",
    "get_findings", "get_logs", "stop_scan", "finish", "note",
    "list_databases", "list_tables", "list_columns", "list_tamper_scripts",
    "check_waf_status", "escalate_attack", "recommend_tamper_for_dbms", "crawl_target",
    "search_data", "diagnose_detection_failure",
    "nosql_scan_target", "nosql_enumerate", "nosql_search_collections", "nosql_test_injection",
}

# Actions that mutate target-side state or exfiltrate significant data
# volume - these are gated behind the confirm callback even when the
# agent is otherwise running autonomously, unless the operator passed
# --agent-yolo.
HIGH_RISK_ACTIONS = {
    "dump_all", "dump_table", "os_shell", "os_cmd", "file_write", "file_read",
    "registry_write", "takeover", "nosql_dump_collection", "redis_dump_keys",
    "elasticsearch_dump_index", "couchdb_dump_database",
}


class ScopeViolation(Exception):
    pass


class BudgetExceeded(Exception):
    pass


class SafetyPolicy(object):
    def __init__(self, allowed_hosts, max_iterations=40, max_wall_clock=3600,
                 yolo=False, confirm_callback=None):
        """
        allowed_hosts: iterable of hostnames/IPs the operator explicitly
                        authorized for this run (derived from the target
                        URL(s) they supplied - the agent can never add a
                        new host to scope on its own).
        max_iterations: hard cap on plan->act->observe loop iterations.
        max_wall_clock: hard cap in seconds for the whole autonomous run.
        yolo:           if True, HIGH_RISK_ACTIONS execute without the
                        confirm_callback prompt. Off by default.
        confirm_callback: callable(action_name, args) -> bool, used to ask
                        the human operator before a high-risk action runs.
                        If None and yolo is False, high-risk actions are
                        simply refused (fail safe).
        """
        self.allowed_hosts = set(h.lower() for h in allowed_hosts)
        self.max_iterations = max_iterations
        self.max_wall_clock = max_wall_clock
        self.yolo = yolo
        self.confirm_callback = confirm_callback
        self._start_time = None
        self._iterations = 0

    def start(self):
        import time
        self._start_time = time.time()
        self._iterations = 0

    def check_host_in_scope(self, url_or_host):
        if not isinstance(url_or_host, str):
            raise ScopeViolation(
                "Refusing to act - the target/host/url argument must be a string, got %s (%r). "
                "This is almost always malformed model output, not a legitimate action." % (
                    type(url_or_host).__name__, url_or_host
                )
            )

        parsed = urlparse(url_or_host if "://" in url_or_host else "//" + url_or_host)
        host = (parsed.hostname or url_or_host).lower()

        if host not in self.allowed_hosts:
            raise ScopeViolation(
                "Refusing to act against '%s' - not in the authorized scope for this run (%s). "
                "Start a new agent run with --target if you intend to test this host." % (
                    host, ", ".join(sorted(self.allowed_hosts)) or "<none>"
                )
            )

    def tick(self):
        import time
        self._iterations += 1

        if self._iterations > self.max_iterations:
            raise BudgetExceeded("Agent hit its iteration cap (%d) without finishing." % self.max_iterations)

        if self._start_time and (time.time() - self._start_time) > self.max_wall_clock:
            raise BudgetExceeded("Agent hit its wall-clock budget (%ds) without finishing." % self.max_wall_clock)

    def authorize(self, action_name, args):
        """
        Raises ScopeViolation, or returns False (skip this action) / True
        (go ahead) for high-risk actions. Does NOT tick the iteration/time
        budget itself - the caller ticks exactly once per loop iteration
        (including on parse failures) so budget accounting stays 1:1 with
        actual planner turns regardless of which/how many actions run.

        `args` is untrusted model output (parsed from the planning model's
        JSON/tool-call reply, not validated structurally before reaching
        here) - a malformed or hallucinated reply can hand this a list,
        string, number, or None instead of a dict. Fail safe (raise
        ScopeViolation, the same "refuse and let the caller nudge a retry"
        path as an out-of-scope host) rather than let a raw AttributeError/
        TypeError escape and crash the whole autonomous run - see
        lib/ai/tests/test_safety.py's TestMalformedArgsRobustness.
        """
        if not isinstance(args, dict):
            raise ScopeViolation(
                "Refusing '%s' - its arguments were %s, not an object/dict, which is not a "
                "valid tool call. This is almost always malformed model output." % (
                    action_name, type(args).__name__
                )
            )

        target = args.get("url") or args.get("target") or args.get("host")
        if target:
            self.check_host_in_scope(target)

        if action_name in HIGH_RISK_ACTIONS and not self.yolo:
            if self.confirm_callback is None:
                return False
            return bool(self.confirm_callback(action_name, args))

        return True
