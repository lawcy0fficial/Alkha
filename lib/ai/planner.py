#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

The agentic core: a plan -> act -> observe loop that lets a local Ollama
model drive sqlmap's own REST API toward an operator-given goal, using
only the closed tool set in lib.ai.tools. This module never imports
lib.controller / lib.core.option / plugins directly - it only ever talks
to the engine over HTTP via EngineClient, same as a human operator using
alkhaapi.py --client would.
"""

import json
import time

from lib.ai.ollama_client import OllamaClient, OllamaError, extract_json_block
from lib.ai.tools import TOOL_SPECS, ToolExecutor, render_tool_spec_for_prompt, render_native_tool_schema, tool_names
from lib.ai.safety import SafetyPolicy, ScopeViolation, BudgetExceeded
from lib.ai.memory import AgentMemory
from lib.ai.knowledge_base import KnowledgeBase

SYSTEM_PROMPT_TEMPLATE = """You are the autonomous planning core of an authorized web application \
security assessment, driving the open-source tool sqlmap through a fixed \
set of actions. The operator has explicitly authorized testing against: \
{target}. Never suggest or reference any other target.

Your goal for this run: {goal}

Known so far (ground truth from the engine, not your memory of the chat):
{facts}
{prior_knowledge}

You may ONLY act by returning a single JSON object of the exact shape:
{{"thought": "<your reasoning, 1-3 sentences>", "action": {{"name": "<tool name>", "args": {{...}}}}}}

No text outside that JSON object. Available tools:
{tools}

Guidance:
- Always set_target before configure_scan/start_scan.
- If the goal is to assess a whole site rather than one known URL, or
  set_target's URL has no obvious injectable parameter, call
  crawl_target instead of start_scan to discover more pages/forms first.
- Prefer a conservative level/risk first, then escalate only if findings
  justify it (e.g. no injection found at level=1,risk=1 -> try level=3,risk=2).
- Use check_status and get_findings to observe results before deciding the
  next step - don't call start_scan repeatedly without checking outcomes.
- If configure_scan's observation includes a "warnings" list, an option
  name you used didn't match a real sqlmap option and was dropped - use
  the suggested correction (if any) and retry with the corrected name.
- If a scan is still running, prefer check_status over starting a new one.
- If start_scan's observation includes a "warning" about a repeated
  configuration, change something (level/risk/technique/tamper) before
  retrying - identical inputs will produce identical results.
- Once an injection point is confirmed, use list_databases -> list_tables
  -> list_columns -> dump_table in that order to enumerate incrementally,
  rather than reaching for dump_all immediately.
- If you're looking for something specific (credentials, tokens, PII)
  rather than exploring generally, call search_data with a keyword
  instead of dumping full tables blindly - it's faster and more precise.
- dump_table accepts columns/where/start_row/stop_row to narrow a dump
  once you know what you need - prefer that over a full-table dump when
  you only need specific rows or fields.
- If a scan completes with no injection found and get_logs suggests
  filtering/WAF interference (blocked requests, unexpected redirects,
  suspiciously uniform responses), call list_tamper_scripts before giving
  up - don't conclude "not injectable" without trying evasion first.
- Call check_waf_status early if a scan finds nothing - it reads
  sqlmap's own automatic WAF/IPS heuristic result directly, don't guess
  this from free-text logs yourself.
- If a scan finds nothing, call diagnose_detection_failure before
  escalating blindly - it distinguishes page-instability (needs a
  manual 'string'/'notString' hint - sqlmap's own documented fix,
  normally offered interactively but skipped in --batch mode), WAF
  detection, and an inconclusive early heuristic, each of which calls
  for a different next step rather than the same generic retry.
- Once a scan at the current settings has found nothing, prefer
  escalate_attack over hand-picking new configure_scan options - it
  advances through a fixed, deliberate sequence (broaden coverage ->
  max level/risk/technique -> light WAF evasion -> aggressive WAF
  evasion -> isolate each technique individually) so each attempt is
  guaranteed meaningfully different from the last. Only override it with
  your own configure_scan choice if you have a specific, stated reason
  (e.g. you already know the DBMS and want a DBMS-specific tamper
  script - call recommend_tamper_for_dbms once "Known so far" shows a
  DBMS, and prefer its suggestions over escalate_attack's generic set).
- If a parameter looks like it stores a value for later use (a name,
  comment, profile field, registration form) rather than reflecting it
  immediately, and normal testing finds nothing, consider it might be
  SECOND-ORDER: the injection's effect may only appear on a different
  page. If the goal or context suggests where that might be (a profile
  page, a confirmation page, an admin listing), set configure_scan's
  options to include secondUrl set to that other page's URL - sqlmap
  will submit the payload to the current target and check THAT other
  URL's response for the true/false or timing signal instead of the
  immediate response.
- If the target seems Node/Express/MongoDB-backed rather than
  SQL-backed (e.g. sqlmap's own tests consistently find nothing despite
  escalation, or the goal mentions MongoDB/NoSQL directly), use
  nosql_test_injection to probe for operator/$where-clause injection
  instead of continuing to force SQL-specific techniques. For a bare
  MongoDB host (no web app in front of it), use nosql_scan_target ->
  nosql_enumerate -> nosql_search_collections/nosql_dump_collection,
  mirroring the SQL-side enumerate-then-narrow pattern.
- When you have enough evidence to answer the goal (or have exhausted
  reasonable options), call finish with a clear summary.
- finish is refused if you haven't called get_findings, check_status,
  or get_logs at least once this run - there must be something to
  ground the summary in. Repeating the exact same action with the exact
  same arguments several times in a row is also blocked - if that
  happens, change something or move on rather than retrying identically.
"""


class PlannerError(Exception):
    pass


class AgentPlanner(object):
    def __init__(self, engine_client, taskid, ollama_client, goal, target,
                 safety_policy=None, on_event=None, use_native_tools=True,
                 knowledge_base=None, max_ollama_retries=3, retry_backoff_base=1.0,
                 stuck_action_threshold=3, sleep_fn=time.sleep):
        """
        on_event(kind, payload): optional callback invoked for every
        thought/action/observation, so a CLI/TUI can stream progress
        instead of waiting for the whole run to finish. kind is one of
        "iteration_start" (a new loop turn began; payload is
        {"n", "max_n", "elapsed"}), "thinking_start" (about to block on
        an Ollama call - may fire more than once per iteration, once per
        retry attempt), "thought", "action", "observation", "state" (the
        structured findings summary changed this turn; payload is the
        facts_summary() string), "warning", "done".

        use_native_tools: try Ollama's OpenAI-style function-calling
        (tool_calls in the response) first, for models that support it
        (llama3.1, qwen2.5, mistral-nemo, ...) - lower latency and more
        reliable than parsing JSON out of free-text content, since it
        skips the extract-JSON-then-retry loop entirely on a hit. Models
        without native tool-calling support just ignore the `tools` field
        and reply in plain text as before; step() falls back to the
        strict-JSON-in-content parsing automatically on the same call, no
        extra round-trip.

        knowledge_base: KnowledgeBase instance (lib/ai/knowledge_base.py)
        for cross-run memory of this host. Defaults to the standard
        ~/.sqlmap/agent_knowledge.json store; pass an explicit instance
        (or one pointed at a throwaway path) to disable/isolate it, e.g.
        in tests.

        max_ollama_retries / retry_backoff_base: a transient Ollama
        failure (model warming up, brief network blip) used to end the
        entire run immediately (PlannerError). Now retried with
        exponential backoff (retry_backoff_base * 2**attempt seconds)
        before giving up - a single hiccup shouldn't cost the whole scan.

        stuck_action_threshold: if the model calls the exact same tool
        with the exact same arguments this many times in a row, step()
        refuses to execute it again and returns a nudge observation
        instead - catches unproductive loops (repeatedly calling
        get_logs or check_status with no new information) that the
        model's own judgement failed to break out of. This is separate
        from and broader than ToolExecutor's own repeat-start_scan-
        configuration warning (lib/ai/tools.py), which only covers scan
        configurations and still lets the call through with a warning;
        this one actively blocks after the threshold, for any action.

        sleep_fn: injectable in place of time.sleep, so tests can verify
        retry behavior without real wall-clock delay.
        """
        self.engine = engine_client
        self.taskid = taskid
        self.ollama = ollama_client
        self.memory = AgentMemory(goal=goal, target=target)
        self.tools = ToolExecutor(engine_client, taskid)
        self.safety = safety_policy or SafetyPolicy(allowed_hosts=_hosts_from_target(target))
        self.on_event = on_event or (lambda kind, payload: None)
        self.use_native_tools = use_native_tools
        self.kb = knowledge_base if knowledge_base is not None else KnowledgeBase()
        self.max_ollama_retries = max_ollama_retries
        self.retry_backoff_base = retry_backoff_base
        self.stuck_action_threshold = stuck_action_threshold
        self._sleep = sleep_fn
        self._recent_actions = []  # rolling window of (name, sorted-args-tuple) actually executed
        self._has_gathered_evidence = False  # has get_findings/check_status/get_logs ever run?

    def _emit(self, kind, payload):
        self.on_event(kind, payload)

    def _build_messages(self):
        system = SYSTEM_PROMPT_TEMPLATE.format(
            target=self.memory.target,
            goal=self.memory.goal,
            facts=self.memory.facts_summary(),
            prior_knowledge=self.kb.render_for_prompt(self.memory.target) or "",
            tools=render_tool_spec_for_prompt(),
        )
        messages = [{"role": "system", "content": system}]

        for event in self.memory.transcript_for_prompt():
            if event["role"] == "tool":
                content = event["content"]
                messages.append({
                    "role": "user",
                    "content": "OBSERVATION for action '%s': %s" % (
                        content["action"], _truncate(str(content["result"]), 2000)
                    ),
                })
            elif event["role"] == "assistant":
                messages.append({"role": "assistant", "content": event["content"]})

        if len(messages) == 1:
            messages.append({"role": "user", "content": "Begin. Decide your first action."})

        return messages

    def step(self):
        """Runs exactly one plan->act->observe cycle. Returns True if finished."""
        self.safety.tick()

        self._emit("iteration_start", {
            "n": self.safety._iterations,
            "max_n": self.safety.max_iterations,
            "elapsed": (time.time() - self.safety._start_time) if self.safety._start_time else 0,
        })

        messages = self._build_messages()
        self._emit("thinking_start", None)
        reply = self._chat_with_retry(messages)

        name, args, thought, assistant_record = self._parse_reply(reply)

        if name is None:
            self._emit("warning", "Model returned no parseable action; nudging it to retry.")
            self.memory.record("assistant", assistant_record)
            self.memory.record("tool", {
                "action": "_parse_error",
                "args": {},
                "result": "Your last reply wasn't a valid tool call or JSON action object. "
                          "Respond with ONLY the JSON object described in the system prompt "
                          "(or a tool call, if your model supports it).",
            })
            return False

        self._emit("thought", thought)
        self.memory.record("assistant", assistant_record)

        if name not in tool_names():
            self._emit("warning", "Model chose unknown tool '%s'" % name)
            self.memory.record_action(name, args, {"ok": False, "error": "unknown tool"})
            return False

        if name == "finish" and not self._has_gathered_evidence:
            self._emit("warning", "Blocked finish - no observation-gathering action "
                                   "(get_findings/check_status/get_logs, or a nosql_*/redis_*/"
                                   "elasticsearch_*/couchdb_* tool) has been called yet this run.")
            self.memory.record_action(name, args, {
                "ok": False,
                "error": "finish refused: you haven't called get_findings, check_status, get_logs, "
                         "a nosql_* tool (nosql_scan_target/nosql_enumerate/nosql_test_injection/"
                         "nosql_search_collections/nosql_dump_collection), a redis_* tool "
                         "(redis_scan_target/redis_enumerate_keys/redis_dump_keys), an "
                         "elasticsearch_* tool (elasticsearch_scan_target/"
                         "elasticsearch_enumerate_indices/elasticsearch_dump_index), or a couchdb_* "
                         "tool (couchdb_scan_target/couchdb_enumerate_databases/"
                         "couchdb_dump_database) even once this run, so there's nothing to ground a "
                         "summary in. Call one of those first.",
            })
            return False

        if self._is_stuck_repeat(name, args):
            self._emit("warning", "Blocked repeated action '%s' with identical arguments "
                                   "(called %d times in a row with no change) - forcing a different next step." % (
                                       name, self.stuck_action_threshold))
            self.memory.record_action(name, args, {
                "ok": False,
                "error": "This exact action with these exact arguments has been called %d times in a "
                         "row with no new information gained. Repeating it again won't help - change "
                         "the arguments, try a different tool, or call finish if you've exhausted "
                         "reasonable options." % self.stuck_action_threshold,
            })
            return False

        try:
            allowed = self.safety.authorize(name, args)
        except ScopeViolation as ex:
            self._emit("warning", str(ex))
            self.memory.record_action(name, args, {"ok": False, "error": str(ex)})
            return False

        if not allowed:
            self._emit("warning", "High-risk action '%s' blocked - needs operator confirmation or --agent-yolo." % name)
            self.memory.record_action(name, args, {"ok": False, "error": "blocked: requires confirmation"})
            return False

        self._emit("action", {"name": name, "args": args})

        result = self.tools.execute(name, args)
        self._emit("observation", result)

        facts_before = self.memory.facts_summary()
        self.memory.record_action(name, args, result)
        facts_after = self.memory.facts_summary()
        if facts_after != facts_before:
            self._emit("state", facts_after)

        self._track_action(name, args)

        if name in ("get_findings", "check_status", "get_logs",
                    "nosql_scan_target", "nosql_enumerate", "nosql_search_collections",
                    "nosql_dump_collection", "nosql_test_injection",
                    "redis_scan_target", "redis_enumerate_keys", "redis_dump_keys",
                    "elasticsearch_scan_target", "elasticsearch_enumerate_indices",
                    "elasticsearch_dump_index", "couchdb_scan_target",
                    "couchdb_enumerate_databases", "couchdb_dump_database") and result.get("ok"):
            # the nosql_*/redis_*/elasticsearch_*/couchdb_* tools are the
            # non-SQL paths' equivalent of get_findings/check_status -
            # they're how an agent working a MongoDB-, Redis-,
            # Elasticsearch-, or CouchDB-backed target actually observes
            # something, since none of those paths ever touch the sqlmap
            # REST engine at all. Without these here, a run that only ever
            # uses one of these tool families could never pass the finish
            # gate above and would always burn its full iteration/time
            # budget before dying with BudgetExceeded instead of finishing
            # cleanly - found via TestNosqlAgentEndToEnd actually driving a
            # full NoSQL-only agent loop rather than testing each layer in
            # isolation (see doc/ALKHA.md §17); applied proactively to each
            # new backend since then rather than waiting to rediscover the
            # same gap every time (see §19/§20/§21).
            self._has_gathered_evidence = True

        if name == "finish":
            caveats = self.memory.grounding_check(args.get("summary", ""))
            for caveat in caveats:
                self._emit("warning", "grounding check: %s" % caveat)
                self.memory.findings["notes"].append("GROUNDING CHECK: %s" % caveat)

            if self.memory.findings["injection_points"] and not caveats:
                # `tamper` came from a configure_scan call's options dict -
                # validate_options() only checks that "tamper" is a real
                # sqlmap option *name*, not that its *value* is the string
                # the model was supposed to send. A hallucinated
                # configure_scan({"tamper": 12345}) would otherwise crash
                # here with AttributeError, right as a genuinely successful,
                # evidence-backed run tries to persist what it found.
                tamper = self.tools.current_options().get("tamper") or ""
                if not isinstance(tamper, str):
                    tamper = ""
                tamper_list = [t.strip() for t in tamper.split(",") if t.strip()]
                self.kb.record_success(
                    self.memory.target,
                    dbms=self.memory.findings["dbms"],
                    injection_points=self.memory.findings["injection_points"],
                    tamper=tamper_list,
                )

            self._emit("done", self.memory.to_report_dict())
            return True

        return False

    def _chat_with_retry(self, messages):
        last_error = None

        for attempt in range(self.max_ollama_retries + 1):
            try:
                return self.ollama.chat(
                    messages,
                    tools=render_native_tool_schema() if self.use_native_tools else None,
                    json_mode=not self.use_native_tools,
                )
            except OllamaError as ex:
                last_error = ex
                if attempt < self.max_ollama_retries:
                    backoff = self.retry_backoff_base * (2 ** attempt)
                    self._emit("warning", "Ollama call failed (attempt %d/%d): %s - retrying in %.1fs" % (
                        attempt + 1, self.max_ollama_retries + 1, ex, backoff))
                    self._sleep(backoff)
                    self._emit("thinking_start", None)

        self._emit("warning", "Ollama call failed after %d attempts: %s" % (self.max_ollama_retries + 1, last_error))
        raise PlannerError(str(last_error))

    def _is_stuck_repeat(self, name, args):
        signature = (name, tuple(sorted((args or {}).items())))
        window = self._recent_actions[-(self.stuck_action_threshold - 1):]
        return len(window) == self.stuck_action_threshold - 1 and all(a == signature for a in window)

    def _track_action(self, name, args):
        signature = (name, tuple(sorted((args or {}).items())))
        self._recent_actions.append(signature)
        if len(self._recent_actions) > self.stuck_action_threshold + 2:
            self._recent_actions = self._recent_actions[-(self.stuck_action_threshold + 2):]

    def _parse_reply(self, reply):
        """
        Returns (name, args, thought, assistant_record_for_transcript) or
        (None, None, None, raw_content) if nothing parseable was found.
        Tries native tool_calls first, falls back to JSON-in-content.

        `reply` is untrusted model output - every shape assumed below
        (tool_calls[0] being a dict, its "function" being a dict, the
        JSON-parsed "action" being a dict) can fail to hold for a
        malformed or hallucinated reply. Treat any such mismatch as the
        same "nothing parseable" case already handled below for a
        missing/absent action, rather than letting an AttributeError
        propagate out of step() and crash the whole run - see
        lib/ai/tests/test_planner_integration.py's
        TestMalformedReplyRobustness.
        """
        tool_calls = reply.get("tool_calls")

        if tool_calls and isinstance(tool_calls[0], dict):
            call = tool_calls[0].get("function")
            if isinstance(call, dict):
                name = call.get("name")
                raw_args = call.get("arguments")
                if raw_args is None:
                    raw_args = {}
                args = raw_args if isinstance(raw_args, dict) else (extract_json_block(str(raw_args)) or {})
                if not isinstance(args, dict):
                    args = {}
                thought = reply.get("content") or "(native tool call)"
                record = json.dumps({"thought": thought, "action": {"name": name, "args": args}})
                return name, args, thought, record

        content = reply.get("content", "")
        parsed = extract_json_block(content)

        if not parsed or "action" not in parsed or not isinstance(parsed["action"], dict):
            return None, None, None, content

        action = parsed["action"]
        args = action.get("args")
        if not isinstance(args, dict):
            args = {}
        return action.get("name"), args, parsed.get("thought", ""), content

    def run(self):
        """Runs the loop until finish/limits/error. Returns the final report dict."""
        self.safety.start()

        try:
            while True:
                if self.step():
                    break
        except BudgetExceeded as ex:
            self._emit("warning", "Stopping: %s" % ex)
            self.memory.findings["notes"].append("Run stopped early: %s" % ex)
        except PlannerError as ex:
            self._emit("warning", "Stopping due to planner error: %s" % ex)
            self.memory.findings["notes"].append("Run stopped due to error: %s" % ex)

        return self.memory.to_report_dict()


def _hosts_from_target(target):
    try:
        from urllib.parse import urlparse
    except ImportError:
        from urlparse import urlparse

    parsed = urlparse(target if "://" in target else "//" + target)
    return [parsed.hostname] if parsed.hostname else [target]


def _truncate(s, n):
    return s if len(s) <= n else s[:n] + "...(truncated)"
