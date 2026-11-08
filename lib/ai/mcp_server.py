#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

A Model Context Protocol (MCP) server exposing Alkha's existing tool
catalog (lib/ai/tools.py's TOOL_SPECS/ToolExecutor - the same closed
set of SQL/NoSQL/Redis/Elasticsearch/CouchDB actions alkha_agent.py's
own autonomous loop uses) to any MCP client over stdio - Claude Code,
another orchestrator, or any tool that speaks the protocol.

This is deliberately a thin transport/dispatch layer, not a second
implementation of anything: every tool call still goes through the
exact same lib/ai/safety.py SafetyPolicy (scope-locking to the
operator-authorized host(s), HIGH_RISK_ACTIONS gating) and
lib/ai/tools.py ToolExecutor the CLI agent uses. An MCP client gets
exactly the same closed, safety-checked action set - not a side door
around it. In particular:
    - There is still no "run arbitrary shell command" tool here, for
      the same reason lib/ai/tools.py's own module docstring gives:
      this is a closed set of specific, named actions, not general
      remote code execution.
    - A HIGH_RISK action (dump_table, redis_dump_keys,
      elasticsearch_dump_index, couchdb_dump_database, ...) is refused
      by default, exactly like an un-gated CLI run - construct the
      server with yolo=True (the --yolo flag on alkha_mcp_server.py)
      to allow them, the same explicit opt-in --agent-yolo already
      requires for the CLI agent. There is no MCP-native interactive
      confirmation prompt implemented here (that would need the
      client to support MCP's elicitation capability, which not all
      clients do yet) - the binary yolo/no-yolo choice at server
      startup is the honest alternative: never silently allow, never
      pretend to prompt and then not.
    - Scope is fixed at server startup from the operator-supplied
      --target/--allowed-hosts, exactly like the CLI agent derives it
      from --target - an MCP client can never expand scope by asking
      for a new host, only by the operator restarting the server with
      a different scope.

Protocol notes: implements the MCP stdio transport (JSON-RPC 2.0,
one complete JSON object per line, UTF-8, no embedded newlines) and
just the methods a tool-calling client needs - initialize,
notifications/initialized, tools/list, tools/call, ping. No resources,
prompts, sampling, or elicitation capabilities - this server only ever
needs to advertise and run tools.
"""

import json
import sys
import time

from lib.ai.tools import TOOL_SPECS, ToolExecutor
from lib.ai.safety import SafetyPolicy, ScopeViolation, BudgetExceeded

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "alkha"
SERVER_VERSION = "1.0.0"


def tool_list_for_mcp():
    """
    Converts TOOL_SPECS into MCP's tools/list shape - {"name",
    "description", "inputSchema"} per tool, inputSchema being standard
    JSON Schema. Every argument is typed as a JSON Schema "string" (the
    same simplification lib/ai/tools.py's own
    render_native_tool_schema() already makes for Ollama's function-
    calling schema - TOOL_SPECS' args descriptions are free text for a
    model to read, not a real type system to infer from); "required" is
    populated by looking for the literal "(required)" substring each
    arg's own description already uses to tell a model the same thing.
    """
    tools = []
    for spec in TOOL_SPECS:
        properties = {}
        required = []
        for arg_name, arg_desc in spec["args"].items():
            properties[arg_name] = {"type": "string", "description": str(arg_desc)}
            if "(required)" in str(arg_desc):
                required.append(arg_name)

        schema = {"type": "object", "properties": properties}
        if required:
            schema["required"] = required

        tools.append({"name": spec["name"], "description": spec["description"], "inputSchema": schema})
    return tools


class McpServer(object):
    def __init__(self, engine_client, taskid, safety_policy, stdin=None, stdout=None, on_event=None):
        self.tools = ToolExecutor(engine_client, taskid)
        self.safety = safety_policy
        self.stdin = stdin if stdin is not None else sys.stdin
        self.stdout = stdout if stdout is not None else sys.stdout
        self._emit = on_event or (lambda *a, **kw: None)
        self._initialized = False

    def serve_forever(self):
        self.safety.start()
        for line in self.stdin:
            line = line.strip()
            if not line:
                continue
            self.handle_line(line)

    def handle_line(self, line):
        """Parses and dispatches exactly one incoming JSON-RPC line. Split out from
        serve_forever() so tests can feed lines directly without a real stdin stream."""
        try:
            msg = json.loads(line)
        except ValueError:
            return  # malformed JSON with no reliable id to respond to - drop it, per JSON-RPC convention

        if not isinstance(msg, dict):
            return

        method = msg.get("method")
        msg_id = msg.get("id")  # absent/None on a notification - no response is sent for those

        try:
            if method == "initialize":
                self._initialized = True
                self._respond(msg_id, {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                })
            elif method == "notifications/initialized":
                pass  # client acknowledging initialize - no response for a notification
            elif method == "ping":
                self._respond(msg_id, {})
            elif method == "tools/list":
                self._respond(msg_id, {"tools": tool_list_for_mcp()})
            elif method == "tools/call":
                self._handle_tool_call(msg_id, msg.get("params") or {})
            else:
                self._error(msg_id, -32601, "Method not found: %s" % method)
        except Exception as ex:
            # a truly unexpected exception in dispatch itself (not a tool
            # error, which _handle_tool_call already converts to a normal
            # isError result) - report it as a JSON-RPC error rather than
            # letting it kill the whole server process over one bad call.
            self._error(msg_id, -32603, "Internal error: %s" % ex)

    def _handle_tool_call(self, msg_id, params):
        name = params.get("name")
        arguments = params.get("arguments")
        if arguments is None:
            arguments = {}

        if not isinstance(arguments, dict):
            self._tool_error(msg_id, "'arguments' must be an object, got %s" % type(arguments).__name__)
            return

        try:
            allowed = self.safety.authorize(name, arguments)
        except ScopeViolation as ex:
            self._emit("refused", {"name": name, "reason": str(ex)})
            self._tool_error(msg_id, str(ex))
            return

        if not allowed:
            self._emit("refused", {"name": name, "reason": "high-risk, not yolo"})
            self._tool_error(msg_id, "'%s' is a high-risk action and was refused - restart the MCP "
                                       "server with --yolo to allow it for this session." % name)
            return

        try:
            self.safety.tick()
        except BudgetExceeded as ex:
            self._tool_error(msg_id, str(ex))
            return

        self._emit("call", {"name": name, "arguments": arguments})
        result = self.tools.execute(name, arguments)
        self._emit("result", {"name": name, "result": result})

        is_error = isinstance(result, dict) and result.get("ok") is False
        self._respond(msg_id, {"content": [{"type": "text", "text": json.dumps(result)}], "isError": is_error})

    def _tool_error(self, msg_id, message):
        # a refused/invalid tool call is reported as a normal tools/call
        # result with isError=true (the MCP-idiomatic way - lets a client
        # show the model what went wrong and retry), not a JSON-RPC
        # protocol-level error, which is reserved for _dispatch failures.
        self._respond(msg_id, {"content": [{"type": "text", "text": message}], "isError": True})

    def _respond(self, msg_id, result):
        if msg_id is None:
            return
        self._write({"jsonrpc": "2.0", "id": msg_id, "result": result})

    def _error(self, msg_id, code, message):
        if msg_id is None:
            return
        self._write({"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}})

    def _write(self, obj):
        self.stdout.write(json.dumps(obj) + "\n")
        self.stdout.flush()


def build_default_safety_policy(allowed_hosts, yolo=False, max_iterations=500, max_wall_clock=None):
    """
    Higher default max_iterations than the CLI agent's (40): the CLI
    agent's cap exists to bound a SELF-directed autonomous loop that
    decides its own next action - a runaway/looping local model is the
    risk that cap defends against. An MCP server is driven by an
    external client making deliberate, individually-chosen tool calls
    (a human, or another agent under its own separate judgment) over
    what may legitimately be a long testing session, so a much higher
    default is the honest fit for how this is actually used - it is
    still a real, finite cap, not disabled.
    """
    return SafetyPolicy(allowed_hosts=allowed_hosts, max_iterations=max_iterations,
                          max_wall_clock=max_wall_clock or (24 * 3600), yolo=yolo)
