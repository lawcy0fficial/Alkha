#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

alkha_agent.py - Alkha's autonomous agentic runner, powered by a
local Ollama model driving the unmodified sqlmap engine underneath.
The classic sqlmap scanning engine is unmodified - this is a new,
standalone entry point on top of it (see doc/NEXTGEN.md).

Rendering goes entirely through lib/core/tui.py - the same module behind
alkha.py's --modern-ui - so the agent and the classic engine share one
visual language instead of each entry point inventing its own ANSI
formatting.

Usage:
    # 1) start the REST API server (separate terminal):
    python alkhaapi.py -s

    # 2) point the agent at an authorized target with a goal:
    python alkha_agent.py --target "http://testphp.vulnweb.com/artists.php?artist=1" \\
                            --goal "Determine if the 'artist' parameter is SQL injectable and identify the DBMS" \\
                            --model llama3.1

Flags of note:
    --agent-yolo         skip confirmation prompts for high-risk actions
                          (e.g. dump_all) - use only when you are certain
                          the engagement authorizes it.
    --max-iterations N   hard cap on agent loop steps (default 40)
    --max-seconds N      hard cap on wall-clock run time (default 3600)
    --ollama-host        default http://127.0.0.1:11434
    --api-host/--api-port  where sqlmap's own REST API is listening
    --no-auto-start-api  don't auto-launch alkhaapi.py -s if nothing is
                          listening at --api-host/--api-port yet (by
                          default, a loopback --api-host with nothing
                          reachable there gets one spawned and managed
                          automatically - see lib/ai/api_bootstrap.py)
"""

from __future__ import print_function

import argparse
import json
import os
import sys

sys.dont_write_bytecode = True

from lib.ai.api_bootstrap import ensure_server_running, shutdown as shutdown_api, ApiBootstrapError
from lib.ai.engine_client import EngineClient, EngineError
from lib.ai.ollama_client import OllamaClient
from lib.ai.planner import AgentPlanner
from lib.ai.safety import SafetyPolicy
from lib.core.tui import (render_welcome_panel, step, substep, kv_table, style,
                           iteration_rule, state_line, render_final_report, Spinner)


class EventRenderer(object):
    """
    Stateful on_event callback (planner.py's AgentPlanner just calls
    on_event(kind, payload) - it has no notion of a terminal, spinners,
    or anything stateful across calls). This class owns the one thing a
    bare function couldn't: an active Spinner instance that starts on
    "thinking_start" and must be stopped again before ANY other line
    prints, or its \\r-driven redraw would corrupt whatever printed next.

    Kept in alkha_agent.py rather than lib/core/tui.py because it
    encodes *this entry point's* opinion of which tui.py primitive each
    planner event maps to - tui.py stays a library of independent
    rendering primitives with no knowledge of the agent's event vocabulary.
    """

    def __init__(self):
        self._spinner = None

    def _stop_spinner(self):
        if self._spinner is not None:
            self._spinner.__exit__(None, None, None)
            self._spinner = None

    def __call__(self, kind, payload):
        if kind == "thinking_start":
            # a fresh "thinking_start" can arrive while one is already
            # running (the retry-backoff re-emit in planner.py's
            # _chat_with_retry) - stop any stale one first rather than
            # leaking a second background thread.
            self._stop_spinner()
            self._spinner = Spinner("thinking")
            self._spinner.__enter__()
            return

        # every other event kind prints a normal line - the spinner's
        # \r redraw loop must not still be running underneath it.
        self._stop_spinner()

        if kind == "iteration_start":
            iteration_rule(payload["n"], payload["max_n"], payload["elapsed"])
        elif kind == "thought":
            if payload:
                substep("thinking: %s" % payload)
        elif kind == "action":
            args_str = ", ".join("%s=%r" % (k, v) for k, v in (payload.get("args") or {}).items())
            step("%s(%s)" % (payload["name"], args_str), status="running")
        elif kind == "observation":
            summary = payload if not isinstance(payload, dict) else {k: v for k, v in payload.items() if k != "data"}
            substep(_short(summary))
        elif kind == "state":
            state_line(payload)
        elif kind == "warning":
            step(payload, status="warn")
        elif kind == "done":
            step("run complete", status="done")


def _short(obj, limit=220):
    s = str(obj)
    return s if len(s) <= limit else s[:limit] + " …"


def confirm(action_name, args):
    prompt = style("[confirm] ", "warn") + "run high-risk action '%s' with args %r? [y/N] " % (action_name, args)
    reply = input(prompt)
    return reply.strip().lower() in ("y", "yes")


def main():
    parser = argparse.ArgumentParser(description="Autonomous Ollama-powered agent for sqlmap")
    parser.add_argument("--target", required=True, help="Authorized target URL")
    parser.add_argument("--goal", required=True, help="What you want the agent to accomplish")
    parser.add_argument("--data", help="POST data for the target request")
    parser.add_argument("--cookie", help="Cookie header for the target request")
    parser.add_argument("--model", default="llama3.1", help="Ollama model tag (default: llama3.1)")
    parser.add_argument("--ollama-host", default="http://127.0.0.1:11434")
    parser.add_argument("--api-host", default="127.0.0.1", help="sqlmap REST API host")
    parser.add_argument("--api-port", default=8775, type=int, help="sqlmap REST API port")
    parser.add_argument("--api-username", default=None)
    parser.add_argument("--api-password", default=None)
    parser.add_argument("--no-auto-start-api", dest="auto_start_api", action="store_false", default=True,
                         help="don't auto-launch alkhaapi.py -s when --api-host/--api-port isn't reachable "
                              "(default: auto-start it if --api-host is a loopback address)")
    parser.add_argument("--insecure-api", dest="insecure_api", action="store_true",
                         help="passed through to an auto-started API server - see alkhaapi.py --insecure-api")
    parser.add_argument("--allow-dangerous-options", dest="allow_dangerous_options", action="store_true",
                         help="passed through to an auto-started API server - see alkhaapi.py --allow-dangerous-options")
    parser.add_argument("--max-iterations", default=40, type=int)
    parser.add_argument("--max-seconds", default=3600, type=int)
    parser.add_argument("--agent-yolo", action="store_true", help="skip confirmation for high-risk actions")
    parser.add_argument("--json-report", default=None, help="write the final structured report to this path")
    args = parser.parse_args()

    render_welcome_panel(
        model=args.model,
        ollama_host=args.ollama_host,
        target=args.target,
        goal=args.goal,
        workdir=os.getcwd(),
    )

    spawned_api_proc = None
    if args.auto_start_api:
        try:
            spawned_api_proc = ensure_server_running(
                args.api_host, args.api_port,
                username=args.api_username, password=args.api_password,
                insecure=args.insecure_api, allow_dangerous_options=args.allow_dangerous_options,
                on_event=lambda msg: substep(msg),
            )
        except ApiBootstrapError as ex:
            step(str(ex), status="fail")
            sys.exit(1)

    engine = EngineClient(host=args.api_host, port=args.api_port,
                           username=args.api_username, password=args.api_password)

    try:
        taskid = engine.new_task()
    except EngineError as ex:
        step(str(ex), status="fail")
        shutdown_api(spawned_api_proc)
        sys.exit(1)

    kv_table([("task", taskid)])
    print()

    ollama = OllamaClient(host=args.ollama_host, model=args.model)

    safety = SafetyPolicy(
        allowed_hosts=_hosts_from_target(args.target),
        max_iterations=args.max_iterations,
        max_wall_clock=args.max_seconds,
        yolo=args.agent_yolo,
        confirm_callback=None if args.agent_yolo else confirm,
    )

    goal = args.goal
    if args.data or args.cookie:
        goal += " (initial request context: data=%r cookie=%r)" % (args.data, args.cookie)

    planner = AgentPlanner(
        engine_client=engine,
        taskid=taskid,
        ollama_client=ollama,
        goal=goal,
        target=args.target,
        safety_policy=safety,
        on_event=EventRenderer(),
    )

    try:
        report = planner.run()
    except KeyboardInterrupt:
        print()
        step("interrupted - stopping scan and cleaning up task...", status="warn")
        try:
            engine.stop_scan(taskid)
        except EngineError:
            pass
        shutdown_api(spawned_api_proc)
        sys.exit(130)

    print()
    render_final_report(report)

    if args.json_report:
        with open(args.json_report, "w") as f:
            json.dump(report, f, indent=2)
        kv_table([("report", args.json_report)])

    shutdown_api(spawned_api_proc)


def _hosts_from_target(target):
    try:
        from urllib.parse import urlparse
    except ImportError:
        from urlparse import urlparse
    parsed = urlparse(target if "://" in target else "//" + target)
    return [parsed.hostname] if parsed.hostname else [target]


if __name__ == "__main__":
    main()
