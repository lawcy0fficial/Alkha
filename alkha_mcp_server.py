#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Entry point for the Alkha MCP server (see lib/ai/mcp_server.py for the
protocol/dispatch implementation and the reasoning behind what this
does and deliberately doesn't expose).

Usage:
    python alkha_mcp_server.py --target "http://example.com/page.php?id=1"

CRITICAL: MCP's stdio transport uses stdout as the actual JSON-RPC
message channel - nothing else may ever be written there, or every MCP
client reading it breaks. All diagnostic/status output in this file
goes to stderr instead, and lib/core/tui.py's rendering functions
(which write to real stdout) are deliberately never imported here -
unlike alkha_agent.py, which is a normal interactive terminal program
and uses them freely.
"""

import argparse
import sys

from lib.ai.api_bootstrap import ensure_server_running, shutdown as shutdown_api, ApiBootstrapError
from lib.ai.engine_client import EngineClient, EngineError
from lib.ai.mcp_server import McpServer, build_default_safety_policy
from lib.ai.planner import _hosts_from_target


def _log(message):
    print(message, file=sys.stderr)
    sys.stderr.flush()


def main():
    parser = argparse.ArgumentParser(
        description="Alkha MCP server - exposes the same safety-gated tool catalog "
                    "alkha_agent.py's autonomous loop uses, to any MCP client over stdio.")
    parser.add_argument("--target", default=None,
                         help="authorized target URL - its host becomes part of the authorized scope")
    parser.add_argument("--allowed-hosts", default=None,
                         help="comma-separated additional authorized hosts/IPs (at least one of "
                              "--target/--allowed-hosts is required)")
    parser.add_argument("--yolo", action="store_true",
                         help="allow HIGH_RISK tool calls (dump_table, redis_dump_keys, "
                              "elasticsearch_dump_index, couchdb_dump_database, ...) without this "
                              "flag, every tools/call for one of them is refused, the same fail-safe "
                              "default as an un-gated CLI agent run")
    parser.add_argument("--max-iterations", type=int, default=500,
                         help="hard cap on tool calls for this server's lifetime (default 500 - "
                              "higher than alkha_agent.py's 40, since a persistent server serving "
                              "an external client's deliberate calls is a different usage pattern "
                              "than a self-directed autonomous loop - see "
                              "lib/ai/mcp_server.py's build_default_safety_policy())")
    parser.add_argument("--max-seconds", type=int, default=24 * 3600,
                         help="hard cap on this server's wall-clock lifetime in seconds (default 24h)")
    parser.add_argument("--api-host", default="127.0.0.1")
    parser.add_argument("--api-port", default=8775, type=int)
    parser.add_argument("--api-username", default=None)
    parser.add_argument("--api-password", default=None)
    parser.add_argument("--no-auto-start-api", dest="auto_start_api", action="store_false", default=True,
                         help="don't auto-launch alkhaapi.py -s when --api-host/--api-port isn't "
                              "reachable (see lib/ai/api_bootstrap.py)")
    parser.add_argument("--insecure-api", dest="insecure_api", action="store_true")
    parser.add_argument("--allow-dangerous-options", dest="allow_dangerous_options", action="store_true")
    args = parser.parse_args()

    hosts = []
    if args.target:
        hosts.extend(_hosts_from_target(args.target))
    if args.allowed_hosts:
        hosts.extend(h.strip() for h in args.allowed_hosts.split(",") if h.strip())
    hosts = [h for h in hosts if h]

    if not hosts:
        _log("error: --target or --allowed-hosts is required to establish the authorized scope "
             "every tool call is checked against")
        sys.exit(1)

    spawned_api_proc = None
    if args.auto_start_api:
        try:
            spawned_api_proc = ensure_server_running(
                args.api_host, args.api_port,
                username=args.api_username, password=args.api_password,
                insecure=args.insecure_api, allow_dangerous_options=args.allow_dangerous_options,
                on_event=_log,
            )
        except ApiBootstrapError as ex:
            _log(str(ex))
            sys.exit(1)

    engine = EngineClient(host=args.api_host, port=args.api_port,
                           username=args.api_username, password=args.api_password)
    try:
        taskid = engine.new_task()
    except EngineError as ex:
        _log(str(ex))
        shutdown_api(spawned_api_proc)
        sys.exit(1)

    safety = build_default_safety_policy(hosts, yolo=args.yolo, max_iterations=args.max_iterations,
                                          max_wall_clock=args.max_seconds)

    _log("alkha MCP server ready - scope: %s - yolo: %s - task: %s" % (
        ", ".join(sorted(safety.allowed_hosts)), args.yolo, taskid))

    server = McpServer(engine, taskid, safety, on_event=lambda kind, payload: _log("[%s] %s" % (kind, payload)))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _log("interrupted, shutting down")
    finally:
        try:
            engine.stop_scan(taskid)
        except EngineError:
            pass
        shutdown_api(spawned_api_proc)


if __name__ == "__main__":
    main()
