# Alkha Agent (Ollama-powered autonomous layer)

Phase 1 of Alkha's enhancement over stock sqlmap: a fully autonomous
plan → act → observe loop, driven by a local Ollama model, that
operates the unmodified sqlmap engine toward an operator-given goal.

## Design principles

1. **Additive only.** Nothing in `lib/controller`, `lib/core`, or
   `plugins` was modified. The agent is a new `lib/ai/` package plus one
   new entry point, `alkha_agent.py`. `alkha.py` and `alkhaapi.py` are
   byte-for-byte unchanged.
2. **The agent is a REST API client, not a new engine.** It drives
   sqlmap exactly the way `alkhaapi.py --client` or any external
   integration already could - `task/new`, `option/set`, `scan/start`,
   `scan/status`, `scan/data`, `scan/log`, `scan/stop`. All 30 DBMS
   plugins, every technique, every tamper script keep working exactly as
   before; the LLM just decides *which* of sqlmap's existing capabilities
   to invoke and when.
3. **Closed tool set.** The model cannot run arbitrary shell commands or
   arbitrary HTTP requests - only the ten named actions in
   `lib/ai/tools.py`, each mapped to a specific REST endpoint.
4. **Local-only "brain."** Ollama runs on the operator's own machine (or
   any host they point it at) - no API key, no third-party LLM vendor
   sees engagement data.
5. **Scope and budget are enforced outside the model's control.**
   `lib/ai/safety.py`'s `SafetyPolicy`:
   - derives the allowed host(s) from the `--target` the *operator*
     supplied - the model can never add a new host to scope;
   - hard-caps loop iterations (`--max-iterations`, default 40) and
     wall-clock time (`--max-seconds`, default 3600);
   - gates high-risk actions (currently `dump_all`; the list is easy to
     extend) behind an operator confirmation prompt unless `--agent-yolo`
     is explicitly passed;
   - fails safe on malformed/hallucinated model output rather than
     crashing: every value derived from the model's reply (`args`,
     `url`/`host`/`target`) is type-checked before use, everywhere it
     enters this codebase (`tools.py`, `safety.py`, `planner.py`'s
     reply parsing) - see `doc/ALKHA.md` §15 for the fuzz audit that
     found and closed this as a systemic gap, not a one-off fix.

## Architecture

```
alkha_agent.py            CLI entry point, terminal event stream
lib/ai/
  api_bootstrap.py         auto-launches alkhaapi.py -s if nothing is listening yet
  ollama_client.py         stdlib-only HTTP client for Ollama /api/chat
  engine_client.py         typed wrapper over sqlmap's existing REST API
  tools.py                 the closed action schema + executor
  safety.py                scope / iteration / risk guardrails
  memory.py                transcript + structured findings store
  planner.py                the plan->act->observe loop itself
```

Every turn: the planner builds a system+transcript prompt describing the
goal, target, tool schema and guardrail summary; asks Ollama for a single
JSON `{"thought": ..., "action": {"name": ..., "args": {...}}}`; validates
the action against `SafetyPolicy`; executes it via `EngineClient`; records
the observation; repeats until the model calls `finish`, a budget is hit,
or the operator interrupts (Ctrl-C stops the scan cleanly).

## Usage

```bash
# 1. install & run a local model
ollama pull llama3.1
ollama serve

# 2. run the agent against an authorized target - one terminal is enough now
python alkha_agent.py \
    --target "http://testphp.vulnweb.com/artists.php?artist=1" \
    --goal "Determine if the 'artist' parameter is SQL injectable and identify the DBMS" \
    --model llama3.1 \
    --json-report report.json
```

If nothing is listening at `--api-host`/`--api-port` (default
`127.0.0.1:8775`), `alkha_agent.py` auto-starts `alkhaapi.py -s` itself
and shuts it down when the run ends - see the "Done since this doc was
first written" section below. You can still run `python alkhaapi.py -s`
by hand first the old way (e.g. to share one server across several
agent runs, or to point at a non-default host) - the agent detects it's
already up and leaves it alone. Pass `--no-auto-start-api` to require a
pre-started server and fail fast instead if one isn't reachable.

Useful flags: `--agent-yolo` (skip high-risk confirmation), `--max-iterations`,
`--max-seconds`, `--api-host/--api-port` (if the REST API runs elsewhere),
`--no-auto-start-api` (require a pre-started REST API), `--insecure-api`/
`--allow-dangerous-options` (passed through to an auto-started server),
`--ollama-host` (remote Ollama), `--data`/`--cookie` (initial request context).

## Extending the tool set

Add a new entry to `TOOL_SPECS` in `lib/ai/tools.py` with a name,
description and args schema, then handle it in `ToolExecutor.execute()`
by calling the corresponding `EngineClient` method (add one if the REST
API doesn't expose it yet - see `lib/utils/api.py` for the full endpoint
list: options, scan control, data, log, admin, download). Whatever you
add is automatically available through both `alkha_agent.py`'s own
loop and the MCP server below - there's only the one tool catalog.

## MCP server

`alkha_mcp_server.py` exposes the exact same tool catalog and
`SafetyPolicy` the autonomous loop above uses, over the Model Context
Protocol (JSON-RPC 2.0 over stdio), so any MCP client - Claude Code,
another orchestrator, your own tooling - can drive real scans through a
standard protocol instead of only through this file's own loop:

```bash
python alkha_mcp_server.py --target "http://example.com/page.php?id=1"
```

Scope is fixed at startup from `--target`/`--allowed-hosts` (at least
one is required - the server refuses to start without it). A
`HIGH_RISK` tool call (`dump_table`, `os_cmd`, `redis_dump_keys`, ...)
is refused by default, the same fail-safe as an un-gated CLI run - pass
`--yolo` to allow them for the session; there's no interactive
confirmation prompt over MCP, since not every client supports MCP's
elicitation capability - the binary choice at startup is the honest
alternative to pretending to prompt and then not. `--max-iterations`
defaults to 500 (vs. the CLI agent's 40) and `--max-seconds` to 24
hours - a persistent server serving an external client's deliberately
chosen calls is a different usage pattern than a self-directed
autonomous loop, so it gets a correspondingly different (not absent)
budget. The REST API auto-starts the same way `alkha_agent.py`'s does
(`--no-auto-start-api` to disable).

**If you're extending this file**: MCP's stdio transport uses stdout
as the actual protocol channel - never write anything else there.
`lib/core/tui.py`'s rendering functions are never imported here for
exactly this reason; every diagnostic goes to stderr.

See `doc/ALKHA.md` §22 for the full writeup, including what was
deliberately *not* added here and why.

## What's deliberately NOT done yet (next phases)

- The specific weak points you found during your own code review -
  tell me what they are and I'll fold fixes into the next pass.

## Phase 2 terminal UI (done)

The Claude-Code-style terminal UI overhaul listed here as "not done
yet" is now done: `lib/core/tui.py` gained `iteration_rule()` (a
divider marking each loop turn with iteration count and elapsed
time), `state_line()` (a compact "what we know so far" recap, printed
only when structured findings actually changed that turn), and
`render_final_report()` (a real structured summary - DBMS/user/
injection-points headline, database/table/dump counts, notes/caveats
as a visually distinct block - replacing the old notes-only panel).
`alkha_agent.py`'s bare `on_event` function became a stateful
`EventRenderer` class that starts a live spinner on a new
`thinking_start` event (emitted before every Ollama call, including
retries) so the terminal isn't silently frozen during a slow local
model, and stops it before any other line prints.

Verified by actually running a full scripted plan->act->observe loop
end-to-end through the real rendering code and reading the output,
not just asserting individual functions don't crash - that live run
caught a genuine pre-existing bug unrelated to the UI work itself:
`AgentMemory`'s grounding-check regex had no word boundary, so
`"table"` matched as a substring inside `"injec[table]"`, producing a
false "you claimed an unconfirmed database" caveat on an accurate
summary. Fixed with a `\b` word boundary and a regression test built
from the exact sentence that triggered it - see `doc/ALKHA.md`.

## Done since this doc was first written (corrections, not additions)

Two items used to be listed above as "not done yet." Both turned out to
already be implemented and tested by the time this doc was re-checked
against the actual code - this section corrects the record rather than
re-announcing them as new work:

- **Native Ollama tool-calling.** `AgentPlanner` already defaults to
  `use_native_tools=True`: `_chat_with_retry` sends
  `render_native_tool_schema()` from `lib/ai/tools.py` on every call,
  and `_parse_reply` checks `reply["tool_calls"]` first, falling back
  to strict-JSON-in-content parsing only when a model doesn't return a
  native tool call. Covered by
  `test_planner_integration.TestPlannerNativeToolCalling` (asserts the
  tool schema was actually sent) alongside the existing
  `TestPlannerJsonFallback` coverage for models without native support.
- **Auto-launching `alkhaapi.py -s`.** `lib/ai/api_bootstrap.py`
  (`ensure_server_running()`) now checks whether something is already
  listening at `--api-host`/`--api-port`; if not, and the host is a
  loopback address, it spawns `alkhaapi.py -s` as a managed subprocess,
  polls until the port opens (or the process dies, or a startup
  timeout is hit), and hands the `Popen` handle back to
  `alkha_agent.py`, which shuts it down when the run ends via
  `shutdown()`. A pre-existing server (or a non-default
  `--api-host`/`--api-port` someone is already running) is detected
  and left alone rather than duplicated. Disable with
  `--no-auto-start-api` to require a pre-started server as before.
  Non-loopback `--api-host` with nothing listening there is reported
  as a clear configuration error rather than silently doing nothing,
  since this process has no way to start something on a remote host.
  Unit-tested with injectable `popen_fn`/`port_check_fn`
  (`lib/ai/tests/test_api_bootstrap.py`, 13 tests, no real subprocess
  or socket involved) **and** verified against the real thing: spawned
  a genuine `alkhaapi.py -s` on a free port, confirmed a second call
  detects it's already up instead of double-spawning, drove a real
  `task/new` + `option/list` round-trip through `EngineClient` against
  it, and confirmed `shutdown()` actually closes the port afterward.
