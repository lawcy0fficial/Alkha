#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Defines the fixed set of actions the planning model is allowed to choose
from, and executes them against an EngineClient. This is intentionally a
CLOSED set (no "run arbitrary shell command" tool) - the agent can only
do what sqlmap's own REST API already exposes, described in plain
language so a local model can reliably pick the right one.

`os_cmd` and `file_read` are NOT an exception to this - each is one
specific, named action mapped to one specific, pre-existing sqlmap
feature (--os-cmd/--file-read), gated HIGH_RISK exactly like
dump_table, and functional only when sqlmap's own engine has already
confirmed the privilege/technique prerequisites those features have
always required (a real injection point with stacked queries or UDF
support). There is still no general-purpose command-execution
primitive here - see lib/ai/option_validator.py's
DANGEROUS_OPTIONS_BLOCKED_FROM_CONFIGURE_SCAN for the other sqlmap
options (osShell/osPwn/osSmb/osBof/fileWrite/regAdd/regDel/...) that
remain deliberately unreachable through this agent, and why.
"""

from lib.ai.tamper_catalog import render_catalog_for_prompt, recommend_for_dbms
from lib.ai.option_validator import validate_options
from lib.ai.escalation import EscalationLadder

TOOL_SPECS = [
    {
        "name": "set_target",
        "description": "Register the target URL/options for this task before starting a scan. Must be called once before configure_scan/start_scan. To test an injection point sqlmap wouldn't otherwise recognize automatically (a specific field inside a JSON/XML body, a specific header value, a specific part of the URL path), put a literal asterisk (*) at that exact position in url/data/headers - sqlmap tests exactly that marked spot instead of guessing.",
        "args": {"url": "string (required)", "data": "string (optional POST body - JSON/XML auto-detected, or mark a spot with *)",
                  "cookie": "string (optional)", "headers": "string (optional) - extra headers as \"Name1: value1\\nName2: value2\", mark an injectable header value with *"},
    },
    {
        "name": "configure_scan",
        "description": "Set sqlmap scan options for the current task, e.g. level, risk, technique, dbms, tamper scripts. Call again any time to adjust strategy based on findings.",
        "args": {"options": "object of sqlmap option name -> value, e.g. {\"level\": 3, \"risk\": 2, \"technique\": \"BEUST\"}"},
    },
    {
        "name": "start_scan",
        "description": "Launch the scan with whatever target/options are currently set. Non-blocking - poll with check_status.",
        "args": {},
    },
    {
        "name": "check_status",
        "description": "Get whether the scan is still running, and how far along it is.",
        "args": {},
    },
    {
        "name": "get_findings",
        "description": "Retrieve structured results collected so far (injection points, DBMS banner, databases/tables/columns/dumped data).",
        "args": {},
    },
    {
        "name": "get_logs",
        "description": "Retrieve recent engine log lines - useful for diagnosing why detection is failing (WAF block, bad parameter, etc).",
        "args": {"start": "int (optional)", "end": "int (optional)"},
    },
    {
        "name": "stop_scan",
        "description": "Stop the current scan (e.g. once enough evidence is gathered, or to reconfigure before restarting).",
        "args": {},
    },
    {
        "name": "list_databases",
        "description": "Enumerate database names on the target DBMS. Only useful after an injection point has been confirmed. Runs a scan pass with the engine's database-enumeration option.",
        "args": {},
    },
    {
        "name": "list_tables",
        "description": "Enumerate tables. If db is omitted, enumerates tables in every database found so far.",
        "args": {"db": "string (optional) - restrict to one database"},
    },
    {
        "name": "list_columns",
        "description": "Enumerate columns (and types) of a specific table.",
        "args": {"db": "string (required)", "table": "string (required)"},
    },
    {
        "name": "dump_table",
        "description": "Dump the contents of one specific table. Lower blast-radius than dump_all - prefer this once you know which table matters. Can be narrowed to specific columns, a row range, or a SQL WHERE condition for a smaller, more targeted, more accurate extraction instead of pulling everything.",
        "args": {"db": "string (required)", "table": "string (required)",
                  "columns": "string (optional) - comma-separated column names, e.g. 'username,password'",
                  "where": "string (optional) - SQL WHERE condition, e.g. \"username='admin'\"",
                  "start_row": "integer (optional) - 1-indexed first row to dump",
                  "stop_row": "integer (optional) - 1-indexed last row to dump"},
    },
    {
        "name": "os_cmd",
        "description": "HIGH RISK: execute exactly one operating-system command on the back-end DBMS host and return its output, via sqlmap's own established stacked-queries/UDF takeover technique (sqlmap itself still requires a confirmed, privileged injection point for this to work - this tool does not add any new capability beyond what sqlmap's --os-cmd already does, it just makes that existing feature agent-callable). Single-shot and non-interactive - not a persistent shell, not a payload delivery mechanism. Requires operator confirmation unless running in --agent-yolo mode, same as dump_table. Call get_findings/check_status afterward to see the command's output.",
        "args": {"command": "string (required) - the exact OS command to execute, e.g. 'whoami' or 'id'"},
    },
    {
        "name": "file_read",
        "description": "HIGH RISK: read one specific file from the back-end DBMS host's filesystem via sqlmap's own established file-read technique (requires a confirmed, privileged injection point, same prerequisite as os_cmd/dump_table - this does not add any new capability beyond sqlmap's --file-read). Read-only - use this to prove filesystem-level impact (e.g. reading /etc/passwd) the same way dump_table proves database-level impact. Requires operator confirmation unless running in --agent-yolo mode. Call get_findings/check_status afterward to see the file's content.",
        "args": {"path": "string (required) - absolute path of the file to read on the DBMS host"},
    },
    {
        "name": "search_data",
        "description": "Search for database/table/column names matching a keyword across the whole schema (e.g. search for 'pass' to find password-like columns without knowing which table holds them first). More targeted and accurate than blindly dumping everything to look for something specific.",
        "args": {"query": "string (required) - keyword to search for, e.g. 'pass', 'email', 'token'",
                  "in_columns": "boolean (optional) - search column names specifically (default: search everywhere)"},
    },
    {
        "name": "dump_all",
        "description": "HIGH RISK: instruct sqlmap to dump all discovered database contents. Requires operator confirmation unless running in --agent-yolo mode.",
        "args": {},
    },
    {
        "name": "list_tamper_scripts",
        "description": "Look up sqlmap's tamper scripts (WAF/IDS evasion, DBMS-specific payload mangling) by keyword. Use this when a scan finds no injection but you suspect filtering/WAF interference, or when you know the DBMS and want DBMS-specific payload variants. Returns name+description pairs; pass names via configure_scan's options as {\"tamper\": \"name1,name2\"}.",
        "args": {"query": "string (optional) - filter by keyword, e.g. 'mysql', 'space', 'waf'. Omit to see common ones."},
    },
    {
        "name": "recommend_tamper_for_dbms",
        "description": "Given a known (or suspected) DBMS, returns tamper scripts specifically restricted to that DBMS first, then generic ones - more targeted than list_tamper_scripts' keyword search since it's based on each script's own declared DBMS restriction, not text matching. Use this once findings show a DBMS but injection detection/dumping is still failing.",
        "args": {"dbms": "string - e.g. 'MySQL', 'PostgreSQL', or the exact value from get_findings' dbms field"},
    },
    {
        "name": "check_waf_status",
        "description": "Check whether sqlmap's own automatic WAF/IPS heuristic (runs at the start of every scan) flagged this target. Deterministic - reads the actual log line, doesn't guess. Call this before deciding evasion is needed.",
        "args": {},
    },
    {
        "name": "escalate_attack",
        "description": "Advance to the next rung of a fixed, deliberate escalation ladder (broaden coverage -> max level/risk/technique -> light WAF evasion -> aggressive WAF evasion -> isolate each technique individually) and start a scan with it. Use this instead of guessing new configure_scan options by hand once a scan at the current settings has found nothing - it guarantees each attempt is meaningfully different from the last, in the order an experienced pentester would actually try them. Returns None/exhausted once every rung has been tried.",
        "args": {},
    },
    {
        "name": "crawl_target",
        "description": "Crawl the target site from a starting URL to discover additional links/pages to test, instead of testing only one pre-identified URL+parameter. Use this when the goal is to assess a whole site/application rather than one known injectable-looking URL, or when set_target's URL has no obvious parameter to test.",
        "args": {"depth": "integer (optional, default 2) - how many links deep to follow", "forms": "boolean (optional) - also parse and test HTML forms found on crawled pages"},
    },
    {
        "name": "diagnose_detection_failure",
        "description": "When a scan finds no injection, call this before escalating blindly - it reads the actual scan log for sqlmap's own specific diagnostic signals (page instability, negative heuristic pre-check, WAF detection) and tells you which apply and what each one actually implies, instead of you guessing from raw log text.",
        "args": {},
    },
    {
        "name": "nosql_scan_target",
        "description": "Check whether a MongoDB instance allows unauthenticated (anonymous) access - a common real-world misconfiguration, independent of any web application in front of it. Use this when the goal involves a MongoDB-backed target directly (not through a web app parameter).",
        "args": {"host": "string (required)", "port": "integer (optional, default 27017)"},
    },
    {
        "name": "nosql_enumerate",
        "description": "List databases and their collections on a MongoDB instance (the NoSQL equivalent of list_databases/list_tables). Requires the instance to already be known accessible (see nosql_scan_target).",
        "args": {"host": "string (required)", "port": "integer (optional, default 27017)",
                  "username": "string (optional)", "password": "string (optional)"},
    },
    {
        "name": "nosql_search_collections",
        "description": "Search collection names across every database on a MongoDB instance for a keyword (e.g. 'user', 'secret') - the NoSQL equivalent of search_data's table-search mode.",
        "args": {"host": "string (required)", "port": "integer (optional, default 27017)", "keyword": "string (required)",
                  "username": "string (optional)", "password": "string (optional)"},
    },
    {
        "name": "nosql_dump_collection",
        "description": "HIGH RISK: extract documents from one MongoDB collection. Requires operator confirmation unless running in --agent-yolo mode, same as dump_table/dump_all on the SQL side. Narrow with query/limit rather than pulling everything.",
        "args": {"host": "string (required)", "port": "integer (optional, default 27017)",
                  "database": "string (required)", "collection": "string (required)",
                  "query": "object (optional) - MongoDB filter, e.g. {\"role\": \"admin\"}",
                  "limit": "integer (optional, default 1000)",
                  "username": "string (optional)", "password": "string (optional)"},
    },
    {
        "name": "nosql_test_injection",
        "description": "Probe a URL+parameter for NoSQL (MongoDB operator or $where-clause) injection in a web application - the non-SQL counterpart to sqlmap's own injection detection. Sends a baseline request plus a fixed set of operator-injection (id[$ne]=1 style) and $where-breakout payloads, comparing response content/status to find bypasses. Use this for a target you suspect is Node/Express/MongoDB-backed rather than SQL-backed.",
        "args": {"url": "string (required)", "param": "string (required) - the parameter name to test"},
    },
    {
        "name": "redis_scan_target",
        "description": "Check whether a Redis instance allows unauthenticated access - Redis has no authentication by default, and an exposed instance is one of the most commonly reported real-world misconfigurations. Use this when the goal involves a Redis-backed target directly (not through a web app parameter).",
        "args": {"host": "string (required)", "port": "integer (optional, default 6379)"},
    },
    {
        "name": "redis_enumerate_keys",
        "description": "List keys on a Redis instance via cursor-based SCAN (never the blocking KEYS command). Requires the instance to already be known accessible (see redis_scan_target).",
        "args": {"host": "string (required)", "port": "integer (optional, default 6379)",
                  "pattern": "string (optional, default '*') - glob-style key pattern",
                  "limit": "integer (optional, default 1000)"},
    },
    {
        "name": "redis_dump_keys",
        "description": "HIGH RISK: read the value of specific Redis keys (auto-detecting each key's type - string/list/set/hash/zset - and using the matching read command). Requires operator confirmation unless running in --agent-yolo mode, same as dump_table/nosql_dump_collection. Read-only - never writes, deletes, or flushes anything. Call redis_enumerate_keys first to find keys worth reading.",
        "args": {"host": "string (required)", "port": "integer (optional, default 6379)",
                  "keys": "array of strings (required) - the specific keys to read"},
    },
    {
        "name": "elasticsearch_scan_target",
        "description": "Check whether an Elasticsearch or OpenSearch instance allows unauthenticated access via its plain HTTP REST API - a very commonly reported real-world finding when the security plugin isn't enabled. Use this when the goal involves an Elasticsearch/OpenSearch-backed target directly (not through a web app parameter).",
        "args": {"host": "string (required)", "port": "integer (optional, default 9200)"},
    },
    {
        "name": "elasticsearch_enumerate_indices",
        "description": "List indices on an Elasticsearch/OpenSearch instance via GET /_cat/indices. Requires the instance to already be known accessible (see elasticsearch_scan_target).",
        "args": {"host": "string (required)", "port": "integer (optional, default 9200)"},
    },
    {
        "name": "elasticsearch_dump_index",
        "description": "HIGH RISK: read documents from a specific Elasticsearch/OpenSearch index via a plain GET .../_search (no scripting, no query body beyond a result-size limit). Requires operator confirmation unless running in --agent-yolo mode, same as dump_table/nosql_dump_collection/redis_dump_keys. Read-only. Call elasticsearch_enumerate_indices first to find indices worth reading.",
        "args": {"host": "string (required)", "port": "integer (optional, default 9200)",
                  "index": "string (required)", "limit": "integer (optional, default 100)"},
    },
    {
        "name": "couchdb_scan_target",
        "description": "Check whether a CouchDB instance allows unauthenticated access to _all_dbs - a properly secured CouchDB 2.x+ install requires admin credentials for this, but many real-world exposed instances don't. Use this when the goal involves a CouchDB-backed target directly (not through a web app parameter).",
        "args": {"host": "string (required)", "port": "integer (optional, default 5984)"},
    },
    {
        "name": "couchdb_enumerate_databases",
        "description": "List databases on a CouchDB instance via GET /_all_dbs. Requires the instance to already be known accessible (see couchdb_scan_target).",
        "args": {"host": "string (required)", "port": "integer (optional, default 5984)"},
    },
    {
        "name": "couchdb_dump_database",
        "description": "HIGH RISK: read documents from a specific CouchDB database via GET .../_all_docs?include_docs=true (design documents are automatically filtered out - only application data is returned). Requires operator confirmation unless running in --agent-yolo mode, same as dump_table/nosql_dump_collection/redis_dump_keys/elasticsearch_dump_index. Read-only. Call couchdb_enumerate_databases first to find databases worth reading.",
        "args": {"host": "string (required)", "port": "integer (optional, default 5984)",
                  "database": "string (required)", "limit": "integer (optional, default 100)"},
    },
    {
        "name": "note",
        "description": "Record an intermediate observation/hypothesis in the agent's own memory without taking an engine action. Use this to think out loud between tool calls.",
        "args": {"text": "string"},
    },
    {
        "name": "finish",
        "description": "Call this when the objective is met (or definitively not achievable) to end the autonomous loop and produce the final report.",
        "args": {"summary": "string - final findings and recommendation"},
    },
]


def tool_names():
    return [t["name"] for t in TOOL_SPECS]


def render_tool_spec_for_prompt():
    lines = []
    for t in TOOL_SPECS:
        lines.append("- %s(%s): %s" % (
            t["name"],
            ", ".join("%s=%s" % (k, v) for k, v in t["args"].items()) or "no args",
            t["description"],
        ))
    return "\n".join(lines)


def render_native_tool_schema():
    """
    Ollama (>= 0.3) supports OpenAI-style function-calling for models
    trained for it (e.g. llama3.1, qwen2.5, mistral-nemo). Converts
    TOOL_SPECS into that schema so capable models can return structured
    tool_calls directly instead of us parsing JSON out of free-text
    content. Models without native tool-calling support simply ignore
    the `tools` field and we fall back to strict-JSON prompting - see
    planner.AgentPlanner.step(), which checks for tool_calls first and
    falls back automatically.
    """
    schema = []
    for t in TOOL_SPECS:
        properties = {}
        for arg_name, arg_desc in t["args"].items():
            properties[arg_name] = {"type": "string", "description": str(arg_desc)}
        schema.append({
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": {"type": "object", "properties": properties},
            },
        })
    return schema


class ToolExecutor(object):
    def __init__(self, engine_client, taskid):
        self.engine = engine_client
        self.taskid = taskid
        self._pending_options = {}
        self._attempted_signatures = set()
        self._ladder = EscalationLadder()

    def current_options(self):
        """Public read-only view of the options accumulated so far via
        set_target/configure_scan - used by the planner to persist which
        tamper scripts (if any) were in effect on a successful run."""
        return dict(self._pending_options)

    def execute(self, name, args):
        # `args` is untrusted model output (parsed from the planning model's
        # JSON/tool-call reply) - a malformed or hallucinated reply can hand
        # this a list, string, number, or None instead of a dict/object.
        # Every branch below assumes dict-like `.get()` access, so validate
        # once here rather than letting an AttributeError from deep inside
        # a branch crash the whole autonomous run - see
        # lib/ai/tests/test_tools.py's TestMalformedArgsRobustness.
        if args is not None and not isinstance(args, dict):
            return {"ok": False, "error": "%s's arguments were %s, not an object/dict, which is "
                                           "not a valid tool call." % (name, type(args).__name__)}
        args = args or {}

        if name == "set_target":
            opts = {"url": args.get("url")}
            if args.get("data"):
                opts["data"] = args["data"]
            if args.get("cookie"):
                opts["cookie"] = args["cookie"]
            if args.get("headers"):
                opts["headers"] = args["headers"]
            self._pending_options.update(opts)
            return {"ok": True, "message": "Target registered", "options": opts}

        if name == "configure_scan":
            clean, errors = validate_options(args.get("options") or {})
            self._pending_options.update(clean)
            result = {"ok": True, "message": "Scan configured", "options": self._pending_options}
            if errors:
                result["warnings"] = errors
            return result

        if name == "start_scan":
            signature = tuple(sorted(self._pending_options.items()))
            repeat = signature in self._attempted_signatures
            self._attempted_signatures.add(signature)

            result = self.engine.start_scan(self.taskid, self._pending_options)
            response = {"ok": True, "message": "Scan started", "engine": result}

            if repeat:
                response["warning"] = (
                    "This exact option configuration was already tried once this run with no "
                    "new evidence recorded since. Repeating it won't produce a different result - "
                    "change level/risk/technique/tamper, or call list_tamper_scripts, before retrying."
                )

            return response

        if name == "check_status":
            return {"ok": True, "status": self.engine.scan_status(self.taskid)}

        if name == "get_findings":
            return {"ok": True, "data": self.engine.scan_data(self.taskid)}

        if name == "get_logs":
            return {"ok": True, "log": self.engine.scan_log(self.taskid, args.get("start"), args.get("end"))}

        if name == "check_waf_status":
            log_result = self.engine.scan_log(self.taskid)
            messages = [entry.get("message", "") for entry in (log_result.get("log") or [])]
            # NOTE: match on "heuristics detected that the target is protected", not the
            # shorter "is protected by some kind of WAF/IPS" - that shorter phrase is also
            # a substring of the neutral "checking if the target is protected by..."
            # announcement that prints regardless of outcome, which caused a real false
            # positive here (caught by lib/ai/tests/test_tools.py) before this fix.
            detected = any("heuristics detected that the target is protected" in m for m in messages)
            checked = detected or any("checking if the target is protected by" in m for m in messages)
            return {
                "ok": True,
                "waf_detected": detected,
                "checked": checked,
                "note": "WAF/IPS detected by sqlmap's own heuristic" if detected else (
                    "Checked, nothing detected" if checked else "Not yet checked - run start_scan first"
                ),
            }

        if name == "diagnose_detection_failure":
            log_result = self.engine.scan_log(self.taskid)
            messages = [entry.get("message", "") for entry in (log_result.get("log") or [])]

            unstable = any("target url content is not stable" in m.lower() for m in messages)
            heuristic_negative = any("might not be injectable" in m.lower() for m in messages)
            heuristic_positive = any(
                "might be injectable" in m.lower() and "might not be injectable" not in m.lower()
                for m in messages
            )
            waf_detected = any("heuristics detected that the target is protected" in m.lower() for m in messages)

            signals = []
            suggestions = []

            if unstable:
                signals.append("page content is unstable across requests (dynamic content - timestamps, "
                                "tokens, counters - confuses the automatic true/false comparison)")
                suggestions.append("If you know what text distinguishes a genuinely successful response "
                                    "(e.g. the goal mentions a specific welcome message, error text, or "
                                    "record count), set configure_scan's options to include 'string' (text "
                                    "that only appears on true/valid responses) or 'notString' (text that "
                                    "only appears on false/invalid ones) - this is sqlmap's own documented "
                                    "fix for exactly this situation, normally offered interactively but "
                                    "skipped in --batch mode.")

            if waf_detected:
                signals.append("a WAF/IPS was detected")
                suggestions.append("Use escalate_attack to reach the WAF-evasion rungs, or "
                                    "recommend_tamper_for_dbms if the DBMS is already known.")

            if heuristic_negative and not heuristic_positive:
                signals.append("sqlmap's own early heuristic pre-check judged the parameter probably "
                                "not injectable (this is a fast pre-check, not the final conclusive test)")
                suggestions.append("Don't treat this alone as conclusive - the full technique tests may "
                                    "still find something the heuristic missed. If they also find nothing, "
                                    "it's a stronger (though still not certain) signal.")

            if not signals:
                signals.append("no specific failure signal found in the log - the scan may simply not have "
                                "run yet, or the parameter may genuinely not be injectable at the tested "
                                "level/risk/technique")
                suggestions.append("Use escalate_attack to try broader coverage before concluding.")

            return {"ok": True, "signals": signals, "suggestions": suggestions}

        if name == "escalate_attack":
            rung = self._ladder.next_rung()
            if rung is None:
                return {"ok": True, "exhausted": True,
                         "message": "Every rung of the escalation ladder has been tried. "
                                    "If nothing worked, the target is very likely not injectable "
                                    "at this parameter, or needs a technique/DBMS-specific approach "
                                    "outside this ladder."}

            self._pending_options.update(rung["options"])
            self._attempted_signatures.add(tuple(sorted(self._pending_options.items())))
            result = self.engine.start_scan(self.taskid, self._pending_options)
            return {
                "ok": True,
                "rung": rung["label"],
                "why": rung["why"],
                "options": dict(rung["options"]),
                "engine": result,
            }

        if name == "crawl_target":
            opts = dict(self._pending_options)
            try:
                opts["crawlDepth"] = int(args.get("depth") or 2)
            except (TypeError, ValueError):
                return {"ok": False, "error": "crawl_target's 'depth' must be an integer, got %r" % (args.get("depth"),)}
            if args.get("forms"):
                opts["forms"] = True
            result = self.engine.start_scan(self.taskid, opts)
            return {"ok": True, "message": "Crawl started (depth=%d)" % opts["crawlDepth"], "engine": result}

        if name == "stop_scan":
            return {"ok": True, "result": self.engine.stop_scan(self.taskid)}

        if name == "list_databases":
            self._pending_options["getDbs"] = True
            result = self.engine.start_scan(self.taskid, self._pending_options)
            self._pending_options.pop("getDbs", None)
            return {"ok": True, "message": "Database enumeration started", "engine": result}

        if name == "list_tables":
            opts = dict(self._pending_options)
            opts["getTables"] = True
            if args.get("db"):
                opts["db"] = args["db"]
            result = self.engine.start_scan(self.taskid, opts)
            return {"ok": True, "message": "Table enumeration started", "engine": result}

        if name == "list_columns":
            if not args.get("db") or not args.get("table"):
                return {"ok": False, "error": "list_columns requires both 'db' and 'table'"}
            opts = dict(self._pending_options)
            opts.update({"getColumns": True, "db": args["db"], "tbl": args["table"]})
            result = self.engine.start_scan(self.taskid, opts)
            return {"ok": True, "message": "Column enumeration started", "engine": result}

        if name == "dump_table":
            if not args.get("db") or not args.get("table"):
                return {"ok": False, "error": "dump_table requires both 'db' and 'table'"}
            opts = dict(self._pending_options)
            opts.update({"dumpTable": True, "db": args["db"], "tbl": args["table"]})
            if args.get("columns"):
                opts["col"] = args["columns"]
            if args.get("where"):
                opts["dumpWhere"] = args["where"]
            try:
                if args.get("start_row"):
                    opts["limitStart"] = int(args["start_row"])
                if args.get("stop_row"):
                    opts["limitStop"] = int(args["stop_row"])
            except (TypeError, ValueError):
                return {"ok": False, "error": "dump_table's 'start_row'/'stop_row' must be integers, "
                                               "got start_row=%r stop_row=%r" % (
                                                   args.get("start_row"), args.get("stop_row"))}
            result = self.engine.start_scan(self.taskid, opts)
            return {"ok": True, "message": "Table dump started", "options": opts, "engine": result}

        if name == "os_cmd":
            command = args.get("command")
            if not command or not isinstance(command, str):
                return {"ok": False, "error": "os_cmd requires a 'command' string"}
            opts = dict(self._pending_options)
            opts["osCmd"] = command
            result = self.engine.start_scan(self.taskid, opts)
            return {"ok": True, "message": "OS command execution started - call get_findings/"
                                            "check_status for output", "command": command, "engine": result}

        if name == "file_read":
            path = args.get("path")
            if not path or not isinstance(path, str):
                return {"ok": False, "error": "file_read requires a 'path' string"}
            opts = dict(self._pending_options)
            opts["fileRead"] = path
            result = self.engine.start_scan(self.taskid, opts)
            return {"ok": True, "message": "File read started - call get_findings/check_status "
                                            "for content", "path": path, "engine": result}

        if name == "search_data":
            if not args.get("query"):
                return {"ok": False, "error": "search_data requires 'query'"}
            opts = dict(self._pending_options)
            opts["search"] = True
            if args.get("in_columns"):
                opts["col"] = args["query"]
            else:
                opts["tbl"] = args["query"]
            result = self.engine.start_scan(self.taskid, opts)
            return {"ok": True, "message": "Search started for '%s'" % args["query"], "options": opts, "engine": result}

        if name == "dump_all":
            self._pending_options["dumpAll"] = True
            result = self.engine.start_scan(self.taskid, self._pending_options)
            return {"ok": True, "message": "Dump-all scan started", "engine": result}

        if name == "list_tamper_scripts":
            return {"ok": True, "catalog": render_catalog_for_prompt(args.get("query"))}

        if name == "recommend_tamper_for_dbms":
            if not args.get("dbms"):
                return {"ok": False, "error": "recommend_tamper_for_dbms requires 'dbms'"}
            rec = recommend_for_dbms(args["dbms"])
            return {
                "ok": True,
                "dbms_specific": rec["specific"],
                "generic": rec["generic"][:15],  # keep the response bounded; specific ones matter most
                "suggestion": ("Try: tamper=\"%s\"" % ",".join(rec["specific"][:3])) if rec["specific"]
                               else "No DBMS-specific scripts found for this DBMS; consider the generic list.",
            }

        if name == "nosql_scan_target":
            if not args.get("host"):
                return {"ok": False, "error": "nosql_scan_target requires 'host'"}
            try:
                from lib.nosql.mongo_client import scan_anonymous_access
                result = scan_anonymous_access(args["host"], port=int(args.get("port") or 27017))
                return {"ok": True, "result": result}
            except Exception as ex:
                return {"ok": False, "error": str(ex)}

        if name == "nosql_enumerate":
            if not args.get("host"):
                return {"ok": False, "error": "nosql_enumerate requires 'host'"}
            try:
                from lib.nosql.mongo_client import enumerate_databases
                result = enumerate_databases(args["host"], port=int(args.get("port") or 27017),
                                              username=args.get("username"), password=args.get("password"))
                return {"ok": True, "result": result}
            except Exception as ex:
                return {"ok": False, "error": str(ex)}

        if name == "nosql_search_collections":
            if not args.get("host") or not args.get("keyword"):
                return {"ok": False, "error": "nosql_search_collections requires 'host' and 'keyword'"}
            try:
                from lib.nosql.mongo_client import search_collections
                result = search_collections(args["host"], port=int(args.get("port") or 27017), keyword=args["keyword"],
                                             username=args.get("username"), password=args.get("password"))
                return {"ok": True, "matches": result}
            except Exception as ex:
                return {"ok": False, "error": str(ex)}

        if name == "nosql_dump_collection":
            if not args.get("host") or not args.get("database") or not args.get("collection"):
                return {"ok": False, "error": "nosql_dump_collection requires 'host', 'database', and 'collection'"}
            try:
                from lib.nosql.mongo_client import dump_collection
                result = dump_collection(args["host"], port=int(args.get("port") or 27017),
                                          database=args["database"], collection=args["collection"],
                                          username=args.get("username"), password=args.get("password"),
                                          query=args.get("query"), limit=int(args.get("limit") or 1000))
                return {"ok": True, "documents": result, "count": len(result)}
            except Exception as ex:
                return {"ok": False, "error": str(ex)}

        if name == "nosql_test_injection":
            if not args.get("url") or not args.get("param"):
                return {"ok": False, "error": "nosql_test_injection requires 'url' and 'param'"}
            try:
                from lib.nosql.injection_probe import probe
                result = probe(args["url"], args["param"])
                return {"ok": True, "likely_injectable": result["likely_injectable"],
                         "baseline": result["baseline"],
                         "anomalous_payloads": [f for f in result["findings"] if f["anomalous"]]}
            except Exception as ex:
                return {"ok": False, "error": str(ex)}

        if name == "redis_scan_target":
            if not args.get("host"):
                return {"ok": False, "error": "redis_scan_target requires 'host'"}
            try:
                from lib.nosql.redis_client import scan_anonymous_access
                result = scan_anonymous_access(args["host"], port=int(args.get("port") or 6379))
                return {"ok": True, "result": result}
            except Exception as ex:
                return {"ok": False, "error": str(ex)}

        if name == "redis_enumerate_keys":
            if not args.get("host"):
                return {"ok": False, "error": "redis_enumerate_keys requires 'host'"}
            try:
                from lib.nosql.redis_client import enumerate_keys
                result = enumerate_keys(args["host"], port=int(args.get("port") or 6379),
                                         pattern=args.get("pattern") or "*", limit=int(args.get("limit") or 1000))
                return {"ok": True, "result": result}
            except Exception as ex:
                return {"ok": False, "error": str(ex)}

        if name == "redis_dump_keys":
            keys = args.get("keys")
            if not args.get("host") or not keys:
                return {"ok": False, "error": "redis_dump_keys requires 'host' and 'keys'"}
            if not isinstance(keys, list):
                # `keys` is untrusted model output described as "array of
                # strings" in TOOL_SPECS, but a hallucinated reply could
                # hand this a bare string - iterating that silently walks
                # it character-by-character (the same TABLES-iteration bug
                # class already caught and fixed in memory.py's
                # _merge_engine_findings; see doc/ALKHA.md §15) rather than
                # failing clearly, so reject it explicitly instead.
                return {"ok": False, "error": "redis_dump_keys's 'keys' must be an array of strings, got %s" % (
                    type(keys).__name__)}
            try:
                from lib.nosql.redis_client import dump_keys
                result = dump_keys(args["host"], port=int(args.get("port") or 6379), keys=keys)
                return {"ok": True, "entries": result, "count": len(result)}
            except Exception as ex:
                return {"ok": False, "error": str(ex)}

        if name == "elasticsearch_scan_target":
            if not args.get("host"):
                return {"ok": False, "error": "elasticsearch_scan_target requires 'host'"}
            try:
                from lib.nosql.elasticsearch_client import scan_anonymous_access
                result = scan_anonymous_access(args["host"], port=int(args.get("port") or 9200))
                return {"ok": True, "result": result}
            except Exception as ex:
                return {"ok": False, "error": str(ex)}

        if name == "elasticsearch_enumerate_indices":
            if not args.get("host"):
                return {"ok": False, "error": "elasticsearch_enumerate_indices requires 'host'"}
            try:
                from lib.nosql.elasticsearch_client import enumerate_indices
                result = enumerate_indices(args["host"], port=int(args.get("port") or 9200))
                return {"ok": True, "indices": result, "count": len(result)}
            except Exception as ex:
                return {"ok": False, "error": str(ex)}

        if name == "elasticsearch_dump_index":
            if not args.get("host") or not args.get("index"):
                return {"ok": False, "error": "elasticsearch_dump_index requires 'host' and 'index'"}
            try:
                from lib.nosql.elasticsearch_client import dump_index
                result = dump_index(args["host"], port=int(args.get("port") or 9200),
                                     index=args["index"], limit=int(args.get("limit") or 100))
                return {"ok": True, "documents": result, "count": len(result)}
            except Exception as ex:
                return {"ok": False, "error": str(ex)}

        if name == "couchdb_scan_target":
            if not args.get("host"):
                return {"ok": False, "error": "couchdb_scan_target requires 'host'"}
            try:
                from lib.nosql.couchdb_client import scan_anonymous_access
                result = scan_anonymous_access(args["host"], port=int(args.get("port") or 5984))
                return {"ok": True, "result": result}
            except Exception as ex:
                return {"ok": False, "error": str(ex)}

        if name == "couchdb_enumerate_databases":
            if not args.get("host"):
                return {"ok": False, "error": "couchdb_enumerate_databases requires 'host'"}
            try:
                from lib.nosql.couchdb_client import enumerate_databases
                result = enumerate_databases(args["host"], port=int(args.get("port") or 5984))
                return {"ok": True, "databases": result, "count": len(result)}
            except Exception as ex:
                return {"ok": False, "error": str(ex)}

        if name == "couchdb_dump_database":
            if not args.get("host") or not args.get("database"):
                return {"ok": False, "error": "couchdb_dump_database requires 'host' and 'database'"}
            try:
                from lib.nosql.couchdb_client import dump_database
                result = dump_database(args["host"], port=int(args.get("port") or 5984),
                                        database=args["database"], limit=int(args.get("limit") or 100))
                return {"ok": True, "documents": result, "count": len(result)}
            except Exception as ex:
                return {"ok": False, "error": str(ex)}

        if name == "note":
            return {"ok": True, "noted": args.get("text", "")}

        if name == "finish":
            return {"ok": True, "finished": True, "summary": args.get("summary", "")}

        return {"ok": False, "error": "Unknown tool '%s'" % name}
