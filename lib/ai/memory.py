#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import json
import time

from lib.core.enums import CONTENT_TYPE


class AgentMemory(object):
    """
    Keeps the plan->act->observe transcript (fed back to the LLM each turn,
    trimmed to stay within context) plus a structured findings dict that
    the final report is built from - independent of how verbose the model
    chat log gets.
    """

    def __init__(self, goal, target, max_transcript_events=60):
        self.goal = goal
        self.target = target
        self.started_at = time.time()
        self.events = []
        self.findings = {
            "target": target,
            "goal": goal,
            "injection_points": [],
            "dbms": None,
            "banner": None,
            "current_user": None,
            "current_db": None,
            "hostname": None,
            "is_dba": None,
            "databases": [],
            "tables": {},
            "columns": {},
            "dumped_tables": [],
            "nosql_access": [],
            "os_command_results": [],
            "file_read_results": [],
            "notes": [],
        }
        self.max_transcript_events = max_transcript_events

    def record(self, role, content):
        self.events.append({"t": time.time(), "role": role, "content": content})
        if len(self.events) > self.max_transcript_events:
            # Keep the goal-setting head and the freshest tail; drop the noisy middle.
            self.events = self.events[:2] + self.events[-(self.max_transcript_events - 2):]

    def record_action(self, name, args, result):
        self.record("tool", {"action": name, "args": args, "result": result})

        if name == "get_findings" and isinstance(result, dict) and result.get("ok"):
            items = result.get("data", {}).get("data", [])
            self._merge_engine_findings(items)

        if name == "note":
            # `args["text"]` is untrusted model output - a hallucinated
            # non-string value (a number, list, dict) would otherwise sit in
            # findings["notes"] until a later "\n".join(notes) (in
            # alkha_agent.py's final report rendering) or an f-string crashes
            # on it far away from where the bad value actually originated.
            # Coerce once, here, at the point of entry.
            text = args.get("text", "")
            self.findings["notes"].append(text if isinstance(text, str) else str(text))

        if name == "nosql_test_injection" and isinstance(result, dict) and result.get("ok") \
                and result.get("likely_injectable"):
            # grounding_check()'s "did you actually confirm an injection"
            # check only looks at findings["injection_points"] - without
            # this, EVERY successful NoSQL-only finish would get a false
            # "unverified claim" caveat regardless of how solid the actual
            # nosql_test_injection result was, since that finding never
            # reached the one place grounding_check looks. Found by
            # TestNosqlAgentEndToEnd actually running a full NoSQL-only
            # agent loop against a real vulnerable target, not by testing
            # grounding_check() or nosql_test_injection() in isolation -
            # each alone looked correct.
            point = {"place": "nosql", "parameter": args.get("param")}
            if point not in self.findings["injection_points"]:
                self.findings["injection_points"].append(point)

        if name == "nosql_enumerate" and isinstance(result, dict) and result.get("ok"):
            # same reasoning as above, for the "you claimed to enumerate
            # databases" family of grounding checks - nosql_enumerate's
            # result was never reaching findings["databases"]/["tables"]
            # at all, the direct NoSQL analogue of _merge_engine_findings'
            # CONTENT_TYPE.DBS/TABLES handling for the sqlmap-engine path.
            payload = result.get("result") or {}
            for db, collections in (payload.get("databases") or {}).items():
                if db not in self.findings["databases"]:
                    self.findings["databases"].append(db)
                if collections:
                    self.findings["tables"].setdefault(db, [])
                    for c in collections:
                        if c not in self.findings["tables"][db]:
                            self.findings["tables"][db].append(c)

        if name == "nosql_dump_collection" and isinstance(result, dict) and result.get("ok"):
            # same class of gap as nosql_test_injection/nosql_enumerate
            # above: a successful dump never reached findings["dumped_tables"]
            # at all, unlike the sqlmap-engine path's dump_table (which
            # populates this via CONTENT_TYPE.DUMP_TABLE) - so facts_summary()
            # stayed "(nothing confirmed yet)" even immediately after a real,
            # successful data exfiltration, meaning the model itself had no
            # memory of having already dumped this collection on its next
            # turn (risking a redundant re-dump), and the final report would
            # silently undercount NoSQL dumps to zero. Append-only, no
            # dedup, matching the existing dump_table/CONTENT_TYPE.DUMP_TABLE
            # convention above rather than introducing an inconsistent
            # dedup policy for only one of the two dump paths.
            self.findings["dumped_tables"].append({
                "backend": "mongodb", "database": args.get("database"), "collection": args.get("collection"),
                "count": result.get("count"),
            })

        if name == "nosql_scan_target" and isinstance(result, dict) and result.get("ok"):
            # arguably the single most important finding in a NoSQL
            # engagement - whether the instance requires no authentication
            # at all - had no path into structured findings whatsoever,
            # unlike the other four nosql_* tools (see doc/ALKHA.md §17).
            # Doesn't fit any existing list field the way the other three
            # did, and deliberately does NOT go into findings["notes"]:
            # notes render under a WARN-colored "notes / caveats" heading
            # in the final report (tui.py's render_final_report), which
            # would misrepresent a strong POSITIVE finding (or a normal,
            # unremarkable "auth_required" result) as if it were a
            # caveat/problem with the run itself. Gets its own field
            # instead, appended per scan (a host can legitimately be
            # scanned more than once - e.g. re-checking after remediation)
            # rather than deduped, matching dumped_tables' append-only
            # convention immediately above for the same reason: each call
            # is a distinct, independent observation worth keeping, not a
            # single fact to converge on.
            inner = result.get("result") or {}
            self.findings["nosql_access"].append({
                "backend": "mongodb", "host": args.get("host"), "port": args.get("port") or 27017,
                "status": inner.get("status"), "version": inner.get("version"),
                "database_count": inner.get("database_count"),
            })

        if name == "redis_scan_target" and isinstance(result, dict) and result.get("ok"):
            # same field as nosql_scan_target immediately above - "backend"
            # is what tells them apart (see doc/ALKHA.md §19). Redis has no
            # analogue of MongoDB's "how many databases" count (it has 16
            # numbered DBs by default, not a comparable metric worth
            # conflating with database_count), so that key is always None
            # for a redis entry rather than omitted - keeping every
            # nosql_access entry's key set uniform regardless of backend
            # is simpler for any future code iterating this list than
            # branching on which keys happen to be present.
            inner = result.get("result") or {}
            self.findings["nosql_access"].append({
                "backend": "redis", "host": args.get("host"), "port": args.get("port") or 6379,
                "status": inner.get("status"), "version": inner.get("version"),
                "database_count": None,
            })

        if name == "redis_dump_keys" and isinstance(result, dict) and result.get("ok"):
            # same reasoning as nosql_dump_collection above, generalized:
            # a successful redis_dump_keys result previously had no path
            # into findings["dumped_tables"] either.
            self.findings["dumped_tables"].append({
                "backend": "redis", "host": args.get("host"), "count": result.get("count"),
            })

        if name == "elasticsearch_scan_target" and isinstance(result, dict) and result.get("ok"):
            # same field, third backend - "index_count" is Elasticsearch's
            # analogue of MongoDB's database_count (both map onto the
            # shared "database_count" key so facts_summary()/
            # render_final_report() don't need a fourth backend-specific
            # field; Redis is the one backend with no comparable metric,
            # hence always None there).
            inner = result.get("result") or {}
            self.findings["nosql_access"].append({
                "backend": "elasticsearch", "host": args.get("host"), "port": args.get("port") or 9200,
                "status": inner.get("status"), "version": inner.get("version"),
                "database_count": inner.get("index_count"),
            })

        if name == "elasticsearch_dump_index" and isinstance(result, dict) and result.get("ok"):
            # same reasoning as nosql_dump_collection/redis_dump_keys above.
            self.findings["dumped_tables"].append({
                "backend": "elasticsearch", "host": args.get("host"), "index": args.get("index"),
                "count": result.get("count"),
            })

        if name == "couchdb_scan_target" and isinstance(result, dict) and result.get("ok"):
            # fourth backend, same field - CouchDB's database_count (from
            # _all_dbs) is a genuinely comparable "how many things are in
            # here" metric, same as MongoDB's and Elasticsearch's, so it
            # maps onto the same shared database_count key rather than
            # needing special handling.
            inner = result.get("result") or {}
            self.findings["nosql_access"].append({
                "backend": "couchdb", "host": args.get("host"), "port": args.get("port") or 5984,
                "status": inner.get("status"), "version": inner.get("version"),
                "database_count": inner.get("database_count"),
            })

        if name == "couchdb_dump_database" and isinstance(result, dict) and result.get("ok"):
            # same reasoning as the other three dump handlers above.
            self.findings["dumped_tables"].append({
                "backend": "couchdb", "host": args.get("host"), "database": args.get("database"),
                "count": result.get("count"),
            })

    def _merge_engine_findings(self, data_items):
        """
        Maps each item's REST-API `type` field (sqlmap's CONTENT_TYPE enum,
        lib/core/enums.py) to the right findings bucket, using the exact
        value shape each content type is dumped with (lib/core/dump.py) -
        not a heuristic on the field's Python type, which is fragile and
        was wrong in an earlier version of this file.
        """
        for item in data_items or []:
            if not isinstance(item, dict):
                # data_items comes from sqlmap's own REST API response, which
                # is well-formed in practice - but a malformed/intercepted
                # response (a proxy or WAF mangling the JSON, a network
                # hiccup) shouldn't crash the one system meant to catch
                # exactly this kind of unreliable data. Skip, don't raise.
                continue

            itype = item.get("type")
            value = item.get("value")

            if itype == CONTENT_TYPE.TECHNIQUES and isinstance(value, list):
                for injection in value:
                    if isinstance(injection, dict) and injection.get("place"):
                        point = {"place": injection.get("place"), "parameter": injection.get("parameter")}
                        if point not in self.findings["injection_points"]:
                            self.findings["injection_points"].append(point)
                        if injection.get("dbms") and not self.findings["dbms"]:
                            self.findings["dbms"] = injection["dbms"]

            elif itype == CONTENT_TYPE.DBMS_FINGERPRINT and value:
                self.findings["dbms"] = value

            elif itype == CONTENT_TYPE.BANNER and value:
                self.findings["banner"] = value

            elif itype == CONTENT_TYPE.CURRENT_USER and value:
                self.findings["current_user"] = value

            elif itype == CONTENT_TYPE.CURRENT_DB and value:
                self.findings["current_db"] = value

            elif itype == CONTENT_TYPE.HOSTNAME and value:
                self.findings["hostname"] = value

            elif itype == CONTENT_TYPE.IS_DBA and value is not None:
                self.findings["is_dba"] = value

            elif itype == CONTENT_TYPE.DBS and isinstance(value, list):
                for db in value:
                    if db not in self.findings["databases"]:
                        self.findings["databases"].append(db)

            elif itype == CONTENT_TYPE.TABLES and isinstance(value, dict):
                for db, tables in value.items():
                    self.findings["tables"].setdefault(db, [])
                    if not isinstance(tables, list):
                        # a malformed engine response could hand this a
                        # string - iterating that silently (and wrongly)
                        # walks it character-by-character instead of
                        # failing clearly, so skip rather than corrupt
                        # the findings dict with garbage single-char
                        # "table names".
                        continue
                    for t in tables:
                        if t not in self.findings["tables"][db]:
                            self.findings["tables"][db].append(t)

            elif itype == CONTENT_TYPE.COLUMNS and isinstance(value, dict):
                self.findings["columns"].update(value)

            elif itype == CONTENT_TYPE.DUMP_TABLE and value:
                self.findings["dumped_tables"].append(value)

            elif itype == CONTENT_TYPE.OS_CMD and value:
                # confirmed real code execution on the back-end DBMS host -
                # arguably the single most significant finding this whole
                # codebase can produce (a step further than any NoSQL
                # module's "anonymous access", which only proves exposed
                # data, not arbitrary code execution). See
                # render_final_report()/facts_summary() for how this is
                # surfaced with matching prominence.
                self.findings["os_command_results"].append(value if isinstance(value, str) else str(value))

            elif itype == CONTENT_TYPE.FILE_READ and value:
                self.findings["file_read_results"].append(value if isinstance(value, str) else str(value))

    def transcript_for_prompt(self):
        return self.events

    def to_report_dict(self):
        return {
            "goal": self.goal,
            "target": self.target,
            "duration_seconds": round(time.time() - self.started_at, 1),
            "findings": self.findings,
        }

    def facts_summary(self):
        """
        Compact "known so far" block derived straight from the structured
        findings dict (not the raw transcript) - injected fresh into the
        system prompt every turn so the model always has the accurate
        current state in front of it, even after older transcript events
        have been trimmed (see record()) or if a smaller local model
        simply loses track of details buried in a long chat history.
        """
        f = self.findings
        lines = []

        if f["dbms"]:
            lines.append("DBMS: %s" % f["dbms"])
        if f["banner"]:
            lines.append("Banner: %s" % f["banner"])
        if f["current_user"]:
            lines.append("Current user: %s (DBA: %s)" % (f["current_user"], f["is_dba"]))
        if f["os_command_results"]:
            # the single most significant finding this codebase can
            # produce - confirmed arbitrary code execution, not just data
            # exposure - so it's surfaced ahead of injection_points/
            # databases/tables even though those are recorded first.
            last_output = f["os_command_results"][-1]
            last_output = last_output if len(last_output) <= 200 else last_output[:200] + "..."
            lines.append("OS COMMAND EXECUTION CONFIRMED - %d command(s) run, most recent output: %s" % (
                len(f["os_command_results"]), last_output))
        if f["file_read_results"]:
            lines.append("File read from DBMS host confirmed - %d file(s) read" % len(f["file_read_results"]))
        if f["injection_points"]:
            lines.append("Confirmed injection points: %s" % f["injection_points"])
        if f["databases"]:
            lines.append("Databases found: %s" % f["databases"])
        if f["tables"]:
            lines.append("Tables found: %s" % f["tables"])
        if f["dumped_tables"]:
            lines.append("Tables dumped so far: %d" % len(f["dumped_tables"]))
        for access in f["nosql_access"]:
            backend_label = {"mongodb": "MongoDB", "redis": "Redis",
                              "elasticsearch": "Elasticsearch", "couchdb": "CouchDB"}.get(
                access["backend"], access["backend"])
            if access["status"] == "open":
                db_count_suffix = (", %s database(s)" % access["database_count"]
                                    if access["database_count"] is not None else "")
                lines.append("NoSQL: %s:%s allows ANONYMOUS ACCESS (no auth required) - "
                              "%s %s%s" % (
                                  access["host"], access["port"], backend_label,
                                  access["version"] or "unknown version", db_count_suffix))
            else:
                lines.append("NoSQL: %s:%s (%s) - %s" % (
                    access["host"], access["port"], backend_label, access["status"]))

        return "\n".join(lines) if lines else "(nothing confirmed yet)"

    def grounding_check(self, summary):
        """
        Lightweight hallucination guard: local models (especially smaller
        ones) can produce a confident-sounding finish summary that doesn't
        actually match what the engine recorded - e.g. claiming injection
        was found when no CONTENT_TYPE.TECHNIQUES entry was ever recorded,
        naming a different DBMS than what was actually fingerprinted, or
        naming a table/database that was never actually enumerated. This
        isn't full NLP verification, just a keyword-level check against
        the structured findings dict (which is accurate - see
        _merge_engine_findings). Returns a list of caveat strings to
        attach to the report; empty if the summary is consistent with
        what was actually observed.
        """
        caveats = []
        # `summary` is untrusted model output (args.get("summary", "") from
        # a finish call) - the model can hand this any JSON type (a number,
        # list, dict), not just a string, despite the tool spec describing
        # it as one. Coerce rather than crash on .lower().
        if not isinstance(summary, str):
            summary = str(summary) if summary else ""
        lowered = summary.lower()

        positive_words = ("injectable", "vulnerable", "vulnerability found", "successfully exploited")
        negative_words = ("not injectable", "not vulnerable", "no vulnerability", "no injection")

        claims_success = any(w in lowered for w in positive_words) and not any(w in lowered for w in negative_words)
        claims_failure = any(w in lowered for w in negative_words)

        has_evidence = bool(self.findings["injection_points"])

        if claims_success and not has_evidence:
            caveats.append(
                "The summary claims an injection was found, but no injection point was actually "
                "recorded in structured findings (get_findings was never called with a confirmed "
                "result, or wasn't called at all before finish). Treat this summary as unverified."
            )

        if claims_failure and has_evidence:
            caveats.append(
                "The summary claims no injection was found, but structured findings DO contain "
                "%d recorded injection point(s): %s. The summary may be stale or wrong." % (
                    len(self.findings["injection_points"]), self.findings["injection_points"]
                )
            )

        caveats.extend(self._check_dbms_claim(lowered))
        caveats.extend(self._check_named_entity_claims(lowered, "databases", "database"))
        caveats.extend(self._check_named_entity_claims(lowered, "tables", "table"))
        caveats.extend(self._check_os_command_claim(lowered))
        caveats.extend(self._check_file_read_claim(lowered))
        caveats.extend(self._check_nosql_access_claim(lowered))

        return caveats

    def _check_file_read_claim(self, lowered_summary):
        """Same reasoning as _check_os_command_claim - a claimed filesystem
        read with no recorded CONTENT_TYPE.FILE_READ result is unverified."""
        claim_words = ("read the file", "read a file", "filesystem access", "file read",
                        "retrieved the file", "accessed the file")
        claims_file_read = any(w in lowered_summary for w in claim_words)

        if claims_file_read and not self.findings["file_read_results"]:
            return [
                "The summary claims a file was read from the DBMS host, but no file content was "
                "actually recorded in structured findings (file_read was never called with a "
                "confirmed result, or wasn't called at all before finish). Treat this summary as "
                "unverified."
            ]
        return []

    def _check_nosql_access_claim(self, lowered_summary):
        """
        Found the same way every other grounding gap in this codebase
        was found: checking rather than assuming. grounding_check()
        validated SQL injection/DBMS claims from the moment it was
        written, but never gained an equivalent check for NoSQL
        anonymous-access claims (MongoDB/Redis/Elasticsearch/CouchDB)
        when that support was added later - an agent could claim
        "MongoDB allows anonymous access" with zero recorded
        nosql_access evidence and nothing would catch it, the exact
        failure mode this whole grounding system exists to prevent.
        """
        claim_words = ("anonymous access", "no authentication required", "unauthenticated access",
                        "allows anonymous", "requires no authentication", "open access")
        claims_open_access = any(w in lowered_summary for w in claim_words)

        has_open_nosql_access = any(a["status"] == "open" for a in self.findings["nosql_access"])

        if claims_open_access and not has_open_nosql_access:
            return [
                "The summary claims anonymous/unauthenticated access to a datastore, but no "
                "structured finding actually recorded an 'open' access status (a *_scan_target "
                "tool was never called with a confirmed open result before finish). Treat this "
                "summary as unverified."
            ]
        return []

    def _check_os_command_claim(self, lowered_summary):
        """
        The highest-severity claim this codebase can validate deserves
        the same anti-hallucination check as an injection claim, not a
        weaker one just because it was added later. A summary claiming
        OS command execution / code execution / shell access without a
        corresponding CONTENT_TYPE.OS_CMD entry actually recorded is
        exactly the kind of confident-sounding but ungrounded claim
        grounding_check() exists to catch.
        """
        claim_words = ("os command", "command execution", "code execution", "shell access",
                        "executed a command", "ran a command", "remote code execution")
        claims_os_cmd = any(w in lowered_summary for w in claim_words)

        if claims_os_cmd and not self.findings["os_command_results"]:
            return [
                "The summary claims OS command execution, but no command output was actually "
                "recorded in structured findings (os_cmd was never called with a confirmed result, "
                "or wasn't called at all before finish). Treat this summary as unverified."
            ]
        return []

    def _check_dbms_claim(self, lowered_summary):
        """
        If the summary names a specific DBMS, it should match what was
        actually fingerprinted (self.findings["dbms"]), not a different
        one - a model can misremember or guess a DBMS name from general
        knowledge ("this looks like a typical MySQL app") rather than
        report what the engine actually confirmed.
        """
        from lib.core.enums import DBMS

        known_dbms_names = [getattr(DBMS, n) for n in dir(DBMS) if not n.startswith("_")]
        mentioned = [name for name in known_dbms_names if name.lower() in lowered_summary]

        if not mentioned:
            return []

        actual = (self.findings.get("dbms") or "").lower()

        if not actual:
            # No DBMS was fingerprinted at all - any named DBMS in the
            # summary is unverified, full stop. (An earlier version of
            # this check ran the substring-containment comparison below
            # even when `actual` was empty, and "" is a substring of
            # every string in Python, which silently defeated the
            # mismatch check for exactly this case - caught by testing
            # this scenario directly, not assumed correct.)
            return ["The summary names %s, but no DBMS was actually fingerprinted in structured "
                    "findings (get_findings never recorded a CONTENT_TYPE.DBMS_FINGERPRINT/BANNER/"
                    "TECHNIQUES entry with dbms info). This DBMS claim is unverified." % (
                        " and ".join("'%s'" % m for m in mentioned)
                    )]

        # actual findings["dbms"] can be a version string like "MySQL >= 5.0.12" -
        # a mentioned name counts as consistent if it's a substring of that,
        # not requiring an exact match.
        mismatched = [name for name in mentioned if name.lower() not in actual and actual not in name.lower()]

        if mismatched:
            return ["The summary names %s, but structured findings recorded the DBMS as '%s'. "
                    "The summary's DBMS claim may be wrong." % (
                        " and ".join("'%s'" % m for m in mismatched), self.findings["dbms"]
                    )]

        return []

    def _check_named_entity_claims(self, lowered_summary, findings_key, label):
        """
        Generic check for "the summary claims to have found/dumped a
        specific named database or table" that doesn't actually appear
        anywhere in structured findings. Only fires when the summary
        uses an explicit discovery/dump verb next to a quoted-looking
        name, to avoid false-flagging normal prose that happens to
        contain a common word - this is intentionally conservative
        (fewer false alarms) rather than exhaustive.
        """
        import re

        # \b word boundaries matter here: without them, "table"/"db" match
        # as substrings inside ordinary words (e.g. "injec[table] via" or
        # "verify[db] entries"), misfiring on prose that never claims a
        # named database/table at all - caught by actually running a full
        # end-to-end demo, not just unit tests with hand-picked strings.
        pattern = r"\b(?:table|database|db)\b\s+['\"]?([a-zA-Z_][a-zA-Z0-9_]{2,})['\"]?"
        mentioned_names = set(re.findall(pattern, lowered_summary))

        if not mentioned_names:
            return []

        known = self.findings.get(findings_key) or []
        known_lower = set()
        if isinstance(known, dict):
            known_lower.update(k.lower() for k in known.keys())
            for v in known.values():
                known_lower.update(str(t).lower() for t in (v or []))
        else:
            known_lower.update(str(k).lower() for k in known)

        unsupported = mentioned_names - known_lower

        if unsupported and known_lower:
            return ["The summary mentions %s name(s) %s not present in structured findings' "
                    "recorded %ss (%s). Double-check this wasn't inferred rather than "
                    "actually enumerated." % (
                        label, sorted(unsupported), label, sorted(known_lower)
                    )]

        return []

    def to_json(self):
        return json.dumps(self.to_report_dict(), indent=2)
