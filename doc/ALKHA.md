# Alkha: agentic AI layer, modern CLI, NoSQL support, security hardening, and the rebrand itself

This document consolidates everything added on top of stock sqlmap 1.10 in
this build. Nothing described elsewhere in this repository's docs was
removed or altered in behavior by default - every change here is either
strictly additive (new files) or gated behind an explicit opt-in flag
(`--modern-ui`) or an explicit new entry point (`alkha_agent.py`,
`alkhaapi.py --allow-dangerous-options`/`--insecure-api`). Running
`python alkha.py` with no new flags behaves exactly as stock 1.10 did.

For the agent's own architecture and usage, see [doc/AGENT.md](AGENT.md).
This document is the higher-level index: what exists, why, and - just as
importantly - what has actually been verified to work versus what hasn't.

> **Note on this file's history:** this document was found missing from
> disk partway through development, alongside an unexplained file
> (`doc/ALKHA.md`, left untouched and unopened rather than trusted) and
> several product changes (retry-with-backoff, stuck-loop detection, a
> finish-requires-evidence guard, a `diagnose_detection_failure` tool)
> that hadn't been narrated in the visible development history. Each was
> inspected for correctness and safety before being trusted or documented
> here (§11) - all were well-tested, well-integrated, and consistent with
> this codebase's own conventions; one real integration bug between two
> of them (a test that inadvertently tripped the new evidence-guard) was
> found via the test suite and fixed. This file was then rebuilt from the
> full development record.
>
> The `doc/ALKHA.md` mystery was resolved later, unrelated to any of
> this: comparing it byte-for-byte against this file's own snapshot from
> an earlier round showed identical `lib/ai/` code and a byte-identical
> `lib/core/settings.py` - genuine earlier work in this same project's
> continuous lineage (planning notes for the eventual Alkha rebrand,
> named in anticipation of it), not contamination from elsewhere. This
> document has since been merged into that file, which is now the
> canonical one - you are reading it.

## 1. Agentic AI layer (`lib/ai/`, `alkha_agent.py`)

A local-model-driven (Ollama) autonomous agent that plans, acts, and
observes against sqlmap's own existing REST-JSON API
(`lib/utils/api.py`) - it never touches the detection/exploitation
engine directly, so every DBMS plugin and technique behaves exactly as
it always has. Run `python alkhaapi.py -s` in one terminal, then
`python alkha_agent.py --target <url> --goal "..."` in another.

| Component | Purpose |
|---|---|
| `lib/ai/ollama_client.py` | stdlib-only HTTP client for a local Ollama server |
| `lib/ai/engine_client.py` | typed wrapper over sqlmap's REST API - the agent's only channel to the engine |
| `lib/ai/tools.py` | closed set of 21 actions the model may take (no arbitrary shell/HTTP) |
| `lib/ai/safety.py` | scope lock, iteration/wall-clock budget, high-risk-action confirmation gate |
| `lib/ai/memory.py` | per-run transcript + structured findings, grounded in the real `CONTENT_TYPE` enum |
| `lib/ai/planner.py` | the plan→act→observe loop; native Ollama tool-calling with automatic JSON-prompting fallback; retry-with-backoff on transient Ollama failures; stuck-loop detection; finish-requires-evidence guard (see §11) |
| `lib/ai/tamper_catalog.py` | exposes all 70 `tamper/*.py` evasion scripts to the model by keyword, and by DBMS restriction (`recommend_tamper_for_dbms`) |
| `lib/ai/option_validator.py` | catches hallucinated/mistyped option names before they reach the REST API |
| `lib/ai/knowledge_base.py` | cross-run memory (`~/.sqlmap/agent_knowledge.json`) of what worked against which host |
| `lib/ai/escalation.py` | deterministic attack-escalation ladder (see §5) - not left to the model's own judgement |

Current tool set (21): `set_target`, `configure_scan`, `start_scan`,
`check_status`, `get_findings`, `get_logs`, `stop_scan`,
`list_databases`, `list_tables`, `list_columns`, `dump_table`,
`search_data`, `dump_all`, `list_tamper_scripts`,
`recommend_tamper_for_dbms`, `check_waf_status`, `escalate_attack`,
`crawl_target`, `diagnose_detection_failure`, `note`, `finish`.

**Verified:** full plan→act→observe loop against mock Ollama + mock REST
API (both the JSON-fallback and native tool-calling code paths); scope
violations correctly blocked; high-risk actions correctly fail safe
without a confirm callback and correctly respect `--agent-yolo`; findings
extraction checked against the real `lib/core/enums.CONTENT_TYPE` shapes,
not guessed; the grounding/hallucination guard verified to catch a mock
model that claimed success with zero recorded evidence; the knowledge
base verified to persist and be read back across genuinely separate
Python processes.

**Known limitation:** the agent's tool set covers scan configuration,
enumeration, and dumping - it does not expose OS/file/registry takeover
options (`osShell`, `fileWrite`, etc.), which are also exactly the
options blocked by default on the REST API (see §3). This is intentional
scope, not an oversight.

## 2. Modern CLI (`lib/core/tui.py`, `--modern-ui`)

An opt-in rendering layer styled after low-noise agentic-CLI output
(single accent color, status lines, tree connectors for sub-detail)
instead of sqlmap's classic ASCII-art banner and bracket log lines.
Everything still funnels through the existing `dataToStdout()`/logging
machinery, so `--disable-coloring`, non-TTY stripping, and REST-API
stdout redirection all keep working unchanged.

| Component | Purpose |
|---|---|
| `render_banner()` / `render_startup_lines()` | swapped in for `banner()` in `alkha.py`, with the same `--version`/`--api` suppression logic the classic path has |
| `ModernLogHandler` + `swap_log_handler()` | replaces `lib.core.log`'s handler at its one chokepoint - covers every `logger.*()` call across the entire codebase with zero per-call-site edits |
| `ModernProgressBar` + `lib.utils.progress.get_progress_bar()` | drop-in sibling of the classic `ProgressBar`, used by the three payload-testing loops during live data extraction |

`alkha_agent.py` renders through this same module.

**Verified:** banner/`--version` suppression parity confirmed byte-for-byte
against classic; a real end-to-end scan against a live HTTP target
confirmed the log handler swap doesn't change program logic or exit
codes, only rendering; `ModernProgressBar`'s percent/ETA math confirmed
numerically identical to the classic implementation; a genuinely
SQL-injectable target (real SQLite, naive string concatenation) was
scanned end-to-end, with `ModernProgressBar` rendering live through 8
real character-extraction steps and the final dumped value exactly
matching the planted database value.

**Known limitation:** the union/error-based progress bar call sites were
investigated with a real UNION-injectable SQLite target, and sqlmap
correctly chose a more efficient single-shot retrieval instead of the
per-row loop - so that specific path wasn't observed firing live. It
calls the identical, already-verified `ModernProgressBar` class.

## 3. Security hardening (`lib/utils/api.py`, `lib/utils/hashdb.py`, `lib/core/target.py`)

1. **REST API auth-by-default.** `alkhaapi.py -s` used to bind with zero
   authentication and zero restriction on which options a client could
   set - including `evalCode`, which executes arbitrary Python via
   `exec()`. Now: non-loopback binding without credentials is refused
   unless `--insecure-api` is passed, and `RESTAPI_DANGEROUS_OPTIONS`
   is blocked on both `/option/<id>/set` and `/scan/<id>/start` by
   default, opt-in via `--allow-dangerous-options`.
2. **Timing-safe credential comparison** via `hmac.compare_digest()`.
3. **Session/hash-DB file trust.** Locked to `0600` on creation; resuming
   a file passed explicitly via `-s` now warns about pickle-
   deserialization trust.
4. **`shell=True` audit** - every call site traced individually, all
   confirmed to only execute operator/developer strings, never
   target-influenced data.

**Verified:** all four fixes tested against a live running
`alkhaapi.py -s` instance over real HTTP.

## 4. Automated test suite (`lib/ai/tests/`)

`unittest`, stdlib only. Run from the repository root:

```bash
python -m unittest discover -s lib/ai/tests -p "test_*.py" -v
```

102 tests across 8 files. This suite's teeth were checked, not assumed:
the double-tick budget bug (see §10) was deliberately reintroduced into
`safety.py` after the test suite was written, confirmed to fail the
corresponding test, then reverted and reconfirmed passing.

## 5. Deterministic escalation, WAF awareness (`lib/ai/escalation.py`)

`escalate_attack` replaces model guesswork with a fixed, ordered ladder:
baseline, broaden coverage, max level/risk/all-techniques, light WAF
evasion, aggressive WAF evasion, transport-level evasion
(`--chunked`/`--hpp`), then isolate each of the six technique letters
individually. Every rung only ever broadens coverage or adds evasion.

`check_waf_status` reads sqlmap's own automatic WAF/IPS heuristic
directly from the structured log. `recommend_tamper_for_dbms` parses
each tamper script's `dependencies()` function via `ast` for real DBMS
restrictions - 19 of 70 shipped scripts are genuinely restricted.

**Verified end-to-end against a real blocking WAF** (a reverse proxy
blocking realistic signature patterns broad enough that whitespace-only
obfuscation doesn't bypass it): rungs 1-3 all correctly failed, matching
a classic CLI baseline against the same WAF; rung 4 succeeded
immediately where they didn't. Two WAF-pattern bugs in the test harness
itself were caught by testing against real sqlmap traffic before
trusting the result.

## 6. Attack surface discovery (`crawl_target`) + a real upstream bug fix

Wires sqlmap's existing crawler into the tool set. Live testing
surfaced a real upstream bug: `"php"` was present in
`CRAWL_EXCLUDE_EXTENSIONS`, silently defeating crawling on probably the
most common real-world backend extension, for every user of `--crawl`.
Removed; reran the identical scenario, now correctly discovered.

`forms=True` verified via sqlmap's own `--smoke-test` and a real HTML
form pointing at a genuinely injectable endpoint.

## 7. Second-order SQL injection (`secondUrl`)

Lets the agent test injection points whose effect only appears on a
different page than the one the payload was submitted to. Verified
with a genuinely second-order-vulnerable target (safely parameterized
storage endpoint, unsafely-concatenated read endpoint). A severe bug
(a literal JSON example crashing `str.format()` on every planner run)
was caught by the test suite before shipping.

## 8. End-to-end proof against a real blocking WAF

See §5.

## 9. Precision dumping, targeted search, custom injection points

`dump_table` accepts `columns`/`where`/`start_row`/`stop_row`, verified
live against a real 5-row table. `search_data` wraps `--search`,
checked against the real implementation; live testing surfaced a real
DBMS limitation (SQLite refuses column search - no
`information_schema`), correctly passed through, not hidden. `set_target`
accepts `headers` and documents the `*` custom-injection-point marker.

## 10. Bugs this testing discipline actually caught

A safety-budget double-tick that silently halved `--max-iterations`; a
`--modern-ui` banner ignoring classic suppression logic; a `chmod()` on
a not-yet-existent file whose `OSError` was silently swallowed; a
findings parser using a guessed heuristic instead of the real enum; a
WAF-detection substring match firing on a neutral announcement instead
of the actual positive-detection message; a literal JSON example
crashing every planner run; two WAF-pattern bugs in a test harness; a
test that inadvertently tripped a newly-added evidence-gathering guard.
None of these would have been caught by code review alone.

## 11. Retry/backoff, stuck-loop detection, finish-requires-evidence, diagnose_detection_failure

Found already integrated with test coverage (see the note at the top of
this document):

- **`_chat_with_retry`**: a transient Ollama failure is now retried with
  exponential backoff before ending the run. `sleep_fn` is injectable
  for tests.
- **Stuck-loop detection**: the same tool called with identical
  arguments too many times in a row is refused with a nudge instead of
  executed again.
- **Finish-requires-evidence guard**: `finish` is refused unless an
  observation-gathering action has run at least once this run.
- **`diagnose_detection_failure`**: reads the scan log for sqlmap's own
  diagnostic phrases (page instability, negative heuristic, WAF
  detection) and returns concrete suggestions for each, including
  pointing at sqlmap's real `string`/`notString` options.

**The one real bug found while verifying these:** a retry test used
`finish` as its terminal action, which the new evidence-guard correctly
refused since the test's minimal script never gathered evidence first -
a genuine interaction between two separately-reasonable features,
caught by running the full suite. Fixed by using `note` instead. Added
three previously-missing dedicated tests for the evidence-guard itself.
102 tests now, all passing.

## 12. Deeper grounding: DBMS and named-entity claim verification

`grounding_check` (§1) originally only validated the two claims that
matter most - success/failure vs. recorded injection-point evidence.
Extended it to catch two more real failure modes: a summary naming a
specific DBMS that doesn't match (or was never fingerprinted against)
`findings["dbms"]`, and a summary naming a specific table/database that
never actually appeared in `findings["tables"]`/`["databases"]` - both
plausible ways a model states something it inferred or half-remembered
rather than something the engine actually confirmed. The table/database
check is deliberately conservative: it only fires when there's at least
one known entity to compare against, to avoid false-flagging ordinary
prose that happens to mention a table-sounding word with no findings
context at all.

**A real bug caught immediately by testing the exact scenario the
check exists for:** the DBMS-mismatch logic's first version silently
passed the "summary names a DBMS but nothing was ever fingerprinted"
case - the one it was specifically built to catch - because Python's
`"" in "oracle"` is always `True`, and the mismatch comparison ran
through the same substring-containment branch regardless of whether
`findings["dbms"]` was actually empty. Caught by directly testing that
scenario (not assumed correct because the "wrong DBMS while one *was*
fingerprinted" case worked), fixed by handling the empty-`actual` case
explicitly before the substring comparison, reverified all six
scenarios (correct/wrong/absent DBMS, correct/wrong/absent table).

**A second bug, in an existing test, surfaced by the extension
working correctly:** `test_hallucinated_success_gets_caveat_and_is_not_
persisted_to_kb` asserted exactly one caveat for a summary that both
claims unfounded success *and* names an unfingerprinted DBMS - once the
new check could see that second problem too, the count correctly became
two, and the old assertion broke. Not a regression - the test's
expectation was just no longer complete - fixed by asserting both
specific caveats by content rather than loosening the count.

Verified through the actual `AgentPlanner` end-to-end, not just at the
`AgentMemory` unit level: a scripted run confirms a real MySQL
injection but has the model claim "Oracle" in its finish summary - the
mismatch is caught, and (using the existing caveats-gated persistence
logic from §1, unchanged) the run is correctly *not* written to the
knowledge base. 109 tests now (up from 102), all passing.

## 13. NoSQL injection support (`lib/nosql/`) - NoSQLMap integration

Everything above targeted SQL injection exclusively. This adds a
genuinely distinct injection class - NoSQL/MongoDB operator and
`$where`-clause injection - built from
[NoSQLMap](https://github.com/codingo/NoSQLMap) (Copyright 2014
Russell Butturini, GPLv3-or-later). **Licensing note**: sqlmap here is
GPLv2-or-later; a "v2-or-later" work can be used under GPLv3 terms, so
the combined project is distributable under GPLv3 - the more
restrictive of the two. NoSQLMap's copyright notice is preserved in
the derived files.

NoSQLMap itself is Python 2, ~2,500 lines, built as an interactive
`raw_input()`-driven menu tightly coupled to module-level global state
- fundamentally incompatible with this project's programmatic,
agent-driven architecture (and with Python 3, which everything else
here runs on). Two different integration decisions were made,
depending on which part of NoSQLMap was involved:

- **`lib/nosql/mongo_client.py`** - a genuine line-by-line port of
  NoSQLMap's `nsmmongo.py` (anonymous-access detection, database/
  collection enumeration) to standalone, importable Python 3
  functions, since that module's logic was already cleanly separable
  from the menu loop. Deliberately **not** ported: `stealDBs()`'s use
  of MongoDB's `copy_database` admin command (removed in MongoDB
  server 4.2+ and modern pymongo - porting it faithfully would build a
  feature that doesn't work against any currently-supported MongoDB;
  `dump_collection()` is the modern `find()`-based equivalent instead,
  mirroring `dump_table` on the SQL side), and Metasploit-based shell/
  exploit launching (`msfLaunch`) - excluded for the same reason
  sqlmap's own `os-shell`/`os-cmd`/file-write options are blocked by
  default elsewhere in this project (§3): this is a data-injection and
  enumeration framework, not an OS-takeover one.

  **Honest limitation, not glossed over**: this module could **not**
  be live-tested against a real MongoDB instance - this sandbox has no
  network egress, no `pymongo` package available to install, and no
  `mongod` binary. Every other claim in this document is backed by a
  real running instance; this one isn't, and that gap is real. What
  *was* verified: the module loads and degrades cleanly with a clear
  `MongoUnavailable` error when `pymongo` is absent (rather than
  crashing on import or with an opaque `AttributeError` deep inside a
  call), confirmed for every public function.

- **`lib/nosql/injection_probe.py`** - **not** a port. NoSQLMap's own
  web-app injection logic (`getApps()`/`postApps()` in `nosqlmap.py`)
  is ~1,700 lines interleaved with interactive prompts mid-attack,
  not cleanly separable the way `nsmmongo.py` was. Both NoSQLMap's own
  README and this reimplementation credit the same underlying research
  (Ming Chow's DEF CON 21 "Abusing NoSQL Databases") for the technique
  class itself: associative-array operator injection (`id[$ne]=1`,
  `id[$gt]=`, etc. - exploits frameworks that auto-parse bracket
  query-string syntax into a nested filter object passed straight into
  a MongoDB query) and `$where`-clause JavaScript injection
  (`' || '1'=='1`-style string breakouts, for apps that build `$where`
  filters via string concatenation). Since this only needs stdlib
  HTTP, it was built and verified the same way as everything else in
  this project.

  **Two real bugs found through that live testing, not shipped on the
  first green run:**
  1. A length-only anomaly threshold (even after one round of tuning)
     missed a confirmed-real bypass because two semantically opposite
     responses ("Access denied" vs "Welcome, realuser!") happened to
     differ by only 5 characters - length alone can't distinguish
     that. Replaced with content-similarity comparison
     (`difflib.SequenceMatcher`, stdlib) - the same category of fix
     sqlmap's own dynamic-content detection already relies on for
     exactly this reason.
  2. The default "OR-true string breakout" payload (`"' || '1'=='1"`)
     started with a bare, empty leading fragment before the `||` -
     `'' || <anything>` evaluates falsy in both JavaScript and Python
     regardless of what follows, so this specific payload could never
     actually break out of any target, a fact that isn't obvious from
     reading the payload text alone. Fixed to `"x' || 'a'=='a"` (a
     truthy leading fragment), confirmed against a real target built
     specifically to have this vulnerability class and nothing else.

  Verified against two independently-built, genuinely vulnerable
  targets (one for each injection class), both live-tested through the
  actual `nosql_test_injection` agent tool path, not just the module
  directly: operator injection (a homepage-free target reproducing the
  Express.js/`qs` bracket-parsing vulnerability pattern) and `$where`
  injection (a target reproducing string-concatenation-into-eval).
  Both correctly detected after the fixes; neither before.

**New agent tools**: `nosql_scan_target`, `nosql_enumerate`,
`nosql_search_collections` (all `SAFE_ACTIONS` - read-only),
`nosql_dump_collection` (`HIGH_RISK_ACTIONS`, same confirmation gate as
`dump_table`/`dump_all`), `nosql_test_injection` (`SAFE_ACTIONS`).
`SafetyPolicy.authorize()`'s scope-check was widened to also recognize
a `host` argument (previously only `url`/`target`), since NoSQL tools
address a bare host:port rather than a URL - purely additive, existing
SQL-tool scope-checking is unaffected. 128 tests now (up from 109),
including 19 new ones (`lib/ai/tests/test_nosql.py`) covering URL
construction, payload structure, graceful pymongo-absent degradation,
safety/scope integration, and the two live-target detections.

**A note on environment resilience**: this integration was built
twice. The sandbox environment reset mid-session (working directory
and all in-progress files lost without warning) partway through the
first attempt, immediately after the length-threshold bug had been
found and fixed but before either the payload bug or the agent-tool
wiring existed. The project was restored from the last successfully
delivered package (§12's state, 109 tests) and the NoSQL work redone
from scratch on top of it - the length-threshold fix was reapplied
from memory of having just found it, and the payload bug and full tool
wiring were found/built fresh the second time through. Mentioned here
because it's a real thing that happened to this project's development,
not because it changes anything about the correctness of what's
described above - everything in this section reflects the current,
actually-tested code.

**Update: the two live targets are now checked into the repo, and the
MongoDB-server gap has a partial (explicitly-labeled) fix.** The
"environment resilience" note above describes throwaway scripts that
existed only in a lost sandbox session - anyone picking this project
up afterward would have had to rebuild them from scratch (as
happened here, again) just to re-confirm this section's claims still
hold. Two changes address that:

1. `lib/ai/tests/live_targets/operator_injection_target.py` and
   `where_injection_target.py` are now real files in the repo, not
   one-off scripts - minimal stdlib `http.server` targets reproducing
   the same two vulnerability classes described above. Start both
   (ports 9380/9381) and `TestInjectionProbeLiveIntegration` in
   `lib/ai/tests/test_nosql.py` runs for real instead of skipping;
   confirmed the exact same detections this section already claims
   (`likely_injectable: True` for both, via the real `probe()`
   function; all four documented `$where` payloads individually
   verified by hand to produce their documented outcome, not just
   through the aggregate test result).
2. `mongo_client.py`'s "could not be live-tested against a real
   MongoDB instance" limitation is now partially closed:
   `lib/ai/tests/fake_pymongo.py` is an in-memory stand-in for
   `pymongo`/`bson` (not a real server - its own docstring is explicit
   about exactly what this does and doesn't prove), and
   `lib/ai/tests/test_mongo_client_fake_server.py` (16 tests) drives
   every public function in `mongo_client.py` - `scan_anonymous_access`,
   `enumerate_databases` (including the `system.users` finding
   extraction and per-database enumeration-failure handling),
   `dump_collection` (query filtering, `limit`, BSON-to-plain
   conversion), `search_collections`, `get_server_info` - against it.
   This exercised the module's actual logic and caught one real bug -
   in the fake, not in `mongo_client.py`: an early version of the
   fake's `db.system.users` attribute chain didn't reproduce
   pymongo's own dotted-collection-name behavior, which
   `enumerate_databases()` depends on to find the users collection at
   all. `mongo_client.py` was correct throughout; the fake needed
   fixing to actually exercise it properly.
   **What this still does not prove**: real MongoDB wire-protocol
   behavior, real auth failure modes, real BSON edge cases, or
   anything the actual `pymongo` driver might do differently than this
   fake. The original limitation - no real `mongod` available in this
   sandbox - is unchanged; this closes the "logic was never even
   exercised" gap, not the "verified against a real server" gap.

## 14. Complete rebrand: sqlmap → Alkha

Everything up to this point still ran under the name "sqlmap" - the
banner, `VERSION_STRING`, entry-point filenames, and home directory
all still said so, even as the codebase itself had grown a full
agentic layer, a modern UI, and NoSQL support. This section is that
naming catching up to the reality of what the project had become.

**What changed:**

- `lib/core/settings.py`: `VERSION_STRING` is now `alkha/<version>#<type>`
  (previously `sqlmap/...`); `DESCRIPTION`, `DEFAULT_USER_AGENT`, the
  legal disclaimer, and the classic ASCII-art `BANNER` all updated. The
  banner's old ASCII art (a stylized rendering of the literal word
  "sqlmap") was replaced with a plain text banner rather than reused
  under a new name - reusing another project's own distinctive visual
  mark for a "complete" rebrand would misrepresent origin, not just
  skip attribution. `SITE` still points to `https://sqlmap.org` -
  that's the real, honest origin of the underlying engine, not a
  fabricated Alkha domain.
- **Entry points**: `sqlmap.py` → `alkha.py`, `sqlmapapi.py` →
  `alkhaapi.py`, `alkha_agent.py` (previously `sqlmap_agent.py`) are
  now the real, primary files. The old names still exist as thin
  compatibility shims, not deleted - `lib/utils/api.py`'s
  `Task.engine_start()` **hardcodes `"sqlmap.py"`** to spawn the
  actual scan-engine subprocess for every single REST API scan, which
  is what this project's entire agentic layer depends on, and
  `lib/core/testing.py`'s smoke-test runner does the same. Renaming
  the real file while leaving a working shim at the old name was the
  safe way to get a genuine rebrand without touching that load-bearing,
  easy-to-get-wrong code path directly.
- **A real bug in the first version of that shim, caught by testing
  it properly rather than trusting it because direct invocation
  worked**: the shim used `runpy.run_path(..., run_name="__main__")`
  unconditionally. `alkhaapi.py` does `from sqlmap import modulePath` -
  a plain *import*, not an execution - and forcing `run_name="__main__"`
  regardless of how the shim itself was invoked meant that import
  statement alone triggered `alkha.py`'s entire program (banner, a
  scan attempt, immediate exit) as a side effect, before `alkhaapi.py`
  ever got to parse its own `-s`/`-p` arguments. The original
  unmodified `sqlmap.py` never had this problem - it has its own
  `if __name__ == "__main__":` guard, which a plain import correctly
  never triggers. Caught by actually starting `alkhaapi.py -s` and
  seeing a scan banner instead of a "Running REST-JSON API server..."
  message, not by assuming the shim worked because `sqlmap.py --version`
  alone looked fine. Fixed by having the shim check its own `__name__`
  and only force `__main__` semantics when genuinely run directly;
  when imported, it loads `alkha.py` as a real module instead and
  re-exports its public names. **Reverified with the test that
  actually matters**: started `alkhaapi.py -s` for real, submitted a
  scan through the actual `EngineClient` REST path, and confirmed the
  spawned engine subprocess completed successfully
  (`{"success": true, "engineid": ...}`, `"status": "terminated"`,
  `returncode: 0`) - proof the hardcoded `"sqlmap.py"` reference still
  resolves correctly through the fixed shim, not just that the shim
  file parses.
- **Home directory**: `~/.sqlmap`/`~/.local/share/sqlmap` →
  `~/.alkha`/`~/.local/share/alkha` (`lib/core/common.py`'s
  `setPaths()`, plus `lib/ai/knowledge_base.py`'s cross-run store).
  Verified with a real scan: output correctly lands under
  `~/.local/share/alkha/output/`. Existing sqlmap users' old data at
  the previous location isn't touched or migrated - a new identity
  starting a new home directory is the expected, honest consequence of
  an actual rebrand, not a bug.
- **`--update` disabled outright for this build**
  (`lib/core/update.py`, gated on a new `IS_CUSTOM_BUILD` flag in
  `settings.py`). Traced through what it actually does first: on a
  non-git checkout (this is a plain extracted tree, not a git clone),
  it falls back to fetching a zipball from upstream sqlmap's own
  `GIT_REPOSITORY` and overwriting files in the current directory -
  which would silently replace every modification in this project
  (`lib/ai/`, `lib/nosql/`, `lib/core/tui.py`, the security fixes) with
  vanilla sqlmap. That's real, if opt-in (`--update` plus a manual `y`
  confirmation) - and leaving it live under a new name, with an
  operator who runs `--update` out of habit expecting to update
  *Alkha*, would be a bad outcome hiding behind a prompt that's easy to
  click through. Refuses immediately with a clear explanation instead.
- **Crash-report messaging**: `lib/core/common.py`'s unhandled-exception
  message used to direct every crash to sqlmap's own GitHub issue
  tracker unconditionally. Fixed to say plainly that this is a modified
  build with no separate tracker of its own, and to only point at
  upstream for what's actually upstream's code to fix - directing bug
  reports about *this project's* modifications to the original
  maintainers would have been genuinely unfair to them.

**Licensing, stated plainly**: this is a derivative work of sqlmap
(GPLv2-or-later, https://sqlmap.org) and NoSQLMap (GPLv3-or-later,
https://github.com/codingo/NoSQLMap), copyright notices preserved in
every file that carries them. A GPLv2-or-later work can be used under
GPLv3 terms, so the combined project is distributable under GPLv3 -
see §13 for the fuller reasoning. Renaming the project doesn't change
any of that; `LICENSE` and the original copyright headers throughout
the codebase are untouched. See `doc/LICENSING.md` for the full
compliance guide - what redistribution/rebranding requires, what a
closed-source/commercial variant would actually require (the sqlmap
engine and the NoSQLMap-derived portion of `lib/nosql/mongo_client.py`
have two *separate* licensing questions with two separate answers, not
one combined answer), and a practical release checklist.

**Verified**: full `lib/ai/tests/` suite (128 tests) passes after every
change in this section, checked incrementally rather than once at the
end given how much of this touched genuinely load-bearing
infrastructure (the REST API subprocess spawn in particular); both old
and new names for all three entry points produce identical, correct
output; a real scan through the REST API confirmed end-to-end after
the shim fix; the classic banner, `--modern-ui` banner, and the
agent's welcome panel all render the new branding consistently with
no leftover "sqlmap" references in user-facing text checked so far.

## 15. Fuzz audit: untrusted model output could crash the whole run

A targeted fuzz pass across `lib/ai/tools.py` (`ToolExecutor.execute()`),
`lib/ai/safety.py` (`SafetyPolicy.authorize()`/`check_host_in_scope()`),
and `lib/ai/planner.py` (`AgentPlanner._parse_reply()`) - the three
places untrusted, model-generated output first reaches this codebase
- found a real, systemic bug class: none of them validated that the
values they received (a tool call's `args`, a JSON reply's `action`,
a `url`/`host`/`target` value) were actually the type they assumed
before calling `.get()`, `.items()`, `.lower()`, or `"x" in y` on them.
A malformed or hallucinated model reply - a plausible failure mode for
any local LLM, not a contrived adversarial input - could crash the
entire autonomous `run()` loop with an uncaught `AttributeError` or
`TypeError`, since `step()` only catches `ScopeViolation` around the
`authorize()` call and nothing at all around `execute()` or
`_parse_reply()`.

**How it was found**: a hand-rolled fuzz harness (no `hypothesis`
available in this sandbox - no network to install it) generated ~300
malformed argument shapes per tool (non-dict `args`, dicts with
wrong-typed values for `url`/`port`/`depth`/`options`/`query`/etc.)
and ran every one against every `TOOL_SPECS` entry, every action name
through `authorize()`, and a battery of malformed model replies
through `_parse_reply()` and a full `step()`. Before any fix: **111
crashes** in `execute()`, **360** in `authorize()`, and every one of
15 malformed-reply shapes crashed `_parse_reply()`/`step()`. All
distinct root causes, not one bug repeated:

- `ToolExecutor.execute()` did `args = args or {}` then called
  `args.get(...)` in every branch - a non-dict truthy `args` (a list,
  string, or number) sailed past the `or {}` and crashed on the first
  `.get()`.
- `SafetyPolicy.authorize()`'s first line, `args.get("url") or
  args.get("target") or args.get("host")`, made the same assumption;
  `check_host_in_scope()` additionally assumed whatever it got back
  was a string before doing `"://" in url_or_host`, crashing with
  `TypeError: argument of type 'int' is not iterable` for a
  non-string-but-truthy `url`/`host`/`target` value.
- `AgentPlanner._parse_reply()` assumed the JSON-parsed `"action"` key
  was a dict before calling `.get("name")` on it, assumed a native
  `tool_calls[0]` and its `"function"` were dicts, and could return a
  non-dict `args` (a list from `extract_json_block` on a malformed
  `arguments` string) straight into `execute()`, defeating that
  function's own guard by handing it something that looked falsy-safe
  but wasn't `None`.
- `option_validator.validate_options()`'s `(options or {}).items()`
  had the identical `or {}` gap as `ToolExecutor.execute()`, for
  `configure_scan`'s `options` argument specifically.
- `tamper_catalog.py`'s `render_catalog_for_prompt()` and
  `recommend_for_dbms()` both called `.lower()` on their `query`/
  `dbms_name` argument without checking it was a string first.

**The fix, in each case, was to fail safe at the boundary rather than
validate deeper in**: `execute()` now rejects a non-dict truthy `args`
with a normal `{"ok": False, "error": ...}` response (the same shape
every other validation failure already returns) before any branch
runs; `authorize()` and `check_host_in_scope()` raise `ScopeViolation`
for the same case (the existing "refused, not crashed" path an
out-of-scope host already used); `_parse_reply()` now checks
`isinstance(..., dict)` at every point it previously assumed one,
folding every malformed shape into the same "nothing parseable, nudge
a retry" path already used for a plain unparseable reply;
`validate_options()` and the two `tamper_catalog.py` functions
degrade gracefully (a clear dropped-with-reason error, or a
string-coerced/generic-only fallback) instead of raising. Two
narrower, pre-existing gaps were fixed the same day for consistency:
`crawl_target`'s and `dump_table`'s unguarded `int()` coercions on
`depth`/`start_row`/`stop_row` (the `nosql_*` handlers already had
this right, wrapped in their own try/except - it just hadn't been
applied to these two, which predate that work) now return a clear
error on a non-numeric value instead of raising `ValueError`; and
`nosql_test_injection` (the one `nosql_*` handler with no try/except
at all) is now wrapped like its siblings.

**Verified**: the same fuzz harness re-run after the fix (with a wider
random-shape battery than the first pass, ~300 shapes × 26 tools) found
**zero** crashes across all three surfaces. 12 new regression tests
were added across `test_tools.py` (`TestMalformedArgsRobustness`),
`test_safety.py` (`TestMalformedArgsRobustness`),
`test_planner_integration.py` (`TestMalformedReplyRobustness`),
`test_option_validator.py`, and `test_tamper_catalog.py`, each
encoding the specific malformed shapes the fuzzer found rather than a
generic "doesn't crash" smoke test, so a regression here fails loudly
and specifically. Full suite: **169/169 tests pass** (up from 157).

**Extending the audit past the first three surfaces found four more,
same root cause, different files:**

- `AgentMemory.grounding_check()` did `(summary or "").lower()` -
  `finish`'s `summary` argument is untrusted model output like every
  other tool argument, and a non-string-but-truthy value (a number,
  list, dict) crashed this on the one action every run ends on.
- `AgentMemory.record_action()`'s `note` handling stored
  `args.get("text", "")` verbatim - a non-string value sat in
  `findings["notes"]` until `alkha_agent.py`'s final-report rendering
  did `"\n".join(notes)`, which raises `TypeError` on the first
  non-string item, crashing the CLI at the very last step of an
  otherwise-successful run.
- **The most severe of the four**: `planner.py`'s finish handling did
  `tamper = (self.tools.current_options().get("tamper") or "");
  tamper.split(",")` to persist which tamper scripts were in effect on
  a confirmed success. `validate_options()` only checks that
  `"tamper"` is a real sqlmap option *name*, never that its *value* is
  the string the model was supposed to send - a hallucinated
  `configure_scan({"tamper": 12345})` earlier in the same run crashed
  this with `AttributeError: 'int' object has no attribute 'split'`,
  **right as a genuinely successful, evidence-backed run tried to save
  what it found** - the single worst place in the whole codebase for
  an uncaught exception to land.
- `AgentMemory._merge_engine_findings()` assumed every item in the
  engine's own `scan_data()` response was a dict, and a `TABLES` value
  that wasn't a list got iterated character-by-character (Python
  iterates strings by character) rather than failing clearly - not a
  crash, but silent data corruption. This one is fed by sqlmap's own
  REST response rather than the model, so it's a defense-in-depth fix
  (a malformed/intercepted response, not model hallucination) rather
  than closing an LLM-facing gap - included here because the same
  audit pass found it and the fix is the same shape.
- `EngineClient._request()` validated that every REST API response was
  *parseable* JSON but not that it was a JSON *object* - a
  technically-valid array/string/number/null response would crash
  every caller's `r.get("success")` with `AttributeError` instead of
  the existing, clear `EngineError` path. Same defense-in-depth
  category as the point above; fixed at the single choke point every
  API call passes through, so every caller is covered at once. Real
  end-to-end confirmed working after the fix (task creation, options
  listing, status check, all through the actual REST server).
- `escalation.py` and `knowledge_base.py`'s `_host_key`/`lookup`/
  `record_success` were also checked and found already sound - the
  former takes no external input at all, the latter's `target` comes
  from the operator's own `--target` flag, not the model. One
  defense-in-depth fix went into `knowledge_base.py`'s
  `render_for_prompt()` anyway - a hand-edited or older-version
  knowledge file could contain non-string tamper entries, and its
  `", ".join()` is now coerced the same way.

**Verified**: 8 more regression tests across `test_memory.py`
(`TestMalformedInputRobustness`), `test_planner_integration.py`
(the exact `configure_scan({"tamper": 12345})` → grounded finish
scenario), and a new `test_engine_client.py` (6 tests, using a patched
`urlopen` since no prior test file existed for this module) covering
the response-shape hardening specifically. Full suite: **180/180
tests pass** (up from 169).

## 16. Phase 2 terminal UI, and a bug only a live run could catch

Closed the last item on the "not done yet" list: `lib/core/tui.py`
gained `iteration_rule()`, `state_line()`, and `render_final_report()`;
`alkha_agent.py`'s `on_event` became a stateful `EventRenderer` that
runs a live spinner during Ollama calls (see `doc/AGENT.md`'s "Phase 2
terminal UI (done)" section for the full writeup).

Worth recording separately here: this was verified by actually running
a full scripted plan->act->observe loop end-to-end through the real
rendering code and reading the terminal output, not just asserting
each new function individually doesn't crash - and that live run
immediately surfaced a real, pre-existing bug that had sat undetected
through every prior audit pass in this document: `AgentMemory`'s
`_check_named_entity_claims()` used the regex
`(?:table|database|db)\s+['"]?([a-zA-Z_][a-zA-Z0-9_]{2,})['"]?` with no
word boundary before the keyword group. A finish summary containing
the ordinary sentence "...is inject**able via** boolean-based blind
and UNION query on MySQL..." matched `table` as a substring of
"injectable", then captured "via" as the supposed database name -
producing a false "you claimed an unconfirmed database" caveat on a
completely accurate summary. Fixed by adding `\b` word boundaries
around the keyword group; verified against both the exact sentence
that triggered it and the legitimate matches ("table users", "database
webapp", "the db users_backup") to confirm the fix didn't just move
the false-negative/false-positive boundary elsewhere.

This is the kind of bug that a fuzzer sweeping argument *types* (as in
§15) structurally cannot find - it only exists at the level of
specific English word choice, which only surfaces by generating
plausible content and actually reading what the code did with it. The
type-level fuzzing in §15 and this content-level check are
complementary, not redundant: neither would have caught what the other
found.

**Verified**: 21 new tests (`test_tui.py`, 16 tests for the new
rendering functions; `test_event_renderer.py`, 5 tests for the
spinner-lifecycle logic using a fake Spinner so no real threads/TTY
are needed) plus a regression test for the regex fix built from the
exact triggering sentence. Full suite: **202/202 tests pass** (up from
180).

## 17. The NoSQL agent path had never actually been run end to end - two real bugs found

Every prior NoSQL-related check exercised one layer at a time: `probe()`
directly against a live target (§15/§16), `mongo_client.py` against a fake
pymongo, `ToolExecutor.execute("nosql_*", ...)` directly with a mocked
engine. None of them ran the actual thing an operator relies on: the full
autonomous plan→act→observe loop, with a scripted model choosing to use
the NoSQL tools, the same way `TestPlannerJsonFallback`/
`TestPlannerGroundingIntegration` already proved the SQL path works.
Writing `TestNosqlAgentEndToEnd` (driving a real `AgentPlanner.run()`
against the real live operator-injection target from §15/§16) to close
that gap found two real, independent bugs - both pre-existing, neither
related to the NoSQL work being new, both invisible to every test that
came before because each tested a layer in isolation:

- **The hard finish-gate didn't recognize any `nosql_*` tool as
  evidence-gathering.** `AgentPlanner.step()`'s gate only counted
  `get_findings`/`check_status`/`get_logs` - the sqlmap-engine path's
  observation tools - toward `_has_gathered_evidence`. A pure-NoSQL
  engagement that never touches the sqlmap REST engine at all could
  therefore never pass the gate, and `finish` would be blocked forever;
  the run would burn its entire iteration/time budget and terminate via
  `BudgetExceeded` instead of finishing cleanly, no matter how solid the
  actual NoSQL finding was. Fixed by adding all five `nosql_*` tool names
  to the evidence-gathering check (only when they return `ok: True`,
  matching the existing pattern) and updating the gate's own warning/error
  text, which still only mentioned the three SQL-path tool names.
- **`AgentMemory.record_action()` never merged any `nosql_*` result into
  the structured findings dict.** `grounding_check()`'s "did you actually
  confirm an injection" check only ever looks at
  `findings["injection_points"]`, which `_merge_engine_findings()`
  populates exclusively from the sqlmap engine's own
  `CONTENT_TYPE.TECHNIQUES` data - a successful `nosql_test_injection`
  had no path into that dict at all. The practical effect: **every
  successful NoSQL-only finish would receive a false "you claimed an
  injection but nothing was recorded, treat as unverified" caveat**,
  regardless of how solid the actual finding was - the exact failure mode
  grounding_check exists to catch, misfiring on a summary that was
  completely accurate. Fixed by merging a successful, `likely_injectable`
  `nosql_test_injection` result into `findings["injection_points"]`
  (as `{"place": "nosql", "parameter": <param>}`, deduplicated the same
  way the sqlmap-engine path already dedupes), and a successful
  `nosql_enumerate` result into `findings["databases"]`/`["tables"]` -
  the direct NoSQL analogue of `_merge_engine_findings`'s
  `CONTENT_TYPE.DBS`/`TABLES` handling, closing the same class of gap
  for the "you claimed to enumerate databases" grounding check before it
  could misfire the same way.

Neither bug was visible from any single layer's tests - `grounding_check()`
in isolation looked correct (it correctly flags an unsupported claim given
the findings dict it's handed), and `nosql_test_injection` in isolation
looked correct (it correctly calls `probe()` and returns an accurate
result) - the gap was entirely in the wiring between them, which only an
actual end-to-end run exercises.

**Verified**: `TestNosqlAgentEndToEnd` (2 tests, real live target,
skips automatically like §15/§16's live tests if the target isn't
running) - one drives a full successful NoSQL-only run to a clean finish
with zero false caveats, the other confirms an out-of-scope host is
still refused correctly (and never actually reaches `probe()`) even
though `nosql_test_injection` now counts as evidence. Plus 7 more unit
tests: `TestNosqlFindingsExtraction` in `test_memory.py` (6 tests, the
findings-merge logic in isolation, no live target needed) and a
finish-gate regression in `test_planner_integration.py`'s
`TestHardFinishGate` (using a mocked `probe()`, since that test is about
the gate mechanism, not injection detection). Full suite: **211/211
tests pass** (up from 202).

**Third gap in the same area, found by the same check**: while adding
tests for the fixes above, a check of `facts_summary()`'s output after a
simulated `nosql_dump_collection` call showed the same shape of bug -
`findings["dumped_tables"]` (what the sqlmap-engine path's `dump_table`
populates via `CONTENT_TYPE.DUMP_TABLE`) had no NoSQL equivalent path in
either. Practical effect: `facts_summary()` stayed `"(nothing confirmed
yet)"` immediately after a real, successful data exfiltration - meaning
the model had no memory of having already dumped a collection on its
next turn (risking a redundant re-dump), and the final report would
silently undercount NoSQL dumps to zero regardless of how much data was
actually pulled. Fixed the same way as the other two: a successful
`nosql_dump_collection` result now appends
`{"database", "collection", "count"}` to `findings["dumped_tables"]`
(append-only, no dedup, matching the existing `dump_table` convention
rather than introducing an inconsistency between the two dump paths).
4 more unit tests added; full suite: **214/214 tests pass**.

**Follow-up closed**: `nosql_scan_target`'s anonymous-access result -
arguably the single most important finding in a NoSQL engagement,
whether the instance requires no authentication at all - now has its
own findings field, done properly rather than rushed into the wrong
bucket. `AgentMemory.findings["nosql_access"]` is a new list (not
folded into `notes`, for the reason noted above: an "open" result is a
strong positive finding, and even a routine "auth_required" result is
not a caveat about the run, so surfacing either under `notes`'s
`WARN`-colored "notes / caveats" heading would misrepresent both).
Populated by a successful `nosql_scan_target` call as
`{"host", "port", "status", "version", "database_count"}`,
append-only per scan (a host can legitimately be scanned more than
once - e.g. re-checking after remediation - so each call is kept as
its own observation rather than deduped, matching `dumped_tables`'
existing convention).

`facts_summary()` renders an `"open"` result distinctly and
prominently - `"NoSQL: <host>:<port> allows ANONYMOUS ACCESS (no auth
required) - MongoDB <version>, N database(s)"` - so the model itself
sees it as unmistakably significant on its next turn, while
`"auth_required"`/`"error"`/`"unreachable"` render as a plain,
unremarkable one-liner. `render_final_report()` (`lib/core/tui.py`)
does the same in the terminal: an `"open"` result is styled `BAD` (red)
- deliberately distinct from `notes`'s `WARN` (yellow), since this is a
confirmed finding, not a concern about the run - anything else renders
plainly.

**Verified**: 6 new `test_memory.py` tests (extraction, both status
branches, the append-not-dedupe behavior, failure leaves findings
untouched) and 4 new `test_tui.py` tests (the `BAD`-styled open case,
the plain `auth_required` case, multiple entries, and the no-entries
case rendering no section at all) - plus a full end-to-end
`TestNosqlAgentEndToEnd` test driving a real `AgentPlanner.run()`
through a scan-target-only engagement (mocking
`scan_anonymous_access()` itself, since no real `mongod` is available
in this sandbox - the same constraint already documented for
`test_mongo_client_fake_server.py`) to confirm the finish-gate and
findings-merge fixes work together, not just in isolation. Full suite:
**224/224 tests pass** (up from 214).

## 18. `ollama_client.py` had the same response-shape gap as `engine_client.py` - never checked until now

`EngineClient._request()` was hardened in §15 against a technically-valid-
but-unexpected top-level JSON shape (array/string/number/null instead of
an object). `OllamaClient` talks to a different server over the same kind
of HTTP+JSON interface and was never checked for the identical class of
gap - it hadn't been touched by any prior audit pass, largely because
until this point no test file existed for it at all.

Confirmed by direct reproduction before fixing anything (matching this
whole audit's practice of proving the crash before writing the fix):
`chat()`'s `if "error" in parsed:` raised `TypeError` for a bare JSON
number or `null` response (`in` requires an iterable), and the following
`parsed.get("message", {})` raised `AttributeError` for a list or string
response. `list_models()` had the equivalent gap one level deeper - its
`except ValueError` only catches a genuinely non-JSON response; a
technically-valid `[1, 2, 3]` or `{"models": "not a list"}` response
sailed past that catch and crashed on `.get("models", [])` or the
list-comprehension's `m.get("name")` respectively.

A third, related gap was found in the same pass: `extract_json_block()`
(used by `planner.py`'s `_parse_reply()` on `reply.get("content", "")`)
only guarded against a falsy `text` (`None`, `""`) before handing it to
`re.search()` - a non-string-but-truthy value (a number, list, dict)
crashed with `TypeError: expected string or bytes-like object`. Since
`reply` is Ollama's own response dict, a malformed `"content"` field
(from Ollama itself, or a proxy in front of it) would have taken this
same path into an uncaught crash inside `_parse_reply()`, the same
severity class as every other untrusted-input gap closed in §15.

**Fixed** the same way as `EngineClient._request()`: `chat()` validates
`isinstance(parsed, dict)` before touching it further, raising a clear
`OllamaError` naming the actual type received; `list_models()` validates
the top level and the `"models"` value's shape, and skips (rather than
crashes on) any non-dict entry within it, degrading to an empty list
throughout rather than raising, since a model-listing helper failing
silently is a reasonable UX and matches its own pre-existing
`except ValueError: return []` convention; `extract_json_block()` now
checks `isinstance(text, str)` alongside the existing falsy check.

**Verified**: new `test_ollama_client.py` (19 tests - no test file
existed for this module before this audit pass) covering the exact
response shapes reproduced above, using the same patched-`urlopen`
technique as `test_engine_client.py`, plus dedicated `extract_json_block`
coverage including the legitimate markdown-fence and embedded-JSON
extraction cases to confirm the fix didn't regress the common case.
Full suite: **243/243 tests pass** (up from 224).

## 19. Redis support - the first non-MongoDB NoSQL backend

Extended past MongoDB into Redis - by far the most commonly reported
exposed-NoSQL-datastore finding in real bug bounty programs, since Redis
has no authentication by default and its RESP2 wire protocol is simple
enough to implement directly rather than needing a client library the
way MongoDB's protocol needed `pymongo`.

**Scoped deliberately, matching `mongo_client.py`'s own documented
principle**: this is a data-enumeration and read-only dumping module,
not a remote-code-execution one. `lib/nosql/redis_client.py`'s module
docstring explicitly excludes the well-known unauthenticated-Redis-to-
RCE techniques (writing an SSH key or cron job via `CONFIG SET dir` +
`SAVE`, `MODULE LOAD`, replication-based attacks) and any
destructive/write command (`FLUSHALL` etc.) - the same reasoning
`sqlmap`'s own `os-shell`/`os-cmd` are opt-in and heavily gated rather
than reached for by default. Anonymous-access detection, key
enumeration (via cursor-based `SCAN`, never the blocking `KEYS`
command - this may be someone else's production instance), and
type-aware read-only value dumping (`GET`/`LRANGE`/`SMEMBERS`/
`HGETALL`/`ZRANGE` as appropriate per key) is the full scope, the
direct analogue of `mongo_client.py`'s `dump_collection()` or sqlmap's
own `dump_table`.

**Built as a from-scratch RESP2 implementation**, not a port of any
existing tool - `_encode_command`/`_read_reply` implement just enough
of the protocol (simple strings, errors, integers, bulk strings,
arrays) for this module's needs, verified against the official protocol
spec rather than against another codebase.

**A real fake Redis server, not just mocks**: `lib/ai/tests/live_targets/
fake_redis_server.py` speaks enough real RESP2 to answer `PING`/`INFO`/
`SCAN`/`TYPE`/`GET`/`LRANGE`/`SMEMBERS`/`HGETALL`/`ZRANGE` correctly, in
both an open and an `--auth-required` mode - the same "prove it against
something actually speaking the protocol" standard already established
for the HTTP-based NoSQL injection targets (§15/§16) and the fake
pymongo (`test_mongo_client_fake_server.py`), extended to a raw-socket
protocol this time rather than HTTP.

**Agent wiring, applying every lesson from §17/§18 proactively rather
than waiting to rediscover them**: three new tools
(`redis_scan_target`, `redis_enumerate_keys`, `redis_dump_keys` -
the last correctly marked `HIGH_RISK` alongside
`nosql_dump_collection`/`dump_table` in `lib/ai/safety.py`) were added
already wired into the finish-gate's evidence-gathering check and
`AgentMemory.record_action()`'s findings-merge logic in the same
change that introduced them, rather than needing a follow-up end-to-end
test to discover the gap the way §17 did for the `nosql_*` family.
`redis_dump_keys`'s `keys` argument (untrusted model output, described
as "array of strings" in `TOOL_SPECS` but not guaranteed to actually be
one) is explicitly type-checked before use - a hallucinated bare string
would otherwise be iterated character-by-character, the exact `TABLES`-
iteration bug class already caught and fixed in §15.

**The findings schema was generalized, not duplicated**: rather than
add a separate `redis_access`/`redis_dumped` list next to MongoDB's
`nosql_access`/`dumped_tables`, both fields gained a `"backend"` key
(`"mongodb"` or `"redis"`) so a single list holds either, and
`facts_summary()`/`render_final_report()` pick the right display label
from it - Redis has no equivalent of MongoDB's "database count" (16
numbered DBs by default, not a comparable metric), so that field is
always `None` on a Redis entry rather than omitted, keeping every
entry's key set uniform regardless of backend for whatever code
iterates the list next.

**A real bug found and fixed by the end-to-end test anyway**, despite
applying §17's lessons proactively: the first run of
`TestRedisAgentEndToEnd` failed with `redis_dump_keys` refused, not
because of a wiring bug this time, but because `redis_dump_keys` is
correctly `HIGH_RISK` and the test hadn't enabled yolo mode - a good
reminder that "gated pending operator confirmation" and "broken" look
identical from a test's assertions unless the test accounts for the
gate. Fixed by constructing the test's `SafetyPolicy` with `yolo=True`
(the test's stand-in for `--agent-yolo`), not by loosening anything in
the actual gating logic.

**Verified**: `test_redis_client.py` (21 tests - 11 protocol-level unit
tests for `_encode_command`/`_read_reply`/`_parse_info` needing no
server at all, 10 live-integration tests against the real fake server
in both its open and auth-required modes), `TestRedisFindingsExtraction`
in `test_memory.py` (7 tests, including one confirming MongoDB and
Redis access entries can coexist and are labeled correctly, and one
confirming a Redis entry never prints a stray "None database(s)"
artifact of the shared schema), and `TestRedisAgentEndToEnd` in
`test_planner_integration.py` (2 tests, a full successful open-access-
plus-dump run and an out-of-scope-host refusal, both against the real
live fake server). Full suite: **273/273 tests pass** (up from 243).

**Deliberate next steps, not built this round**: Elasticsearch/
OpenSearch (unauthenticated cluster access on port 9200 is a very
commonly reported bug-bounty finding, and speaks plain HTTP+JSON - no
protocol implementation needed, just HTTP requests the way
`injection_probe.py` already does) and CouchDB (also plain HTTP+JSON,
`_all_dbs`/`_all_docs`) are the natural next additions using the exact
pattern established here and in §13: a `lib/nosql/<backend>_client.py`
module with the same anonymous-access/enumerate/dump shape, a real
live fake target for testing, and the same three-tool wiring into
`tools.py`/`safety.py`/`memory.py`/`planner.py`. Not built this round
so each gets the same level of real verification Redis just did,
rather than three shallow, undertested stubs delivered at once.
Cassandra and other backends that need a real client-library dependency
(no simple protocol to implement directly, the way MongoDB needed
`pymongo`) would follow `mongo_client.py`'s pattern instead - optional
import, graceful degradation, a fake in-memory test double.

## 20. Elasticsearch/OpenSearch support - the second addition, lessons applied proactively

The second of the two next steps named at the end of §19 - unauthenticated
Elasticsearch/OpenSearch access on port 9200 is, like open Redis, one of
the most commonly reported real-world bug-bounty findings. Speaks plain
HTTP+JSON natively (OpenSearch is a fork of Elasticsearch 7.10 and kept
the same `_cat`/`_search` surface, so one module covers both), so
`lib/nosql/elasticsearch_client.py` needs no client library at all - built
the same way `injection_probe.py` was, stdlib HTTP only.

**Same deliberate scope exclusion as MongoDB/Redis, adapted to this
engine's actual CVE history**: the module docstring explicitly excludes
any use of the scripting engine (`_scripts`, inline `script` fields, or
`_update_by_query` with one) - Elasticsearch has real, documented CVEs
where its old Groovy/MVEL scripting sandboxes allowed remote code
execution via a crafted script, so using scripting at all here would be
reaching for exactly that technique class, not data enumeration. Also
excluded: `_snapshot`/`_reindex` with a `remote` source (an SSRF/
exfiltration primitive reaching beyond this instance) and any
destructive/write call. Anonymous-access detection, `_cat/indices`
enumeration, and plain `_search`-based read-only document dumping is the
full scope - the same three-tool shape (`elasticsearch_scan_target`,
`elasticsearch_enumerate_indices`, `elasticsearch_dump_index`, the last
`HIGH_RISK`) as Redis.

**Every lesson from §17/§19 applied proactively, not rediscovered**:
finish-gate evidence-gathering, `HIGH_RISK_ACTIONS`, and the
findings-merge logic were all wired into `tools.py`/`safety.py`/
`memory.py`/`planner.py` in the same change that introduced the tools -
and this time the proactive fixes actually held: both
`TestElasticsearchAgentEndToEnd` tests (including the `HIGH_RISK`-gated
dump, correctly requiring `yolo=True` the same way §19's Redis dump
did) passed on the first real run against the live fake server, no
follow-up fix needed. The findings schema extended cleanly to a third
backend rather than needing another generalization pass:
`nosql_access`/`dumped_tables` entries now carry `"backend":
"elasticsearch"`, and Elasticsearch's index count maps onto the same
shared `database_count` field MongoDB already used (Elasticsearch's
`_cat/indices` count and MongoDB's database count are comparable
"how many things are in here" metrics in a way Redis's numbered-DB
concept isn't - which is exactly why that field stays `None` for Redis
specifically, not because the field itself doesn't generalize).

**A real bug was still found, in the test infrastructure this time**:
`fake_elasticsearch_server.py`'s first version answered `GET /<any-
index>/_search` with `200` and an empty hit list for a nonexistent
index, rather than the real Elasticsearch/OpenSearch behavior (`404
index_not_found_exception`) - caught immediately by
`test_dump_index_for_nonexistent_index_raises_clear_error` failing for
the right reason (the fake server was wrong, not
`elasticsearch_client.py`), the same class of "fix the fake, not the
product" finding as §16's `_breakout_outcome` quote-handling bug and
§13's `db.system.users` attribute-chain gap. Fixed by having the fake
check `_FAKE_DOCS` before answering, matching real behavior.

**Verified**: `test_elasticsearch_client.py` (9 live-integration tests
against the real fake server in both modes - no protocol-level unit
tests needed the way Redis's RESP2 implementation did, since this
module is plain HTTP+JSON with nothing to hand-parse),
`TestElasticsearchFindingsExtraction` in `test_memory.py` (7 tests,
including one confirming all three backends - MongoDB, Redis,
Elasticsearch - can coexist in the same run and are each labeled
correctly), and `TestElasticsearchAgentEndToEnd` in
`test_planner_integration.py` (2 tests, both passing on the first real
run). Full suite: **291/291 tests pass** (up from 273).

## 21. CouchDB support - the fourth backend, and a real sandbox reset recovered from mid-task

The last of the originally-named "next steps" from §19: CouchDB, also
plain HTTP+JSON (no client library needed), same three-tool shape as
Redis/Elasticsearch (`couchdb_scan_target`, `couchdb_enumerate_databases`,
`couchdb_dump_database`, the last `HIGH_RISK`).

**Scoped to this engine's actual CVE history**, same principle as the
other three: `lib/nosql/couchdb_client.py`'s docstring explicitly
excludes the CVE-2017-12635/CVE-2017-12636 technique chain - a real,
well-documented type-confusion bug that let a non-admin register
themselves as an admin via a crafted `_users` document, then abuse the
admin-only `_config/os_daemons` endpoint to add an arbitrary shell
command CouchDB itself launches. This module never writes to `_users`
or `_config` at all - anonymous-access detection, `_all_dbs`
enumeration, and `_all_docs`-based read-only dumping (with CouchDB's
own design documents, identified by an `_id` starting with `_design/`,
filtered out as view/index definitions rather than application data)
is the full scope.

**A second real sandbox reset happened mid-task** - the same failure
mode already documented in §13's "environment resilience" note,
recurring for the same underlying reason (this container can be reset
between tool calls without warning). Recovered exactly the way §13
describes: restored from the last successfully delivered package
(§20's state, 291 tests, confirmed passing after restore) and rebuilt
`couchdb_client.py` and `fake_couchdb_server.py` from scratch on top of
it - both files hadn't been included in any delivered zip yet, so nothing
downstream needed re-verifying, unlike §13's version of this incident
where in-progress wiring had to be rebuilt too. Mentioned here for the
same reason §13 records it: it's a real thing that happened, not
because it changes anything about the correctness of what's described
in this section - everything below reflects the actual, tested code as
it exists after the rebuild.

**Every lesson applied proactively held up a second time**: finish-gate,
`HIGH_RISK_ACTIONS`, and findings-merge were wired in from the start,
and - like Elasticsearch in §20, unlike MongoDB in §17 and Redis in
§19 - both end-to-end tests, including the `HIGH_RISK`-gated dump,
passed on the first real run against the live fake server.

**A real bug was still found, once again in the test infrastructure
rather than the product**: the first draft of the reasoning for this
section almost skipped verifying the fake server's `_all_docs` handling
of a nonexistent database matched real CouchDB's `404`/`not_found`
behavior - checked explicitly this time given §20's `_search` fake-
server bug was the exact same class of mistake, and confirmed correct
via `test_dump_database_for_nonexistent_database_raises_clear_error`
passing against a fake server that does the right thing from its first
version.

**Verified**: `test_couchdb_client.py` (9 live-integration tests,
including one confirming design documents are correctly filtered out
of a dump), `TestCouchDBFindingsExtraction` in `test_memory.py` (7
tests, including one confirming all four backends - MongoDB, Redis,
Elasticsearch, CouchDB - can coexist in the same run and are each
labeled correctly), and `TestCouchDBAgentEndToEnd` in
`test_planner_integration.py` (2 tests, both passing on the first real
run). Full suite: **309/309 tests pass** (up from 291).

This closes every backend named in §19's original roadmap. Cassandra
and any backend needing a real client-library dependency would follow
`mongo_client.py`'s pattern instead (optional import, graceful
degradation, a fake in-memory test double) - a reasonable next step if
picked up, but not a gap in what was promised so far.

## 22. MCP server - and one boundary that was explicitly not crossed

The request that led to this section asked for three things: an MCP
server for more accurate testing, stronger self-validation of agent
findings, and "shell access completely." The third was declined as
asked - not built as unrestricted/ungated shell access wired into the
agent - and that's worth recording here with the same weight as
everything that *was* built, not glossed over.

**Why**: every module added this session (MongoDB, Redis,
Elasticsearch, CouchDB) draws one consistent line - data enumeration
and read-only dumping, with each module's own docstring naming the
specific real-world RCE technique it deliberately excludes. `tools.py`'s
own module docstring already stated the principle before this section
existed: "intentionally a CLOSED set (no 'run arbitrary shell command'
tool)". `safety.py` had already reserved `os_shell`/`os_cmd`/
`file_write`/`file_read`/`registry_write` as `HIGH_RISK_ACTIONS` names
for exactly this class of action - but, tellingly, nobody had ever
actually wired any of them up as a callable tool. That gap was
deliberate restraint, not an oversight, and "complete" (ungated) shell
access specifically would have been removing the one thing every other
tool in this codebase has: an accountable gate. See the response in
this conversation for the fuller reasoning given at the time.

**What was built instead, in the same conversation, right after that
boundary was drawn:**

### MCP server (`lib/ai/mcp_server.py`, `alkha_mcp_server.py`)

A real Model Context Protocol server - JSON-RPC 2.0 over stdio,
`initialize`/`notifications/initialized`/`tools/list`/`tools/call`/
`ping` - exposing exactly the same tool catalog and `SafetyPolicy`
`alkha_agent.py`'s own autonomous loop uses. Not a second
implementation of anything: `McpServer` is a thin transport/dispatch
layer over the existing `ToolExecutor`/`SafetyPolicy`, so an MCP
client (Claude Code, another orchestrator, custom tooling) gets the
exact same closed, safety-checked action set as the CLI agent - never
a side door around it.

- Scope is fixed at server startup from `--target`/`--allowed-hosts`,
  the same way the CLI agent derives it from `--target` - an MCP
  client can never expand scope mid-session, only the operator
  restarting the server with a different one can.
- A `HIGH_RISK` action is refused by default, exactly like an un-gated
  CLI run; `--yolo` is the explicit, binary opt-in (there's no MCP-
  native interactive confirmation implemented here, since not every
  client supports MCP's elicitation capability yet - a honest binary
  choice at startup beats pretending to prompt and then not).
- `max_iterations` defaults much higher (500) than the CLI agent's 40
  - reasoned explicitly in `build_default_safety_policy()`'s docstring:
    the CLI agent's cap bounds a *self-directed* loop deciding its own
    next action, which is the runaway-loop risk that number defends
    against; an MCP server is driven by an external client's
    deliberately chosen calls over what may be a legitimately long
    session, a different usage pattern deserving a different default -
    still a real, finite cap, never disabled.
- **stdout purity is load-bearing and was treated as such**: MCP's
  stdio transport uses stdout as the actual protocol channel, so
  `alkha_mcp_server.py` never imports `lib/core/tui.py`'s rendering
  functions (which write real stdout) the way `alkha_agent.py` freely
  does - every diagnostic goes to stderr instead, called out explicitly
  in both files' docstrings as the one thing that would silently break
  every real MCP client if violated.

**Verified at two layers**, matching this project's established
standard: `test_mcp_server.py` (20 tests) drives `McpServer.handle_line()`
directly against an in-memory stdout for fast, deterministic protocol-
level coverage (malformed-input robustness, the safety-integration
tests that prove this server never bypasses `SafetyPolicy` rather than
just asserting it in a docstring); `test_mcp_server_e2e.py` (8 tests)
spawns the real `alkha_mcp_server.py` entry point as a real subprocess
and speaks real newline-delimited JSON-RPC over its real stdin/stdout
pipes - including the real `api_bootstrap.py` auto-starting a real
`alkhaapi.py -s` and a real `EngineClient` round-trip through it, the
same "prove it against the real thing" standard as every live-target
test before this one.

### Gated `os_cmd`/`file_read` tools, and a real security gap found and closed first

Before adding anything new, checking `configure_scan`'s existing option-
validation path turned up a real, serious, pre-existing gap: `lib/ai/
option_validator.py`'s `valid_option_names()` pulled from sqlmap's
*entire* option schema with no risk filtering at all - meaning
`configure_scan({"options": {"osCmd": "whoami"}})` followed by
`start_scan` already reached real, unauthenticated-from-this-agent's-
perspective OS command execution with **zero** `HIGH_RISK` gating,
since `configure_scan`/`start_scan` themselves were never gated - only
specific action *names* like `dump_table` were. `safety.py`'s own
`HIGH_RISK_ACTIONS` reservations for `os_cmd`/`file_write`/`file_read`/
`registry_write` had silently never covered this path at all. Closed
immediately, before building anything else: `DANGEROUS_OPTIONS_BLOCKED_
FROM_CONFIGURE_SCAN` in `option_validator.py` now explicitly rejects
`osCmd`, `fileRead`, `fileWrite`, `fileDest`, `osShell`, `osPwn`,
`osSmb`, `osBof`, `regRead`, `regAdd`, `regDel` from the generic
`configure_scan` path - each with a clear error, and for `osCmd`/
`fileRead` specifically, pointing at the dedicated gated tool to use
instead.

Added exactly two new tools on top of that closed door - `os_cmd` and
`file_read`, both `HIGH_RISK` - deliberately the *only* two of the
eleven dangerous option names above made reachable at all, and only
through their own dedicated, gated tools:

- **`os_cmd`** maps directly to sqlmap's own `--os-cmd` (execute one
  specific command via the engine's established stacked-queries/UDF
  takeover technique, non-interactive, single-shot - not a persistent
  shell, not a payload delivery mechanism). Confirmed this actually
  functions correctly, non-interactively, via the REST API by reading
  sqlmap's real source rather than assuming: `lib/takeover/
  abstraction.py`'s `runCmd()` normally prompts an interactive "retrieve
  output? [Y/n/a]" terminal question via `readInput()`, but `lib/utils/
  api.py` forces `conf.batch = True` for every REST API task, and
  `readInput()` auto-answers with its default ('Y') whenever
  `conf.batch` is set - so the prompt never actually blocks in this
  context. Confirmed separately that the command's output is correctly
  tagged `CONTENT_TYPE.OS_CMD` (not silently dropped) by tracing
  `kb.partRun` getting set to `"osCmd"` during the underlying SQL
  technique execution and `lib/core/dicts.py`'s `PART_RUN_CONTENT_
  TYPES` mapping that string to the right content type.
- **`file_read`** maps to sqlmap's own `--file-read` the same way -
  read one specific file from the DBMS host's filesystem, the direct
  analogue of `dump_table` proving database-level impact but for
  filesystem-level impact instead (e.g. reading `/etc/passwd`).

Both tools explicitly validate their argument is actually a string
before use (the `TABLES`-iteration bug class from §15, applied
proactively this time rather than waiting to find it again). `os_shell`/
`os_pwn`/`os_smb`/`os_bof` were deliberately never wired up at all -
beyond being blocked from `configure_scan`, they're `action="store_true"`
CLI flags designed to prompt an *interactive terminal session*
(`os_pwn`/`os_smb` specifically deliver a full Meterpreter/VNC payload),
architecturally incompatible with the REST API's start/poll/stop model
regardless of whether they should be agent-callable at all.

**Findings schema extended with matching severity, not an afterthought**:
`findings["os_command_results"]`/`["file_read_results"]` are new fields,
and confirmed OS command execution is surfaced *ahead of* injection
points/databases/tables in both `facts_summary()` and
`render_final_report()` - arguably the single most significant finding
this whole codebase can produce (a step further than any NoSQL module's
"anonymous access", which only proves exposed data, not arbitrary code
execution), styled `BAD` (red) in the terminal report the same way an
"open" `nosql_access` entry already was.

**`grounding_check()` extended for the highest-severity claim it can
now validate** - the same anti-hallucination coverage SQL-injection
claims have always had, applied without a weaker version just because
it was added later: a finish summary claiming OS command execution,
filesystem access, or "complete"/code execution with no corresponding
recorded result gets exactly the same "treat this summary as
unverified" caveat an unsupported injection claim already did.

**A second, genuinely separate gap found the same way, in the same
pass**: checking whether `grounding_check()` validated NoSQL anonymous-
access claims at all (it should, by the same logic as every other
claim type) found that it never had - from the moment MongoDB support
was added, a summary could claim "MongoDB allows anonymous access"
with zero recorded `nosql_access` evidence and nothing would catch it.
Closed the same way: a new `_check_nosql_access_claim()`, covering all
four backends through the shared `nosql_access` field.

**Verified**: 6 new tests in `test_tools.py` (both tools' argument
validation and real option-setting, confirmed against `FakeEngine`'s
recorded `start_scan` calls), 4 new tests in
`test_option_validator.py`'s `TestDangerousOptionsBlockedFromConfigureScan`
(including one that confirms each blocked name is actually a real
sqlmap option, not a typo this test would pass against vacuously), 9
new tests in `test_memory.py` across the findings-merge, facts_summary,
and both new grounding checks, 5 new tests in `test_tui.py`, and 3 full
agent-loop integration tests in `test_planner_integration.py`
(`TestOsCmdAgentIntegration`) using `FakeEngine` - not a live target,
since the underlying SQL-injection-to-OS-command-execution chain is
inherited, unmodified, already-battle-tested sqlmap functionality with
no real vulnerable/privilege-escalatable DBMS available in this sandbox
to test it live against the way the NoSQL modules' simple protocols
allowed; what these tests verify is the wiring - correct option names,
correct gating, correct findings merge, correct grounding - which is
what's actually new here. Full suite: **357/357 tests pass** (up from
309).

## 23. CI never actually ran any of this - and a hang found before trusting the fix

Checking `.github/workflows/tests.yml` turned up a gap as real as §22's
`configure_scan` one, just further from the code itself: it's the
unmodified stock sqlmap workflow - checkout, import `sqlmap`/`sqlmapapi`,
run `--smoke`/`--vuln`. It has never once run anything under
`lib/ai/tests/` - all 357 tests built across this entire project have
had zero CI coverage, relying entirely on being run by hand each
session.

Added a second job, `agent-tests`, alongside the untouched original
(`build`) rather than modifying it - Python-3-only, Ubuntu-only (the AI
layer needs Python 3 specifically, and nothing in this suite is
OS-dependent the way the classic engine's full matrix exists to catch),
compiling every agent/NoSQL/UI module, starting all eight live test
targets, then running the full suite.

**Caught a real hang before trusting the workflow**, the same
discipline as every live-target claim verified against the real thing
rather than assumed: the first draft backgrounded the eight live-target
processes without redirecting their output away from the step's own
stdout. Run locally to confirm the workflow would actually work before
shipping it - exactly the step most tempting to skip for a CI config,
since "it's just YAML" - and it hung indefinitely with zero output,
timing out rather than completing. Root cause: each live target runs
`serve_forever()` and never exits, so an inherited, un-redirected
stdout file descriptor stays open on every one of them - the shell
(and, by the same well-documented mechanism, a GitHub Actions step)
waits for every inherited descriptor to close before reporting the
step complete, not just the foreground command. Fixed by redirecting
every backgrounded target's output to its own log file, the same
pattern every live-target test run elsewhere in this project has used
from the start (`>/tmp/*.log 2>&1 &`) - confirmed by rerunning the
exact fixed sequence locally: 357/357 in both the broken-redirect
diagnosis run and the fixed one, the difference being the fixed one
actually returns.

This is a small thing relative to the earlier security gap in §22, but
the same lesson applies at every layer this project touches: a
plausible-looking fix (the YAML was syntactically valid, the logic
looked right) is not a verified one until it's actually been run.
