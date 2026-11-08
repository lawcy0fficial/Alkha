# Alkha ![](https://i.imgur.com/fe85aVR.png)

[![License: GPLv2-or-later / GPLv3](https://img.shields.io/badge/license-GPLv2--or--later%20%2F%20GPLv3-red.svg)](LICENSE)

Alkha is an AI-augmented SQL & NoSQL injection and database takeover
framework - a fork of the open source penetration testing tool sqlmap
(https://sqlmap.org), with an added Ollama-driven autonomous agent, an
MCP server exposing the same tool catalog to any MCP client, an opt-in
modern CLI, non-SQL datastore support (MongoDB injection/access from
NoSQLMap, https://github.com/codingo/NoSQLMap, plus Redis,
Elasticsearch/OpenSearch, and CouchDB anonymous-access detection and
dumping built directly into this fork), gated single-shot OS-command-
execution and filesystem-read tools (`os_cmd`/`file_read`, mapped to
sqlmap's own `--os-cmd`/`--file-read`, HIGH_RISK-confirmation-gated the
same way database dumping is - see
[doc/ALKHA.md](doc/ALKHA.md) §13/§19/§20/§21/§22), and several security
hardening fixes. The underlying detection/exploitation engine - the
powerful detection engine, the niche pentester features, the broad
switch set for database fingerprinting, data fetching, filesystem
access, and out-of-band OS command execution - is 100% original,
unmodified sqlmap.

> **Quick links:** run the classic engine directly with `python alkha.py -u <url> [options]`
> (same options as sqlmap always had), or drive the autonomous agent with `python alkha_agent.py --target <url> --goal "..."`
> (it auto-starts the REST API for you - see [doc/AGENT.md](doc/AGENT.md) if you'd rather run it yourself).
> See [doc/ALKHA.md](doc/ALKHA.md) for everything added on top of stock sqlmap and what's been
> verified, [doc/AGENT.md](doc/AGENT.md) for the agent's architecture and usage, and
> [doc/LICENSING.md](doc/LICENSING.md) for a consolidated compliance guide if you're planning to
> redistribute, rebrand further, or commercialize this project.

Installation
----

This repository *is* Alkha - there's no separate install step beyond having
Python and (optionally) Ollama available:

    python3 alkha.py --version

Alkha works with **Python 3** (the AI agent layer specifically; the classic
sqlmap engine it's built on additionally supports Python 2.7, unchanged from
upstream). No third-party Python packages are required for the classic
engine, the agent's SQL-injection path, or the Redis/Elasticsearch/
CouchDB support (all implemented directly against their native
wire/HTTP protocols, no client library needed) -
everything under `thirdparty/` is bundled (see `doc/THIRD-PARTY.md`).
The MongoDB direct-connection tools (`lib/nosql/mongo_client.py`)
additionally need `pymongo` (`pip install pymongo`) if you intend to use
them; everything else works
without it.

To use the autonomous agent (`alkha_agent.py`), you'll also need
[Ollama](https://ollama.com) installed and a model pulled:

    ollama pull llama3.1

The agent auto-starts sqlmap's own REST API for you - see
[doc/AGENT.md](doc/AGENT.md) for the full setup and every available flag.

If what you actually want is unmodified upstream sqlmap rather than this
fork, get it directly from https://sqlmap.org or
https://github.com/sqlmapproject/sqlmap.

Usage
----

Classic engine (identical switches to upstream sqlmap - nothing here
changed by this fork):

    python alkha.py -h    # basic options
    python alkha.py -hh   # every option

    python alkha.py -u "http://example.com/page.php?id=1" --batch

Autonomous agent (see [doc/AGENT.md](doc/AGENT.md) for every flag,
including how to point it at a remote Ollama host or a pre-started REST
API):

    python alkha_agent.py --target "http://example.com/page.php?id=1" \
        --goal "Determine if the 'id' parameter is SQL injectable" \
        --model llama3.1

MCP server (same tool catalog and safety policy, exposed to any MCP
client - Claude Code, another orchestrator - over the Model Context
Protocol instead of this project's own agent loop; see
[doc/AGENT.md](doc/AGENT.md) for every flag):

    python alkha_mcp_server.py --target "http://example.com/page.php?id=1"

Since the classic engine's options are entirely unchanged from upstream,
sqlmap's own [user's manual](https://github.com/sqlmapproject/sqlmap/wiki/Usage)
and [sample run](https://asciinema.org/a/46601) are accurate references for
every `alkha.py` switch - just substitute `alkha.py` for `sqlmap.py` in any
command you see there.

Screenshots
----

![Screenshot](https://raw.github.com/wiki/sqlmapproject/sqlmap/images/sqlmap_screenshot.png)

The screenshot above is the classic engine's output, shared unchanged with
upstream sqlmap (more in the [collection of screenshots](https://github.com/sqlmapproject/sqlmap/wiki/Screenshots)
on sqlmap's own wiki). For what the agent's terminal UI and the modern CLI
banner actually look like, see [doc/AGENT.md](doc/AGENT.md) and
[doc/ALKHA.md](doc/ALKHA.md) §16.

Links
----

The classic detection/exploitation engine is 100% unmodified upstream
sqlmap, so these are sqlmap's own links, not a separate Alkha project
presence - useful for engine documentation, issues in the shared codebase,
and attribution:

* Homepage: https://sqlmap.org
* Issue tracker: https://github.com/sqlmapproject/sqlmap/issues
* User's manual: https://github.com/sqlmapproject/sqlmap/wiki
* Frequently Asked Questions (FAQ): https://github.com/sqlmapproject/sqlmap/wiki/FAQ
* X: [@sqlmap](https://x.com/sqlmap)
* Demos: [https://www.youtube.com/user/inquisb/videos](https://www.youtube.com/user/inquisb/videos)

For anything specific to what this fork added - the agent, the NoSQL
support, the modern CLI, security hardening - see
[doc/ALKHA.md](doc/ALKHA.md), [doc/AGENT.md](doc/AGENT.md), and
[doc/LICENSING.md](doc/LICENSING.md) in this repository instead; none of
that is on sqlmap's own site or issue tracker.

Translations
----

The translations below are of **upstream sqlmap's own README**, maintained
by the sqlmap project - they describe the original tool, not this fork's
additions (the agent, NoSQL support, etc., which only exist here). Useful
if you want the classic engine's own documentation in your language; not a
translation of anything in this repository specifically.

* [Arabic](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-ar-AR.md)
* [Bengali](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-bn-BD.md)
* [Bulgarian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-bg-BG.md)
* [Chinese](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-zh-CN.md)
* [Croatian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-hr-HR.md)
* [Dutch](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-nl-NL.md)
* [French](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-fr-FR.md)
* [Georgian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-ka-GE.md)
* [German](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-de-DE.md)
* [Greek](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-gr-GR.md)
* [Hindi](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-in-HI.md)
* [Indonesian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-id-ID.md)
* [Italian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-it-IT.md)
* [Japanese](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-ja-JP.md)
* [Korean](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-ko-KR.md)
* [Kurdish (Central)](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-ckb-KU.md)
* [Persian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-fa-IR.md)
* [Polish](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-pl-PL.md)
* [Portuguese](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-pt-BR.md)
* [Russian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-ru-RU.md)
* [Serbian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-rs-RS.md)
* [Slovak](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-sk-SK.md)
* [Spanish](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-es-MX.md)
* [Turkish](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-tr-TR.md)
* [Ukrainian](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-uk-UA.md)
* [Vietnamese](https://github.com/sqlmapproject/sqlmap/blob/master/doc/translations/README-vi-VN.md)
