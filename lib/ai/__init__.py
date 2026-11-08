#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

lib.ai
------
Agentic AI layer for sqlmap. Entirely additive: it drives the existing
sqlmap REST-JSON API (lib.utils.api / alkhaapi.py) as a client, and does
not modify the core detection/exploitation engine in any way.

Modules:
    ollama_client  - minimal HTTP client for a local Ollama server
    engine_client   - typed wrapper around sqlmap's REST-JSON API
    tools           - the action schema exposed to the LLM ("function calling")
    safety          - scope/iteration/rate guardrails for autonomous runs
    memory          - running transcript + structured findings store
    planner         - the plan -> act -> observe agent loop
"""
