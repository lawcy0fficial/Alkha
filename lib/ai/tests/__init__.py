#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

lib.ai.tests
------------
Unit/integration tests for the agentic AI layer (lib/ai/). Uses stdlib
unittest, deliberately separate from sqlmap's own doctest-based test
convention (lib/core/testing.py) since this package's testing needs
(mock Ollama/engine responses, multi-step planner loops) don't fit a
docstring-embedded doctest well.

Run all of them from the repository root with:

    python -m unittest discover -s lib/ai/tests -p "test_*.py" -v

Each file here formalizes an ad-hoc verification script written and run
by hand during development - see doc/ALKHA.md for the narrative
history of what each one caught.
"""
