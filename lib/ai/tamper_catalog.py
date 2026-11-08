#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Exposes sqlmap's 71 tamper scripts (tamper/*.py) to the AI agent as a
lookup catalog. Without this, the agent only knows tamper scripts exist
if it happens to guess a name via configure_scan's free-form options
dict - a whole category of sqlmap's evasion capability (WAF/IDS bypass,
DBMS-specific payload mangling) would otherwise be invisible to it.
Read-only, stdlib `ast` parsing of the shipped scripts - no code from
tamper/ is imported or executed by this module.
"""

import ast
import os

from lib.core.enums import DBMS

_TAMPER_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "tamper"))

_cache = None
_DBMS_CONSTANT_NAMES = [name for name in dir(DBMS) if not name.startswith("_")]


def _first_docstring_line(func_node):
    doc = ast.get_docstring(func_node) or ""
    for line in doc.strip().splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def _referenced_dbms_constants(func_node):
    """
    Scans a dependencies() function body for DBMS.<CONSTANT> attribute
    references (the pattern every DBMS-restricted tamper script uses to
    warn when run against the wrong backend - e.g. tamper/space2mysqlblank.py
    references DBMS.MYSQL). Returns the list of actual DBMS display
    strings ("MySQL", "Microsoft SQL Server", ...) referenced, or an
    empty list for scripts with no DBMS restriction (dependencies() is a
    no-op `pass`).
    """
    found = []

    for node in ast.walk(func_node):
        if isinstance(node, ast.Attribute) and node.attr in _DBMS_CONSTANT_NAMES:
            if isinstance(node.value, ast.Name) and node.value.id == "DBMS":
                value = getattr(DBMS, node.attr)
                if value not in found:
                    found.append(value)

    return found


def load_catalog():
    """
    Returns a list of {"name": ..., "description": ..., "dbms": [...]}
    dicts, one per tamper/*.py script. "dbms" is the list of DBMS
    display strings the script's own dependencies() function declares
    it's restricted to (empty = works generically / no declared
    restriction). Cached after first call (the tamper/ directory doesn't
    change during a run).
    """
    global _cache

    if _cache is not None:
        return _cache

    catalog = []

    if not os.path.isdir(_TAMPER_DIR):
        _cache = catalog
        return catalog

    for filename in sorted(os.listdir(_TAMPER_DIR)):
        if not filename.endswith(".py") or filename == "__init__.py":
            continue

        path = os.path.join(_TAMPER_DIR, filename)

        try:
            with open(path, "r") as f:
                tree = ast.parse(f.read(), filename=filename)
        except (SyntaxError, OSError):
            continue

        tamper_func = None
        deps_func = None

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "tamper" and tamper_func is None:
                tamper_func = node
            if isinstance(node, ast.FunctionDef) and node.name == "dependencies" and deps_func is None:
                deps_func = node

        if tamper_func is None:
            continue

        name = filename[:-3]
        description = _first_docstring_line(tamper_func) or "(no description available)"
        dbms_restriction = _referenced_dbms_constants(deps_func) if deps_func is not None else []
        catalog.append({"name": name, "description": description, "dbms": dbms_restriction})

    _cache = catalog
    return catalog


def render_catalog_for_prompt(query=None):
    """
    query: optional case-insensitive substring filter (e.g. "mysql",
    "space", "waf") so the agent can narrow a 70-entry list instead of
    always paying the full token cost.
    """
    catalog = load_catalog()

    if query:
        # `query` is untrusted model-supplied input for list_tamper_scripts - a
        # non-string value (a hallucinated number/list/dict argument) shouldn't
        # crash the whole run; treat it as its string form rather than failing.
        q = str(query).lower()
        catalog = [c for c in catalog if q in c["name"].lower() or q in c["description"].lower()
                   or any(q in d.lower() for d in c["dbms"])]

    if not catalog:
        return "(no matching tamper scripts found)"

    return "\n".join("- %s: %s%s" % (
        c["name"], c["description"],
        " [restricted to: %s]" % ", ".join(c["dbms"]) if c["dbms"] else ""
    ) for c in catalog)


def recommend_for_dbms(dbms_name):
    """
    Returns tamper script names best suited once a specific DBMS is
    known: scripts explicitly restricted to that DBMS first (an exact
    structural signal parsed from each script's own dependencies()
    function - not a guess), then generic scripts with no declared
    restriction as a fallback. dbms_name may be a raw findings value
    like "MySQL >= 5.0.12", matched by substring against the known DBMS
    display names.
    """
    if not dbms_name:
        return {"specific": [], "generic": [c["name"] for c in load_catalog() if not c["dbms"]]}

    # dbms_name is untrusted model-supplied input - a non-string value
    # (hallucinated number/list/dict argument) has no meaningful substring
    # match, so fall back to the same "no DBMS known" result rather than
    # crashing on .lower().
    if not isinstance(dbms_name, str):
        return {"specific": [], "generic": [c["name"] for c in load_catalog() if not c["dbms"]]}

    lowered = dbms_name.lower()
    specific = []
    generic = []

    for entry in load_catalog():
        if any(d.lower() in lowered or lowered in d.lower() for d in entry["dbms"]):
            specific.append(entry["name"])
        elif not entry["dbms"]:
            generic.append(entry["name"])

    # Whitespace-obfuscation scripts (space2*) defeat basic WAF/signature
    # matching far more often than narrow rewrites like commalesslimit -
    # surface them first so the top-3 suggestion below is actually the
    # most broadly useful pick, not just alphabetically first.
    specific.sort(key=lambda n: (not n.startswith("space2"), n))

    return {"specific": specific, "generic": generic}
