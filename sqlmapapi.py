#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Compatibility shim: the real entry point is now alkhaapi.py (see
doc/NEXTGEN.md for the rebrand writeup). Prefer running alkhaapi.py
directly.

Nothing in this codebase currently imports "sqlmapapi" the way
lib/utils/api.py hardcodes "sqlmap.py" or alkhaapi.py does
"from sqlmap import modulePath" - so the unconditional
run_name="__main__" below has never actually misfired here. It still
follows the same direct-vs-import-safe guard as sqlmap.py's and
sqlmap_agent.py's shims, purely for consistency and so a future
"from sqlmapapi import ..." doesn't quietly re-run the whole REST API
server as a side effect of the import, the same bug that was caught
and fixed in sqlmap.py's shim (see that file's docstring).
"""

import os
import runpy

_ALKHAAPI_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alkhaapi.py")

if __name__ == "__main__":
    runpy.run_path(_ALKHAAPI_PATH, run_name="__main__")
else:
    import importlib.util
    _spec = importlib.util.spec_from_file_location("alkhaapi", _ALKHAAPI_PATH)
    _alkhaapi_module = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_alkhaapi_module)
    globals().update({k: v for k, v in vars(_alkhaapi_module).items() if not k.startswith("_")})
