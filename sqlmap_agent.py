#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Compatibility shim: the real entry point is now alkha_agent.py (see
doc/NEXTGEN.md for the rebrand writeup). Nothing internal hardcodes
this filename the way lib/utils/api.py hardcodes "sqlmap.py", but this
follows the same direct-vs-import-safe pattern as sqlmap.py/
sqlmapapi.py for consistency, in case anything ever imports from it.
Prefer running alkha_agent.py directly.
"""

import os
import runpy

_ALKHA_AGENT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alkha_agent.py")

if __name__ == "__main__":
    runpy.run_path(_ALKHA_AGENT_PATH, run_name="__main__")
else:
    import importlib.util
    _spec = importlib.util.spec_from_file_location("alkha_agent", _ALKHA_AGENT_PATH)
    _alkha_agent_module = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_alkha_agent_module)
    globals().update({k: v for k, v in vars(_alkha_agent_module).items() if not k.startswith("_")})
