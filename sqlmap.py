#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Compatibility shim: the real entry point is now alkha.py (see
doc/NEXTGEN.md for the rebrand writeup). This file exists so that
code which hardcodes the "sqlmap.py" filename - notably
lib/utils/api.py's Task.engine_start(), which spawns
"python sqlmap.py --api -c <config>" as the actual scan-engine
subprocess for every REST API scan, lib/core/testing.py's
--smoke-test/--vuln-test runner, and alkhaapi.py's own
"from sqlmap import modulePath" - keeps working unmodified, since
patching every such hardcoded reference throughout the codebase would
be significant, avoidable risk to functionality (the REST API is what
this project's entire agentic layer, lib/ai/, depends on) for a
purely cosmetic gain. Prefer running alkha.py directly.

IMPORTANT: must behave correctly both when run directly (spawn
alkha.py's real __main__ logic) and when merely imported as a module
(alkhaapi.py does "from sqlmap import modulePath" - this must NOT
re-execute alkha.py's scan logic as a side effect of that import, the
same way the original unmodified sqlmap.py never executed its own
main() just from being imported, thanks to its own
"if __name__ == '__main__':" guard). An earlier version of this shim
used runpy.run_path(..., run_name="__main__") unconditionally, which
defeated that guard regardless of how the shim itself was invoked -
caught by testing alkhaapi.py -s and finding it printed a scan banner
and exited instead of starting the REST server, not assumed correct
because the shim "worked" for direct sqlmap.py invocation alone.
"""

import os
import runpy

_ALKHA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alkha.py")

if __name__ == "__main__":
    runpy.run_path(_ALKHA_PATH, run_name="__main__")
else:
    import importlib.util
    _spec = importlib.util.spec_from_file_location("alkha", _ALKHA_PATH)
    _alkha_module = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_alkha_module)
    globals().update({k: v for k, v in vars(_alkha_module).items() if not k.startswith("_")})
