#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Cross-run memory for the agent. lib/ai/memory.py's AgentMemory is
per-run (gone when the process exits); this persists a small amount of
distilled knowledge per authorized host across separate invocations of
alkha_agent.py, so a second run against a host you've already tested
doesn't start from zero - it can skip straight to a DBMS/tamper
combination that worked before instead of re-discovering it by trial
and error.

Deliberately minimal: only what's needed to bias future planning
(confirmed DBMS, confirmed injection points, tamper scripts that were
in effect during a confirmed success). Never stores response bodies,
dumped data, or credentials - this is a hint file, not a findings
archive (JSON reports from --json-report already serve that purpose).

Stored at ~/.sqlmap/agent_knowledge.json - deliberately independent of
sqlmap's own paths.SQLMAP_HOME_PATH (lib/core/common.py) so this module
stays usable standalone from alkha_agent.py without requiring the full
sqlmap.py init chain (dirtyPatches/resolveCrossReferences/setPaths) to
have run first.
"""

import json
import os
import time

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

_DEFAULT_PATH = os.path.join(os.path.expanduser("~"), ".alkha", "agent_knowledge.json")


class KnowledgeBase(object):
    def __init__(self, path=None):
        self.path = path or _DEFAULT_PATH
        self._data = None

    def _load(self):
        if self._data is not None:
            return self._data

        if os.path.isfile(self.path):
            try:
                with open(self.path, "r") as f:
                    self._data = json.load(f)
            except (ValueError, OSError):
                self._data = {}
        else:
            self._data = {}

        return self._data

    def _save(self):
        data = self._load()
        directory = os.path.dirname(self.path)

        try:
            if directory and not os.path.isdir(directory):
                os.makedirs(directory)

            tmp_path = self.path + ".tmp"
            with open(tmp_path, "w") as f:
                json.dump(data, f, indent=2)

            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, self.path)
        except OSError:
            pass  # best-effort; a failed write shouldn't break a scan

    @staticmethod
    def _host_key(target):
        parsed = urlparse(target if "://" in target else "//" + target)
        return (parsed.hostname or target).lower()

    def lookup(self, target):
        """Returns the stored record dict for this host's hostname, or None."""
        return self._load().get(self._host_key(target))

    def record_success(self, target, dbms=None, injection_points=None, tamper=None):
        """
        Called when a run ends with grounded evidence (real injection
        points recorded, not just a model's claim - see
        AgentMemory.grounding_check). Merges into any existing record
        for this host rather than overwriting it, since different runs
        may confirm different parameters/tamper combinations over time.
        """
        key = self._host_key(target)
        data = self._load()
        record = data.get(key, {"dbms": None, "injection_points": [], "tamper": [], "last_seen": None})

        if dbms:
            record["dbms"] = dbms

        for point in (injection_points or []):
            if point not in record["injection_points"]:
                record["injection_points"].append(point)

        for t in (tamper or []):
            if t not in record["tamper"]:
                record["tamper"].append(t)

        record["last_seen"] = time.strftime("%Y-%m-%d %H:%M:%S")

        data[key] = record
        self._data = data
        self._save()

    def render_for_prompt(self, target):
        record = self.lookup(target)

        if not record:
            return None

        lines = ["Prior successful run(s) against this host (from an earlier agent session):"]
        if record.get("dbms"):
            lines.append("  DBMS: %s" % record["dbms"])
        if record.get("injection_points"):
            lines.append("  Known injection points: %s" % record["injection_points"])
        if record.get("tamper"):
            # defensive: a hand-edited knowledge file, or a record written by
            # an older version of this code before the tamper-value-type fix
            # in planner.py, could contain non-string entries - coerce rather
            # than let ", ".join() crash on a stale on-disk file.
            tamper_names = [t if isinstance(t, str) else str(t) for t in record["tamper"]]
            lines.append("  Tamper scripts that were in effect on a successful run: %s" % ", ".join(tamper_names))
        lines.append("  (last confirmed: %s) - verify these still hold, don't assume unchanged." % record.get("last_seen"))

        return "\n".join(lines)
