#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

A local model asked to "try harder" tends to either repeat the same
configuration with cosmetic changes, or jump straight to the most
aggressive settings without reason to believe they're needed. Neither
is what an experienced pentester actually does - they escalate in a
deliberate order: broaden coverage, add evasion only once a WAF is
suspected, then isolate techniques one at a time to see which specific
detection signature is being blocked.

This module encodes that order as data, not prompting. Each rung is a
plain options dict for configure_scan/start_scan - nothing here talks
to the network or the engine directly, so it stays trivially testable.
Escalation only ever *broadens* level/risk/technique coverage or adds
evasion (tamper/random-agent/delay); it never touches scope, and it
never reaches for os-shell/file-write/etc - those remain governed
entirely by lib/ai/safety.py regardless of ladder position.
"""

_TECHNIQUE_LETTERS = ("B", "T", "E", "U", "S", "Q")  # boolean, time (slow, so try after boolean), error, union, stacked, inline

LADDER = [
    {
        "label": "baseline",
        "why": "Conservative defaults - cheapest test, correct call for the first attempt.",
        "options": {"level": 1, "risk": 1},
    },
    {
        "label": "broaden coverage",
        "why": "No injection at baseline. Broaden parameter/payload coverage before assuming evasion is needed.",
        "options": {"level": 3, "risk": 2},
    },
    {
        "label": "maximum coverage, all techniques",
        "why": "Still nothing. Push to the highest level/risk and explicitly enable every technique.",
        "options": {"level": 5, "risk": 3, "technique": "".join(_TECHNIQUE_LETTERS)},
    },
    {
        "label": "waf evasion, light",
        "why": "Maximum coverage still found nothing - now a WAF/IPS/input-filter is the more likely explanation. "
               "Add basic space/comment obfuscation and a random User-Agent.",
        "options": {"level": 5, "risk": 3, "technique": "".join(_TECHNIQUE_LETTERS),
                    "tamper": "space2comment,charunicodeencode", "randomAgent": True},
    },
    {
        "label": "waf evasion, aggressive",
        "why": "Light evasion didn't help - stack more tamper transforms and slow down to dodge rate-based blocking.",
        "options": {"level": 5, "risk": 3, "technique": "".join(_TECHNIQUE_LETTERS),
                    "tamper": "space2comment,between,randomcase,charunicodeencode",
                    "randomAgent": True, "delay": 1},
    },
    {
        "label": "waf evasion, transport-level",
        "why": "Payload-level obfuscation didn't help - some WAFs inspect the reassembled request body/query "
               "differently than the raw wire format. Try chunked transfer-encoding and HTTP parameter "
               "pollution, which change how the request is framed rather than what the payload looks like.",
        "options": {"level": 5, "risk": 3, "technique": "".join(_TECHNIQUE_LETTERS),
                    "tamper": "space2comment,between,randomcase,charunicodeencode",
                    "randomAgent": True, "chunked": True, "hpp": True},
    },
]


def technique_isolation_rungs():
    """
    Appended after the main ladder on request (see EscalationLadder):
    one rung per individual technique letter, at max level/risk with the
    aggressive tamper set still applied. Isolating techniques matters
    because a WAF/filter often blocks one signature (e.g. UNION SELECT)
    while leaving another (e.g. boolean-blind) completely untouched -
    testing all techniques combined can still fail if the combined
    request pattern itself gets flagged.
    """
    rungs = []
    for letter in _TECHNIQUE_LETTERS:
        rungs.append({
            "label": "isolate technique %s" % letter,
            "why": "Testing technique '%s' alone, in case the combined multi-technique request pattern "
                   "itself was what triggered filtering." % letter,
            "options": {"level": 5, "risk": 3, "technique": letter,
                        "tamper": "space2comment,between,randomcase,charunicodeencode",
                        "randomAgent": True},
        })
    return rungs


class EscalationLadder(object):
    """
    Stateful position tracker, one per agent run (owned by ToolExecutor).
    Call next_rung() to get the next config to try; returns None once
    every rung (including per-technique isolation) has been exhausted.
    """

    def __init__(self):
        self._rungs = list(LADDER) + technique_isolation_rungs()
        self._position = -1

    def next_rung(self):
        self._position += 1
        if self._position >= len(self._rungs):
            return None
        return self._rungs[self._position]

    def exhausted(self):
        return self._position >= len(self._rungs) - 1

    def current_label(self):
        if 0 <= self._position < len(self._rungs):
            return self._rungs[self._position]["label"]
        return None
