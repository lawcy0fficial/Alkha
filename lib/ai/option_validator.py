#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Grounds the agent's configure_scan calls against sqlmap's real option
list (lib/core/optiondict.py), instead of letting a hallucinated or
mistyped option name (e.g. "riskLevel" instead of "risk", "dbName"
instead of "db") sail through configure_scan and either get silently
ignored by the REST API or produce a confusing downstream failure many
turns later. This is read-only introspection of optiondict.py's
structure - it does not import or run any scanning logic.
"""

import difflib

from lib.core.optiondict import optDict

_VALID_OPTIONS = None


def valid_option_names():
    global _VALID_OPTIONS

    if _VALID_OPTIONS is None:
        names = set()
        for family, options in optDict.items():
            names.update(options.keys())
        _VALID_OPTIONS = names

    return _VALID_OPTIONS


DANGEROUS_OPTIONS_BLOCKED_FROM_CONFIGURE_SCAN = {
    # Every one of these is a real sqlmap option (present in optDict, so
    # valid_option_names() would otherwise accept it) that reaches
    # operating-system or filesystem access on the compromised DBMS host -
    # exactly the class of action lib/ai/safety.py's HIGH_RISK_ACTIONS
    # already reserves names for (os_shell, os_cmd, file_write, file_read,
    # registry_write). That reservation only ever gated actions by NAME
    # at the tool level - it never accounted for configure_scan's generic
    # option pass-through being a side door to the exact same
    # capabilities with NO gating at all, since configure_scan/start_scan
    # themselves were never HIGH_RISK. Found the same way every other gap
    # in this codebase was: checking rather than assuming, this time
    # while building the intentionally-gated os_cmd/file_read tools this
    # blocklist exists to make the ONLY way to reach these specific two.
    #   - fileWrite/fileDest: writing to the target's filesystem is a
    #     step further than every other module built this session (which
    #     all stop at read-only enumeration/dumping) - out of scope here
    #     the same way MongoDB/Redis/Elasticsearch/CouchDB support all
    #     stop short of any write/execute primitive.
    #   - osShell/osPwn/osSmb/osBof: all `action="store_true"` CLI flags
    #     designed to prompt an interactive terminal session (a shell, an
    #     OOB Meterpreter/VNC payload) - architecturally incompatible
    #     with the REST API's start/poll/stop model even before getting
    #     to whether they should be agent-callable at all; osPwn/osSmb
    #     specifically deliver a full remote-access payload (Meterpreter/
    #     VNC), a fundamentally larger capability than "run one command
    #     and read its output."
    #   - regRead/regAdd/regDel: Windows registry read/write - regAdd/
    #     regDel are persistent-write primitives with no read-only-
    #     enumeration analogue; regRead is blocked alongside them for
    #     consistency and because it has no dedicated gated tool built
    #     for it (unlike fileRead/osCmd below).
    # fileRead and osCmd are still reachable - through the dedicated,
    # explicitly HIGH_RISK-gated file_read/os_cmd tools in tools.py,
    # never through this generic path.
    "fileWrite", "fileDest", "osShell", "osPwn", "osSmb", "osBof",
    "regRead", "regAdd", "regDel", "fileRead", "osCmd",
}


def validate_options(options):
    """
    options: dict of option-name -> value, as the agent would pass to
    configure_scan.

    Returns (clean_options, errors). clean_options contains only the
    keys that matched a real sqlmap option; errors is a list of
    human-readable strings (one per bad key) with a close-match
    suggestion when one exists, meant to be fed straight back to the
    model as an observation so it can self-correct next turn instead of
    silently losing the option or failing several turns later.
    """
    valid = valid_option_names()
    clean = {}
    errors = []

    if options is not None and not isinstance(options, dict):
        return clean, ["configure_scan's 'options' argument was %s, not an object/dict - "
                        "no options applied. This is almost always malformed model output." % (
                            type(options).__name__)]

    for key, value in (options or {}).items():
        if key in DANGEROUS_OPTIONS_BLOCKED_FROM_CONFIGURE_SCAN:
            if key in ("fileRead", "osCmd"):
                errors.append("'%s' can't be set via configure_scan - use the dedicated %s tool "
                               "instead, which is explicitly gated as high-risk." % (
                                   key, "file_read" if key == "fileRead" else "os_cmd"))
            else:
                errors.append("'%s' can't be set via configure_scan - operating-system/filesystem/"
                               "registry write and interactive-shell options are not available to "
                               "this agent." % key)
            continue

        if key in valid:
            clean[key] = value
            continue

        suggestion = difflib.get_close_matches(key, valid, n=1, cutoff=0.6)
        if suggestion:
            errors.append("Unknown option '%s' - did you mean '%s'? Dropped from this call." % (key, suggestion[0]))
        else:
            errors.append("Unknown option '%s' - not a real sqlmap option. Dropped from this call." % key)

    return clean, errors
