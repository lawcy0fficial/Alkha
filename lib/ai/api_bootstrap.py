#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Auto-launches sqlmap's own REST-JSON API (alkhaapi.py -s) as a managed
subprocess when alkha_agent.py can't reach one already running, so
`python alkha_agent.py --target ... --goal ...` works standalone in
one terminal instead of requiring a separate `python alkhaapi.py -s`
to be started by hand first (see doc/AGENT.md's "deliberately not
done yet" list - this closes that item).

Deliberately additive and narrow:
- If a server is already reachable at the given host/port, this does
  nothing and returns None - an operator who already has
  `alkhaapi.py -s` running (e.g. pointed at a non-default port, or
  shared across multiple agent runs) is left alone.
- Only ever spawns a server on a loopback address. Auto-starting a
  process on a remote host makes no sense (this process has no way to
  execute anything there) - a non-loopback --api-host with nothing
  listening is a configuration error, not something to paper over, so
  it's reported clearly instead of silently doing nothing useful.
- The caller (alkha_agent.py) owns the lifecycle: it gets back the
  Popen handle (or None), and is responsible for calling shutdown()
  when the run ends - this module never installs its own atexit/signal
  handlers, so it stays a plain, synchronously-testable function
  rather than something with hidden global state.
"""

import os
import socket
import subprocess
import sys
import time

# Ollama/sqlmap agent runs are expected to be local-operator tooling;
# these are the only hostnames auto-start will ever spawn a process
# for. Widen only if there's ever a legitimate case for reaching an
# API on a machine this process could also spawn a process on (e.g.
# containers sharing a network namespace) - not the common case today.
LOOPBACK_HOSTS = frozenset(["127.0.0.1", "localhost", "::1"])


class ApiBootstrapError(Exception):
    pass


def is_port_open(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def find_alkhaapi_path():
    # lib/ai/api_bootstrap.py -> lib/ai -> lib -> repository root
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(root, "alkhaapi.py")


def ensure_server_running(host, port, username=None, password=None, insecure=False,
                           allow_dangerous_options=False, startup_timeout=20.0,
                           poll_interval=0.3, popen_fn=subprocess.Popen,
                           port_check_fn=is_port_open, alkhaapi_path=None, on_event=None):
    """
    Returns a Popen handle for a newly-spawned alkhaapi.py -s process,
    or None if a server was already reachable (nothing for the caller
    to manage/shut down in that case). Raises ApiBootstrapError if a
    server needs to be started but can't be (non-loopback host with
    nothing listening, alkhaapi.py missing, the process exits before
    coming up, or it never opens the port within startup_timeout).

    popen_fn / port_check_fn / alkhaapi_path are injectable so this can
    be exercised in tests without spawning a real subprocess or process
    listening on a real socket - see lib/ai/tests/test_api_bootstrap.py.
    """
    def emit(message):
        if on_event:
            on_event(message)

    if port_check_fn(host, port, timeout=1.0):
        emit("REST API already reachable at %s:%d - using it." % (host, port))
        return None

    if host not in LOOPBACK_HOSTS:
        raise ApiBootstrapError(
            "No REST API reachable at %s:%d, and it is not a loopback address, so it can't be "
            "auto-started from here. Either start it yourself on that host with "
            "'python alkhaapi.py -s -H %s -p %d', or point --api-host at a loopback "
            "address if you meant to run it locally." % (host, port, host, port)
        )

    path = alkhaapi_path or find_alkhaapi_path()
    if not os.path.isfile(path):
        raise ApiBootstrapError("Cannot auto-start the REST API - alkhaapi.py not found at %s" % path)

    cmd = [sys.executable, path, "-s", "-H", host, "-p", str(port)]
    if username and password:
        cmd += ["--username", username, "--password", password]
    if insecure:
        cmd.append("--insecure-api")
    if allow_dangerous_options:
        cmd.append("--allow-dangerous-options")

    emit("No REST API reachable at %s:%d - auto-starting one..." % (host, port))

    proc = popen_fn(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                     cwd=os.path.dirname(path) or None, universal_newlines=True)

    deadline = time.time() + startup_timeout

    while time.time() < deadline:
        if proc.poll() is not None:
            output = _drain(proc)
            raise ApiBootstrapError(
                "Auto-started REST API process exited early (exit code %s) before becoming "
                "reachable. Its output:\n%s" % (proc.returncode, output[-2000:])
            )

        if port_check_fn(host, port, timeout=1.0):
            emit("REST API up at %s:%d (pid %s)." % (host, port, getattr(proc, "pid", "?")))
            return proc

        time.sleep(poll_interval)

    shutdown(proc)
    raise ApiBootstrapError(
        "Timed out after %.0fs waiting for the auto-started REST API to become reachable "
        "at %s:%d." % (startup_timeout, host, port)
    )


def shutdown(proc, timeout=5.0):
    """Stops a process previously returned by ensure_server_running(). No-op for None or an
    already-exited process - safe to call unconditionally from a caller's cleanup path."""
    if proc is None or proc.poll() is not None:
        return

    proc.terminate()

    try:
        proc.wait(timeout=timeout)
    except Exception:
        proc.kill()


def _drain(proc):
    try:
        return proc.stdout.read() or ""
    except Exception:
        return ""
