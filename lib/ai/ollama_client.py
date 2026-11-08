#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

Thin client for a local Ollama server (https://ollama.com). Uses only the
standard library so it has no impact on sqlmap's existing dependency set.
"""

import json
import re

try:
    from urllib.request import Request, urlopen
    from urllib.error import URLError, HTTPError
except ImportError:  # Python 2 fallback (sqlmap still supports it in places)
    from urllib2 import Request, urlopen, URLError, HTTPError


class OllamaError(Exception):
    pass


class OllamaClient(object):
    """
    Talks to a local (or remote) Ollama daemon's /api/chat endpoint.
    No API key, no external service, no network egress beyond the
    user-configured Ollama host - keeps the whole "brain" on the
    operator's own machine, which matters for engagement confidentiality.
    """

    def __init__(self, host="http://127.0.0.1:11434", model="llama3.1", timeout=120, temperature=0.2):
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.temperature = temperature

    def _post(self, path, payload):
        data = json.dumps(payload).encode("utf-8")
        req = Request("%s%s" % (self.host, path), data=data, headers={"Content-Type": "application/json"})

        try:
            resp = urlopen(req, timeout=self.timeout)
            raw = resp.read().decode("utf-8", "replace")
        except HTTPError as ex:
            raise OllamaError("Ollama HTTP error %s: %s" % (ex.code, ex.read().decode("utf-8", "replace")))
        except URLError as ex:
            raise OllamaError(
                "Could not reach Ollama at %s (%s). Is 'ollama serve' running and is the model pulled "
                "('ollama pull %s')?" % (self.host, ex.reason, self.model)
            )

        return raw

    def chat(self, messages, tools=None, json_mode=False):
        """
        messages: list of {"role": "system"|"user"|"assistant", "content": str}
        tools:    optional OpenAI-style tool schema (Ollama >= 0.3 supports function calling
                  for tool-capable models; for models without native tool-calling we fall back
                  to strict-JSON prompting, see planner.py)
        Returns the raw assistant message dict from Ollama.
        """
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": self.temperature},
        }

        if tools:
            payload["tools"] = tools

        if json_mode:
            payload["format"] = "json"

        raw = self._post("/api/chat", payload)

        try:
            parsed = json.loads(raw)
        except ValueError:
            raise OllamaError("Non-JSON response from Ollama: %s" % raw[:300])

        if not isinstance(parsed, dict):
            # Ollama's /api/chat always responds with a JSON object in
            # practice, but "error" in parsed below would otherwise raise
            # TypeError for a bare number/null and AttributeError for a
            # list/string once we reach parsed.get(...) - a proxy in front
            # of Ollama mangling the response, or a future API change,
            # should surface as a clear OllamaError here instead (same
            # fix already applied to EngineClient._request() for the
            # identical class of gap on the sqlmap REST API side).
            raise OllamaError("Unexpected JSON shape from Ollama (expected an object, got %s): %s" % (
                type(parsed).__name__, raw[:300]))

        if "error" in parsed:
            raise OllamaError(parsed["error"])

        return parsed.get("message", {})

    def list_models(self):
        raw = self._post_get("/api/tags")
        try:
            parsed = json.loads(raw)
        except ValueError:
            return []

        if not isinstance(parsed, dict):
            return []

        models = parsed.get("models")
        if not isinstance(models, list):
            return []

        return [m.get("name") for m in models if isinstance(m, dict)]

    def _post_get(self, path):
        req = Request("%s%s" % (self.host, path))
        try:
            resp = urlopen(req, timeout=self.timeout)
            return resp.read().decode("utf-8", "replace")
        except (HTTPError, URLError) as ex:
            raise OllamaError("Could not reach Ollama at %s (%s)" % (self.host, ex))


def extract_json_block(text):
    """
    Best-effort extraction of a JSON object from a model response that may
    include stray prose/markdown fences around the JSON (common with models
    that don't support native structured output / tool calling).
    """
    if not text or not isinstance(text, str):
        # `text` traces back to reply.get("content", "") in planner.py's
        # _parse_reply() - reply is Ollama's own response dict, so a
        # non-string "content" value (a malformed Ollama response, or a
        # proxy in front of it mangling the field) previously crashed
        # re.search with TypeError here instead of being treated as
        # "nothing to extract," the same way an empty/missing content
        # already is.
        return None

    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    else:
        brace = re.search(r"\{.*\}", text, re.DOTALL)
        if brace:
            text = brace.group(0)

    try:
        return json.loads(text)
    except ValueError:
        return None
