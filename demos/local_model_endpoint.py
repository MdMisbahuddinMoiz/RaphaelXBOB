"""Local OpenAI-compatible model endpoint for the offline demo.

WHAT THIS IS
------------
A real HTTP server speaking the OpenAI ``POST /v1/chat/completions``
wire protocol, plus a deterministic policy that reads the request and
emits the same structured proposal contract a hosted model would. It
exists so the vertical slice can be demonstrated end to end on a
machine with no vendor credential.

WHAT THIS IS NOT
----------------
It is NOT a language model and it is NOT a Raphael component. It has no
reasoning; its replies come from a fixed rule table keyed on the
observations Raphael hands it. It is labelled `local-deterministic` in
every response so no log, transcript, or evidence record can imply a
hosted model ran. Point the console at a real endpoint to exercise a
real model — the adapter path is identical either way.

Governance is unaffected: whatever replies this server emits still
arrive as a proposal and still cross Runtime -> Broker -> Policy. A
malicious or broken endpoint cannot widen authority; the worst it can
do is propose an action Policy denies.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

MODEL_ID = "local-deterministic"
DISCOVERY_SKILL = "network-service-discovery"


def _summary(context: Dict[str, Any]) -> Dict[str, Any]:
    """The `ModelContext.summary()` the adapter serialized.

    `build_request_body` nests the whole summary under the `mission`
    key (alongside `available_skills`), so unwrap it once here rather
    than in every rule.
    """
    inner = context.get("mission")
    return inner if isinstance(inner, dict) else context


def _observation_ports(context: Dict[str, Any]) -> List[int]:
    """Every open port the governed loop has observed so far."""
    summary = _summary(context)
    ports: set = set()
    for observation in summary.get("observations") or ():
        for entry in observation.get("open_services") or ():
            if entry.get("port") is not None:
                ports.add(int(entry["port"]))
        for port in observation.get("ports_open") or ():
            ports.add(int(port))
    return sorted(ports)


def _target_host(context: Dict[str, Any]) -> str:
    """The host the mission scope names, else the last proposed target."""
    summary = _summary(context)
    scope = summary.get("scope") or ""
    host = scope.split(",")[0].split("/")[0].strip()
    if host:
        return host
    for turn in reversed(summary.get("recent_turns") or ()):
        if turn.get("target"):
            return str(turn["target"])
    return "127.0.0.1"


def decide(context: Dict[str, Any]) -> Dict[str, Any]:
    """The deterministic proposal rule table.

    Nothing observed yet  -> propose one bounded governed discovery pass.
    Ports observed        -> propose a governed HTTP request against the
                             first open port the operator authorized.
    Service already read  -> the assessment is done; declare `done`.

    The rule table is intentionally trivial: the point of the demo is
    the GOVERNED LOOP, not the intelligence of the model.
    """
    summary = _summary(context)
    host = _target_host(context)
    known = _observation_ports(context)
    turns = summary.get("recent_turns") or ()
    already_fetched = any(
        turn.get("capability") == "network_http_request" for turn in turns)
    if not known:
        return {
            "intent": "act",
            "skill": DISCOVERY_SKILL,
            "target": host,
            "purpose": (f"no services observed for {host} yet; run one "
                        "governed discovery pass (ports=8080) to learn "
                        "what is listening"),
        }
    port = known[0]
    if already_fetched:
        return {
            "intent": "done",
        }
    return {
        "intent": "act",
        "skill": "network-http-request",
        "target": f"http://{host}:{port}/",
        "purpose": (f"discovery reported port {port} open on {host}; "
                    "fetch its root to observe the service"),
    }


class _Handler(BaseHTTPRequestHandler):
    server_version = "RaphaelLocalModel/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        """Silence per-request stderr noise; the demo prints its own."""

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        if self.path.rstrip("/").endswith("/models"):
            self._json(200, {"object": "list", "data": [
                {"id": MODEL_ID, "object": "model", "owned_by": "local"},
            ]})
            return
        self._json(404, {"error": {"message": "not found"}})

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        if not self.path.rstrip("/").endswith("/chat/completions"):
            self._json(404, {"error": {"message": "not found"}})
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._json(400, {"error": {"message": "invalid JSON"}})
            return
        reply = decide(_extract_context(payload))
        self._json(200, {
            "id": "chatcmpl-local",
            "object": "chat.completion",
            "model": MODEL_ID,
            "provider": MODEL_ID,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": json.dumps(reply, sort_keys=True),
                },
                "finish_reason": "stop",
            }],
        })

    def _json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _extract_context(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Recover the harness context the provider adapter serialized.

    The adapter sends `{"mission": ..., "available_skills": ...}` as
    the single user message. This is a demo-only reader; the governed
    contract it consumes is `ModelContext.summary()`.
    """
    for message in reversed(payload.get("messages") or ()):
        if message.get("role") != "user":
            continue
        try:
            return json.loads(message.get("content") or "{}")
        except ValueError:
            return {}
    return {}


class LocalModelEndpoint:
    """Context manager running the endpoint on a background thread."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._server = ThreadingHTTPServer((host, port), _Handler)
        self._server.daemon_threads = True
        self._thread: Optional[threading.Thread] = None

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/v1"

    def __enter__(self) -> "LocalModelEndpoint":
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)


def probe(base_url: str, timeout: float = 5.0) -> Tuple[bool, str]:
    """Check the endpoint answers a chat completion. (ok, model id)."""
    import urllib.error
    import urllib.request
    body = json.dumps({
        "model": MODEL_ID,
        "messages": [{"role": "user", "content": json.dumps({
            "mission": {"scope": "127.0.0.1"}, "observations": [],
            "recent_turns": [],
        })}],
    }).encode("utf-8")
    request = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions", data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return True, json.loads(response.read()).get("model", "")
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return False, type(exc).__name__


__all__ = ["DISCOVERY_SKILL", "LocalModelEndpoint", "MODEL_ID", "decide",
           "probe"]
