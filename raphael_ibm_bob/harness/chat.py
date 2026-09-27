"""raphael_ibm_bob.harness.chat — operator chat state for the agent runtime.

The chat is an INTERACTION LAYER over the governed agent loop, never a
second execution path. A chat message is context: it is appended to the
mission conversation, folded into the `ModelContext` the model already
receives, and the model still emits an ordinary `ActionRequest` that
travels Runtime -> Broker -> Policy exactly as it does without chat.

Nothing in this module executes a capability, opens a socket, or imports
the Broker. It is a bounded, append-only transcript plus a stop flag.

Layout
------
One JSONL file per mission under ``<runs_root>/chat/<mission>.jsonl``.
Append-only, like the evidence ledger it points at: a message is never
rewritten, so the transcript cannot be used to launder a conclusion that
the ledger does not support.

Credential discipline
---------------------
Operator text is free-form, so it is the one place a secret can arrive
by accident (an operator pasting a key into the box). `redact()` runs on
every write and replaces credential-shaped material with a marker. The
API key field on the provider form is unaffected: it never reaches a
chat message at all.
"""
from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

#: Roles a message can carry.
ROLE_OPERATOR = "operator"
ROLE_AGENT = "agent"
ROLE_SYSTEM = "system"
ROLES = frozenset({ROLE_OPERATOR, ROLE_AGENT, ROLE_SYSTEM})

#: Distinct visual/structural message types. The UI renders each
#: differently; they are never collapsed into one generic bubble.
TYPE_USER = "user"
TYPE_AGENT = "agent"
TYPE_ACTION = "action"
TYPE_POLICY = "policy"
TYPE_EXECUTION = "execution"
TYPE_EVIDENCE = "evidence"
TYPE_MODEL_ERROR = "model_error"
TYPE_SYSTEM = "system"
MESSAGE_TYPES = frozenset({
    TYPE_USER, TYPE_AGENT, TYPE_ACTION, TYPE_POLICY, TYPE_EXECUTION,
    TYPE_EVIDENCE, TYPE_MODEL_ERROR, TYPE_SYSTEM,
})

#: Mission run states surfaced in the header.
STATE_IDLE = "idle"
STATE_RUNNING = "running"
STATE_STOPPED = "stopped"
STATE_COMPLETE = "complete"
STATE_REFUSED = "refused"
STATE_ERROR = "error"

#: Bound on a single stored message. Operator text is free-form; an
#: unbounded paste must not be able to bloat the transcript.
MAX_CONTENT_CHARS = 4000
#: Bound on how many messages one read returns.
MAX_READ_MESSAGES = 500
#: Marker written in place of credential-shaped material.
REDACTED_MARKER = "[redacted]"

# Credential-shaped material an operator could paste into the chat box.
# Deliberately narrow: it must catch real secrets without mangling
# ordinary prose about, say, a "token" in an application.
_PATTERNS: Tuple[Tuple[re.Pattern, str], ...] = (
    (re.compile(r"sk-[A-Za-z0-9_\-]{16,}"), "api key"),
    (re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?"
                r"-----END[A-Z ]*PRIVATE KEY-----"), "private key"),
    (re.compile(r"(?i)\b(?:api[_-]?key|password|passwd|secret|token)\b"
                r"\s*[:=]\s*\S+"), "credential assignment"),
    (re.compile(r"(?i)\bAuthorization\s*:\s*\S+"), "authorization header"),
)

_lock = threading.RLock()


def redact(text: Any) -> str:
    """Replace credential-shaped material with a marker.

    Applied to every stored message. The transcript is rendered back to
    the operator and travels to the provider, so a pasted key must never
    survive into either.
    """
    value = "" if text is None else str(text)
    for pattern, _label in _PATTERNS:
        value = pattern.sub(REDACTED_MARKER, value)
    return value


def has_credential_shape(text: Any) -> bool:
    """True when `text` contains credential-shaped material."""
    value = "" if text is None else str(text)
    return any(pattern.search(value) for pattern, _ in _PATTERNS)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_mission_id(mission_id: Any) -> str:
    """Filesystem-safe mission id. Rejects traversal outright."""
    raw = str(mission_id or "").strip()
    if not raw:
        raise ValueError("mission_id is required")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,96}", raw):
        raise ValueError("mission_id contains unsupported characters")
    if raw in (".", ".."):
        raise ValueError("mission_id is not a usable name")
    return raw


@dataclass(frozen=True)
class ChatMessage:
    """One entry in the mission transcript."""

    id: str
    ts: str
    role: str
    message_type: str
    content: str
    run_id: str = ""
    turn_index: Optional[int] = None
    action_id: str = ""
    evidence_ids: Tuple[str, ...] = ()
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "ts": self.ts,
            "role": self.role,
            "message_type": self.message_type,
            "content": self.content,
            "run_id": self.run_id,
            "turn_index": self.turn_index,
            "action_id": self.action_id,
            "evidence_ids": list(self.evidence_ids),
            "detail": dict(self.detail),
        }

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "ChatMessage":
        return cls(
            id=str(raw.get("id", "")),
            ts=str(raw.get("ts", "")),
            role=str(raw.get("role", ROLE_SYSTEM)),
            message_type=str(raw.get("message_type", TYPE_SYSTEM)),
            content=str(raw.get("content", "")),
            run_id=str(raw.get("run_id", "")),
            turn_index=raw.get("turn_index"),
            action_id=str(raw.get("action_id", "")),
            evidence_ids=tuple(raw.get("evidence_ids") or ()),
            detail=dict(raw.get("detail") or {}),
        )


def operator_message(mission_id: str, content: Any, *,
                     run_id: str = "") -> ChatMessage:
    """Build (and redact) an operator message."""
    text = str(content or "").strip()
    if not text:
        raise ValueError("message is required")
    return ChatMessage(
        id=_message_id(TYPE_USER),
        ts=_utcnow(),
        role=ROLE_OPERATOR,
        message_type=TYPE_USER,
        content=redact(text)[:MAX_CONTENT_CHARS],
        run_id=run_id,
    )


def agent_message(content: Any, *, message_type: str = TYPE_AGENT,
                  run_id: str = "", turn_index: Optional[int] = None,
                  evidence_ids: Iterable[str] = (),
                  action_id: str = "",
                  detail: Optional[Dict[str, Any]] = None) -> ChatMessage:
    """Build a system-authored message (agent, policy, evidence, ...)."""
    if message_type not in MESSAGE_TYPES:
        raise ValueError(f"unknown message_type: {message_type}")
    return ChatMessage(
        id=_message_id(message_type),
        ts=_utcnow(),
        role=ROLE_AGENT if message_type != TYPE_SYSTEM else ROLE_SYSTEM,
        message_type=message_type,
        content=redact(content)[:MAX_CONTENT_CHARS],
        run_id=run_id,
        turn_index=turn_index,
        action_id=action_id,
        evidence_ids=tuple(str(e) for e in evidence_ids),
        detail=dict(detail or {}),
    )


def system_event(content: Any, **kwargs: Any) -> ChatMessage:
    return agent_message(content, message_type=TYPE_SYSTEM, **kwargs)


_COUNTER_LOCK = threading.Lock()
_COUNTER = 0


def _message_id(prefix: str) -> str:
    global _COUNTER
    with _COUNTER_LOCK:
        _COUNTER += 1
        serial = _COUNTER
    return f"C-{prefix[:4].upper()}-{serial:06d}"


class ChatLog:
    """Append-only transcript + stop flag for one mission."""

    def __init__(self, runs_root: Path, mission_id: str) -> None:
        self._mission_id = _safe_mission_id(mission_id)
        root = Path(runs_root)
        self._dir = root / "chat"
        self._path = self._dir / f"{self._mission_id}.jsonl"
        self._stop_path = self._dir / f"{self._mission_id}.stopped"

    @property
    def mission_id(self) -> str:
        return self._mission_id

    @property
    def path(self) -> Path:
        return self._path

    # -- writes ---------------------------------------------------------
    def append(self, message: ChatMessage) -> ChatMessage:
        """Append one message. Never rewrites an existing line."""
        with _lock:
            self._dir.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(message.to_dict(), sort_keys=True))
                handle.write("\n")
        return message

    def extend(self, messages: Iterable[ChatMessage]) -> List[ChatMessage]:
        return [self.append(m) for m in messages]

    def append_operator(self, content: Any, *, run_id: str = "") -> ChatMessage:
        return self.append(operator_message(self._mission_id, content,
                                            run_id=run_id))

    def append_event(self, content: Any, *, message_type: str,
                     run_id: str = "", turn_index: Optional[int] = None,
                     evidence_ids: Iterable[str] = (),
                     action_id: str = "",
                     detail: Optional[Dict[str, Any]] = None) -> ChatMessage:
        return self.append(agent_message(
            content, message_type=message_type, run_id=run_id,
            turn_index=turn_index, evidence_ids=evidence_ids,
            action_id=action_id, detail=detail))

    def clear(self) -> None:
        with _lock:
            for path in (self._path, self._stop_path):
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass

    # -- reads ----------------------------------------------------------
    def messages(self, limit: int = MAX_READ_MESSAGES) -> List[ChatMessage]:
        """Read the transcript tail, oldest first. Unparseable lines are
        skipped rather than failing the whole read."""
        with _lock:
            if not self._path.exists():
                return []
            try:
                lines = self._path.read_text(encoding="utf-8").splitlines()
            except OSError:
                return []
        out: List[ChatMessage] = []
        for line in lines[-max(1, min(limit, MAX_READ_MESSAGES)):]:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(ChatMessage.from_dict(json.loads(line)))
            except (ValueError, TypeError):
                continue
        return out

    def to_list(self, limit: int = MAX_READ_MESSAGES) -> List[Dict[str, Any]]:
        return [m.to_dict() for m in self.messages(limit)]

    # -- stop flag ------------------------------------------------------
    def is_stopped(self) -> bool:
        return self._stop_path.exists()

    def stop(self) -> Dict[str, Any]:
        """Record a real stop. Subsequent turns are refused server-side."""
        with _lock:
            self._dir.mkdir(parents=True, exist_ok=True)
            self._stop_path.write_text(_utcnow() + "\n", encoding="utf-8")
        return {"stopped": True, "mission_id": self._mission_id,
                "at": _utcnow()}

    def resume(self) -> Dict[str, Any]:
        """Clear the stop flag so the operator may continue."""
        with _lock:
            try:
                os.unlink(self._stop_path)
            except FileNotFoundError:
                pass
        return {"stopped": False, "mission_id": self._mission_id}


def chat_log(runs_root: Path, mission_id: str) -> ChatLog:
    return ChatLog(runs_root, mission_id)


__all__ = [
    "ChatLog",
    "ChatMessage",
    "MESSAGE_TYPES",
    "MAX_CONTENT_CHARS",
    "MAX_READ_MESSAGES",
    "REDACTED_MARKER",
    "ROLES",
    "ROLE_AGENT",
    "ROLE_OPERATOR",
    "ROLE_SYSTEM",
    "STATE_COMPLETE",
    "STATE_ERROR",
    "STATE_IDLE",
    "STATE_REFUSED",
    "STATE_RUNNING",
    "STATE_STOPPED",
    "TYPE_ACTION",
    "TYPE_AGENT",
    "TYPE_EVIDENCE",
    "TYPE_EXECUTION",
    "TYPE_MODEL_ERROR",
    "TYPE_POLICY",
    "TYPE_SYSTEM",
    "TYPE_USER",
    "agent_message",
    "chat_log",
    "has_credential_shape",
    "operator_message",
    "redact",
    "system_event",
]
