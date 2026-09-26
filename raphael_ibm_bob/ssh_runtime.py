"""raphael_ibm_bob.ssh_runtime — governed SSH session boundary.

The ONLY network-I/O boundary for ``Capability.NETWORK_SSH_SESSION``.
Modelled on the established ``telnet_runtime`` discipline, with one
important difference: the model never receives a session. It proposes
ONE ``ActionRequest``; Policy decides; the Broker stamps it; this
mediator opens a session, executes exactly ONE already-approved command,
and closes. There is no interactive handle to leak.

Session model (never a shell handed to the model)::

    OPEN SESSION -> EXECUTE ONE APPROVED COMMAND -> STRUCTURED RESULT -> CLOSE

Governance properties, all enforced here and in ``policy``:

* The host must match the mission-bound TargetProfile EXACTLY. No
  wildcards, no CIDR expansion, no userinfo, no secondary destination.
* The port must appear in the profile's authorized port list, and the
  protocol must be explicitly authorized (``ssh``).
* Credentials are referenced by id and resolved from a process-local
  ``CredentialVault`` at execution time. Plaintext never enters the
  mission, the spec, the ledger, the timeline, evidence, errors, logs, or
  ``repr()``; evidence carries a fingerprint only.
* Commands pass a reusable command-policy layer. Shell chaining and
  control constructs are refused, and ``sh -c`` / ``bash -c`` style
  indirection can never be authorized implicitly.
* Every invocation is bound to (run_id, invocation_id) and replay-guarded.
* One request executes at most ONE command. A multi-command request is a
  DENY, not a silent chain.
* Bounded everywhere: command timeout, stdout limit, stderr limit, max
  command length, max commands per session.

Transport is paramiko (a real SSH implementation, already present), kept
strictly behind this module and injectable so tests never need a socket.
Nothing here is machine-specific: no exploit, no target knowledge.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from raphael_ibm_bob.contracts import (
    ActionRequest,
    Capability,
    Mission,
)
from raphael_ibm_bob.credential_provenance import CredentialVault
from raphael_ibm_bob.network_scope import (
    NetworkScopeError,
    parse_ssh_target,
)
from raphael_ibm_bob.network_runtime import _decision_allows
from raphael_ibm_bob.target_profile import TargetProfile

SSH_CAPABILITY_ID = "network_ssh_session"
PROVIDER_UNTRUSTED = "provider_untrusted"

#: The only transport protocol this boundary speaks.
SSH_PROTOCOL = "ssh"
SUPPORTED_SSH_PROTOCOLS: Tuple[str, ...] = (SSH_PROTOCOL,)

#: Safety bounds. Every one is configurable DOWNWARD by the mission
#: spec; none can be raised past the hard ceiling here.
DEFAULT_COMMAND_TIMEOUT = 15.0
MAX_COMMAND_TIMEOUT = 120.0
DEFAULT_STDOUT_LIMIT = 8192
DEFAULT_STDERR_LIMIT = 4096
MAX_STDOUT_LIMIT = 65536
MAX_STDERR_LIMIT = 16384
DEFAULT_MAX_COMMAND_CHARS = 256
MAX_COMMAND_CHARS_CEILING = 1024
DEFAULT_MAX_COMMANDS_PER_SESSION = 1
MAX_COMMANDS_PER_SESSION_CEILING = 16

#: Shell metacharacters. Any of these in a command is a DENY unless the
#: policy is explicitly configured to require authorization for them.
SHELL_METACHARACTERS: Tuple[str, ...] = (
    ";", "|", "&", ">", "<", "`", "$", "(", ")", "{", "}", "[", "]",
    "*", "?", "!", "~", "'", '"', "\\", "\n", "\r", "\t", "#",
)

#: Interpreters and tools that would turn an approved command into an
#: arbitrary one. Denied by default and NOT waivable through the
#: allow-list — indirection is the whole attack.
FORBIDDEN_BINARIES: Tuple[str, ...] = (
    "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "ash", "busybox",
    "sudo", "su", "doas", "pkexec", "env", "eval", "exec", "command",
    "xargs", "find", "nc", "ncat", "netcat", "socat", "telnet",
    "curl", "wget", "python", "python2", "python3", "perl", "ruby",
    "php", "node", "ssh", "scp", "sftp", "rsync", "chmod", "chown",
    "chgrp", "rm", "mv", "cp", "dd", "mkfifo", "kill", "killall",
    "reboot", "shutdown", "halt", "poweroff", "mount", "umount",
    "insmod", "rmmod", "modprobe", "crontab", "at", "nohup", "setsid",
)

#: The specific indirection shapes that are always refused, named
#: separately so the denial reason is legible in evidence.
_INDIRECTION_RE = re.compile(
    r"(?:^|/)(?:sh|bash|zsh|dash|ksh|csh|tcsh|ash)\s+-c\b", re.IGNORECASE)

#: Commands that are neither safe nor universally sensible, so the
#: policy layer demands an explicit mission authorization for them.
_SENSITIVE_PREFIXES: Tuple[str, ...] = ("cat", "head", "tail", "id", "whoami")


class SshSessionState(str, Enum):
    """Closed outcome of one governed SSH session."""
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    REFUSED = "refused"
    UNAVAILABLE = "unavailable"
    DENIED = "denied"
    AUTH_FAILED = "auth_failed"


class CommandDecision(str, Enum):
    """Result of the reusable command-policy layer.

    ``REQUIRE_AUTHORIZATION`` is distinct from ``DENY``: the command is
    not inherently forbidden, it simply is not authorized for THIS
    mission and must be declared by the operator before it can run.
    """
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_AUTHORIZATION = "require_authorization"


class SshCommandPolicy:
    """Reusable, fail-closed command policy for governed remote sessions.

    Deliberately generic — it knows nothing about any particular target,
    distribution, or challenge. The operator supplies an allow-list; this
    layer decides, and the decision is what the ledger records.

    Two rejection classes are NOT waivable by the allow-list:

    * shell metacharacters and indirection (``sh -c ...``), and
    * the forbidden-interpreter list.

    Everything else that is simply not authorized returns
    ``REQUIRE_AUTHORIZATION`` so the operator gets an actionable reason
    rather than a generic "denied".
    """

    def __init__(self, *, allowlist: Sequence[str] = (),
                 sensitive_prefixes: Sequence[str] = _SENSITIVE_PREFIXES,
                 max_command_chars: int = DEFAULT_MAX_COMMAND_CHARS,
                 forbid_metacharacters: bool = True) -> None:
        if max_command_chars <= 0:
            raise ValueError("max_command_chars must be positive")
        self._allowlist = tuple(allowlist)
        self._sensitive = tuple(sensitive_prefixes)
        self._max_chars = int(max_command_chars)
        self._forbid_meta = bool(forbid_metacharacters)

    @property
    def allowlist(self) -> Tuple[str, ...]:
        return self._allowlist

    @property
    def max_command_chars(self) -> int:
        return self._max_chars

    def evaluate(self, command: object,
                 extra_authorized: Sequence[str] = ()) -> Tuple[
                     CommandDecision, str]:
        """Return ``(decision, reason)``. Never raises."""
        if not isinstance(command, str) or not command.strip():
            return CommandDecision.DENY, "command-empty"
        if command != command.strip():
            return CommandDecision.DENY, "command-whitespace"
        if "\x00" in command:
            return CommandDecision.DENY, "command-nul-byte"
        if len(command) > self._max_chars:
            return CommandDecision.DENY, "command-too-long"
        # Indirection is checked BEFORE anything else: a command whose
        # first token is an interpreter with -c can execute anything, so
        # no allow-list entry may ever rescue it.
        if _INDIRECTION_RE.search(command):
            return CommandDecision.DENY, "command-indirection-rejected"
        if self._forbid_meta:
            for token in SHELL_METACHARACTERS:
                if token in command:
                    return CommandDecision.DENY, (
                        f"command-metacharacter:{token!r}")
        parts = command.split()
        binary = parts[0].rsplit("/", 1)[-1] if parts else ""
        if binary.lower() in FORBIDDEN_BINARIES:
            return CommandDecision.DENY, f"command-forbidden-binary:{binary}"
        allowed = self._allowlist + tuple(extra_authorized)
        if command in allowed:
            # An allow-listed command that also touches a sensitive
            # prefix still requires the operator to have declared it —
            # which `extra_authorized` is. Recorded for evidence clarity.
            return CommandDecision.ALLOW, "ok"
        if any(binary.lower() == prefix for prefix in self._sensitive):
            return CommandDecision.REQUIRE_AUTHORIZATION, (
                f"command-requires-authorization:{binary}")
        return CommandDecision.REQUIRE_AUTHORIZATION, "command-not-authorized"


def command_from_purpose(purpose: object) -> str:
    """Extract the proposed command from an ActionRequest purpose.

    Two wire forms, both unambiguous:

    * ``cmd="<command>"`` — the whole quoted string is the command.
      This is the form to use for any command with an argument, and it
      leaves the rest of the purpose free for the rationale.
    * ``cmd=<token>`` — a bare single token (no spaces).

    Anything else yields ``""`` and the caller DENIES: a command is
    never inferred from prose, which would let a model smuggle one
    past review. Quoted text is still untrusted input — the policy
    layer runs over the extracted command either way.
    """
    text = purpose if isinstance(purpose, str) else ""
    match = re.search(r'cmd="([^"]*)"', text)
    if match:
        return match.group(1).strip()
    match = re.search(r"cmd='([^']*)'", text)
    if match:
        return match.group(1).strip()
    match = re.search(r"cmd=(\S+)", text)
    return match.group(1) if match else ""


def _clause_tail(purpose: object) -> str:
    """The text following the `cmd=` clause, whichever form was used."""
    text = purpose if isinstance(purpose, str) else ""
    quoted = re.search(r'cmd="([^"]*)"', text) or \
        re.search(r"cmd='([^']*)'", text)
    if quoted:
        return text[quoted.end():]
    bare = re.search(r"cmd=(\S+)", text)
    return text[bare.end():] if bare else ""


def chaining_detected(purpose: object) -> Optional[str]:
    """Return the chaining token if a ``cmd=`` clause is followed by one.

    `command_from_purpose` reads ONE clause, so "cmd=ls && cat flag" would
    otherwise be truncated to `ls` and the second command silently
    DISCARDED. That is safe but dishonest: the model would believe a
    chain ran. This makes the continuation explicit so the caller can
    DENY the whole request instead. Chaining INSIDE the quoted command
    is caught by the policy layer, which sees the full text.
    """
    tail = _clause_tail(purpose).lstrip()
    for token in SHELL_METACHARACTERS:
        if tail.startswith(token):
            return token
    return None


@dataclass(frozen=True)
class SshSessionSpec:
    """Explicit, structured SSH session schema (mission-declared).

    Holds a CREDENTIAL ID, never a password. The plaintext is resolved
    from the vault at execution time and never enters this object, so
    the spec is safe to log, serialize, and put in evidence.
    """
    target: str
    port: int
    username: str
    credential_id: str
    policy: SshCommandPolicy
    authorized_commands: Tuple[str, ...] = ()
    max_commands: int = DEFAULT_MAX_COMMANDS_PER_SESSION
    command_timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT
    stdout_limit: int = DEFAULT_STDOUT_LIMIT
    stderr_limit: int = DEFAULT_STDERR_LIMIT
    host_key_policy: str = "strict"
    purpose: str = "ssh-session"

    def sensitive_dict(self) -> Dict[str, Any]:
        """Evidence-safe view. Contains no plaintext, ever."""
        return {
            "target": self.target,
            "port": self.port,
            "protocol": SSH_PROTOCOL,
            "username": self.username,
            "credential_id": self.credential_id or "",
            "credential_present": bool(self.credential_id),
            "authorized_commands": list(self.authorized_commands),
            "max_commands": self.max_commands,
            "command_timeout_seconds": self.command_timeout_seconds,
            "stdout_limit": self.stdout_limit,
            "stderr_limit": self.stderr_limit,
            "host_key_policy": self.host_key_policy,
        }


@dataclass(frozen=True)
class SshSessionResult:
    """Closed, bounded outcome of one governed SSH session."""
    state: SshSessionState
    invocation_id: str
    session_id: str
    mission_id: str
    target_id: str
    host: str
    port: int
    protocol: str
    username: str
    command: str = ""
    command_decision: str = "not-attempted"
    command_reason: str = ""
    run_id: str = ""
    authenticated: bool = False
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    stdout_sha256: Optional[str] = None
    stderr_sha256: Optional[str] = None
    commands_executed: int = 0
    error: str = ""

    @property
    def success(self) -> bool:
        return self.state is SshSessionState.SUCCESS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state.value,
            "invocation_id": self.invocation_id,
            "session_id": self.session_id,
            "mission_id": self.mission_id,
            "target_id": self.target_id,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "username": self.username,
            "run_id": self.run_id,
            "command": self.command,
            "command_decision": self.command_decision,
            "command_reason": self.command_reason,
            "authenticated": self.authenticated,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "commands_executed": self.commands_executed,
            "error": self.error[:512],
            PROVIDER_UNTRUSTED: True,
        }


# ---------------------------------------------------------------------------
# transport (paramiko, isolated behind the mediator)
# ---------------------------------------------------------------------------

def _clip(text: Any, limit: int) -> Tuple[str, bool]:
    """Clip output to `limit` characters; report whether it was cut."""
    value = text if isinstance(text, str) else ("" if text is None
                                                else str(text))
    if limit < 0 or len(value) <= limit:
        return value, False
    return value[:limit], True


def _digest(text: str) -> Optional[str]:
    return hashlib.sha256(text.encode("utf-8")).hexdigest() if text else None


def paramiko_ssh_session(
    *,
    host: str,
    port: int,
    username: str,
    password: Optional[str],
    command: str,
    timeout: float,
    stdout_limit: int,
    stderr_limit: int,
    host_key_policy: str = "strict",
) -> Dict[str, Any]:
    """Open one SSH session, run ONE command, close. Returns a dict.

    The ONLY function in Raphael that speaks the SSH wire protocol. It
    holds no policy: the caller has already decided, and this function
    simply refuses to run when the decision was not ALLOW.

    ``host_key_policy='strict'`` refuses an unknown host key. That is
    the fail-closed default: an unverified host is never silently
    trusted. Callers must pass an explicit, pre-provisioned policy
    object to change that, and the choice is recorded in evidence.
    """
    try:
        import paramiko  # imported lazily: transport detail, not policy
    except ImportError as exc:  # pragma: no cover - environment guard
        return {"state": SshSessionState.UNAVAILABLE.value,
                "error": f"ssh-transport-unavailable:{type(exc).__name__}"}

    client = paramiko.SSHClient()
    if host_key_policy == "strict":
        # paramiko >= 4 does NOT auto-load system known_hosts. Without
        # this the RejectPolicy below can never succeed and every strict
        # session dies with "not found in known_hosts".
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    elif host_key_policy == "auto-add":
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        return {"state": SshSessionState.DENIED.value,
                "error": f"host-key-policy-unsupported:{host_key_policy}"}

    session_id = ""
    try:
        client.connect(
            hostname=host, port=port, username=username,
            # `password or None` would turn an empty credential into
            # None, and paramiko then offers NO auth method at all, so a
            # server that permits an empty/none password login becomes
            # unreachable. Pass the value through: None means "try
            # empty", and the server accepts or refuses on its own terms.
            password="" if password is None else password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        session_id = _digest(f"{host}:{port}:{time.time()}")[:16] or ""
        transport = client.get_transport()
        if transport is not None and session_id:
            # Deterministic per-session id for evidence correlation.
            session_id = hashlib.sha256(
                session_id.encode("utf-8")).hexdigest()[:16]
        _stdin, stdout, stderr = client.exec_command(
            command=command, timeout=timeout)
        code = stdout.channel.recv_exit_status()
        out, out_cut = _clip(_drain(stdout), stdout_limit)
        err, err_cut = _clip(_drain(stderr), stderr_limit)
        return {
            "state": SshSessionState.SUCCESS.value,
            "session_id": session_id,
            "exit_code": code,
            "stdout": out,
            "stderr": err,
            "stdout_truncated": out_cut,
            "stderr_truncated": err_cut,
            "authenticated": True,
            "error": "",
        }
    except paramiko.AuthenticationException:
        return {"state": SshSessionState.AUTH_FAILED.value,
                "error": "ssh-auth-failed", "authenticated": False}
    except paramiko.SSHException as exc:
        text = str(exc).lower()
        if "timed out" in text or "timeout" in text:
            return {"state": SshSessionState.TIMEOUT.value,
                    "error": "ssh-timeout"}
        return {"state": SshSessionState.REFUSED.value,
                "error": f"ssh-error:{type(exc).__name__}"}
    except (OSError, ValueError) as exc:
        return {"state": SshSessionState.UNAVAILABLE.value,
                "error": f"ssh-unavailable:{type(exc).__name__}",
                "authenticated": False}
    finally:
        # The session is ALWAYS closed, on every path.
        try:
            client.close()
        except Exception:  # noqa: BLE001 - close must never mask a result
            pass


def _drain(stream: Any) -> str:
    """Read a channel stream to EOF as text, bounded by the channel."""
    if stream is None:
        return ""
    try:
        return stream.read().decode("utf-8", "replace")
    except (OSError, ValueError):
        return ""

class SshReplayGuard:
    """Process-local replay guard over SSH invocation identities."""

    def __init__(self) -> None:
        self._run_by_invocation: Dict[str, str] = {}
        self._lock = threading.Lock()

    def register(self, run_id: str, invocation_id: str) -> None:
        if not run_id or not invocation_id:
            raise ValueError("run_id and invocation_id are required")
        with self._lock:
            if invocation_id in self._run_by_invocation:
                raise ValueError(f"replayed invocation: {invocation_id!r}")
            self._run_by_invocation[invocation_id] = run_id

    def is_registered(self, invocation_id: str) -> bool:
        with self._lock:
            return invocation_id in self._run_by_invocation

    def run_for(self, invocation_id: str) -> Optional[str]:
        with self._lock:
            return self._run_by_invocation.get(invocation_id)


class SshMediator:
    """Minimal governed SSH mediator: one session, one command, closed.

    Order of checks is a security boundary. Nothing touches the network
    until the target, port, protocol, credential, command, and Policy
    decision have all been accepted.
    """

    _BINDING_SECRET: bytes = os.urandom(32)

    def __init__(self, *,
                 session_fn: Callable[..., Dict[str, Any]]
                 = paramiko_ssh_session,
                 vault: Optional[CredentialVault] = None,
                 replay_guard: Optional[SshReplayGuard] = None,
                 command_timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT,
                 max_commands: int = DEFAULT_MAX_COMMANDS_PER_SESSION) -> None:
        if command_timeout_seconds <= 0:
            raise ValueError("command_timeout_seconds must be positive")
        if max_commands <= 0:
            raise ValueError("max_commands must be positive")
        self._session_fn = session_fn
        self._vault = vault
        self.replay_guard = replay_guard or SshReplayGuard()
        self._timeout = min(float(command_timeout_seconds),
                            MAX_COMMAND_TIMEOUT)
        self._max_commands = min(int(max_commands),
                                  MAX_COMMANDS_PER_SESSION_CEILING)

    def binding_hash(self, identity: Dict[str, Any]) -> str:
        """HMAC binding over the execution identity (replay resistance)."""
        payload = json.dumps(identity, sort_keys=True, separators=(",", ":"))
        return hmac.new(self._BINDING_SECRET, payload.encode("utf-8"),
                        hashlib.sha256).hexdigest()

    def invoke(self, *, request: ActionRequest, profile: TargetProfile,
               spec: SshSessionSpec, invocation_id: str, run_id: str,
               decision: Any = None) -> SshSessionResult:
        """Validate everything, then run at most ONE approved command."""
        def fail(state: SshSessionState, error: str, *,
                 host: str = "", port: int = 0,
                 command: str = "", decision_name: str = "not-attempted",
                 reason: str = "") -> SshSessionResult:
            return SshSessionResult(
                state=state, invocation_id=invocation_id, session_id="",
                mission_id=profile.mission_id, target_id=profile.target_id,
                host=host or profile.locator, port=port,
                protocol=SSH_PROTOCOL, username=spec.username,
                command=command, command_decision=decision_name,
                command_reason=reason, run_id=run_id, error=error)

        # 1. Exact-host target parse. No wildcard, no CIDR, no userinfo.
        try:
            target = parse_ssh_target(request.target)
        except NetworkScopeError as exc:
            return fail(SshSessionState.DENIED, f"ssh-target-invalid:{exc}")

        # 2. Exact host + port + protocol authorization.
        if not profile.allows(host=target.host, port=target.port,
                              protocol=SSH_PROTOCOL):
            return fail(SshSessionState.DENIED, "ssh-target-not-authorized",
                        host=target.host, port=target.port)
        if target.scheme not in SUPPORTED_SSH_PROTOCOLS:
            return fail(SshSessionState.DENIED,
                        f"ssh-protocol-unsupported:{target.scheme}",
                        host=target.host, port=target.port)
        if spec.port != target.port:
            return fail(SshSessionState.DENIED, "ssh-port-mismatch",
                        host=target.host, port=target.port)
        if spec.target and spec.target != target.host:
            return fail(SshSessionState.DENIED, "ssh-spec-host-mismatch",
                        host=target.host, port=target.port)

        # 3. The Policy decision must be an explicit ALLOW.
        if not _decision_allows(decision, request):
            return fail(SshSessionState.DENIED,
                        "ssh-authorization-not-allow",
                        host=target.host, port=target.port)

        chain = chaining_detected(request.purpose)
        if chain is not None:
            return fail(SshSessionState.DENIED,
                        f"ssh-command-chaining-rejected:{chain!r}",
                        host=target.host, port=target.port)
        command = command_from_purpose(request.purpose)
        if not command:
            return fail(SshSessionState.DENIED, "ssh-no-command",
                        host=target.host, port=target.port)
        verdict, why = spec.policy.evaluate(
            command, extra_authorized=spec.authorized_commands)
        if verdict is not CommandDecision.ALLOW:
            return fail(SshSessionState.DENIED, f"ssh-command-rejected:{why}",
                        host=target.host, port=target.port, command=command,
                        decision_name=verdict.value, reason=why)
        if spec.max_commands > 1 or self._max_commands != 1:
            # A request may never carry a batch; refuse an explicit one.
            return fail(SshSessionState.DENIED, "ssh-multiple-commands",
                        host=target.host, port=target.port, command=command,
                        decision_name=verdict.value, reason="ok")

        # 5. Credential: referenced, resolved, never persisted.
        password = None
        if self._vault is not None and spec.credential_id:
            if not self._vault.is_authorized_for(
                    spec.credential_id, target.host, SSH_PROTOCOL):
                return fail(SshSessionState.DENIED,
                            "ssh-credential-not-authorized",
                            host=target.host, port=target.port,
                            command=command, decision_name=verdict.value,
                            reason="ok")
            password = self._vault.retrieve(spec.credential_id)
            if password is None:
                return fail(SshSessionState.DENIED,
                            "ssh-credential-reference-invalid",
                            host=target.host, port=target.port,
                            command=command, decision_name=verdict.value,
                            reason="ok")

        # 6. Replay / invocation binding.
        try:
            self.replay_guard.register(run_id, invocation_id)
        except ValueError:
            return fail(SshSessionState.DENIED, "ssh-replay",
                        host=target.host, port=target.port, command=command,
                        decision_name=verdict.value, reason="ok")

        # 7. Bounded execution: one command, one session, always closed.
        timeout = min(self._timeout,
                      float(spec.command_timeout_seconds),
                      MAX_COMMAND_TIMEOUT)
        outcome = self._session_fn(
            host=target.host,
            port=target.port,
            username=spec.username,
            password=password,
            command=command,
            timeout=timeout,
            stdout_limit=min(spec.stdout_limit, MAX_STDOUT_LIMIT),
            stderr_limit=min(spec.stderr_limit, MAX_STDERR_LIMIT),
            host_key_policy=spec.host_key_policy,
        )
        # Drop the plaintext the moment the transport returns.
        password = None

        # The bound is a GOVERNANCE property, so the governor enforces
        # it rather than trusting the transport to have done so. A
        # misbehaving or substituted transport cannot push unbounded
        # output into evidence.
        out, out_cut = _clip(outcome.get("stdout", "") or "",
                             min(spec.stdout_limit, MAX_STDOUT_LIMIT))
        err, err_cut = _clip(outcome.get("stderr", "") or "",
                             min(spec.stderr_limit, MAX_STDERR_LIMIT))

        state = outcome.get("state", SshSessionState.FAILURE.value)
        if not isinstance(state, SshSessionState):
            try:
                state = SshSessionState(state)
            except ValueError:
                state = SshSessionState.FAILURE

        return SshSessionResult(
            state=state, invocation_id=invocation_id,
            session_id=str(outcome.get("session_id") or ""),
            mission_id=profile.mission_id, target_id=profile.target_id,
            host=target.host, port=target.port, protocol=SSH_PROTOCOL,
            username=spec.username, command=command,
            command_decision=verdict.value, command_reason=why,
            run_id=run_id, authenticated=bool(outcome.get("authenticated")),
            exit_code=outcome.get("exit_code"), stdout=out, stderr=err,
            stdout_truncated=bool(outcome.get("stdout_truncated")) or out_cut,
            stderr_truncated=bool(outcome.get("stderr_truncated")) or err_cut,
            stdout_sha256=_digest(out), stderr_sha256=_digest(err),
            commands_executed=1 if state is SshSessionState.SUCCESS else 0,
            error=str(outcome.get("error") or "")[:512])


_ssh_mediator_singleton: Optional[SshMediator] = None
_ssh_lock = threading.Lock()


def get_ssh_mediator() -> SshMediator:
    global _ssh_mediator_singleton
    with _ssh_lock:
        if _ssh_mediator_singleton is None:
            _ssh_mediator_singleton = SshMediator()
        return _ssh_mediator_singleton


def set_ssh_mediator(mediator: Optional[SshMediator]) -> None:
    global _ssh_mediator_singleton
    with _ssh_lock:
        _ssh_mediator_singleton = mediator


def build_ssh_spec(mission: Mission, profile: TargetProfile, *,
                   vault: Optional[CredentialVault] = None) \
        -> Optional[SshSessionSpec]:
    """Build the structured session spec from the mission declaration.

    The mission declares the SESSION SHAPE — username, credential
    reference, authorized commands, and bounds. Host and port come from
    the mission-bound TargetProfile, never from the caller, so a model
    cannot redirect a session to a host the operator did not authorize.
    """
    raw = (mission.problem or {}).get("ssh")
    if not isinstance(raw, dict):
        return None

    def _bounded_int(key: str, default: int, ceiling: int) -> int:
        try:
            value = int(raw.get(key, default))
        except (TypeError, ValueError):
            return default
        return max(1, min(value, ceiling))

    def _bounded_float(key: str, default: float, ceiling: float) -> float:
        try:
            value = float(raw.get(key, default))
        except (TypeError, ValueError):
            return default
        if value <= 0:
            return default
        return min(value, ceiling)

    port = profile.allowed_ports[0] if profile.allowed_ports else 22
    policy = SshCommandPolicy(
        allowlist=tuple(str(c) for c in (raw.get("allowlist") or [])),
        max_command_chars=_bounded_int(
            "max_command_chars", DEFAULT_MAX_COMMAND_CHARS,
            MAX_COMMAND_CHARS_CEILING),
        forbid_metacharacters=bool(
            raw.get("forbid_metacharacters", True)),
    )
    return SshSessionSpec(
        target=profile.locator,
        port=port,
        username=str(raw.get("username", "")),
        credential_id=str(raw.get("credential_id", "") or ""),
        policy=policy,
        authorized_commands=tuple(
            str(c) for c in (raw.get("authorized_commands")
                             or raw.get("commands") or [])),
        max_commands=_bounded_int(
            "max_commands", DEFAULT_MAX_COMMANDS_PER_SESSION,
            MAX_COMMANDS_PER_SESSION_CEILING),
        command_timeout_seconds=_bounded_float(
            "command_timeout_seconds", DEFAULT_COMMAND_TIMEOUT,
            MAX_COMMAND_TIMEOUT),
        stdout_limit=_bounded_int(
            "stdout_limit", DEFAULT_STDOUT_LIMIT, MAX_STDOUT_LIMIT),
        stderr_limit=_bounded_int(
            "stderr_limit", DEFAULT_STDERR_LIMIT, MAX_STDERR_LIMIT),
        host_key_policy=str(raw.get("host_key_policy", "strict")),
        purpose=str(raw.get("purpose", "ssh-session")),
    )


__all__ = [
    "DEFAULT_COMMAND_TIMEOUT",
    "DEFAULT_MAX_COMMANDS_PER_SESSION",
    "DEFAULT_STDERR_LIMIT",
    "DEFAULT_STDOUT_LIMIT",
    "FORBIDDEN_BINARIES",
    "MAX_COMMAND_CHARS_CEILING",
    "MAX_COMMANDS_PER_SESSION_CEILING",
    "MAX_COMMAND_TIMEOUT",
    "MAX_STDERR_LIMIT",
    "MAX_STDOUT_LIMIT",
    "PROVIDER_UNTRUSTED",
    "SHELL_METACHARACTERS",
    "SSH_CAPABILITY_ID",
    "SSH_PROTOCOL",
    "SUPPORTED_SSH_PROTOCOLS",
    "CommandDecision",
    "SshCommandPolicy",
    "SshMediator",
    "SshReplayGuard",
    "SshSessionResult",
    "SshSessionSpec",
    "SshSessionState",
    "build_ssh_spec",
    "command_from_purpose",
    "get_ssh_mediator",
    "paramiko_ssh_session",
    "set_ssh_mediator",
]
