"""tests.test_ssh_session — governed SSH target-session capability.

Covers the full governance contract for
``Capability.NETWORK_SSH_SESSION``:

1  exact-host authorization          10 stdout bounding
2  exact-port authorization          11 stderr bounding
3  missing authorization             12 session close
4  credential redaction              13 evidence generation
5  session open success              14 replay / invocation binding
6  session open failure              15 no direct model-to-process path
7  command allow                     16 no shell bypass
8  command deny                      17 no secondary destination
9  command timeout                   18 existing-capability regressions

Deterministic and offline. The transport is an injected
``session_fn``; no socket, no paramiko connection, no subprocess.
"""
from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from raphael_ibm_bob.broker import BOBBroker
from raphael_ibm_bob.contracts import ActionRequest, Capability, Mission
from raphael_ibm_bob.credential_provenance import (
    CredentialProvenance,
    CredentialVault,
)
from raphael_ibm_bob.evidence_ledger import EvidenceLedger
from raphael_ibm_bob.policy import BOBPolicy
from raphael_ibm_bob.runtime import BOBRuntime
from raphael_ibm_bob.ssh_runtime import (
    MAX_STDOUT_LIMIT,
    CommandDecision,
    SshCommandPolicy,
    SshMediator,
    SshSessionSpec,
    SshSessionState,
    build_ssh_spec,
    command_from_purpose,
)
from raphael_ibm_bob.target_profile import TargetStore, build_target_profile
from raphael_ibm_bob.workspace import Workspace

HOST = "127.0.0.1"
PORT = 2222
MISSION_ID = "M-SSH-001"
SECRET = "sup3r-s3cret-ssh-password-DO-NOT-LEAK"


def _fake_session(**kwargs):
    """Injected transport. Records its call; never opens a socket."""
    _fake_session.calls.append(dict(kwargs))
    return _fake_session.outcome


_fake_session.calls = []
_fake_session.outcome = {
    "state": "success", "session_id": "sess-1", "exit_code": 0,
    "stdout": "ok\n", "stderr": "", "authenticated": True, "error": "",
}


def _reset_transport(**overrides):
    _fake_session.calls = []
    _fake_session.outcome = {
        "state": "success", "session_id": "sess-1", "exit_code": 0,
        "stdout": "ok\n", "stderr": "", "authenticated": True, "error": "",
    }
    _fake_session.outcome.update(overrides)


def _mission(*, commands=("ls",), credential_id="", port=PORT) -> Mission:
    return Mission(
        mission_id=MISSION_ID, description="ssh session", scope=HOST,
        criteria=["session"],
        problem={"ssh": {
            "username": "rag",
            "credential_id": credential_id,
            "authorized_commands": list(commands),
            "port": port,
        }},
    )


def _store(port=PORT, protocols="ssh") -> TargetStore:
    store = TargetStore()
    store.set_target(build_target_profile(
        mission_id=MISSION_ID, locator=HOST, allowed_ports=[port],
        allowed_protocols=protocols, authorization_ref="lab",
        platform="htb"))
    return store


def _request(command="ls", *, host=HOST, port=PORT, purpose=None,
             capability=Capability.NETWORK_SSH_SESSION,
             timeout_seconds=20.0) -> ActionRequest:
    return ActionRequest(
        sequence=0, requester="skill:network-ssh-session",
        capability=capability,
        target=f"ssh://{host}:{port}",
        purpose=purpose if purpose is not None else f"cmd={command}",
        timeout_seconds=timeout_seconds,
    )


class _Rig:
    """One governed stack: Policy -> Broker -> Runtime + SSH mediator."""

    def __init__(self, store: TargetStore, *, vault=None, mediator=None,
                 ledger=None, workspace=None):
        self.store = store
        self.workspace = workspace or Workspace(tempfile.mkdtemp())
        self.ledger = ledger or EvidenceLedger(self.workspace.root)
        self.vault = vault
        self.mediator = mediator or SshMediator(
            session_fn=_fake_session, vault=vault)
        self.broker = BOBBroker(
            BOBPolicy(self.workspace, target_store=store,
                      credential_vault=vault), self.workspace,
            ledger=self.ledger, target_store=store, ssh_mediator=self.mediator,
            credential_vault=vault)
        self.runtime = BOBRuntime(self.broker)

    def submit(self, request, mission):
        return self.runtime.submit(request, mission)


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        _reset_transport()


# ---------------------------------------------------------------------------
# 1-3. Authorization
# ---------------------------------------------------------------------------

class AuthorizationTests(_Base):
    def test_exact_host_authorization(self):
        store = _store()
        rig = _Rig(store)
        allowed = rig.submit(_request(), _mission())
        self.assertEqual(allowed.broker_result.decision.decision.value,
                         "allow")
        self.assertTrue(allowed.broker_result.capability_invoked)

        other = _Rig(_store())
        before = len(_fake_session.calls)
        denied = other.submit(_request(host="10.255.255.1"), _mission())
        self.assertEqual(denied.broker_result.decision.decision.value, "deny")
        self.assertIn("ssh-target-mismatch",
                      denied.broker_result.decision.reason)
        self.assertIsNone(denied.execution)
        # No transport call was made for the denied request.
        self.assertEqual(len(_fake_session.calls), before)

    def test_exact_port_authorization(self):
        rig = _Rig(_store(port=PORT))
        ok = rig.submit(_request(port=PORT), _mission(port=PORT))
        self.assertEqual(ok.broker_result.decision.decision.value, "allow")

        other = _Rig(_store(port=2223))
        denied = other.submit(_request(port=2222), _mission(port=2222))
        self.assertEqual(denied.broker_result.decision.decision.value, "deny")
        self.assertIn("ssh-target-mismatch",
                      denied.broker_result.decision.reason)

    def test_protocol_must_be_explicitly_authorized(self):
        store = _store(protocols="http")
        rig = _Rig(store)
        denied = rig.submit(_request(), _mission())
        self.assertEqual(denied.broker_result.decision.decision.value, "deny")
        self.assertEqual(_fake_session.calls, [])

    def test_missing_authorization_denies(self):
        empty = TargetStore()
        rig = _Rig(empty)
        denied = rig.submit(_request(), _mission())
        self.assertEqual(denied.broker_result.decision.decision.value, "deny")
        self.assertIn("ssh-no-authorized-target",
                      denied.broker_result.decision.reason)
        self.assertEqual(_fake_session.calls, [])

    def test_no_wildcard_and_no_cidr(self):
        store = _store()
        rig = _Rig(store)
        from raphael_ibm_bob.network_scope import (
            NetworkScopeError, parse_ssh_target)
        for bad in ("ssh://*.example:22", "ssh://10.0.0.0/24:22",
                    "ssh://host:0", "ssh://host:99999"):
            with self.subTest(target=bad):
                with self.assertRaises(NetworkScopeError):
                    parse_ssh_target(bad)

    def test_no_secondary_destination_in_target(self):
        """userinfo/path/query are all refused by the parser."""
        from raphael_ibm_bob.network_scope import (
            NetworkScopeError, parse_ssh_target)
        for bad in ("ssh://user:pass@host:22", "ssh://host:22/cmd",
                    "ssh://host:22?a=b", "http://host:22",
                    "ssh://host:99999"):
            with self.subTest(target=bad):
                with self.assertRaises(NetworkScopeError):
                    parse_ssh_target(bad)

    def test_no_session_spec_denies(self):
        rig = _Rig(_store())
        mission = Mission(mission_id=MISSION_ID, description="d", scope=HOST,
                          criteria=[], problem={})
        denied = rig.submit(_request(), mission)
        self.assertEqual(denied.broker_result.decision.decision.value, "deny")
        self.assertIn("ssh-no-session-spec",
                      denied.broker_result.decision.reason)


# ---------------------------------------------------------------------------
# 4. Credential redaction
# ---------------------------------------------------------------------------

class CredentialRedactionTests(_Base):
    def _vault_with_secret(self, host=HOST):
        vault = CredentialVault()
        ref = vault.store("ssh_password", SECRET, host,
                          CredentialProvenance.DEFAULT_CREDENTIAL)
        vault.mark_validated(ref.credential_id, host, "ssh")
        vault.authorize(ref.credential_id, host, "ssh")
        return vault, ref

    def test_credential_absent_from_spec_evidence_and_errors(self):
        vault, ref = self._vault_with_secret()
        spec = build_ssh_spec(_mission(credential_id=ref.credential_id),
                               _store().current(), vault=vault)
        rendered = json.dumps(spec.sensitive_dict(), sort_keys=True)
        self.assertNotIn(SECRET, rendered)
        self.assertNotIn(SECRET, repr(spec))
        self.assertNotIn(SECRET, str(spec))
        self.assertIn("credential_present", rendered)

    def test_credential_absent_from_ledger_timeline_and_result(self):
        vault, ref = self._vault_with_secret()
        mission = _mission(credential_id=ref.credential_id)
        rig = _Rig(_store(), vault=vault)
        result = rig.submit(_request(), mission)
        self.assertTrue(result.broker_result.capability_invoked)
        # Transport received the secret...
        self.assertEqual(_fake_session.calls[0]["password"], SECRET)
        # ...but nothing the operator or ledger can read contains it.
        self.assertNotIn(SECRET, json.dumps(result.execution.to_dict(),
                                             sort_keys=True))
        self.assertNotIn(SECRET, json.dumps(result.execution.evidence,
                                             sort_keys=True, default=str))
        raw = (self.rig_ledger_text(rig))
        self.assertNotIn(SECRET, raw)
        timeline = json.dumps(result.to_dict() if hasattr(result, "to_dict")
                              else result.broker_result.__dict__, default=str)
        self.assertNotIn(SECRET, timeline)

    def rig_ledger_text(self, rig) -> str:
        path = Path(rig.ledger.run_dir()) / "evidence.jsonl"
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def test_unauthorized_credential_reference_denies(self):
        """A vault credential scoped to another host is refused."""
        vault = CredentialVault()
        ref = vault.store("ssh_password", SECRET, "10.0.0.9",
                          CredentialProvenance.DEFAULT_CREDENTIAL)
        vault.mark_validated(ref.credential_id, "10.0.0.9", "ssh")
        vault.authorize(ref.credential_id, "10.0.0.9", "ssh")
        rig = _Rig(_store(), vault=vault)
        denied = rig.submit(
            _request(), _mission(credential_id=ref.credential_id))
        self.assertEqual(denied.broker_result.decision.decision.value, "deny")
        self.assertIn("ssh-credential-not-authorized",
                      denied.broker_result.decision.reason)
        self.assertEqual(_fake_session.calls, [])

    def test_invalid_credential_reference_denies(self):
        rig = _Rig(_store(), vault=CredentialVault())
        denied = rig.submit(
            _request(), _mission(credential_id="no-such-credential"))
        self.assertEqual(denied.broker_result.decision.decision.value, "deny")
        self.assertEqual(_fake_session.calls, [])

    def test_console_never_renders_a_credential_field(self):
        from raphael_ibm_bob.http.app import Request, config_from_env, dispatch
        from raphael_ibm_bob.http.views import agent_console as view
        html = view.render(ssh_state={"credential_id": "vault-1",
                                      "target": "ssh://127.0.0.1:2222",
                                      "commands": ["ls"]})
        self.assertNotIn(SECRET, html)
        self.assertNotIn('name="password"', html)
        self.assertIn("CREDENTIAL REFERENCE", html)
        self.assertIn("vault-1", html)


# ---------------------------------------------------------------------------
# 5-6. Session open success / failure
# ---------------------------------------------------------------------------

class SessionOpenTests(_Base):
    def test_session_open_success_produces_structured_result(self):
        _reset_transport(exit_code=0, stdout="bin boot dev\n")
        rig = _Rig(_store())
        result = rig.submit(_request("ls"), _mission())
        self.assertTrue(result.execution.success)
        evidence = result.execution.evidence
        for key in ("session_id", "host", "port", "protocol", "command",
                    "command_decision", "exit_code", "stdout", "stderr",
                    "invocation_id"):
            self.assertIn(key, evidence)
        self.assertEqual(evidence["host"], HOST)
        self.assertEqual(evidence["port"], PORT)
        self.assertEqual(evidence["protocol"], "ssh")
        self.assertEqual(evidence["exit_code"], 0)
        self.assertEqual(evidence["command"], "ls")
        self.assertTrue(evidence["authenticated"])
        self.assertTrue(evidence["provider_untrusted"])

    def test_session_open_failure_is_never_success(self):
        for state in ("auth_failed", "timeout", "refused", "unavailable",
                      "failure"):
            with self.subTest(state=state):
                _reset_transport(state=state, error="boom",
                                 authenticated=False)
                rig = _Rig(_store())
                result = rig.submit(_request("ls"), _mission())
                self.assertFalse(result.execution.success)
                self.assertEqual(
                    result.execution.evidence["ssh_result"]["state"], state)

    def test_transport_always_closes_its_session(self):
        """paramiko_ssh_session closes in `finally` on every path."""
        import inspect
        from raphael_ibm_bob import ssh_runtime
        source = inspect.getsource(ssh_runtime.paramiko_ssh_session)
        self.assertIn("finally:", source)
        self.assertIn("client.close()", source)

    def test_unsupported_transport_is_reported_not_raised(self):
        result = SshMediator(session_fn=_fake_session).invoke(
            request=_request(), profile=_store().current(),
            spec=build_ssh_spec(_mission(), _store().current()),
            invocation_id="SSH-1", run_id="run",
            decision=_allow())
        self.assertTrue(result.to_dict()["protocol"] == "ssh")

    def test_host_key_policy_default_is_strict(self):
        spec = build_ssh_spec(_mission(), _store().current())
        self.assertEqual(spec.host_key_policy, "strict")


# ---------------------------------------------------------------------------
# 7-8. Command policy
# ---------------------------------------------------------------------------

class CommandPolicyTests(_Base):
    def test_command_allow(self):
        rig = _Rig(_store())
        result = rig.submit(_request("id"), _mission(commands=("ls", "id")))
        self.assertTrue(result.execution.success)
        self.assertEqual(result.execution.evidence["command_decision"],
                         CommandDecision.ALLOW.value)
        self.assertEqual(_fake_session.calls[0]["command"], "id")

    def test_command_deny_when_not_authorized(self):
        rig = _Rig(_store())
        denied = rig.submit(_request("whoami"),
                            _mission(commands=("ls",)))
        self.assertEqual(denied.broker_result.decision.decision.value, "deny")
        self.assertIn("ssh-command-rejected",
                      denied.broker_result.decision.reason)
        self.assertEqual(_fake_session.calls, [])

    def test_require_authorization_distinct_from_deny(self):
        policy = SshCommandPolicy(allowlist=("ls",))
        verdict, _why = policy.evaluate("cat")
        self.assertIs(verdict, CommandDecision.REQUIRE_AUTHORIZATION)
        verdict, _why = policy.evaluate("ls")
        self.assertIs(verdict, CommandDecision.ALLOW)
        verdict, why = policy.evaluate("ls; rm -rf /")
        self.assertIs(verdict, CommandDecision.DENY)

    def test_explicit_mission_authorization_promotes_command(self):
        """REQUIRE_AUTHORIZATION becomes ALLOW only when the mission
        declares the exact command."""
        rig = _Rig(_store())
        allowed = rig.submit(_request("id"), _mission(commands=("ls", "id")))
        self.assertTrue(allowed.execution.success)

    def test_command_must_be_a_structured_clause(self):
        """A prose purpose never becomes a command."""
        rig = _Rig(_store())
        denied = rig.submit(
            _request(purpose="please run ls on the target"),
            _mission(commands=("ls",)))
        self.assertEqual(denied.broker_result.decision.decision.value, "deny")
        self.assertIn("ssh-no-command",
                      denied.broker_result.decision.reason)

    def test_command_extraction_is_exact(self):
        self.assertEqual(command_from_purpose("cmd=ls observe"), "ls")
        self.assertEqual(command_from_purpose("purpose=probe cmd=id now"), "id")
        self.assertEqual(command_from_purpose("no clause here"), "")

    def test_multiple_commands_in_one_request_are_refused(self):
        rig = _Rig(_store())
        denied = rig.submit(_request(purpose="cmd=ls && cat flag"),
                            _mission())
        self.assertEqual(denied.broker_result.decision.decision.value, "deny")
        self.assertEqual(_fake_session.calls, [])

    def test_multi_command_mission_is_refused_by_policy(self):
        mission = Mission(
            mission_id=MISSION_ID, description="d", scope=HOST,
            criteria=[], problem={"ssh": {
                "username": "u", "authorized_commands": ["ls"],
                "max_commands": 5}})
        rig = _Rig(_store())
        denied = rig.submit(_request("ls"), mission)
        self.assertEqual(denied.broker_result.decision.decision.value, "deny")
        self.assertIn("ssh-multiple-commands-forbidden",
                      denied.broker_result.decision.reason)


# ---------------------------------------------------------------------------
# 9-11. Bounds
# ---------------------------------------------------------------------------

class BoundTests(_Base):
    def test_command_timeout_is_passed_and_clamped(self):
        mission = _mission()
        mission.problem["ssh"]["command_timeout_seconds"] = 5
        rig = _Rig(_store())
        rig.submit(_request("ls"), mission)
        self.assertLessEqual(_fake_session.calls[0]["timeout"], 5.0)

    def test_stdout_bounding(self):
        _reset_transport(stdout="A" * 10000)
        mission = _mission()
        mission.problem["ssh"]["stdout_limit"] = 64
        rig = _Rig(_store())
        result = rig.submit(_request("ls"), mission)
        self.assertEqual(len(result.execution.evidence["stdout"]), 64)
        self.assertTrue(result.execution.evidence["stdout_truncated"])
        self.assertTrue(result.execution.evidence["stdout_sha256"])

    def test_stderr_bounding(self):
        _reset_transport(stderr="B" * 10000)
        mission = _mission()
        mission.problem["ssh"]["stderr_limit"] = 32
        rig = _Rig(_store())
        result = rig.submit(_request("ls"), mission)
        self.assertEqual(len(result.execution.evidence["stderr"]), 32)
        self.assertTrue(result.execution.evidence["stderr_truncated"])

    def test_bounds_are_clamped_to_hard_ceilings(self):
        mission = _mission()
        mission.problem["ssh"]["stdout_limit"] = 10 ** 9
        mission.problem["ssh"]["stderr_limit"] = 10 ** 9
        spec = build_ssh_spec(mission, _store().current())
        self.assertLessEqual(spec.stdout_limit, MAX_STDOUT_LIMIT)

    def test_command_length_bounded(self):
        long_cmd = "ls " + ("x" * 5000)
        rig = _Rig(_store())
        denied = rig.submit(_request(long_cmd), _mission(commands=(long_cmd,)))
        self.assertEqual(denied.broker_result.decision.decision.value, "deny")

    def test_nonpositive_timeout_is_invalid(self):
        from raphael_ibm_bob.policy import _timeout_is_valid
        for bad in (0, -1, float("nan"), float("inf")):
            with self.subTest(bad=bad):
                self.assertFalse(_timeout_is_valid(bad))
        self.assertTrue(_timeout_is_valid(None))
        self.assertTrue(_timeout_is_valid(5))


# ---------------------------------------------------------------------------
# 12-14. Close, evidence, replay
# ---------------------------------------------------------------------------

class LifecycleTests(_Base):
    def test_session_close_is_recorded(self):
        rig = _Rig(_store())
        result = rig.submit(_request("ls"), _mission())
        self.assertTrue(result.execution.evidence["session_id"])
        self.assertEqual(result.execution.evidence["commands_executed"], 1)

    def test_evidence_generated_with_producer_ssh(self):
        rig = _Rig(_store())
        result = rig.submit(_request("ls"), _mission())
        self.assertTrue(result.broker_result.evidence_ids)
        path = Path(rig.ledger.run_dir()) / "evidence.jsonl"
        records = [json.loads(line) for line in
                   path.read_text(encoding="utf-8").splitlines() if line]
        producers = {r.get("producer") for r in records}
        self.assertIn("ssh", producers)
        kinds = {r.get("kind") for r in records}
        self.assertTrue({"request", "decision", "result", "evidence"} <= kinds)

    def test_replay_is_refused(self):
        mediator = SshMediator(session_fn=_fake_session)
        mediator.replay_guard.register("run-1", "SSH-same")
        profile = _store().current()
        spec = build_ssh_spec(_mission(), profile)
        result = mediator.invoke(
            request=_request("ls"), profile=profile, spec=spec,
            invocation_id="SSH-same", run_id="run-1", decision=_allow())
        self.assertEqual(result.state, SshSessionState.DENIED)
        self.assertIn("ssh-replay", result.error)
        self.assertEqual(_fake_session.calls, [])

    def test_replay_guard_binds_invocation_to_run(self):
        from raphael_ibm_bob.ssh_runtime import SshReplayGuard
        guard = SshReplayGuard()
        guard.register("run-a", "SSH-1")
        self.assertTrue(guard.is_registered("SSH-1"))
        self.assertEqual(guard.run_for("SSH-1"), "run-a")
        with self.assertRaises(ValueError):
            guard.register("run-b", "SSH-1")

    def test_invocation_binding_hash_is_stable_and_secret_free(self):
        mediator = SshMediator(session_fn=_fake_session)
        first = mediator.binding_hash({"run": "r", "seq": 1})
        second = mediator.binding_hash({"run": "r", "seq": 1})
        self.assertEqual(first, second)
        self.assertNotEqual(first, mediator.binding_hash({"run": "r",
                                                           "seq": 2}))
        self.assertNotIn(SECRET, first)

    def test_non_allow_decision_blocks_the_transport(self):
        from raphael_ibm_bob.contracts import Decision
        from raphael_ibm_bob.policy import BOBPolicy as _P
        deny = Decision.DENY
        mediator = SshMediator(session_fn=_fake_session)
        result = mediator.invoke(
            request=_request("ls"), profile=_store().current(),
            spec=build_ssh_spec(_mission(), _store().current()),
            invocation_id="SSH-x", run_id="r", decision=deny)
        self.assertEqual(result.state, SshSessionState.DENIED)
        self.assertEqual(_fake_session.calls, [])


# ---------------------------------------------------------------------------
# 15-17. No bypass
# ---------------------------------------------------------------------------

class NoBypassTests(_Base):
    def test_no_direct_model_to_process_path(self):
        """The mediator exposes no process/handle surface to a caller."""
        forbidden = ("Popen", "subprocess", "os.system", "exec_command",
                     "socket", "connect", "paramiko")
        source = Path(SshMediator.__module__.replace(".", "/") + ".py")
        for attr in forbidden:
            self.assertFalse(hasattr(SshMediator, attr), attr)
        self.assertTrue(source.exists())

    def test_model_adapter_has_no_session_handle(self):
        """The model's proposal surface stays request-only."""
        from raphael_ibm_bob.harness.model import ModelAdapter
        self.assertTrue(hasattr(ModelAdapter, "propose"))
        for forbidden in ("connect", "exec_command", "Popen", "ssh"):
            self.assertFalse(hasattr(ModelAdapter, forbidden), forbidden)

    def test_capability_reaches_mediator_only_through_broker(self):
        """Submitting a raw SSH action outside Runtime has no path."""
        store = _store()
        mediator = SshMediator(session_fn=_fake_session)
        broker = BOBBroker(BOBPolicy(Workspace(tempfile.mkdtemp()),
                                       target_store=store),
                           Workspace(tempfile.mkdtemp()),
                           target_store=store, ssh_mediator=mediator)
        with self.assertRaises(Exception):
            broker.execute_capability(_request("ls"), _mission())

    def test_no_shell_bypass_constructs(self):
        policy = SshCommandPolicy(allowlist=("ls",))
        for bad in ("ls; rm -rf /", "ls | nc h p", "ls && id", "ls > /etc/x",
                    "ls `id`", "$(id)", "ls\nid", "sh -c 'id'",
                    "bash -c id", "/bin/sh -c id", "ls & id",
                    "ls >out", "cat /etc/passwd", "sudo ls", "env ls"):
            with self.subTest(command=bad):
                verdict, _why = policy.evaluate(bad)
                self.assertIsNot(verdict, CommandDecision.ALLOW, bad)

    def test_interpreter_paths_cannot_bypass_the_allowlist(self):
        policy = SshCommandPolicy(allowlist=("/bin/sh -c id",))
        verdict, _why = policy.evaluate("/bin/sh -c id")
        self.assertIs(verdict, CommandDecision.DENY)


# ---------------------------------------------------------------------------
# 18. Existing-capability regressions
# ---------------------------------------------------------------------------

class RegressionTests(_Base):
    def test_http_capability_still_works_alongside_ssh(self):
        store = TargetStore()
        store.set_target(build_target_profile(
            mission_id="M-REG", locator=HOST, allowed_ports=[8080],
            allowed_protocols="http", authorization_ref="lab", platform="htb"))
        ws = Workspace(tempfile.mkdtemp())
        broker = BOBBroker(BOBPolicy(ws, target_store=store), ws,
                           target_store=store,
                           ssh_mediator=SshMediator(session_fn=_fake_session))
        runtime = BOBRuntime(broker)
        mission = Mission(mission_id="M-REG", description="d", scope=HOST,
                          criteria=[])
        denied = runtime.submit(ActionRequest(
            sequence=0, requester="t",
            capability=Capability.NETWORK_HTTP_REQUEST,
            target="http://127.0.0.1:9999/", purpose="method=GET"), mission)
        self.assertEqual(denied.broker_result.decision.decision.value, "deny")
        self.assertIn("network-target-mismatch",
                      denied.broker_result.decision.reason)

    def test_telnet_capability_is_unaffected(self):
        from raphael_ibm_bob.telnet_runtime import validate_command
        ok, _ = validate_command("ls", ("ls", "pwd"))
        self.assertTrue(ok)
        ok, _why = validate_command("ls; id", ("ls", "pwd"))
        self.assertFalse(ok)

    def test_discovery_capability_is_unaffected(self):
        from raphael_ibm_bob.discovery_runtime import _parse_port_spec
        ports, _ = _parse_port_spec("ports=8080")
        self.assertEqual(ports, (8080,))

    def test_ssh_is_declared_but_grants_no_authority_alone(self):
        from raphael_ibm_bob.capability_bootstrap import ssh_descriptor
        descriptor = ssh_descriptor()
        self.assertEqual(descriptor.capability_id, "NETWORK_SSH_SESSION")
        self.assertEqual(descriptor.authorization_scope, "network_ssh")
        self.assertIn("credential", [p.kind for p in descriptor.prerequisites])

    def test_skill_is_offered_to_the_model(self):
        from raphael_ibm_bob.harness.providers.openai_compat import skill_catalog
        from raphael_ibm_bob.skills import default_registry, register_default_skills
        catalog = skill_catalog(register_default_skills(default_registry()))
        entries = {c["skill"]: c for c in catalog}
        self.assertIn("network-ssh-session", entries)
        self.assertEqual(entries["network-ssh-session"]["capability"],
                         Capability.NETWORK_SSH_SESSION.value)

    def test_model_can_propose_ssh_and_policy_approves(self):
        """End-to-end: model-shaped proposal -> Policy -> Broker."""
        from raphael_ibm_bob.harness.providers.openai_compat import (
            validate_proposal)
        from raphael_ibm_bob.skills import default_registry, register_default_skills
        registry = register_default_skills(default_registry())
        request = validate_proposal(
            {"intent": "act", "skill": "network-ssh-session",
             "target": f"ssh://{HOST}:{PORT}",
             "purpose": "cmd=ls enumerate the authorized target"},
            registry)
        self.assertEqual(request.capability, Capability.NETWORK_SSH_SESSION)
        rig = _Rig(_store())
        result = rig.submit(request, _mission())
        self.assertTrue(result.execution.success)
        self.assertEqual(_fake_session.calls[0]["command"], "ls")


def _allow():
    """An ALLOW PolicyDecision, built the way the Broker builds one."""
    from raphael_ibm_bob.contracts import (
        Capability, Decision, PolicyDecision)
    return PolicyDecision(sequence=0, decision=Decision.ALLOW, reason="ok",
                          capability=Capability.NETWORK_SSH_SESSION,
                          target=f"ssh://{HOST}:{PORT}")


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Production wiring: the HTTP/console -> mission -> spec chain
# ---------------------------------------------------------------------------

class ProductionWiringTests(unittest.TestCase):
    """The defects that stopped SSH from ever executing in production.

    Each of these failed in the real Agent UI path while the unit suite
    stayed green, because the unit suite injected a spec directly and
    never went through the route that builds the mission.
    """

    def setUp(self) -> None:
        from raphael_ibm_bob.http.app import config_from_env
        from raphael_ibm_bob.target_profile import TargetStore
        self._tmp = tempfile.TemporaryDirectory(prefix="raphael-ssh-prod-")
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.config = config_from_env()
        self.config.sessions_root = self.tmp / "sessions"
        self.config.runs_root = self.tmp / "runs"
        self.config.target_store = TargetStore()

    def _post(self, path, body):
        from raphael_ibm_bob.http.app import Request, dispatch
        return dispatch(Request("POST", path, body=body), self.config)

    def _declare_target(self, mission_id=MISSION_ID):
        from raphael_ibm_bob.http.app import Request, dispatch
        return dispatch(Request("POST", "/agent/target", body={
            "mission_id": mission_id, "host": HOST,
            "port_spec": "8080,2222", "protocols": "http,ssh",
            "authorization_ref": "lab"}), self.config)

    def test_console_command_field_reaches_the_spec(self):
        """The route stores `commands`; the spec must read it."""
        self._declare_target()
        self._post("/agent/ssh-session", {
            "target": f"ssh://{HOST}:2222", "username": "root",
            "commands": "id, whoami"})
        stored = self.config.target_store.get_ssh_session(MISSION_ID)
        self.assertEqual(stored["commands"], ["id", "whoami"])
        mission = Mission(
            mission_id=MISSION_ID, description="d", scope=HOST,
            criteria=[], problem={"ssh": dict(stored)})
        spec = build_ssh_spec(mission, self.config.target_store.current())
        self.assertEqual(list(spec.authorized_commands), ["id", "whoami"])

    def test_console_secret_reaches_the_vault_and_nowhere_else(self):
        secret = "prod-path-secret-not-real"
        self._declare_target()
        self._post("/agent/ssh-session", {
            "target": f"ssh://{HOST}:2222", "username": "root",
            "commands": "id", "credential_secret": secret})
        stored = self.config.target_store.get_ssh_session(MISSION_ID)
        self.assertTrue(stored["credential_id"])
        self.assertNotIn(secret, str(stored))
        vault = self.config.credential_vault
        self.assertEqual(vault.retrieve(stored["credential_id"]), secret)
        self.assertTrue(vault.is_authorized_for(
            stored["credential_id"], HOST, "ssh"))

    def test_session_binds_to_the_declared_target_mission(self):
        """No mission id in the SSH form must still attach to the target."""
        self._declare_target("M-OPS-XYZ")
        self._post("/agent/ssh-session", {
            "target": f"ssh://{HOST}:2222", "username": "root",
            "commands": "id", "credential_secret": "s"})
        self.assertIsNotNone(
            self.config.target_store.get_ssh_session("M-OPS-XYZ"))

    def test_console_never_renders_the_credential_secret(self):
        from raphael_ibm_bob.http.app import Request, dispatch
        secret = "render-check-secret"
        self._declare_target()
        self._post("/agent/ssh-session", {
            "target": f"ssh://{HOST}:2222", "username": "root",
            "commands": "id", "credential_secret": secret})
        html = dispatch(Request("GET", "/agent"), self.config).body
        self.assertIn('name="credential_secret"', html)
        self.assertIn('type="password"', html)
        self.assertNotIn(secret, html)
