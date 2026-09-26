"""tests.test_ssh_session_e2e — governed SSH against a REAL transport.

The unit suite injects a fake transport. This module runs the whole
chain over a genuine SSH connection to a local, in-process SSH server:

    model-shaped proposal
      -> ActionRequest
      -> BOBRuntime -> BOBBroker -> BOBPolicy
      -> SshMediator
      -> real SSH transport (paramiko client -> paramiko server)
      -> ONE bounded command on a real exec channel
      -> structured evidence in the ledger
      -> the result is what a subsequent model turn would observe

No external host, no exploit, no Kioptrix. The server is a harmless
read-only command table on 127.0.0.1 with an in-memory host key.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from raphael_ibm_bob.broker import BOBBroker
from raphael_ibm_bob.contracts import Capability, Mission
from raphael_ibm_bob.credential_provenance import (
    CredentialProvenance,
    CredentialVault,
)
from raphael_ibm_bob.evidence_ledger import EvidenceLedger
from raphael_ibm_bob.harness.providers.openai_compat import validate_proposal
from raphael_ibm_bob.policy import BOBPolicy
from raphael_ibm_bob.runtime import BOBRuntime
from raphael_ibm_bob.skills import default_registry, register_default_skills
from raphael_ibm_bob.ssh_runtime import SshMediator, paramiko_ssh_session
from raphael_ibm_bob.target_profile import TargetStore, build_target_profile
from raphael_ibm_bob.workspace import Workspace
from tests.ssh_fixture import (
    FIXTURE_PASSWORD,
    FIXTURE_USERNAME,
    LocalSshServer,
)

HOST = "127.0.0.1"
MISSION_ID = "M-SSH-E2E"
SECRET = FIXTURE_PASSWORD


class _Stack:
    def __init__(self, port: int, *, allowlist=("ls", "id", "whoami", "pwd"),
                 vault=None, password: str = FIXTURE_PASSWORD,
                 host_key_policy: str = "auto-add"):
        # The credential is ALWAYS a vault reference resolved by the
        # mediator, never a literal in the mission.
        if vault is None:
            vault = CredentialVault()
        self.vault = vault
        ref = vault.store("ssh_password", password, HOST,
                          CredentialProvenance.DEFAULT_CREDENTIAL)
        vault.mark_validated(ref.credential_id, HOST, "ssh")
        vault.authorize(ref.credential_id, HOST, "ssh")
        self.credential_id = ref.credential_id
        self.host_key_policy = host_key_policy
        self.workspace = Workspace(tempfile.mkdtemp())
        self.ledger = EvidenceLedger(self.workspace.root)
        self.store = TargetStore()
        self.store.set_target(build_target_profile(
            mission_id=MISSION_ID, locator=HOST, allowed_ports=[port],
            allowed_protocols="ssh", authorization_ref="local-fixture",
            platform="htb"))
        self.mediator = SshMediator(
            session_fn=paramiko_ssh_session, vault=vault)
        self.broker = BOBBroker(
            BOBPolicy(self.workspace, target_store=self.store,
                      credential_vault=vault),
            self.workspace, ledger=self.ledger, target_store=self.store,
            ssh_mediator=self.mediator, credential_vault=vault)
        self.runtime = BOBRuntime(self.broker)
        self.mission = Mission(
            mission_id=MISSION_ID, description="ssh e2e", scope=HOST,
            criteria=["session"],
            problem={"ssh": {
                "username": FIXTURE_USERNAME,
                "credential_id": self.credential_id,
                "authorized_commands": list(allowlist),
                "port": port,
                # The fixture's host key is generated in memory per run,
                # so strict host-key verification cannot be satisfied
                # against it. The failure mode being tested here is
                # command/evidence governance, not host-key trust; the
                # strict default is covered in the unit suite.
                "host_key_policy": host_key_policy,
            }},
        )


class RealTransportTests(unittest.TestCase):
    """One fixture server for the module; each test gets a clean stack."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = LocalSshServer()
        cls.server.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.__exit__(None, None, None)

    def _model_request(self, command: str, *, allowlist):
        """A proposal shaped exactly as the model would return it."""
        registry = register_default_skills(default_registry())
        return validate_proposal(
            {"intent": "act", "skill": "network-ssh-session",
             "target": f"ssh://{HOST}:{self.server.port}",
             "purpose": f'cmd="{command}" observe the authorized target'},
            registry)

    def test_end_to_end_authorized_command(self):
        stack = _Stack(self.server.port)
        request = self._model_request("ls", allowlist=("ls", "id"))
        self.assertEqual(request.capability, Capability.NETWORK_SSH_SESSION)

        result = stack.runtime.submit(request, stack.mission)
        decision = result.broker_result.decision
        self.assertEqual(decision.decision.value, "allow", decision.reason)
        self.assertTrue(result.broker_result.capability_invoked)
        self.assertTrue(result.execution.success)

        evidence = result.execution.evidence
        self.assertEqual(evidence["exit_code"], 0)
        self.assertIn("home", evidence["stdout"])
        self.assertEqual(evidence["command"], "ls")
        self.assertEqual(evidence["protocol"], "ssh")
        self.assertEqual(evidence["host"], HOST)
        self.assertEqual(evidence["port"], self.server.port)
        self.assertTrue(evidence["authenticated"])
        self.assertTrue(evidence["provider_untrusted"])
        self.assertTrue(evidence["stdout_sha256"])

    def test_evidence_is_persisted_for_the_next_turn(self):
        stack = _Stack(self.server.port)
        result = stack.runtime.submit(
            self._model_request("whoami", allowlist=("whoami",)),
            stack.mission)
        evidence_id = result.broker_result.evidence_ids[-1]
        self.assertTrue(evidence_id.startswith("SX-"))

        path = Path(stack.ledger.run_dir()) / "evidence.jsonl"
        records = [json.loads(line) for line in
                   path.read_text(encoding="utf-8").splitlines() if line]
        ssh_records = [r for r in records if r.get("producer") == "ssh"]
        self.assertEqual(len(ssh_records), 1)
        self.assertEqual(ssh_records[0]["evidence_id"], evidence_id)
        payload = ssh_records[0]["payload"]
        self.assertIn("rag", payload["stdout"])  # the whoami OUTPUT
        # A later model turn observes exactly this shape.
        self.assertEqual(payload["ssh_result"]["command"], "whoami")
        self.assertEqual(payload["ssh_result"]["exit_code"], 0)

    def test_non_authorized_command_never_reaches_the_transport(self):
        stack = _Stack(self.server.port)
        request = self._model_request("uname", allowlist=("ls",))
        result = stack.runtime.submit(request, stack.mission)
        self.assertEqual(result.broker_result.decision.decision.value, "deny")
        self.assertIn("ssh-command-rejected",
                      result.broker_result.decision.reason)
        self.assertIsNone(result.execution)

    def test_shell_chaining_is_refused_before_any_session(self):
        stack = _Stack(self.server.port)
        request = self._model_request("ls", allowlist=("ls",))
        # A chained purpose must be refused outright, not truncated.
        chained = type(request)(
            sequence=request.sequence, requester=request.requester,
            capability=request.capability, target=request.target,
            purpose='cmd="ls" && cat /etc/shadow', timeout_seconds=20.0)
        result = stack.runtime.submit(chained, stack.mission)
        self.assertEqual(result.broker_result.decision.decision.value, "deny")
        self.assertIn("ssh-command-chaining-rejected",
                      result.broker_result.decision.reason)
        self.assertIsNone(result.execution)

    def test_wrong_password_fails_closed(self):
        stack = _Stack(self.server.port, password="not-the-fixture-password")

        result = stack.runtime.submit(
            self._model_request("ls", allowlist=("ls",)), stack.mission)
        self.assertTrue(result.broker_result.capability_invoked)
        self.assertFalse(result.execution.success)
        self.assertEqual(
            result.execution.evidence["ssh_result"]["state"], "auth_failed")
        # The rejected secret is nowhere in the evidence.
        self.assertNotIn("not-the-fixture-password",
                         json.dumps(result.execution.evidence, default=str))

    def test_credential_flows_to_transport_but_never_into_evidence(self):
        stack = _Stack(self.server.port)

        result = stack.runtime.submit(
            self._model_request("id", allowlist=("id",)), stack.mission)
        self.assertTrue(result.execution.success)
        # Real authentication happened...
        self.assertTrue(result.execution.evidence["authenticated"])
        # ...and the credential appears in NO readable artifact.
        rendered = json.dumps(result.execution.to_dict(), default=str)
        rendered += json.dumps(result.execution.evidence, default=str)
        path = Path(stack.ledger.run_dir()) / "evidence.jsonl"
        rendered += path.read_text(encoding="utf-8")
        rendered += json.dumps(stack.mission.to_dict(), default=str)
        self.assertNotIn(SECRET, rendered)
        self.assertIn("credential_present", rendered)

    def test_output_is_bounded_over_a_real_session(self):
        stack = _Stack(self.server.port, allowlist=("cat /var/log/messages",))
        stack.mission.problem["ssh"]["stdout_limit"] = 64
        result = stack.runtime.submit(
            self._model_request("cat /var/log/messages",
                                allowlist=("cat /var/log/messages",)),
            stack.mission)
        self.assertTrue(result.execution.success)
        self.assertEqual(len(result.execution.evidence["stdout"]), 64)
        self.assertTrue(result.execution.evidence["stdout_truncated"])

    def test_remote_non_zero_exit_is_reported_not_swallowed(self):
        stack = _Stack(self.server.port, allowlist=("cat /etc/shadow",))
        result = stack.runtime.submit(
            self._model_request("cat /etc/shadow",
                                allowlist=("cat /etc/shadow",)),
            stack.mission)
        self.assertTrue(result.execution.success)
        self.assertEqual(result.execution.evidence["exit_code"], 1)
        self.assertIn("Permission denied",
                      result.execution.evidence["stderr"])

    def test_unreachable_target_fails_closed(self):
        """A declared, authorized port with nothing listening fails closed."""
        stack = _Stack(1)  # nothing listening on port 1
        registry = register_default_skills(default_registry())
        request = validate_proposal(
            {"intent": "act", "skill": "network-ssh-session",
             "target": f"ssh://{HOST}:1",
             "purpose": 'cmd="ls" observe'}, registry)
        result = stack.runtime.submit(request, stack.mission)
        self.assertEqual(result.broker_result.decision.decision.value, "allow")
        self.assertFalse(result.execution.success)
        self.assertIn(
            result.execution.evidence["ssh_result"]["state"],
            ("unavailable", "refused", "timeout", "failure"))

    def test_strict_host_key_policy_refuses_unknown_key(self):
        """The fail-closed default is real, not decorative."""
        stack = _Stack(self.server.port, host_key_policy="strict")
        result = stack.runtime.submit(
            self._model_request("ls", allowlist=("ls",)), stack.mission)
        self.assertFalse(result.execution.success)
        self.assertIn(
            result.execution.evidence["ssh_result"]["state"],
            ("unavailable", "refused", "failure"))


if __name__ == "__main__":
    unittest.main()
