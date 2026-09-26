"""Acceptance proof for the AI-assisted governed execution loop.

The system under test is the EXISTING governed seam, not a new one:

    ModelAdapter.propose(ModelContext) -> ActionRequest
      -> BOBRuntime.submit -> BOBBroker.submit
      -> BOBPolicy.consult  (fail-closed ALLOW/DENY)
      -> capability (only on ALLOW)
      -> EvidenceLedger (+ seal.py hash chain)
      -> BOBQualityGate.evaluate (sole COMPLETE authority)

The invariant these tests exist to pin down:

    THE MODEL PROPOSES. RAPHAEL DECIDES. THE MODEL NEVER EXECUTES.

No network access, no credentials, no real targets. RFC 5737 documentation
addresses are used wherever a host string is required.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Dict, Optional

from raphael_ibm_bob.broker import BOBBroker
from raphael_ibm_bob.contracts import (
    ActionRequest,
    Capability,
    Decision,
    Mission,
)
from raphael_ibm_bob.evidence_ledger import EvidenceLedger, create_run_dir
from raphael_ibm_bob.harness.model import ModelContext, ScriptedModelAdapter
from raphael_ibm_bob.policy import BOBPolicy
from raphael_ibm_bob.quality_gate import BOBQualityGate, GateInputs
from raphael_ibm_bob.runtime import BOBRuntime
from raphael_ibm_bob.target_profile import build_target_profile
from raphael_ibm_bob.workspace import Workspace


class _Rig:
    """One governed stack over a throwaway workspace."""

    def __init__(self, scope: Optional[Path] = None) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "allowed").mkdir()
        (self.root / "outside").mkdir()
        self.allowed = self.root / "allowed"
        self.outside = self.root / "outside"
        self.fixture = self.allowed / "fixture.txt"
        self.fixture.write_text("governed fixture\n", encoding="utf-8")
        self.secret = self.outside / "secret.txt"
        self.secret.write_text("must never be read\n", encoding="utf-8")

        _, self.run_dir = create_run_dir(self.root / "runs")
        self.workspace = Workspace(self.root)
        self.ledger = EvidenceLedger(self.run_dir)
        self.broker = BOBBroker(
            policy=BOBPolicy(workspace=self.workspace),
            workspace=self.workspace,
            ledger=self.ledger,
        )
        self.runtime = BOBRuntime(self.broker)
        self.mission = Mission(
            mission_id="m-acceptance",
            description="AI-assisted governed loop acceptance",
            scope=str(self.allowed if scope is None else scope),
            criteria=["every proposal is decided by Raphael, not the model"],
        )

    def request(self, **overrides) -> ActionRequest:
        fields = dict(
            sequence=0,
            requester="assistant:mock",
            capability=Capability.READ,
            target=str(self.fixture),
            purpose="assistant-proposal: inspect the authorized fixture",
        )
        fields.update(overrides)
        return ActionRequest(**fields)

    def kinds(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for record in self.ledger.all_records():
            key = record["kind"]
            counts[key] = counts.get(key, 0) + 1
        return counts

    def close(self) -> None:
        self.ledger.close()
        self._tmp.cleanup()


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.rig = _Rig()
        self.addCleanup(self.rig.close)


class AuthorizedProposalReachesBroker(_Base):
    """1. An authorized proposal is decided ALLOW, executed, and evidenced."""

    def test_read_of_authorized_target_is_allowed_and_evidenced(self) -> None:
        model = ScriptedModelAdapter(
            {self.rig.mission.mission_id: self.rig.request()})
        proposal = model.propose(ModelContext(
            mission=self.rig.mission,
            findings=[],
            workspace_root=str(self.rig.root),
            evidence_count=0,
            session_id="s-acceptance",
        ))

        outcome = self.rig.runtime.submit(proposal, self.rig.mission)

        self.assertEqual(outcome.broker_result.decision.decision,
                         Decision.ALLOW)
        self.assertTrue(outcome.broker_result.capability_invoked)
        self.assertIsNotNone(outcome.execution)
        self.assertTrue(outcome.execution.success)
        self.assertEqual(outcome.execution.error, None)

        kinds = self.rig.kinds()
        self.assertEqual(kinds.get("request"), 1)
        self.assertEqual(kinds.get("decision"), 1)
        self.assertEqual(kinds.get("result"), 1)
        self.assertGreaterEqual(kinds.get("evidence", 0), 1)


class UnauthorizedCapabilityDenied(_Base):
    """2. An unknown capability is denied and nothing executes."""

    def test_unknown_capability_denied_without_execution(self) -> None:
        outcome = self.rig.runtime.submit(
            self.rig.request(capability="not_a_registered_capability"),
            self.rig.mission,
        )

        self.assertEqual(outcome.broker_result.decision.decision, Decision.DENY)
        self.assertIn("capability-not-allowed",
                      outcome.broker_result.decision.reason)
        self.assertFalse(outcome.broker_result.capability_invoked)
        self.assertIsNone(outcome.execution)
        self.assertEqual(self.rig.broker.capability_invocations, 0)

    def test_denial_is_recorded_without_a_result(self) -> None:
        self.rig.runtime.submit(
            self.rig.request(capability="not_a_registered_capability"),
            self.rig.mission,
        )
        kinds = self.rig.kinds()
        self.assertEqual(kinds.get("request"), 1)
        self.assertEqual(kinds.get("decision"), 1)
        self.assertIsNone(kinds.get("result"))


class OutOfScopeTargetDenied(unittest.TestCase):
    """3. A target outside mission scope is denied and never read."""

    def setUp(self) -> None:
        self.rig = _Rig()
        self.addCleanup(self.rig.close)
        self.rig.mission = Mission(
            mission_id="m-scope",
            description="scope enforcement",
            scope=str(self.rig.allowed),
            criteria=["scope is enforced"],
        )

    def test_out_of_scope_read_is_denied(self) -> None:
        outcome = self.rig.runtime.submit(
            self.rig.request(target=str(self.rig.secret)),
            self.rig.mission,
        )

        self.assertEqual(outcome.broker_result.decision.decision, Decision.DENY)
        self.assertIn("scope-mismatch", outcome.broker_result.decision.reason)
        self.assertFalse(outcome.broker_result.capability_invoked)
        self.assertIsNone(outcome.execution)
        self.assertEqual(self.rig.broker.capability_invocations, 0)

    def test_denial_is_evidenced(self) -> None:
        self.rig.runtime.submit(
            self.rig.request(target=str(self.rig.secret)),
            self.rig.mission,
        )
        kinds = self.rig.kinds()
        self.assertEqual(kinds.get("decision"), 1)
        self.assertIsNone(kinds.get("result"))


class MalformedModelOutputRejected(_Base):
    """5. Structurally invalid proposals fail closed and never execute."""

    def test_empty_target_is_rejected_by_runtime(self) -> None:
        with self.assertRaises(ValueError):
            self.rig.runtime.submit(self.rig.request(target=""),
                                    self.rig.mission)
        self.assertEqual(self.rig.broker.capability_invocations, 0)

    def test_empty_requester_is_rejected_by_runtime(self) -> None:
        with self.assertRaises(ValueError):
            self.rig.runtime.submit(self.rig.request(requester=""),
                                    self.rig.mission)
        self.assertEqual(self.rig.broker.capability_invocations, 0)

    def test_empty_purpose_is_rejected_by_runtime(self) -> None:
        with self.assertRaises(ValueError):
            self.rig.runtime.submit(self.rig.request(purpose=""),
                                    self.rig.mission)
        self.assertEqual(self.rig.broker.capability_invocations, 0)

    def test_non_finite_timeouts_are_rejected_before_the_ledger(self) -> None:
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(timeout=bad):
                with self.assertRaises(ValueError):
                    self.rig.runtime.submit(
                        self.rig.request(timeout_seconds=bad),
                        self.rig.mission,
                    )
        self.assertEqual(self.rig.broker.capability_invocations, 0)
        self.assertEqual(self.rig.kinds(), {})

    def test_non_positive_and_non_numeric_timeouts_are_rejected(self) -> None:
        for bad in (0, -1, True, "5"):
            with self.subTest(timeout=bad):
                with self.assertRaises(ValueError):
                    self.rig.runtime.submit(
                        self.rig.request(timeout_seconds=bad),
                        self.rig.mission,
                    )
        self.assertEqual(self.rig.broker.capability_invocations, 0)


class TimeoutBoundIsFailClosed(_Base):
    """9. The execution bound is validated for every capability class."""

    CAPABILITIES = (
        Capability.READ,
        Capability.LIST,
        Capability.SEARCH,
        Capability.WRITE,
        Capability.RUN_TEST,
        Capability.C1A_STATIC_FILE_INSPECT,
    )

    def test_invalid_bounds_rejected_for_every_capability(self) -> None:
        invalid = (float("nan"), float("inf"), float("-inf"), 0, -3, True, "5")
        for capability in self.CAPABILITIES:
            for bound in invalid:
                with self.subTest(capability=capability, bound=bound):
                    with self.assertRaises(ValueError):
                        self.rig.broker.submit(
                            self.rig.request(capability=capability,
                                             timeout_seconds=bound),
                            self.rig.mission,
                        )
        self.assertEqual(self.rig.broker.capability_invocations, 0)
        self.assertEqual(self.rig.kinds(), {})

    def test_valid_bounds_are_not_over_blocked(self) -> None:
        for bound in (None, 0.5, 2, 30):
            with self.subTest(bound=bound):
                outcome = self.rig.broker.submit(
                    self.rig.request(timeout_seconds=bound),
                    self.rig.mission,
                )
                self.assertEqual(outcome.decision.decision, Decision.ALLOW)
                self.assertTrue(outcome.capability_invoked)
                self.assertTrue(outcome.execution.success)


class FailureFeedsNextDecision(_Base):
    """6. A failed execution is recorded and observable by the next step."""

    def test_failed_execution_is_recorded_as_unsuccessful(self) -> None:
        failing = self.rig.allowed / "test_generated_failure.py"
        failing.write_text("def test_x():\n    assert False\n", encoding="utf-8")

        outcome = self.rig.runtime.submit(
            self.rig.request(capability=Capability.RUN_TEST,
                             target=str(failing)),
            self.rig.mission,
        )

        self.assertEqual(outcome.broker_result.decision.decision,
                         Decision.ALLOW)
        self.assertIsNotNone(outcome.execution)
        # The governed attempt happened and is reported as unsuccessful
        # rather than being silently upgraded to success.
        self.assertFalse(outcome.execution.success)
        self.assertTrue(outcome.execution.error)

        results = [r for r in self.rig.ledger.all_records()
                   if r["kind"] == "result"]
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["success"])

    def test_next_context_observes_the_growing_evidence(self) -> None:
        self.rig.runtime.submit(self.rig.request(), self.rig.mission)
        evidence_count = len(self.rig.ledger.all_records())
        self.assertGreater(evidence_count, 0)

        context = ModelContext(
            mission=self.rig.mission,
            findings=[],
            workspace_root=str(self.rig.root),
            evidence_count=evidence_count,
            session_id="s-acceptance",
        )
        self.assertEqual(context.evidence_count, evidence_count)


class ModelCannotSelfCertify(_Base):
    """7. BOBQualityGate is the only authority that may emit COMPLETE."""

    def test_gate_refuses_even_when_caller_claims_success(self) -> None:
        self.rig.runtime.submit(self.rig.request(), self.rig.mission)

        verdict = BOBQualityGate(self.rig.ledger).evaluate(GateInputs(
            mission=self.rig.mission,
            findings=[],
            regression_ok=True,      # the caller claims tests passed
            behavior_probe_ok=True,  # the caller claims the probe passed
        ))

        self.assertEqual(verdict.verdict.value, "refuse")
        self.assertTrue(
            {"B:required-tests", "C:regression"} & set(verdict.failed),
            f"expected an evidence-backed condition to fail, got {verdict.failed}")
        self.assertTrue(verdict.reasons)

    def test_gate_refuses_on_an_empty_ledger(self) -> None:
        verdict = BOBQualityGate(self.rig.ledger).evaluate(GateInputs(
            mission=self.rig.mission,
            findings=[],
            regression_ok=True,
            behavior_probe_ok=True,
        ))
        self.assertEqual(verdict.verdict.value, "refuse")
        self.assertIn("F:evidence", verdict.failed)


class TargetAgnosticTwoTargets(_Base):
    """8. Different authorized targets yield different governed decisions
    with NO change to Raphael source."""

    def test_two_profiles_bind_two_hosts_with_no_code_change(self) -> None:
        first = build_target_profile(
            mission_id="m-target-a",
            locator="198.51.100.10",
            allowed_ports=[80],
            allowed_protocols=["http"],
            authorization_ref="engagement://target-a",
        )
        second = build_target_profile(
            mission_id="m-target-b",
            locator="203.0.113.20",
            allowed_ports=[8080],
            allowed_protocols=["http"],
            authorization_ref="engagement://target-b",
        )

        self.assertNotEqual(first.target_id, second.target_id)
        self.assertTrue(first.allows(host="198.51.100.10", port=80,
                                     protocol="http"))
        # Scope is host-specific: profile A must not authorize host B.
        self.assertFalse(first.allows(host="203.0.113.20", port=8080,
                                      protocol="http"))
        self.assertTrue(second.allows(host="203.0.113.20", port=8080,
                                      protocol="http"))
        self.assertFalse(second.allows(host="198.51.100.10", port=80,
                                       protocol="http"))

    def test_same_code_gives_different_decisions_per_target(self) -> None:
        mission_a = Mission(mission_id="m-target-a", description="a",
                            scope=str(self.rig.allowed), criteria=["c"])
        mission_b = Mission(mission_id="m-target-b", description="b",
                            scope=str(self.rig.allowed), criteria=["c"])
        rig = self.rig

        class PerTargetAdapter:
            def propose(self, context: ModelContext) -> ActionRequest:
                if context.mission.mission_id == "m-target-a":
                    return ActionRequest(
                        sequence=0, requester="assistant:mock",
                        capability=Capability.READ,
                        target=str(rig.fixture),
                        purpose="assistant-proposal: target A observation")
                return ActionRequest(
                    sequence=0, requester="assistant:mock",
                    capability=Capability.LIST,
                    target=str(rig.allowed),
                    purpose="assistant-proposal: target B observation")

        model = PerTargetAdapter()
        proposal_a = model.propose(ModelContext(
            mission=mission_a, findings=[], workspace_root=str(rig.root),
            evidence_count=0, session_id="s"))
        proposal_b = model.propose(ModelContext(
            mission=mission_b, findings=[], workspace_root=str(rig.root),
            evidence_count=0, session_id="s"))

        self.assertNotEqual(proposal_a.capability, proposal_b.capability)

        result_a = rig.runtime.submit(proposal_a, mission_a)
        result_b = rig.runtime.submit(proposal_b, mission_b)
        self.assertEqual(result_a.broker_result.decision.decision,
                         Decision.ALLOW)
        self.assertEqual(result_b.broker_result.decision.decision,
                         Decision.ALLOW)
        self.assertEqual(rig.broker.capability_invocations, 2)


class LoopIsBounded(_Base):
    """10. The model loop is explicitly bounded and fails loudly."""

    def test_scripted_adapter_raises_on_exhaustion(self) -> None:
        model = ScriptedModelAdapter({})
        with self.assertRaises(KeyError):
            model.propose(ModelContext(
                mission=self.rig.mission, findings=[],
                workspace_root=str(self.rig.root), evidence_count=0,
                session_id="s"))

    def test_run_model_mission_stops_at_max_turns(self) -> None:
        from raphael_ibm_bob.harness.model_run import run_model_mission
        from raphael_ibm_bob.harness.session import (
            RaphaelSession,
            WorkspaceContext,
        )

        rig = self.rig
        session = RaphaelSession.create(
            session_id="s-bounded",
            mission=rig.mission,
            workspace=WorkspaceContext(workspace_root=str(rig.root),
                                       project_name="acceptance"),
        )
        model = ScriptedModelAdapter(
            {rig.mission.mission_id: rig.request()})

        outcome = run_model_mission(
            session, rig.mission, rig.root,
            runs_root=rig.root / "runs", model=model, max_turns=2,
        )

        self.assertEqual(outcome.turns, 2)
        self.assertEqual(outcome.terminal, "max-turns")
        self.assertIn("max_turns=2", outcome.terminal_reason)


if __name__ == "__main__":
    unittest.main()
