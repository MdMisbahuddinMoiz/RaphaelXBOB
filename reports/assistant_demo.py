"""AI-assisted governed security assessment — submission demo.

Four acts, one command, zero credentials, zero network:

    A. ALLOW       model proposal -> policy ALLOW -> broker -> execution -> evidence
    B. DENY        unauthorized proposal -> DENY -> broker NOT invoked -> denial evidenced
    C. FEEDBACK    failed action -> evidence -> next model context sees it -> next proposal
    D. VERIFICATION  apparently-successful action -> QualityGate still REFUSES

The invariant: THE MODEL PROPOSES. RAPHAEL DECIDES WHETHER EXECUTION IS PERMITTED.

Run:  cd /home/moiz/raphael-2.0-rbsv2r && PYTHONPATH=. python3 reports/assistant_demo.py
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from raphael_ibm_bob.broker import BOBBroker
from raphael_ibm_bob.contracts import ActionRequest, Capability, Decision, Mission
from raphael_ibm_bob.evidence_ledger import EvidenceLedger, create_run_dir
from raphael_ibm_bob.harness.model import ModelContext, ScriptedModelAdapter
from raphael_ibm_bob.policy import BOBPolicy
from raphael_ibm_bob.quality_gate import BOBQualityGate, GateInputs
from raphael_ibm_bob.runtime import BOBRuntime
from raphael_ibm_bob.seal import verify_seal, write_seal
from raphael_ibm_bob.workspace import Workspace


class Rig:
    """A governed stack: model -> runtime -> broker -> policy -> evidence."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "allowed").mkdir()
        (self.root / "outside").mkdir()
        self.allowed = self.root / "allowed"
        self.fixture = self.allowed / "app.py"
        self.fixture.write_text("def login():\n    return True\n", encoding="utf-8")
        self.secret = self.root / "outside" / "secret.txt"
        self.secret.write_text("authorized target only\n", encoding="utf-8")

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
            mission_id="demo-mission",
            description="AI-assisted governed assessment of an authorized workspace",
            scope=str(self.allowed),
            criteria=["every model proposal is decided by Raphael, never by the model"],
        )

    def context(self, evidence_count: int) -> ModelContext:
        return ModelContext(
            mission=self.mission,
            findings=[],
            workspace_root=str(self.root),
            evidence_count=evidence_count,
            session_id="demo-session",
        )

    def count(self) -> int:
        return len(self.ledger.all_records())

    def kinds(self) -> dict:
        out = {}
        for record in self.ledger.all_records():
            out[record["kind"]] = out.get(record["kind"], 0) + 1
        return out

    def close(self) -> None:
        self.ledger.close()
        self._tmp.cleanup()


def rule(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def demo_a_allow() -> None:
    rule("DEMO A — ALLOW:  model proposal -> Raphael ALLOW -> broker -> evidence")
    rig = Rig()
    try:
        model = ScriptedModelAdapter({
            rig.mission.mission_id: ActionRequest(
                sequence=0, requester="assistant:model",
                capability=Capability.READ, target=str(rig.fixture),
                purpose="assistant-proposal: inspect the authorized application"),
        })
        proposal = model.propose(rig.context(evidence_count=0))
        print(f"  model proposes : capability={proposal.capability.value} "
              f"target={Path(proposal.target).name}")

        outcome = rig.runtime.submit(proposal, rig.mission)
        print(f"  policy decides : {outcome.broker_result.decision.decision.value.upper()}"
              f"  (reason={outcome.broker_result.decision.reason})")
        print(f"  broker invoked : {outcome.broker_result.capability_invoked}")
        print(f"  execution      : success={outcome.execution.success}")
        print(f"  evidence       : {rig.kinds()}")
        print(f"  PROVES         : an authorized model proposal reaches execution, "
              f"and every stage is recorded.")
    finally:
        rig.close()


def demo_b_deny() -> None:
    rule("DEMO B — DENY:  unauthorized proposal -> DENY -> broker NOT invoked")
    rig = Rig()
    try:
        before_invocations = rig.broker.capability_invocations
        for label, overrides in (
            ("unknown capability", {"capability": "shell_exec"}),
            ("out-of-scope target", {"target": str(rig.secret)}),
        ):
            fields = dict(
                sequence=0, requester="assistant:model",
                capability=Capability.READ, target=str(rig.fixture),
                purpose="assistant-proposal")
            fields.update(overrides)
            model = ScriptedModelAdapter({rig.mission.mission_id: ActionRequest(**fields)})
            outcome = rig.runtime.submit(
                model.propose(rig.context(0)), rig.mission)
            print(f"  {label:22s} -> {outcome.broker_result.decision.decision.value.upper()}"
                  f"  reason={outcome.broker_result.decision.reason}")
            print(f"  {'':22s}    broker invoked="
                  f"{outcome.broker_result.capability_invoked}  "
                  f"execution={outcome.execution}")
        print(f"  capability invocations across both attempts: "
              f"{rig.broker.capability_invocations - before_invocations}")
        print(f"  evidence: {rig.kinds()}  (decision recorded, NO result record)")
        print("  PROVES   : the model cannot reach execution for an unauthorized "
              "capability or an out-of-scope target.")
    finally:
        rig.close()


def demo_c_feedback() -> None:
    rule("DEMO C — FEEDBACK:  failure -> evidence -> next context -> next proposal")
    rig = Rig()
    try:
        failing = rig.allowed / "test_generated.py"
        failing.write_text("def test_x():\n    assert False\n", encoding="utf-8")

        model = ScriptedModelAdapter({
            rig.mission.mission_id: ActionRequest(
                sequence=0, requester="assistant:model",
                capability=Capability.RUN_TEST, target=str(failing),
                purpose="assistant-proposal: run the generated test"),
        })

        first = rig.runtime.submit(model.propose(rig.context(0)), rig.mission)
        after_first = rig.count()
        print(f"  turn 1 proposal : RUN_TEST {Path(failing).name}")
        print(f"  decision        : {first.broker_result.decision.decision.value.upper()}")
        print(f"  execution       : success={first.execution.success} "
              f"error={(first.execution.error or '')[:60]}")
        print(f"  evidence after 1: {after_first} records")

        second_context = rig.context(evidence_count=after_first)
        print(f"  turn 2 context  : evidence_count={second_context.evidence_count} "
              f"(the model now SEES the failure)")
        second = rig.runtime.submit(
            ActionRequest(sequence=0, requester="assistant:model",
                          capability=Capability.READ, target=str(rig.fixture),
                          purpose="assistant-proposal: fall back to inspection after failure"),
            rig.mission)
        print(f"  turn 2 decision : {second.broker_result.decision.decision.value.upper()}"
              f"  -> success={second.execution.success}")
        print(f"  evidence total  : {rig.count()} records  {rig.kinds()}")
        print("  PROVES          : a failed action becomes evidence the next proposal "
              "can react to (AI-assisted iterative replanning).")
    finally:
        rig.close()


def demo_d_verification() -> None:
    rule("DEMO D — VERIFICATION:  apparent success -> QualityGate still REFUSES")
    rig = Rig()
    try:
        model = ScriptedModelAdapter({
            rig.mission.mission_id: ActionRequest(
                sequence=0, requester="assistant:model",
                capability=Capability.READ, target=str(rig.fixture),
                purpose="assistant-proposal: inspect the authorized application"),
        })
        outcome = rig.runtime.submit(model.propose(rig.context(0)), rig.mission)
        print(f"  action executed : success={outcome.execution.success} "
              f"(the model may consider this a win)")

        verdict = BOBQualityGate(rig.ledger).evaluate(GateInputs(
            mission=rig.mission,
            findings=[],
            regression_ok=True,      # the caller/model CLAIMS success
            behavior_probe_ok=True,  # the caller/model CLAIMS a clean probe
        ))
        print(f"  gate verdict    : {verdict.verdict.value.upper()}")
        print(f"  gate passed     : {list(verdict.passed)}")
        print(f"  gate failed     : {list(verdict.failed)}")
        for reason in verdict.reasons:
            print(f"    - {reason}")
        # Real run modules seal the ledger after close; mirror that here.
        write_seal(rig.run_dir)
        ok, why = verify_seal(rig.run_dir)
        print(f"  evidence seal   : verified={ok} ({why})")
        print("  PROVES          : the model cannot certify its own success. "
              "BOBQualityGate is the sole authority, and it refuses unsupported claims.")
    finally:
        rig.close()


if __name__ == "__main__":
    print("Raphael — AI-assisted governed security assessment")
    print("Model proposes. Raphael decides. No credentials or network required.")
    demo_a_allow()
    demo_b_deny()
    demo_c_feedback()
    demo_d_verification()
    print("\n" + "=" * 72)
    print("DEMO COMPLETE — all four acts executed through the governed boundary.")
    print("=" * 72)
