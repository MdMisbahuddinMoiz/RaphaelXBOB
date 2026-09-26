"""raphael_ibm_bob.harness.model_run — governed multi-turn model run.

Promotes the live model loop (previously demo-only) into the Harness
as a reusable, mission-generic component. The model only PROPOSES;
every proposal is validated against the skill registry and submitted
through the existing Runtime -> Broker -> Policy boundary. The loop
performs NO authorization and NO gating of its own: it coordinates
turns, registers a finding when the model applies a remediation, asks
the existing Verifier/Falsifier to retest/challenge it, persists
probe/regression proofs, and finally asks the existing QualityGate
for the verdict.

This module contains NO subprocess and NO capability dispatch. The
optional `probe` is a caller-supplied callable (an independent
oracle the caller owns); the Harness only consumes its boolean result
and persists the corresponding evidence record.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from raphael_ibm_bob.broker import BOBBroker
from raphael_ibm_bob.contracts import (
    Capability,
    Finding,
    FindingState,
    Mission,
    capability_id,
)
from raphael_ibm_bob.evidence_ledger import (
    EvidenceLedger,
    create_run_dir,
    digest_id,
)
from raphael_ibm_bob.falsifier import ChallengeSpec, Falsifier
from raphael_ibm_bob.finding import FindingStore
from raphael_ibm_bob.harness.loop import excerpt_output
from raphael_ibm_bob.harness.model import ModelAdapter, ModelContext
from raphael_ibm_bob.harness.providers import (
    DoneSignal,
    ProviderError,
    StructuredProposalError,
)
from raphael_ibm_bob.harness.run import RaphaelRun, save_run
from raphael_ibm_bob.harness.session import RaphaelSession, save_session
from raphael_ibm_bob.policy import BOBPolicy
from raphael_ibm_bob.quality_gate import BOBQualityGate, GateInputs
from raphael_ibm_bob.runtime import BOBRuntime
from raphael_ibm_bob.seal import write_seal
from raphael_ibm_bob.specialization import (
    TaskState,
    decompose_mission,
    default_roles,
)
from raphael_ibm_bob.verifier import RetestSpec, Verifier
from raphael_ibm_bob.workspace import Workspace


#: How many folded observations are handed to the model per turn. The
#: ledger is append-only and grows; the model context must stay bounded.
MAX_OBSERVATIONS = 8

#: How many discovered ports are named per observation. Enough to plan
#: a follow-up, small enough to keep the prompt bounded.
MAX_OBSERVED_PORTS = 32


def authorized_session_view(mission: Mission) -> Optional[dict]:
    """What the model must know to make a LEGAL session proposal.

    Without this the model can only guess a command, and a guessed
    command is denied by Policy exactly as an illegal one would be —
    which looks like a governance failure but is really a missing
    declaration. This carries the operator's authorized scope only; it
    grants nothing and is still checked at Broker -> Policy time.
    """
    raw = (mission.problem or {}).get("ssh")
    if not isinstance(raw, dict):
        return None
    commands = [str(c) for c in (raw.get("authorized_commands")
                                 or raw.get("commands") or ())]
    if not commands:
        return None
    return {
        "protocol": str(raw.get("protocol", "ssh")),
        "target": str(raw.get("target", "")),
        "username": str(raw.get("username", "")),
        "authorized_commands": commands,
        "one_command_per_request": True,
        "how_to_propose": (
            "Write the rationale first, then END the purpose with the "
            "literal clause cmd= (c-m-d-EQUALS) followed by the whole "
            "command in double quotes, e.g. Read the remote note "
            "cmd=\"cat note.txt\". The equals sign is REQUIRED; without "
            "it the request is denied as carrying no command. The "
            "clause MUST be last -- a shell operator after it is "
            "denied as chaining. Use ONLY a command from "
            "authorized_commands. Its output is returned to you "
            "verbatim on the next turn, so read it before proposing "
            "the same command again."),
    }

#: Ledger record kinds that carry a discovery result. Discovery writes
#: `producer="discovery"`; the result record carries the port table.
DISCOVERY_PRODUCERS = ("discovery",)


def _port_table(discovery_result: dict) -> list:
    """Open ports + service names from one discovery result payload."""
    rows = []
    for entry in (discovery_result.get("port_results") or []):
        if entry.get("state") != "open":
            continue
        rows.append({
            "port": entry.get("port"),
            "service": entry.get("service"),
            "latency_ms": entry.get("latency_ms"),
        })
    return rows[:MAX_OBSERVED_PORTS]


def fold_observations(ledger: EvidenceLedger) -> Tuple[dict, ...]:
    """Fold ledger evidence into bounded, model-facing observations.

    Read-only and derived: nothing here grants authority, and nothing
    is invented. A NETWORK_SERVICE_DISCOVERY invocation contributes one
    observation naming the host, the ports it probed, and the ports that
    actually answered — that is what lets the model choose a NEXT
    governed action from real evidence instead of repeating the last
    one. Provider output stays labelled `provider_untrusted`.

    Bounded to the most recent `MAX_OBSERVATIONS`; ledger order is
    append-only, so the tail is the newest evidence.
    """
    observations: List[dict] = []
    for record in ledger.all_records():
        if record.get("producer") not in DISCOVERY_PRODUCERS:
            continue
        payload = record.get("payload")
        if not isinstance(payload, dict):
            continue
        result = payload.get("discovery_result") or {}
        observations.append({
            "kind": "service-discovery",
            "capability": payload.get("capability")
            or Capability.NETWORK_SERVICE_DISCOVERY.value,
            "host": payload.get("host") or result.get("host"),
            "ports_probed": payload.get("ports_probed"),
            "ports_open": list(payload.get("ports_open") or []),
            "open_services": _port_table(result),
            "state": result.get("state"),
            # A sweep is a SAMPLE, not proof of absence. The model must
            # see this explicitly or it will read "no open ports" as
            # "nothing is listening" and stop, when in fact only a
            # bounded window of the port space was probed.
            "capped": bool(payload.get("capped")),
            "exhaustive": False,
            "probed_ports": list(payload.get("probed_ports") or ()),
            "unprobed_hint": (
                "Only the ports listed in probed_ports were checked. "
                "A closed port there means closed AT THAT PORT ONLY; "
                "services may still exist on ports outside this sweep. "
                "Request a different ports= range to widen coverage."
                if payload.get("ports_probed") else ""),
            "provider_untrusted": True,
            "evidence_id": record.get("evidence_id"),
        })
    return tuple(observations[-MAX_OBSERVATIONS:])


@dataclass(frozen=True)
class AgentTurn:
    """One governed turn, as the operator sees it.

    Records the full OBSERVE -> PROPOSE -> POLICY -> EXECUTE -> EVIDENCE
    chain for a single step. `rationale` is the model's own one-line
    `purpose` (the structured contract forbids free-form reasoning, so
    no chain-of-thought is stored or displayed); `next_action` states
    what the loop will do next. Presentation-only: the authoritative
    record is the evidence ledger this turn also wrote.
    """
    index: int
    observation: dict
    proposal: dict
    rationale: str
    policy: dict
    execution: dict
    evidence: dict
    next_action: str

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "observation": self.observation,
            "proposal": self.proposal,
            "rationale": self.rationale,
            "policy": self.policy,
            "execution": self.execution,
            "evidence": self.evidence,
            "next_action": self.next_action,
        }


def write_timeline(run_dir: Path, turns: List[AgentTurn], terminal: str,
                   terminal_reason: str, gate_verdict: Optional[str]
                   ) -> Path:
    """Persist the operator-facing governed loop projection.

    Written after the ledger closes so every turn's evidence references
    are final. Never raises: the ledger is the authoritative record and
    this file is a read-only convenience projection over it.
    """
    path = run_dir / "timeline.json"
    payload = {
        "turns": [t.to_dict() for t in turns],
        "terminal": terminal,
        "terminal_reason": terminal_reason,
        "gate_verdict": gate_verdict,
    }
    try:
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    except OSError as exc:  # pragma: no cover - filesystem fault
        _log.warning("timeline write failed: %s", type(exc).__name__)
    return path


def _observation_view(observations: Tuple[dict, ...]) -> dict:
    """Compact OBSERVE snapshot for one turn (bounded, no credentials)."""
    latest = observations[-1] if observations else None
    return {
        "observation_count": len(observations),
        "services_known": sorted({
            entry["port"]
            for obs in observations
            for entry in (obs.get("open_services") or [])
            if entry.get("port") is not None
        }),
        "latest": latest,
    }


def _evidence_view(result, output: str) -> dict:
    """Compact EVIDENCE snapshot for one turn, from the governed result.

    `evidence_ids` are the ledger's own append-only record ids, so the
    operator view points at the authoritative chain rather than a
    parallel copy. Discovery payloads stay flagged `provider_untrusted`
    — a scan result is evidence, never a verified finding.
    """
    execution = result.execution
    return {
        "evidence_ids": list(result.evidence_ids),
        "request_seq": result.request_seq,
        "decision_seq": result.decision_seq,
        "result_seq": result.result_seq,
        "provider_untrusted": bool(
            (execution.evidence or {}).get("provider_untrusted"))
        if execution else False,
        "excerpt": (output or "")[:400],
    }


ProbeCallable = Callable[[], bool]

_log = logging.getLogger(__name__)


def _try_write_seal(run_dir: Path) -> None:
    """Write seal.json after ledger close; never raises.

    Mirrors ``network_run._try_write_seal`` so an AI-assisted run carries
    the same tamper-evident hash chain as a network run. Without this the
    model path left ``verify_seal`` reporting ``missing-seal``. A seal
    failure is logged, never fatal: it must not alter the run's verdict,
    state, or evidence records.
    """
    try:
        write_seal(run_dir)
    except Exception as exc:  # noqa: BLE001 — intentional fail-safe
        _log.warning(
            "seal write failed for run %s: %s: %s",
            run_dir.name, type(exc).__name__, exc,
        )


#: Single source of truth for the model-loop turn bound. Referenced by
#: `harness.api.start_model_run` and the HTTP layer so an omitted
#: `max_turns` means the SAME thing on every entry point (M15.2 parity).
DEFAULT_MAX_TURNS = 14

#: Which pipeline step each capability advances (M14 orchestration).
_CAPABILITY_STEP = {
    Capability.READ: "investigate",
    Capability.LIST: "investigate",
    Capability.SEARCH: "investigate",
    Capability.RUN_TEST: "reproduce",
    Capability.WRITE: "remediate",
}


def _roles_context() -> Tuple[dict, ...]:
    """Compact, deterministic role vocabulary for the model."""
    return tuple({
        "role": role.id,
        "purpose": role.purpose,
        "capabilities": sorted(c.value for c in role.capabilities),
    } for role in default_roles().list_roles())


def _task_context(plan) -> dict:
    root = plan.root
    return {
        "task_id": root.task_id,
        "name": root.name,
        "role": root.role,
        "steps": [{"task_id": t.task_id, "name": t.name,
                   "role": t.role, "skills": list(t.skills),
                   "state": plan.states[t.task_id].value}
                  for t in root.subtasks],
    }


def _advance_task(plan, mission_id: str, capability: Capability,
                  success: bool) -> None:
    """Nudge the matching pipeline step's state (declaration only).

    Guarded: only PENDING -> ACTIVE and ACTIVE -> COMPLETED are
    applied; any other current state is left untouched. Never affects
    the QualityGate.
    """
    step = _CAPABILITY_STEP.get(capability)
    if step is None:
        return
    task_id = f"{mission_id}::{step}"
    if task_id not in plan.states:
        return
    current = plan.states[task_id]
    if current is TaskState.PENDING:
        plan.mark(task_id, TaskState.ACTIVE)
    elif current is TaskState.ACTIVE and success:
        plan.mark(task_id, TaskState.COMPLETED)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _terminal_reason(exc: BaseException) -> str:
    """Redacted, bounded reason string for a non-`done` terminal.

    Provider errors are already redacted by the adapter; this only
    bounds length so a malformed model response cannot bloat records.
    """
    return f"{type(exc).__name__}:{exc}"[:500]


def _workspace_files(workspace_root: Path, mission: Mission,
                     limit: int = 40) -> Tuple[str, ...]:
    """Bounded, deterministic listing of in-scope files for context.

    Lists regular files under `workspace_root/<mission.scope>` (or the
    root when scope is empty), sorted, capped. Gives the model the
    file surface without dumping the whole repository.
    """
    root = Path(workspace_root)
    base = root / mission.scope if mission.scope else root
    if not base.is_dir():
        base = root
    files: List[str] = []
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        if any(part == "__pycache__" for part in path.parts):
            continue
        try:
            files.append(path.relative_to(root).as_posix())
        except ValueError:
            continue
        if len(files) >= limit:
            break
    return tuple(files)


def _latest_bound_execution(ledger: EvidenceLedger):
    records = ledger.all_records()
    decisions = {r.get("request_seq"): r.get("decision") for r in records
                 if r.get("kind") == "decision"}
    results = {r.get("request_seq"): r for r in records
               if r.get("kind") == "result"}
    req_seq = None
    for r in records:
        if r.get("kind") != "request":
            continue
        seq = r.get("seq")
        if (decisions.get(seq) == "allow"
                and results.get(seq, {}).get("success") is True):
            req_seq = seq
    if req_seq is None:
        return 0, 0, None
    decs = [r for r in records if r.get("kind") == "decision"
            and r.get("request_seq") == req_seq]
    dec_seq = decs[-1].get("seq") if decs else 0
    res_seq = (results.get(req_seq) or {}).get("seq")
    return req_seq, dec_seq, res_seq


def _persist_proof(ledger: EvidenceLedger, kind: str, ok: bool) -> None:
    req_seq, dec_seq, res_seq = (0, 0, None)
    if ok:
        req_seq, dec_seq, res_seq = _latest_bound_execution(ledger)
    if kind == "probe":
        payload = {"kind": "probe",
                   "result": "passed" if ok else "failed",
                   "allowed": ok, "request_seq": req_seq,
                   "result_seq": res_seq}
        prefix = "PB"
    else:
        payload = {"kind": "regression",
                   "result": "passed" if ok else "failed",
                   "request_seq": req_seq, "result_seq": res_seq}
        prefix = "RG"
    ledger.append_evidence(
        evidence_id=digest_id(payload, prefix=prefix),
        producer=kind, request_seq=req_seq, decision_seq=dec_seq,
        result_seq=res_seq, payload=payload)


def passing_run_tests(ledger: EvidenceLedger) -> bool:
    """True iff some RUN_TEST executed with artifact returncode 0.

    Reads the persisted result artifacts — the same evidence the
    QualityGate inspects — so a failing test does not count.
    """
    records = ledger.all_records()
    run_test_seqs = {
        rec.get("seq") for rec in records
        if rec.get("kind") == "request"
        and rec.get("capability") == "run_test"
    }
    for rec in records:
        if rec.get("kind") != "result":
            continue
        if rec.get("request_seq") not in run_test_seqs:
            continue
        ref = rec.get("artifact_ref", "")
        try:
            data = json.loads(Path(ref).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if data.get("success") is True and \
                (data.get("evidence") or {}).get("returncode") == 0:
            return True
    return False


@dataclass
class ModelRunResult:
    """Authoritative run record plus terminal-loop details."""
    run: RaphaelRun
    terminal: str
    turns: int
    gate_verdict: Optional[str]
    task_plan: Optional[dict] = None
    terminal_reason: str = ""
    #: Absolute path of the persisted governed-loop projection, or "" if
    #: the run failed before the ledger closed. Read-only convenience
    #: projection; the evidence ledger remains authoritative.
    timeline: str = ""


def run_model_mission(session: RaphaelSession, mission: Mission,
                      workspace_root: Path, *, runs_root: Path,
                      model: ModelAdapter,
                      sessions_root: Optional[Path] = None,
                      max_turns: int = DEFAULT_MAX_TURNS,
                      probe: Optional[ProbeCallable] = None,
                      history_window: int = 5,
                      target_store: object = None) -> ModelRunResult:
    """Drive one governed, model-led mission to a terminal state.

    The loop is strictly:

        OBSERVE  fold_observations(ledger) -> ModelContext
        MODEL    model.propose(context) -> ActionRequest   (proposal only)
        PROPOSE  record the request, its capability, and the rationale
        POLICY   runtime.submit -> Broker -> Policy         (the ONLY path)
        EXECUTE  broker-mediated capability invocation
        EVIDENCE append-only ledger records become next turn's input

    The model never holds a capability, mediator, socket, or subprocess
    handle: it returns an `ActionRequest` and nothing else. Execution
    authority belongs to Runtime -> Broker -> Policy exclusively.

    `target_store` is injected so a network mission's declared
    `TargetProfile` is consulted explicitly rather than via the
    process-wide fallback. Policy still re-derives permission from it.

    The `RaphaelRun.state` becomes `completed`/`refused` per the
    QualityGate verdict, or `failed` when the loop itself raises. A
    model error is not fatal: it ends the turn loop and the gate
    judges whatever evidence exists.
    """
    run_id, run_dir = create_run_dir(runs_root)
    run = RaphaelRun(
        run_id=run_id,
        session_id=session.session_id,
        mission=mission,
        workspace_root=str(workspace_root),
        state="running",
        ledger_dir=str(run_dir),
    )
    session.add_run(run_id)
    # Persist the run record immediately (state="running") so an active
    # model run is observable while it executes (live operator streaming).
    save_run(run)

    workspace = Workspace(workspace_root)
    ledger = EvidenceLedger(run_dir)
    terminal = "max-turns"
    terminal_reason = ""
    turn_log: List[dict] = []
    agent_turns: List[AgentTurn] = []
    current_finding_id: Optional[str] = None
    plan = None

    try:
        policy = BOBPolicy(workspace, target_store=target_store)
        broker = BOBBroker(policy, workspace, ledger=ledger,
                           target_store=target_store)
        runtime = BOBRuntime(broker)
        store = FindingStore(ledger)
        verifier = Verifier(runtime, ledger, store)
        falsifier = Falsifier(runtime, ledger, store)
        gate = BOBQualityGate(ledger)
        files = _workspace_files(Path(workspace_root), mission)
        plan = decompose_mission(mission)
        roles_ctx = _roles_context()

        for index in range(max_turns):
            observed = fold_observations(ledger)
            context = ModelContext(
                mission=mission,
                findings=list(store.all()),
                workspace_root=str(workspace_root),
                evidence_count=len(ledger.all_records()),
                workspace_files=files,
                recent_turns=tuple(turn_log[-history_window:]),
                session_id=session.session_id,
                available_roles=roles_ctx,
                active_task=_task_context(plan),
                observations=observed,
                authorized_session=authorized_session_view(mission),
            )
            try:
                request = model.propose(context)
            except DoneSignal:
                terminal = "done"
                terminal_reason = "model declared done"
                agent_turns.append(AgentTurn(
                    index=index,
                    observation=_observation_view(observed),
                    proposal={"intent": "done"},
                    rationale="model declared the mission complete",
                    policy={"decision": "n/a",
                            "reason": "terminal signal, no action proposed"},
                    execution={"executed": False},
                    evidence={"evidence_count": len(ledger.all_records())},
                    next_action="stop: hand control to the QualityGate",
                ))
                break
            except (StructuredProposalError, ProviderError, KeyError) as exc:
                terminal = "model-error"
                terminal_reason = _terminal_reason(exc)
                break

            try:
                result = runtime.submit(request, mission)
            except Exception as exc:
                terminal = "runtime-error"
                terminal_reason = _terminal_reason(exc)
                break

            decision = result.broker_result.decision
            turn = {
                "capability": capability_id(request.capability),
                "target": request.target,
                "decision": decision.decision.value,
                "executed": result.broker_result.capability_invoked,
                "success": (result.execution.success
                            if result.execution else None),
                "output": "",
                "error": "",
            }
            if result.execution is not None:
                turn["output"] = (
                    excerpt_output(request, result.execution) or "")[:800]
            agent_turns.append(AgentTurn(
                index=index,
                observation=_observation_view(observed),
                proposal={
                    "capability": capability_id(request.capability),
                    "target": request.target,
                    "requester": request.requester,
                },
                rationale=(request.purpose or "")[:300],
                policy={
                    "decision": decision.decision.value,
                    "reason": decision.reason,
                },
                execution={
                    "executed": result.broker_result.capability_invoked,
                    "success": (result.execution.success
                                if result.execution else None),
                    "error": (result.execution.error
                              if result.execution else None),
                },
                evidence=_evidence_view(result, turn["output"]),
                next_action=(
                    "re-observe the ledger and propose the next governed "
                    "action"),
            ))

            if (request.capability is Capability.WRITE
                    and decision.decision.value == "allow"):
                previous = (store.get(current_finding_id)
                            if current_finding_id else None)
                finding = Finding(
                    finding_id=f"F-{run_id[-6:]}-{index:02d}",
                    state=FindingState.UNVERIFIED,
                    summary=f"model-proposed fix: {request.target}",
                    target=request.target,
                    supersedes=(previous.finding_id
                                if previous is not None else None),
                )
                store.register(finding)
                if previous is not None and \
                        previous.state is FindingState.REFUTED:
                    store.transition(
                        previous.finding_id, FindingState.SUPERSEDED,
                        evidence_seqs=(),
                        supersedes=finding.finding_id)
                current_finding_id = finding.finding_id
                verify_out = verifier.verify(
                    finding,
                    RetestSpec(capability=Capability.READ,
                               target=request.target,
                               expected_substring=None),
                    mission, requester="harness")
                if verify_out.transition_applied and probe is not None:
                    try:
                        probe_ok_now = bool(probe())
                    except Exception:
                        probe_ok_now = False
                    falsifier.challenge(
                        store.get(finding.finding_id),
                        ChallengeSpec(
                            capability=Capability.READ,
                            target=request.target,
                            purpose="harness:probe-counter-example",
                            predicate=(lambda _p, _ok=probe_ok_now: not _ok)),
                        mission, requester="harness")

            turn_log.append(turn)
            _advance_task(plan, mission.mission_id,
                          request.capability, bool(turn["success"]))

        probe_ok: Optional[bool] = None
        if probe is not None:
            try:
                probe_ok = bool(probe())
            except Exception:
                probe_ok = False
            _persist_proof(ledger, "probe", probe_ok)
        tests_ok = passing_run_tests(ledger)
        _persist_proof(ledger, "regression", tests_ok)

        if terminal == "max-turns":
            terminal_reason = f"reached max_turns={max_turns}"

        evaluation = gate.evaluate(GateInputs(
            mission=mission,
            findings=list(store.all()),
            regression_ok=tests_ok,
            behavior_probe_ok=bool(probe_ok),
        ))
        run.gate_verdict = evaluation.verdict.value
        run.finding_ids = [f.finding_id for f in store.all()]
        run.state = ("completed"
                     if evaluation.verdict.value == "complete"
                     else "refused")
        run.finished_at = _utcnow()
    except Exception as exc:
        run.state = "failed"
        run.failure_reason = f"{type(exc).__name__}:{exc}"
        run.finished_at = _utcnow()
        save_run(run)
        ledger.close()
        _try_write_seal(run_dir)
        write_timeline(run_dir, agent_turns, terminal, terminal_reason,
                       run.gate_verdict)
        if sessions_root is not None:
            save_session(session, sessions_root)
        raise
    save_run(run)
    ledger.close()
    _try_write_seal(run_dir)
    timeline = str(write_timeline(run_dir, agent_turns, terminal,
                                  terminal_reason, run.gate_verdict))
    if sessions_root is not None:
        save_session(session, sessions_root)
    task_plan = plan.to_dict() if plan is not None else None
    if task_plan is not None:
        (run_dir / "tasks.json").write_text(
            json.dumps(task_plan, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
    return ModelRunResult(run=run, terminal=terminal,
                          turns=len(turn_log),
                          gate_verdict=run.gate_verdict,
                          task_plan=task_plan,
                          terminal_reason=terminal_reason,
                          timeline=timeline)


__all__ = [
    "DEFAULT_MAX_TURNS",
    "MAX_OBSERVATIONS",
    "AgentTurn",
    "ModelRunResult",
    "ProbeCallable",
    "authorized_session_view",
    "fold_observations",
    "passing_run_tests",
    "run_model_mission",
    "write_timeline",
]
