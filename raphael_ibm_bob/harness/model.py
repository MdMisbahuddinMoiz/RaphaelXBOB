"""raphael_ibm_bob.harness.model — model interaction boundary.

The model PROPOSES; RAPHAEL decides and executes. This module defines
only the seam: what context goes in, what structured proposal comes
out. It holds no credentials, no endpoints, and no routing — those live
in `harness.providers`, behind the `ModelAdapter` protocol declared
here. The planner consumes a `ModelAdapter` and never learns which
provider is behind it.

`ScriptedModelAdapter` is an explicitly labeled deterministic test
double (scripted replies for tests/demos), never presented as a working
model provider.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, Tuple, \
    runtime_checkable

from raphael_ibm_bob.contracts import ActionRequest, Finding, Mission


@dataclass(frozen=True)
class ModelContext:
    """What the Harness shows the model: mission + current state.

    Deliberately small (same discipline as FocusedContext): the model
    sees the mission, finding summaries with states, workspace
    facts, a bounded file listing, recent turn outcomes, and the
    governed observations folded back from the evidence ledger (the
    services/ports a discovery pass actually reported) — never
    credentials, never raw policy internals, never the full ledger.
    """
    mission: Mission
    findings: List[Finding] = field(default_factory=list)
    workspace_root: str = ""
    evidence_count: int = 0
    workspace_files: Tuple[str, ...] = ()
    recent_turns: Tuple[Dict[str, Any], ...] = ()
    session_id: str = ""
    # M14 specialization context (compact; declarations only).
    available_roles: Tuple[Dict[str, Any], ...] = ()
    active_task: Optional[Dict[str, Any]] = None
    #: The authorized session scope the operator declared (SSH today):
    #: target, protocol, username, and — critically — the exact commands
    #: this mission may run. Without it the model can only GUESS, and a
    #: guessed command is denied exactly as an illegal one would be.
    #: A declaration grants no authority; it only tells the model what a
    #: legal proposal looks like.
    authorized_session: Optional[Dict[str, Any]] = None
    #: Governed observations folded back from the evidence ledger —
    #: e.g. the services/ports a NETWORK_SERVICE_DISCOVERY pass actually
    #: reported. Bounded and structured; this is what lets the model
    #: choose its NEXT action from real evidence rather than repeating
    #: the previous one. Never credentials, never raw policy internals.
    observations: Tuple[Dict[str, Any], ...] = ()
    #: The operator's own message from the chat console, when there is
    #: one. It is CONTEXT, never an instruction the harness honours: the
    #: model still returns an ordinary ActionRequest, and the message
    #: grants no authority that the mission, target profile, and Policy
    #: do not already grant. Redacted on the way in by
    #: `harness.chat.operator_message`, so a pasted credential cannot
    #: reach the provider through it.
    operator_note: Optional[str] = None

    def summary(self) -> Dict[str, Any]:
        return {
            "mission_id": self.mission.mission_id,
            "description": self.mission.description,
            "scope": self.mission.scope,
            "findings": [
                {"finding_id": f.finding_id,
                 "state": f.state.value,
                 "target": f.target} for f in self.findings
            ],
            "workspace_root": self.workspace_root,
            "evidence_count": self.evidence_count,
            "workspace_files": list(self.workspace_files),
            "recent_turns": list(self.recent_turns),
            "session_id": self.session_id,
            "available_roles": list(self.available_roles),
            "active_task": self.active_task,
            "authorized_session": self.authorized_session,
            "observations": list(self.observations),
            "operator_note": self.operator_note,
        }



@runtime_checkable
class ModelAdapter(Protocol):
    """Boundary every model integration must satisfy."""

    def propose(self, context: ModelContext) -> ActionRequest:
        """Return ONE proposed action for the given context.

        The proposal is an ordinary ActionRequest the Harness submits
        through Runtime -> Broker -> Policy. Returning a proposal
        grants nothing; Policy may still deny it.
        """
        ...


class ScriptedModelAdapter:
    """Deterministic test double: canned proposals keyed by mission.

    NOT a model provider. Used by tests and scripted demos so the
    Harness interaction path executes without network or credentials.
    Unknown missions raise KeyError loudly instead of inventing an
    action.
    """

    def __init__(self, proposals: Dict[str, ActionRequest]):
        self._proposals = dict(proposals)

    def propose(self, context: ModelContext) -> ActionRequest:
        try:
            return self._proposals[context.mission.mission_id]
        except KeyError:
            raise KeyError(
                f"scripted adapter has no proposal for mission "
                f"{context.mission.mission_id!r}") from None


__all__ = [
    "ModelAdapter",
    "ModelContext",
    "ScriptedModelAdapter",
]
