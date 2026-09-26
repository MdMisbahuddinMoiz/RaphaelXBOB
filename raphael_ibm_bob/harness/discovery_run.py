"""raphael_ibm_bob.harness.discovery_run — governed service discovery mission.

Executes a single NETWORK_SERVICE_DISCOVERY capability request through the
existing Runtime → Broker → Policy → DiscoveryMediator path and returns a
structured result the UI can display and use to populate the target form.

This is NOT a second discovery implementation. It builds one ActionRequest,
submits it through the governed stack, reads the evidence, and returns.
Nothing here bypasses Policy or the Broker.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional

from raphael_ibm_bob.broker import BOBBroker
from raphael_ibm_bob.contracts import ActionRequest, Capability, Mission
from raphael_ibm_bob.discovery_runtime import get_discovery_mediator
from raphael_ibm_bob.policy import BOBPolicy
from raphael_ibm_bob.runtime import BOBRuntime
from raphael_ibm_bob.target_profile import TargetProfile, get_target_store
from raphael_ibm_bob.workspace import Workspace

DEFAULT_DISCOVERY_TIMEOUT = 30.0


@dataclass
class DiscoveryRunResult:
    """Result of a single governed discovery invocation through the harness."""
    allowed: bool          # Policy ALLOWed the request
    success: bool          # At least one port was found open
    ports_open: List[int]
    port_details: List[dict]   # list of {port, state, service, latency_ms}
    ports_probed: int
    host: str
    error: Optional[str]
    state: str             # DiscoveryState value
    capped: bool
    invocation_id: Optional[str]
    deny_reason: Optional[str]


def run_discovery(
    *,
    host: str,
    mission_id: str,
    port_spec: str = "",
    workspace_root: Path,
    target_store: Any = None,
    discovery_mediator: Any = None,
    timeout_seconds: float = DEFAULT_DISCOVERY_TIMEOUT,
    requester: str = "operator-discovery",
) -> DiscoveryRunResult:
    """Execute one governed service discovery request and return the result.

    Uses the process-wide target store (or the injected one) — the caller
    must have declared an authorized TargetProfile for this mission_id first.
    If no profile is declared or the request is denied, returns a structured
    failure (never raises for policy rejections).
    """
    store = target_store if target_store is not None else get_target_store()
    mediator = (discovery_mediator if discovery_mediator is not None
                else get_discovery_mediator())

    workspace = Workspace(workspace_root)
    policy = BOBPolicy(workspace, target_store=store)
    broker = BOBBroker(
        policy, workspace,
        target_store=store,
        discovery_mediator=mediator,
    )
    runtime = BOBRuntime(broker)

    mission = Mission(
        mission_id=mission_id,
        description=f"service discovery for {host}",
        scope=host,
        criteria=["service-discovery"],
    )

    # purpose must be non-empty, so an absent port_spec uses the sentinel
    # below rather than "", which the runtime rejects. Omitting a `ports=`
    # clause is what makes _parse_port_spec fall back to its bounded default
    # sweep; restoring "" here reintroduces the runtime's ValueError.
    spec = port_spec.strip()
    purpose = f"ports={spec}" if spec else "service-discovery"
    request = ActionRequest(
        sequence=0,
        requester=requester,
        capability=Capability.NETWORK_SERVICE_DISCOVERY,
        target=host,
        purpose=purpose,
        timeout_seconds=timeout_seconds,
    )

    result = runtime.submit(request, mission)
    decision = result.broker_result.decision
    execution = result.execution

    if decision.decision.value != "allow":
        return DiscoveryRunResult(
            allowed=False,
            success=False,
            ports_open=[],
            port_details=[],
            ports_probed=0,
            host=host,
            error=f"policy-denied:{decision.reason}",
            state="denied",
            capped=False,
            invocation_id=None,
            deny_reason=decision.reason,
        )

    ev = (execution.evidence if execution else {}) or {}
    dr = ev.get("discovery_result") or {}
    ports_open = list(ev.get("ports_open") or [])
    port_results = dr.get("port_results") or []

    return DiscoveryRunResult(
        allowed=True,
        success=execution.success if execution else False,
        ports_open=ports_open,
        port_details=[
            {
                "port": r.get("port"),
                "state": r.get("state"),
                "service": r.get("service"),
                "latency_ms": r.get("latency_ms"),
            }
            for r in port_results
            if r.get("state") == "open"
        ],
        ports_probed=int(ev.get("ports_probed") or 0),
        host=ev.get("host") or host,
        error=execution.error if execution else "no-execution",
        state=dr.get("state") or "unknown",
        capped=bool(ev.get("capped")),
        invocation_id=ev.get("invocation_id"),
        deny_reason=None,
    )


__all__ = [
    "DEFAULT_DISCOVERY_TIMEOUT",
    "DiscoveryRunResult",
    "run_discovery",
]
