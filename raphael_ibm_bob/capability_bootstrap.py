"""raphael_ibm_bob.capability_bootstrap — D13 governed capability wiring.

Declares the BOB capabilities in the D13 registry and provides the two
adapter shapes:

    InertAdapter      — a declared capability with NO governed binding.
                        `execute` FAILS CLOSED. Declaring is not executing.
    MediatedAdapter   — an adapter bound to the EXISTING Runtime. Its
                        `execute` builds an ordinary ActionRequest and
                        calls `runtime.submit(...)`, i.e. it routes
                        through Runtime -> Broker -> Policy. It never
                        consults Policy itself, never imports the broker,
                        and never bypasses the governed path.

Bridging rule: a descriptor's ``capability_id`` equals the
``contracts.Capability`` enum *name*. A descriptor with no enum binding
(e.g. ``NETWORK_SSH_SESSION`` before SSH is implemented) can be declared
and discovered, but ``plan_to_action_requests`` will fail closed on it.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from raphael_ibm_bob.capability_registry import (
    AdapterNotBoundError,
    CapabilityDescriptor,
    CapabilityRegistry,
    ExecutionAdapter,
    PrerequisiteSpec,
    get_registry,
)
from raphael_ibm_bob.contracts import Capability
from raphael_ibm_bob.observation_model import ObservationBuilder


class InertAdapter:
    """Declaration-only adapter: execution is refused (fail closed)."""

    def execute(self, target_facts: dict, credentials: list,
                mission_params: dict) -> dict:
        raise AdapterNotBoundError(
            "capability is declared but has no governed execution adapter "
            "bound; refusing to execute (fail closed)")

    def execute_governed(self, request: Any, mission: Any, decision: Any) -> Any:
        raise AdapterNotBoundError(
            "capability is declared but has no governed execution adapter "
            "bound; refusing to execute (fail closed)")


class MediatedAdapter:
    """Adapter whose execution routes through the existing governed Runtime.

    `runtime` is the existing governed Runtime object (injected — this
    module does not import it). `mission` is the active Mission. `execute`
    prepares an ordinary ``ActionRequest`` and calls ``runtime.submit``;
    the broker consults Policy and, on DENY, performs no side effect.
    """

    def __init__(self, capability: Any, runtime: Any, mission: Any) -> None:
        self._capability = capability
        self._runtime = runtime
        self._mission = mission
        self._governed_executor: Callable[..., Any] | None = None

    def set_governed_executor(self, executor: Callable[..., Any]) -> None:
        self._governed_executor = executor

    def execute_governed(
        self, request: Any, mission: Any, decision: Any,
    ) -> Any:
        if self._governed_executor is None:
            raise AdapterNotBoundError(
                "capability has no Broker execution adapter bound")
        return self._governed_executor(request, mission, decision)

    def execute(self, target_facts: dict, credentials: list,
                mission_params: dict) -> dict:
        from raphael_ibm_bob.contracts import ActionRequest
        target = mission_params.get("target")
        if not target:
            raise ValueError("MediatedAdapter requires mission_params['target']")
        request = ActionRequest(
            sequence=0,
            requester=f"adapter:{self._capability.value}",
            capability=self._capability,
            target=target,
            purpose=mission_params.get("purpose", target),
        )
        result = self._runtime.submit(request, self._mission)
        decision = result.broker_result.decision
        execution = result.execution
        if decision.decision.value != "allow" or execution is None:
            return {
                "observation_type": "capability_decision",
                "capability_id": self._capability.name,
                "decision": decision.decision.value,
                "reason": decision.reason,
                "target": target,
                "executed": False,
            }
        output = execution.output or ""
        record = ObservationBuilder.from_capability_output(
            capability_id=self._capability.name,
            output=output,
            target_host=target_facts.get("host", self._mission.mission_id),
            observation_type="network_response",
            provenance={"request_seq": result.request_seq,
                        "decision": decision.decision.value},
        )
        return record.to_evidence_dict()


# ---------------------------------------------------------------------------
# Descriptor catalog
# ---------------------------------------------------------------------------

_NETWORK_MISSIONS = frozenset(
    {"recon", "web_enum", "service_interaction", "flag_capture"})


def _http_descriptor() -> CapabilityDescriptor:
    return CapabilityDescriptor(
        capability_id="NETWORK_HTTP_REQUEST",
        protocol="http",
        description="Governed HTTP(S) GET/HEAD request capability (D9).",
        prerequisites=frozenset([
            PrerequisiteSpec(kind="service", predicate="http",
                             description="HTTP service on target"),
            PrerequisiteSpec(kind="authorization", predicate="http",
                             description="HTTP authorization in scope"),
        ]),
        authorization_scope="network_http",
        evidence_schema="http_response_v1",
        execution_adapter="raphael_ibm_bob.network_runtime",
        verifier_binding="raphael_ibm_bob.verifier",
        falsifier_binding="raphael_ibm_bob.falsifier",
        mission_types=_NETWORK_MISSIONS,
    )


def _telnet_descriptor() -> CapabilityDescriptor:
    return CapabilityDescriptor(
        capability_id="NETWORK_TELNET_SESSION",
        protocol="telnet",
        description="Governed Telnet session capability (D12).",
        prerequisites=frozenset([
            PrerequisiteSpec(kind="service", predicate="telnet",
                             description="Telnet service on target"),
            PrerequisiteSpec(kind="authorization", predicate="telnet",
                             description="Telnet authorization in scope"),
            PrerequisiteSpec(kind="credential", predicate="telnet",
                             description="Telnet credential available"),
        ]),
        authorization_scope="network_telnet",
        evidence_schema="telnet_session_v1",
        execution_adapter="raphael_ibm_bob.telnet_runtime",
        verifier_binding="raphael_ibm_bob.verifier",
        falsifier_binding="raphael_ibm_bob.falsifier",
        mission_types=_NETWORK_MISSIONS,
    )


def ssh_descriptor() -> CapabilityDescriptor:
    """Declaration for the governed SSH session capability.

    Previously descriptor-only ("no enum, no adapter yet"), which
    proved the fabric was target-agnostic. It is now EXECUTABLE: the
    enum member `Capability.NETWORK_SSH_SESSION` exists and the broker
    delegates to `raphael_ibm_bob.ssh_runtime.SshMediator`, the only
    SSH-I/O boundary. Declaration still grants no authority — every
    request still crosses Runtime -> Broker -> Policy.
    """
    return CapabilityDescriptor(
        capability_id="NETWORK_SSH_SESSION",
        protocol="ssh",
        description=(
            "Governed SSH session (one already-approved command per "
            "session, via the Broker/Policy path only)."),
        prerequisites=frozenset([
            PrerequisiteSpec(kind="service", predicate="ssh",
                             description="SSH service on target"),
            PrerequisiteSpec(kind="authorization", predicate="ssh",
                             description="SSH in scope"),
            PrerequisiteSpec(kind="credential", predicate="ssh_valid",
                             description="Validated SSH credential"),
        ]),
        authorization_scope="network_ssh",
        evidence_schema="ssh_session_v1",
        execution_adapter="raphael_ibm_bob.ssh_runtime",
        verifier_binding=None,
        falsifier_binding=None,
        mission_types=frozenset(
            {"flag_capture", "service_interaction", "credential_access"}),
    )


def _discovery_descriptor() -> CapabilityDescriptor:
    return CapabilityDescriptor(
        capability_id="NETWORK_SERVICE_DISCOVERY",
        protocol="tcp",
        description=(
            "Governed TCP service/port discovery (D13+). "
            "stdlib socket.connect_ex only; no subprocess, no shell, no nmap."
        ),
        prerequisites=frozenset([
            PrerequisiteSpec(kind="authorization", predicate="discovery",
                             description="Discovery authorization in scope"),
        ]),
        authorization_scope="network_discovery",
        evidence_schema="discovery_v1",
        execution_adapter="raphael_ibm_bob.discovery_runtime",
        verifier_binding=None,
        falsifier_binding=None,
        mission_types=_NETWORK_MISSIONS,
    )


def network_descriptors() -> list:
    """Governed network capabilities (HTTP + Telnet + Discovery).

    SSH is deliberately NOT here: it is declared by the D15 descriptor
    catalogue (`d15_capability_catalogue.d15_descriptors`), which the
    applicability matrix composes with this list. Listing it in both
    would register the same capability id twice, and duplicate
    registration is a governance violation.
    """
    return [_http_descriptor(), _telnet_descriptor(), _discovery_descriptor()]


def register_default(registry: Optional[CapabilityRegistry] = None
                     ) -> CapabilityRegistry:
    """Register the governed network capabilities with inert adapters.

    Idempotent: already-registered ids are skipped (so bootstrapping the
    process-wide registry twice is harmless).
    """
    registry = registry or get_registry()
    for descriptor in network_descriptors():
        if registry.has(descriptor.capability_id):
            continue
        registry.register(descriptor, InertAdapter())
    # The SSH declaration is registered here too (idempotently) so the
    # Broker's default registry can bind a governed adapter. The
    # InertAdapter is the fail-closed placeholder: only the Broker's
    # binding table turns it executable.
    ssh = ssh_descriptor()
    if not registry.has(ssh.capability_id):
        registry.register(ssh, InertAdapter())
    return registry


def register_ssh(registry: Optional[CapabilityRegistry] = None
                 ) -> CapabilityRegistry:
    """Register the SSH declaration (proof of target-agnostic extension)."""
    registry = registry or get_registry()
    if not registry.has("NETWORK_SSH_SESSION"):
        registry.register(ssh_descriptor(), InertAdapter())
    return registry


def bind_governed_adapters(registry: CapabilityRegistry, runtime: Any,
                           mission: Any,
                           capability_ids: Optional[list] = None) -> None:
    """Bind MediatedAdapters so declared capabilities can execute.

    Only call this with the real governed Runtime. The adapter delegates
    to Runtime -> Broker -> Policy; the registry never executes directly.
    """
    ids = capability_ids or [d.capability_id
                             for d in registry.all_capabilities()]
    for capability_id in ids:
        try:
            capability = Capability[capability_id]
        except KeyError:
            continue  # no governed enum -> cannot bind (fail closed)
        registry.bind_adapter(
            capability_id,
            MediatedAdapter(capability, runtime, mission))


__all__ = [
    "InertAdapter",
    "MediatedAdapter",
    "bind_governed_adapters",
    "network_descriptors",
    "register_default",
    "register_ssh",
    "ssh_descriptor",
]

from raphael_ibm_bob.d15_capability_catalogue import (
    d15_descriptors,
    dns_metadata_descriptor,
    generic_service_banner_descriptor,
    register_d15_descriptors,
    smb_metadata_descriptor,
    tls_metadata_descriptor,
)

__all__ += [
    "d15_descriptors",
    "dns_metadata_descriptor",
    "generic_service_banner_descriptor",
    "register_d15_descriptors",
    "smb_metadata_descriptor",
    "tls_metadata_descriptor",
]
