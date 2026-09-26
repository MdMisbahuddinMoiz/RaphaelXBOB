"""raphael_ibm_bob.policy — BOB MVP Policy implementation.

FAIL-CLOSED.

For an `ActionRequest`, returns a `PolicyDecision` with either ALLOW or DENY.
Reasons are deterministic strings so tests can assert them.

Decision inputs:
    - Capability must be one of READ/LIST/SEARCH/WRITE/RUN_TEST.
    - Target must resolve under the declared Workspace.
    - Capability-specific invariants:
        WRITE: target must NOT exist as a directory; the resolved path
               must be inside the workspace and the parent directory must
               exist.
        READ:  target must be a regular file inside the workspace.
        LIST:  target must be a directory inside the workspace.
        SEARCH: target must be a directory inside the workspace.
        RUN_TEST: target must be a regular file ending in test_*.py or
                  *_test.py and live inside the workspace.
    - Mission scope, if set, is treated as a substring constraint on the
      target. A target whose normalized form does not contain the mission
      scope substring is denied with `reason="scope"`.

This module NEVER performs the action. It only decides.

Legacy semantics:
    src/orchestrator/brain/scope_parser.py (ScopeParser, fail-closed) is
    the source of inspiration; the BOB policy grammar is different.
    src/orchestrator/brain/rate_limiter.py is not used at M2 because the
    MVP has no time-window rate limit semantics.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from raphael_ibm_bob.contracts import (
    ActionRequest,
    Capability,
    Decision,
    Mission,
    PolicyDecision,
    capability_id,
)
from raphael_ibm_bob.c1a_scope import scope_contains, within_root
from raphael_ibm_bob.network_runtime import ALLOWED_METHODS, method_from_purpose
from raphael_ibm_bob.network_scope import (
    NetworkScopeError,
    canonical_host,
    host_in_scope,
    parse_http_target,
    parse_ssh_target,
    parse_telnet_target,
)
from raphael_ibm_bob.discovery_runtime import MAX_DISCOVERY_PORTS, _parse_port_spec
from raphael_ibm_bob.telnet_runtime import (
    build_telnet_spec,
    command_from_purpose,
    validate_command,
)
from raphael_ibm_bob.target_profile import TARGET_STAGES, get_target_store
from raphael_ibm_bob.workspace import Workspace


@dataclass(frozen=True)
class PolicyCapabilityMetadata:
    scope: str = "path"
    authorizer: Callable[[ActionRequest, Mission, Path | None], PolicyDecision] | None = None


def _timeout_is_valid(value: object) -> bool:
    """True iff a request timeout is a finite positive real number.

    ``None`` means "use the broker default" and is accepted. NaN and the
    infinities are rejected: they compare false against ``<= 0`` yet would
    reach the ledger as a non-JSON-serializable value, so this is a
    fail-closed check rather than cosmetic validation.
    """
    if value is None:
        return True
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return math.isfinite(value) and value > 0


class BOBPolicy:
    """MVP Policy. Fail-closed. Pure (no side effects)."""

    def __init__(self, workspace: Workspace, target_store=None,
                 credential_vault=None):
        self._workspace = workspace
        self._target_store = target_store
        # Optional process-local credential vault. Policy consults it to
        # confirm a referenced credential is authorized for this exact
        # host and protocol; it never reads or logs plaintext.
        self._credential_vault = credential_vault
        self._metadata: dict[str, PolicyCapabilityMetadata] = {}
        self._register_builtin_metadata()

    def register_capability(
        self, capability_id_value: str, metadata: PolicyCapabilityMetadata,
    ) -> None:
        if not capability_id_value:
            raise ValueError("capability_id is required")
        self._metadata[capability_id_value] = metadata

    def _register_builtin_metadata(self) -> None:
        self._metadata = {
            Capability.READ.value: PolicyCapabilityMetadata(
                authorizer=self._authorize_read),
            Capability.LIST.value: PolicyCapabilityMetadata(
                authorizer=self._authorize_list),
            Capability.SEARCH.value: PolicyCapabilityMetadata(
                authorizer=self._authorize_search),
            Capability.WRITE.value: PolicyCapabilityMetadata(
                authorizer=self._authorize_write),
            Capability.RUN_TEST.value: PolicyCapabilityMetadata(
                authorizer=self._authorize_run_test),
            Capability.C1A_STATIC_FILE_INSPECT.value: PolicyCapabilityMetadata(
                authorizer=self._consult_c1a),
            Capability.NETWORK_HTTP_REQUEST.value: PolicyCapabilityMetadata(
                scope="network", authorizer=self._consult_network),
            Capability.NETWORK_TELNET_SESSION.value: PolicyCapabilityMetadata(
                scope="network", authorizer=self._consult_telnet),
            Capability.NETWORK_SERVICE_DISCOVERY.value: PolicyCapabilityMetadata(
                scope="network", authorizer=self._consult_discovery),
            Capability.NETWORK_SSH_SESSION.value: PolicyCapabilityMetadata(
                scope="network", authorizer=self._consult_ssh),
        }

    def consult(self, request: ActionRequest, mission: Mission) -> PolicyDecision:
        metadata = self._metadata.get(capability_id(request.capability))
        if metadata is None:
            return self._deny(
                request,
                f"capability-not-allowed:{capability_id(request.capability)}",
            )

        # 2. Target must be a non-empty string.
        if not request.target or not isinstance(request.target, str):
            return self._deny(request, "target-empty-or-invalid")

        # 2b. Network capability: authorize against the mission-bound
        # TargetProfile (URL targets are not workspace paths; the network
        # scope algebra replaces path containment).
        if metadata.scope == "network":
            if metadata.authorizer is None:
                return self._deny(request, "capability-policy-metadata-invalid")
            return metadata.authorizer(request, mission, None)

        if metadata.scope == "mission":
            if mission.scope and not scope_contains(mission.scope, request.target):
                return self._deny(request, "scope-mismatch")
            if metadata.authorizer is None:
                return self._allow(request)
            return metadata.authorizer(request, mission, None)

        # 3. Workspace containment check.
        try:
            resolved = self._workspace.resolve(request.target)
        except PermissionError:
            return self._deny(request, "target-outside-workspace")
        except FileNotFoundError:
            # READ/LIST/SEARCH/RUN_TEST need the path to exist; WRITE
            # needs the parent to exist. We let capability checks below
            # decide whether existence matters.
            resolved = None  # type: ignore[assignment]

        # 4. Mission scope containment check.
        # Canonical component-boundary containment (raphael_ibm_bob.c1a_scope)
        # — the SAME helper the QualityGate uses. This rejects sibling string
        # prefixes, traversal, and malformed paths that a substring check
        # would have accepted.
        if mission.scope and not scope_contains(mission.scope, request.target):
            return self._deny(request, "scope-mismatch")

        if metadata.authorizer is None:
            return self._allow(request)
        return metadata.authorizer(request, mission, resolved)

    def _consult_network(
        self, request: ActionRequest, mission: Mission,
        _resolved: Path | None = None,
    ) -> PolicyDecision:
        """D9 network authorization (fail closed).

        The URL must be a valid http(s) target whose host/port/protocol are
        exactly authorized by the mission-bound TargetProfile, with an
        explicit authorization reference, an allowed method, and a positive
        timeout. Any failure is a DENY (no invocation, no result).
        """
        try:
            target = parse_http_target(request.target)
        except NetworkScopeError as exc:
            return self._deny(request, f"network-target-invalid:{exc}")
        store = self._target_store or get_target_store()
        profile = store.get_target(mission.mission_id)
        if profile is None:
            return self._deny(request, "network-no-authorized-target")
        if not profile.authorization_ref:
            return self._deny(request, "network-authorization-missing")
        if not profile.allows(host=target.host, port=target.port,
                              protocol=target.scheme):
            return self._deny(request, "network-target-mismatch")
        method = method_from_purpose(request.purpose)
        if method not in ALLOWED_METHODS:
            return self._deny(request, f"network-method-not-allowed:{method}")
        # The mediator always enforces its own bounded timeout; a missing
        # request timeout is acceptable (resolved by the broker default).
        if not _timeout_is_valid(request.timeout_seconds):
            return self._deny(request, "network-timeout-invalid")
        return self._allow(request)

    def _consult_telnet(
        self, request: ActionRequest, mission: Mission,
        _resolved: Path | None = None,
    ) -> PolicyDecision:
        """D12 Telnet authorization (fail closed).

        The ``telnet://host:port`` target must be exactly authorized by the
        mission-bound TargetProfile (protocol ``telnet``), the mission must
        declare a session spec, and the role's command must pass the
        fail-closed allow-list. Any failure is a DENY (no session, no result).
        """
        try:
            target = parse_telnet_target(request.target)
        except NetworkScopeError as exc:
            return self._deny(request, f"telnet-target-invalid:{exc}")
        store = self._target_store or get_target_store()
        profile = store.get_target(mission.mission_id)
        if profile is None:
            return self._deny(request, "telnet-no-authorized-target")
        if not profile.authorization_ref:
            return self._deny(request, "telnet-authorization-missing")
        if not profile.allows(host=target.host, port=target.port,
                              protocol="telnet"):
            return self._deny(request, "telnet-target-mismatch")
        if not _timeout_is_valid(request.timeout_seconds):
            return self._deny(request, "telnet-timeout-invalid")
        spec = build_telnet_spec(mission, profile)
        if spec is None:
            return self._deny(request, "telnet-no-session-spec")
        role = command_from_purpose(request.purpose)
        command = spec.command_for_role(role)
        ok, why = validate_command(command, spec.authorized_commands())
        if not ok:
            return self._deny(request, f"telnet-command-rejected:{why}")
        return self._allow(request)

    def _consult_discovery(
        self, request: ActionRequest, mission: Mission,
        _resolved: Path | None = None,
    ) -> PolicyDecision:
        """Governed service discovery authorization (fail closed).

        The target must be a plain host/IP matching the mission-bound
        TargetProfile locator exactly. No port in the target string —
        the port list is carried in the ActionRequest purpose as
        ``ports=<spec>``. The profile may be at either lifecycle stage
        (an IP-only ``discovery`` profile is exactly what makes discovery
        reachable before the ports are known). Any failure is a DENY.
        """
        store = self._target_store or get_target_store()
        profile = store.get_target(mission.mission_id)
        if profile is None:
            return self._deny(request, "discovery-no-authorized-target")
        if not profile.authorization_ref:
            return self._deny(request, "discovery-authorization-missing")
        if profile.stage not in TARGET_STAGES:
            return self._deny(request, "discovery-profile-stage-invalid")
        # Target must be the declared locator host only (no port, no path).
        try:
            req_canonical = canonical_host(request.target)
        except NetworkScopeError as exc:
            return self._deny(request, f"discovery-target-invalid:{exc}")
        try:
            profile_canonical = canonical_host(profile.locator)
        except NetworkScopeError as exc:
            return self._deny(request, f"discovery-profile-invalid:{exc}")
        if req_canonical != profile_canonical:
            return self._deny(request, "discovery-target-mismatch")
        if not host_in_scope(profile.scope, profile_canonical):
            return self._deny(request, "discovery-scope-violation")
        # Validate port spec if present; fail closed on malformed.
        try:
            ports, _ = _parse_port_spec(request.purpose or "")
        except ValueError as exc:
            return self._deny(request, f"discovery-port-spec-invalid:{exc}")
        if len(ports) > MAX_DISCOVERY_PORTS:
            return self._deny(request, "discovery-port-range-too-large")
        if not _timeout_is_valid(request.timeout_seconds):
            return self._deny(request, "discovery-timeout-invalid")
        return self._allow(request)

    def _consult_ssh(
        self, request: ActionRequest, mission: Mission,
        _resolved: Path | None = None,
    ) -> PolicyDecision:
        """Governed SSH session authorization (fail closed).

        Every failure mode is a DENY, evaluated before any transport is
        touched:

        * the target must be an ``ssh://host:port`` literal with no
          userinfo, no path, and no query (no secondary destination and
          no credential smuggled through the URL);
        * a mission-bound TargetProfile must exist and carry an
          authorization reference;
        * host, port, and protocol must match the profile EXACTLY —
          ``profile.allows`` is an equality check, never a wildcard or
          a CIDR expansion;
        * the mission must declare an SSH session spec, and the spec's
          port and host must agree with the request;
        * the request must carry exactly ONE structured ``cmd=``
          command, and that command must independently pass the
          command-policy layer (ALLOW). ``DENY`` means it can never
          run; ``REQUIRE_AUTHORIZATION`` means the operator has not
          authorized it for this mission;
        * the request timeout must be valid.
        """
        from raphael_ibm_bob.ssh_runtime import (
            CommandDecision,
            build_ssh_spec,
            chaining_detected,
            command_from_purpose,
        )
        try:
            target = parse_ssh_target(request.target)
        except NetworkScopeError as exc:
            return self._deny(request, f"ssh-target-invalid:{exc}")
        store = self._target_store or get_target_store()
        profile = store.get_target(mission.mission_id)
        if profile is None:
            return self._deny(request, "ssh-no-authorized-target")
        if not profile.authorization_ref:
            return self._deny(request, "ssh-authorization-missing")
        if not profile.allows(host=target.host, port=target.port,
                              protocol="ssh"):
            return self._deny(request, "ssh-target-mismatch")
        if not _timeout_is_valid(request.timeout_seconds):
            return self._deny(request, "ssh-timeout-invalid")
        spec = build_ssh_spec(mission, profile)
        if spec is None:
            return self._deny(request, "ssh-no-session-spec")
        if spec.port != target.port or (spec.target
                                         and spec.target != target.host):
            return self._deny(request, "ssh-spec-target-mismatch")
        command = command_from_purpose(request.purpose)
        if not command:
            return self._deny(request, "ssh-no-command")
        verdict, why = spec.policy.evaluate(
            command, extra_authorized=spec.authorized_commands)
        if verdict is not CommandDecision.ALLOW:
            return self._deny(request, f"ssh-command-rejected:{why}")
        if spec.max_commands != 1:
            return self._deny(request, "ssh-multiple-commands-forbidden")
        chain = chaining_detected(request.purpose)
        if chain is not None:
            return self._deny(
                request, f"ssh-command-chaining-rejected:{chain!r}")
        # The credential REFERENCE must resolve and be authorized for
        # this exact host and protocol BEFORE the action is executable.
        # Without this the check would live only in the mediator, and
        # Policy would approve a session it already knows cannot run.
        if spec.credential_id:
            if self._credential_vault is None:
                return self._deny(request, "ssh-no-credential-authority")
            if not self._credential_vault.is_authorized_for(
                    spec.credential_id, target.host, "ssh"):
                return self._deny(request, "ssh-credential-not-authorized")
            if self._credential_vault.retrieve(
                    spec.credential_id) is None:
                return self._deny(
                    request, "ssh-credential-reference-invalid")
        return self._allow(request)

    def _consult_c1a(
        self, request: ActionRequest, _mission: Mission,
        resolved: Path | None,
    ) -> PolicyDecision:
        """C1A-specific authorization (fail closed).

        The target must resolve to an existing regular file inside the
        workspace, be canonically contained in the workspace root, and the
        request MUST carry an explicit positive timeout (no unbounded
        out-of-process execution). The mission-scope containment check has
        already run using the shared canonical helper.
        """
        if resolved is None:
            return self._deny(request, "c1a-target-missing")
        if not resolved.is_file():
            return self._deny(request, "c1a-target-not-file")
        if not within_root(str(self._workspace.root), str(resolved)):
            return self._deny(request, "c1a-target-outside-workspace")
        if (request.timeout_seconds is None
                or not isinstance(request.timeout_seconds, (int, float))
                or isinstance(request.timeout_seconds, bool)
                or request.timeout_seconds <= 0):
            return self._deny(request, "c1a-timeout-required")
        return self._allow(request)

    def _authorize_read(
        self, request: ActionRequest, _mission: Mission,
        resolved: Path | None,
    ) -> PolicyDecision:
        if resolved is None:
            return self._deny(request, "read-target-missing")
        if not resolved.is_file():
            return self._deny(request, "read-target-not-file")
        return self._allow(request)

    def _authorize_list(
        self, request: ActionRequest, _mission: Mission,
        resolved: Path | None,
    ) -> PolicyDecision:
        if resolved is None:
            return self._deny(request, "list-target-missing")
        if not resolved.is_dir():
            return self._deny(request, "list-target-not-directory")
        return self._allow(request)

    def _authorize_search(
        self, request: ActionRequest, _mission: Mission,
        resolved: Path | None,
    ) -> PolicyDecision:
        if resolved is None:
            return self._deny(request, "search-target-missing")
        if not resolved.is_dir():
            return self._deny(request, "search-target-not-directory")
        return self._allow(request)

    def _authorize_write(
        self, request: ActionRequest, _mission: Mission,
        resolved: Path | None,
    ) -> PolicyDecision:
        if resolved is None:
            return self._deny(request, "write-target-unresolved")
        if resolved.exists() and resolved.is_dir():
            return self._deny(request, "write-target-is-directory")
        if not resolved.parent.is_dir():
            return self._deny(request, "write-parent-missing")
        return self._allow(request)

    def _authorize_run_test(
        self, request: ActionRequest, _mission: Mission,
        resolved: Path | None,
    ) -> PolicyDecision:
        if resolved is None:
            return self._deny(request, "run_test-target-missing")
        if not resolved.is_file():
            return self._deny(request, "run_test-target-not-file")
        name = resolved.name
        if not ((name.startswith("test_") and name.endswith(".py"))
                or name.endswith("_test.py")):
            return self._deny(request, "run_test-name-pattern")
        return self._allow(request)

    # Helpers -----------------------------------------------------------------

    def _allow(self, request: ActionRequest) -> PolicyDecision:
        return PolicyDecision(
            sequence=request.sequence,
            decision=Decision.ALLOW,
            reason="ok",
            capability=request.capability,
            target=request.target,
            evidence_id=None,
        )

    def _deny(self, request: ActionRequest, reason: str) -> PolicyDecision:
        return PolicyDecision(
            sequence=request.sequence,
            decision=Decision.DENY,
            reason=reason,
            capability=request.capability,
            target=request.target,
            evidence_id=None,
        )


__all__ = ["BOBPolicy", "PolicyCapabilityMetadata"]
