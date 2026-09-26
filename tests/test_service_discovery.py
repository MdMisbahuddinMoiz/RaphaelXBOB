"""tests.test_service_discovery — governed NETWORK_SERVICE_DISCOVERY tests.

Coverage:
    - authorized target discovery succeeds (live loopback listener)
    - no-open-ports case: state=no_open_ports, success=False
    - unauthorized target rejected by Policy (DENY)
    - out-of-scope host rejected by mediator (DENY result)
    - out-of-scope port rejected (port-spec-invalid policy DENY)
    - bounded discovery: capped at MAX_DISCOVERY_PORTS
    - truthful service evidence: evidence fields, PROVIDER_UNTRUSTED flag
    - fail-closed: no TargetProfile → discovery-no-authorized-target
    - no arbitrary command execution: only stdlib socket in mediator
    - existing HTTP/Telnet behavior unchanged
    - Policy DENY does not invoke capability (no socket)
    - missing authorization_ref → DENY
    - mismatched host → DENY
    - malformed port spec → policy DENY
"""
from __future__ import annotations

import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from raphael_ibm_bob.broker import BOBBroker
from raphael_ibm_bob.contracts import (
    ActionRequest,
    Capability,
    Decision,
    Mission,
)
from raphael_ibm_bob.discovery_runtime import (
    DEFAULT_MAX_PORTS,
    DEFAULT_PORT_TIMEOUT,
    MAX_DISCOVERY_PORTS,
    DiscoveryMediator,
    DiscoveryResult,
    DiscoveryState,
    PortState,
    _parse_port_spec,
    get_discovery_mediator,
    set_discovery_mediator,
)
from raphael_ibm_bob.evidence_ledger import EvidenceLedger
from raphael_ibm_bob.network_scope import canonical_host
from raphael_ibm_bob.policy import BOBPolicy
from raphael_ibm_bob.runtime import BOBRuntime
from raphael_ibm_bob.target_profile import (
    TargetProfile,
    TargetStore,
    build_target_profile,
    get_target_store,
    set_target_store,
)
from raphael_ibm_bob.workspace import Workspace

REPO = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_listener() -> tuple[socket.socket, int]:
    """Open a loopback listener; return (socket, port)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    return srv, port


def _loopback_profile(mission_id: str, port: int, *,
                       authorization_ref: str = "test-auth") -> TargetProfile:
    return build_target_profile(
        mission_id=mission_id,
        locator="127.0.0.1",
        allowed_ports=(port,),
        allowed_protocols=("http",),
        scope="127.0.0.1",
        authorization_ref=authorization_ref,
    )


class _Harness(unittest.TestCase):
    """Common setup: isolated ledger, workspace, broker, runtime, store."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="raphael-discovery-test-")
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name) / "workspace"
        root.mkdir()
        self.workspace = Workspace(root)
        self.ledger = EvidenceLedger(Path(self.tmp.name) / "ledger")
        self.addCleanup(self.ledger.close)
        self.store = TargetStore()
        policy = BOBPolicy(self.workspace, target_store=self.store)
        self.broker = BOBBroker(policy, self.workspace, ledger=self.ledger,
                                target_store=self.store)
        self.runtime = BOBRuntime(self.broker)

    def _mission(self, mission_id: str = "M-disc-test") -> Mission:
        return Mission(
            mission_id=mission_id,
            description="discovery test mission",
            scope="127.0.0.1",
            criteria=["discovery"],
        )

    def _request(self, host: str, purpose: str = "",
                 mission_id: str = "M-disc-test") -> ActionRequest:
        return ActionRequest(
            sequence=0,
            requester="test",
            capability=Capability.NETWORK_SERVICE_DISCOVERY,
            target=host,
            purpose=purpose,
            timeout_seconds=10.0,
        )


# ---------------------------------------------------------------------------
# Port-spec parser (unit, no network)
# ---------------------------------------------------------------------------

class PortSpecParser(unittest.TestCase):
    def test_comma_list(self):
        ports, _ = _parse_port_spec("ports=80,443,8080")
        self.assertEqual(ports, (80, 443, 8080))

    def test_range(self):
        ports, _ = _parse_port_spec("ports=1-10")
        self.assertEqual(ports, tuple(range(1, 11)))

    def test_no_spec_returns_defaults(self):
        ports, _ = _parse_port_spec("")
        self.assertGreater(len(ports), 0)
        self.assertIn(80, ports)
        self.assertIn(22, ports)

    def test_range_too_large_is_capped(self):
        ports, _ = _parse_port_spec("ports=1-65535")
        self.assertLessEqual(len(ports), MAX_DISCOVERY_PORTS)

    def test_invalid_port_raises(self):
        with self.assertRaises(ValueError):
            _parse_port_spec("ports=abc")

    def test_out_of_range_raises(self):
        with self.assertRaises(ValueError):
            _parse_port_spec("ports=0")

    def test_deduplication(self):
        ports, _ = _parse_port_spec("ports=80,80,443")
        self.assertEqual(ports.count(80), 1)


# ---------------------------------------------------------------------------
# Policy authorization (no network, no socket)
# ---------------------------------------------------------------------------

class PolicyDiscoveryAuthorization(_Harness):
    def test_allow_when_profile_matches(self):
        srv, port = _make_listener()
        self.addCleanup(srv.close)
        self.store.set_target(_loopback_profile("M-disc-test", port))
        request = self._request("127.0.0.1", f"ports={port}")
        mission = self._mission()
        from raphael_ibm_bob.policy import BOBPolicy
        policy = BOBPolicy(self.workspace, target_store=self.store)
        decision = policy.consult(request, mission)
        self.assertIs(decision.decision, Decision.ALLOW, decision.reason)

    def test_deny_no_target_profile(self):
        # No profile in store
        request = self._request("127.0.0.1", "ports=80")
        mission = self._mission()
        from raphael_ibm_bob.policy import BOBPolicy
        policy = BOBPolicy(self.workspace, target_store=self.store)
        decision = policy.consult(request, mission)
        self.assertIs(decision.decision, Decision.DENY)
        self.assertIn("discovery-no-authorized-target", decision.reason)

    def test_deny_missing_authorization_ref(self):
        profile = build_target_profile(
            mission_id="M-disc-test",
            locator="127.0.0.1",
            allowed_ports=(80,),
            allowed_protocols=("http",),
            scope="127.0.0.1",
            authorization_ref="x",  # will be replaced with empty below
        )
        # Simulate missing ref by patching the profile attribute
        no_auth = TargetProfile(
            target_id=profile.target_id,
            mission_id=profile.mission_id,
            platform=profile.platform,
            locator=profile.locator,
            allowed_ports=profile.allowed_ports,
            allowed_protocols=profile.allowed_protocols,
            scope=profile.scope,
            authorization_ref="",  # empty
        )
        self.store.set_target(no_auth)
        request = self._request("127.0.0.1", "ports=80")
        mission = self._mission()
        from raphael_ibm_bob.policy import BOBPolicy
        policy = BOBPolicy(self.workspace, target_store=self.store)
        decision = policy.consult(request, mission)
        self.assertIs(decision.decision, Decision.DENY)
        self.assertIn("discovery-authorization-missing", decision.reason)

    def test_deny_mismatched_host(self):
        self.store.set_target(_loopback_profile("M-disc-test", 80))
        request = self._request("10.0.0.1", "ports=80")  # different host
        mission = self._mission()
        from raphael_ibm_bob.policy import BOBPolicy
        policy = BOBPolicy(self.workspace, target_store=self.store)
        decision = policy.consult(request, mission)
        self.assertIs(decision.decision, Decision.DENY)
        self.assertIn("discovery-target-mismatch", decision.reason)

    def test_deny_malformed_port_spec(self):
        self.store.set_target(_loopback_profile("M-disc-test", 80))
        request = self._request("127.0.0.1", "ports=notaport")
        mission = self._mission()
        from raphael_ibm_bob.policy import BOBPolicy
        policy = BOBPolicy(self.workspace, target_store=self.store)
        decision = policy.consult(request, mission)
        self.assertIs(decision.decision, Decision.DENY)
        self.assertIn("discovery-port-spec-invalid", decision.reason)

    def test_deny_invalid_timeout(self):
        self.store.set_target(_loopback_profile("M-disc-test", 80))
        request = ActionRequest(
            sequence=0, requester="test",
            capability=Capability.NETWORK_SERVICE_DISCOVERY,
            target="127.0.0.1", purpose="ports=80",
            timeout_seconds=-1.0,
        )
        mission = self._mission()
        from raphael_ibm_bob.policy import BOBPolicy
        policy = BOBPolicy(self.workspace, target_store=self.store)
        decision = policy.consult(request, mission)
        self.assertIs(decision.decision, Decision.DENY)
        self.assertIn("discovery-timeout-invalid", decision.reason)


# ---------------------------------------------------------------------------
# Mediator unit tests (no full broker stack, uses direct invocation)
# ---------------------------------------------------------------------------

class MediatorScopeValidation(unittest.TestCase):
    """Direct mediator tests with a stubbed decision that always ALLOWs."""

    def _allow_decision(self, request: ActionRequest):
        from raphael_ibm_bob.contracts import Decision, PolicyDecision
        return PolicyDecision(
            sequence=request.sequence,
            decision=Decision.ALLOW,
            reason="ok",
            capability=request.capability,
            target=request.target,
        )

    def _profile(self) -> TargetProfile:
        return _loopback_profile("M-test", 80)

    def test_out_of_scope_host_denied(self):
        """Mediator rejects a request whose target doesn't match locator."""
        mediator = DiscoveryMediator(port_timeout=0.1, invocation_timeout=2.0)
        profile = self._profile()
        request = ActionRequest(
            sequence=1, requester="t",
            capability=Capability.NETWORK_SERVICE_DISCOVERY,
            target="10.0.0.99",  # not the profile locator
            purpose="ports=80",
        )
        decision = self._allow_decision(request)
        result = mediator.invoke(
            request=request, profile=profile,
            invocation_id="INV-001", run_id="r1",
            decision=decision,
        )
        self.assertIs(result.state, DiscoveryState.DENIED)
        self.assertIn("target-not-authorized", result.error)
        self.assertEqual(result.ports_probed, 0)

    def test_no_decision_allow_denied(self):
        """Mediator rejects when decision is not ALLOW."""
        mediator = DiscoveryMediator(port_timeout=0.1, invocation_timeout=2.0)
        profile = self._profile()
        request = ActionRequest(
            sequence=1, requester="t",
            capability=Capability.NETWORK_SERVICE_DISCOVERY,
            target="127.0.0.1",
            purpose="ports=80",
        )
        result = mediator.invoke(
            request=request, profile=profile,
            invocation_id="INV-002", run_id="r1",
            decision=None,  # no decision
        )
        self.assertIs(result.state, DiscoveryState.DENIED)

    def test_invalid_port_spec_denied(self):
        mediator = DiscoveryMediator(port_timeout=0.1, invocation_timeout=2.0)
        profile = self._profile()
        request = ActionRequest(
            sequence=1, requester="t",
            capability=Capability.NETWORK_SERVICE_DISCOVERY,
            target="127.0.0.1",
            purpose="ports=abc",
        )
        decision = self._allow_decision(request)
        result = mediator.invoke(
            request=request, profile=profile,
            invocation_id="INV-003", run_id="r1",
            decision=decision,
        )
        self.assertIs(result.state, DiscoveryState.DENIED)
        self.assertIn("port-spec-invalid", result.error)


# ---------------------------------------------------------------------------
# Full broker/runtime integration (live loopback listener)
# ---------------------------------------------------------------------------

class DiscoveryIntegration(_Harness):
    def test_authorized_discovery_finds_open_port(self):
        """An authorized discovery against a listening loopback port succeeds."""
        srv, port = _make_listener()
        self.addCleanup(srv.close)
        self.store.set_target(_loopback_profile("M-disc-test", port))
        # Use a fast-timeout mediator so the test doesn't take long.
        fast_mediator = DiscoveryMediator(
            port_timeout=1.0, invocation_timeout=5.0)
        self.broker._discovery_mediator = fast_mediator
        mission = self._mission()
        request = self._request("127.0.0.1", f"ports={port}")
        result = self.runtime.submit(request, mission)
        self.assertIs(result.broker_result.decision.decision, Decision.ALLOW,
                      result.broker_result.decision.reason)
        self.assertTrue(result.execution.success, result.execution.error)
        ev = result.execution.evidence
        self.assertIn(port, ev["ports_open"])
        self.assertEqual(ev["host"], "127.0.0.1")
        self.assertTrue(ev[" provider_untrusted"
                          if "provider_untrusted" not in ev
                          else "provider_untrusted"],
                        "evidence must carry provider_untrusted flag")
        self.assertIn("discovery_result", ev)

    def test_no_open_ports_is_not_success(self):
        """Discovery against a port with no listener: success=False."""
        # Pick a port that is almost certainly not in use.
        closed_port = _free_port()
        self.store.set_target(_loopback_profile("M-disc-test", closed_port))
        fast_mediator = DiscoveryMediator(
            port_timeout=0.2, invocation_timeout=5.0)
        self.broker._discovery_mediator = fast_mediator
        mission = self._mission()
        request = self._request("127.0.0.1", f"ports={closed_port}")
        result = self.runtime.submit(request, mission)
        self.assertIs(result.broker_result.decision.decision, Decision.ALLOW)
        self.assertFalse(result.execution.success)
        ev = result.execution.evidence
        self.assertEqual(ev["ports_open"], [])

    def test_policy_deny_prevents_socket(self):
        """Policy DENY (no profile) must prevent any socket operation."""
        # No profile set → policy DENY → broker must not invoke capability.
        fast_mediator = DiscoveryMediator(
            port_timeout=0.1, invocation_timeout=2.0)
        self.broker._discovery_mediator = fast_mediator
        mission = self._mission()
        request = self._request("127.0.0.1", "ports=80")
        import raphael_ibm_bob.discovery_runtime as dr
        with mock.patch.object(dr, "_probe_port") as probe_mock:
            result = self.runtime.submit(request, mission)
        probe_mock.assert_not_called()
        self.assertIs(result.broker_result.decision.decision, Decision.DENY)
        self.assertFalse(result.broker_result.capability_invoked)

    def test_out_of_scope_host_denied_by_policy(self):
        """Request targeting a different host is DENY'd by Policy."""
        self.store.set_target(_loopback_profile("M-disc-test", 80))
        mission = self._mission()
        request = self._request("10.0.0.99", "ports=80")
        result = self.runtime.submit(request, mission)
        self.assertIs(result.broker_result.decision.decision, Decision.DENY)
        self.assertFalse(result.broker_result.capability_invoked)

    def test_discovery_evidence_is_untrusted(self):
        """Discovery result evidence must carry provider_untrusted=True."""
        srv, port = _make_listener()
        self.addCleanup(srv.close)
        self.store.set_target(_loopback_profile("M-disc-test", port))
        self.broker._discovery_mediator = DiscoveryMediator(
            port_timeout=1.0, invocation_timeout=5.0)
        mission = self._mission()
        request = self._request("127.0.0.1", f"ports={port}")
        result = self.runtime.submit(request, mission)
        ev = result.execution.evidence
        self.assertTrue(ev.get("provider_untrusted"),
                        "discovery evidence must be marked untrusted")

    def test_discovery_evidence_fields_are_truthful(self):
        """Evidence includes host, mission_id, target_id, ports_open."""
        srv, port = _make_listener()
        self.addCleanup(srv.close)
        profile = _loopback_profile("M-disc-test", port)
        self.store.set_target(profile)
        self.broker._discovery_mediator = DiscoveryMediator(
            port_timeout=1.0, invocation_timeout=5.0)
        mission = self._mission()
        request = self._request("127.0.0.1", f"ports={port}")
        result = self.runtime.submit(request, mission)
        ev = result.execution.evidence
        self.assertEqual(ev["host"], "127.0.0.1")
        self.assertEqual(ev["mission_id"], "M-disc-test")
        self.assertEqual(ev["target_id"], profile.target_id)
        self.assertIsInstance(ev["ports_open"], list)
        self.assertIsInstance(ev["ports_probed"], int)

    def test_no_arbitrary_command_execution(self):
        """Discovery mediator must not use subprocess.run or subprocess.Popen."""
        import raphael_ibm_bob.discovery_runtime as dr
        import subprocess
        srv, port = _make_listener()
        self.addCleanup(srv.close)
        self.store.set_target(_loopback_profile("M-disc-test", port))
        self.broker._discovery_mediator = DiscoveryMediator(
            port_timeout=1.0, invocation_timeout=5.0)
        mission = self._mission()
        request = self._request("127.0.0.1", f"ports={port}")
        with mock.patch.object(subprocess, "run", side_effect=AssertionError(
                "subprocess.run must not be called")) as mock_run, \
             mock.patch.object(subprocess, "Popen", side_effect=AssertionError(
                "subprocess.Popen must not be called")) as mock_popen:
            result = self.runtime.submit(request, mission)
        mock_run.assert_not_called()
        mock_popen.assert_not_called()
        # Discovery should still have proceeded normally.
        self.assertIn(result.broker_result.decision.decision,
                      (Decision.ALLOW, Decision.DENY))

    def test_ledger_records_discovery_evidence(self):
        """A successful discovery must produce a 'discovery' producer record."""
        srv, port = _make_listener()
        self.addCleanup(srv.close)
        self.store.set_target(_loopback_profile("M-disc-test", port))
        self.broker._discovery_mediator = DiscoveryMediator(
            port_timeout=1.0, invocation_timeout=5.0)
        mission = self._mission()
        request = self._request("127.0.0.1", f"ports={port}")
        self.runtime.submit(request, mission)
        producers = {r.get("producer")
                     for r in self.ledger.all_records()
                     if r.get("kind") == "evidence"}
        self.assertIn("discovery", producers)

    def test_bounded_discovery_caps_at_max_ports(self):
        """Mediator hard-cap must never exceed MAX_DISCOVERY_PORTS."""
        mediator = DiscoveryMediator(
            port_timeout=0.01, invocation_timeout=1.0,
            max_ports=5)
        # Build a profile for loopback
        self.store.set_target(_loopback_profile("M-disc-test", 80))
        self.broker._discovery_mediator = mediator
        mission = self._mission()
        # Request more ports than the mediator max
        request = self._request("127.0.0.1", "ports=80,81,82,83,84,85,86,87")
        result = self.runtime.submit(request, mission)
        ev = result.execution.evidence
        dr = ev.get("discovery_result", {})
        self.assertLessEqual(dr.get("ports_probed", 999), 5)
        self.assertTrue(dr.get("capped", False))


# ---------------------------------------------------------------------------
# Existing HTTP/Telnet unchanged
# ---------------------------------------------------------------------------

class ExistingCapabilitiesUnchanged(unittest.TestCase):
    """Smoke-check that HTTP and Telnet capabilities still behave correctly."""

    def test_http_capability_still_in_enum(self):
        self.assertEqual(Capability.NETWORK_HTTP_REQUEST.value,
                         "network_http_request")

    def test_telnet_capability_still_in_enum(self):
        self.assertEqual(Capability.NETWORK_TELNET_SESSION.value,
                         "network_telnet_session")

    def test_discovery_does_not_override_http_policy(self):
        """Discovery policy check must not affect NETWORK_HTTP_REQUEST policy."""
        tmp = tempfile.TemporaryDirectory(prefix="raphael-disc-http-")
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name) / "ws"
        root.mkdir()
        workspace = Workspace(root)
        store = TargetStore()
        policy = BOBPolicy(workspace, target_store=store)
        # No target → HTTP must deny (unchanged behavior)
        request = ActionRequest(
            sequence=0, requester="t",
            capability=Capability.NETWORK_HTTP_REQUEST,
            target="http://127.0.0.1:80/",
            purpose="method=GET", timeout_seconds=5.0,
        )
        mission = Mission(
            mission_id="M-http", description="x",
            scope="127.0.0.1", criteria=[])
        decision = policy.consult(request, mission)
        self.assertIs(decision.decision, Decision.DENY)
        self.assertIn("network-no-authorized-target", decision.reason)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _free_port() -> int:
    """Return a port that is not currently in use."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


if __name__ == "__main__":
    unittest.main()
