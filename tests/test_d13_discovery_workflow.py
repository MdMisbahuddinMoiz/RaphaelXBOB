"""tests.test_d13_discovery_workflow — IP-only declaration -> governed
service discovery -> target-scope refinement.

This is the regression for the IP/discovery circular dependency: declaring
an authorized target previously required explicit ports and protocols,
while discovery required an authorized target. The fix is a second
lifecycle stage (``discovery``) whose port/protocol allow-lists are
empty, so it authorizes NETWORK_SERVICE_DISCOVERY and nothing else.

Deterministic and offline: a local stdlib loopback listener stands in for
the target. No external network, no shell, no subprocess, no nmap.

Covers:
    - IP-only declaration succeeds and is marked stage=discovery
    - a discovery-stage profile authorizes NO service capability
    - discovery is authorized on a discovery-stage profile
    - exact-host enforcement (no wildcard / no CIDR widening)
    - bounded port specification
    - discovery success and failure are distinguishable
    - discovery evidence is truthful and UNTRUSTED
    - discovery -> target-scope refinement promotes the profile
    - HTTP route/controller behaviour
    - no subprocess or shell escape in the discovery path
"""
from __future__ import annotations

import ast
import shutil
import socket
import tempfile
import unittest
from pathlib import Path

from raphael_ibm_bob.broker import BOBBroker
from raphael_ibm_bob.contracts import ActionRequest, Capability, Mission
from raphael_ibm_bob.discovery_runtime import (
    MAX_DISCOVERY_PORTS,
    DiscoveryMediator,
    DiscoveryState,
    PortState,
    _probe_port,
    suggested_protocols,
)
from raphael_ibm_bob.evidence_ledger import EvidenceLedger
from raphael_ibm_bob.http.app import (
    RaphaelHTTPConfig,
    Request,
    build_router,
    dispatch,
)
from raphael_ibm_bob.policy import BOBPolicy
from raphael_ibm_bob.runtime import BOBRuntime
from raphael_ibm_bob.target_profile import (
    TARGET_STAGE_AUTHORIZED,
    TARGET_STAGE_DISCOVERY,
    TargetProfileError,
    TargetStore,
    build_target_profile,
)

REPO = Path(__file__).resolve().parents[1]
MISSION = "M-d13-discovery"
HOST = "127.0.0.1"
AUTH_REF = "HTB-AUTHORIZED-D13"


def _listener() -> tuple[socket.socket, int]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, 0))
    srv.listen(5)
    return srv, srv.getsockname()[1]


def _discovery_profile(mission_id: str = MISSION, *, host: str = HOST,
                       scope=None, authorization_ref: str = AUTH_REF):
    return build_target_profile(
        mission_id=mission_id, locator=host, allowed_ports="",
        allowed_protocols="", scope=scope, authorization_ref=authorization_ref,
        stage=TARGET_STAGE_DISCOVERY)


def _authorized_profile(mission_id: str = MISSION, *, host: str = HOST,
                        ports=(80,), protocols=("http",),
                        authorization_ref: str = AUTH_REF):
    return build_target_profile(
        mission_id=mission_id, locator=host, allowed_ports=list(ports),
        allowed_protocols=list(protocols), authorization_ref=authorization_ref,
        stage=TARGET_STAGE_AUTHORIZED)


class _Governed(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="d13-discovery-")
        self.addCleanup(self.tmp.cleanup)
        self.workspace_root = Path(self.tmp.name)
        self.store = TargetStore()
        self.policy = BOBPolicy(_ws(self.workspace_root),
                                target_store=self.store)
        self.mediator = DiscoveryMediator(port_timeout=0.25,
                                          invocation_timeout=10.0,
                                          max_ports=64)
        self.broker = BOBBroker(self.policy, _ws(self.workspace_root),
                                target_store=self.store,
                                discovery_mediator=self.mediator)
        self.runtime = BOBRuntime(self.broker)

    def submit(self, target: str, purpose: str = "",
               mission_id: str = MISSION, timeout_seconds=None):
        mission = Mission(mission_id=mission_id, description="d13",
                          scope=target, criteria=["discovery"])
        request = ActionRequest(
            sequence=0, requester="test",
            capability=Capability.NETWORK_SERVICE_DISCOVERY,
            target=target, purpose=purpose,
            timeout_seconds=timeout_seconds)
        return self.runtime.submit(request, mission)


def _ws(root: Path):
    from raphael_ibm_bob.workspace import Workspace
    return Workspace(root)


# ---------------------------------------------------------------------------
# IP-only declaration (the circular-dependency fix)
# ---------------------------------------------------------------------------

class IPOnlyDeclaration(unittest.TestCase):
    def test_ip_only_profile_builds(self):
        profile = _discovery_profile()
        self.assertEqual(profile.locator, HOST)
        self.assertEqual(profile.allowed_ports, ())
        self.assertEqual(profile.allowed_protocols, ())
        self.assertEqual(profile.stage, TARGET_STAGE_DISCOVERY)
        self.assertTrue(profile.is_discovery_only)
        self.assertTrue(profile.authorization_ref)

    def test_explicit_none_ports_builds(self):
        profile = build_target_profile(
            mission_id=MISSION, locator=HOST, allowed_ports=None,
            allowed_protocols=None, authorization_ref=AUTH_REF,
            stage=TARGET_STAGE_DISCOVERY)
        self.assertEqual(profile.allowed_ports, ())

    def test_authorized_stage_still_requires_ports(self):
        with self.assertRaises(TargetProfileError):
            build_target_profile(
                mission_id=MISSION, locator=HOST, allowed_ports="",
                allowed_protocols="", authorization_ref=AUTH_REF)

    def test_authorized_stage_still_requires_protocols(self):
        with self.assertRaises(TargetProfileError):
            build_target_profile(
                mission_id=MISSION, locator=HOST, allowed_ports="80",
                allowed_protocols="", authorization_ref=AUTH_REF)

    def test_authorized_profile_is_not_discovery_only(self):
        self.assertFalse(_authorized_profile().is_discovery_only)
        self.assertEqual(_authorized_profile().stage, TARGET_STAGE_AUTHORIZED)

    def test_unknown_stage_rejected(self):
        with self.assertRaises(TargetProfileError):
            build_target_profile(
                mission_id=MISSION, locator=HOST, allowed_ports="",
                allowed_protocols="", authorization_ref=AUTH_REF,
                stage="wildcard")

    def test_serialised_profile_exposes_stage(self):
        payload = _discovery_profile().to_dict()
        self.assertEqual(payload["stage"], TARGET_STAGE_DISCOVERY)
        self.assertTrue(payload["discovery_only"])

    def test_manual_declaration_still_works(self):
        profile = _authorized_profile(ports=(80, 443),
                                      protocols=("http", "https"))
        self.assertEqual(profile.allowed_ports, (80, 443))
        self.assertTrue(profile.allows(host=HOST, port=443, protocol="https"))


# ---------------------------------------------------------------------------
# A discovery-stage profile authorizes no service capability
# ---------------------------------------------------------------------------

class DiscoveryProfileAuthorizesNothingElse(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = _discovery_profile()
        self.tmp = tempfile.TemporaryDirectory(prefix="d13-stage-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = TargetStore()
        self.store.set_target(self.profile)
        self.policy = BOBPolicy(_ws(self.root), target_store=self.store)

    def _decide(self, capability: Capability, target: str, purpose: str = ""):
        mission = Mission(mission_id=MISSION, description="d13", scope=HOST,
                          criteria=["c"])
        request = ActionRequest(sequence=0, requester="test",
                                capability=capability, target=target,
                                purpose=purpose)
        return self.policy.consult(request, mission)

    def test_allows_is_false_for_every_port_and_protocol(self):
        for port in (80, 443, 23, 8080):
            for proto in ("http", "https", "telnet"):
                self.assertFalse(
                    self.profile.allows(host=HOST, port=port, protocol=proto),
                    f"discovery profile must not allow {proto}/{port}")

    def test_http_is_denied(self):
        decision = self._decide(Capability.NETWORK_HTTP_REQUEST,
                                f"http://{HOST}/")
        self.assertEqual(decision.decision.value, "deny")
        self.assertEqual(decision.reason, "network-target-mismatch")

    def test_telnet_is_denied(self):
        decision = self._decide(Capability.NETWORK_TELNET_SESSION,
                                f"telnet://{HOST}:23")
        self.assertEqual(decision.decision.value, "deny")
        self.assertEqual(decision.reason, "telnet-target-mismatch")

    def test_discovery_is_allowed(self):
        decision = self._decide(Capability.NETWORK_SERVICE_DISCOVERY, HOST)
        self.assertEqual(decision.decision.value, "allow")


# ---------------------------------------------------------------------------
# Discovery authorization: exact host, bounded ports, fail closed
# ---------------------------------------------------------------------------

class DiscoveryAuthorization(_Governed):
    def test_discovery_allowed_on_ip_only_profile(self):
        self.store.set_target(_discovery_profile())
        result = self.submit(HOST, "ports=1-2")
        self.assertEqual(result.broker_result.decision.decision.value, "allow")

    def test_discovery_allowed_on_authorized_profile(self):
        self.store.set_target(_authorized_profile())
        result = self.submit(HOST, "ports=1-2")
        self.assertEqual(result.broker_result.decision.decision.value, "allow")

    def test_denied_without_any_target(self):
        result = self.submit(HOST, "ports=1-2")
        self.assertEqual(result.broker_result.decision.decision.value, "deny")
        self.assertEqual(result.broker_result.decision.reason,
                         "discovery-no-authorized-target")

    def test_denied_when_target_belongs_to_another_mission(self):
        self.store.set_target(_discovery_profile("M-someone-else"))
        result = self.submit(HOST, "ports=1-2")
        self.assertEqual(result.broker_result.decision.decision.value, "deny")

    def test_denied_without_authorization_ref(self):
        with self.assertRaises(TargetProfileError):
            _discovery_profile(authorization_ref="")
        self.store.set_target(_discovery_profile())
        result = self.submit(HOST, "ports=1-2")
        self.assertEqual(result.broker_result.decision.decision.value, "allow")

    def test_exact_host_enforced_other_host_denied(self):
        self.store.set_target(_discovery_profile())
        result = self.submit("10.129.101.115", "ports=1-2")
        decision = result.broker_result.decision
        self.assertEqual(decision.decision.value, "deny")
        self.assertEqual(decision.reason, "discovery-target-mismatch")

    def test_no_wildcard_expansion(self):
        self.store.set_target(_discovery_profile())
        for bad in ("0.0.0.0", "*", "10.129.0.0/16", "10.129.101.0/24"):
            result = self.submit(bad, "ports=1-2")
            self.assertEqual(
                result.broker_result.decision.decision.value, "deny",
                f"{bad} must not be discoverable")

    def test_port_bearing_target_string_rejected(self):
        self.store.set_target(_discovery_profile())
        result = self.submit(f"{HOST}:8080", "ports=1-2")
        self.assertEqual(result.broker_result.decision.decision.value, "deny")

    def test_bounded_range_does_not_materialize_full_range(self):
        self.store.set_target(_discovery_profile())
        result = self.submit(HOST, "ports=1-65535")
        decision = result.broker_result.decision
        self.assertEqual(decision.decision.value, "allow")
        evidence = result.execution.evidence
        self.assertLessEqual(evidence["ports_probed"], 64)

    def test_malformed_port_spec_denied(self):
        self.store.set_target(_discovery_profile())
        for spec in ("ports=0", "ports=70000", "ports=abc", "ports=9-1"):
            result = self.submit(HOST, spec)
            self.assertEqual(
                result.broker_result.decision.decision.value, "deny", spec)
            self.assertIn("port-spec-invalid",
                          result.broker_result.decision.reason)

    def test_invalid_timeout_denied(self):
        self.store.set_target(_discovery_profile())
        mission = Mission(mission_id=MISSION, description="d13", scope=HOST,
                          criteria=["discovery"])
        for bad in (0, -1, True, "abc", float("nan")):
            request = ActionRequest(
                sequence=0, requester="test",
                capability=Capability.NETWORK_SERVICE_DISCOVERY,
                target=HOST, purpose="ports=1-2", timeout_seconds=bad)
            decision = self.policy.consult(request, mission)
            self.assertEqual(decision.decision.value, "deny", repr(bad))
            self.assertEqual(decision.reason, "discovery-timeout-invalid")

    def test_non_positive_timeout_rejected_by_broker(self):
        self.store.set_target(_discovery_profile())
        for bad in (0, -1):
            with self.assertRaises(ValueError):
                self.submit(HOST, "ports=1-2", timeout_seconds=bad)

    def test_out_of_scope_locator_rejected_at_build(self):
        with self.assertRaises(TargetProfileError):
            _discovery_profile(scope="10.0.0.0/8")


# ---------------------------------------------------------------------------
# Discovery success / failure and truthful evidence
# ---------------------------------------------------------------------------

class DiscoveryTruthfulness(_Governed):
    def setUp(self) -> None:
        super().setUp()
        self.srv, self.open_port = _listener()
        self.addCleanup(self.srv.close)

    def test_open_port_is_found_and_reported_truthfully(self):
        self.store.set_target(_discovery_profile())
        result = self.submit(HOST, f"ports={self.open_port}")
        self.assertTrue(result.execution.success)
        evidence = result.execution.evidence
        self.assertEqual(list(evidence["ports_open"]), [self.open_port])
        self.assertEqual(evidence["host"], HOST)
        self.assertEqual(evidence["mission_id"], MISSION)
        self.assertEqual(evidence["ports_probed"], 1)
        self.assertTrue(evidence["provider_untrusted"])
        details = [d for d in evidence["discovery_result"]["port_results"]
                   if d["port"] == self.open_port]
        self.assertEqual(details[0]["state"], "open")

    def test_closed_port_is_not_reported_open(self):
        self.store.set_target(_discovery_profile())
        closed = _closed_port()
        result = self.submit(HOST, f"ports={closed}")
        self.assertFalse(result.execution.success)
        evidence = result.execution.evidence
        self.assertEqual(evidence["ports_open"], [])
        self.assertEqual(evidence["discovery_result"]["state"],
                         DiscoveryState.NO_OPEN_PORTS.value)

    def test_mixed_ports_report_only_the_open_one(self):
        self.store.set_target(_discovery_profile())
        closed = _closed_port()
        result = self.submit(HOST, f"ports={closed},{self.open_port}")
        self.assertTrue(result.execution.success)
        self.assertEqual(list(result.execution.evidence["ports_open"]),
                         [self.open_port])
        self.assertEqual(result.execution.evidence["ports_probed"], 2)

    def test_capped_is_reported_when_mediator_truncates(self):
        self.store.set_target(_discovery_profile())
        result = self.submit(HOST, "ports=1-200")
        evidence = result.execution.evidence
        self.assertTrue(evidence["capped"])
        self.assertLessEqual(evidence["ports_probed"], 64)

    def test_evidence_never_claims_authority(self):
        self.store.set_target(_discovery_profile())
        result = self.submit(HOST, f"ports={self.open_port}")
        evidence = result.execution.evidence
        self.assertTrue(evidence["provider_untrusted"])
        self.assertNotIn("verdict", evidence)
        self.assertNotIn("finding_state", evidence)

    def test_ledger_records_discovery_producer(self):
        ledger = EvidenceLedger(self.workspace_root / "ledger")
        self.addCleanup(ledger.close)
        broker = BOBBroker(self.policy, _ws(self.workspace_root),
                          ledger=ledger, target_store=self.store,
                          discovery_mediator=self.mediator)
        runtime = BOBRuntime(broker)
        self.store.set_target(_discovery_profile())
        mission = Mission(mission_id=MISSION, description="d13", scope=HOST,
                          criteria=["discovery"])
        runtime.submit(ActionRequest(
            sequence=0, requester="test",
            capability=Capability.NETWORK_SERVICE_DISCOVERY,
            target=HOST, purpose=f"ports={self.open_port}"), mission)
        producers = {r.get("producer")
                     for r in ledger.all_records()
                     if r.get("kind") == "evidence"}
        self.assertIn("discovery", producers)


def _closed_port() -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind((HOST, 0))
    port = srv.getsockname()[1]
    srv.close()
    return port


# ---------------------------------------------------------------------------
# discovery -> target-scope refinement
# ---------------------------------------------------------------------------

class ScopeRefinement(unittest.TestCase):
    def test_refined_promotes_to_authorized(self):
        discovered = [80, 8080]
        profile = _discovery_profile().refined(
            allowed_ports=discovered,
            allowed_protocols=suggested_protocols(discovered))
        self.assertEqual(profile.stage, TARGET_STAGE_AUTHORIZED)
        self.assertEqual(profile.allowed_ports, (80, 8080))
        self.assertEqual(profile.allowed_protocols, ("http",))
        self.assertTrue(profile.allows(host=HOST, port=8080, protocol="http"))
        self.assertFalse(profile.allows(host=HOST, port=22, protocol="http"))

    def test_refined_preserves_host_scope_and_authorization(self):
        base = _discovery_profile()
        refined = base.refined(allowed_ports=[23],
                               allowed_protocols=["telnet"])
        self.assertEqual(refined.locator, base.locator)
        self.assertEqual(refined.scope, base.scope)
        self.assertEqual(refined.authorization_ref, base.authorization_ref)
        self.assertEqual(refined.mission_id, base.mission_id)

    def test_refined_rejects_empty_allow_lists(self):
        with self.assertRaises(TargetProfileError):
            _discovery_profile().refined(allowed_ports=[], allowed_protocols=[])

    def test_refined_rejects_unsupported_protocol(self):
        with self.assertRaises(TargetProfileError):
            _discovery_profile().refined(allowed_ports=[22],
                                        allowed_protocols=["gopher"])

    def test_suggested_protocols_are_bounded_by_allowed_protocols(self):
        self.assertEqual(suggested_protocols([22, 25, 445]), ())
        self.assertEqual(suggested_protocols([23]), ("telnet",))
        self.assertEqual(suggested_protocols([80, 443]), ("http", "https"))
        self.assertEqual(suggested_protocols([9999]), ())

    def test_refinement_actually_unblocks_http_policy(self):
        tmp = tempfile.TemporaryDirectory(prefix="d13-refine-")
        self.addCleanup(tmp.cleanup)
        store = TargetStore()
        store.set_target(_discovery_profile())
        workspace = _ws(Path(tmp.name))
        policy = BOBPolicy(workspace, target_store=store)
        mission = Mission(mission_id=MISSION, description="d13", scope=HOST,
                          criteria=["c"])
        http_request = ActionRequest(
            sequence=0, requester="test",
            capability=Capability.NETWORK_HTTP_REQUEST,
            target=f"http://{HOST}:80/", purpose="method=GET")
        self.assertEqual(
            policy.consult(http_request, mission).decision.value, "deny")

        store.set_target(store.current().refined(
            allowed_ports=[80], allowed_protocols=["http"]))
        self.assertEqual(
            policy.consult(http_request, mission).decision.value, "allow")


# ---------------------------------------------------------------------------
# HTTP route / controller behaviour
# ---------------------------------------------------------------------------

class _Routes(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="d13-routes-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = TargetStore()
        self.cfg = RaphaelHTTPConfig(target_store=self.store,
                                     runs_root=self.root / "runs")
        self.router = build_router()

    def call(self, method, path, body=None):
        return dispatch(Request(method=method, path=path, body=body),
                        self.cfg, self.router)

    def declare_ip_only(self, host=HOST, mission_id=MISSION):
        return self.call("POST", "/htb/target", {
            "mission_id": mission_id, "locator": host,
            "allowed_ports": "", "allowed_protocols": "",
            "scope": host, "authorization_ref": AUTH_REF,
            "stage": "discovery"})

    def test_route_declared_ip_only_target(self):
        resp = self.declare_ip_only()
        self.assertEqual(resp.status, 201, resp.body)
        target = resp.body["target"]
        self.assertEqual(target["stage"], "discovery")
        self.assertEqual(target["allowed_ports"], [])
        self.assertTrue(target["discovery_only"])

    def test_route_rejects_unknown_stage(self):
        resp = self.call("POST", "/htb/target", {
            "mission_id": MISSION, "locator": HOST, "allowed_ports": "",
            "allowed_protocols": "", "authorization_ref": AUTH_REF,
            "stage": "root"})
        self.assertEqual(resp.status, 422)

    def test_route_still_requires_ports_for_authorized_stage(self):
        resp = self.call("POST", "/htb/target", {
            "mission_id": MISSION, "locator": HOST, "allowed_ports": "",
            "allowed_protocols": "", "authorization_ref": AUTH_REF})
        self.assertEqual(resp.status, 422)

    def test_route_manual_declaration_unaffected(self):
        resp = self.call("POST", "/htb/target", {
            "mission_id": MISSION, "locator": HOST, "allowed_ports": "80,443",
            "allowed_protocols": "http,https", "authorization_ref": AUTH_REF})
        self.assertEqual(resp.status, 201, resp.body)
        self.assertEqual(resp.body["target"]["stage"], "authorized")

    def test_discover_denied_without_declared_target(self):
        resp = self.call("POST", "/htb/discover",
                         {"host": HOST, "mission_id": MISSION})
        self.assertEqual(resp.status, 403, resp.body)
        self.assertFalse(resp.body["allowed"])
        self.assertEqual(resp.body["deny_reason"],
                         "discovery-no-authorized-target")

    def test_discover_denied_for_foreign_host(self):
        self.declare_ip_only()
        resp = self.call("POST", "/htb/discover",
                         {"host": "10.129.101.115", "mission_id": MISSION})
        self.assertEqual(resp.status, 403, resp.body)
        self.assertEqual(resp.body["deny_reason"], "discovery-target-mismatch")

    def test_discover_reports_open_port_and_suggestions(self):
        srv, port = _listener()
        self.addCleanup(srv.close)
        self.declare_ip_only()
        resp = self.call("POST", "/htb/discover", {
            "host": HOST, "mission_id": MISSION, "port_spec": str(port)})
        self.assertEqual(resp.status, 200, resp.body)
        self.assertTrue(resp.body["allowed"])
        self.assertTrue(resp.body["success"])
        self.assertEqual(resp.body["ports_open"], [port])
        self.assertEqual(resp.body["ports_probed"], 1)
        self.assertEqual(resp.body["state"], "success")
        self.assertEqual(resp.body["host"], HOST)
        self.assertIn("suggested_protocols", resp.body)
        self.assertTrue(resp.body["invocation_id"].startswith("DSC-"))

    def test_discover_requires_host_and_mission(self):
        self.assertEqual(
            self.call("POST", "/htb/discover", {"mission_id": MISSION}).status,
            422)
        self.assertEqual(
            self.call("POST", "/htb/discover", {"host": HOST}).status, 422)

    def test_discover_rejects_bad_timeout(self):
        self.declare_ip_only()
        for bad in (0, -5, "abc", 100000):
            resp = self.call("POST", "/htb/discover", {
                "host": HOST, "mission_id": MISSION, "timeout": bad})
            self.assertEqual(resp.status, 422, repr(bad))


class ConsoleView(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="d13-ui-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def render(self, target_state):
        from raphael_ibm_bob.http.views.operations_console import render_index
        return render_index(
            [], runs_root=self.tmp, sessions_root=self.tmp,
            vpn_status={"state": "connected"},
            mode_state={"mode": "testing", "testing_profile": "htb"},
            target_state=target_state)

    def test_discovery_controls_present(self):
        html = self.render(None)
        self.assertIn("DISCOVER SERVICES", html)
        self.assertIn("APPLY TO TARGET SCOPE", html)
        self.assertIn("tg-disc-ports", html)
        self.assertIn("tg-disc-result", html)
        self.assertIn("/htb/discover", html)

    def test_ports_are_not_required_in_the_form(self):
        html = self.render(None)
        self.assertNotIn('id="tg-ports" required', html)
        self.assertNotIn('id="tg-protocols" required', html)

    def test_no_guessed_ports_are_prefilled(self):
        html = self.render(None)
        self.assertIn('id="tg-ports" value=""', html)
        self.assertNotIn('id="tg-ports" value="80,443"', html)

    def test_discovery_only_target_is_labelled(self):
        html = self.render({
            "mission_id": MISSION, "locator": HOST, "allowed_ports": [],
            "allowed_protocols": [], "scope": HOST,
            "authorization_ref": AUTH_REF, "stage": "discovery",
            "discovery_only": True})
        self.assertIn("DISCOVERY ONLY", html)
        self.assertIn("no service port is", html)

    def test_authorized_target_still_labelled_authorized(self):
        html = self.render({
            "mission_id": MISSION, "locator": HOST, "allowed_ports": [80],
            "allowed_protocols": ["http"], "scope": HOST,
            "authorization_ref": AUTH_REF, "stage": "authorized"})
        self.assertIn("SERVICE AUTHORIZED", html)
        self.assertIn('id="tg-ports" value="80"', html)


# ---------------------------------------------------------------------------
# no subprocess / shell escape
# ---------------------------------------------------------------------------

class NoEscape(unittest.TestCase):
    MODULES = (
        "raphael_ibm_bob/discovery_runtime.py",
        "raphael_ibm_bob/harness/discovery_run.py",
        "raphael_ibm_bob/http/routes/htb.py",
    )
    FORBIDDEN_IMPORTS = {"subprocess", "pty", "multiprocessing", "commands"}
    FORBIDDEN_CALLS = {"system", "popen", "spawn", "spawnl", "execv", "execve"}

    def test_no_process_spawning_imports(self):
        for rel in self.MODULES:
            tree = ast.parse((REPO / rel).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotIn(alias.name.split(".")[0],
                                         self.FORBIDDEN_IMPORTS, f"{rel}")
                elif isinstance(node, ast.ImportFrom) and node.module:
                    self.assertNotIn(node.module.split(".")[0],
                                     self.FORBIDDEN_IMPORTS, f"{rel}")

    def test_no_process_spawning_calls(self):
        for rel in self.MODULES:
            tree = ast.parse((REPO / rel).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if isinstance(func, ast.Attribute):
                    self.assertNotIn(func.attr, self.FORBIDDEN_CALLS,
                                     f"{rel}: {func.attr}")
                for kw in node.keywords:
                    self.assertNotEqual(kw.arg, "shell", f"{rel}: shell=")

    def test_discovery_uses_only_tcp_connect(self):
        text = (REPO / "raphael_ibm_bob/discovery_runtime.py").read_text(
            encoding="utf-8")
        self.assertIn("socket.connect_ex", text)
        for needle in ("urllib.request", "http.client", "AF_PACKET",
                       "SOCK_RAW", "importlib.import_module"):
            self.assertNotIn(needle, text)

    def test_probe_never_reports_non_open_as_open(self):
        closed = _closed_port()
        result = _probe_port(HOST, closed, 0.5)
        self.assertIsNot(result.state, PortState.OPEN)
        self.assertIsNot(result.state, None)
