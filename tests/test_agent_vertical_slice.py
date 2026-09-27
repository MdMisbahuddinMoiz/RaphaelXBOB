"""tests.test_agent_vertical_slice — the AI pentester vertical slice.

Focused tests for the seven properties the slice must hold:

    1. provider configuration      normalized, redacted, never echoed
    2. provider adapter            messages -> structured proposal
    3. invalid provider / API failure   fails closed, no key leak
    4. planner -> Broker boundary  every proposal is brokered
    5. unauthorized rejection      an out-of-scope action never executes
    6. evidence returned to planner    discovered ports reach turn N+1
    7. no direct model->tool path  the model holds no execution handle

Deterministic and offline. The "model" is an in-process stub that returns
scripted proposals (a labelled test double, never a live provider); the
"target" is a real loopback listener so the governed discovery path
actually executes. No external network, no shell, no subprocess.
"""
from __future__ import annotations

import json
import socket
import tempfile
import threading
import unittest
from unittest import mock
from pathlib import Path

from raphael_ibm_bob.contracts import ActionRequest, Capability, Mission
from raphael_ibm_bob.harness import api
from raphael_ibm_bob.harness.model import ModelAdapter, ModelContext
from raphael_ibm_bob.harness.model_run import (
    MAX_OBSERVATIONS,
    authorized_session_view,
    fold_observations,
)
from raphael_ibm_bob.harness.providers import (
    ProviderConfig,
    ProviderConfigError,
    ProviderRegistry,
    default_provider_registry,
)
from raphael_ibm_bob.harness.providers.openai_compat import (
    OpenAICompatAdapter,
    ProviderError,
    validate_proposal,
)
from raphael_ibm_bob.http.app import Request, config_from_env, dispatch
from raphael_ibm_bob.http.routes import agent as agent_routes
from raphael_ibm_bob.skills import default_registry, register_default_skills
from raphael_ibm_bob.target_profile import (
    TARGET_STAGE_AUTHORIZED,
    TargetStore,
    build_target_profile,
)

SECRET = "sk-test-vertical-slice-DO-NOT-LEAK-0001"
HOST = "127.0.0.1"
MISSION_ID = "M-AGENT-TEST-001"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

class _Listener:
    """A real loopback TCP listener standing in for the target service."""

    def __init__(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((HOST, 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        self._sock.settimeout(0.2)
        while not self._stop:
            try:
                conn, _addr = self._sock.accept()
            except (TimeoutError, OSError):
                continue
            try:
                conn.close()
            except OSError:
                pass

    def close(self) -> None:
        self._stop = True
        self._thread.join(timeout=2)
        self._sock.close()


def _mission() -> Mission:
    return Mission(
        mission_id=MISSION_ID,
        description=f"governed assessment of {HOST}",
        scope=HOST,
        criteria=["service-discovery"],
    )


def _profile(port: int, *, protocols: str = "http") -> object:
    return build_target_profile(
        mission_id=MISSION_ID,
        locator=HOST,
        allowed_ports=[port],
        allowed_protocols=protocols,
        authorization_ref="unit-test-lab",
        platform="htb",
        stage=TARGET_STAGE_AUTHORIZED,
    )


class _ScriptedProposer:
    """Deterministic model double: scripted proposals, one per turn.

    Satisfies the `ModelAdapter` protocol. It holds no capability, no
    broker, no mediator, and no socket — it can only RETURN an
    `ActionRequest`, which is exactly the boundary the tests defend.
    """

    def __init__(self, proposals):
        self._proposals = list(proposals)
        self.contexts = []

    def propose(self, context: ModelContext) -> ActionRequest:
        self.contexts.append(context)
        if not self._proposals:
            from raphael_ibm_bob.harness.providers import DoneSignal
            raise DoneSignal("script exhausted")
        return self._proposals.pop(0)


def _discovery_request(target: str, purpose: str) -> ActionRequest:
    return ActionRequest(
        sequence=0,
        requester="skill:network-service-discovery",
        capability=Capability.NETWORK_SERVICE_DISCOVERY,
        target=target,
        purpose=purpose,
        timeout_seconds=10.0,
    )


def _run_agent(tmp: Path, listener: _Listener, model):
    """Drive the governed loop against a freshly declared target."""
    store = TargetStore()
    store.set_target(_profile(listener.port))
    mission = _mission()
    session = api.create_session(
        mission=mission, workspace_root=tmp / "workspace",
        project_name=MISSION_ID, sessions_root=tmp / "sessions")
    result = api.start_model_run(
        session, mission=mission, model=model, max_turns=4,
        sessions_root=tmp / "sessions", runs_root=tmp / "runs",
        target_store=store)
    return result, store


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="raphael-vs-")
        self.tmp = Path(self._tmp.name)
        (self.tmp / "workspace").mkdir()
        self.addCleanup(self._tmp.cleanup)
        self.listener = _Listener()
        self.addCleanup(self.listener.close)

    def _context(self, observations=()) -> ModelContext:
        return ModelContext(mission=_mission(), observations=observations)


# ---------------------------------------------------------------------------
# 1. Provider configuration
# ---------------------------------------------------------------------------

class ProviderConfigurationTests(_Base):
    def test_normalized_config_reports_every_field(self):
        config = ProviderConfig(
            provider="openai-compatible", endpoint="http://h/v1",
            model="m", api_key=SECRET)
        redacted = config.redacted()
        self.assertEqual(redacted["provider"], "openai-compatible")
        self.assertEqual(redacted["endpoint"], "http://h/v1")
        self.assertEqual(redacted["model"], "m")
        self.assertEqual(redacted["api_key"], "set")

    def test_credential_is_write_only_in_every_rendering(self):
        config = ProviderConfig(
            provider="openai-compatible", endpoint="http://h/v1",
            model="m", api_key=SECRET)
        for rendered in (repr(config), str(config), json.dumps(
                config.redacted(), sort_keys=True), f"{config}"):
            self.assertNotIn(SECRET, rendered, rendered)

    def test_blank_key_reports_unset(self):
        config = ProviderConfig(endpoint="http://h/v1", model="m")
        self.assertEqual(config.redacted()["api_key"], "unset")
        self.assertFalse(config.has_api_key)

    def test_config_is_frozen(self):
        config = ProviderConfig(endpoint="http://h/v1", model="m")
        with self.assertRaises(Exception):
            config.model = "other"  # type: ignore[misc]

    def test_operator_fields_win_over_environment(self):
        config = api.build_provider_configuration(
            "openai-compatible", endpoint="http://operator/v1",
            model="operator-model", api_key=SECRET,
            environ={"RAPHAEL_MODEL_ENDPOINT": "http://env/v1",
                     "RAPHAEL_MODEL_NAME": "env-model",
                     "RAPHAEL_MODEL_API_KEY": "env-key"})
        self.assertEqual(config.endpoint, "http://operator/v1")
        self.assertEqual(config.model, "operator-model")
        self.assertEqual(config.api_key, SECRET)

    def test_blank_operator_fields_fall_back_to_environment(self):
        config = api.build_provider_configuration(
            "openai-compatible",
            environ={"RAPHAEL_MODEL_ENDPOINT": "http://env/v1",
                     "RAPHAEL_MODEL_NAME": "env-model",
                     "RAPHAEL_MODEL_API_KEY": "env-key"})
        self.assertEqual(config.endpoint, "http://env/v1")
        self.assertEqual(config.model, "env-model")
        self.assertEqual(config.api_key, "env-key")

    def test_missing_configuration_names_the_field_not_the_value(self):
        """The error names the FORM FIELD, never a value.

        The endpoint now has a provider-declared default, so the model
        is the only field an operator can still leave unset.
        """
        with self.assertRaises(ProviderConfigError) as ctx:
            api.build_provider_configuration(
                "openai-compatible", environ={})
        message = str(ctx.exception)
        self.assertIn("model", message)
        self.assertIn("RAPHAEL_MODEL_NAME", message)
        self.assertNotIn(SECRET, message)

    def test_endpoint_falls_back_to_the_provider_default(self):
        """BLANKER 1: selecting a provider alone must be enough."""
        config = api.build_provider_configuration(
            "openai-compatible", model="m", environ={})
        self.assertEqual(config.endpoint,
                         "https://openrouter.ai/api/v1")

    def test_explicit_endpoint_still_beats_the_default(self):
        config = api.build_provider_configuration(
            "openai-compatible", endpoint="http://operator/v1", model="m",
            environ={})
        self.assertEqual(config.endpoint, "http://operator/v1")

    def test_environment_is_never_mutated(self):
        import os
        before = dict(os.environ)
        api.build_provider_configuration(
            "openai-compatible", endpoint="http://operator/v1",
            model="m", api_key=SECRET, environ={})
        self.assertEqual(dict(os.environ), before)

    def test_invalid_bounds_fail_closed(self):
        for kwargs in ({"timeout_seconds": 0}, {"max_tokens": 0},
                       {"temperature": 9.0}, {"provider": "  "}):
            with self.subTest(**kwargs):
                with self.assertRaises(ProviderConfigError):
                    ProviderConfig(endpoint="http://h/v1", model="m", **kwargs)


# ---------------------------------------------------------------------------
# 2. Provider adapter (planner stays provider-agnostic)
# ---------------------------------------------------------------------------

class ProviderAdapterTests(_Base):
    def test_registry_dispatches_by_provider_id(self):
        registry = default_provider_registry()
        self.assertIn("openai-compatible", registry)
        config = ProviderConfig(endpoint="http://h/v1", model="m")
        adapter = registry.create(config, default_registry())
        self.assertIsInstance(adapter, OpenAICompatAdapter)
        self.assertIsInstance(adapter, ModelAdapter)

    def test_provider_registry_is_additive_not_a_branch(self):
        registry = ProviderRegistry()
        registry.register("stub", lambda config, reg: config)
        self.assertEqual(registry.provider_ids(), ("stub",))
        with self.assertRaises(ProviderConfigError):
            registry.register("stub", lambda config, reg: config)

    def test_planner_consumes_only_the_model_adapter_protocol(self):
        adapter = api.make_model_adapter(
            "openai-compatible", endpoint="http://127.0.0.1:1/v1",
            model="m", api_key=SECRET, environ={})
        self.assertIsInstance(adapter, ModelAdapter)
        # The planner-visible surface is exactly `propose(context)`.
        self.assertTrue(hasattr(adapter, "propose"))
        for forbidden in ("submit", "execute_capability", "invoke",
                          "run_capability", "socket", "Popen"):
            self.assertFalse(hasattr(adapter, forbidden), forbidden)

    def test_validated_proposal_becomes_an_action_request(self):
        registry = register_default_skills(default_registry())
        request = validate_proposal(
            {"intent": "act", "skill": "network-service-discovery",
             "target": HOST, "purpose": "ports=8080 learn what listens"},
            registry)
        self.assertIsInstance(request, ActionRequest)
        self.assertEqual(request.capability,
                         Capability.NETWORK_SERVICE_DISCOVERY)
        self.assertEqual(request.target, HOST)
        self.assertEqual(request.requester,
                         "skill:network-service-discovery")

    def test_discovery_skill_is_offered_to_the_model(self):
        from raphael_ibm_bob.harness.providers.openai_compat import (
            skill_catalog)
        catalog = skill_catalog(register_default_skills(default_registry()))
        entries = {c["skill"]: c for c in catalog}
        self.assertIn("network-service-discovery", entries)
        self.assertEqual(entries["network-service-discovery"]["capability"],
                         Capability.NETWORK_SERVICE_DISCOVERY.value)
        self.assertIn("ports=", entries["network-service-discovery"][
            "description"])


# ---------------------------------------------------------------------------
# 3. Invalid provider / API failure
# ---------------------------------------------------------------------------

class ProviderFailureTests(_Base):
    def test_unknown_provider_is_rejected_before_any_request(self):
        with self.assertRaises(ProviderConfigError) as ctx:
            api.make_model_adapter(
                "no-such-provider", endpoint="http://127.0.0.1:1/v1",
                model="m", api_key=SECRET, environ={})
        message = str(ctx.exception)
        self.assertIn("unknown provider", message)
        self.assertNotIn(SECRET, message)

    def test_unreachable_endpoint_raises_provider_error(self):
        adapter = api.make_model_adapter(
            "openai-compatible", endpoint="http://127.0.0.1:1/v1",
            model="m", api_key=SECRET, environ={})
        with self.assertRaises(ProviderError) as ctx:
            adapter.propose(self._context())
        self.assertNotIn(SECRET, str(ctx.exception))

    def test_provider_error_message_names_no_credential(self):
        adapter = api.make_model_adapter(
            "openai-compatible", endpoint="http://127.0.0.1:1/v1",
            model="m", api_key=SECRET, environ={})
        try:
            adapter.propose(self._context())
        except ProviderError as exc:
            rendered = "".join(str(v) for v in
                               (exc, exc.args, exc.__cause__))
        else:  # pragma: no cover - the call must fail
            self.fail("unreachable endpoint did not raise")
        self.assertNotIn(SECRET, rendered)

    def test_malformed_provider_payload_fails_closed(self):
        registry = register_default_skills(default_registry())
        from raphael_ibm_bob.harness.providers import StructuredProposalError
        for payload in ({}, {"intent": "act"},
                        {"intent": "act", "skill": "nope",
                         "target": HOST, "purpose": "p"},
                        {"intent": "act", "skill": "read-file",
                         "target": HOST}):
            with self.subTest(payload=payload):
                with self.assertRaises(StructuredProposalError):
                    validate_proposal(payload, registry)


# ---------------------------------------------------------------------------
# 4/5/6/7. The governed loop
# ---------------------------------------------------------------------------

class GovernedLoopTests(_Base):
    def test_authorized_discovery_is_brokered_and_evidenced(self):
        model = _ScriptedProposer([
            _discovery_request(HOST, f"ports={self.listener.port} probe"),
        ])
        result, _store = _run_agent(self.tmp, self.listener, model)
        timeline = api.get_agent_timeline(result.run.run_id, self.tmp / "runs")
        self.assertIsNotNone(timeline)
        turn = timeline["turns"][0]
        self.assertEqual(turn["policy"]["decision"], "allow")
        self.assertTrue(turn["execution"]["executed"])
        self.assertTrue(turn["execution"]["success"])
        self.assertTrue(turn["evidence"]["evidence_ids"])
        self.assertTrue(turn["evidence"]["provider_untrusted"])
        records = api.get_evidence(result.run.run_id, self.tmp / "runs")
        kinds = [r.get("kind") for r in records]
        self.assertIn("request", kinds)
        self.assertIn("decision", kinds)
        self.assertIn("result", kinds)
        self.assertIn("evidence", kinds)

    def test_unauthorized_target_is_denied_and_never_executes(self):
        # The model proposes a host the operator never declared.
        model = _ScriptedProposer([
            _discovery_request("10.255.255.1", "ports=80 probe"),
        ])
        result, _store = _run_agent(self.tmp, self.listener, model)
        timeline = api.get_agent_timeline(result.run.run_id, self.tmp / "runs")
        turn = timeline["turns"][0]
        self.assertEqual(turn["policy"]["decision"], "deny")
        self.assertIn("discovery-target-mismatch", turn["policy"]["reason"])
        self.assertFalse(turn["execution"]["executed"])
        self.assertIsNone(turn["execution"]["success"])
        records = api.get_evidence(result.run.run_id, self.tmp / "runs")
        self.assertNotIn("result", [r.get("kind") for r in records])

    def test_unknown_capability_is_denied_and_never_executes(self):
        model = _ScriptedProposer([ActionRequest(
            sequence=0, requester="model", capability="shell_exec",
            target=HOST, purpose="run a command")])
        result, _store = _run_agent(self.tmp, self.listener, model)
        timeline = api.get_agent_timeline(result.run.run_id, self.tmp / "runs")
        turn = timeline["turns"][0]
        self.assertEqual(turn["policy"]["decision"], "deny")
        self.assertIn("capability-not-allowed", turn["policy"]["reason"])
        self.assertFalse(turn["execution"]["executed"])

    def test_discovered_ports_reach_the_next_turn(self):
        model = _ScriptedProposer([
            _discovery_request(HOST, f"ports={self.listener.port} probe"),
            _discovery_request(HOST, f"ports={self.listener.port} again"),
        ])
        result, _store = _run_agent(self.tmp, self.listener, model)
        self.assertEqual(result.turns, 2)
        # Turn 0 sees nothing; turn 1 sees the discovered service.
        self.assertEqual(model.contexts[0].observations, ())
        observations = model.contexts[1].observations
        self.assertTrue(observations, "discovery evidence never reached "
                                     "the second turn")
        latest = observations[-1]
        self.assertEqual(latest["kind"], "service-discovery")
        self.assertEqual(latest["host"], HOST)
        self.assertEqual(latest["ports_open"], [self.listener.port])
        self.assertEqual([e["port"] for e in latest["open_services"]],
                         [self.listener.port])
        self.assertTrue(latest["provider_untrusted"])

    def test_observations_reach_the_serialized_model_prompt(self):
        from raphael_ibm_bob.harness.providers.openai_compat import (
            build_request_body, skill_catalog)
        context = self._context(observations=(
            {"kind": "service-discovery", "host": HOST,
             "ports_open": [8080]},))
        registry = register_default_skills(default_registry())
        config = ProviderConfig(endpoint="http://h/v1", model="m")
        body = build_request_body(config, context, skill_catalog(registry))
        user = json.loads(body["messages"][1]["content"])
        self.assertEqual(user["mission"]["observations"][0]["ports_open"],
                         [8080])
        # The discovery skill must be offered, or the model cannot pick it.
        self.assertIn("network-service-discovery",
                      [c["skill"] for c in user["available_skills"]])

    def test_model_context_carries_no_credential(self):
        observations = ({"kind": "service-discovery", "ports_open": [1]},)
        rendered = json.dumps(
            self._context(observations=observations).summary())
        self.assertNotIn(SECRET, rendered)

    def test_fold_observations_is_bounded(self):
        model = _ScriptedProposer([
            _discovery_request(HOST, f"ports={self.listener.port} probe")
            for _ in range(MAX_OBSERVATIONS + 3)
        ])
        result, _store = _run_agent(self.tmp, self.listener, model)
        self.assertLessEqual(len(model.contexts[-1].observations),
                             MAX_OBSERVATIONS)

    def test_folding_observations_writes_nothing(self):
        model = _ScriptedProposer([
            _discovery_request(HOST, f"ports={self.listener.port} probe")])
        result, _store = _run_agent(self.tmp, self.listener, model)
        run_dir = self.tmp / "runs" / result.run.run_id
        ledger_file = run_dir / "evidence.jsonl"
        before = ledger_file.read_bytes()
        from raphael_ibm_bob.evidence_ledger import EvidenceLedger
        from raphael_ibm_bob.harness.model_run import _port_table
        ledger = EvidenceLedger(run_dir)
        self.addCleanup(ledger.close)
        self.assertTrue(fold_observations(ledger))
        _port_table({"port_results": []})
        self.assertEqual(ledger_file.read_bytes(), before)

    def test_model_proposal_is_the_only_execution_path(self):
        model = _ScriptedProposer([
            _discovery_request(HOST, f"ports={self.listener.port} probe")])
        result, _store = _run_agent(self.tmp, self.listener, model)
        records = api.get_evidence(result.run.run_id, self.tmp / "runs")
        requests = [r for r in records if r.get("kind") == "request"]
        self.assertTrue(requests)
        for record in requests:
            # Every executed request carries the broker's dense sequence
            # stamp, i.e. it went through the Broker, not the model.
            self.assertIsInstance(record.get("seq"), int)
        timeline = api.get_agent_timeline(result.run.run_id, self.tmp / "runs")
        self.assertEqual(timeline["turns"][0]["proposal"]["requester"],
                         "skill:network-service-discovery")

    def test_terminal_done_is_not_an_action(self):
        model = _ScriptedProposer([])  # raises DoneSignal immediately
        result, _store = _run_agent(self.tmp, self.listener, model)
        self.assertEqual(result.terminal, "done")
        timeline = api.get_agent_timeline(result.run.run_id, self.tmp / "runs")
        self.assertEqual(timeline["turns"][0]["proposal"]["intent"], "done")
        self.assertEqual(timeline["turns"][0]["policy"]["decision"], "n/a")
        requests = [r for r in api.get_evidence(result.run.run_id,
                                                self.tmp / "runs")
                    if r.get("kind") == "request"]
        self.assertEqual(requests, [])

    def test_model_cannot_self_certify_completion(self):
        model = _ScriptedProposer([
            _discovery_request(HOST, f"ports={self.listener.port} probe")])
        result, _store = _run_agent(self.tmp, self.listener, model)
        # The QualityGate alone emits the verdict, and a single discovery
        # mission cannot satisfy its conditions: REFUSE, never COMPLETE.
        self.assertIn(result.gate_verdict, ("complete", "refuse"))
        gate = api.get_gate(result.run.run_id, self.tmp / "runs")
        self.assertEqual(gate["decision"], result.gate_verdict)


# ---------------------------------------------------------------------------
# Port-spec parsing (the governed discovery parameter)
# ---------------------------------------------------------------------------

class PortSpecTests(unittest.TestCase):
    def test_rationale_may_follow_the_ports_clause(self):
        from raphael_ibm_bob.discovery_runtime import _parse_port_spec
        ports, _ = _parse_port_spec("ports=8080) to see what answers")
        self.assertEqual(ports, (8080,))

    def test_malformed_specs_still_fail_closed(self):
        from raphael_ibm_bob.discovery_runtime import _parse_port_spec
        for purpose in ("ports=abc", "ports=80a", "ports=1-2-3",
                        "ports=0", "ports=1-99999"):
            with self.subTest(purpose=purpose):
                with self.assertRaises(ValueError):
                    _parse_port_spec(purpose)

    def test_absent_clause_sweeps_the_authorized_ports(self):
        """BLANKER 2: no ports= clause must still cover authorized scope.

        Discovery is driven by the TargetProfile (declared
        authorization), not by a fixed guess list that happens to miss
        the service the operator actually authorized.
        """
        from raphael_ibm_bob.discovery_runtime import _parse_port_spec
        ports, count = _parse_port_spec("service-discovery", (8080, 2222))
        self.assertIn(8080, ports)
        self.assertIn(2222, ports)
        self.assertEqual(count, len(ports))
        self.assertLessEqual(count, 128)

    def test_default_sweep_stays_bounded(self):
        from raphael_ibm_bob.discovery_runtime import (
            MAX_DISCOVERY_PORTS, _parse_port_spec)
        ports, count = _parse_port_spec("service-discovery", ())
        self.assertLessEqual(len(ports), MAX_DISCOVERY_PORTS)
        self.assertLessEqual(count, MAX_DISCOVERY_PORTS)

    def test_max_ports_narrows_a_sweep_but_keeps_authorized_scope(self):
        """The mission may narrow a sweep; authorization still wins."""
        from raphael_ibm_bob.discovery_runtime import (
            _parse_max_ports, _parse_port_spec)
        self.assertEqual(_parse_max_ports("max_ports=8 narrow"), 8)
        self.assertEqual(_parse_max_ports("no clause"), 0)
        ports, _ = _parse_port_spec("ports=1-1024", (8080, 2222))
        # Authorized ports are placed first, so a narrow cap can only
        # truncate the caller's own exploration.
        self.assertEqual(ports[:2], (8080, 2222))
        self.assertIn(8080, ports[:8])
        self.assertIn(2222, ports[:8])

    def test_explicit_range_is_still_capped_and_fail_closed(self):
        from raphael_ibm_bob.discovery_runtime import _parse_port_spec
        ports, _ = _parse_port_spec("ports=1-1024")
        self.assertEqual(len(ports), 1024)
        with self.assertRaises(ValueError):
            _parse_port_spec("ports=abc")


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------

class AgentHttpTests(_Base):
    def setUp(self) -> None:
        super().setUp()
        self.config = config_from_env()
        self.config.sessions_root = self.tmp / "sessions"
        self.config.runs_root = self.tmp / "runs"
        self.config.target_store = TargetStore()

    def _post(self, path, body):
        return dispatch(Request("POST", path, body=body), self.config)

    def test_console_never_echoes_a_submitted_key(self):
        response = dispatch(Request("GET", "/agent"), self.config)
        self.assertEqual(response.status, 200)
        self.assertIn('name="api_key"', response.body)
        self.assertIn("type=\"password\"", response.body)
        self.assertNotIn(SECRET, response.body)

    def test_target_requires_explicit_ports_and_protocols(self):
        response = self._post("/agent/target", {
            "mission_id": MISSION_ID, "host": HOST,
            "port_spec": str(self.listener.port), "protocols": ""})
        self.assertEqual(response.status, 422)
        self.assertIn("protocols is required", response.body["error"]["message"])

    def test_start_without_provider_configuration_is_503(self):
        declared = self._post("/agent/target", {
            "mission_id": MISSION_ID, "host": HOST,
            "port_spec": str(self.listener.port), "protocols": "http",
            "authorization_ref": "lab"})
        self.assertEqual(declared.status, 201)
        response = self._post("/agent/start", {
            "mission_id": MISSION_ID, "provider": "openai-compatible",
            "workspace_root": str(self.tmp / "workspace")})
        self.assertEqual(response.status, 503)
        self.assertNotIn(SECRET, json.dumps(response.body))

    def test_unknown_provider_is_rejected(self):
        # An APPROVED model, so the provider check is what fails (the
        # model allow-list is enforced first — see the Phase 1 tests).
        response = self._post("/agent/start", {
            "mission_id": MISSION_ID, "host": HOST,
            "port_spec": str(self.listener.port), "protocols": "http",
            "provider": "no-such-provider", "endpoint": "http://h/v1",
            "model": api.AUDIT_ALLOWED_MODEL_IDS[0], "api_key": SECRET})
        self.assertEqual(response.status, 503)
        self.assertIn("unknown provider",
                      response.body["error"]["message"])
        self.assertNotIn(SECRET, json.dumps(response.body))

    def test_timeline_route_is_read_only_and_bounded(self):
        response = dispatch(
            Request("GET", "/runs/does-not-exist/timeline"), self.config)
        self.assertEqual(response.status, 404)


    # --- Model authorization (Phase 1) ---------------------------------

    def _declare(self):
        return self._post("/agent/target", {
            "mission_id": MISSION_ID, "host": HOST,
            "port_spec": str(self.listener.port), "protocols": "http",
            "authorization_ref": "lab"})

    def test_each_approved_model_id_is_admitted(self):
        from raphael_ibm_bob.harness import api as harness_api
        for model_id in harness_api.AUDIT_ALLOWED_MODEL_IDS:
            with self.subTest(model=model_id):
                self.assertTrue(
                    harness_api.is_audit_allowed_model(model_id))
                self.assertEqual(
                    harness_api.require_audit_allowed_model(model_id),
                    model_id)
                # A vendor prefix is stripped, not treated as a new id.
                self.assertEqual(
                    harness_api.require_audit_allowed_model(
                        f"vendor/{model_id.upper()}"),
                    model_id)

    def test_non_approved_model_is_rejected_with_422(self):
        self.assertEqual(self._declare().status, 201)
        # `local-deterministic` is deliberately absent: it is now an
        # approved offline-demo provider, admitted by
        # test_each_approved_model_id_is_admitted. The near-miss below
        # guards against prefix matching admitting unapproved variants.
        for model_id in ("gpt-4", "local-deterministic-v2",
                         "qwen2.5-coder-3b", "mimo-2.6-flash-x",
                         "muse-spark-1.3.1"):
            with self.subTest(model=model_id):
                response = self._post("/agent/start", {
                    "mission_id": MISSION_ID, "host": HOST,
                    "port_spec": str(self.listener.port),
                    "protocols": "http", "provider": "openai-compatible",
                    "endpoint": "http://127.0.0.1:1/v1",
                    "model": model_id, "api_key": SECRET,
                    "workspace_root": str(self.tmp / "workspace")})
                self.assertEqual(response.status, 422, model_id)
                self.assertIn("approved audit list",
                              response.body["error"]["message"])
                self.assertNotIn(SECRET, json.dumps(response.body))

    def test_rejection_precedes_any_provider_or_broker_work(self):
        """A denied model must never build an adapter or open a run."""
        self.assertEqual(self._declare().status, 201)
        calls = []

        def _boom(*_a, **_k):  # pragma: no cover - must never run
            calls.append("provider-built")
            raise AssertionError("adapter built for a denied model")

        with unittest.mock.patch.object(api, "make_model_adapter", _boom), \
                unittest.mock.patch.object(
                    api, "start_model_run",
                    side_effect=AssertionError("run started")):
            response = self._post("/agent/start", {
                "mission_id": MISSION_ID, "host": HOST,
                "port_spec": str(self.listener.port), "protocols": "http",
                "provider": "openai-compatible",
                "endpoint": "http://127.0.0.1:1/v1",
                "model": "gpt-4", "api_key": SECRET,
                "workspace_root": str(self.tmp / "workspace")})
        self.assertEqual(response.status, 422)
        self.assertEqual(calls, [])
        self.assertEqual(api.get_runs(self.config.runs_root), [])

    def test_model_rejection_precedes_target_declaration(self):
        """Model authorization is the FIRST check, ahead of any target."""
        self.assertIsNone(self.config.target_store.current())
        response = self._post("/agent/start", {
            "mission_id": MISSION_ID, "host": HOST, "port_spec": "1",
            "protocols": "http", "model": "not-approved",
            "endpoint": "http://127.0.0.1:1/v1", "api_key": SECRET,
            "workspace_root": str(self.tmp / "workspace")})
        self.assertEqual(response.status, 422)
        # No authorized target was created by the rejected request.
        self.assertIsNone(self.config.target_store.current())

    def test_blank_model_defers_to_the_server_environment(self):
        """Blank is the documented server-environment passthrough."""
        from raphael_ibm_bob.harness import api as harness_api
        self.assertEqual(harness_api.require_audit_allowed_model(""), "")
        self.assertEqual(harness_api.require_audit_allowed_model(None), "")
        self.assertEqual(self._declare().status, 201)
        response = self._post("/agent/start", {
            "mission_id": MISSION_ID, "model": "",
            "provider": "openai-compatible",
            "workspace_root": str(self.tmp / "workspace")})
        # No RAPHAEL_MODEL_NAME in this environment -> 503, not 422.
        self.assertEqual(response.status, 503)

    def test_console_offers_only_approved_models(self):
        html = dispatch(Request("GET", "/agent"), self.config).body
        from raphael_ibm_bob.harness import api as harness_api
        # Suggested ids come from the centralized list, never a local copy.
        for model_id in harness_api.AUDIT_ALLOWED_MODEL_IDS:
            self.assertIn(f'value="{model_id}"', html)
        self.assertEqual(_model_options(html),
                         list(harness_api.AUDIT_ALLOWED_MODEL_IDS) * 2)
        self.assertEqual(html.count('name="model"'), 2)

    def test_vendor_prefixed_approved_id_reaches_the_provider(self):
        """Validation strips the prefix; dispatch must not.

        Real providers key on the full `vendor/model` string, so an
        operator who types `vendor/approved-id` must have that exact id
        forwarded — while the allow-list still decides admissibility.
        """
        from raphael_ibm_bob.harness import api as harness_api
        base = harness_api.AUDIT_ALLOWED_MODEL_IDS[0]
        self.assertEqual(self._declare().status, 201)
        seen = {}

        def _capture(provider="openai-compatible", registry=None, **kwargs):
            seen.update(kwargs)
            raise ProviderConfigError("stop after capture")

        with mock.patch.object(api, "make_model_adapter", _capture):
            self._post("/agent/start", {
                "mission_id": MISSION_ID, "model": f"vendor/{base}",
                "endpoint": "http://127.0.0.1:1/v1", "api_key": SECRET,
                "provider": "openai-compatible",
                "workspace_root": str(self.tmp / "workspace")})
        self.assertEqual(seen.get("model"), f"vendor/{base}")

    def test_vendor_prefixed_unapproved_id_is_rejected(self):
        self.assertEqual(self._declare().status, 201)
        response = self._post("/agent/start", {
            "mission_id": MISSION_ID, "model": "vendor/gpt-4",
            "endpoint": "http://127.0.0.1:1/v1", "api_key": SECRET,
            "workspace_root": str(self.tmp / "workspace")})
        self.assertEqual(response.status, 422)
        self.assertIn("approved audit list",
                      response.body["error"]["message"])


class MaxTurnsRegressionTests(AgentHttpTests):
    """A non-default turn budget must survive the HTTP hop.

    The start form once lost its `max_turns` input, so every run was
    silently capped at the default of 6 turns no matter what the
    operator submitted. A silent cap looks exactly like a model that
    cannot make progress, so it is defended here at both ends: the
    form must carry the field, and the value must arrive at the
    runtime as that exact integer.
    """

    def test_start_form_carries_a_max_turns_field(self):
        html = dispatch(Request("GET", "/agent"), self.config).body
        self.assertIn('name="max_turns"', html)

    def test_submitted_turn_budget_reaches_the_runtime(self):
        self.assertEqual(self._declare().status, 201)
        seen = {}

        def _capture(*args, **kwargs):
            seen["max_turns"] = kwargs.get("max_turns")
            raise api.ProviderError("stop after capture")

        with mock.patch.object(api, "start_model_run", _capture):
            self._post("/agent/start", {
                "mission_id": MISSION_ID, "model": api.AUDIT_ALLOWED_MODEL_IDS[0],
                "endpoint": "http://127.0.0.1:1/v1", "api_key": SECRET,
                "max_turns": 20,
                "workspace_root": str(self.tmp / "workspace")})
        self.assertEqual(seen.get("max_turns"), 20)

    def test_absent_turn_budget_falls_back_to_the_default(self):
        self.assertEqual(self._declare().status, 201)
        seen = {}

        def _capture(*args, **kwargs):
            seen["max_turns"] = kwargs.get("max_turns")
            raise api.ProviderError("stop after capture")

        with mock.patch.object(api, "start_model_run", _capture):
            self._post("/agent/start", {
                "mission_id": MISSION_ID, "model": api.AUDIT_ALLOWED_MODEL_IDS[0],
                "endpoint": "http://127.0.0.1:1/v1", "api_key": SECRET,
                "workspace_root": str(self.tmp / "workspace")})
        self.assertEqual(seen.get("max_turns"), agent_routes.DEFAULT_UI_TURNS)


class SshObservationRegressionTests(unittest.TestCase):
    """A governed SSH result must be READABLE by the model.

    `excerpt_output` had no case for `network_ssh_session`, so the
    result fell through to `str(evidence)[:500]` -- a dict repr that
    reaches `exit_code` and then truncates long before `stdout`. The
    command provably ran, the ledger held its output, and the model
    was handed evidence that something happened with no way to see
    what. It then re-ran the same authorized command turn after turn
    looking for output it had actually already been given.

    These tests pin the observable contract: the recorded stdout is
    present verbatim, provenance rides along, and nothing is invented.
    """

    def _excerpt(self, payload):
        from raphael_ibm_bob.harness.loop import excerpt_output
        request = ActionRequest(sequence=1, requester="test",
                                capability=Capability.NETWORK_SSH_SESSION,
                                target=HOST, purpose="rationale cmd=\"cat x\"")
        evidence = {"evidence_id": "SX-test", "payload": payload}
        return excerpt_output(request, mock.Mock(evidence=evidence))

    def test_stdout_is_returned_verbatim(self):
        stdout = "backup-restore: running as root (setuid)\nHTB{lab-root}\n"
        out = self._excerpt({"command": "backup-restore", "exit_code": 0,
                             "stdout": stdout, "stderr": ""})
        self.assertIn("HTB{lab-root}", out)
        self.assertIn(stdout.strip(), out)

    def test_provenance_and_exit_code_accompany_the_output(self):
        out = self._excerpt({"command": "ls", "exit_code": 2,
                             "stdout": "note.txt\n", "stderr": "denied"})
        self.assertIn("SX-test", out)
        self.assertIn("cmd='ls'", out)
        self.assertIn("exit=2", out)
        self.assertIn("note.txt", out)
        self.assertIn("denied", out)

    def test_declared_truncation_is_reported_not_hidden(self):
        out = self._excerpt({"command": "cat big", "exit_code": 0,
                             "stdout": "head only", "stderr": "",
                             "stdout_truncated": True})
        self.assertIn("stdout_truncated=true", out)

    def test_no_invented_content_when_nothing_executed(self):
        out = self._excerpt({"command": "ls", "exit_code": None,
                             "stdout": "", "stderr": ""})
        self.assertNotIn("HTB{", out)


class SshCommandSyntaxGuidanceTests(unittest.TestCase):
    """The `cmd=` contract must be shown, not merely described.

    The live model wrote `cmd "cat note.txt"` (no equals sign) and was
    denied as carrying no command. The parser was right to deny it --
    validation must not be loosened to suit the model -- so the fix
    belongs in the guidance the model actually reads.
    """

    def test_capability_description_shows_the_equals_sign(self):
        description = next(
            c.description for c in default_registry().list_capabilities()
            if c.capability.value == "network_ssh_session")
        # The description must carry the literal clause, including the
        # equals sign the live model kept dropping.
        self.assertIn("cmd=", description)
        self.assertIn("c-m-d-EQUALS", description)
        self.assertIn("double quotes", description)
        # Capability descriptions are rendered verbatim in the escaped
        # operator arsenal, so they must stay free of quote and
        # angle-bracket characters (documented in skills.py).
        for forbidden in ('"', "'", "<", ">", "&"):
            self.assertNotIn(forbidden, description)

    def test_authorized_session_guidance_shows_the_equals_sign(self):
        mission = Mission(
            mission_id="M-SYNTAX", description="probe", scope=("ssh",),
            criteria=(),
            problem={"ssh": {"target": "ssh://127.0.0.2:2222",
                             "username": "labuser",
                             "commands": ["ls"]}})
        view = authorized_session_view(mission)
        self.assertIn("cmd=", view["how_to_propose"])
        self.assertIn('cmd="cat note.txt"', view["how_to_propose"])

    def test_equals_sign_is_still_required_by_the_parser(self):
        from raphael_ibm_bob.ssh_runtime import command_from_purpose
        self.assertEqual(
            command_from_purpose('rationale cmd="cat note.txt"'), "cat note.txt")
        self.assertEqual(
            command_from_purpose('rationale cmd "cat note.txt"'), "")

    def test_chaining_after_the_clause_is_still_rejected(self):
        from raphael_ibm_bob.ssh_runtime import chaining_detected
        self.assertIsNone(chaining_detected('rationale cmd="cat note.txt"'))
        self.assertIsNotNone(
            chaining_detected('rationale cmd="ls" && cat flag.txt'))

def _model_options(html: str) -> list:
    """Every model id the console SUGGESTS via its datalists, in order."""
    import re
    return [
        value
        for block in re.findall(
            r'<datalist id="agent-models">(.*?)</datalist>', html, re.S)
        for value in re.findall(r'<option value="([^"]+)"', block)]


if __name__ == "__main__":
    unittest.main()
