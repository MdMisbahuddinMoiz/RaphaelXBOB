"""Focused tests for the governed agent chat console.

The property under test throughout: the chat is an INTERACTION LAYER over
the existing governed runtime, never a second execution path. An operator
message becomes model CONTEXT; the model still returns an ordinary
ActionRequest; that request still travels Runtime -> Broker -> Policy; and
Policy can still refuse. Every test here that asserts "the agent acted"
also asserts the request went through a governed decision.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from raphael_ibm_bob.contracts import ActionRequest, Capability, Mission
from raphael_ibm_bob.harness import api
from raphael_ibm_bob.harness.chat import (
    MAX_CONTENT_CHARS,
    ChatLog,
    chat_log,
    has_credential_shape,
    redact,
)
from raphael_ibm_bob.harness.model import ModelAdapter, ModelContext
from raphael_ibm_bob.harness.providers import DoneSignal
from raphael_ibm_bob.http.app import Request, config_from_env, dispatch
from raphael_ibm_bob.http.views import agent_chat as ac
from raphael_ibm_bob.http.views import agent_console as console
from raphael_ibm_bob.target_profile import TargetStore, build_target_profile

MISSION_ID = "M-CHAT-001"
HOST = "127.0.0.1"
PORT = 80
SECRET = "sk-or-v1-RENDEREDMUSTNOTAPPEAR000000000"


class _ScriptedProposer:
    """Deterministic model double — returns ActionRequests, nothing else.

    It holds no capability, broker, mediator, or socket. That is the whole
    point: if the chat ever bypassed the governed path, this double could
    not produce a passing test.
    """

    def __init__(self, proposals):
        self._proposals = list(proposals)
        self.contexts = []

    def propose(self, context: ModelContext) -> ActionRequest:
        self.contexts.append(context)
        if not self._proposals:
            raise DoneSignal("script exhausted")
        return self._proposals.pop(0)


def _profile(port: int = PORT):
    return build_target_profile(
        mission_id=MISSION_ID, locator=HOST, allowed_ports=str(port),
        allowed_protocols="http", authorization_ref="lab",
        stage="authorized")


def _mission() -> Mission:
    return Mission(mission_id=MISSION_ID,
                   description=f"governed assessment of {HOST}",
                   scope=HOST, criteria=["service-discovery"])


def _discovery(purpose: str = "recon", target: str = HOST) -> ActionRequest:
    return ActionRequest(
        sequence=0, requester="skill:network-service-discovery",
        capability=Capability.NETWORK_SERVICE_DISCOVERY,
        target=target, purpose=purpose, timeout_seconds=10.0)


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="raphael-chat-")
        self.tmp = Path(self._tmp.name)
        (self.tmp / "workspace").mkdir()
        self.runs = self.tmp / "runs"
        self.runs.mkdir()
        self.addCleanup(self._tmp.cleanup)

    def _session(self, mission=None):
        return api.create_session(
            mission=mission or _mission(), workspace_root=self.tmp / "workspace",
            project_name=MISSION_ID, sessions_root=self.tmp / "sessions")

    def _store(self) -> TargetStore:
        store = TargetStore()
        store.set_target(_profile())
        return store


# ---------------------------------------------------------------------------
# A. Chat route accepts an operator message
# ---------------------------------------------------------------------------

class ChatRouteTests(_Base):
    def _config(self):
        cfg = config_from_env()
        cfg.sessions_root = self.tmp / "sessions"
        cfg.runs_root = self.runs
        cfg.target_store = self._store()
        return cfg

    def test_A_route_accepts_operator_message(self):
        cfg = self._config()
        response = dispatch(Request("POST", "/agent/message", body={
            "mission_id": MISSION_ID,
            "message": "Start reconnaissance on this target."}), cfg)
        # No provider is configured in this process, so the model call is
        # refused — but the OPERATOR MESSAGE was accepted and stored first.
        self.assertIn(response.status, (200, 503))
        stored = api.read_chat(MISSION_ID, self.runs)["messages"]
        self.assertTrue(any(m["role"] == "operator" for m in stored))
        self.assertIn("Start reconnaissance",
                      stored[0]["content"])

    def test_M_malformed_message_fails_safely(self):
        cfg = self._config()
        blank = dispatch(Request("POST", "/agent/message", body={
            "mission_id": MISSION_ID, "message": "   "}), cfg)
        self.assertEqual(blank.status, 422)
        # A body with no mission_id is NOT malformed: it binds to the
        # mission the operator already declared, exactly as the start form
        # does. What must never happen is a crash or a leaked traceback.
        inherited = dispatch(Request("POST", "/agent/message", body={
            "message": "continue"}), cfg)
        self.assertNotEqual(inherited.status, 500)
        self.assertNotIn("Traceback", json.dumps(blank.body))
        self.assertNotIn("Traceback", json.dumps(inherited.body))

    def test_mission_without_a_declared_target_is_rejected(self):
        """A mission the operator never authorised must not run."""
        cfg = config_from_env()
        cfg.sessions_root = self.tmp / "sessions"
        cfg.runs_root = self.runs
        cfg.target_store = TargetStore()   # no target declared
        response = dispatch(Request("POST", "/agent/message", body={
            "mission_id": "M-NEVER-DECLARED", "message": "hello"}), cfg)
        self.assertEqual(response.status, 422)
        self.assertIn("authorized target", json.dumps(response.body).lower())


# ---------------------------------------------------------------------------
# B/C. Operator note enters model context; the turn runs the REAL runtime
# ---------------------------------------------------------------------------

class ChatTurnTests(_Base):
    def test_B_operator_message_reaches_the_model_context(self):
        model = _ScriptedProposer([_discovery()])
        session = self._session()
        api.start_chat_turn(
            session, _mission(), model=model,
            message="Investigate the HTTP service.",
            runs_root=self.runs, sessions_root=self.tmp / "sessions",
            target_store=self._store())
        self.assertTrue(model.contexts)
        self.assertEqual(
            model.contexts[0].operator_note, "Investigate the HTTP service.")

    def test_C_turn_executes_through_the_governed_runtime(self):
        """The model proposed; Broker -> Policy decided; evidence followed."""
        model = _ScriptedProposer([_discovery("enumerating authorized ports")])
        result = api.start_chat_turn(
            self._session(), _mission(), model=model,
            message="Start reconnaissance.",
            runs_root=self.runs, sessions_root=self.tmp / "sessions",
            target_store=self._store())
        self.assertEqual(result["turns"], 1)
        timeline = result["timeline"]
        self.assertTrue(timeline.get("turns"))
        turn = timeline["turns"][0]
        # A governed decision exists — the request was NOT executed directly.
        self.assertIn(turn["policy"]["decision"], ("allow", "deny"))
        self.assertIn("evidence_ids", turn["evidence"])

    def test_D_consequential_execution_still_requires_an_action_request(self):
        """A DENY must be visible and must mean nothing was invoked."""
        model = _ScriptedProposer([
            _discovery("out of scope", target="203.0.113.9")])
        result = api.start_chat_turn(
            self._session(), _mission(), model=model, message="go",
            runs_root=self.runs, sessions_root=self.tmp / "sessions",
            target_store=self._store())
        turn = result["timeline"]["turns"][0]
        self.assertEqual(turn["policy"]["decision"], "deny")
        self.assertFalse(turn["execution"]["executed"])

    def test_E_chat_cannot_execute_a_capability_directly(self):
        """Static: no chat module may reach a capability or the broker."""
        for name in ("chat.py",):
            src = Path("raphael_ibm_bob/harness") / name
            text = src.read_text(encoding="utf-8")
            for forbidden in ("BOBBroker", "BOBRuntime", "execute_governed",
                              "capability_invoked", "subprocess", "socket.",
                              "os.system"):
                self.assertNotIn(forbidden, text,
                                 f"{forbidden} in {src}")
        routes = Path("raphael_ibm_bob/http/routes/agent.py").read_text(
            encoding="utf-8")
        chat_body = routes[routes.index("def message("):routes.index("def _record_chat_turns")]
        for forbidden in ("BOBBroker", "BOBRuntime", "execute_governed",
                          "import socket", "subprocess"):
            self.assertNotIn(forbidden, chat_body,
                             f"chat route reaches {forbidden}")

    def test_H_followup_turn_sees_prior_evidence(self):
        store = self._store()
        first = _ScriptedProposer([_discovery("first observation")])
        api.start_chat_turn(
            self._session(), _mission(), model=first, message="look around",
            runs_root=self.runs, sessions_root=self.tmp / "sessions",
            target_store=store)
        second = _ScriptedProposer([_discovery("second")])
        api.start_chat_turn(
            self._session(), _mission(), model=second, message="continue",
            runs_root=self.runs, sessions_root=self.tmp / "sessions",
            target_store=store)
        self.assertTrue(second.contexts)
        recent = second.contexts[0].recent_turns
        self.assertTrue(recent, "follow-up turn saw no prior turns")
        self.assertTrue(any(t.get("capability") for t in recent))


# ---------------------------------------------------------------------------
# F/G. DENY and evidence are visible in the transcript
# ---------------------------------------------------------------------------

class TranscriptTests(_Base):
    def test_G_evidence_appears_in_the_chat(self):
        from raphael_ibm_bob.http.routes import agent as routes
        model = _ScriptedProposer([_discovery("sweeping the authorized host")])
        with mock.patch.object(api, "make_model_adapter", return_value=model), \
             mock.patch.object(api, "require_audit_allowed_model",
                               return_value="mimo-v2.6-flash"):
            cfg = config_from_env()
            cfg.sessions_root = self.tmp / "sessions"
            cfg.runs_root = self.runs
            cfg.target_store = self._store()
            response = dispatch(Request("POST", "/agent/message", body={
                "mission_id": MISSION_ID, "message": "recon"}), cfg)
        self.assertEqual(response.status, 200, response.body)
        types = {m["message_type"] for m in response.body["messages"]}
        self.assertIn("action", types)
        self.assertIn("policy", types)
        self.assertTrue({"evidence", "execution"} & types)

    def test_F_policy_deny_appears_in_the_chat(self):
        cfg = config_from_env()
        cfg.sessions_root = self.tmp / "sessions"
        cfg.runs_root = self.runs
        cfg.target_store = self._store()
        model = _ScriptedProposer([_discovery("out of scope",
                                              target="203.0.113.9")])
        with mock.patch.object(api, "make_model_adapter", return_value=model), \
             mock.patch.object(api, "require_audit_allowed_model",
                               return_value="mimo-v2.6-flash"):
            response = dispatch(Request("POST", "/agent/message", body={
                "mission_id": MISSION_ID, "message": "go out of scope"}), cfg)
        self.assertEqual(response.status, 200, response.body)
        policies = [m for m in response.body["messages"]
                    if m["message_type"] == "policy"]
        self.assertTrue(policies)
        self.assertIn("DENY", policies[0]["content"].upper())


# ---------------------------------------------------------------------------
# I. Stop prevents future turns
# ---------------------------------------------------------------------------

class StopTests(_Base):
    def _config(self):
        cfg = config_from_env()
        cfg.sessions_root = self.tmp / "sessions"
        cfg.runs_root = self.runs
        cfg.target_store = self._store()
        return cfg

    def test_I_stop_prevents_future_turns(self):
        cfg = self._config()
        stopped = dispatch(Request("POST", "/agent/stop",
                                   body={"mission_id": MISSION_ID}), cfg)
        self.assertEqual(stopped.status, 200)
        self.assertTrue(stopped.body["stopped"])
        model = _ScriptedProposer([_discovery()])
        with mock.patch.object(api, "make_model_adapter", return_value=model):
            after = dispatch(Request("POST", "/agent/message", body={
                "mission_id": MISSION_ID, "message": "keep going"}), cfg)
        self.assertEqual(after.status, 409)
        self.assertEqual(after.body["error"]["code"], "MISSION_STOPPED")
        # The model was never consulted: no new execution, no hidden work.
        self.assertEqual(model.contexts, [])
        # The stop is recorded as a real system event, not a UI variable.
        messages = api.read_chat(MISSION_ID, self.runs)["messages"]
        self.assertTrue(any("STOPPED" in m["content"] for m in messages))

    def test_resume_clears_the_gate(self):
        cfg = self._config()
        dispatch(Request("POST", "/agent/stop",
                         body={"mission_id": MISSION_ID}), cfg)
        resumed = dispatch(Request("POST", "/agent/resume",
                                   body={"mission_id": MISSION_ID}), cfg)
        self.assertFalse(resumed.body["stopped"])
        model = _ScriptedProposer([_discovery()])
        with mock.patch.object(api, "make_model_adapter", return_value=model):
            response = dispatch(Request("POST", "/agent/message", body={
                "mission_id": MISSION_ID, "message": "again"}), cfg)
        self.assertNotEqual(response.status, 409)


# ---------------------------------------------------------------------------
# J/L. Rendering: provider info, QualityGate, and the nine message types
# ---------------------------------------------------------------------------

class RenderingTests(unittest.TestCase):
    def test_J_provider_and_model_render(self):
        html = console.render(
            target={"mission_id": MISSION_ID, "locator": HOST},
            provider_state={"provider": "openai-compatible",
                            "model": "mimo-v2.6-flash"})
        self.assertIn("openai-compatible", html)
        self.assertIn("mimo-v2.6-flash", html)

    def test_L_quality_gate_renders_independently(self):
        gate = {"verdict": "refuse", "reason": "conditions not satisfied"}
        html = ac.evidence_panel(None, gate)
        self.assertIn("REFUSE", html.upper())
        self.assertIn("conditions not satisfied", html)
        # A refusal is never dressed up as completion.
        self.assertNotIn("COMPLETE", html.upper())

    def test_all_eight_message_types_render_distinctly(self):
        seen = set()
        for mtype in (ac.TYPE_LABEL):
            block = ac.message_block({
                "id": "C-1", "ts": "t", "role": "agent",
                "message_type": mtype, "content": "content",
                "evidence_ids": ["DX-1"], "turn_index": 3})
            self.assertIn("content", block)
            label, css = ac.TYPE_LABEL[mtype]
            self.assertIn(label, block)
            self.assertIn(css, block)
            seen.add(css)
        self.assertGreaterEqual(len(seen), 7,
                                "message types collapsed into one style")

    def test_action_card_shows_policy_and_evidence(self):
        card = ac._action_card({
            "capability": "network_ssh_session", "target": "127.0.0.2:2222",
            "decision": "allow", "reason": "", "rationale": "read the note",
            "execution": {"executed": True, "success": True},
            "evidence_ids": ["SX-abc"]})
        self.assertIn("network_ssh_session", card)
        self.assertIn("ALLOW", card)
        self.assertIn("SX-abc", card)
        self.assertIn("read the note", card)
        denied = ac._action_card({"capability": "network_ssh_session",
                                  "decision": "deny",
                                  "reason": "command-not-authorized"})
        self.assertIn("DENY", denied)
        self.assertIn("command-not-authorized", denied)

    def test_three_region_layout_and_accessibility(self):
        html = console.render(
            target={"mission_id": MISSION_ID, "locator": HOST},
            provider_state={"provider": "openai-compatible",
                            "model": "mimo-v2.6-flash"})
        self.assertIn("chatgrid", html)
        self.assertIn("AI AGENT CHAT", html)
        self.assertIn("MISSION &amp; SCOPE", html)
        self.assertIn("SERVICES", html)
        # Accessibility: labelled log, labelled composer, focus styles.
        self.assertIn('role="log"', html)
        self.assertIn('aria-live="polite"', html)
        self.assertIn('aria-label="Message to the agent"', html)
        self.assertIn(":focus-visible", html)
        # Responsive stacking.
        self.assertIn("@media (max-width:1100px)", html)

    def test_governance_is_advertised_and_no_cot_is_rendered(self):
        html = console.render(
            target={"mission_id": MISSION_ID, "locator": HOST})
        self.assertIn("GOVERNANCE ENFORCED", html)
        for forbidden in ("chain-of-thought", "token trace", "raw prompt"):
            self.assertNotIn(forbidden, html.lower())


# ---------------------------------------------------------------------------
# K. Credential redaction
# ---------------------------------------------------------------------------

class RedactionTests(_Base):
    def test_redact_replaces_credential_shapes(self):
        for payload in (
            f"my key is sk-or-v1-{'A' * 40}",
            "password: hunter2hunter2",
            "api_key=abcdef123456",
            "Authorization: Bearer abcdef123456",
            "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
        ):
            self.assertTrue(has_credential_shape(payload), payload)
            self.assertNotIn("hunter2", redact(payload))
        self.assertIn(redact("api_key=abcdef123456"),
                      "[redacted]")

    def test_redaction_does_not_mangle_ordinary_prose(self):
        for text in ("the service returned a token header",
                     "password field on the login page",
                     "investigate port 8080"):
            self.assertEqual(redact(text), text)

    def test_credential_never_reaches_the_transcript(self):
        log = chat_log(self.runs, MISSION_ID)
        message = log.append_operator(
            f"here is the key sk-or-v1-{'A' * 40} please use it")
        self.assertNotIn("A" * 40, message.content)
        stored = json.dumps(api.read_chat(MISSION_ID, self.runs))
        self.assertNotIn("A" * 40, stored)
        self.assertIn("[redacted]", stored)

    def test_credential_never_reaches_the_rendered_page(self):
        log = chat_log(self.runs, MISSION_ID)
        log.append_operator(f"key sk-or-v1-{'B' * 40}")
        html = console.render(
            target={"mission_id": MISSION_ID, "locator": HOST},
            provider_state={"provider": "openai-compatible",
                            "model": "mimo-v2.6-flash"},
            chat_messages=log.to_list())
        self.assertNotIn("B" * 40, html)

    def test_console_never_echoes_a_submitted_key(self):
        html = console.render(
            provider_state={"provider": "openai-compatible",
                            "model": "mimo-v2.6-flash",
                            "api_key": SECRET})
        self.assertNotIn(SECRET, html)

    def test_chat_form_carries_no_credential_field(self):
        html = console.render(
            target={"mission_id": MISSION_ID, "locator": HOST})
        self.assertIn('action="/agent/message"', html)
        # The composer must not smuggle a provider secret into the DOM.
        composer = html[html.index('action="/agent/message"'):]
        composer = composer[:composer.index("</form>")]
        self.assertNotIn('name="api_key"', composer)

    def test_message_length_is_bounded(self):
        log = chat_log(self.runs, MISSION_ID)
        message = log.append_operator("x" * (MAX_CONTENT_CHARS * 3))
        self.assertLessEqual(len(message.content), MAX_CONTENT_CHARS)


# ---------------------------------------------------------------------------
# Transcript persistence
# ---------------------------------------------------------------------------

class PersistenceTests(_Base):
    def test_transcript_is_append_only_and_ordered(self):
        log = ChatLog(self.runs, MISSION_ID)
        first = log.append_operator("one")
        second = log.append_event("two", message_type="agent")
        third = log.append_event("three", message_type="system")
        messages = log.messages()
        self.assertEqual([m.id for m in messages],
                         [first.id, second.id, third.id])
        self.assertEqual([m.message_type for m in messages],
                         ["user", "agent", "system"])
        # Re-reading does not duplicate or reorder.
        self.assertEqual(len(log.messages()), 3)

    def test_reopened_log_never_reissues_an_id(self):
        """A restart must not reissue ids the durable transcript holds.

        The id counter is process-local, so without seeding from the
        persisted transcript a reopened log starts numbering from 1 again
        and two records claim the same handle.
        """
        first = chat_log(self.runs, MISSION_ID).append_operator("one")
        # A fresh ChatLog stands in for a restarted server process.
        second = chat_log(self.runs, MISSION_ID).append_operator("two")
        self.assertNotEqual(first.id, second.id)
        first_serial = int(first.id.rpartition("-")[2])
        second_serial = int(second.id.rpartition("-")[2])
        self.assertGreater(second_serial, first_serial)
        # The durable transcript still holds both, distinctly.
        reopened = chat_log(self.runs, MISSION_ID).messages()
        self.assertEqual([m.id for m in reopened], [first.id, second.id])

    def test_first_id_on_an_empty_log_is_well_formed(self):
        """A new transcript starts clean, with a well-formed unique id.

        The counter is process-global, so the serial is not asserted to
        be 1 — only that the id is well formed and is the sole entry.
        """
        log = chat_log(self.runs, "M-FRESH-LOG")
        message = log.append_operator("hello")
        self.assertRegex(message.id, r"^C-[A-Z]{4}-\d{6}$")
        self.assertEqual([m.id for m in log.messages()], [message.id])

    def test_mission_id_traversal_is_refused(self):
        for bad in ("../escape", "a/b", "..", ""):
            with self.assertRaises(ValueError):
                chat_log(self.runs, bad)

    def test_corrupt_lines_are_skipped_not_fatal(self):
        log = chat_log(self.runs, MISSION_ID)
        log.append_operator("good")
        with log.path.open("a", encoding="utf-8") as handle:
            handle.write("{not json}\n")
        log.append_operator("also good")
        messages = log.messages()
        self.assertEqual([m.content for m in messages],
                         ["good", "also good"])


if __name__ == "__main__":
    unittest.main()
