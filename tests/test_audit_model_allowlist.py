"""tests.test_audit_model_allowlist — Workstream C audit gate tests.

The audit admits exactly two models (MiMo 2.6 Flash, Muse Spark 1.3) on the
operator selection path (UI select + HTTP route validation). The generic
provider adapter and the server-environment path are intentionally
untouched; these tests pin the boundary so a future edit cannot silently
widen it, and prove existing offline tests/demos keep working.

Uses obviously-fake keys and never contacts a network.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from raphael_ibm_bob.harness import api


class AllowListShape(unittest.TestCase):
    def test_exactly_the_approved_canonical_ids(self) -> None:
        """The list is the audit's approved set — nothing more.

        `mimo-v2.6-flash` was added on operator instruction: the audit's
        `mimo-2.6-flash` is not an id any reachable provider serves,
        while OpenRouter exposes `xiaomi/mimo-v2.6-flash`, whose
        vendor-stripped base id is `mimo-v2.6-flash`. This test pins the
        set so an id cannot be widened without this file changing too.
        """
        self.assertEqual(
            tuple(api.AUDIT_ALLOWED_MODEL_IDS),
            ("mimo-2.6-flash", "muse-spark-1.3", "mimo-v2.6-flash",
             "local-deterministic"))

    def test_labels_cover_every_id(self) -> None:
        self.assertEqual(set(api.AUDIT_ALLOWED_MODEL_LABELS),
                         set(api.AUDIT_ALLOWED_MODEL_IDS))

    def test_served_mi_mo_id_is_admitted(self) -> None:
        """`xiaomi/mimo-v2.6-flash` normalizes to an approved base id."""
        self.assertTrue(api.is_audit_allowed_model("xiaomi/mimo-v2.6-flash"))
        self.assertTrue(api.is_audit_allowed_model("XIAOMI/MIMO-V2.6-FLASH"))
        self.assertEqual(
            api.require_audit_allowed_model("xiaomi/mimo-v2.6-flash"),
            "mimo-v2.6-flash")
        # One character away is still not approved.
        self.assertFalse(api.is_audit_allowed_model("mimo-v2.6-flash-1"))


class NormalizeAndMatch(unittest.TestCase):
    def test_bare_ids_allowed(self) -> None:
        self.assertTrue(api.is_audit_allowed_model("mimo-2.6-flash"))
        self.assertTrue(api.is_audit_allowed_model("muse-spark-1.3"))

    def test_vendor_prefix_and_case_accepted(self) -> None:
        self.assertTrue(api.is_audit_allowed_model("xiaomi/mimo-2.6-flash"))
        self.assertTrue(api.is_audit_allowed_model("MIMO/MIMO-2.6-FLASH"))
        self.assertTrue(api.is_audit_allowed_model("  iflytek/Muse-Spark-1.3 "))

    def test_blank_means_server_environment(self) -> None:
        for blank in (None, "", "   "):
            self.assertTrue(api.is_audit_allowed_model(blank))
            self.assertEqual(api.require_audit_allowed_model(blank), "")

    def test_unapproved_rejected(self) -> None:
        for bad in ("gpt-4", "claude-3", "vendor/space-bunny",
                    "mimo-2.6-flash-evil", "muse-spark-1.4", 123):
            self.assertFalse(api.is_audit_allowed_model(bad), bad)
            with self.assertRaises(ValueError, msg=str(bad)):
                api.require_audit_allowed_model(bad)

    def test_normalized_value_returned(self) -> None:
        self.assertEqual(
            api.require_audit_allowed_model("Xiaomi/MIMO-2.6-Flash"),
            "mimo-2.6-flash")


def _route_config(tmp: str):
    base = Path(tmp)
    sessions = base / "sessions"
    runs = base / "runs"
    ws = base / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    return (SimpleNamespace(
        sessions_root=sessions, runs_root=runs,
        default_max_turns=3, mode_manager=None, target_store=None), ws)


def _make_session(ws: Path, sessions_root: Path) -> str:
    from raphael_ibm_bob.contracts import Mission
    from raphael_ibm_bob.harness.session import (
        RaphaelSession, WorkspaceContext, save_session)
    mission = Mission(mission_id="M-allow", description="d",
                      scope="", criteria=["c"])
    session = RaphaelSession.create(
        mission=mission,
        workspace=WorkspaceContext(workspace_root=str(ws),
                                   project_name="allow"))
    save_session(session, sessions_root)
    return session.session_id


CLEAN_ENV = {"PATH": os.environ.get("PATH", ""),
             "PYTHONPATH": os.environ.get("PYTHONPATH", "")}


class RouteValidation(unittest.TestCase):
    def test_runs_model_rejects_unapproved_with_422(self) -> None:
        from raphael_ibm_bob.http.routes import runs
        with tempfile.TemporaryDirectory() as tmp:
            config, ws = _route_config(tmp)
            sid = _make_session(ws, config.sessions_root)
            req = SimpleNamespace(
                body={"session_id": sid, "provider": "openai-compatible",
                      "model": "gpt-4", "endpoint": "https://x.example/v1",
                      "api_key": "sk-fake", "max_turns": 1},
                headers={}, query={})
            with mock.patch.dict(os.environ, CLEAN_ENV, clear=True):
                with self.assertRaises(Exception) as ctx:
                    runs.start_model_run(req, {}, config)
        err = ctx.exception
        self.assertEqual(getattr(err, "status", None), 422)
        self.assertEqual(getattr(err, "code", None), "INVALID_INPUT")

    def test_runs_model_allowed_now_resolves_provider_default(self) -> None:
        """BLANKER 1: an approved model with no explicit config must work.

        This used to 503 with "RAPHAEL_MODEL_ENDPOINT is not set" for an
        operator who had done everything the UI asked. The provider now
        declares a default endpoint, so the request reaches the adapter.
        It still fails closed on a model that is not approved, and on a
        genuinely unresolvable configuration.
        """
        from raphael_ibm_bob.http.routes import runs
        with tempfile.TemporaryDirectory() as tmp:
            config, ws = _route_config(tmp)
            sid = _make_session(ws, config.sessions_root)
            req = SimpleNamespace(
                body={"session_id": sid, "model": "mimo-2.6-flash",
                      "api_key": "sk-fake", "max_turns": 1},
                headers={}, query={})
            with mock.patch.dict(os.environ, CLEAN_ENV, clear=True):
                status, body = runs.start_model_run(req, {}, config)
        self.assertEqual(status, 201)
        self.assertEqual(body["terminal"], "model-error")

    def test_runs_model_unapproved_still_422(self) -> None:
        """The allow-list gate is unchanged by the endpoint default."""
        from raphael_ibm_bob.http.routes import runs
        with tempfile.TemporaryDirectory() as tmp:
            config, ws = _route_config(tmp)
            sid = _make_session(ws, config.sessions_root)
            req = SimpleNamespace(
                body={"session_id": sid, "model": "gpt-4", "max_turns": 1},
                headers={}, query={})
            with mock.patch.dict(os.environ, CLEAN_ENV, clear=True):
                with self.assertRaises(Exception) as ctx:
                    runs.start_model_run(req, {}, config)
        err = ctx.exception
        self.assertEqual(getattr(err, "status", None), 422)
        self.assertEqual(getattr(err, "code", None), "INVALID_INPUT")

    def test_operations_start_rejects_unapproved_with_422(self) -> None:
        from raphael_ibm_bob.http.routes import operations
        with tempfile.TemporaryDirectory() as tmp:
            config, ws = _route_config(tmp)
            sid = _make_session(ws, config.sessions_root)
            req = SimpleNamespace(
                body={"session_id": sid, "mode": "model",
                      "model": "claude-x", "max_turns": "1"},
                headers={}, query={})
            with mock.patch.dict(os.environ, CLEAN_ENV, clear=True):
                with self.assertRaises(Exception) as ctx:
                    operations.start_operation(req, {}, config)
        err = ctx.exception
        self.assertEqual(getattr(err, "status", None), 422)
        self.assertEqual(getattr(err, "code", None), "INVALID_INPUT")


class ConsoleSelect(unittest.TestCase):
    def render(self) -> str:
        from raphael_ibm_bob.http.views import operations_console as oc
        with tempfile.TemporaryDirectory() as tmp:
            return oc.render_index(
                [], runs_root=Path(tmp) / "runs",
                sessions_root=Path(tmp) / "sessions",
                vpn_status=None, mode_state={"mode": "normal"},
                target_state=None)

    def test_model_is_select_with_both_approved_ids(self) -> None:
        html = self.render()
        self.assertIn('name="model"', html)
        self.assertIn('value="mimo-2.6-flash"', html)
        self.assertIn('value="muse-spark-1.3"', html)
        self.assertIn("MiMo 2.6 Flash", html)
        self.assertIn("Muse Spark 1.3", html)

    def test_no_unapproved_model_named_in_console(self) -> None:
        html = self.render().lower()
        for banned in ("space-bunny", "gpt-4", "claude", "gemini",
                       "deepseek", "qwen", "nemotron", "kimi"):
            self.assertNotIn(banned, html)


if __name__ == "__main__":
    unittest.main()
