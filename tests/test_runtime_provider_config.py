"""Runtime-only provider configuration for the Harness UI.

Covers the optional live-operator credential path: an operator may supply a
provider/model/api_key for ONE run. The credential must build the existing
`OpenAICompatAdapter` in memory and must never be persisted, logged, returned,
or serialized into any run artefact.

These tests use an obviously-fake key and never contact a network.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from raphael_ibm_bob.harness import api
from raphael_ibm_bob.contracts import Mission
from raphael_ibm_bob.harness.model import ModelAdapter, ModelContext
from raphael_ibm_bob.harness.providers.openai_compat import (
    OpenAICompatAdapter,
    ProviderConfigError,
)

FAKE = "sk-or-v1-FAKEKEYMUSTNOTLEAK0000000000000000"

CLEAN_ENV = {
    "PATH": os.environ.get("PATH", ""),
    "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
}


class RuntimeConfigBuilds(unittest.TestCase):
    """Base: isolates the environment so results never depend on real config."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def build(self, **kwargs) -> ModelAdapter:
        with mock.patch.dict(os.environ, CLEAN_ENV, clear=True):
            return api.make_model_adapter(**kwargs)


class EnvironmentPathUnchanged(RuntimeConfigBuilds):
    """The credential-free submission path must be untouched."""

    def test_env_only_path_still_works(self) -> None:
        with mock.patch.dict(os.environ, {
            **CLEAN_ENV,
            "RAPHAEL_MODEL_ENDPOINT": "https://openrouter.ai/api/v1",
            "RAPHAEL_MODEL_NAME": "env/model",
            "RAPHAEL_MODEL_API_KEY": FAKE,
        }, clear=True):
            adapter = api.make_model_adapter()
        self.assertIsInstance(adapter, OpenAICompatAdapter)
        self.assertEqual(adapter._config.model, "env/model")

    def test_missing_env_still_fails_closed(self) -> None:
        """Still fail-closed, and it names the field that is missing.

        The endpoint now falls back to the provider's declared default,
        so the MODEL is the field an operator can still leave unset. The
        error must name it (plus its env var) and never a value.
        """
        with mock.patch.dict(os.environ, CLEAN_ENV, clear=True):
            with self.assertRaises(ProviderConfigError) as ctx:
                api.make_model_adapter()
        message = str(ctx.exception)
        self.assertIn("model", message)
        self.assertIn("RAPHAEL_MODEL_NAME", message)
        self.assertNotIn(FAKE, message)

    def test_endpoint_falls_back_to_provider_default(self) -> None:
        """BLANKER 1: a provider alone is enough to configure an adapter."""
        with mock.patch.dict(os.environ, CLEAN_ENV, clear=True):
            adapter = api.make_model_adapter(
                provider="openai-compatible", model="mimo-2.6-flash")
        self.assertIsInstance(adapter, OpenAICompatAdapter)
        self.assertEqual(adapter._config.endpoint,
                         "https://openrouter.ai/api/v1")


class RuntimeOverrideReachesExistingAdapter(RuntimeConfigBuilds):
    """The supplied values must reach the EXISTING provider unchanged."""

    def test_openrouter_endpoint_model_and_key(self) -> None:
        adapter = self.build(
            provider="openai-compatible",
            api_key=FAKE,
            endpoint="https://openrouter.ai/api/v1",
            model="vendor/space-bunny",
        )
        self.assertIsInstance(adapter, OpenAICompatAdapter)
        self.assertIsInstance(adapter, ModelAdapter)
        cfg = adapter._config
        self.assertEqual(cfg.endpoint, "https://openrouter.ai/api/v1")
        self.assertEqual(cfg.model, "vendor/space-bunny")
        self.assertEqual(cfg.api_key, FAKE)
        # OpenRouter must not receive OpenCode session headers.
        self.assertFalse(cfg.uses_opencode_headers())

    def test_no_duplicate_provider_abstraction(self) -> None:
        """The override must reuse OpenAICompatAdapter, not add a class."""
        import raphael_ibm_bob.harness.providers as pkg
        names = [n for n in dir(pkg) if "Provider" in n]
        self.assertNotIn("OpenRouterProvider", names)
        self.assertNotIn("LLMProvider", names)

    def test_unknown_provider_rejected(self) -> None:
        with self.assertRaises(ProviderConfigError):
            self.build(provider="openai-compatible-x", api_key=FAKE,
                       endpoint="https://openrouter.ai/api/v1", model="m")

    def test_blank_values_fall_back_to_env(self) -> None:
        with mock.patch.dict(os.environ, {
            **CLEAN_ENV,
            "RAPHAEL_MODEL_ENDPOINT": "https://env.example/v1",
            "RAPHAEL_MODEL_NAME": "env/model",
            "RAPHAEL_MODEL_API_KEY": "env-key-not-real",
        }, clear=True):
            adapter = api.make_model_adapter(
                api_key="  ", endpoint="", model=None)
        self.assertEqual(adapter._config.endpoint, "https://env.example/v1")
        self.assertEqual(adapter._config.model, "env/model")


class CredentialNeverPersisted(RuntimeConfigBuilds):
    """The key must not reach any session, run, or evidence surface."""

    def test_redacted_reports_configured_not_the_key(self) -> None:
        adapter = self.build(api_key=FAKE,
                             endpoint="https://openrouter.ai/api/v1",
                             model="vendor/space-bunny")
        shown = adapter._config.redacted()
        self.assertEqual(shown["api_key"], "set")
        self.assertNotIn(FAKE, json.dumps(shown))

    def test_key_absent_from_session_and_run_records(self) -> None:
        from raphael_ibm_bob.contracts import Mission
        from raphael_ibm_bob.harness.run import RaphaelRun
        from raphael_ibm_bob.harness.session import RaphaelSession
        mission = Mission(mission_id="m", description="d", scope="",
                          criteria=["c"])
        session = RaphaelSession.create(
            session_id="s1", mission=mission, provider="openai-compatible",
            model="vendor/space-bunny")
        run = RaphaelRun(
            run_id="r1", session_id="s1", mission=mission,
            workspace_root="/tmp", ledger_dir="/tmp/runs/r1")
        self.assertNotIn(FAKE, json.dumps(session.to_dict()))
        self.assertNotIn(FAKE, json.dumps(run.to_dict()))
        for blob in (session.to_dict(), run.to_dict()):
            self.assertNotIn("api_key", json.dumps(blob))

    def test_environment_is_not_mutated(self) -> None:
        before = dict(os.environ)
        self.build(api_key=FAKE, endpoint="https://openrouter.ai/api/v1",
                   model="vendor/space-bunny")
        self.assertEqual(dict(os.environ), before,
                         "os.environ must not be mutated")
        self.assertNotIn("RAPHAEL_MODEL_API_KEY", os.environ)


class CredentialNeverDisclosed(RuntimeConfigBuilds):
    """No error path may echo the key."""

    def test_key_absent_from_every_provider_exception(self) -> None:
        with mock.patch.dict(os.environ, CLEAN_ENV, clear=True):
            adapter = api.make_model_adapter(
                api_key=FAKE, endpoint="http://127.0.0.1:9/v1",
                model="vendor/space-bunny")
            with self.assertRaises(Exception) as ctx:
                adapter.propose(ModelContext(
                    mission=Mission(mission_id="m", description="d",
                                    scope="", criteria=["c"]),
                    findings=[], workspace_root="/tmp", evidence_count=0,
                    session_id="s"))
        blob = f"{ctx.exception!r} {ctx.exception}"
        self.assertNotIn(FAKE, blob)

    def test_provider_module_does_not_log(self) -> None:
        """Stronger: the provider emits no log records at all."""
        from raphael_ibm_bob.harness.providers import openai_compat
        source = Path(openai_compat.__file__).read_text(encoding="utf-8")
        self.assertNotIn("import logging", source)
        self.assertNotIn("logging.getLogger", source)

    def test_provider_emits_no_log_records_on_failure(self) -> None:
        with mock.patch.dict(os.environ, CLEAN_ENV, clear=True):
            adapter = api.make_model_adapter(
                api_key=FAKE, endpoint="http://127.0.0.1:9/v1",
                model="vendor/space-bunny")
            with self.assertNoLogs("raphael_ibm_bob", level="DEBUG"):
                with self.assertRaises(Exception):
                    adapter.propose(ModelContext(
                        mission=Mission(mission_id="m", description="d",
                                        scope="", criteria=["c"]),
                        findings=[], workspace_root="/tmp", evidence_count=0,
                        session_id="s"))

    def test_key_never_enters_the_llm_prompt_body(self) -> None:
        from raphael_ibm_bob.harness.providers.openai_compat import (
            OpenAICompatConfig, build_request_body)
        from raphael_ibm_bob.harness.model import ModelContext
        from raphael_ibm_bob.contracts import Mission
        cfg = OpenAICompatConfig(
            endpoint="https://openrouter.ai/api/v1",
            model="vendor/space-bunny", api_key=FAKE)
        mission = Mission(mission_id="m", description="d", scope="",
                          criteria=["c"])
        ctx = ModelContext(mission=mission, findings=[],
                           workspace_root="/tmp", evidence_count=0,
                           session_id="s")
        body = build_request_body(cfg, ctx, [{"skill": "read-file"}])
        self.assertNotIn(FAKE, json.dumps(body))


class ConsoleNeverRendersACredential(unittest.TestCase):
    """Close the gap: no test covered the operations console index page.

    Existing suites assert `assertNotIn("api_key", html)` for pages that have
    no credential input (graph, event stream, command center). This page DOES
    legitimately have a field *named* `api_key`, so the correct assertion is
    that no credential VALUE is rendered and the input is masked — not that
    the name is absent.
    """

    SECRET = "sk-or-v1-RENDEREDMUSTNOTAPPEAR000000000"

    def render(self) -> str:
        from raphael_ibm_bob.http.views import operations_console as oc
        with tempfile.TemporaryDirectory() as tmp:
            return oc.render_index(
                [], runs_root=Path(tmp) / "runs",
                sessions_root=Path(tmp) / "sessions",
                vpn_status={"connected": False}, mode_state={"mode": "normal"},
                target_state=None)

    def test_provider_fieldset_is_present(self) -> None:
        html = self.render()
        for needle in ('name="provider"', 'name="endpoint"',
                       'name="model"', 'name="api_key"'):
            self.assertIn(needle, html)

    def test_key_input_is_masked_and_never_prefilled(self) -> None:
        html = self.render()
        idx = html.index('name="api_key"')
        tag = html[idx - 80:idx + 160]
        self.assertIn('type="password"', tag)
        # No value attribute at all => nothing can be pre-filled or echoed.
        self.assertNotIn("value=", tag)
        self.assertNotIn(self.SECRET, html)

    def test_no_credential_persisted_in_browser_storage(self) -> None:
        from raphael_ibm_bob.http.views import operations_console as oc
        src = Path(oc.__file__).read_text(encoding="utf-8")
        # The provider key must never be written to web storage. The existing
        # `raphael_api_key` server-token flow is a different, pre-existing key.
        self.assertNotIn("setItem('api_key'", src)
        self.assertNotIn('setItem("api_key"', src)
        self.assertNotIn("localStorage", src)

    def test_console_html_carries_no_authorization_header(self) -> None:
        html = self.render()
        self.assertNotIn("authorization:", html.lower())


class GovernanceUnaffected(unittest.TestCase):
    """The runtime key must not weaken the governed loop."""

    def test_scripted_provider_still_works_after_change(self) -> None:
        from raphael_ibm_bob.contracts import (
            ActionRequest, Capability, Decision, Mission)
        from raphael_ibm_bob.broker import BOBBroker
        from raphael_ibm_bob.evidence_ledger import (
            EvidenceLedger, create_run_dir)
        from raphael_ibm_bob.harness.model import ModelContext, ScriptedModelAdapter
        from raphael_ibm_bob.policy import BOBPolicy
        from raphael_ibm_bob.runtime import BOBRuntime
        from raphael_ibm_bob.workspace import Workspace

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "f.txt"
            target.write_text("x\n", encoding="utf-8")
            _, run_dir = create_run_dir(root / "runs")
            ws = Workspace(root)
            broker = BOBBroker(policy=BOBPolicy(workspace=ws),
                               workspace=ws,
                               ledger=EvidenceLedger(run_dir))
            runtime = BOBRuntime(broker)
            mission = Mission(mission_id="m", description="d",
                              scope=str(root), criteria=["c"])
            adapter = ScriptedModelAdapter({mission.mission_id: ActionRequest(
                sequence=0, requester="assistant", capability=Capability.READ,
                target=str(target), purpose="p")})
            self.assertIsInstance(adapter, ModelAdapter)
            ctx = ModelContext(mission=mission, findings=[],
                               workspace_root=str(root), evidence_count=0,
                               session_id="s")
            ok = runtime.submit(adapter.propose(ctx), mission)
            self.assertEqual(ok.broker_result.decision.decision, Decision.ALLOW)

            # Negative: an unauthorized proposal must still be denied with
            # zero capability invocations.
            before = broker.capability_invocations
            bad = ScriptedModelAdapter({mission.mission_id: ActionRequest(
                sequence=0, requester="assistant", capability="shell_exec",
                target=str(target), purpose="p")})
            denied = runtime.submit(bad.propose(ctx), mission)
            self.assertEqual(denied.broker_result.decision.decision,
                             Decision.DENY)
            self.assertFalse(denied.broker_result.capability_invoked)
            self.assertEqual(broker.capability_invocations, before)


if __name__ == "__main__":
    unittest.main()
