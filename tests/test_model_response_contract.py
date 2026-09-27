"""Provider-response contract and target-platform declaration.

Two defects found by running the real product against a real reasoning
model and a real VulnHub target:

1. The console declared every target as `platform="htb"` through a
   hardcoded hidden input, so a VulnHub machine was mislabelled.
2. A reasoning model that returned no usable action was reported with
   one error whose message named two unrelated causes, so the failure
   could not be told apart from a malformed proposal, a transport
   failure, or a Policy denial.

The response shapes below were captured from a live MiMo V2.6 Flash
call, not invented: at a 512-token budget the model returned
`finish_reason="length"`, `content: null`, and spent 511 of 512
completion tokens on `reasoning`.

No test here may leak reasoning text or a credential into an error, a
record, or rendered HTML.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from raphael_ibm_bob.harness.providers.openai_compat import (
    ModelResponseInvalid,
    ProviderError,
    StructuredProposalError,
    config_from_env,
    parse_response_body,
)
from raphael_ibm_bob.target_profile import (
    ALLOWED_PLATFORMS,
    PLATFORM_SPECS,
    TargetProfileError,
    build_target_profile,
)

SECRET = "sk-or-v1-MUSTNOTLEAK0000000000000000"
MARKER = "SECRET-THOUGHT-MARKER-do-not-leak"


def _body(content, *, finish="stop", reasoning=None):
    message = {"role": "assistant", "content": content}
    if reasoning is not None:
        message["reasoning"] = reasoning
    return {"choices": [{"finish_reason": finish, "message": message}]}


class _EnvGuard:
    """Restore the process environment exactly as found."""

    def __init__(self, *keys):
        self.keys = keys
        self.saved = {}

    def __enter__(self):
        for key in self.keys:
            self.saved[key] = os.environ.pop(key, None)
        return self

    def __exit__(self, *exc):
        for key, value in self.saved.items():
            os.environ.pop(key, None)
            if value is not None:
                os.environ[key] = value
        return False


class ResponseStateClassification(unittest.TestCase):
    """Cases A/B/C/D/E must stay distinguishable."""

    def test_A_valid_content_parses(self):
        body = _body('{"skill_id": "network-service-discovery"}',
                     reasoning="deliberation")
        self.assertIn("network-service-discovery", parse_response_body(body))

    def test_C_truncated_generation_is_max_tokens(self):
        """The exact shape observed live at a 512-token budget."""
        body = _body(None, finish="length", reasoning="x" * 2518)
        with self.assertRaises(ModelResponseInvalid) as ctx:
            parse_response_body(body)
        self.assertEqual(ctx.exception.reason,
                         ModelResponseInvalid.MAX_TOKENS_EXHAUSTED)

    def test_C_reasoning_only_is_its_own_state(self):
        body = _body(None, finish="stop", reasoning="thought only")
        with self.assertRaises(ModelResponseInvalid) as ctx:
            parse_response_body(body)
        self.assertEqual(
            ctx.exception.reason,
            ModelResponseInvalid.REASONING_ONLY_NO_ACTION_CONTENT)

    def test_C_blank_content_is_empty_content(self):
        with self.assertRaises(ModelResponseInvalid) as ctx:
            parse_response_body(_body("   ", finish="stop"))
        self.assertEqual(ctx.exception.reason,
                         ModelResponseInvalid.EMPTY_CONTENT)

    def test_D_nothing_at_all_is_empty_response(self):
        with self.assertRaises(ModelResponseInvalid) as ctx:
            parse_response_body(_body(None, finish="stop"))
        self.assertEqual(ctx.exception.reason,
                         ModelResponseInvalid.EMPTY_RESPONSE)

    def test_E_transport_failure_stays_provider_error(self):
        with self.assertRaises(ProviderError):
            parse_response_body({"unexpected": "envelope"})

    def test_model_response_state_is_its_own_type(self):
        """Distinct from a malformed proposal, but still catchable."""
        body = _body(None, finish="stop", reasoning="only reasoning")
        with self.assertRaises(ModelResponseInvalid) as ctx:
            parse_response_body(body)
        self.assertIsInstance(ctx.exception, StructuredProposalError)
        self.assertIsNot(type(ctx.exception), StructuredProposalError)


class NoReasoningLeakage(unittest.TestCase):
    """Chain-of-thought must never reach an error, record or UI."""

    def test_reasoning_text_never_appears_in_the_error(self):
        for body in (_body(None, finish="length", reasoning=MARKER),
                     _body(None, finish="stop", reasoning=MARKER),
                     _body("   ", finish="stop", reasoning=MARKER)):
            with self.assertRaises(ModelResponseInvalid) as ctx:
                parse_response_body(body)
            self.assertNotIn(MARKER, f"{ctx.exception}")
            self.assertNotIn(MARKER, ctx.exception.reason)

    def test_credential_never_appears_in_the_error(self):
        body = _body(None, finish="length",
                     reasoning=f"{SECRET} {MARKER}")
        with self.assertRaises(ModelResponseInvalid) as ctx:
            parse_response_body(body)
        self.assertNotIn(SECRET, f"{ctx.exception}")


class NoTokenBudgetDependency(unittest.TestCase):
    """Classification must come from the response, not a size assumption."""

    def test_same_shape_classifies_identically_at_any_budget(self):
        body = _body(None, finish="stop", reasoning="only thinking")
        seen = set()
        for budget in ("1", "512", "4096", "100000"):
            with _EnvGuard("RAPHAEL_MODEL_MAX_TOKENS"):
                os.environ["RAPHAEL_MODEL_MAX_TOKENS"] = budget
                with self.assertRaises(ModelResponseInvalid) as ctx:
                    parse_response_body(body)
                seen.add(ctx.exception.reason)
        self.assertEqual(len(seen), 1,
                         "reason must not vary with max_tokens")

    def test_default_budget_is_not_a_demo_override(self):
        """No 4096 baked into the product."""
        with _EnvGuard("RAPHAEL_MODEL_MAX_TOKENS",
                       "RAPHAEL_MODEL_ENDPOINT", "RAPHAEL_MODEL_NAME"):
            os.environ["RAPHAEL_MODEL_ENDPOINT"] = "http://example.invalid"
            os.environ["RAPHAEL_MODEL_NAME"] = "test-model"
            self.assertNotEqual(config_from_env().max_tokens, 4096)


class TargetPlatformDeclaration(unittest.TestCase):
    """The operator's platform choice is authoritative input."""

    def test_vulnhub_profile_stores_vulnhub(self):
        profile = build_target_profile(
            mission_id="M-P", locator="127.0.0.1",
            allowed_ports="2222,8080", allowed_protocols="http,ssh",
            authorization_ref="LAB", platform="vulnhub",
            environment="isolated-lab")
        self.assertEqual(profile.platform, "vulnhub")
        self.assertEqual(profile.stage, "authorized")

    def test_htb_still_works(self):
        profile = build_target_profile(
            mission_id="M-P", locator="127.0.0.1", allowed_ports="80",
            allowed_protocols="http", authorization_ref="HTB-REF",
            platform="htb")
        self.assertEqual(profile.platform, "htb")

    def test_unsupported_platform_is_rejected(self):
        with self.assertRaises(TargetProfileError):
            build_target_profile(
                mission_id="M-P", locator="127.0.0.1", allowed_ports="80",
                allowed_protocols="http", authorization_ref="R",
                platform="not-a-platform", environment="isolated-lab")

    def test_vulnhub_still_requires_isolated_environment(self):
        """The stricter rule for non-HTB platforms is unchanged."""
        with self.assertRaises(TargetProfileError):
            build_target_profile(
                mission_id="M-P", locator="127.0.0.1", allowed_ports="80",
                allowed_protocols="http", authorization_ref="R",
                platform="vulnhub")

    def test_platform_options_come_from_the_canonical_registry(self):
        self.assertEqual(ALLOWED_PLATFORMS,
                         tuple(spec.name for spec in PLATFORM_SPECS))
        self.assertIn("vulnhub", ALLOWED_PLATFORMS)



class ConsolePlatformSelector(unittest.TestCase):
    """The console exposes platform and never mislabels the backend."""

    def test_console_has_a_selector_not_a_hidden_htb(self):
        from raphael_ibm_bob.http.views.agent_console import render
        html = render(target={"mission_id": "M-P", "platform": "vulnhub",
                              "locator": "127.0.0.1"})
        self.assertIn('name="platform"', html)
        self.assertNotIn('type="hidden" name="platform" value="htb"', html)
        self.assertIn("VULNHUB", html.upper())

    def test_declare_form_still_has_its_submit_button(self):
        """A lost submit button makes the whole form unsubmittable.

        Added after a repair dropped it: the platform selector was present
        and every assertion still passed, so only checking the rendered
        form caught it.
        """
        from raphael_ibm_bob.http.views.agent_console import render
        html = render(target={"mission_id": "M-P", "locator": "127.0.0.1"})
        self.assertIn("Declare target", html)
        self.assertEqual(html.count('action="/agent/target"'), 1)
        self.assertIn("Start the agent", html)

    def test_selector_reflects_the_declared_platform(self):
        from raphael_ibm_bob.http.views.agent_console import _platform_select
        chosen = _platform_select("vulnhub")
        self.assertIn('<option value="vulnhub" selected>', chosen)
        self.assertIn('<option value="htb">', chosen)

    def test_console_does_not_claim_vulnhub_when_backend_says_htb(self):
        from raphael_ibm_bob.http.views.agent_console import _platform_select
        rendered = _platform_select("htb")
        self.assertIn('<option value="htb" selected>', rendered)
        self.assertNotIn('<option value="vulnhub" selected>', rendered)

    def test_no_credential_in_console_html(self):
        from raphael_ibm_bob.http.views.agent_console import render
        html = render(target={"mission_id": "M-P", "locator": "127.0.0.1"})
        self.assertNotIn(SECRET, html)
        self.assertNotIn("sk-or-v1-", html)


if __name__ == "__main__":
    unittest.main()
