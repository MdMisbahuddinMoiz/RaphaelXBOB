"""Real-provider readiness check for the Raphael agent slice.

Answers one question honestly: **is a real approved model reachable from
this machine right now?** It never prints a credential, never writes
one, and never fabricates a provider.

What it does, in order:

1. Runs the centralized audit allow-list over the requested model.
2. Normalizes the operator configuration into a `ProviderConfig`
   (endpoint / model / key / bounds) and prints only `redacted()`.
3. Performs ONE minimal authenticated `POST {endpoint}/chat/completions`
   to confirm the credential and the model id actually work together.

Step 3 is the only network call, and it is a provider health check, not
an agent action: nothing is brokered, no capability runs, no evidence is
written. It exists so "is the real provider working?" is a measurement
rather than an assumption.

Configuration comes from the EXISTING operator mechanism — the
`RAPHAEL_MODEL_*` server environment — or from flags. A key supplied by
flag is held in memory for the life of the process and is never logged.

Exit codes:
    0  a real approved model answered
    3  configuration incomplete (names the missing field)
    4  the model is not on the audit allow-list
    5  the provider rejected or could not be reached
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from raphael_ibm_bob.harness import api  # noqa: E402
from raphael_ibm_bob.harness.providers import ProviderConfigError  # noqa: E402

OK, NOT_CONFIGURED, NOT_APPROVED, PROVIDER_FAILED = 0, 3, 4, 5

#: Smallest possible probe. One short completion, no tools, no repo
#: context — this measures the provider, not the agent.
PROBE_MESSAGES = [
    {"role": "system", "content": "Reply with one word."},
    {"role": "user", "content": "Reply with the single word: ready"},
]


def _report_missing(field: str) -> int:
    print(f"RESULT: NOT CONFIGURED — {field}")
    print()
    print("Still required to run a real approved model:")
    print("  RAPHAEL_MODEL_ENDPOINT  base URL of an OpenAI-compatible API")
    print("                          (e.g. https://openrouter.ai/api/v1)")
    print("  RAPHAEL_MODEL_NAME      one of: "
          + ", ".join(api.AUDIT_ALLOWED_MODEL_IDS))
    print("  RAPHAEL_MODEL_API_KEY   the provider's bearer credential")
    print()
    print("Export them in the server environment, or enter provider / "
          "model / endpoint / API key on the Raphael agent console "
          "(GET /agent). Nothing is stored in plaintext either way.")
    return NOT_CONFIGURED


def _reason(exc: urllib.error.HTTPError) -> str:
    """The provider's own error message, truncated.

    Describes this account and model, never the bearer credential, so
    it is safe to print. Falls back to the HTTP reason phrase.
    """
    try:
        payload = json.loads(exc.read().decode("utf-8", "replace"))
        message = (payload.get("error") or {}).get("message")
        if isinstance(message, str) and message.strip():
            return message.strip()[:300]
    except (ValueError, AttributeError, OSError):
        pass
    return exc.reason or "no detail"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", default="openai-compatible")
    parser.add_argument("--model", default=os.environ.get(
        "RAPHAEL_MODEL_NAME", ""))
    parser.add_argument("--endpoint", default=os.environ.get(
        "RAPHAEL_MODEL_ENDPOINT", ""))
    args = parser.parse_args(argv)

    print("=" * 70)
    print("RAPHAEL — real provider readiness")
    print("=" * 70)

    print("1. MODEL AUTHORIZATION (centralized audit allow-list)")
    try:
        approved = api.require_audit_allowed_model(args.model)
    except ValueError as exc:
        print(f"   REJECTED: {exc}")
        return NOT_APPROVED
    if approved:
        print(f"   APPROVED: {approved}")
    else:
        print("   server environment (RAPHAEL_MODEL_NAME) — not overridden")

    print("\n2. PROVIDER CONFIGURATION (normalized, redacted)")
    try:
        config = api.build_provider_configuration(
            args.provider, endpoint=args.endpoint or None,
            model=approved or None)
    except ProviderConfigError as exc:
        return _report_missing(str(exc))
    for key, value in config.redacted().items():
        print(f"   {key:16} {value}")
    print("   NOTE: the credential value itself is never rendered, logged,")
    print("         persisted, or returned to a browser.")

    print("\n3. PROVIDER HEALTH PROBE (one minimal completion)")
    body = json.dumps({
        "model": config.model,
        "messages": PROBE_MESSAGES,
        "max_tokens": 8,
        "temperature": 0,
    }).encode("utf-8")
    request = urllib.request.Request(
        config.endpoint.rstrip("/") + "/chat/completions",
        data=body,
        headers={"Content-Type": "application/json",
                 "User-Agent": "RaphaelHarness/1.0"},
        method="POST")
    if config.has_api_key:
        request.add_header("Authorization", "Bearer " + config.api_key)
    try:
        with urllib.request.urlopen(
                request, timeout=config.timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # The provider's own message is safe to surface: it describes
        # THIS account and model, never the bearer credential. Reporting
        # it matters — a 403 is frequently an ACCOUNT gate (age
        # attestation, tier restriction) rather than a bad key, and
        # collapsing both into "credential rejected" points the operator
        # at the wrong thing.
        print(f"   FAILED: provider HTTP {exc.code} — {_reason(exc)}")
        if exc.code == 401:
            print("   -> the credential was rejected. Check "
                  "RAPHAEL_MODEL_API_KEY.")
        elif exc.code == 403:
            print("   -> the credential AUTHENTICATED; the ACCOUNT is "
                  "gated for this model. Complete the provider's "
                  "requirement, then re-run.")
        elif exc.code == 400:
            print(f"   -> the endpoint or model id was rejected "
                  f"(model={config.model!r}).")
        elif exc.code == 404:
            print(f"   -> no route to model={config.model!r}.")
        print(f"\nRESULT: PROVIDER FAILED ({exc.code})")
        return PROVIDER_FAILED
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(f"   FAILED: {type(exc).__name__} — endpoint unreachable")
        print(f"\nRESULT: PROVIDER FAILED ({type(exc).__name__})")
        return PROVIDER_FAILED

    try:
        reply = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        print("   FAILED: provider response had no choices/message/content")
        print("\nRESULT: PROVIDER FAILED (bad payload)")
        return PROVIDER_FAILED
    print(f"   model id accepted: {payload.get('model', config.model)!r}")
    print(f"   response: {str(reply)[:120]!r}")
    print("\nRESULT: OK — a real approved model answered.")
    print("Run the Web UI (python3 -m raphael_ibm_bob.http) and open "
          "/agent to drive the governed loop with it.")
    return OK


if __name__ == "__main__":
    sys.exit(main())
