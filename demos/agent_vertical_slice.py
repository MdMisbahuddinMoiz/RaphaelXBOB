"""AI pentester vertical slice — local governed demonstration.

SCOPE NOTE — this is a DEVELOPER script, not an operator entry point.
It calls `harness.api.start_model_run` directly, so it does NOT pass
through the audit model allow-list that the operator surfaces enforce
(`/agent/start`, `/runs/model`, `/operations/start`). That is why it can
use the local deterministic endpoint. An operator driving the agent
from the Web UI is bound by `api.require_audit_allowed_model`; see
`scripts/check_real_provider.sh` for the real-model path.

Runs the whole slice against a LOCAL fixture and a LOCAL model endpoint,
with no vendor credential and no external network:

    127.0.0.1:8080  (fixture target, real TCP listener)
      -> AI observes            (no evidence yet)
      -> AI proposes action     (governed service discovery)
      -> Raphael authorizes     (Runtime -> Broker -> Policy: ALLOW)
      -> governed capability runs (Broker -> DiscoveryMediator)
      -> evidence returns       (append-only ledger, provider_untrusted)
      -> AI selects next action (ports fold into the next context)
      -> AI declares done       -> QualityGate is the sole authority

Every step below goes through the PRODUCT code path. Nothing here calls
a socket, a mediator, or a capability directly: the demo only declares
an authorized target, builds a provider adapter, and runs the same
`harness.api.start_model_run` the Web UI calls.

Usage:
    PYTHONPATH=. python3 demos/agent_vertical_slice.py
    PYTHONPATH=. python3 demos/agent_vertical_slice.py --turns 6
"""
from __future__ import annotations

import argparse
import http.server
import socket
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from demos.local_model_endpoint import (  # noqa: E402
    LocalModelEndpoint,
    MODEL_ID,
    probe,
)
from raphael_ibm_bob.contracts import Mission  # noqa: E402
from raphael_ibm_bob.harness import api  # noqa: E402
from raphael_ibm_bob.target_profile import (  # noqa: E402
    build_target_profile,
    set_target_store,
    TargetStore,
)

FIXTURE_HOST = "127.0.0.1"
FIXTURE_PORT = 8080
MISSION_ID = "M-AGENT-DEMO-001"
AUTHORIZATION_REF = "local-demo-lab"

RULE = ("\n" + "=" * 74 + "\n")


class _FixtureHandler(http.server.BaseHTTPRequestHandler):
    """The demo target: a plain HTTP service on the declared host."""

    server_version = "RaphaelFixture/1.0"

    def log_message(self, fmt: str, *args) -> None:
        """Silent: the demo prints its own narrative."""

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        body = (b"Raphael local fixture service.\n"
                b"This host is authorized for the demo mission only.\n")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FixtureTarget:
    """Real loopback listener standing in for the authorized target."""

    def __init__(self, host: str = FIXTURE_HOST,
                 port: int = FIXTURE_PORT) -> None:
        self._server = http.server.ThreadingHTTPServer((host, port),
                                                       _FixtureHandler)
        self._server.daemon_threads = True
        self._thread = None

    @property
    def address(self) -> str:
        host, port = self._server.server_address[:2]
        return f"{host}:{port}"

    def __enter__(self) -> "FixtureTarget":
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)


def _step(text: str) -> None:
    print(f"{RULE}{text}{RULE}", flush=True)


def _render(timeline: dict) -> None:
    for turn in timeline.get("turns", ()):
        observation = turn.get("observation") or {}
        proposal = turn.get("proposal") or {}
        policy = turn.get("policy") or {}
        execution = turn.get("execution") or {}
        evidence = turn.get("evidence") or {}
        print(f"  TURN {turn['index']}")
        print(f"    OBSERVE   services_known="
              f"{observation.get('services_known')}  "
              f"observations_folded={observation.get('observation_count')}")
        print(f"    PROPOSE   {proposal.get('capability', 'intent')}"
              f" -> {proposal.get('target', '')}")
        print(f"    RATIONALE {turn.get('rationale', '')}")
        print(f"    POLICY    {policy.get('decision').upper()}"
              f"  ({policy.get('reason', '')})")
        print(f"    EXECUTE   invoked={execution.get('executed')}"
              f"  success={execution.get('success')}")
        print(f"    EVIDENCE  {', '.join(evidence.get('evidence_ids') or []) or '-'}"
              f"  provider_untrusted={evidence.get('provider_untrusted')}")
        excerpt = (evidence.get("excerpt") or "").strip()
        if excerpt:
            print(f"    OBSERVED  {excerpt[:200]}")
        print(f"    NEXT      {turn.get('next_action', '')}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--turns", type=int, default=4,
                        help="max governed turns (default: 4)")
    parser.add_argument("--port", type=int, default=FIXTURE_PORT,
                        help="fixture target port (default: 8080)")
    args = parser.parse_args(argv)

    workdir = Path(tempfile.mkdtemp(prefix="raphael-agent-demo-"))
    workspace = workdir / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    runs_root = workdir / "runs"
    sessions_root = workdir / "sessions"

    with FixtureTarget(port=args.port) as fixture, \
            LocalModelEndpoint() as endpoint:
        _step("PHASE 1 — PROVIDER UI (normalized configuration)")
        try:
            api.build_provider_configuration(
                "openai-compatible",
                endpoint=endpoint.base_url,
                model=MODEL_ID,
                api_key="demo-key-never-persisted",
                environ={})
        except Exception as exc:
            print(f"  provider configuration FAILED: {exc}")
            return 1
        config = api.build_provider_configuration(
            "openai-compatible", endpoint=endpoint.base_url,
            model=MODEL_ID, api_key="demo-key-never-persisted", environ={})
        print(f"  providers registered : {api.available_providers()}")
        print(f"  endpoint            : {config.redacted()['endpoint']}")
        print(f"  model               : {config.redacted()['model']}")
        print(f"  api key             : {config.redacted()['api_key']} "
              "(value never printed, logged, or persisted)")
        ok, reported = probe(endpoint.base_url)
        print(f"  endpoint reachable  : {ok} (model={reported or '-'})")
        if not ok:
            return 1
        model = api.make_model_adapter(
            "openai-compatible", endpoint=endpoint.base_url,
            model=MODEL_ID, api_key="demo-key-never-persisted")
        print(f"  adapter             : {type(model).__name__} "
              "(implements ModelAdapter.propose)")

        _step("PHASE 2 — MODEL ADAPTER (planner stays provider-agnostic)")
        print(f"  adapter class       : {type(model).__module__}")
        print("  the planner consumes ModelAdapter; it never sees the "
              "provider id, endpoint, or key")

        profile = build_target_profile(
            mission_id=MISSION_ID,
            locator=FIXTURE_HOST,
            allowed_ports=[args.port],
            allowed_protocols="http",
            authorization_ref=AUTHORIZATION_REF,
            platform="htb",
        )
        store = TargetStore()
        store.set_target(profile)
        set_target_store(store)
        print(f"  target host         : {profile.locator}  "
              f"(fixture listening on {fixture.address})")
        print(f"  stage               : {profile.stage}")

        mission = Mission(
            mission_id=MISSION_ID,
            description=f"governed assessment of {profile.locator}",
            scope=profile.scope,
            criteria=["service-discovery"],
        )
        session = api.create_session(
            mission=mission, workspace_root=workspace,
            project_name=MISSION_ID, model=MODEL_ID,
            provider="openai-compatible", sessions_root=sessions_root)

        result = api.start_model_run(
            session, mission=mission, model=model, max_turns=args.turns,
            sessions_root=sessions_root, runs_root=runs_root,
            target_store=store)
        timeline = api.get_agent_timeline(result.run.run_id, runs_root)
        if timeline is None:
            print("  no timeline persisted")
            return 1

        _step("PHASE 5 — UI VISIBILITY (exactly what /agent renders)")
        _render(timeline)

        _step("PHASE 6 — LOCAL DEMO RESULT")
        print(f"  run id              : {result.run.run_id}")
        print(f"  terminal            : {result.terminal}"
              f"  ({result.terminal_reason})")
        print(f"  governed turns      : {result.turns}")
        print(f"  quality gate verdict: {result.gate_verdict}")
        print(f"  evidence records    : "
              f"{len(api.get_evidence(result.run.run_id, runs_root))}")
        print(f"  timeline projection : {timeline and 'runs/<id>/timeline.json'}")
        print(f"  workspace           : {workspace}")
        print(f"  runs root           : {runs_root}")
        print("  NB the gate judges the evidence, not the model: REFUSE here "
              "is the honest verdict for a 2-condition discovery mission")
    return 0


if __name__ == "__main__":
    sys.exit(main())
