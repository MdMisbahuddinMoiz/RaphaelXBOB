"""Agent routes — the AI pentester vertical slice control surface.

    GET  /agent                 operator console (provider, target, loop)
    POST /agent/start           start a governed, model-led agent run
    POST /agent/target          declare the authorized target
    GET  /runs/{run_id}/timeline  read-only governed-loop projection

Orchestration only. This module builds no model loop, no provider, and
no capability: it normalizes operator input, delegates to
`harness.api` and `target_profile`, and renders. The only execution path
remains Model -> Raphael ActionRequest -> Runtime -> Broker -> Policy ->
Capability -> Evidence.

Credential discipline: `api_key` arrives in the POST body, is used to
build an in-memory `ProviderConfig`, and is then dropped. It is never
written to the session, the run record, the ledger, an artifact, the
URL, or any response. The console reports only `set` / `unset`.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from raphael_ibm_bob.contracts import Mission
from raphael_ibm_bob.credential_provenance import (
    CredentialProvenance,
    CredentialVault,
)
from raphael_ibm_bob.harness import api
from raphael_ibm_bob.harness.run import find_run_dir
from raphael_ibm_bob.network_scope import (
    NetworkScopeError,
    parse_ssh_target,
)
from raphael_ibm_bob.harness.providers import ProviderConfigError
from raphael_ibm_bob.http import errors, security
from raphael_ibm_bob.http.app import Response
from raphael_ibm_bob.http.routes._common import body_object
from raphael_ibm_bob.http.views import agent_console as view
from raphael_ibm_bob.target_profile import (
    ALLOWED_PROTOCOLS,
    TARGET_STAGE_AUTHORIZED,
    TargetProfileError,
    build_target_profile,
    get_target_store,
)

#: Upper bound for operator-supplied `max_turns` (UI guardrail only; the
#: governed loop keeps its own bound).
MAX_UI_TURNS = 50
DEFAULT_UI_TURNS = 6

#: Platform + environment used when the operator does not choose. A
#: non-HTB platform must name an isolated environment explicitly, so
#: loopback labs declare `isolated-lab` and cannot reach an ordinary
#: network by accident.
DEFAULT_PLATFORM = "htb"


def _vault(config):
    """The process-local credential vault for this server instance.

    Created on first use and held on the config, so the same vault backs
    the HTTP layer, Policy, and the SSH mediator. Plaintext lives here
    and nowhere else.
    """
    vault = getattr(config, "credential_vault", None)
    if vault is None:
        vault = CredentialVault()
        try:
            config.credential_vault = vault
        except Exception:  # noqa: BLE001 - frozen config: fall back
            pass
    return vault


def _store(config):
    store = getattr(config, "target_store", None)
    return store if store is not None else get_target_store()


def _text(body: Dict[str, Any], key: str) -> str:
    value = body.get(key)
    return value.strip() if isinstance(value, str) else ""


def _max_turns(body: Dict[str, Any]) -> int:
    raw = body.get("max_turns")
    if raw in (None, ""):
        return DEFAULT_UI_TURNS
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise errors.invalid_input("max_turns must be an integer") from None
    if value < 1 or value > MAX_UI_TURNS:
        raise errors.invalid_input(
            f"max_turns must be between 1 and {MAX_UI_TURNS}")
    return value


def _workspace_root(config, body: Dict[str, Any]) -> Path:
    """Resolve the governed workspace root for this run.

    Defaults to the repository working directory so an operator who just
    wants to point the agent at a loopback target is not forced to
    create a workspace tree first. An explicit path must already exist.
    """
    raw = _text(body, "workspace_root")
    root = Path(raw) if raw else Path(config.runs_root).resolve().parent
    root = root.resolve()
    if not root.is_dir():
        raise errors.invalid_input(
            "workspace_root must be an existing directory")
    return root


def _active_mission_id(config, body: Dict[str, Any]) -> str:
    """The mission this request belongs to.

    Prefers the operator-supplied id, then the TargetProfile currently
    declared, then a stable default. The SSH session and the agent run
    MUST resolve to the same id or the session silently fails to attach.
    """
    supplied = _text(body, "mission_id")
    if supplied:
        return supplied
    profile = _any_target(config)
    if profile and profile.get("mission_id"):
        return str(profile["mission_id"])
    return "M-AGENT-001"


def _provider_state(config) -> Dict[str, Any]:
    """Non-secret snapshot of the server model configuration.

    Reports only the endpoint/model Raphael would fall back to and
    whether a credential exists — never the credential itself.
    """
    state: Dict[str, Any] = {}
    try:
        from raphael_ibm_bob.harness.providers.openai_compat import (
            API_KEY_ENV,
            ENDPOINT_ENV,
            MODEL_ENV,
        )
        import os
        state["endpoint"] = os.environ.get(ENDPOINT_ENV, "")
        state["model"] = os.environ.get(MODEL_ENV, "")
        state["api_key"] = "set" if os.environ.get(API_KEY_ENV) else "unset"
    except Exception:  # noqa: BLE001 - a UI must never 500 on config
        pass
    state.setdefault("api_key", "unset")
    try:
        from raphael_ibm_bob.harness.providers import (
            default_provider_registry,
            provider_default_endpoint,
        )
        provider_ids = default_provider_registry().provider_ids()
    except Exception:  # noqa: BLE001 - a UI must never 500 on config
        provider_ids: tuple = ()

        def provider_default_endpoint(_provider: object) -> str:
            return ""
    selected = state.get("provider") or (provider_ids[0] if provider_ids
                                         else "")
    state["provider"] = selected
    # Pre-fill the endpoint from the provider's DECLARED DEFAULT so the
    # console is usable without the operator having to know the URL. An
    # explicit environment value still wins, and an explicit field
    # submitted by the operator overrides both.
    if not state.get("endpoint"):
        state["endpoint"] = provider_default_endpoint(selected)
    if not state.get("model"):
        labels = api.AUDIT_ALLOWED_MODEL_LABELS
        state["model"] = next(iter(labels), "")
    state["workspace_root"] = str(Path(config.runs_root).resolve().parent)
    state["max_turns"] = getattr(config, "default_max_turns",
                                 DEFAULT_UI_TURNS)
    return state


def _any_target(config) -> Optional[Dict[str, Any]]:
    """The declared target, whatever mission it is bound to.

    The console shows the operator what Policy will consult. The
    mission binding itself is still enforced inside the TargetStore on
    every governed action — this only renders the current declaration.
    """
    profile = _store(config).current()
    return profile.to_dict() if profile is not None else None


def _run_state(config, run_id: str
               ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    try:
        timeline = api.get_agent_timeline(run_id, config.runs_root)
    except Exception:  # noqa: BLE001 - unknown run renders as "no timeline"
        timeline = None
    try:
        gate = api.get_gate(run_id, config.runs_root)
    except Exception:  # noqa: BLE001
        gate = None
    return timeline, gate


def _model_ref(config, run_id: str) -> Optional[Dict[str, str]]:
    """Provider/model names for a run, read from its session record.

    Names only — the session deliberately stores a reference, never a
    credential, so this is safe to render.
    """
    try:
        run = api.get_run(run_id, config.runs_root)
        session = api.get_session(run.session_id, config.sessions_root)
    except Exception:  # noqa: BLE001 - an unknown run renders as unknown
        return None
    return {"provider": session.provider, "model": session.model}



def _ssh_state(config) -> Tuple[Optional[dict], Optional[dict]]:
    """Current SSH session declaration plus the form's prefill state."""
    store = _store(config)
    getter = getattr(store, "get_ssh_session", None)
    session = None
    if callable(getter):
        for candidate in _session_missions(store):
            session = getter(candidate)
            if session:
                break
    if session is None:
        latest = getattr(store, "latest_ssh_session", None)
        session = latest() if callable(latest) else None
    return session, dict(session) if session else None


def _session_missions(store) -> List[str]:
    """Mission ids the operator has declared a target for, newest last."""
    missions = getattr(store, "_ssh_sessions", None)
    if isinstance(missions, dict):
        return list(missions)
    return []


def console(request, params, config):
    """GET /agent — the AI agent operator console."""
    run_id = request.query_one("run") or ""
    if run_id:
        try:
            security.check_resource_id(run_id, "run_id")
        except ValueError as exc:
            raise errors.bad_request(str(exc)) from None
    timeline, gate = _run_state(config, run_id) if run_id else (None, None)
    ssh_session, ssh_state = _ssh_state(config)
    target_mission = _any_target(config) or None
    chat_messages: List[dict] = []
    chat_stopped = False
    chat_stop_reason = ""
    chat_mission = str((target_mission or {}).get("mission_id") or "")
    if chat_mission:
        try:
            chat_payload = api.read_chat(chat_mission, config.runs_root)
            chat_messages = chat_payload["messages"]
            chat_stopped = bool(chat_payload["stopped"])
            if chat_stopped:
                chat_stop_reason = (
                    "Mission stopped. No further model turns or capability "
                    "execution until it is resumed.")
        except ValueError:
            chat_messages = []
    state = _provider_state(config)
    run_state = "stopped" if chat_stopped else (
        "refused" if (gate or {}).get("verdict") == "refuse" else (
            "complete" if (gate or {}).get("verdict") == "complete" else
            ("running" if timeline else "idle")))
    turn_count = len((timeline or {}).get("turns") or ())
    html = view.render(
        run_id=run_id,
        provider_state=state,
        target=target_mission or None,
        timeline=timeline,
        gate=gate,
        model_ref=_model_ref(config, run_id) if run_id else None,
        ssh_session=ssh_session,
        ssh_state=ssh_state,
        chat_messages=chat_messages,
        chat_stopped=chat_stopped,
        chat_stopped_reason=chat_stop_reason,
        run_state=run_state,
        turn=turn_count,
        max_turns=int(state.get("max_turns", 0) or 0),
    )
    return Response(200, html, content_type=view.HTML)


def timeline(request, params, config):
    """GET /runs/{run_id}/timeline — read-only governed-loop projection."""
    run_id = params["run_id"]
    payload, _gate = _run_state(config, run_id)
    if payload is None:
        raise errors.not_found(
            errors.RUN_NOT_FOUND,
            f"no governed-loop timeline for run {run_id}")
    return {"run_id": run_id, "timeline": payload}


def set_target(request, params, config):
    """POST /agent/target — declare the authorized network target.

    Delegates validation to `build_target_profile`, the same
    fail-closed constructor the HTB target route uses. The operator
    must name both the authorized ports and the authorized protocols;
    Raphael never infers either. A blank `port_spec` is rejected here
    too, so the declared profile is always the one Policy will consult.
    """
    body = body_object(request)
    host = _text(body, "host")
    if not host:
        raise errors.invalid_input("host is required")
    mission_id = _active_mission_id(config, body)
    if not mission_id:
        raise errors.invalid_input("mission_id is required")
    protocols = _text(body, "protocols")
    if not protocols:
        raise errors.invalid_input(
            "protocols is required: name the authorized protocols "
            f"(one of: {', '.join(ALLOWED_PROTOCOLS)})")
    try:
        profile = build_target_profile(
            mission_id=mission_id,
            locator=host,
            allowed_ports=_text(body, "port_spec"),
            allowed_protocols=protocols,
            authorization_ref=_text(body, "authorization_ref") or None,
            platform=_text(body, "platform") or DEFAULT_PLATFORM,
            environment=_text(body, "environment") or None,
            stage=TARGET_STAGE_AUTHORIZED,
        )
    except TargetProfileError as exc:
        # Only the fail-closed constructor's own rejection is a 422. A
        # programming error must surface as a 500 rather than be
        # laundered into a plausible-looking "invalid input".
        raise errors.invalid_input(str(exc)) from None
    _store(config).set_target(profile)
    return 201, {"configured": True, "target": profile.to_dict()}


def start(request, params, config):
    """POST /agent/start — run the governed agent loop against a target.

    Order of operations is a security boundary, not a convenience:

    1. authorize the MODEL against the existing audit allow-list
       (`api.require_audit_allowed_model`) — the same centralized
       mechanism `/runs/model` and `/operations/start` use. Nothing is
       duplicated and no new model id is introduced.
    2. declare / reuse the authorized target.
    3. only then build the provider adapter and enter the governed loop.

    A rejected model therefore NEVER reaches a provider, a network call,
    or the Broker. A blank model means "server environment"
    (`RAPHAEL_MODEL_NAME`), which is operator-configured infrastructure
    and is deliberately outside the per-run list, matching the existing
    routes.

    The API key is consumed to build an in-memory `ProviderConfig` and
    is never persisted, logged, or returned.
    """
    body = body_object(request)
    mission_id = _active_mission_id(config, body)

    # (1) MODEL AUTHORIZATION — before any provider work.
    #
    # `require_audit_allowed_model` is the ONLY gate: it validates the
    # vendor-stripped base id and raises for anything unapproved. The
    # value actually sent to the provider is the operator's own id,
    # unmodified, because providers key on the full `vendor/model`
    # string (OpenRouter serves `meta/muse-spark-1.3`, not
    # `muse-spark-1.3`). Validation strips; dispatch does not.
    requested_model = _text(body, "model")
    try:
        approved_model = api.require_audit_allowed_model(requested_model)
    except ValueError as exc:
        raise errors.invalid_input(str(exc)) from None

    host = _text(body, "host")
    store = _store(config)
    profile = None
    try:
        profile = store.get_target(mission_id)
    except Exception:  # noqa: BLE001 - fall through to a fresh declaration
        profile = None
    if profile is None and host:
        try:
            profile = build_target_profile(
                mission_id=mission_id,
                locator=host,
                allowed_ports=_text(body, "port_spec"),
                allowed_protocols=(_text(body, "protocols")
                                   or _text(body, "protocol")),
                authorization_ref=(_text(body, "authorization_ref")
                                   or "operator-declared"),
                platform=_text(body, "platform") or DEFAULT_PLATFORM,
                environment=_text(body, "environment") or None,
                stage=TARGET_STAGE_AUTHORIZED,
            )
        except TargetProfileError as exc:
            raise errors.invalid_input(str(exc)) from None
        store.set_target(profile)
    if profile is None:
        raise errors.invalid_input(
            "no authorized target: declare one on /agent first, or send "
            "host + port_spec + protocols with this request")

    # (3) Provider construction — only after the model is authorized.
    try:
        model = api.make_model_adapter(
            _text(body, "provider") or "openai-compatible",
            api_key=_text(body, "api_key") or None,
            endpoint=_text(body, "endpoint") or None,
            model=requested_model or None)
    except ProviderConfigError as exc:
        raise errors.ApiError(503, errors.MODEL_NOT_CONFIGURED,
                              str(exc)) from None

    # The declared SSH session (if any) becomes the mission's session
    # shape, so the governed loop can propose `network-ssh-session`
    # actions and Policy can check each command against it.
    ssh_state = store.get_ssh_session(mission_id)
    problem: Dict[str, Any] = {}
    if ssh_state:
        problem["ssh"] = dict(ssh_state)

    mission = Mission(
        mission_id=mission_id,
        description=_text(body, "description")
        or f"governed assessment of {profile.locator}",
        scope=profile.scope,
        criteria=["service-discovery"],
        problem=problem,
    )
    session = api.create_session(
        mission=mission,
        workspace_root=_workspace_root(config, body),
        project_name=mission_id,
        # Record the AUTHORIZED model id (or the server-environment
        # sentinel) so the console shows what actually ran. Names only.
        model=approved_model or "server-environment",
        provider=_text(body, "provider") or "openai-compatible",
        sessions_root=config.sessions_root)
    result = api.start_model_run(
        session, mission=mission, model=model,
        max_turns=_max_turns(body),
        sessions_root=config.sessions_root,
        runs_root=config.runs_root,
        target_store=store)
    return Response(200, view.redirect_page(
        f"/agent?run={result.run.run_id}",
        note=f"Run {result.run.run_id}: {result.turns} governed turn(s), "
             f"terminal={result.terminal}."),
        content_type=view.HTML)


def _ssh_bound(body, key, default, ceiling):
    """Read an operator bound, clamped to the hard ceiling."""
    raw = body.get(key)
    if raw in (None, ""):
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return default
    if value <= 0:
        return default
    return min(value, ceiling)


def set_ssh_session(request, params, config):
    """POST /agent/ssh-session — declare the governed SSH session shape.

    Records what the operator authorizes: target, protocol, credential
    REFERENCE, allow-listed commands, and safety bounds. It authorizes
    nothing by itself — every command still crosses Runtime -> Broker ->
    Policy at execution time.

    There is deliberately no password field. The credential is a vault
    id; plaintext never enters this request, the mission, the ledger,
    or any response.
    """
    body = body_object(request)
    target = _text(body, "target")

    if not target:
        raise errors.invalid_input("target is required")
    try:
        parsed = parse_ssh_target(target)
    except NetworkScopeError as exc:
        raise errors.invalid_input(str(exc)) from None
    if _text(body, "protocol") not in ("", "ssh"):
        raise errors.invalid_input("only the ssh protocol is supported")
    commands = [part.strip() for part in _text(body, "commands").split(",")
                if part.strip()]
    if not commands:
        raise errors.invalid_input(
            "at least one authorized command is required")
    mission_id = _active_mission_id(config, body)
    credential = _text(body, "credential_secret")
    credential_id = _text(body, "credential_id")
    if credential:
        # The secret is accepted here, moved straight into the
        # process-local vault, and never rendered, logged, persisted or
        # echoed. Only the generated reference id is returned to the UI.
        vault = _vault(config)
        reference = vault.store(
            "ssh_password", credential, parsed.host,
            CredentialProvenance.PROVIDED)
        vault.mark_validated(reference.credential_id, parsed.host, "ssh")
        vault.authorize(reference.credential_id, parsed.host, "ssh")
        credential_id = reference.credential_id

    session = {
        "mission_id": mission_id,
        "target": parsed.url,
        "host": parsed.host,
        "port": parsed.port,
        "protocol": "ssh",
        "username": _text(body, "username"),
        "credential_id": credential_id,
        "commands": commands,
        "command_timeout_seconds": _ssh_bound(
            body, "command_timeout_seconds", 15.0, 120.0),
        "stdout_limit": int(_ssh_bound(body, "stdout_limit", 8192, 65536)),
        "stderr_limit": int(_ssh_bound(body, "stderr_limit", 4096, 16384)),
        "host_key_policy": _text(body, "host_key_policy") or "strict",
    }
    _store(config).set_ssh_session(mission_id, session)
    # Redirect to the console so the operator SEES the declared session,
    # the same way the start form does. A raw JSON body after a form POST
    # is not a usable console.
    return Response(200, view.redirect_page(
        "/agent", note="SSH session declared."), content_type=view.HTML)




# ---------------------------------------------------------------------------
# Chat console
# ---------------------------------------------------------------------------
#
# The chat is an interaction layer over the SAME governed path the console
# already used. A message is context: it is folded into the ModelContext the
# model already receives, and the model still returns an ordinary
# ActionRequest that travels Runtime -> Broker -> Policy. There is
# deliberately no "execute this because the operator said so" branch here.


def _chat_mission(config, body: Dict[str, Any]) -> str:
    """The mission a chat message belongs to."""
    mission_id = _active_mission_id(config, body)
    if not mission_id:
        raise errors.invalid_input(
            "mission_id is required: declare a target on /agent first")
    return mission_id


def _chat_turns_from_timeline(timeline: Optional[Dict[str, Any]]
                              ) -> Tuple[List[dict], List[dict]]:
    """Split a persisted timeline into chat rows.

    Read-only projection of what the governed loop actually recorded. The
    ledger remains authoritative; this only re-shapes it for the transcript.
    """
    actions: List[dict] = []
    observations: List[dict] = []
    for turn in (timeline or {}).get("turns") or ():
        if not isinstance(turn, dict):
            continue
        actions.append({
            "turn_index": turn.get("index"),
            "capability": (turn.get("proposal") or {}).get("capability"),
            "target": (turn.get("proposal") or {}).get("target"),
            "rationale": turn.get("rationale") or "",
            "policy": turn.get("policy") or {},
            "execution": turn.get("execution") or {},
            "evidence": turn.get("evidence") or {},
        })
        record = view._discovery_record(turn.get("observation"))
        if record:
            observations.append({
                "host": record.get("host"),
                "ports_probed": record.get("ports_probed"),
                "capped": record.get("capped"),
                "exhaustive": record.get("exhaustive"),
                "open_ports": [entry.get("port")
                               for entry in (record.get("open_services") or [])],
            })
    return actions, observations


def chat(request, params, config):
    """GET /agent/chat — the mission transcript and its stop state."""
    body = {k: v[0] for k, v in (request.query or {}).items()}
    mission_id = _chat_mission(config, body)
    try:
        payload = api.read_chat(mission_id, config.runs_root)
    except ValueError as exc:
        raise errors.invalid_input(str(exc)) from None
    return dict(payload, run_state=(
        "stopped" if payload["stopped"] else "idle"))


def message(request, params, config):
    """POST /agent/message — one governed turn in response to the operator.

    The single most important property of this route is what it does NOT
    do: it never executes a capability, never touches the Broker, and
    never interprets the operator's text as a privileged command. It
    delegates to `api.start_chat_turn`, which runs the ordinary governed
    loop for a single turn.
    """
    body = body_object(request)
    mission_id = _chat_mission(config, body)
    text = _text(body, "message")
    if not text:
        raise errors.invalid_input("message is required")

    try:
        log = api.chat_log(config.runs_root, mission_id)
    except ValueError as exc:
        raise errors.invalid_input(str(exc)) from None
    if log.is_stopped():
        raise errors.conflict(
            "MISSION_STOPPED",
            "mission is stopped: no further model turns or capability "
            "execution until it is resumed")

    log.append_operator(text, run_id=_text(body, "run_id"))

    # (1) MODEL AUTHORIZATION — identical gate to /agent/start. A rejected
    # model never reaches a provider, the Broker, or Policy.
    requested_model = _text(body, "model")
    try:
        approved_model = api.require_audit_allowed_model(requested_model)
    except ValueError as exc:
        raise errors.invalid_input(str(exc)) from None

    store = _store(config)
    try:
        profile = store.get_target(mission_id)
    except Exception:  # noqa: BLE001 — no declared target for this mission
        profile = None
    if profile is None:
        raise errors.invalid_input(
            f"no authorized target declared for mission {mission_id}")

    # (2) Provider construction — only after the model is authorized.
    try:
        model_adapter = api.make_model_adapter(
            _text(body, "provider") or "openai-compatible",
            api_key=_text(body, "api_key") or None,
            endpoint=_text(body, "endpoint") or None,
            model=requested_model or None)
    except ProviderConfigError as exc:
        raise errors.ApiError(503, errors.MODEL_NOT_CONFIGURED,
                              str(exc)) from None

    ssh_state = store.get_ssh_session(mission_id)
    problem: Dict[str, Any] = {"ssh": dict(ssh_state)} if ssh_state else {}
    mission = Mission(
        mission_id=mission_id,
        description=_text(body, "description")
        or f"governed assessment of {profile.locator}",
        scope=profile.scope,
        criteria=["service-discovery"],
        problem=problem,
    )
    session = api.create_session(
        mission=mission,
        workspace_root=_workspace_root(config, body),
        project_name=mission_id,
        model=approved_model or "server-environment",
        provider=_text(body, "provider") or "openai-compatible",
        sessions_root=config.sessions_root)

    result = api.start_chat_turn(
        session, mission, model=model_adapter, message=text,
        runs_root=config.runs_root,
        sessions_root=config.sessions_root,
        target_store=store)

    actions, observations = _chat_turns_from_timeline(result["timeline"])
    _record_chat_turns(log, result, actions, observations, config)
    return {
        "run_id": result["run_id"],
        "state": result["state"],
        "terminal": result["terminal"],
        "gate_verdict": result["gate_verdict"],
        "turns": result["turns"],
        "messages": log.to_list(),
    }


def _latest_discovery(config, run_id: str) -> Optional[Dict[str, Any]]:
    """The discovery result this run's LEDGER actually recorded.

    A turn's `observation` is what the model saw BEFORE it acted, so it
    can never report the result of its own action. This reads the run's
    own evidence ledger instead and normalises the latest record produced
    by network service discovery into what the transcript displays:

        {"host": str, "open_ports": [...], "ports_probed": int,
         "capped": bool}

    Fail-closed, exactly like `view._discovery_record`. An absent run, an
    absent or unreadable ledger, a record for another run, a malformed
    record, or a record whose required fields cannot be established all
    yield None, and the transcript then says "no evidence produced".
    Discovery is never reconstructed from the model's belief.
    """
    if not run_id:
        return None
    try:
        ledger = find_run_dir(Path(config.runs_root), run_id) / "evidence.jsonl"
    except (OSError, ValueError):
        return None
    try:
        lines = ledger.read_text(encoding="utf-8").splitlines()
    except (OSError, ValueError):
        return None

    latest: Optional[Dict[str, Any]] = None
    latest_key: Tuple[int, int] = (-1, -1)
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        payload = record.get("payload")
        if not isinstance(payload, dict):
            continue
        if payload.get("capability") != "network_service_discovery":
            continue
        found = payload.get("discovery_result")
        if not isinstance(found, dict):
            continue
        recorded = found.get("run_id")
        if isinstance(recorded, str) and recorded and recorded != run_id:
            continue
        host = found.get("host")
        open_ports = found.get("ports_open")
        ports_probed = found.get("ports_probed")
        capped = found.get("capped")
        if not isinstance(host, str) or not host:
            continue
        if not isinstance(open_ports, (list, tuple)):
            continue
        if not isinstance(ports_probed, int) or isinstance(ports_probed, bool):
            continue
        if not isinstance(capped, bool):
            continue
        ts = record.get("ts")
        seq = record.get("seq")
        key = (ts if isinstance(ts, int) else 0,
               seq if isinstance(seq, int) else 0)
        if key >= latest_key:
            latest_key = key
            latest = {"host": host,
                      "open_ports": list(open_ports),
                      "ports_probed": ports_probed,
                      "capped": capped}
    return latest


def _record_chat_turns(log, result: Dict[str, Any],
                       actions: List[dict],
                       observations: List[dict], config) -> None:
    """Append the governed outcome of a turn to the transcript."""
    run_id = result.get("run_id", "")
    if result.get("terminal") == "model-error":
        log.append_event(
            f"MODEL ERROR: {result.get('terminal_reason', '')[:200]}",
            message_type="model_error", run_id=run_id)
    for action in actions:
        policy = action.get("policy") or {}
        execution = action.get("execution") or {}
        evidence = action.get("evidence") or {}
        evidence_ids = evidence.get("evidence_ids") or []
        capability = action.get("capability") or "unknown"
        log.append_event(
            f"{capability} on {action.get('target') or 'the authorized target'}",
            message_type="action", run_id=run_id,
            turn_index=action.get("turn_index"),
            evidence_ids=evidence_ids,
            detail={"capability": capability,
                    "target": action.get("target"),
                    "rationale": action.get("rationale")})
        log.append_event(
            f"{str(policy.get('decision', 'n/a')).upper()}"
            + (f" — {policy.get('reason')}" if policy.get("reason") else ""),
            message_type="policy", run_id=run_id,
            turn_index=action.get("turn_index"),
            detail={"decision": policy.get("decision"),
                    "reason": policy.get("reason")})
        if execution.get("executed"):
            log.append_event(
                ("Completed" if execution.get("success")
                 else f"Failed: {execution.get('error') or 'no detail'}"),
                message_type="execution", run_id=run_id,
                turn_index=action.get("turn_index"),
                evidence_ids=evidence_ids)
        # Evidence the turn PRODUCED. A turn's `observation` is what the
        # model saw BEFORE it acted, so it cannot report the result of its
        # own action. Read what the ledger actually recorded for this run
        # instead: the ports below are the ones discovery really reported,
        # not a projection of the model's prior belief.
        produced = _latest_discovery(config, run_id) if run_id else None
        if produced:
            body = (f"{produced.get('host')}: "
                    + (", ".join(str(p) for p in produced.get("open_ports") or [])
                       or "no open ports in the swept range")
                    + f" (probed {produced.get('ports_probed')}"
                    + (", capped" if produced.get("capped") else "")
                    + ")")
        elif evidence_ids:
            body = f"{len(evidence_ids)} record(s) written to the ledger"
        else:
            body = "no evidence produced"
        log.append_event(
            body, message_type="evidence", run_id=run_id,
            turn_index=action.get("turn_index"),
            evidence_ids=evidence_ids,
            detail=dict(produced or {}, excerpt=str(
                evidence.get("excerpt") or "")[:300]))


def stop(request, params, config):
    """POST /agent/stop — end the mission's governed chat.

    A real server-side gate: after this, `/agent/message` refuses, so no
    new model turn and no new capability execution can begin. The
    synchronous runtime cannot cancel a turn already in flight without
    unsafe concurrency, so the gate applies from the next turn boundary;
    that limit is documented rather than papered over.
    """
    body = body_object(request)
    mission_id = _chat_mission(config, body)
    try:
        status = api.stop_chat(mission_id, config.runs_root)
    except ValueError as exc:
        raise errors.invalid_input(str(exc)) from None
    return dict(status, run_state="stopped")


def resume(request, params, config):
    """POST /agent/resume — clear the stop gate."""
    body = body_object(request)
    mission_id = _chat_mission(config, body)
    try:
        status = api.resume_chat(mission_id, config.runs_root)
    except ValueError as exc:
        raise errors.invalid_input(str(exc)) from None
    return dict(status, run_state="idle")


__all__ = ["DEFAULT_ENVIRONMENT", "DEFAULT_PLATFORM", "DEFAULT_UI_TURNS",
           "MAX_UI_TURNS", "chat", "console", "message", "resume",
           "set_ssh_session", "set_target", "start", "stop", "timeline"]
