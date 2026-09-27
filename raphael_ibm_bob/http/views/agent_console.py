"""raphael_ibm_bob.http.views.agent_console — AI agent operator console.

The screen a user opens to run the vertical slice end to end:

    1. configure the AI provider (provider / model / endpoint / key)
    2. declare the authorized target
    3. start the agent
    4. watch every governed turn: observation -> proposal -> policy
       decision -> execution -> evidence -> next action

Presentation only. This module holds no execution authority: it
renders persisted run state plus a form whose POST is handled by
`routes/agent.py`, which delegates to `harness.api`.

Credential discipline:

- The API key is a write-only password field. It is never rendered
  back into HTML, never placed in a URL, and never included in any
  response body. The only thing the page can say about it is
  `api_key: "set" | "unset"`, sourced from `ProviderConfig.redacted()`.
- The model/provider shown are *names*, matching the session record
  convention: a reference, never a secret.

The turn list shows the model's own one-line action rationale (the
`purpose` field of its structured proposal). No chain-of-thought is
requested, stored, or displayed: the provider contract asks for a
single compact JSON object.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from raphael_ibm_bob.harness import api
from raphael_ibm_bob.http.views import agent_chat as ac
from raphael_ibm_bob.http.views import decision_trace as dt
from raphael_ibm_bob.target_profile import PLATFORM_SPECS

HTML = "text/html; charset=utf-8"

_EXTRA_CSS = """
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media (max-width:1100px){.grid2{grid-template-columns:1fr}}
.panel.agent{border-color:rgba(91,127,224,.35)}
.agentform{display:grid;gap:10px}
.agentform label{display:grid;gap:4px;font-size:11px;color:var(--muted);
text-transform:uppercase;letter-spacing:.05em}
.agentform input,.agentform select{font:inherit;background:var(--bg);
color:var(--text);border:1px solid var(--border);border-radius:3px;
padding:7px 9px;width:100%}
.btn{font:inherit;font-size:11px;letter-spacing:.08em;text-transform:uppercase;
background:var(--panel2);color:var(--text);border:1px solid var(--border);
border-radius:3px;padding:8px 16px;cursor:pointer}
.btn:hover{border-color:var(--primary)}
.hint{color:var(--muted);font-size:11px;line-height:1.5;margin:0}
.fieldstat{font-size:10px;color:var(--sec);letter-spacing:.05em}
.kv{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;font-size:12px}
.kv dt{color:var(--muted);text-transform:uppercase;font-size:10px;
letter-spacing:.05em}
.kv dd{margin:0;font-family:'JetBrains Mono',ui-monospace,monospace;
word-break:break-all}
.turn{border:1px solid var(--border);border-radius:4px;padding:10px 12px;
margin-bottom:10px;background:var(--panel)}
.turn h4{margin:0 0 8px;font-size:12px;letter-spacing:.08em;
text-transform:uppercase;color:var(--primary)}
.stage{display:grid;grid-template-columns:96px 1fr;gap:4px 10px;
font-size:11.5px;margin-bottom:4px}
.stage .lbl{color:var(--muted);text-transform:uppercase;font-size:10px;
letter-spacing:.06em;padding-top:1px}
.stage .val{font-family:'JetBrains Mono',ui-monospace,Menlo,Consolas,
monospace;word-break:break-word}
.badge{display:inline-block;padding:1px 7px;border-radius:9px;font-size:10px;
letter-spacing:.06em;text-transform:uppercase;border:1px solid var(--border)}
.badge.allow{color:var(--ok);border-color:rgba(53,183,122,.45)}
.badge.deny{color:var(--crit);border-color:rgba(211,79,97,.45)}
.badge.warn{color:var(--warn);border-color:rgba(215,160,68,.45)}
.pill{display:inline-block;padding:1px 7px;border-radius:9px;font-size:10px;
background:var(--panel2);border:1px solid var(--border);margin:0 4px 4px 0}
.final{border:1px solid var(--border);border-radius:4px;padding:10px 12px;
background:var(--panel2)}
.final .verdict{font-size:14px;letter-spacing:.1em;text-transform:uppercase}
"""


def _shell(title: str, body: str) -> str:
    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, "
        "initial-scale=1\">"
        f"<title>{dt._e(title)}</title>"
        f"<style>{dt._CSS}{_EXTRA_CSS}{ac.CHAT_CSS}</style></head><body>"
        '<header class="cmdbar"><span class="brand">RAPHAEL</span>'
        '<span class="screen">AI Agent</span>'
        '<span class="banner">GOVERNED · MODEL PROPOSES ONLY</span>'
        '<span class="spacer"></span><span class="led ok"></span></header>'
        f"<main>{body}"
        '<p class="readonly">The model proposes. Raphael decides. '
        'Runtime &rarr; Broker &rarr; Policy &rarr; Capability &rarr; '
        'Evidence is the ONLY execution path.</p></main>'
        '<footer class="policystrip mono">POLICY: FAIL-CLOSED · GATE: '
        'QUALITY · NO DIRECT MODEL&rarr;TOOL EXECUTION</footer>'
        "</body></html>")


# ---------------------------------------------------------------------------
# Form
# ---------------------------------------------------------------------------

def _provider_options() -> List[str]:
    try:
        return api.available_providers()
    except Exception:  # noqa: BLE001 - a UI must never 500 on config
        return []


def _provider_select(provider_ids: List[str], selected: str = "") -> str:
    """Provider `<select>`, marking the current selection."""
    options = []
    for provider_id in provider_ids:
        mark = " selected" if provider_id == selected else ""
        options.append(f'<option value="{dt._e(provider_id)}"{mark}>'
                       f'{dt._e(provider_id)}</option>')
    return "".join(options) or '<option value="">none</option>'


def _model_input(selected: str = "") -> str:
    """Model id field restricted by SUGGESTION; enforced by the server.

    A closed `<select>` cannot express the `vendor/model` form that
    real providers key on (OpenRouter serves `meta/muse-spark-1.3`, not
    the bare base id), and the audit allow-list explicitly admits that
    form by stripping the vendor prefix. So this is a text input with a
    datalist of the approved ids.

    The datalist is a convenience only. `api.require_audit_allowed_model`
    re-checks every submission on the server before any provider is
    contacted, so a hand-typed id cannot widen what runs.
    """
    approved = list(api.AUDIT_ALLOWED_MODEL_LABELS.items())
    default = selected or (approved[0][0] if approved else "")
    options = "".join(
        f'<option value="{dt._e(mid)}">{dt._e(label)}</option>'
        for mid, label in approved)
    return ('<label>MODEL (audit allow-list)'
            f'<input name="model" list="agent-models" '
            f'value="{dt._e(default)}" autocomplete="off">'
            f'<datalist id="agent-models">{options}</datalist>'
            '<span class="fieldstat">approved ids only; a '
            '<code>vendor/</code> prefix is allowed</span></label>')


def _endpoint_input(state: Dict[str, Any]) -> str:
    """API endpoint field, pre-filled from the server environment."""
    return ('<label>API ENDPOINT<input name="endpoint" '
            f'value="{dt._e(state.get("endpoint") or "")}" '
            'placeholder="https://openrouter.ai/api/v1" '
            'autocomplete="off"></label>')


def _key_input(state: Dict[str, Any]) -> str:
    """Write-only credential field.

    `type="password"`, no `value` attribute is ever rendered, and the
    only state shown is whether a key was supplied. The submitted value
    exists solely in the POST body, is turned into an in-memory
    `ProviderConfig`, and is then dropped.
    """
    key_state = "set for this run" if state.get("api_key") == "set" \
        else "unset (server environment)"
    return ('<label>API KEY<input name="api_key" type="password" '
            'placeholder="leave blank to use the server environment" '
            'autocomplete="off">'
            f'<span class="fieldstat">current: {dt._e(key_state)}</span>'
            '</label>')


def _platform_select(selected: str) -> str:
    """Target platform selector, sourced from the canonical registry.

    The option list is derived from `target_profile.PLATFORM_SPECS`, so
    the UI cannot drift from what the backend will accept. The operator's
    choice is authoritative input: nothing here infers a platform from a
    hostname or address, and normal `TargetProfile` validation still runs
    after submission.
    """
    chosen = (selected or "").strip().lower()
    options = []
    for spec in PLATFORM_SPECS:
        mark = " selected" if spec.name == chosen else ""
        options.append(f'<option value="{dt._e(spec.name)}"{mark}>'
                       f'{dt._e(spec.name.upper())}</option>')
    return "".join(options)


def _provider_form(provider_state: Dict[str, Any],
                   provider_ids: List[str]) -> str:
    state = provider_state or {}
    return f"""
<form class="agentform" method="post" action="/agent/start">
  <div class="grid2">
    <label>PROVIDER<select name="provider">
      {_provider_select(provider_ids, state.get("provider") or "")}
    </select></label>
    {_model_input(state.get("model") or "")}
    {_endpoint_input(state)}
    {_key_input(state)}
  </div>
  <p class="hint">Only the audit-approved models are accepted, and the
  server re-checks every submission <em>before</em> any provider is
  contacted. The key is used for this run only: it is never printed,
  logged, persisted in plaintext, or sent back to this page &mdash; the
  only thing Raphael reports is whether one was supplied. Raphael reads
  <code>RAPHAEL_MODEL_*</code> from the server environment when these
  fields are blank.</p>
</form>
"""


def _target_form(target: Optional[Dict[str, Any]],
                 mission_id: str) -> str:
    if not target:
        return ('<p class="hint">No authorized target declared. A target is '
                'required before any governed network action can be '
                'authorized.</p>')
    rows = "".join(
        f"<dt>{dt._e(k)}</dt><dd>{dt._e(v)}</dd>" for k, v in target.items())
    return f'<dl class="kv">{rows}</dl>'


def _port_spec(target: Optional[Dict[str, Any]]) -> str:
    """Comma-joined authorized ports for the target form."""
    return ",".join(str(p) for p in (target or {}).get("allowed_ports") or ())


def _protocols(target: Optional[Dict[str, Any]]) -> str:
    """Comma-joined authorized protocols for the target form."""
    return ",".join((target or {}).get("allowed_protocols") or ())


# ---------------------------------------------------------------------------
# Run rendering
# ---------------------------------------------------------------------------

def _stage(label: str, value: Any, *, raw: bool = False) -> str:
    """One labelled stage row. `raw=True` marks pre-rendered HTML."""
    if value in (None, "", [], {}):
        return ""
    body = value if raw else dt._e(value)
    return (f'<div class="stage"><span class="lbl">{dt._e(label)}</span>'
            f'<span class="val">{body}</span></div>')


def _pills(values: Any) -> str:
    if not values:
        return ""
    return "".join(f'<span class="pill">{dt._e(v)}</span>'
                   for v in values)


def _decision_badge(decision: str) -> str:
    css = {"allow": "allow", "deny": "deny"}.get(decision, "warn")
    return f'<span class="badge {css}">{dt._e(str(decision).upper())}</span>'


def _render_turn(turn: Dict[str, Any]) -> str:
    observation = turn.get("observation") or {}
    proposal = turn.get("proposal") or {}
    policy = turn.get("policy") or {}
    execution = turn.get("execution") or {}
    evidence = turn.get("evidence") or {}

    services = _pills(observation.get("services_known"))
    latest = observation.get("latest") or {}
    untrusted = ('<span class="badge warn">provider untrusted</span>'
                 if evidence.get("provider_untrusted") else "")

    body = "".join([
        _stage("observes", services or "no services observed yet", raw=True),
        _stage("known", (f"{len(observation.get('services_known') or [])}"
                         f" port(s); {observation.get('observation_count', 0)}"
                         " observation(s) folded from the ledger")),
        _stage("proposes", f"{dt._e(proposal.get('capability', 'intent'))}"
                           f" &rarr; {dt._e(proposal.get('target', ''))}",
               raw=True),
        _stage("rationale", turn.get("rationale", "")),
        _stage("policy", f"{_decision_badge(policy.get('decision', '?'))} "
                         f"{dt._e(policy.get('reason', ''))}", raw=True),
        _stage("executes", (f"invoked={execution.get('executed')} "
                            f"success={execution.get('success')} "
                            f"error={execution.get('error') or '-'}").strip()),
        _stage("evidence", ", ".join(evidence.get("evidence_ids") or [])
               or "none"),
        _stage("observed", latest.get("ports_open") or "no open ports"),
        _stage("next", turn.get("next_action", "")),
    ])
    return (f'<div class="turn"><h4>Turn {dt._e(turn.get("index", 0))} '
            f'{untrusted}</h4>{body}</div>')


def _render_run(run_id: str, timeline: Optional[Dict[str, Any]],
                gate: Optional[Dict[str, Any]],
                model_ref: Optional[Dict[str, str]] = None) -> str:
    if not timeline:
        return ('<p class="hint">No governed-loop timeline recorded for '
                f'run <code>{dt._e(run_id)}</code>.</p>')
    turns = timeline.get("turns") or []
    rendered = "".join(_render_turn(t) for t in turns) or (
        '<p class="hint">The loop recorded no turns.</p>')
    verdict = (gate or {}).get("verdict") or timeline.get("gate_verdict") \
        or "n/a"
    css = "allow" if str(verdict).lower() == "complete" else "warn"
    ref = model_ref or {}
    return f"""
<div class="final">
  <div class="verdict"><span class="badge {css}">{dt._e(verdict)}</span></div>
  <dl class="kv">
    <dt>provider</dt><dd>{dt._e(ref.get('provider', 'unknown'))}</dd>
    <dt>model</dt><dd>{dt._e(ref.get('model', 'unknown'))}</dd>
    <dt>run</dt><dd>{dt._e(run_id)}</dd>
    <dt>terminal</dt><dd>{dt._e(timeline.get('terminal'))}</dd>
    <dt>reason</dt><dd>{dt._e(timeline.get('terminal_reason') or '-')}</dd>
    <dt>turns</dt><dd>{len(turns)}</dd>
  </dl>
  <p class="hint">The QualityGate alone emits COMPLETE or REFUSE. A model
  can neither declare completion nor skip the Broker.</p>
</div>
{rendered}
"""


# ---------------------------------------------------------------------------
# Page


def _ssh_panel(session: Optional[Dict[str, Any]]) -> str:
    """Governed SSH session state. Never renders a credential.

    Everything shown is an operator-declared name, a bound, or a ledger
    reference. The credential appears only as a reference id — the
    vault holds plaintext and this view never sees it.
    """
    if not session:
        return ('<p class="hint">No SSH session declared. A session needs '
                'a target, an authorized port, the <code>ssh</code> '
                'protocol, a credential reference, and the exact '
                'commands the mission authorizes.</p>')
    rows = "".join(
        f"<dt>{dt._e(k)}</dt><dd>{dt._e(v)}</dd>"
        for k, v in session.items() if not k.startswith("_"))
    return f'<dl class="kv">{rows}</dl>'


def _ssh_form(state: Optional[Dict[str, Any]]) -> str:
    """Configure the session the Broker will authorize.

    The command list is an operator allow-list, not a suggestion: the
    command-policy layer refuses anything outside it and refuses shell
    chaining and interpreter indirection outright. The credential is a
    REFERENCE into the process-local vault; no field here accepts or
    displays a password.
    """
    cfg = state or {}
    return f"""
<form class="agentform" method="post" action="/agent/ssh-session">
  <div class="grid2">
    <label>TARGET (ssh://host:port)<input name="target" required
      value="{dt._e(cfg.get('target', ''))}"
      placeholder="ssh://127.0.0.1:22" autocomplete="off"></label>
    <label>PROTOCOL<input name="protocol" value="ssh" readonly></label>
    <label>USERNAME<input name="username"
      value="{dt._e(cfg.get('username', ''))}" autocomplete="off"></label>
    <label>CREDENTIAL REFERENCE<input name="credential_id"
      value="{dt._e(cfg.get('credential_id', ''))}"
      placeholder="vault id (never a password)" autocomplete="off"></label>
    <label>AUTHORIZED COMMANDS<input name="commands" required
      value="{dt._e(', '.join(cfg.get('commands') or ()))}"
      placeholder="ls, id" autocomplete="off"></label>
    <label>COMMAND TIMEOUT (s)<input name="command_timeout_seconds"
      type="number" min="1" max="120"
      value="{dt._e(cfg.get('command_timeout_seconds', 15))}"></label>
    <label>STDOUT LIMIT<input name="stdout_limit" type="number" min="1"
      max="65536" value="{dt._e(cfg.get('stdout_limit', 8192))}"></label>
    <label>STDERR LIMIT<input name="stderr_limit" type="number" min="1"
      max="16384" value="{dt._e(cfg.get('stderr_limit', 4096))}"></label>
    <label>CREDENTIAL REFERENCE<input name="credential_id"
      value="{dt._e(cfg.get('credential_id', ''))}"
      placeholder="set automatically when a secret is entered"
      autocomplete="off"></label>
    <label>CREDENTIAL SECRET<input name="credential_secret" type="password"
      placeholder="optional: stored in the vault, never shown again"
      autocomplete="off">
      <span class="fieldstat">write-only: never rendered, logged, or
      persisted</span></label>
  </div>
  <p class="hint">One ActionRequest runs at most ONE command and the
  session is always closed. Shell chaining, redirection, substitution
  and <code>sh -c</code>/<code>bash -c</code> indirection are refused by
  policy, not merely discouraged. The credential reference is resolved
  inside the vault at execution time and never leaves it.</p>
  <div><button class="btn" type="submit">Declare SSH session</button></div>
</form>
"""
# ---------------------------------------------------------------------------

def render(run_id: str = "",
           provider_state: Optional[Dict[str, Any]] = None,
           target: Optional[Dict[str, Any]] = None,
           timeline: Optional[Dict[str, Any]] = None,
           gate: Optional[Dict[str, Any]] = None,
           model_ref: Optional[Dict[str, str]] = None,
           ssh_session: Optional[Dict[str, Any]] = None,
           ssh_state: Optional[Dict[str, Any]] = None,
           chat_messages: Optional[List[Dict[str, Any]]] = None,
           chat_stopped: bool = False,
           chat_stopped_reason: str = "",
           run_state: str = "idle",
           turn: int = 0,
           max_turns: int = 0,
           error: str = "") -> str:
    """Render the agent console: mission controls, chat, live evidence.

    The three regions are a PRESENTATION arrangement only. Every control
    that governed the loop before the chat existed still posts to the
    same route it always did, and the chat form posts to /agent/message,
    which runs the same Runtime -> Broker -> Policy path.
    """
    providers = _provider_options()
    state = dict(provider_state or {})
    mission_id = (target or {}).get("mission_id", "")
    notice = (f'<p class="badge deny">{dt._e(error)}</p>' if error else "")
    return _shell("AI Agent", f"""
<h1>AI SECURITY AGENT</h1>
{ac.mission_header(target=target,
                   provider=state.get("provider", "") or "openai-compatible",
                   model=state.get("model", "") or "not configured",
                   run_id=run_id, run_state=run_state, turn=turn,
                   max_turns=max_turns)}
{notice}
<div class="chatgrid">
  <div class="cpanel cmission" aria-label="Mission and scope">
  <div class="sublabel">MISSION &amp; SCOPE</div>
  <details open><summary class="msgsummary">Configure &amp; start</summary>
  <div class="abody">
  <div class="grid2">
  <section class="panel agent">
    <div class="sublabel">1 &middot; MODEL PROVIDER</div>
    {_provider_form(state, providers)}
  </section>
  <section class="panel">
    <div class="sublabel">2 &middot; AUTHORIZED TARGET</div>
    {_target_form(target, mission_id)}
    <form class="agentform" method="post" action="/agent/target"
          style="margin-top:10px">
      <label>MISSION ID<input name="mission_id" required
        value="{dt._e(mission_id or 'M-AGENT-001')}"
        autocomplete="off"></label>
      <label>TARGET HOST / IP<input name="host" required
        value="{dt._e((target or {}).get('locator', ''))}"
        placeholder="127.0.0.1 (host only, no port)" autocomplete="off"></label>
      <label>AUTHORIZED PORTS<input name="port_spec" required
        value="{dt._e(_port_spec(target))}"
        placeholder="8080 or 1-1024" autocomplete="off"></label>
      <label>AUTHORIZED PROTOCOLS<input name="protocols" required
        value="{dt._e(_protocols(target))}"
        placeholder="http" autocomplete="off"></label>
      <label>AUTHORIZATION REF<input name="authorization_ref" required
        value="{dt._e((target or {}).get('authorization_ref', 'local-lab'))}"
        autocomplete="off"></label>
      <label>PLATFORM<select name="platform">
        {_platform_select((target or {}).get('platform', 'htb'))}
      </select></label>
      <input type="hidden" name="environment" value="isolated-lab">
      <label>WORKSPACE ROOT<input name="workspace_root"
        value="{dt._e(state.get('workspace_root', ''))}"
        placeholder="path to a governed workspace" autocomplete="off"></label>
      <label>MAX TURNS<input name="max_turns" type="number" min="1" max="50"
        value="{dt._e(state.get('max_turns', 6))}"></label>
      <button class="btn" type="submit">Declare target</button>
    </form>
  </section>
</div>
<section class="panel" style="margin-top:14px">
  <div class="sublabel">3 &middot; START THE AGENT</div>
  <p class="hint">Starting a run submits every model proposal through
  Runtime &rarr; Broker &rarr; Policy. The model has no tool handle: it
  returns one action request per turn and Raphael decides whether it
  runs.</p>
  <form class="agentform" method="post" action="/agent/start">
    <div class="grid2">
      <label>PROVIDER<select name="provider">
        {_provider_select(providers, state.get("provider") or "")}
      </select></label>
      {_model_input(state.get("model") or "")}
      {_endpoint_input(state)}
      {_key_input(state)}
      <label>MISSION ID<input name="mission_id" required
        value="{dt._e(mission_id or 'M-AGENT-001')}" autocomplete="off"></label>
      <label>TARGET HOST / IP<input name="host"
        value="{dt._e((target or {}).get('locator', ''))}"
        placeholder="blank = use the declared target" autocomplete="off"></label>
      <label>AUTHORIZED PORTS<input name="port_spec"
        value="{dt._e(_port_spec(target))}"
        placeholder="blank = use the declared target" autocomplete="off"></label>
      <label>AUTHORIZED PROTOCOLS<input name="protocols"
        value="{dt._e(_protocols(target))}"
        placeholder="blank = use the declared target" autocomplete="off"></label>
      <label>AUTHORIZATION REF<input name="authorization_ref"
        value="{dt._e((target or {}).get('authorization_ref', 'local-lab'))}"
        autocomplete="off"></label>
      <label>MAX TURNS<input name="max_turns" type="number" min="1" max="50"
        value="{dt._e(state.get('max_turns', 6))}"></label>
      <label>PLATFORM<select name="platform">
        {_platform_select((target or {}).get('platform', 'htb'))}
      </select></label>
      <input type="hidden" name="environment" value="isolated-lab">
      <input type="hidden" name="workspace_root"
        value="{dt._e(state.get('workspace_root', ''))}">
    <div><button class="btn" type="submit">Start the agent</button></div>
  </section>
  <div class="sublabel" style="margin-top:12px">4 &middot; GOVERNED SSH SESSION</div>
  {_ssh_panel(ssh_session)}
  {_ssh_form(ssh_state)}
  </div></details>
  </div>
{ac.chat_panel(mission_id=mission_id, messages=chat_messages or [],
               stopped=chat_stopped, provider_state=state,
               stopped_reason=chat_stopped_reason)}
{ac.evidence_panel(timeline, gate, chat_messages=chat_messages)}
</div>
<section class="panel" style="margin-top:14px">
  <div class="sublabel">GOVERNED LOOP &middot; TIMELINE</div>
  {_render_run(run_id, timeline, gate, model_ref) if run_id else
   '<p class="hint">Start the agent, or send a chat message, to watch each '
   'governed turn.</p>'}
</section>
""")



def redirect_page(url: str, note: str = "") -> str:
    """Post-redirect landing body (mirrors operations_console.redirect_page)."""
    prefix = f"{dt._e(note)} " if note else ""
    return (f'<p class="note">{prefix}Agent run started. '
            f'<a class="row-link" href="{dt._e(url)}">Open agent console</a>'
            f'</p><meta http-equiv="refresh" content="0;url={dt._e(url)}">')


def timeline_json(timeline: Optional[Dict[str, Any]]) -> str:
    """Serialize a timeline for embedding in a page (defensive)."""
    return json.dumps(timeline or {}, sort_keys=True, default=str)


_discovery_record = ac._discovery_record


__all__ = ["HTML", "_discovery_record", "redirect_page", "render",
           "timeline_json"]
