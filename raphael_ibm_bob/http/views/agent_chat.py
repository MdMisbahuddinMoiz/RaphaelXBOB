"""raphael_ibm_bob.http.views.agent_chat — the governed agent chat console.

Presentation only. This module renders a mission transcript, the live
evidence the governed loop produced, and the form that posts an operator
message to `/agent/message`. It holds no execution authority: the form's
POST is handled by `routes/agent.py`, which delegates to `harness.api`
and therefore to the same Runtime -> Broker -> Policy path the non-chat
console has always used.

What the operator sees
----------------------
Each turn is shown as the chain it actually was — OBSERVE -> PROPOSE ->
POLICY -> EXECUTE -> EVIDENCE — with the model's own one-line action
rationale (the `purpose` field of its structured proposal). No
chain-of-thought is requested, stored, or rendered: the provider contract
asks for a single compact JSON object, and the console displays that
purpose verbatim and nothing more.

Credential discipline
----------------------
Operator text is the only free-form input in the system, so it is
redacted on the way in by `harness.chat.operator_message` before it is
stored, before it is rendered, and before it is handed to the provider.
This module additionally never renders a provider key, a credential
value, or anything derived from one.
"""
from __future__ import annotations

import html
import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

from raphael_ibm_bob.harness import chat as chat_state
from raphael_ibm_bob.http.views import decision_trace as dt

HTML = "text/html; charset=utf-8"


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


CHAT_CSS = """
/* --- governed agent chat ------------------------------------------- */
.chatgrid{display:grid;grid-template-columns:280px minmax(0,1fr) 320px;
gap:12px;align-items:start;margin-top:12px}
@media (max-width:1400px){.chatgrid{grid-template-columns:260px minmax(0,1fr)}}
@media (max-width:1100px){.chatgrid{grid-template-columns:1fr}}
@media (max-width:1100px){.chatgrid>.cpanel{order:0}}
@media (max-width:1100px){.chatgrid>.cmission{order:1}}
@media (max-width:1100px){.chatgrid>.cevidence{order:2}}
.cpanel{background:var(--panel);border:1px solid var(--border);
border-radius:5px;padding:12px;min-width:0}
.cmission .kv{margin:0}
.chatlog{display:flex;flex-direction:column;gap:8px;max-height:62vh;
overflow-y:auto;padding-right:4px;scroll-behavior:smooth}

/* --- 1080p layout ---------------------------------------------------
   The console forms predate the three-column layout. `.grid2` is a
   two-column form grid that only collapses at a 1100px VIEWPORT
   media query — but these forms now live inside a 280px sidebar on a
   1920px screen, so the query never fired and every field collapsed to
   roughly 60px wide. Scope the collapse to the sidebar itself rather
   than to the viewport, which is what the layout actually needs. */
.cmission .grid2{grid-template-columns:1fr;gap:10px}
.cmission .grid2>*{min-width:0}
.cmission input,.cmission select,.cmission textarea{
  width:100%;min-width:0;box-sizing:border-box}
.cmission label{display:block}

/* Keep the console inside one screen at 1080p. The mission column is a
   long configuration form; scrolling it internally beats a 3000px page
   that pushes the chat transcript below the fold. */
.cmission{max-height:calc(100vh - 210px);overflow-y:auto}
.cpanel.cchat{display:flex;flex-direction:column;
  max-height:calc(100vh - 210px)}
.cchat .chatlog{flex:1 1 auto;min-height:0;max-height:none}
.cchat .chatcompose{flex:0 0 auto}
.cpanel.cevidence{max-height:calc(100vh - 210px);overflow-y:auto}
.chatlog:focus-within{outline:1px solid var(--primary);outline-offset:2px}
.msg{border:1px solid var(--border);border-left-width:3px;border-radius:4px;
padding:8px 10px;background:var(--panel2);min-width:0}
.msg .mhead{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap;
margin-bottom:4px}
.msg .mrole{font-size:10px;letter-spacing:.09em;text-transform:uppercase;
color:var(--muted);font-weight:600}
.msg .mbody{font-size:13px;line-height:1.5;white-space:pre-wrap;
word-break:break-word}
.msg .mev{font-family:'JetBrains Mono',ui-monospace,monospace;font-size:10px;
color:var(--muted);margin-top:4px;word-break:break-all}
.msg-user{border-left-color:var(--primary)}
.msg-user .mrole{color:var(--primary)}
.msg-agent{border-left-color:var(--sec)}
.msg-action{border-left-color:#c08a2e}
.msg-policy{border-left-color:var(--sec)}
.msg-policy.deny{border-left-color:#c0483c}
.msg-execution{border-left-color:var(--muted)}
.msg-evidence{border-left-color:#3f8f6f}
.msg-model_error{border-left-color:#c0483c;background:rgba(192,72,60,.08)}
.msg-system{border-left-color:var(--muted);background:transparent}
.chatcompose{display:flex;gap:8px;margin-top:10px;align-items:flex-end}
.chatcompose textarea{flex:1;min-height:62px;resize:vertical;font:inherit;
font-size:13px;background:var(--bg);color:var(--text);
border:1px solid var(--border);border-radius:3px;padding:8px}
.chatcompose textarea:focus{outline:2px solid var(--primary);outline-offset:1px}
.chatcompose .btn{white-space:nowrap}
.btn:focus-visible,.msgsummary:focus-visible{outline:2px solid var(--primary);
outline-offset:2px}
.btn[disabled]{opacity:.45;cursor:not-allowed}
.msgsummary{cursor:pointer;font-size:11px;color:var(--muted);
text-transform:uppercase;letter-spacing:.06em;list-style:none;
display:flex;justify-content:space-between;gap:8px;align-items:center}
.msgsummary::-webkit-details-marker{display:none}
.msgsummary::after{content:"\\25BE";font-size:10px}
details[open]>.msgsummary::after{content:"\\25B4"}
.msgbody.collapsed{display:none}
.actioncard{margin-top:6px;border:1px solid var(--border);
border-radius:3px;padding:0;background:var(--bg)}
.actioncard>summary{padding:6px 9px;font-size:11px;letter-spacing:.06em;
text-transform:uppercase;color:var(--muted);cursor:pointer;list-style:none;
display:flex;justify-content:space-between;gap:8px}
.actioncard>summary::-webkit-details-marker{display:none}
.actioncard>summary:focus-visible{outline:2px solid var(--primary);
outline-offset:-2px}
.actioncard .abody{padding:4px 9px 9px}
.badge{font-size:10px;letter-spacing:.06em;padding:2px 6px;border-radius:3px;
border:1px solid var(--border);text-transform:uppercase;white-space:nowrap}
.badge.allow{color:var(--sec);border-color:var(--sec)}
.badge.deny{color:#e0736a;border-color:#c0483c}
.badge.ok{color:#63c39a;border-color:#3f8f6f}
.badge.pending{color:#d9a441;border-color:#c08a2e}
.badge.idle,.badge.stopped{color:var(--muted)}
.chathead{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap;
border-bottom:1px solid var(--border);padding-bottom:8px;margin-bottom:10px}
.chathead .grow{flex:1}
.mono{font-family:'JetBrains Mono',ui-monospace,monospace}
.evlist{display:flex;flex-direction:column;gap:4px;font-size:12px}
.evrow{display:flex;gap:8px;justify-content:space-between;
border-bottom:1px dashed var(--border);padding:3px 0}
.evrow .port{font-family:'JetBrains Mono',ui-monospace,monospace}
.scrollbox{max-height:38vh;overflow-y:auto}
.trunc{max-height:180px;overflow:hidden;position:relative}
details>summary{list-style:none}
details>summary::-webkit-details-marker{display:none}
"""

#: Message type -> (label, css class). Kept as data so the renderer and
#: the tests cannot drift apart.
TYPE_LABEL: Dict[str, Tuple[str, str]] = {
    chat_state.TYPE_USER: ("USER", "msg-user"),
    chat_state.TYPE_AGENT: ("RAPHAEL", "msg-agent"),
    chat_state.TYPE_ACTION: ("ACTION PROPOSED", "msg-action"),
    chat_state.TYPE_POLICY: ("POLICY", "msg-policy"),
    chat_state.TYPE_EXECUTION: ("EXECUTION", "msg-execution"),
    chat_state.TYPE_EVIDENCE: ("EVIDENCE", "msg-evidence"),
    chat_state.TYPE_MODEL_ERROR: ("MODEL ERROR", "msg-model_error"),
    chat_state.TYPE_SYSTEM: ("SYSTEM", "msg-system"),
}


def _discovery_record(observation: Optional[Dict[str, Any]]
                      ) -> Optional[Dict[str, Any]]:
    """The discovery record inside a turn's observation snapshot.

    `AgentTurn.observation` is itself an `_observation_view` whose `latest`
    is an observation whose own `latest` is the folded ledger record, so
    the payload sits two levels down. Unwrap defensively: a missing or
    reshaped projection must render as "no evidence", never as invented
    services.
    """
    node = observation
    for _ in range(3):
        if not isinstance(node, dict):
            return None
        if node.get("open_services") is not None and "host" in node:
            return node
        node = node.get("latest")
    return None

STATE_BADGE: Dict[str, str] = {
    chat_state.STATE_IDLE: "idle",
    chat_state.STATE_RUNNING: "ok",
    chat_state.STATE_STOPPED: "stopped",
    chat_state.STATE_COMPLETE: "ok",
    chat_state.STATE_REFUSED: "deny",
    chat_state.STATE_ERROR: "deny",
}


def message_block(message: Dict[str, Any]) -> str:
    """Render one transcript entry in its own visual language.

    The nine types are deliberately distinct: an operator instruction, a
    model statement, a proposed action, a governance decision, an
    execution outcome, evidence, a model error, and a system event are
    not the same kind of claim and must not look the same.
    """
    mtype = str(message.get("message_type") or chat_state.TYPE_SYSTEM)
    label, css = TYPE_LABEL.get(mtype, ("SYSTEM", "msg-system"))
    if mtype == chat_state.TYPE_POLICY:
        decision = str((message.get("detail") or {}).get("decision")
                       or "").lower()
        if decision in ("deny", "denied"):
            css = "msg-policy deny"
    evidence_ids = list(message.get("evidence_ids") or ())
    turn_index = message.get("turn_index")
    chat_turn = message.get("chat_turn")
    meta: List[str] = []
    if chat_turn is not None:
        meta.append(f"chat turn {chat_turn}")
    if turn_index is not None:
        meta.append(f"run turn {turn_index}")
    if evidence_ids:
        meta.append("evidence " + ", ".join(str(e) for e in evidence_ids))
    return f"""
    <div class="msg {css}" data-message-type="{_e(mtype)}">
      <div class="mhead"><span class="mrole">{_e(label)}</span></div>
      <div class="mbody">{_e(message.get('content', ''))}</div>
      {f'<div class="mev">{_e(" · ".join(meta))}</div>' if meta else ''}
    </div>"""


def _action_card(detail: Dict[str, Any]) -> str:
    """Expandable per-action card: capability, target, policy, evidence.

    Shows the decision and its reason, never a credential. The rationale
    is the model's own one-line `purpose`.
    """
    capability = str(detail.get("capability") or "unknown")
    target = str(detail.get("target") or "")
    decision = str(detail.get("decision") or "n/a")
    reason = str(detail.get("reason") or "")
    rationale = str(detail.get("rationale") or "")
    execution = detail.get("execution") or {}
    evidence_ids = list(detail.get("evidence_ids") or ())
    badge = "allow" if decision.lower() == "allow" else (
        "deny" if decision.lower() in ("deny", "denied") else "pending")
    rows = [
        ("Target", target or "the authorized target"),
        ("Policy", f"{decision.upper()}" + (f" — {reason}" if reason else "")),
    ]
    if execution:
        rows.append(("Execution", "success" if execution.get("success")
                     else "not executed"))
    if evidence_ids:
        rows.append(("Evidence", ", ".join(str(e) for e in evidence_ids)))
    return f"""
    <details class="actioncard">
      <summary><span>{_e(capability)}</span>
        <span class="badge {badge}">{_e(decision)}</span></summary>
      <div class="abody">
        <dl class="kv">{''.join(f'<dt>{_e(k)}</dt><dd>{_e(v)}</dd>' for k, v in rows)}</dl>
        {f'<p class="hint" style="margin-top:6px"><strong>Rationale</strong> '
         f'{_e(rationale)}</p>' if rationale else ''}
      </div>
    </details>"""


def chat_turn_numbers(messages: Iterable[Dict[str, Any]]) -> List[Optional[int]]:
    """Conversation-level turn number for each transcript entry.

    The runtime's own turn counter is per-RUN, and every `/agent/message`
    starts a fresh model run, so it is honestly `turn 0` on every card. That
    is accurate but reads as a bug and, worse, misrepresents the governed
    loop's actual progress across a conversation.

    This derives a presentation-only counter from the durable transcript
    order: each operator message opens the next chat turn, and every entry
    after it belongs to that turn until the next operator message. It is
    derived, never invented, and the underlying per-run turn field is left
    untouched.
    """
    out: List[Optional[int]] = []
    turn = 0
    for message in messages:
        if str(message.get("message_type") or "") == chat_state.TYPE_USER:
            turn += 1
        out.append(turn or None)
    return out


def _chat_services(messages: Iterable[Dict[str, Any]]
                   ) -> List[Dict[str, Any]]:
    """Open ports reported across the whole chat session.

    Read from the transcript's own evidence entries, which carry the
    ledger record recorded when that turn executed. Nothing is merged,
    rewritten or synthesised: a port already seen is not repeated, and the
    evidence ids shown alongside it are the ones the ledger produced.
    """
    out: List[Dict[str, Any]] = []
    seen = set()
    for message in messages:
        if str(message.get("message_type") or "") != chat_state.TYPE_EVIDENCE:
            continue
        detail = message.get("detail") or {}
        host = detail.get("host")
        ports = detail.get("open_ports")
        if not host or not isinstance(ports, (list, tuple)):
            continue
        for port in ports:
            if port in seen:
                continue
            seen.add(port)
            out.append({"port": port, "service": "", "state": "open",
                        "host": host})
    return out


def _chat_actions(messages: Iterable[Dict[str, Any]]
                  ) -> List[Dict[str, Any]]:
    """Governed actions across the chat session, policy decision included.

    Paired by transcript ORDER, not by evidence id: the log records the
    policy entry without repeating the action's evidence ids, so an
    id-based join silently never matches and every decision would render
    as pending. Within a chat turn the sequence is action -> policy ->
    execution -> evidence, so the next policy belongs to the open action.
    """
    out: List[Dict[str, Any]] = []
    open_row: Optional[Dict[str, Any]] = None
    for message in messages:
        mtype = str(message.get("message_type") or "")
        if mtype == chat_state.TYPE_ACTION:
            detail = message.get("detail") or {}
            open_row = {
                "capability": detail.get("capability") or "action",
                "target": detail.get("target") or "",
                "decision": "pending", "reason": "",
                "evidence_ids": [str(i) for i in
                                 (message.get("evidence_ids") or ())],
            }
            out.append(open_row)
        elif mtype == chat_state.TYPE_POLICY and open_row is not None:
            detail = message.get("detail") or {}
            open_row["decision"] = detail.get("decision") or "n/a"
            open_row["reason"] = detail.get("reason") or ""
            if not open_row["evidence_ids"]:
                open_row["evidence_ids"] = [
                    str(i) for i in (message.get("evidence_ids") or ())]
            open_row = None
    return out


def _services(timeline: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Open ports actually reported by a governed discovery pass."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for turn in (timeline or {}).get("turns") or ():
        record = _discovery_record(turn.get("observation"))
        if not record:
            continue
        for entry in record.get("open_services") or ():
            port = entry.get("port")
            if port is None or port in seen:
                continue
            seen.add(port)
            out.append({
                "port": port,
                "service": entry.get("service") or "",
                "state": entry.get("state") or "open",
                "host": record.get("host") or "",
            })
    return out


def _actions(timeline: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for turn in (timeline or {}).get("turns") or ():
        proposal = turn.get("proposal") or {}
        policy = turn.get("policy") or {}
        execution = turn.get("execution") or {}
        evidence = turn.get("evidence") or {}
        out.append({
            "turn_index": turn.get("index"),
            "capability": proposal.get("capability") or "terminal",
            "target": proposal.get("target") or "",
            "decision": policy.get("decision") or "n/a",
            "reason": policy.get("reason") or "",
            "executed": execution.get("executed"),
            "success": execution.get("success"),
            "evidence_ids": list(evidence.get("evidence_ids") or ()),
            "rationale": turn.get("rationale") or "",
        })
    return out

def evidence_panel(timeline: Optional[Dict[str, Any]],
                   gate: Optional[Dict[str, Any]] = None,
                   chat_messages: Optional[Iterable[Dict[str, Any]]] = None
                   ) -> str:
    """Right column: what the agent actually established.

    Aggregated over the whole chat MISSION, not just the most recent
    per-message run. Every `/agent/message` starts a fresh model run, so
    reading only the latest one showed "No discovery evidence yet" beside a
    transcript full of evidence — a visible contradiction. When a chat
    transcript is supplied it is the source; the run timeline remains the
    fallback for the non-chat start path.

    Every row is read from persisted data. Nothing is merged, rewritten or
    synthesised for appearance; evidence ids are the ledger's own, a port
    already seen is not repeated, and an empty section still says so.
    """
    chat = list(chat_messages or ())
    services = _chat_services(chat) or _services(timeline)
    actions = _chat_actions(chat) or _actions(timeline)
    denied = [a for a in actions
              if str(a.get("decision", "")).lower() in ("deny", "denied")]
    verdict = str((gate or {}).get("verdict") or "")
    gate_reason = str((gate or {}).get("reason") or "")

    service_rows = "".join(
        f'<div class="evrow"><span class="port">{_e(s["port"])}/tcp</span>'
        f'<span>{_e(s["service"] or "unknown")}</span>'
        f'<span class="badge ok">{_e(s["state"])}</span></div>'
        for s in services) or '<p class="hint">No discovery evidence yet.</p>'

    action_rows = "".join(
        f'<div class="evrow"><span>{_e(a["capability"])}</span>'
        f'<span class="badge {"allow" if str(a["decision"]).lower() == "allow" else "deny"}">'
        f'{_e(a["decision"])}</span>'
        f'<span class="mono">{_e(", ".join(a["evidence_ids"]) or "-")}</span></div>'
        for a in actions) or '<p class="hint">No governed actions yet.</p>'

    deny_rows = "".join(
        f'<div class="evrow"><span>{_e(a["capability"])}</span>'
        f'<span class="mono">{_e(a["reason"] or "denied")}</span></div>'
        for a in denied) or '<p class="hint">No denied actions.</p>'

    gate_block = (
        f'<div class="evrow"><span>QUALITY GATE</span>'
        f'<span class="badge {"ok" if verdict == "complete" else "deny"}">'
        f'{_e(verdict or "pending")}</span></div>'
        + (f'<p class="hint">{_e(gate_reason)}</p>' if gate_reason else "")
    ) if verdict else '<p class="hint">QualityGate has not run yet.</p>'

    return f"""
  <section class="cpanel cevidence" aria-label="Live evidence">
    <div class="sublabel">SERVICES</div>
    <div class="evlist">{service_rows}</div>
    <div class="sublabel" style="margin-top:12px">ACTION HISTORY</div>
    <div class="evlist scrollbox">{action_rows}</div>
    <div class="sublabel" style="margin-top:12px">DENIED ACTIONS</div>
    <div class="evlist">{deny_rows}</div>
    <div class="sublabel" style="margin-top:12px">GATE</div>
    <div class="evlist">{gate_block}</div>
  </section>"""


def mission_header(*, target: Optional[Dict[str, Any]],
                   provider: str, model: str, run_id: str = "",
                   run_state: str = "idle", turn: int = 0,
                   max_turns: int = 0) -> str:
    """Persistent mission header. Names only — never a credential."""
    locator = str((target or {}).get("locator") or "not declared")
    badge = STATE_BADGE.get(run_state, "idle")
    turn_text = f"{turn} / {max_turns}" if max_turns else str(turn)
    return f"""
<div class="chathead" role="status" aria-label="Mission status">
  <span class="sublabel" style="margin:0">MISSION</span>
  <span class="mono">{_e(locator)}</span>
  <span class="badge {badge}" data-run-state="{_e(run_state)}">{_e(run_state.upper())}</span>
  <span class="grow"></span>
  <span class="hint" style="margin:0">PROVIDER <span class="mono">{_e(provider)}</span></span>
  <span class="hint" style="margin:0">MODEL <span class="mono">{_e(model)}</span></span>
  <span class="hint" style="margin:0">TURN <span class="mono">{_e(turn_text)}</span></span>
  <span class="badge allow">GOVERNANCE ENFORCED</span>
</div>"""


def chat_panel(*, mission_id: str, messages: Iterable[Dict[str, Any]],
               stopped: bool, provider_state: Dict[str, Any],
               stopped_reason: str = "") -> str:
    """Centre column: the transcript and the operator composer.

    The composer posts to /agent/message, which runs ONE governed turn.
    It is a text box, not a command box: the console does not interpret
    what the operator typed, and the model still has to propose an
    ActionRequest that Broker and Policy may refuse.
    """
    entries = list(messages)
    # Presentation-only conversation counter. The per-run turn the runtime
    # records is left exactly as it is; this just makes progress across a
    # conversation legible instead of repeating "turn 0" on every card.
    for entry, number in zip(entries, chat_turn_numbers(entries)):
        entry["chat_turn"] = number
    blocks = "".join(message_block(m) for m in entries)
    if not blocks:
        blocks = ('<p class="hint">No messages yet. Describe what you want '
                  'the governed agent to investigate &mdash; for example '
                  '"Start reconnaissance on this target."</p>')
    disabled = " disabled" if stopped else ""
    stop_control = (
        f'<form method="post" action="/agent/resume" style="margin:0">'
        f'<input type="hidden" name="mission_id" value="{_e(mission_id)}">'
        f'<button class="btn" type="submit">Resume</button></form>'
        if stopped else
        f'<form method="post" action="/agent/stop" style="margin:0">'
        f'<input type="hidden" name="mission_id" value="{_e(mission_id)}">'
        f'<button class="btn" type="submit">Stop</button></form>')
    banner = (f'<p class="badge deny" role="alert">{_e(stopped_reason)}</p>'
              if stopped else "")
    return f"""
  <section class="cpanel cchat" aria-label="AI agent chat">
    <div class="chathead">
      <span class="sublabel" style="margin:0">AI AGENT CHAT</span>
      <span class="grow"></span>
      {stop_control}
    </div>
    {banner}
    <div class="chatlog" id="chatlog" tabindex="0" role="log"
         aria-live="polite" aria-label="Mission transcript">{blocks}</div>
    <form class="chatcompose" method="post" action="/agent/message">
      <input type="hidden" name="mission_id" value="{_e(mission_id)}">
      <!-- No provider credential is carried here: provider, model and
           endpoint resolve server-side, as a blank model means on
           /agent/start. A credential never belongs in the DOM. -->
      <label for="chatmsg" class="visually-hidden" style="position:absolute;
        left:-9999px">Message to the agent</label>
      <textarea id="chatmsg" name="message" rows="2"{disabled}
        placeholder="Tell the agent what to investigate next&hellip;"
        aria-label="Message to the agent"></textarea>
      <button class="btn" type="submit"{disabled}>Send</button>
    </form>
    <p class="hint" style="margin-top:8px">Enter sends &middot; Shift+Enter
    for a new line. Your message is context: the model still proposes, and
    Broker &rarr; Policy still decides.</p>
  </section>"""


__all__ = ["CHAT_CSS", "HTML", "TYPE_LABEL", "chat_panel",
           "evidence_panel", "message_block", "mission_header"]
