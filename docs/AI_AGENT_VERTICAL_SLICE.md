# AI Agent Vertical Slice

Raphael can now be driven by an AI model end to end: a user opens the Web
UI, selects a provider/model, declares a target, starts the agent, and
watches the model reason over observations while **Raphael** independently
governs every consequential action.

The model never executes anything. It proposes; Raphael decides.

```text
OBSERVE  fold_observations(ledger)      -> ModelContext
MODEL    ModelAdapter.propose(context)  -> ActionRequest   (proposal only)
PROPOSE  record capability/target/rationale
POLICY   BOBRuntime.submit -> BOBBroker -> BOBPolicy       (the ONLY path)
EXECUTE  Broker-mediated capability invocation
EVIDENCE append-only ledger records become the next turn's input
REPEAT   until the model declares done, errors, or max_turns is reached
         -> BOBQualityGate is the SOLE authority for COMPLETE / REFUSE
```

---

## 1. Provider UI (normalized internal configuration)

`GET /agent` renders the configuration form and the governed loop.

```python
from raphael_ibm_bob.harness.providers import (
    ProviderConfig, build_provider_config, default_provider_registry)
```

`ProviderConfig` (`raphael_ibm_bob/harness/providers/config.py`) is the
single internal shape the rest of Raphael consumes:

| field            | meaning                                  |
|------------------|------------------------------------------|
| `provider`       | provider id (a wire-format name)         |
| `endpoint`       | base URL of an OpenAI-compatible API     |
| `model`          | model id                                 |
| `api_key`        | credential, **write-only**               |
| `timeout_seconds`| per-call bound                           |
| `max_tokens`     | response bound                           |
| `temperature`    | sampling temperature                     |

Operator-supplied fields win; anything omitted falls back to the
`RAPHAEL_MODEL_*` server environment, so a server configured once needs
no per-run input. `os.environ` is never mutated — a temporary override
would leak one operator's credential into another operator's concurrent
run.

### Credential discipline

- `ProviderConfig` is declared `@dataclass(frozen=True, repr=False)` with
  an explicit `__repr__`/`__str__` that render `"<redacted>"`. An
  accidental `print(config)`, traceback, or log call cannot leak a key.
- `redacted()` is the only serializable view and reports `"set"` /
  `"unset"` — never the value, its length, or a prefix.
- `ProviderConfigError` messages name the **field** that is missing
  (`RAPHAEL_MODEL_ENDPOINT is not set`), never a value.
- The UI key input is `type="password"`, `autocomplete="off"`, and is
  never rendered back. The console only states whether a key was
  supplied.
- The key lives for the duration of one `make_model_adapter` call. It is
  never written to a session, run record, ledger entry, artifact, URL, or
  response.

---

## 2. Model adapter (provider abstraction)

The planner depends on one protocol, not on any vendor:

```python
class ModelAdapter(Protocol):
    def propose(self, context: ModelContext) -> ActionRequest: ...
```

`OpenAICompatAdapter` (`harness/providers/openai_compat.py`) is the one
shipped implementation. It speaks `POST {endpoint}/chat/completions`,
asks for a single compact JSON object, validates it against the T1-1
registry, and returns an ordinary `ActionRequest`. Vendor wire-format
detail — including the OpenCode session-header auto-detect — lives
entirely inside `_post` and `build_adapter`.

Provider selection is a **registry lookup**, not a branch:

```python
registry = default_provider_registry()      # {"openai-compatible": builder}
registry.create(config, skill_registry)     # -> ModelAdapter
```

Adding a provider is one `registry.register(...)` line. The planner
never names a provider and cannot grow a vendor branch.

Failure taxonomy is explicit and always redacted:
`ProviderConfigError`, `ProviderError`, `ProviderTimeout`,
`ProviderCancelled`, `StructuredProposalError`, `DoneSignal`.

---

## 3. The governed loop

`harness/model_run.py::run_model_mission` is the only agent loop. The
model holds **no** capability, mediator, socket, broker, or subprocess
handle — it returns an `ActionRequest` and nothing else.

Each turn records an `AgentTurn`:

| field         | shown as                                       |
|---------------|------------------------------------------------|
| `observation` | services/ports folded from the ledger           |
| `proposal`    | capability + target the model asked for         |
| `rationale`   | the model's own one-line `purpose`              |
| `policy`      | decision + reason                               |
| `execution`   | invoked / success / error                       |
| `evidence`    | ledger evidence ids + provider-untrusted flag   |
| `next_action` | what the loop does next                         |

Turns are persisted to `runs/<run_id>/timeline.json` and served
read-only at `GET /runs/{run_id}/timeline`. The evidence ledger remains
authoritative; the timeline is a rendering projection over it.

**No chain-of-thought is stored or displayed.** The provider contract
asks for a single compact JSON object with no explanations, so
`rationale` is the model's declared action purpose — not its reasoning.

---

## 4. Existing discovery, connected to the planner

`NETWORK_SERVICE_DISCOVERY` was already a fully governed capability
(descriptor, Policy authorizer, Broker path, `DiscoveryMediator`). It
was simply **not in the model's catalog**, so the model could never
propose it.

`skills.py` now declares it in `default_registry()` and registers a
`network-service-discovery` skill. `skill_catalog(registry)` derives the
model-facing catalog from the registry, so discovery appears in the
prompt automatically — there is no parallel hardcoded list.

`fold_observations(ledger)` reads the `producer="discovery"` records and
derives bounded, structured observations:

```python
{"kind": "service-discovery", "host": "127.0.0.1",
 "ports_open": [8080], "open_services": [{"port": 8080,
 "service": "http-alt", "latency_ms": 0.09}],
 "provider_untrusted": True}
```

Those observations become `ModelContext.observations` and are
serialized into the next turn's prompt. That is what lets the model
choose a *different* next action instead of repeating the last one.

The discovery **mediator is untouched** — the model reaches it only
through `Runtime → Broker → Policy`.

### The `ports=` clause

`ActionRequest.purpose` doubles as the proposal's rationale, so
`_parse_port_spec` reads the port list as the well-formed *prefix* of the
clause token and requires the remainder to start at a separator:

```text
ports=8080) to see what answers  -> [8080]
ports=80,443,8080.               -> [80, 443, 8080]
ports=abc / ports=80a / 1-2-3    -> ValueError (DENY, unchanged)
```

Fail-closed behaviour is preserved; only trailing prose is tolerated.

---

## 5. What the Web UI shows

`GET /agent` renders:

1. **Model provider** — provider id, model, endpoint, API key
   (write-only), and whether a key is set.
2. **Authorized target** — host, authorized ports, authorized protocols,
   authorization ref, stage. Both the ports and the protocols must be
   named by the operator; Raphael never infers either.
3. **Start the agent** — the same normalized configuration plus a
   mission id and turn bound.
4. **Governed loop** — per turn: selected provider/model, current
   target, observation, proposal, rationale, policy decision,
   execution result, evidence, next action; then the final state and the
   QualityGate verdict.

`POST /agent/start` is synchronous, matching the existing
`POST /runs/model` contract: the run completes before the response.

---

## 6. Local demo

```bash
./scripts/run_agent_demo.sh            # full slice, 4 turns
./scripts/run_agent_demo.sh --turns 6  # bound the loop
./scripts/run_agent_demo.sh --tests    # run the slice tests
```

`demos/agent_vertical_slice.py` stands up:

- a **real loopback HTTP fixture on `127.0.0.1:8080`** — the authorized
  target, so governed discovery actually connects to something;
- a **local OpenAI-compatible model endpoint** on an ephemeral port.

Then it drives the real product path (`harness.api.start_model_run`) and
prints every stage of the loop.

### The local model endpoint is not a language model

`demos/local_model_endpoint.py` is a real HTTP server speaking the
OpenAI chat-completions wire protocol, driven by a three-rule table
(nothing observed → discover; ports observed → fetch; already fetched →
done). It has no reasoning, labels every response `local-deterministic`,
and is labelled a demo component — not a Raphael component and not a
model. The adapter path it exercises is byte-for-byte the path a hosted
model takes, so swapping in a real endpoint changes nothing on the
Raphael side.

---

## 7. Tests

```bash
PYTHONPATH=. python3 -m unittest tests.test_agent_vertical_slice
```

37 focused tests covering the seven slice properties:

| area                             | tests |
|----------------------------------|-------|
| provider configuration           | normalization, precedence, redaction, frozen, fail-closed bounds, environment never mutated |
| provider adapter                 | registry dispatch, `ModelAdapter` conformance, proposal → `ActionRequest`, discovery offered to the model |
| invalid provider / API failure   | unknown provider rejected before any request, unreachable endpoint, malformed payload, no key in any error |
| planner → Broker boundary        | every turn carries the broker's stamped request/decision/result/evidence chain |
| unauthorized rejection           | out-of-scope host denied with `discovery-target-mismatch`, unknown capability denied, no `result` record written |
| evidence returned to planner     | discovered ports reach turn N+1, reach the serialized prompt, stay bounded and untrusted |
| no direct model→tool execution   | adapter exposes no execution handle; the model holds no broker/mediator/socket; `DoneSignal` is not an action; the QualityGate alone emits the verdict |

No existing security test was weakened. Three existing assertions were
**updated** because the registry surface deliberately grew by one
capability: `tests/test_harness.py` (skill ids + idempotence count),
`tests/test_t1_1_registry.py` (capability count), and the discovery
catalog assertions in `tests/test_m15_1_http_api.py` /
`tests/test_m15_2_parity.py`.

---

## 8. What is deliberately NOT claimed

- **A hosted vendor model is not exercised here.** No `RAPHAEL_MODEL_*`
  credential is configured in this environment, so the demonstrated
  provider is the local OpenAI-compatible endpoint. Point the console at
  a real endpoint to run a real model; the governance path is identical.
- **`COMPLETE` is not reachable for a discovery mission.** The
  QualityGate's conditions A–G require regression and independent-probe
  evidence that a two-condition network discovery mission does not
  produce, so the honest verdict is `REFUSE`. That is the gate working,
  not a failure.
- **The model cannot self-certify.** `DoneSignal` stops the loop; only
  `BOBQualityGate` may emit `COMPLETE`.
- **Discovery output stays `provider_untrusted`.** An open port is
  evidence, never a verified finding.


---

## 9. Model authorization and the real provider

`POST /agent/start` authorizes the model **before** any provider work,
using the existing centralized mechanism — `api.require_audit_allowed_model`
— the same gate `/runs/model` and `/operations/start` already use. The
allow-list is not duplicated and no new model id is introduced.

```python
requested_model = _text(body, "model")
approved_model = api.require_audit_allowed_model(requested_model)  # 422 on reject
# ... target declaration, then:
model = api.make_model_adapter(..., model=requested_model or None)
```

Two properties matter and both are tested:

- **Validation strips, dispatch does not.** The allow-list normalizes a
  vendor prefix (`meta/muse-spark-1.3` → `muse-spark-1.3`) to decide
  admissibility, but the provider receives the operator's exact id,
  because real gateways key on the full `vendor/model` string.
- **Rejection precedes everything.** A denied model never reaches
  `make_model_adapter`, never opens a target, and never creates a run.
  `test_rejection_precedes_any_provider_or_broker_work` asserts this by
  patching both `make_model_adapter` and `start_model_run` to raise.

The console's model field is a text input with a datalist of the
approved ids. The datalist is convenience only — the server re-checks
every submission, so a hand-typed id cannot widen what runs.

### Real-provider readiness

```bash
./scripts/check_real_provider.sh
```

Runs the allow-list, prints the normalized config through
`redacted()` only, then makes one minimal authenticated
chat-completions call. That call is a provider health check: nothing is
brokered, no capability runs, no evidence is written.

| exit | meaning |
|------|---------|
| 0 | a real approved model answered |
| 3 | configuration incomplete (names the missing field) |
| 4 | the model is not on the audit allow-list |
| 5 | the provider rejected or was unreachable |

### Measured provider status

Against `https://openrouter.ai/api/v1` with a working operator
credential (authentication passes; no 401):

| requested id | allow-list | provider result |
|---|---|---|
| `meta/muse-spark-1.3` | admitted (`muse-spark-1.3`) | **403** — the account lacks the 18+ age attestation; the key itself authenticates fine (an ungated model on the same key returns 200) |
| `mimo-2.6-flash` | admitted | **400** — not an id any provider serves; the served model is `xiaomi/mimo-v2.6-flash`, whose base id `mimo-v2.6-flash` was added to the allow-list on operator instruction |
| `xiaomi/mimo-v2.6-flash` | admitted (`mimo-v2.6-flash`) | **200 OK** — real model, drives the governed loop |

### Measured real-model run

`xiaomi/mimo-v2.6-flash` driven through the Web UI against
`127.0.0.1:8080`:

```text
TURN 0  list .                     -> DENY  scope-mismatch
TURN 1  network_service_discovery  -> ALLOW -> executed -> DX-… untrusted
       "ports=1-1024 … since workspace listing was denied"
TURN 2  search .                   -> DENY  scope-mismatch
TURN 3  network_service_discovery  -> ALLOW -> executed -> DX-… untrusted
       "expand the earlier 128-port null result … to reduce uncertainty"
TURN 4  list ./                    -> DENY  scope-mismatch
TURN 5  (no content emitted)       -> terminal model-error
```

Turn 3's rationale is the load-bearing evidence: the model read the
`capped` / `ports_probed` fields out of turn 1's evidence and changed its
next request because of them. That is the observation loop working.

The two discovery executions reported `no_open_ports` because the
mediator's documented `DEFAULT_MAX_PORTS = 128` truncated `1-1024` to
ports 1–128, which does not contain 8080. That bound is disclosed to the
model as `capped: true` in the evidence, and the model acted on it.
Bounded-by-design, not a silent failure.

The loop ended `model-error` because this reasoning model consumed its
`max_tokens` before emitting a content field. That fails closed, and the
QualityGate still judged the run.

### Agent role correction

The first real run exposed a real defect: `_SYSTEM_PROMPT` described a
"governed coding agent" and instructed "inspect unknown files … propose
fixes for observed defects". Against a network-assessment mission the
model obeyed and proposed workspace file operations, which Policy
correctly denied every turn. The prompt now describes the governed
security-assessment role and tells the model to choose freely from the
catalog by mission uncertainty. No action sequence is prescribed — the
model still picks, and Raphael still decides.

`parse_response_body` also distinguishes a `content: null`
(reasoning-only / token-exhausted) response from an empty string. The
`reasoning` field is never read: surfacing it would put
chain-of-thought in the operator UI, which this contract forbids.

Remaining external blockers are account-side, not Raphael defects.

---

## 10. Governed SSH session capability

`Capability.NETWORK_SSH_SESSION` adds a remote-session boundary with the
same governance discipline as HTTP, Telnet and discovery:

```text
model -> ActionRequest -> Broker -> Policy -> SshMediator -> Evidence -> model
```

### Session model

The model never receives a session. It proposes ONE `ActionRequest`; the
Broker stamps it; Policy decides; the mediator opens a session, runs
exactly ONE already-approved command, and closes:

```text
OPEN SESSION -> EXECUTE ONE APPROVED COMMAND -> STRUCTURED RESULT -> CLOSE
```

Transport is paramiko (already a dependency), isolated in
`paramiko_ssh_session` and injectable, so tests never need a socket.
`ssh` joins `ALLOWED_PROTOCOLS`; `NETWORK_SSH_SESSION` joins the
`Capability` enum; `ssh_descriptor()` moves from descriptor-only to
executable; and a `network-ssh-session` skill joins the model catalog.

### Command wire form

The command is a structured clause, never prose:

```text
cmd="ls -la"                    -> command `ls -la`, rest is rationale
cmd="cat /etc/hosts" enumerate  -> command `cat /etc/hosts`
cmd=ls                          -> bare single token
cmd=ls && cat flag              -> DENIED, chaining
```

`SshCommandPolicy` is the reusable command-policy layer. It returns
`ALLOW`, `DENY`, or `REQUIRE_AUTHORIZATION`, and it distinguishes
"this can never run" (metacharacters, `sh -c`/`bash -c` indirection,
forbidden interpreters) from "the operator has not authorized it for
this mission".

### Credential handling

The mission declares a credential REFERENCE. Plaintext lives only in the
process-local `CredentialVault`, is resolved inside the mediator, and is
dropped the moment the transport returns. `SshSessionSpec.sensitive_dict()`
carries `credential_present`, never a value. The Agent Console has no
password field at all.

### Bounds

Command timeout, stdout limit, stderr limit, max command length, and
max commands per session are operator-configurable downward and clamped
to hard ceilings. The **mediator** enforces output bounds itself rather
than trusting the transport, so a substituted or misbehaving transport
cannot push unbounded output into evidence.

### Local validation

```bash
PYTHONPATH=. python3 demos/ssh_session_e2e.py
```

Runs the full chain against a real in-process SSH server on loopback
(`tests/ssh_fixture.py`): real transport, real password auth, real exec
channel, real exit status. The server answers a fixed read-only command
table and refuses all port forwarding.

## 11. Known limitations

### `/agent/start` is synchronous

`POST /agent/start` runs the whole governed loop inline and returns the
finished run. There is no background execution and no run queue, so the
HTTP request is held open for the duration of the mission.

For the current demo this is acceptable: a 20-turn mission against a real
provider completes in roughly 6 minutes, well inside the local harness
and reproducible end to end, and the operator sees the complete turn
sequence in one response. What it does *not* give you is a UI that stays
responsive during a long mission — a browser or proxy timeout in front of
the port will cut the request while the loop is still running.

This is recorded rather than redesigned here. Making it non-blocking means
deciding where a run lives while it is in flight and how a client resumes
observing it, which is a lifecycle change to the run store, not a UI fix.
The `/runs` API already exposes a run directory, so the groundwork exists;
it is deliberately not wired up in this checkpoint.

### Repetitive retrieval of the same evidence

The SSH capability previously had no case in `harness.loop.excerpt_output`,
so a governed SSH result fell through to `str(evidence)[:500]`. That dict
repr reaches `exit_code` and then truncates long before `stdout`: the model
could see that a command ran and succeeded, but not what it printed. It
re-ran the same authorized command across several turns looking for output
it had in fact already been handed.

`excerpt_output` now shapes SSH results explicitly — evidence id, command,
exit code, stdout byte count, and the recorded stdout verbatim — with
declared truncation reported rather than hidden. No summary is generated and
no content is invented; the text is exactly what the mediator bounded and
the ledger stored. The capability description also states that output
returns verbatim on the next turn, so the model can read before re-running.
