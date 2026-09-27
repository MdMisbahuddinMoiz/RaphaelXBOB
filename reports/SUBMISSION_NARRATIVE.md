# Raphael — AI-Assisted Governed Security Assessment

Project: Raphael / `raphael-ibm-bob` 2.0.0. Commit `beef7ef37`, branch
`hackathon/bob-assisted-raphael`. Python 3.14.4. The shipped product
`raphael_ibm_bob/` is stdlib-only (no third-party runtime dependencies).

Positioning: this submission is an **AI-assisted governed security assessment**
agent / framework. The central property:

> **The model can propose. Raphael decides whether execution is permitted.**

## 1. Problem

LLMs can reason about security workflows: suggest next steps, draft test
commands, interpret tool output, and replan when results contradict expectations.
But unrestricted model-driven execution creates three concrete problems:

1. **Governance.** If model output flows directly to execution, there is no
   point at which authorization is checked against mission scope and policy.
2. **Authorization.** A model statement such as "run this test" is a
   declaration, not an authorization decision. Without a separate authority,
   declaration and authorization collapse into one step.
3. **Verification.** Model assertions about success ("the finding is fixed",
   "the target is verified") are untrusted until independently checked against
   measured evidence.

The problem is not that models reason poorly. The problem is that reasoning
without an enforcement boundary cannot produce auditable, deniable, verifiable
assessment work.

## 2. Solution

Raphael places a governed execution boundary around model-generated proposals.
The model contributes reasoning. Raphael contributes permission.

Concretely: every model output is treated as an **untrusted proposal**. It has
no executable force. A deterministic runtime submits it to policy, executes it
only if allowed, records the decision and result as append-only evidence, and
submits the accumulated evidence to an independent quality gate. The model
never executes. Raphael decides whether execution is permitted.

## 3. The interaction layer — AI Agent Chat console

The harness is operated through a governed agent console, and since `8df8b6f39` its
primary surface is a chat transcript:

    Harness
     └── AI Agent Console
          ├── Mission / target configuration
          ├── Operator chat
          ├── Action proposals
          ├── Policy decisions
          ├── Execution status
          ├── Evidence
          └── Timeline

**The chat is an interaction layer over the existing governed runtime, not a second
execution path and not a command executor.** An operator message is *context*: it reaches
the model as `ModelContext.operator_note` and nothing else. The model still returns an
ordinary `ActionRequest`, and that proposal still travels the one governed route:

    Operator message
      → ModelContext.operator_note   (context only; grants no authority)
      → provider / model
      → ActionRequest
      → Runtime
      → Broker
      → Policy
      → Capability
      → Evidence
      → observation folding
      → next turn
      → chat + timeline

There is deliberately no `chat → capability`, `chat → shell`, `chat → subprocess` or
`chat → broker bypass` branch. Each turn runs a single `max_turns=1` governed turn through
the same `start_model_run` → `run_model_mission` → `runtime.submit` path the console
already used, so the operator decides when the next observation happens rather than the
loop running away unattended. Evidence continuity across turns is preserved by seeding the
context with prior turn summaries and the observations their ledgers produced.

The operator message is redacted on the way in, so a pasted credential cannot reach a
provider through the chat. `POST /agent/stop` is a real server-side gate: after it,
`/agent/message` refuses, so no new model turn and no new capability execution can begin.

Routes: `GET /agent/chat`, `POST /agent/message`, `POST /agent/stop`, `POST /agent/resume`.

Transcript evidence shown to the operator is read from the run's own ledger
(`runs/<run_id>/evidence.jsonl`), never reconstructed from the model's pre-action belief. A
turn's observation is what the model saw *before* it acted, so it cannot report the result
of its own action; a missing or malformed record renders as "no evidence produced" rather
than as invented services.

## 4. Key innovation — the untrusted-proposal pipeline

The pipeline is:

```text
LLM reasoning -> untrusted proposal -> Raphael governance -> controlled
execution -> evidence -> verification
```

The invariant is **DECLARATION != AUTHORIZATION**, and the model never executes.

In this design the model adapter has one method: propose. It returns a
requested action. It cannot invoke a capability, write evidence, or declare
completion. Proposal, authorization, execution, and completion are separate
roles held by separate components, and only the governance side holds the
authority to advance from one stage to the next.

## 5. Architecture — the real call path

The governed assistance path is already implemented and uses these exact
modules:

- `harness/model.py:60` — `ModelAdapter.propose(ModelContext) -> ActionRequest`.
  This is the seam. The model's entire influence on execution passes through
  this single method.
- `harness/model.py:73` — `ScriptedModelAdapter`. A deterministic double used
  for offline verification. It replays a scripted proposal list and fails
  loudly when exhausted, so tests cannot silently pass on missing proposals.
- `harness/providers/openai_compat.py` — the real OpenAI-compatible provider.
  Implemented with stdlib `urllib`. Configuration is by environment variable
  only.
- `harness/model_run.py:65` — `DEFAULT_MAX_TURNS = 14`. The assist loop is
  bounded. It cannot run indefinitely on model output.
- `harness/run.py:222-223` — `model.propose(context)` followed by
  `runtime.submit(proposal, mission)`. The proposal crosses the boundary here
  and becomes a governed submission.
- `quality_gate.py` — `BOBQualityGate`. The SOLE authority that may emit
  `COMPLETE`. Neither the model, the provider, nor the runtime may do so.
- `evidence_ledger.py` + `seal.py` — append-only JSONL ledger plus a SHA-256
  prev-hash chain over records.
- `target_profile.py` — `PlatformSpec` with `htb` / `vulnhub` / `vmware`
  entries. Any non-HTB platform requires an explicit isolated environment,
  making every new platform entry STRICTLY MORE restrictive than `htb`.

Control flow per turn: propose, submit, policy consult, allow or deny,
execute only on allow, record decision and result, re-check mediated state,
repeat within the turn bound, then present the ledger to the QualityGate for
an independent COMPLETE / REFUSE verdict.

Replanning across turns is **AI-assisted iterative replanning**: the model may
propose a revised next step in light of recorded denials and results. Each
revised proposal re-enters the same governance path. No proposal inherits
trust from a prior turn.

## 6. Security boundary — enforcement points

The boundary is not a single check. It is the ordered set of points a proposal
must pass:

1. **Policy consult.** Every submitted proposal is evaluated against mission
   scope and capability policy before anything else happens.
2. **Deny short-circuit.** A denial stops the proposal. Denied actions are not
   executed, not retried implicitly, and the denial itself is recorded.
3. **Scope containment.** Workspace path containment and mission-scope
   containment constrain where capabilities may act, independent of what the
   model requested.
4. **Target-profile binding.** Execution is bound to a declared
   `TargetProfile`. There is no ambient or implied target.
5. **Mediated re-checks.** State used for subsequent decisions is re-checked
   through the mediated path rather than accepted from model output.
6. **Sandboxed RUN_TEST.** Test execution passes through the sandboxed
   RUN_TEST capability path, not through direct host execution at the model's
   request.

Four defects found and fixed this session, each verified by execution:

1. `broker.py` accepted non-finite timeouts (`NaN` / `±inf` pass `<= 0`), so
   path-scoped capabilities could persist a non-finite deadline. Fixed at the
   single entrypoint; 0 holes across 42 combinations.
2. `harness/model_run.py` wrote NO evidence seal, so every AI-assisted run
   reported `verify_seal() == (False, 'missing-seal')`. Fixed; assisted runs
   now report `seal-ok`.
3. `evidence_ledger.py` / `broker.py` raised `AttributeError` when recording
   the DENIAL of a capability supplied as a plain string — exactly what an LLM
   produces for an unknown capability — so the denial was lost. Fixed with the
   canonical `capability_id()` helper.
4. Demo `QualityGate` inputs passed a literal `regression_ok=True`
   disconnected from the results the same demos measured. Now derived from
   measured results in every branch.

## 7. Evidence system

Every decision and result is recorded in an append-only JSONL ledger
(`evidence_ledger.py`). Records are causally chained, and `seal.py` computes a
SHA-256 prev-hash chain over the ledger. Verification (`verify_seal`)
recomputes the chain and the record count.

Measured tamper behaviour:

- Fresh run: `(True, 'seal-ok')`.
- Deleting records: `record-count-mismatch`.
- Reordering records: `head-mismatch:ledger-modified-reordered-or-deleted`.

Honest note: the seal is UNKEYED. It provides integrity (detection of
modification, deletion, and reordering), not authenticity (it does not prove
who wrote the ledger). Any claim beyond tamper-evidence would be incorrect,
and none is made here.

## 8. Model integration

- **Provider-agnostic.** The runtime depends only on the `ModelAdapter`
  interface (`propose`). Any model that can produce an `ActionRequest` can be
  attached without changing the governance path.
- **OpenAI-compatible adapter.** `harness/providers/openai_compat.py`
  implements a real provider over stdlib `urllib`, configured by environment
  variables (`RAPHAEL_MODEL_ENDPOINT`, `RAPHAEL_MODEL_NAME` and related
  settings). No credentials are stored in source.
- **Deterministic provider.** `ScriptedModelAdapter` provides a fully
  offline, deterministic proposal source, and the acceptance suite runs
  entirely through this path: no network, no credentials, no real targets.
- **Offline demonstration provider.** `demos/local_model_endpoint.py` is a
  real HTTP server speaking the OpenAI `POST /v1/chat/completions` protocol
  whose replies come from a fixed rule table. It is admitted explicitly in
  the audit allow-list as `local-deterministic` and labelled *not an AI
  model*. It exists so the governed chat path can be demonstrated with no
  vendor credential. Governance is unaffected: its reply still arrives as a
  proposal and still crosses Runtime → Broker → Policy.
- **Real-provider test status: BLOCKED — credentials unavailable.** No
  `RAPHAEL_MODEL_*` environment variables are set and no `.env` file is
  present in the current execution environment. The provider code fails
  closed and names `RAPHAEL_MODEL_ENDPOINT`, `RAPHAEL_MODEL_NAME`,
  `RAPHAEL_MODEL_API_KEY`. No credential was requested, invented, or
  simulated. A real MiMo V2.6 Flash mission **was** demonstrated earlier on
  the `a7d4d1357` vertical-slice checkpoint; that validation is real, and it
  is not what the current offline run reproduces.

## 9. Measured evidence

**Current measured test state at `beef7ef37`: 2160 passed, 0 failed, 1 skipped,
4 xfailed, 297 subtests in 192.73s.**

Session trajectory:

| Checkpoint | passed | failed |
|------------|--------|--------|
| `a7d4d1357` (start of session) | 2148 | 6 |
| `8df8b6f39` after the chat-path fix | 2150 | 4 |
| `3150a3060` after test portability | 2154 | 0 |
| `6009afbc6` / `0ebb9f389` | **2156** | **0** |
| `beef7ef37` after run-path sealing — **latest verified checkpoint** | **2160** | **0** |

The 6 starting failures were: 2 in the chat console (a `NameError` on an
unwritten helper, `_latest_discovery`, plus a missing `config` parameter) and 4
that opened a hardcoded path from another machine
(`/home/yaser/raphael-2.0-rbsv2r/...`). All six are fixed. None was hidden,
skipped, xfailed, or reclassified.

Two further defects were found by executing the system rather than by reading it:

- **Arena artifact destruction.** Because `AblationRunner` wrote into a
  CWD-relative results path and `run_id` is deterministic, every test run
  truncated committed ablation and negative-control evidence — 3682 lines
  across 13–14 files on a full run. Resolved in `9bb6d095c` by test-side CWD
  isolation; the suite now leaves `arena/results/raw` clean.
- **Chat transcript id collision.** Message ids came from a process-local
  counter that reset on restart, reissuing ids the durable transcript already
  held. Resolved in `6009afbc6` by seeding the counter from the persisted log.

- **Missing chain-level seals.** `start_run` and `run_telnet_mission` closed
  their ledgers without writing `seal.json`, so those two paths lacked
  chain-level delete/reorder detection. Resolved in `beef7ef37` by sealing
  after final evidence persistence on both exits, mirroring the network and
  model paths. The tamper tests were reproduced failing 4/4 before the fix.

Full detail: `reports/TEST_INTEGRITY_AUDIT.md` and `reports/FINAL_TEST_MATRIX.md`.

### PROVEN TODAY

- Governed chat console in a real browser against a real controlled target:
  `network_service_discovery on 127.0.0.2` → Policy `ALLOW — ok` → execution
  `Completed` → evidence `127.0.0.2: 2222, 8080 (probed 2)`, read from the run
  ledger.
- Controlled target verification: **14/14** fixture checks pass.
- Real MiMo V2.6 Flash vertical slice at `a7d4d1357`: governed discovery, SSH
  execution, evidence-driven replanning, user-to-root progression.

### NEXT DEMONSTRATION — not yet proven

- **Kioptrix Level 1** is prepared as the next authorized training target. Its
  autonomous compromise has **not** been established by the current
  submission checkpoint, and is not claimed here.
- A real-model browser run, which requires a hosted-model credential that is
  unavailable in the current execution environment.

## 10. Target agnosticism — TARGET-AGNOSTIC

The system is **TARGET-AGNOSTIC**. There is zero functional coupling between
the governance path and any specific target.

Targets are data-driven via `TargetProfile` / `TargetStore`. Adding a new
authorized target is a data entry (profile plus authorization record), with
zero source change to the product. Guard tests forbid target-specific strings
(`kioptrix` / `kioptix` / `metasploitable`) in product source, and that guard
continues to pass.

Two-target and three-target genericity have been proven using RFC 5737
documentation addresses, confirming that multi-target handling exercises only
the generic profile path and no per-target logic.

## 11. Limitations

Stated explicitly, without qualification:

1. **Unkeyed seal.** Every governed run path now writes `seal.json` after its
   final evidence is persisted, and the seal detects tampering (count mismatch,
   reordering, deletion) — but it does **not** authenticate the writer.
   Authenticity would require a keyed mechanism, which is not implemented.
   Protecting `runs/` and `sessions/` with filesystem permissions and backups
   remains the operator's responsibility.
2. **`_execution_context` never cleared.** The in-process execution context is
   not cleared between operations. This is in-process bookkeeping only and is
   outside the LLM threat model (the model has no access to it), but it is an
   uncleared-state limitation and is recorded as such.
3. **WRITE has no file-type guard.** The guard on WRITE is mission scope, not
   file type. A pending WRITE-guard review is open on whether a type-level
   guard should additionally apply. No such guard is claimed.
4. **RUN_TEST collected 0 tests in this environment, so the gate honestly
   REFUSES.** Where required test evidence is absent, the QualityGate emits
   REFUSE rather than converting the absence into a pass. That refusal is the
   correct behaviour and is reported as a refusal, not a completion.
5. **No real-provider verification in the current environment.** The
   OpenAI-compatible provider path is implemented and fails closed without
   configuration, but the execution environment used for this submission pass
   has no `RAPHAEL_MODEL_*` credentials, so no live-model run was performed
   here. A real MiMo V2.6 Flash mission **was** demonstrated earlier at
   `a7d4d1357`; that is a historical validation, not something this
   environment reproduces. Every assisted-loop claim in the current browser
   checkpoint rests on the deterministic provider, which is not an AI model.
6. **Kioptrix Level 1 is not yet demonstrated.** It is prepared as the next
   authorized training target. No autonomous compromise of it is claimed by
   this submission checkpoint.

## 12. Demo flow — four acts

Brief summary; the dedicated demo document owns the commands.

- **Act 1 — ALLOW.** A model-proposed action within scope and policy is
  allowed, executed through the boundary, and recorded with its result.
- **Act 2 — DENY.** A model-proposed action outside scope or policy (including
  an unknown capability supplied as a plain string) is denied, and the denial
  itself is recorded — the case that previously raised `AttributeError`.
- **Act 3 — FEEDBACK.** The denial and recorded results are fed back as
  context, and the model proposes a revised, compliant next step
  (AI-assisted iterative replanning). The revised proposal re-enters the same
  governance path with no inherited trust.
- **Act 4 — VERIFICATION.** The ledger is sealed and verified (`seal-ok`),
  and the QualityGate renders its independent verdict from measured evidence:
  COMPLETE only when the evidence satisfies its conditions, otherwise REFUSE.

## 13. What this is not

This is not a fully autonomous pentesting agent, a self-driving attacker, or
an exploit planner. It is an AI-assisted governed security assessment
framework in which an untrusted model proposes, Raphael alone authorizes and
executes under policy, and an independent gate verifies against sealed
evidence. Anything the model suggests but Raphael does not permit does not
happen.
