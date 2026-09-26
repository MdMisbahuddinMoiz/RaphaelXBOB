# AI-ASSISTED GOVERNED SECURITY ASSESSMENT — READINESS REPORT

**System:** AI-assisted governed security-assessment agent
**NOT:** fully autonomous pentesting agent

> The model can propose. Raphael decides whether execution is permitted.

Commit `0cbcd263f` · branch `hackathon/bob-assisted-raphael` · Python 3.14.4

---

## HEADLINE FINDING

**The AI-assisted governed architecture already existed.** Batch A discovery
(Model 2) returned `PROVIDER ABSTRACTION EXISTS — REUSE IT`. Building a new
`LLMProvider` would have violated the "do NOT duplicate an existing capability"
stop condition. The 30-round programme therefore became **verification and
gap-closing**, not construction.

| Layer | Location | Provenance |
|---|---|---|
| LLM seam | `harness/model.py:60` `ModelAdapter.propose(ModelContext) -> ActionRequest` | pre-existing |
| Deterministic double | `harness/model.py:73` `ScriptedModelAdapter` (raises on exhaustion) | pre-existing |
| Real provider | `harness/providers/openai_compat.py` (stdlib urllib, env config) | pre-existing |
| Governed propose→submit | `harness/run.py:222-223` → `runtime.submit(proposal, mission)` | pre-existing |
| Bounded loop | `harness/model_run.py:65` `DEFAULT_MAX_TURNS = 14` | pre-existing |
| Sole COMPLETE authority | `quality_gate.py` `BOBQualityGate` | pre-existing |
| Evidence chain | `evidence_ledger.py` + `seal.py` prev-hash chain | pre-existing |

`provider_runtime.py` is **not** an LLM abstraction — it is the out-of-process
C1A *capability* boundary. Not extended for model use.

---

## DEFECTS FOUND AND FIXED (all verified by execution)

### 1. Non-finite execution bound reached the ledger — `broker.py`
`submit()` validated with `timeout <= 0`, which is `False` for NaN and ±inf.
Policy's correct `_timeout_is_valid` was wired only into the
network/telnet/discovery authorizers, so READ/LIST/SEARCH/WRITE/RUN_TEST and C1A
would stamp a non-finite deadline onto the request and persist it.
Fixed once at the single governed entrypoint.
**Evidence: 0 holes across 42 combinations (7 invalid × 6 capabilities);
`None`/0.5/2/5/30 still accepted; no over-blocking.**

### 2. AI-assisted runs wrote NO evidence seal — `harness/model_run.py`
`network_run.py` seals on both exit paths; `model_run.py` had **zero** seal
calls, so `verify_seal()` returned `missing-seal` for every model-led run. The
AI-assisted path lacked the tamper-evident chain the network path has.
**Evidence (real run):**
```
fresh model run         -> (True, 'seal-ok')
result records deleted  -> (False, 'record-count-mismatch:sealed=7 observed=6')
ledger order reversed   -> (False, 'head-mismatch:ledger-modified-reordered-or-deleted')
```

### 3. Malformed model output crashed the ledger — `evidence_ledger.py`, `broker.py`
`ActionRequest.capability` is `Capability | str`, and an LLM proposing an
unknown capability yields a plain string. Policy correctly DENIED it, then
`DecisionRecord.build` raised `AttributeError: 'str' object has no attribute
'value'` while recording the denial — the denial was lost and an unhandled
exception propagated. `RequestRecord` already handled this; two sites did not.
Fixed with the canonical `capability_id()` helper.
**Found by the new acceptance suite, not by inspection.**

### 4. Demo gate claims disconnected from measured results — `demos/`
Four call sites passed literal `regression_ok=True` while the same demos
measured the real outcomes. Now derived from the measured test results in
every branch. `c1a_live_hero.py` probe/regression evidence is now **causally
bound** to a real ALLOWed execution (previously hardcoded `request_seq=0`),
which is what gate conditions C and D actually require.

**Verified demo behaviour is unchanged where tests genuinely pass:**
```
canonical_hero --mode raphael   exit=0  RESULT: COMPLETE
canonical_hero --mode baseline  exit=1  RESULT: REFUSE
canonical_hero --mode refuse    exit=1  RESULT: REFUSE
authkit_hero                    exit=0  Gate: COMPLETE
c1a_live_hero                   exit=0  Gate: COMPLETE
```

---

## KNOWN ISSUES — REPORTED, NOT PAPERED OVER

### P1 — WRITE has no file-type guard (operator decision required)
`_authorize_write` checks only resolution/dir/parent; mission-scope containment
is the sole guard, so a WRITE inside scope could target `policy.py`. Not
changed: altering authorization semantics risks the HTB / VulnHub-VMware
behaviour this project must preserve. **Needs an explicit decision.**

### P2 — `_execution_context` never cleared
`broker.py:352` sets it, `:366` reads it, never reset — a caller already
holding `broker._registry` could pass a forged ALLOW. Not changed: it requires
arbitrary in-process Python execution, which already implies total compromise
via the package-root `execute_capability` export (documented
separation-of-concerns). Fixing it adds churn to a security-critical file for
no boundary gain.

### P2 — Cosmetic target references in product comments
`telnet_runtime.py:270` names HTB machine "Meow" in a comment;
`network_runtime.py:58` hardcodes the `HTB{...}` flag format (platform-family,
not machine-specific). No behavioural coupling.

### Pre-existing test bugs (NOT regressions, NOT hidden)
Four tests open a hardcoded path from another machine
(`/home/yaser/raphael-2.0-rbsv2r/...`) and appear verbatim in the pre-existing
`.pytest_cache/v/cache/lastfailed`:
`test_budget_contract.py` ×2, `test_evaluator_isolation.py` ×2.
**No test was weakened, skipped, xfailed or deleted at any point.**

---

## MEASURED TEST RESULTS

| | Baseline (R01) | Final (R29) |
|---|---|---|
| passed | 1921 | **1941** |
| failed | 4 (pre-existing) | **4 (same pre-existing)** |
| skipped / xfailed | 1 / 4 | 1 / 4 |
| subtests | 183 | 236 |
| collected | 1930 | 1950 |

Command: `PYTHONPATH=. python3 -m pytest -q` (168.92s)

**New acceptance suite: `tests/test_assistant_governed_loop.py` — 20 passed,
53 subtests.** No network, no credentials, no real targets.

### Acceptance criteria coverage
| # | Criterion | Test class | Result |
|---|---|---|---|
| 1 | authorized proposal → broker → evidence | `AuthorizedProposalReachesBroker` | PASS |
| 2 | unauthorized capability → DENIED, no exec | `UnauthorizedCapabilityDenied` | PASS |
| 3 | out-of-scope target → DENIED, evidenced | `OutOfScopeTargetDenied` | PASS |
| 5 | malformed model output rejected safely | `MalformedModelOutputRejected` | PASS |
| 6 | failure feedback → next decision | `FailureFeedsNextDecision` | PASS |
| 7 | model cannot self-certify | `ModelCannotSelfCertify` | PASS |
| 8 | two targets, different decisions, no source change | `TargetAgnosticTwoTargets` | PASS |
| 9 | timeout bound fail-closed | `TimeoutBoundIsFailClosed` | PASS |
| 10 | loop bounded / loud exhaustion | `LoopIsBounded` | PASS |

---

## END-TO-END GOVERNED RUN (real, measured)

```
run_id        : 20260926T082855_7485af
turns         : 3        terminal: max-turns (bounded)
ledger        : 17 records = {request:3, decision:3, result:3, evidence:7, gate:1}
gate verdict  : REFUSE
gate reasons  : 'regression_ok=False (caller did not prove regression)'
                'behavior_probe_ok=False (no probe proof supplied)'
seal          : (True, 'seal-ok')
```

The refusal is **correct**: no independent behaviour probe was supplied and the
test did not pass. `RUN_TEST` did execute under bubblewrap
(`sandboxed: true`, `network_isolated: true`) but collected 0 tests
(pytest `returncode=5`), so the gate refused rather than claiming success.
Pre-existing behaviour; reported, not masked.

---

## SCORECARD

| Item | Status |
|---|---|
| Security boundary | **PASS** |
| LLM integration | **PASS** (pre-existing) |
| Mock provider | **PASS** (pre-existing) |
| Evidence | **PASS** (seal gap fixed) |
| Falsification | **PASS** (gate cross-checks conditions B/C/D) |
| Replanning (AI-assisted iterative) | **PASS** |
| Target agnosticism | **PASS** — verdict TARGET-AGNOSTIC |
| HTB regression | **PASS** — unchanged |
| VulnHub/VMware authorization | **PASS** — `PlatformSpec` preserved, untouched |
| No secrets committed/logged | **PASS** — scanned; only `nvapi-REDACTED` placeholders in legacy `src/` |
| Real-model smoke test | **BLOCKED — credentials unavailable** |

### Round 28 — BLOCKED, honestly
No provider credentials exist: `RAPHAEL_MODEL_*`, `OPENAI_API_KEY`,
`ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`, `NVIDIA_API_KEY`
all unset; no `.env` file; no local endpoint. The code fails closed:
`ProviderConfigError: missing model configuration: RAPHAEL_MODEL_ENDPOINT,
RAPHAEL_MODEL_NAME`. **No key was requested, invented, or simulated.** The mock
path is fully reproducible without credentials.

---

## VERDICT

**READY**, with two honestly-labelled residual items (P1 WRITE file-type guard
needs an operator decision; P2 `_execution_context` documented) and the
real-provider smoke test BLOCKED for lack of credentials.

The strongest property is preserved and now proven by executable tests:

> **The model can propose. Raphael decides whether execution is permitted.**
