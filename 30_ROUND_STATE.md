# RAPHAEL — 30-ROUND AI-ASSISTED EXECUTION LOOP — MASTER STATE

> Scope change: *fully autonomous security assessment* → **AI-assisted, governed
> security assessment**. The external model proposes; Raphael decides.
>
> Integrator: Model 0 (primary). Specialists: Models 1–9 (see `reports/`).

---

## ROUND 01 — BASELINE  ✅ COMPLETE

### Git state (measured, not assumed)

| Field | Value |
|---|---|
| Commit | `31298fb58` |
| Branch | `hackathon/bob-assisted-raphael` |
| Dirty tracked files | 16 |
| Untracked paths | 22 |
| Python | 3.14.4 (`/usr/bin/python3`, GCC 15.2.0) |
| Product external deps | **none** — `raphael_ibm_bob/` is stdlib-only |

### Environment blockers found and resolved (no product code changed)

| Blocker | Resolution |
|---|---|
| `pytest` not installed; PEP 668 blocks system pip | `pip install --user --break-system-packages` |
| 18 collection errors: `No module named 'paramiko'` | installed `paramiko 5.0.0` |
| 7 test failures: `No module named 'httpx'` | installed `httpx 0.28.1` |
| No venv possible (`python3-venv` absent) | user-site install, system untouched |
| Docker unavailable | not required for the governed path |

### TEST BASELINE (authoritative, real run — not fabricated)

```
1921 passed, 4 failed, 1 skipped, 4 xfailed, 183 subtests passed
in 189.23s   (1930 collected, 0 collection errors)
```

**The 4 failures are PRE-EXISTING TEST BUGS, not product defects, and not
caused by the in-flight work.** All four open a hardcoded absolute path from a
different machine (`/home/yaser/raphael-2.0-rbsv2r/...`):

- `tests/test_budget_contract.py::test_runner_no_hardcoded_iteration_literal`
- `tests/test_budget_contract.py::test_action_budget_guard_present`
- `tests/test_evaluator_isolation.py::test_environment_no_global_import`
- `tests/test_evaluator_isolation.py::test_arena_entry_fresh_graph_fallback`

All four appear verbatim in the pre-existing `.pytest_cache/v/cache/lastfailed`,
which predates this session. They are recorded, not hidden. **No test was
weakened or deleted to reach this number.**

### In-flight uncommitted work found (MUST NOT be clobbered)

A previous session left a coherent, high-quality D13+ change set:

| File | Change |
|---|---|
| `raphael_ibm_bob/discovery_runtime.py` | NEW — governed TCP discovery mediator |
| `raphael_ibm_bob/harness/discovery_run.py` | NEW — harness discovery entry |
| `raphael_ibm_bob/contracts.py` | `Capability.NETWORK_SERVICE_DISCOVERY` |
| `raphael_ibm_bob/capability_bootstrap.py` | discovery descriptor + registration |
| `raphael_ibm_bob/broker.py` | `_execute_discovery` governed path |
| `raphael_ibm_bob/policy.py` | `_consult_discovery` authorizer, `_timeout_is_valid` |
| `raphael_ibm_bob/target_profile.py` | **`PlatformSpec` / VulnHub+VMware isolation model**, `TARGET_STAGES` |
| `raphael_ibm_bob/harness/api.py` | `start_discovery_run` |
| `raphael_ibm_bob/http/routes/htb.py`, `http/views/operations_console.py` | UI wiring |
| `tests/test_d13_discovery_workflow.py`, `test_d19_platform_authorization.py`, `test_service_discovery.py` | NEW tests |

Assessment: the `TargetProfile` change **is** the "newly implemented
VulnHub/VMware authorization model" the brief requires preserved. It makes
non-HTB platforms strictly *more* restrictive (explicit isolated environment
required) and keeps HTB behaviour unchanged. Test diffs are additive
(capability count 2→3, allow-list additions) — **no test weakened**.

**Conflict risk:** `policy.py`, `broker.py`, `contracts.py`, `target_profile.py`
are core-governance files. The LLM work must be **additive and must not
rewrite** them.

### Test diff integrity check (PASS)

Only additive changes: `len(log) == 2 → 3`, allow-list `+network_service_discovery`,
matrix `+ServiceDiscovery`, prerequisite-authorization indirection. No assertion
was deleted, loosened, or xfailed.

---

## ROUNDS 02–27 — THE ARCHITECTURE ALREADY EXISTED

The single most important finding of Batch A: **the AI-assisted governed loop
was already implemented.** Building a new `LLMProvider` would have violated the
"Do NOT duplicate an existing capability" stop condition.

### What already exists (verified in source, not assumed)

| Layer | Location | Status |
|---|---|---|
| LLM seam | `harness/model.py:60` `ModelAdapter.propose(ModelContext) -> ActionRequest` | pre-existing |
| Deterministic double | `harness/model.py:73` `ScriptedModelAdapter` (raises `KeyError` on exhaustion) | pre-existing |
| Real provider | `harness/providers/openai_compat.py` `OpenAICompatAdapter` / `config_from_env` / `provider_from_env` | pre-existing |
| Provider factory | `harness/api.py:111` `make_model_adapter()` | pre-existing |
| **Governed propose→submit** | `harness/run.py:222-223` `proposal = model.propose(context)` → `runtime.submit(proposal, mission)` | pre-existing |
| Bounded loop | `harness/model_run.py:65` `DEFAULT_MAX_TURNS = 14` | pre-existing |
| Governance | `broker.py:293` policy consult → `:337` DENY short-circuit, no execution | pre-existing |
| Evidence | `evidence_ledger.py` + `seal.py` hash chain | pre-existing |
| Sole authority | `quality_gate.py` `BOBQualityGate` → COMPLETE/REFUSE | pre-existing |
| Regression gate | `model_run.py:396` `regression_ok=tests_ok` (measured via `passing_run_tests(ledger)`) | pre-existing |

`provider_runtime.py` is **not** an LLM abstraction — it is the out-of-process
C1A *capability* boundary. Do not extend it for model use.

### Verified gate results

`regression_ok` is a **caller-supplied parameter** (`quality_gate.py:93`,
required, no default) — the gate does NOT hardcode it, and independently
cross-checks conditions B and C, so a hardcoded `True` cannot alone yield
COMPLETE. Production callers compute it. **Demo callers hardcoded it** →
assigned to Model 5 (fix in progress).

### Target-agnosticism: VERDICT TARGET-AGNOSTIC

Zero functional coupling. Two low-severity cosmetic notes recorded, not fixed:
`telnet_runtime.py:270` names HTB machine "Meow" in a comment only;
`network_runtime.py:58` hardcodes the `HTB{...}` flag format (platform-family,
not machine-specific). Guard tests already exist:
`test_d19_platform_authorization.py` forbids kioptrix/kioptix/metasploitable in
product source; `test_d13_capability_fabric.py` forbids `target ==` branches
and `10.129.` literals in `capability_selector.py`.

---

## CHANGES MADE BY MODEL 0 (integrator-owned files only)

### F1 — `broker.py`: fail-closed non-finite timeout (VERIFIED DEFECT, FIXED)

`submit()` used `timeout <= 0`, which is `False` for NaN and ±inf. Policy's
correct `_timeout_is_valid` was wired only into the network/telnet/discovery
authorizers, so path-scoped capabilities (READ/LIST/SEARCH/WRITE/RUN_TEST) and
C1A would stamp a non-finite deadline onto the request and into the ledger.
Fixed once at the single governed entrypoint so it covers every capability.
**Evidence: 0 holes across 42 combinations (7 invalid values × 6 capabilities);
valid values (`None`, 0.5, 2, 5, 30) still accepted; 217 regression tests pass.**

### F2 — `harness/model_run.py`: AI-assisted runs wrote NO evidence seal (FIXED)

`network_run.py` seals on both exit paths; `model_run.py` had **zero** seal
calls, so `verify_seal()` returned `(False, "missing-seal")` for every
model-led run — the AI-assisted path lacked the tamper-evident chain the
network path has. Added `_try_write_seal()` mirroring the existing
`network_run` helper, called after both `ledger.close()` sites.

**Evidence (real run, not asserted):**
```
fresh model run            -> (True, 'seal-ok')
result records deleted     -> (False, 'record-count-mismatch:sealed=7 observed=6')
ledger order reversed      -> (False, 'head-mismatch:ledger-modified-reordered-or-deleted')
236 harness/evidence/gate tests pass
```

### F3 — `_execution_context` never cleared: DOCUMENTED, NOT CHANGED

`broker.py:352` sets it, `:366` reads it, never reset. A caller already holding
`broker._registry` could invoke `_BrokerAdapter.execute_governed()` with a
forged ALLOW and stale sequence numbers. **Deliberately not patched:** it
requires arbitrary in-process Python execution, which already implies total
compromise via the package-root `execute_capability` export (a documented
separation-of-concerns design). Fixing it adds churn to a security-critical
file for no boundary gain. Recorded as P2 hardening.

### F4 — WRITE has no file-type guard: DOCUMENTED, NOT CHANGED

`_authorize_write` checks only resolution/dir/parent; mission-scope
containment is the sole guard, so a WRITE inside scope could target
`policy.py`. Changing authorization semantics risks the HTB/VulnHub behaviour
the brief requires preserved. Recorded as P1 hardening for operator decision.

---

## ROUND 27 — FULL MOCK END-TO-END RUN (REAL, MEASURED)

`run_model_mission` with `ScriptedModelAdapter`, 3 turns, real workspace:

```
run_id        : 20260926T082855_7485af
run state     : refused          gate verdict : refuse
turns         : 3                terminal     : max-turns (bounded)
ledger        : 17 records = {request:3, decision:3, result:3, evidence:7, gate:1}
gate reasons  : 'regression_ok=False (caller did not prove regression)',
                'regression_ok=False',
                'behavior_probe_ok=False (no probe proof supplied)'
seal          : (True, 'seal-ok')
```

The refusal is **correct and honest**: no independent behaviour probe was
supplied and the test did not pass. `RUN_TEST` did execute under bubblewrap
(`sandboxed: true`, `network_isolated: true`) but the fixture collected 0 tests
(pytest `returncode=5`), so the gate refused rather than claiming success.
Pre-existing behaviour; not introduced here and not masked.

---

## ROUND 02+ — STATUS

| Round | Objective | Status |
|---|---|---|
| 01 | Baseline | ✅ COMPLETE |
| 02 | Architecture trace | ✅ Model 1 complete |
| 03 | LLM integration audit | ✅ **Provider abstraction already exists — reuse** |
| 04 | Provider seam design | ✅ N/A — seam already present, reused as-is |
| 05 | Parallel architecture review | ✅ Models 1/4/5/7 reconciled vs source |
| 06 | Decision schema | ✅ N/A — `ActionRequest` reused, no duplicate model |
| 07 | Decision validation trace | ✅ Model 4 mapped every enforcement point |
| 08 | API key configuration | ✅ pre-existing env-based, no secrets |
| 09 | First LLM adapter | ✅ pre-existing `OpenAICompatAdapter` |
| 10 | Model mock test | ✅ pre-existing `ScriptedModelAdapter` |
| 11 | Context builder | ✅ pre-existing `ModelContext` |
| 12 | First AI-assisted loop | ✅ pre-existing `harness/run.py:222` |
| 13 | Result feedback | ✅ pre-existing (`recent_turns`, evidence_count) |
| 14 | Multi-step bounded loop | ✅ `DEFAULT_MAX_TURNS = 14`, verified bounded |
| 15 | Authorization test | 🔄 Model 8 writing acceptance suite |
| 16 | Out-of-scope target test | 🔄 Model 8 |
| 17 | Invalid capability test | 🔄 Model 8 |
| 18 | Malformed model output | 🔄 Model 8 (+ F1 hardening) |
| 19 | Failure feedback | 🔄 Model 8 |
| 20 | Falsification | ✅ pre-existing gate is sole authority |
| 21 | Evidence integration | ✅ **F2 fixed** — model runs now sealed |
| 22 | Harness integration | ✅ pre-existing `start_model_run` + run-* commands |
| 23 | Regression gate (`regression_ok`) | 🔄 Model 5 fixing demo call sites |
| 24 | Target agnosticism audit | ✅ **TARGET-AGNOSTIC** |
| 25 | Platform matrix | ✅ `PlatformSpec` verified (in-flight work) |
| 26 | Two-target simulation | 🔄 Model 8 |
| 27 | Full mock E2E run | ✅ **COMPLETE — real trace above** |
| 28 | Real-model smoke test | ✅ **BLOCKED — credentials unavailable** (verified: no env vars, no `.env`, no endpoint; code fails closed naming missing vars; no key requested or invented) |
| 29 | Submission hardening | ✅ secret scan clean; no target coupling; 1941 passed / 4 pre-existing |
| 30 | Final independent review | ✅ delivered in `AI_ASSISTED_READINESS_REPORT.md` |

---

## FINAL SUBMISSION HARDENING PHASE

Architecture **FROZEN**. No redesign, no new provider abstraction, no new
capabilities, no autonomous-behaviour claims. Eight independent specialists
launched in parallel, each owning exactly one report (no shared files):

| Model | Owns | Mandate |
|---|---|---|
| 1 | `reports/SUBMISSION_DEMO.md` | Demo acts A/B/C/D, runnable + credential-free |
| 2 | `reports/REAL_PROVIDER_SMOKE_TEST.md` | Provider path, credential-leak audit, BLOCKED status |
| 3 | `reports/WRITE_GUARD_REVIEW.md` | P1 WRITE file-type guard — **recommend only, no product edits** |
| 4 | `reports/FINAL_TEST_MATRIX.md` | Independent re-measurement + proposed path-fix diff |
| 5 | `reports/TARGET_AGNOSTICITY_FINAL.md` | Final coupling audit + three-target probe |
| 6 | `reports/EVIDENCE_FINAL.md` | Seal verification + 4 tamper cases incl. in-place edit |
| 7 | `reports/SUBMISSION_NARRATIVE.md` | Judge-facing narrative, no invented metrics |
| 8 | `reports/REPOSITORY_HYGIENE.md` | Read-only secret/dirty/artefact audit |

**Integration rule:** no specialist recommendation is applied blindly. Model 3's
WRITE-guard recommendation is a *proposal*; Model 0 decides. Model 4's path-fix
is a *diff in a report*; Model 0 applies only if it does not change test intent.

### Process note — a lesson worth keeping
An intermediate full-suite run during the previous batch reported **18 failures**.
That reading was **wrong**: the tree was being modified by another agent while the
suite ran, and the same test passed in isolation. Concurrent test execution across
agents that share a working tree produces false regressions. Final numbers are only
trustworthy from a run on a stable tree — which is why the final matrix is taken
after Batch 1 drains.

### Final measured state (stable tree)
```
1941 passed, 4 failed, 1 skipped, 4 xfailed, 236 subtests in 168.92s
baseline (R01): 1921 passed, 4 failed, 183 subtests
delta: +20 new tests, 0 new failures
```
The 4 failures are the identical pre-existing hardcoded-path test bugs
(`/home/yaser/raphael-2.0-rbsv2r/...`). Never hidden, skipped, xfailed or weakened.

---

## 30-ROUND RE-EXECUTION: HONEST ROUND MAPPING

Most rounds were already completed and measured earlier in this session.
Re-running them would be rediscovering known facts, which the operating rules
forbid. Mapping each round to its actual evidence, and executing only the gaps:

| Round | Status | Evidence |
|---|---|---|
| 01 baseline | DONE | 1921→1941 measured; 4 pre-existing isolated |
| 02 model seam | DONE | `ModelAdapter.propose`; no duplicate abstraction needed |
| 03 model→broker | DONE | `AuthorizedProposalReachesBroker` |
| 04 policy audit | DONE | denial catalogue enumerated from source |
| 05 malformed output | DONE | `MalformedModelOutputRejected` + F1 fix |
| 06 out-of-scope | DONE | `OutOfScopeTargetDenied` |
| 07 target agnosticity | DONE | verdict TARGET-AGNOSTIC |
| **08 VulnHub/VMware** | **DONE THIS PASS** | probe below |
| 09 failure feedback | DONE | `FailureFeedsNextDecision` + Demo C |
| 10 bounded execution | DONE | `LoopIsBounded`; `DEFAULT_MAX_TURNS=14` |
| 11 quality gate | DONE | `ModelCannotSelfCertify` + Demo D |
| 12 falsification | DONE | gate cross-checks B/C/D independently |
| 13 evidence seal | DONE | tamper delete+reorder detected |
| **14 provider failure** | **THIS PASS** | delegated |
| 15 mock provider | DONE | `ScriptedModelAdapter` credential-free |
| 16 real-provider readiness | DONE | BLOCKED — credentials unavailable |
| **17 capability boundary** | **THIS PASS** | delegated |
| 18 WRITE safety | DONE | DEFER — default scopes make it non-exploitable |
| 19 in-process security | DONE | `_execution_context` documented, out of LLM threat model |
| **20 test integrity** | **THIS PASS** | delegated |
| 21 full matrix | DONE | 1941/4 measured |
| **22 demo reproducibility** | **DONE THIS PASS** | 5/5 identical |
| 23 secret hygiene | DONE | scan clean |
| 24 repo hygiene | DONE | large binaries untracked; `=1`/`=430` removed |
| 25 narrative | DONE | `reports/SUBMISSION_NARRATIVE.md` |
| 26 screen path | DONE | `reports/SUBMISSION_DEMO.md` |
| **27 adversarial review** | **THIS PASS** | delegated (hostile reviewers) |
| 28 real model smoke | DONE | BLOCKED — correct, not fabricated |
| 29 final integration | DONE | integrator-only merge |
| **30 final reproducibility** | **THIS PASS** | `FINAL_READINESS_REPORT.md` |

### R08 — VulnHub/VMware authorization strictness (MEASURED)

Non-HTB is **strictly more restrictive** than HTB, and no isolation leak exists:

```
platform families : ('htb', 'vulnhub', 'vmware')
isolated envs     : ('isolated-lab', 'isolated-lab-net', 'host-only-lab')
  htb       default_env=htb           requires_isolation=False
  vulnhub   default_env=isolated-lab  requires_isolation=True
  vmware    default_env=isolated-lab  requires_isolation=True

vulnhub, no environment        -> REFUSED (requires explicit isolated environment)
vmware,  no environment        -> REFUSED
vulnhub, environment='htb'     -> REFUSED  (cannot borrow HTB's leniency)
vmware,  environment='htb'     -> REFUSED
vulnhub, 'isolated-lab'        -> AUTHORIZED env=isolated-lab
vmware,  'isolated-lab'        -> AUTHORIZED env=isolated-lab
htb,     no environment        -> AUTHORIZED env=htb        (no HTB regression)
direct TargetProfile(platform='vulnhub', environment='htb') -> REFUSED (__post_init__)
unknown platform               -> REFUSED (unsupported platform)
```

### R22 — Demo reproducibility (MEASURED)

`reports/assistant_demo.py` run 5 consecutive times: **exit 0 every time,
semantic fingerprint identical 5/5.** The invariants a judge sees are stable:
`ALLOW/reason=ok`, both `DENY` reasons, `capability invocations: 0`,
`success=False` on the failing turn, `evidence_count=5` handed to turn 2,
`gate verdict: REFUSE`, `evidence seal: verified=True (seal-ok)`.

---

## STOP CONDITIONS — STATUS: none triggered

- [x] no two agents editing the same critical architecture
- [x] authorization not weakened (in-flight change makes non-HTB stricter)
- [x] Broker not bypassed
- [x] no secrets in source (`.env.example` holds empty placeholders only)
- [x] no target-specific logic introduced by this session
- [x] no tests relaxed — 4 pre-existing failures recorded, not hidden
- [x] no unbounded model loop (not yet introduced)
