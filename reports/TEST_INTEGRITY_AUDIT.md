# TEST INTEGRITY AUDIT — Round 20

**Repository**: `/home/moiz/raphael-2.0-rbsv2r`  
**Date**: 2026-09-26  
**Measured State**: 1941 passed, 4 failed, 1 skipped, 4 xfailed, 236 subtests  
**Collect Count**: 1950 tests collected  
**Acceptance Suite**: `tests/test_assistant_governed_loop.py` — 20 passed, 53 subtests passed

---

## 1. SKIP ABUSE

**Total skips found**: 22 `@unittest.skipUnless` / `@unittest.skipIf` decorators across 5 test files.

| File | Line | Reason | Classification |
|------|------|--------|----------------|
| `tests/test_run_test_sandbox.py` | 79, 98, 118, 136, 178, 199, 224, 251, 266, 283, 300, 324, 358, 389, 679 | "Linux bubblewrap is required for actual isolation/fixture/root-test execution" | **LEGITIMATE** — environment-dependent (requires `bwrap` on Linux) |
| `tests/test_b4_lifecycle.py` | 440 | "real M5 producer requires systemd-run" | **LEGITIMATE** — environment-dependent (requires `systemd-run`) |
| `tests/test_d12_telnet_live.py` | 33 | "set RAPHAEL_LIVE_MEOW=1 to run the live Meow test" | **LEGITIMATE** — opt-in live test |
| `tests/test_d14_autonomy.py` | 160 | "D14 API unavailable" (import guard) | **LEGITIMATE** — missing dependency |
| `tests/test_t3mp3st_integration.py` | 210, 410, 494 | "real T3MP3ST provider + node + bwrap required" | **LEGITIMATE** — environment-dependent (requires provider checkout, Node, bwrap) |
| `tests/test_c1a_launcher_contract.py` | 41 | "node is not installed" | **LEGITIMATE** — environment-dependent |

**Suspicious skips on governance/security files**: **NONE**. No skips found on files matching `*authoriz*`, `*policy*`, `*broker*`, `*seam*`, `*governance*`, `*security*`, `*invariant*`.

**Verdict**: All 22 skips are environment-dependent and justifiable. **No skip abuse detected.**

---

## 2. XFAIL ABUSE

**Total xfails found**: 4 `@unittest.expectedFailure` decorators in `tests/test_d17_hardening.py`.

| Test | Line | Reason String | Justifiable? |
|------|------|---------------|--------------|
| `test_stale_observation_cannot_overwrite_newer_state` | 155 | (no explicit reason string; decorator only) | **YES** — Documents D17 AutonomousLoop reducer binding gap (stale `source_seq` not bound to execution evidence) |
| `test_content_mismatched_capability_cannot_change_trusted_state` | 183 | (no explicit reason string) | **YES** — Documents D17 gap: capability_id mismatch not detected by weaker reducer |
| `test_content_mismatched_target_cannot_change_trusted_state` | 191 | (no explicit reason string) | **YES** — Documents D17 gap: target host/port mismatch not detected |
| `test_injected_service_cannot_change_trusted_state` | 203 | (no explicit reason string) | **YES** — Documents D17 gap: injected service record not bound |

**Context**: These 4 xfails correspond exactly to the documented D17 hardening gap where `AutonomousLoop` folds observations through `reduce_world_state` (weaker reducer) instead of `reduce_state_transition` (stricter reducer). The gap is explicitly acknowledged in `README.md` under "Honest Limitations" and is **not** a bug that was fixed and never un-marked.

**Verdict**: All 4 xfails are genuine known limitations. **No xfail abuse detected.**

---

## 3. WEAKENED ASSERTIONS

**Total weak assertions found**: 3 instances in test files.

| File | Line | Pattern | Assessment |
|------|------|---------|------------|
| `tests/test_debug_stderr_epipe.py` | 70 | `assert True` | **LEGITIMATE** — Explicitly tests that EPIPE on stderr does not propagate; comment: "The fact we reached here means the write did not propagate; to be explicit:" |
| `tests/test_d5_seven_gate_proof.py` | 292 | `assert True, "Seven-gate proof completed"` | **SUSPICIOUS** — Tautological final assertion after substantial verification (7 gates with ID-link checks). The real assertions are the preceding checks; this final `assert True` adds no value but doesn't mask failures. |
| `tests/test_cli_smoke.py` | 605 | `pass  # ports not strictly required` | **LEGITIMATE** — Not a test body; just an empty branch in a conditional loop for services where ports are optional (tor-proxy, neo4j). |

**Other patterns checked**:
- `assert x is not None` where specific value expected: Found in several tests (e.g., `tests/test_d12_1_ledger_integrity.py`, `tests/test_d14_runtime_path.py`, `tests/e1_interactive_shell_test.py`) — all are legitimate existence checks after operations that should produce a value.
- `assert len(...) > 0`: Found in `tests/test_d5_seven_gate_proof.py`, `tests/e1_interactive_shell_test.py`, `tests/e2_shell_candidate_generation_test.py` — all check that a collection is non-empty after an operation that should produce results; legitimate.
- Bare `assert` with no meaningful check: None found beyond the two `assert True` cases above.

**Verdict**: 1 suspicious (tautological final assertion in `test_d5_seven_gate_proof.py`), 2 legitimate. **No critical weak assertion abuse.**

---

## 4. HARDCODED SUCCESS IN PRODUCT CODE

**Search scope**: `raphael_ibm_bob/` and `demos/` for `regression_ok=True`, `behavior_probe_ok=True`, `verdict="complete"`, `GateVerdict.COMPLETE` returned without evidence.

### `raphael_ibm_bob/quality_gate.py`
- Lines 16, 22, 28, 51, 335, 369: Documentation/comment references to `regression_ok=True` and `behavior_probe_ok=True` as **caller claims** that the gate validates against evidence. Not hardcoded returns.
- Line 502: `verdict = GateVerdict.COMPLETE if not failed else GateVerdict.REFUSE` — **legitimate**, verdict derived from evidence evaluation.
- Line 46: Comment warns "Constructing `GateVerdict.COMPLETE` directly in another module is..." — defensive documentation.

### `demos/canonical_hero.py`
- Line 588: `regression_ok_final = bool(test_login_ok)` — derived from measured test result
- Line 633: `regression_ok_final = bool(test_login_ok2 and test_auth_ok)` — derived from measured test results
- Line 641-642: Both `regression_ok` and `behavior_probe_ok` passed from measured variables (`regression_ok_final`, `probe_ok_final`)

### `demos/authkit_hero.py`
- Line 484: `regression_ok=(test_login_ok2 and test_auth_ok), behavior_probe_ok=probe_ok_v2` — both derived from measured results
- Line 589: `regression_ok=test_ok, behavior_probe_ok=probe_ok` — both derived from measured results

### `demos/c1a_live_hero.py`
- Line 164: `regression_ok=test_result.execution.success` — **derived from measured test result**
- **Line 165: `behavior_probe_ok=True`** — **HARDCODED LITERAL** ⚠️

**Verdict**: **One hardcoded `behavior_probe_ok=True` remains in `demos/c1a_live_hero.py:165`**. The other two demos (`canonical_hero.py`, `authkit_hero.py`) correctly derive both flags from measured test results. This is a regression in `c1a_live_hero.py` that should be fixed.

---

## 5. FAKE EVIDENCE

**Search scope**: Tests for `append_evidence(... producer="regression" ... ok=True)` patterns that could fabricate passing gate records.

### `tests/test_m6_quality_gate.py` (lines 493, 510)
- **Legitimate fixture setup**: Creates synthetic ledger records to test the QualityGate's evaluation logic.
- Test `test_allowed_breadth_without_regression_record_fails_c` appends a regression record **without** linking it to actual request/decision/result sequences → expects gate to **FAIL** condition C.
- Test `test_allowed_breadth_with_regression_record_passes_c` appends a regression record **with** proper sequence linkage → expects gate to **PASS** condition C.
- The synthetic evidence is **honest about being synthetic** — it tests the gate's ability to distinguish linked vs. unlinked evidence. No fabrication of passing records for a real gate run.

### Other test files using `append_evidence`
- `tests/test_d12_1_ledger_integrity.py`, `tests/test_operation_graph.py`, `tests/test_c1a_end_to_end.py`, `tests/test_d9_network.py`, `tests/test_d10_2_network_probe.py`, `tests/test_d16_state_transition.py`, `tests/test_d14_runtime_path.py`, `tests/test_d12_2_trust_boundary.py`, `tests/test_findings_intelligence.py`, `tests/test_d14_autonomous_episode.py`, `tests/test_d4_independent_verification.py`, `tests/test_m10_2_metrics.py`, `tests/test_m14_specialization.py`, `tests/test_m3_evidence.py`, `tests/test_m10_3_benchmark.py`, `tests/test_capability_arsenal.py`, `tests/d16_autonomous_loop_helpers.py`, `tests/test_m11_4_integration.py`
- All are **legitimate test fixture setup** — building ledgers to test downstream components (policy, broker, runtime, gate) in isolation. None construct evidence that would let a **real** gate pass falsely.

**Verdict**: **No fake evidence detected.** `test_m6_quality_gate.py` synthetic ledgers are honest test fixtures that verify the gate's evidence-validation logic.

---

## 6. ACCEPTANCE SUITE COVERAGE

**File**: `tests/test_assistant_governed_loop.py` (20 tests, 53 subtests)

### Assertions verified:
- **Real returned state**: Every test asserts on `outcome.broker_result.decision.decision`, `outcome.broker_result.capability_invoked`, `outcome.execution.success`, `outcome.execution.error`, ledger record kinds/counts.
- **No mock call counts**: Zero `mock.call_count` or `mock.assert_called` assertions.
- **No skip/xfail**: Zero `@unittest.skip*`, `@pytest.mark.skip*`, `@pytest.mark.xfail`, `@unittest.expectedFailure`.
- **No tautological assertions**: Zero `assert True`, `assert False`, `pass #` as test body.
- **Specific value assertions**: Tests check exact enum values (`Decision.ALLOW`, `Decision.DENY`), exact reason strings (`"capability-not-allowed"`, `"scope-mismatch"`), exact record counts.

### Key test classes (all honest):
1. `AuthorizedProposalReachesBroker` — verifies ALLOW decision, capability invoked, execution success, evidence chain
2. `UnauthorizedCapabilityDenied` — verifies DENY, no execution, denial recorded
3. `OutOfScopeTargetDenied` — verifies scope enforcement, no capability invocation
4. `MalformedModelOutputRejected` — verifies fail-closed on invalid proposals (ValueError)
5. `TimeoutBoundIsFailClosed` — verifies timeout validation for all 6 capabilities
6. `FailureFeedsNextDecision` — verifies failed execution recorded as unsuccessful, next context observes evidence
7. `ModelCannotSelfCertify` — verifies QualityGate refuses even when caller claims success (requires evidence)
8. `TargetAgnosticTwoTargets` — verifies different target profiles yield different decisions with same code
9. `LoopIsBounded` — verifies model loop bounded by max_turns

**Verdict**: **ACCEPTANCE SUITE HONEST: YES** — Asserts real returned state, no mock call counts, no skip/xfail, no tautological assertions.

---

## 7. PRE-EXISTING FAILURES (CONTEXT)

The 4 failures are pre-existing tests with hardcoded paths from another machine (`/home/yaser/raphael-2.0-rbsv2r/...`):

| File | Test | Line | Error |
|------|------|------|-------|
| `tests/test_budget_contract.py` | `test_runner_no_hardcoded_iteration_literal` | 36 | FileNotFoundError: `/home/yaser/raphael-2.0-rbsv2r/src/arena/ablation_runner.py` |
| `tests/test_budget_contract.py` | `test_action_budget_guard_present` | 49 | FileNotFoundError: `/home/yaser/raphael-2.0-rbsv2r/src/arena/ablation_runner.py` |
| `tests/test_evaluator_isolation.py` | `test_environment_no_global_import` | 104 | FileNotFoundError: `/home/yaser/raphael-2.0-rbsv2r/src/arena/environment.py` |
| `tests/test_evaluator_isolation.py` | `test_arena_entry_fresh_graph_fallback` | (similar) | FileNotFoundError: hardcoded `/home/yaser/...` path |

These also appear in `.pytest_cache/v/cache/lastfailed`. They are **not** gate-related and do not affect the governed product suite.

---

## FINAL VERDICT

**TEST SUITE IS HONEST** — with one minor exception.

### Summary
| Category | Finding |
|----------|---------|
| Skip abuse | **CLEAN** — 22 skips, all environment-dependent, none on governance/security files |
| Xfail abuse | **CLEAN** — 4 xfails, all document genuine D17 AutonomousLoop reducer binding gap |
| Weak assertions | **MOSTLY CLEAN** — 1 tautological `assert True` in `test_d5_seven_gate_proof.py:292` (doesn't mask failures); 2 legitimate |
| Hardcoded success in demos | **ONE ISSUE** — `demos/c1a_live_hero.py:165` has `behavior_probe_ok=True` hardcoded; other demos derive from measured results |
| Fake evidence | **CLEAN** — `test_m6_quality_gate.py` synthetic ledgers are honest test fixtures |
| Acceptance suite | **HONEST** — 20 tests assert real state, no mocks, no skips/xfails, no tautologies |

### Reasoning
The test suite genuinely tests behavior. Skips and xfails are individually justifiable (environment dependencies and documented D17 gap). The acceptance suite (`test_assistant_governed_loop.py`) is a model of honest testing — it exercises the full governed seam and asserts on real returned state. The only integrity issue is a single hardcoded `behavior_probe_ok=True` in `demos/c1a_live_hero.py:165`, which should be derived from an actual probe run like the other demos do. This does not affect the test suite itself but could mislead a demo observer.

---

## FILES READ
- `tests/test_run_test_sandbox.py` (skip decorators)
- `tests/test_b4_lifecycle.py` (skip decorator)
- `tests/test_d12_telnet_live.py` (skip decorator)
- `tests/test_d14_autonomy.py` (skip decorator)
- `tests/test_t3mp3st_integration.py` (skip decorators)
- `tests/test_c1a_launcher_contract.py` (skip decorator)
- `tests/test_d17_hardening.py` (xfail decorators)
- `tests/test_debug_stderr_epipe.py` (assert True)
- `tests/test_d5_seven_gate_proof.py` (assert True)
- `tests/test_cli_smoke.py` (pass #)
- `tests/test_m6_quality_gate.py` (synthetic evidence)
- `tests/test_assistant_governed_loop.py` (full acceptance suite)
- `raphael_ibm_bob/quality_gate.py` (GateVerdict.COMPLETE logic)
- `demos/canonical_hero.py` (regression_ok/behavior_probe_ok derivation)
- `demos/authkit_hero.py` (regression_ok/behavior_probe_ok derivation)
- `demos/c1a_live_hero.py` (hardcoded behavior_probe_ok=True)

## FILES CREATED
- `reports/TEST_INTEGRITY_AUDIT.md` (this report)

---

**SKIPS**: total=22  suspicious=0  
**XFAILS**: total=4  (each reason: D17 AutonomousLoop reducer binding gap; justifiable YES for all)  
**WEAK ASSERTIONS**: total=3  (worst: `tests/test_d5_seven_gate_proof.py:292` — tautological final `assert True`)  
**HARDCODED SUCCESS REMAINS IN demos/**: `demos/c1a_live_hero.py:165` — `behavior_probe_ok=True`  
**FAKE EVIDENCE**: NONE  
**ACCEPTANCE SUITE HONEST**: YES — asserts real returned state, no mock call counts, no skip/xfail, no tautological assertions  
**COLLECT COUNT / ACCEPTANCE SUITE COUNTS**: 1950 collected / 20 passed, 53 subtests passed  
**VERDICT**: test suite is honest — with one minor demo hardcoding issue (`demos/c1a_live_hero.py:165`)