# TEST INTEGRITY AUDIT

**Repository**: `/home/moiz/raphael-2.0-rbsv2r`
**Branch**: `hackathon/bob-assisted-raphael`
**Current HEAD**: `beef7ef37` — *fix: seal all governed run paths*
**Current measured state**: **2160 passed · 1 skipped · 4 xfailed · 0 failed · 297 subtests** (192.73s)
**Prior audit**: 2026-09-26, at `0cbcd263f` — *1941 passed, 4 failed, 1 skipped, 4 xfailed, 236 subtests*

> Measurements labelled **[2026-09-26]** are historical and describe the repository at
> `0cbcd263f`. They are retained because they establish how the defects in section 7 were
> found. They are **not** the current state. The current state is the line at the top.

---

## 1. SKIP ABUSE

**Measured [2026-09-26]**: 22 `@unittest.skipUnless` / `@unittest.skipIf` decorators across 5 test files.

| File | Line | Reason | Classification |
|------|------|--------|----------------|
| `tests/test_run_test_sandbox.py` | 79, 98, 118, 136, 178, 199, 224, 251, 266, 283, 300, 324, 358, 389, 679 | "Linux bubblewrap is required for actual isolation/fixture/root-test execution" | **LEGITIMATE** — environment-dependent (requires `bwrap` on Linux) |
| `tests/test_b4_lifecycle.py` | 440 | "real M5 producer requires systemd-run" | **LEGITIMATE** — environment-dependent (requires `systemd-run`) |
| `tests/test_d12_telnet_live.py` | 33 | "set RAPHAEL_LIVE_MEOW=1 to run the live Meow test" | **LEGITIMATE** — opt-in live test |
| `tests/test_d14_autonomy.py` | 160 | "D14 API unavailable" (import guard) | **LEGITIMATE** — missing dependency |
| `tests/test_t3mp3st_integration.py` | 210, 410, 494 | "real T3MP3ST provider + node + bwrap required" | **LEGITIMATE** — environment-dependent |
| `tests/test_c1a_launcher_contract.py` | 41 | "node is not installed" | **LEGITIMATE** — environment-dependent |

**Suspicious skips on governance/security files**: **NONE**. No skips found on files matching
`*authoriz*`, `*policy*`, `*broker*`, `*seam*`, `*governance*`, `*security*`, `*invariant*`.

**Verdict**: All 22 skips are environment-dependent and justifiable. **No skip abuse detected.**

The current full-suite run reports **1 skipped**, consistent with these decorators being
mostly conditional and not activating on this host.

---

## 2. XFAIL ABUSE

**Measured [2026-09-26] and confirmed current**: 4 `@unittest.expectedFailure` decorators in
`tests/test_d17_hardening.py`.

**Context**: These 4 xfails correspond exactly to the documented D17 hardening gap where
`AutonomousLoop` folds observations through `reduce_world_state` (weaker reducer) instead of
`reduce_state_transition` (stricter reducer). The gap is explicitly acknowledged in
`README.md` under "Honest Limitations" and is **not** a bug that was fixed and never un-marked.

**Verdict**: All 4 xfails are genuine known limitations. **No xfail abuse detected.**
The current full-suite run still reports exactly `4 xfailed`.

---

## 3. WEAK / TAUTOLOGICAL ASSERTIONS

**Measured [2026-09-26]**: 3 instances, none masking a failure.

| File | Line | Code | Classification |
|------|------|------|----------------|
| `tests/test_d5_seven_gate_proof.py` | 292 | `assert True, "Seven-gate proof completed"` | **SUSPICIOUS** — tautological final assertion after substantial verification. The real assertions precede it; it adds no value but hides nothing. |
| `tests/test_cli_smoke.py` | 605 | `pass  # ports not strictly required` | **LEGITIMATE** — not a test body; an empty branch where ports are optional. |

---

## 4. FABRICATED EVIDENCE / HARDCODED GATE VERDICTS

**Search scope**: `raphael_ibm_bob/` and `demos/` for `regression_ok=True`,
`behavior_probe_ok=True`, `verdict="complete"`, `GateVerdict.COMPLETE`.

**Verdict: CLEAN.** `quality_gate.py:502` derives
`verdict = GateVerdict.COMPLETE if not failed else GateVerdict.REFUSE` from evaluated
evidence — legitimate. No module constructs `GateVerdict.COMPLETE` directly to bypass
evaluation.

Synthetic ledger records in `tests/test_m6_quality_gate.py` and related files are honest
fixtures: they build a ledger to exercise the gate's own logic, and the tests assert that a
gate **refuses** when required evidence is absent or unlinked. They cannot make a real gate
pass falsely.

### 4.1 Demo hardcoding — **RESOLVED**

The [2026-09-26] audit recorded: *"a single hardcoded `behavior_probe_ok=True` in
`demos/c1a_live_hero.py:165`, which should be derived from an actual probe run."*

**Status: RESOLVED** (corrected in `0cbcd263f`, before the prior audit's own HEAD).
**Cause**: the demo asserted a behaviour-probe result for a probe it never executed.
**Resolution**: `demos/c1a_live_hero.py` now passes `behavior_probe_ok=False` with an
explicit comment — *"This demo exercises the governed C1A provider path only; it never runs
the independent behaviour probe, so it must not claim one"* — and derives
`regression_ok` from the measured `test_result.execution.success` of the governed `RUN_TEST`
it actually submitted.

Verified at `0ebb9f389`: `grep -nC 5 'behavior_probe_ok=True' demos/c1a_live_hero.py`
returns no match. The demo now fails closed on the probe it did not run.

The only remaining `behavior_probe_ok=True` occurrences are in **test** fixtures
(`tests/test_d10_1_network_gate.py`, `tests/test_c1a_end_to_end.py`, `tests/test_d9_network.py`),
which are legitimate synthetic gate inputs as described above.

---

## 5. ACCEPTANCE SUITE HONESTY

`tests/test_assistant_governed_loop.py` (20 tests, 53 subtests at `0cbcd263f`) asserts real
returned state — no mock call counts, no skips, no xfails, no tautological assertions — and
exercises the full governed seam (malformed model output rejected, timeout bounds fail
closed, failure feeds the next decision, and the model cannot self-certify a COMPLETE
verdict).

**Verdict: ACCEPTANCE SUITE HONEST — YES.**

---

## 6. RESOLVED INTEGRITY DEFECTS (current session)

These are recorded as **resolved defects discovered during the audit**, not as current
failures. They are the reason the current suite is green and the committed evidence is
intact.

### 6.1 Test-path portability defect
- **Status**: RESOLVED — `3150a3060`
- **Cause**: `tests/test_budget_contract.py` and `tests/test_evaluator_isolation.py` embedded
  an absolute repository path from a different machine (`/home/yaser/raphael-2.0-rbsv2r/...`),
  so 4 tests raised `FileNotFoundError` on any other checkout.
- **Resolution**: repository-root-relative resolution via
  `REPO_ROOT = Path(__file__).resolve().parents[1]`. No production code was changed.
- **Verification**: 13 targeted tests pass; the 4 failures are gone from the full suite
  rather than reclassified, skipped or xfailed.

### 6.2 Arena artifact-destruction defect
- **Status**: RESOLVED — `9bb6d095c`
- **Cause**: `AblationRunner` writes run artifacts into the CWD-relative
  `RESULTS_BASE = Path("arena/results")` (`src/arena/ablation_runner.py:157`), and `run_id` is
  deterministic by design (`(config, template, seed, split)`, no uuid suffix — asserted by
  `tests/test_run_identity.py`). Test runs therefore collided with committed run directories
  and **truncated committed ablation and negative-control evidence**, e.g.
  `abl_SCRIPTED_BASELINE_T1_NEGATIVE_CONTROL_s0042_dev/episodes.jsonl` lost 720 lines from a
  single test; a full suite run removed 3682 lines across 13–14 files.
- **Impact**: any test run — a judge's, CI's, or the operator's — silently destroyed the
  negative-control record the project's governance claims rest on. `git status` cleanliness
  was not a trustworthy integrity signal after any test run.
- **Resolution**: test-side CWD isolation. An autouse fixture
  (`monkeypatch.chdir(tmp_path)`) in the five modules that construct a runner. No change to
  arena production code.
- **Verification**: `python3 -m pytest -q` followed by `git diff --stat -- arena/results/raw`
  returns empty. Proven first in isolation, then across the full suite.

### 6.3 Chat transcript id collision
- **Status**: RESOLVED — `6009afbc6`
- **Cause**: chat message ids were allocated from a process-local module global
  (`_COUNTER`, `raphael_ibm_bob/harness/chat.py:212-221`) that was never seeded from the
  persisted transcript. After a server restart the counter reset to 0 and reissued ids the
  durable append-only log already contained — two records claiming the same handle.
- **Resolution**: `_seed_counter()` raises the global to `max(current, highest persisted
  serial)` on `ChatLog` open, under the existing lock. Id format unchanged.
- **Verification**: regression tests cover reopen-without-collision and empty-log cases.
  Confirmed across real processes: after restarting the server, the next turn continued at
  `C-USER-000011` with no collision.

### 6.4 Missing chain-level seals on two run paths
- **Status**: RESOLVED — `beef7ef37`
- **Cause**: `harness/run.py::start_run` and `harness/telnet_run.py::run_telnet_mission`
  closed their ledgers without writing `seal.json`, on both the normal and the exception
  exit. `network_run` and `model_run` already sealed, so only these two paths produced run
  dirs that verified as `(False, "missing-seal")` and lacked chain-level delete/reorder
  detection. Per-record digests still failed closed; the gap was at the chain level.
- **Resolution**: each module gained the same `_try_write_seal(run_dir)` helper the network
  and model paths already use — never raises, logs at WARNING, and is called immediately
  after `ledger.close()` on both exits, so the seal is written after the run's final
  evidence is persisted and never before. No third sealing implementation; the seal format
  and `verify_seal` semantics are unchanged.
- **Verification**: `tests/test_run_path_sealing.py` proves three states on each path —
  intact run verifies `(True, "seal-ok")`; deleting an evidence record invalidates it;
  reordering evidence records invalidates it; and a missing `seal.json` remains
  `(False, "missing-seal")`, never an implicit pass. **Reproduced before the fix: 4/4 of
  these tests failed** ("run … was not sealed"); after the fix, 4/4 passed. 51 focused
  seal/API tests pass, and the full suite is 2160 passed / 0 failed with
  `arena/results/raw` clean.
- **Note**: `tests/test_m15_1_http_api.py::RunInspection::test_L_seal` previously asserted
  that a fresh run has *no* seal — it had pinned the defect in place. It was inverted, not
  removed: it now asserts a sealed run verifies, and that deleting the sidecar degrades
  honestly to `missing-seal`.

---

## 7. PRE-EXISTING FAILURES — **[2026-09-26] HISTORICAL, NOW RESOLVED**

At `0cbcd263f` the suite had 4 failures, all from the hardcoded paths in section 6.1:

| Test | Line | Historical error |
|------|------|------------------|
| `tests/test_budget_contract.py::test_runner_no_hardcoded_iteration_literal` | 36 | `FileNotFoundError: /home/yaser/raphael-2.0-rbsv2r/src/arena/ablation_runner.py` |
| `tests/test_budget_contract.py::test_action_budget_guard_present` | 49 | same |
| `tests/test_evaluator_isolation.py::test_environment_no_global_import` | 104 | `FileNotFoundError: /home/yaser/raphael-2.0-rbsv2r/src/arena/environment.py` |
| `tests/test_evaluator_isolation.py::test_arena_entry_fresh_graph_fallback` | 112 | `FileNotFoundError: /home/yaser/raphael-2.0-rbsv2r/scripts/arena.py` |

**These are not current failures.** They were fixed in `3150a3060`. The current suite
reports **0 failed**.

---

## FINAL VERDICT

| Category | Finding |
|----------|---------|
| Skip abuse | **CLEAN** — 22 conditional skip decorators, all environment-dependent, none on governance/security files |
| Xfail abuse | **CLEAN** — 4 xfails, all documenting the genuine D17 `AutonomousLoop` reducer binding gap |
| Weak assertions | **MOSTLY CLEAN** — 1 tautological `assert True` (`test_d5_seven_gate_proof.py:292`), masks nothing |
| Hardcoded success in demos | **CLEAN** — resolved in `0cbcd263f`; `c1a_live_hero.py` now fails closed on the probe it does not run |
| Fabricated evidence | **CLEAN** — gate verdicts derived from evaluated evidence; synthetic ledgers are honest fixtures |
| Test-path portability | **RESOLVED** — `3150a3060` |
| Arena artifact destruction | **RESOLVED** — `9bb6d095c` |
| Chat transcript id collision | **RESOLVED** — `6009afbc6` |
| Acceptance suite | **HONEST** — asserts real returned state, no mocks, no skips/xfails, no tautologies |
| Full suite | **2160 passed · 0 failed** |
| Run-path sealing | **RESOLVED** — `beef7ef37` |

**VERDICT**: the test suite is honest and currently green. Four integrity defects and one
portability defect were found and resolved during this audit; each is recorded above with
its cause, its resolving commit, and how it was verified. None was hidden, skipped, xfailed
or reclassified.

---

## FILES READ
- `tests/test_run_test_sandbox.py`, `tests/test_b4_lifecycle.py`, `tests/test_d12_telnet_live.py`,
  `tests/test_d14_autonomy.py`, `tests/test_t3mp3st_integration.py`, `tests/test_c1a_launcher_contract.py`
- `tests/test_d17_hardening.py` (xfail decorators)
- `tests/test_debug_stderr_epipe.py`, `tests/test_d5_seven_gate_proof.py`, `tests/test_cli_smoke.py`
- `tests/test_m6_quality_gate.py` (synthetic evidence)
- `tests/test_assistant_governed_loop.py` (acceptance suite)
- `tests/test_budget_contract.py`, `tests/test_evaluator_isolation.py` (portability defect)
- `tests/test_run_identity.py`, `tests/test_gate_b_action_accounting.py`,
  `tests/test_repair_gate.py`, `tests/test_prompted_agent_repair.py` (arena isolation)
- `raphael_ibm_bob/quality_gate.py`, `raphael_ibm_bob/harness/chat.py`,
  `raphael_ibm_bob/harness/api.py`, `src/arena/ablation_runner.py`
- `demos/canonical_hero.py`, `demos/authkit_hero.py`, `demos/c1a_live_hero.py`
