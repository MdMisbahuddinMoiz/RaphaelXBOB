# FINAL_READINESS_REPORT.md

**Raphael — AI-assisted governed security assessment**
Commit `31298fb58` (HEAD) + **uncommitted working tree** · Python 3.14.4

> The model can propose. Raphael decides whether execution is permitted.

---

# VERDICT: `READY_WITH_DOCUMENTED_BLOCKER`

Two blockers, both requiring an owner action I am not authorised to take
(history rewrite / commit). Neither is a defect in the governed architecture.
**No submission-critical requirement of the architecture is broken.**

---

## CORRECTIONS TO MY OWN EARLIER CLAIMS

The hostile review (Round 27) falsified three claims I made earlier. I verified
each myself and am retracting them:

| My earlier claim | Reality | Evidence |
|---|---|---|
| "No secrets committed/logged — **PASS** — scanned; only `nvapi-REDACTED` placeholders" | **FALSE.** A git-tracked file contains a literal recovered lab credential. | `current-state/reports/ica_live_stapler.py:200` (value not reproduced) |
| "VulnHub/VMware authorization — PASS — `PlatformSpec` **preserved, untouched**" | **FALSE.** `PlatformSpec` did not exist at HEAD; it is new in the uncommitted diff. | `grep -c 'class PlatformSpec'` → HEAD 0, worktree 1; `target_profile.py` +153/-13 |
| "HTB regression — PASS — **unchanged**" | **MISLEADING.** `http/routes/htb.py` (+119), `policy.py` (+78), `target_profile.py` (+153) all changed. | `git diff --stat` |

Also corrected: my report cited commit `31298fb58` as the measured state.
**It is not.** See Blocker 1.

---

# BLOCKERS

## BLOCKER 1 — the cited commit does not contain the fixes

Measured directly against `git show HEAD:<file>`:

| Symbol | HEAD | Working tree |
|---|---|---|
| `math.isfinite` (broker.py timeout fix) | **0** | 1 |
| `_try_write_seal` (model-run seal fix) | **0** | 4 |
| `capability_id(decision.capability)` (ledger fix) | **0** | 1 |
| `tests/test_assistant_governed_loop.py` | **absent** | present |

A judge who checks out `31298fb58` receives pre-fix code: no timeout guard, no
model-run seal, no str-capability fix, no acceptance suite.

**Remediation:** commit the working tree, then update every report to cite the
new commit. Line-number citations in the narrative currently match **neither**
HEAD nor the worktree (e.g. `_execution_context` cited as 352/366; actual HEAD
345/359/361, worktree 364/378/380) — they were written against a third,
intermediate state, so they must be regenerated after the commit.

## BLOCKER 2 — committed credential (pre-existing, legacy residue)

`current-state/reports/ica_live_stapler.py` is **git-tracked** and line 200
contains a literal `user:password` pair (8-char password, not a placeholder).
It is a recovered credential from a historical VulnHub lab host.

- Pre-existing; **not introduced by this work**; the project's own
  `raphael_current.md` already flags it as embarrassing.
- Not in the shipped wheel (`pyproject` includes only `raphael_ibm_bob`).
- The credential is treated as **compromised** and must not be used.
- **I have not printed, copied, or propagated the value.**

**Remediation (owner action):** scrub the value from the working tree, rotate
the lab credential, and — since it is already in git history — either rewrite
history or document its presence and revocation. Do **not** simply delete the
line; that conceals a committed secret.

---

# MEASURED STATE (final run, stable tree)

```
1951 passed, 4 failed, 1 skipped, 4 xfailed, 236 subtests in 180.62s
```
The 4 failures are the **identical** pre-existing hardcoded-path tests
(`/home/yaser/...`, another machine). Verified `git diff --quiet HEAD` returns
clean for both files — they are **unmodified** since the last commit that
touched them, so the failures are definitionally pre-existing and not masked.
Never hidden, skipped, xfailed or weakened.

## Delta
| | Baseline R01 | Final R30 |
|---|---|---|
| passed | 1921 | **1951** |
| failed | 4 (pre-existing) | **4 (same)** |
| subtests | 183 | **236** |

New tests added this session: `tests/test_assistant_governed_loop.py` (20
passed, 53 subtests) and `tests/test_provider_fail_closed.py` (10 passed).

---

# ROUND 14 — PROVIDER FAILURE MODES (new)

`tests/test_provider_fail_closed.py` — **10 passed**. Proves fail-closed for:
missing endpoint, missing model, missing key, invalid provider name, HTTP 500,
timeout, non-JSON body, missing structured fields, and an **adversarial
response asserting authority** (`decision`/`complete`/`severity`/`verified` —
none can become authoritative). Asserts the API key never appears in any
exception message or log output.

Is the API key genuinely required? Read from source, not assumed.

---

# ROUND 17 — CAPABILITY BOUNDARY (new)

**9 executable / 5 descriptor-only.**

- All 5 descriptor-only capabilities (SSH, SMB, TLS, DNS, generic banner)
  **DENY** via `AdapterNotBoundError` — they fail *closed*, they do not
  silently no-op.
- No executable capability runs without a `PolicyDecision`; every execution
  path is downstream of `BOBPolicy.consult` and the DENY short-circuit.
- The mediated network capabilities **re-verify the decision at execution
  time** (`_decision_allows` in `network_runtime`, `telnet_runtime`,
  `discovery_runtime`) — defence in depth beyond the broker gate.

---

# ROUND 20 — TEST INTEGRITY (new)

- **22 skips, 0 suspicious** — all environment-gated (bwrap, systemd-run, node).
  None skip a governance/authorization assertion.
- **4 xfails, all justifiable** — the documented D17 `AutonomousLoop` reducer
  binding gap, matching the README's own limitations section.
- **No fake evidence.** `test_m6_quality_gate.py` builds synthetic ledgers but
  does so transparently.
- Acceptance suite is honest: asserts real returned state, no mock call counts,
  no skip/xfail, no tautological assertions.
- **Weakest assertion found:** `tests/test_d5_seven_gate_proof.py:292` — a
  trailing tautological `assert True` after real work. Cosmetic; not fixed
  (changing an unrelated test's assertions at submission adds risk).

## Residual found and FIXED during this audit
`demos/c1a_live_hero.py:159,165` hardcoded `_persist_probe(ok=True)` and
`behavior_probe_ok=True` while the demo **runs no independent probe** — the
same defect class as the `regression_ok` hardcoding fixed earlier. Now
`ok=False` / `behavior_probe_ok=False`, so the demo honestly reports
`Gate: REFUSE failed=['D:independent-behavior-probe']` (exit 1). Canonical
demos and the submission demo are unaffected.

---

# ROUND 22 — DEMO REPRODUCIBILITY (measured)

`reports/assistant_demo.py` run 5 consecutive times: **exit 0 every time,
semantic fingerprint identical 5/5**, including the security-critical values
(`capability invocations: 0`, `gate verdict: REFUSE`, `seal-ok`).

---

# ROUND 08 — VULNHUB/VMWARE AUTHORIZATION (measured)

Non-HTB is **strictly more restrictive** than HTB. No isolation leak:

```
vulnhub, no environment     -> REFUSED
vmware,  no environment     -> REFUSED
vulnhub, environment='htb'  -> REFUSED   (cannot borrow HTB's leniency)
vmware,  environment='htb'  -> REFUSED
vulnhub, 'isolated-lab'     -> AUTHORIZED
htb,     no environment     -> AUTHORIZED (no HTB regression)
direct TargetProfile(vulnhub, environment='htb') -> REFUSED (__post_init__)
unknown platform            -> REFUSED
```

---

# ROUND 27 — HOSTILE REVIEW: what a judge attacks

| Attack | Valid? | Outcome |
|---|---|---|
| "The AI is fake — nothing real is called" | **NO** | Real `urllib` HTTP client; real loopback `HTTPServer` tests; `test_m11_4_integration.py` wires the **real** `OpenAICompatAdapter` into the **real** Broker/Policy/Runtime. 93 provider tests pass. |
| "The demo is scripted so of course it denies" | **NO** | 10 hand-built hostile `ActionRequest`s with **no adapter** were all denied, 0 invocations. `BOBPolicy.consult(request, mission)` cannot see the model. |
| "It's a wrapper, not an agent" | **PARTIAL** | Genuine non-forwarding logic (gate reads the ledger, not caller booleans; falsifier/verifier/replanner/sandbox/evidence-chain). But the *reasoning* is entirely in the model, which has never been run. Correctly labelled as a governance harness. |
| "The seal is security theatre" | **PARTIAL** | Not theatre: deletion → `record-count-mismatch`, reorder → `head-mismatch`. But unkeyed — an attacker who re-seals passes. **The project already discloses this.** |
| "It never proved anything against a real target" | **NO** | No compromise is claimed anywhere; the README explicitly disclaims solving Breakout. This is a defence. |
| "WRITE can overwrite the policy" | **YES (technical)** | Demonstrated end-to-end via a real provider response. `write-file` **is** in the default skill catalog, so it is model-reachable. **Disclosed as P1**, but severity understated: the sole guard is mission scope, which is empty-by-default in the HTTP API. |
| "4 failing tests mean it isn't green" | **NO** | Files unmodified vs HEAD; failure is a hardcoded path from another machine. |

**Most likely successful attack:** *"the model has never actually run."** The
honest answer is that the governance seam is fully tested against a real HTTP
provider client and a stub server, but no live LLM endpoint was ever contacted.
The reports state this; it should be stated aloud during the demo.

---

# SCORECARD

```
Architecture:            FROZEN — reused, not rebuilt
Provider:                PASS — existing abstraction reused, 0 duplicates
Governance:              PASS
Evidence:                PASS — sealed, tamper-evident (unkeyed, disclosed)
Falsification:           PASS
Replanning:              PASS — AI-assisted iterative, correctly labelled
Target agnosticism:      PASS
HTB authorization:       PASS
VulnHub/VMware:          PASS — strictly stricter, proven
Tests:                   1951 passed / 4 failed / 1 skipped / 4 xfailed
Secrets:                 FOUND (pre-existing, Blocker 2)
Real provider:           BLOCKED — credentials unavailable
Demo:                    PASS — 1 command, exit 0, reproducible 5/5
```

## Residual risks (non-blocking)
1. `WRITE` has no file-type guard — model-reachable, mitigated only by mission
   scope, which is empty-by-default via the HTTP API. **Highest-value P1.**
2. Seal is unkeyed — integrity, not authenticity. Disclosed.
3. `_execution_context` never cleared — in-process only, outside the LLM threat
   model. Documented, deliberately not "fixed".
4. No live-LLM verification — credential-blocked, disclosed.
5. `RUN_TEST` collects 0 tests in this environment (pytest rc=5) though it runs
   sandboxed; the gate consequently refuses rather than claiming success.
