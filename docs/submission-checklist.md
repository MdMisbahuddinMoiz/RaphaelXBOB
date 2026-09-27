# RAPHAEL — SUBMISSION CHECKLIST

**HEAD**: `beef7ef37` · **Branch**: `hackathon/bob-assisted-raphael` · **Python**: 3.14.4
**Product**: `raphael_ibm_bob/` — stdlib-only, no third-party runtime dependencies.

Status vocabulary: **VERIFIED** (physically executed on the current tree) ·
**DOCUMENTED** (written, accuracy tied to a verification step) ·
**NOT VERIFIED** (not yet proven) · **BLOCKED** (cannot proceed here).

> This checklist summarises what the other four submission documents establish:
> `reports/TEST_INTEGRITY_AUDIT.md` (integrity facts), `reports/FINAL_TEST_MATRIX.md`
> (measured test state), `reports/SUBMISSION_NARRATIVE.md` (product story), and
> `docs/HACKATHON_DEMO.md` (demo procedure). Items marked **[2026-09]** were verified
> during earlier sessions and are carried forward; items marked **[2026-09-27]** were
> re-verified for this submission pass.

---

## 1. Repository state

- [x] **VERIFIED [2026-09-27]** — working tree has **zero modified tracked files**.
      `git diff --stat` is empty. Every remaining `git status --short` entry is `??`
      (untracked) and is deliberately excluded from the product history: audit scratch
      (`AUDIT_AGENT_*.md`, `FINAL_RAPHAEL_READINESS_AUDIT.md`, `raphael_current.md`),
      scratch output (`*_output.txt`, `r1.sh`), scratch scripts (`audit_*.py`,
      `verify_security.py`, `reports/_*.py`), and `training/` (Kioptrix demo material).
- [x] **VERIFIED [2026-09-27]** — the chat feature, the two integrity fixes and the
      provider admission are committed as a clean semantic history:
      `8df8b6f39` → `3150a3060` → `9bb6d095c` → `6009afbc6` → `0ebb9f389`.
- [x] **VERIFIED [2026-09]** — no generated artifacts committed: `runs/*` (except tracked
      `runs/.gitkeep`), `metrics.json`, `sessions/` are git-ignored and absent from
      `git ls-files`. Re-confirmed [2026-09-27]: `git ls-files runs/` returns only
      `runs/.gitkeep`.
- [x] **VERIFIED [2026-09]** — no credentials committed.
- [ ] **NOT VERIFIED** — a judge-portal archive has not been produced. No archive is
      created by this pass.

---

## 2. Test state

- [x] **VERIFIED [2026-09-27]** — full suite: **2161 passed · 0 failed · 1 skipped ·
      4 xfailed · 297 subtests** in 195.24s, exit 0. This is the latest verified checkpoint.
- [x] **VERIFIED [2026-09-27]** — the 6 failures present at the start of this pass are
      **fixed, not reclassified**: 2 in the chat console (a `NameError` on an unwritten
      helper plus a missing parameter) and 4 environment-specific test-path failures.
      Journey: **6 failed / 2148 passed → 0 failed / 2161 passed**.
- [x] **VERIFIED [2026-09-27]** — the 4 `xfail`s are the documented D17 `AutonomousLoop`
      reducer gap, individually justifiable. The 1 skip is environment-dependent.
- [x] **VERIFIED [2026-09-27]** — the suite leaves committed evidence intact:
      `git diff --stat -- arena/results/raw` is empty after a full run.

- [x] **VERIFIED [2026-09-27]** — the submission archive reproduces the full suite from a
      **different** directory: 2161 passed / 0 failed from
      `/home/moiz/relocation-check/judge-build-becc9b830/repo`, not just from the source
      checkout. This was verified by extraction and execution, not assumed. *(Previously the
      artefact failed 1 test on extraction — see `reports/TEST_INTEGRITY_AUDIT.md` §6.6.)*

### Recorded test-count discrepancy

Earlier revisions of this checklist and of the README carried competing test counts
("209 tests, 0 failures", "1165 tests, 0 failures", "1183 entries") that did not match
what the suite actually reported. That **test-count discrepancy** is recorded here rather
than quietly overwritten: `README.md` now withdraws the older figures explicitly, and the
authoritative number is the one measured at this HEAD — **2161 passed, 0 failed**. Any
figure in prose that disagrees with a measured run is to be corrected, not averaged.

Per-layer counts: `reports/FINAL_TEST_MATRIX.md`.

---

## 3. Product surface

- [x] **VERIFIED [2026-09-27]** — **governed agent chat console** committed (`8df8b6f39`):
      mission/target configuration, operator chat, action proposals, policy decisions,
      execution status, evidence, timeline.
- [x] **VERIFIED [2026-09-27]** — chat is an **interaction layer over the existing governed
      runtime**, not a second execution path. No `chat → capability`, `chat → shell`,
      `chat → subprocess` or broker-bypass branch exists.
- [x] **VERIFIED [2026-09-27]** — transcript evidence is read from the run ledger
      (`runs/<run_id>/evidence.jsonl`), never reconstructed from the model's pre-action
      belief. Missing or malformed evidence renders as "no evidence produced".
- [x] **VERIFIED [2026-09]** — `POST /agent/stop` is a real server-side gate: after it,
      `/agent/message` refuses, so no new model turn and no new capability execution
      begins.
- [x] **VERIFIED [2026-09]** — operator messages are redacted on the way in, so a pasted
      credential cannot reach a provider through the chat.

---

## 4. Live demonstration

- [x] **VERIFIED [2026-09-27]** — controlled target up: `127.0.0.2:8080` and
      `127.0.0.2:2222` LISTEN; `verify_target.py` → **14/14 passed**.
- [x] **VERIFIED [2026-09-27]** — live browser → chat → governed turn, HTTP 200:
      `network_service_discovery on 127.0.0.2` → Policy `ALLOW — ok` → execution
      `Completed` → evidence `127.0.0.2: 2222, 8080 (probed 2)`.
- [x] **VERIFIED [2026-09-27]** — console renders the chat transcript with each message
      type in its own visual language, under the banner `GOVERNED · MODEL PROPOSES ONLY`.
- [x] **VERIFIED [2026-09-27]** — offline provider `local-deterministic` is admitted
      explicitly in the audit allow-list and labelled **not an AI model** (`0ebb9f389`).
- [ ] **BLOCKED in this environment** — real hosted-model run. No `RAPHAEL_MODEL_*`
      credentials and no `.env` are present. The provider fails closed and names the
      variables it needs. No credential was requested, invented, or simulated.
- [x] **VERIFIED [historical, `a7d4d1357`]** — real MiMo V2.6 Flash vertical slice:
      governed discovery → SSH execution → evidence-driven replanning → user-to-root.
      Real, and not reproduced by this environment.
- [x] **VERIFIED [2026-09-27]** — **Kioptrix Level 1 — VERIFIED TARGET / GOVERNED
      RECONNAISSANCE.** Live VulnHub VM: boot, network reachability, honest `vulnhub`
      declaration, governed service discovery with ledger-backed evidence
      (`127.0.0.1: 2222, 8080`), governed HTTP request executed through Broker → Policy,
      scope/port/protocol denial behaviour verified, live run seal verified.
- [ ] **NOT VERIFIED** — Kioptrix **autonomous compromise: NOT demonstrated. Root access:
      NOT achieved.** Execution stops at the `ssh-no-session-spec` authorization boundary
      (intentional; requires an explicitly declared SSH session specification, not a Policy
      defect). The wider chain requires an exploitation capability not currently present.
      Autonomous AI reasoning on Kioptrix: NOT demonstrated with the offline provider.

---

## 5. Governance

- [x] **VERIFIED [2026-09]** — no direct capability invocation: `execute_capability` is
      imported/called only by `broker.py` (plus the package re-export).
- [x] **VERIFIED [2026-09]** — model authorisation precedes provider construction; a
      rejected model id never reaches a provider, the Broker, or Policy.
- [x] **VERIFIED [2026-09]** — no target is authorised implicitly: a declared
      `TargetProfile` is required, naming host, ports and protocols.
- [x] **VERIFIED [2026-09]** — verdict comes from the QualityGate record
      (`kind="gate"`, `decision="complete"`), not from process exit. `COMPLETE` cannot be
      emitted by a caller, a provider, or the model.
- [x] **VERIFIED [2026-09]** — the model cannot self-certify: the gate refuses even when a
      caller claims success, because the evidence is absent.
- [x] **VERIFIED [2026-09]** — target-agnostic: guard tests forbid target-specific strings
      (`kioptrix` / `kioptix` / `metasploitable`) in product source, and the guard passes.

---

## 6. Evidence and auditability

- [x] **VERIFIED [2026-09]** — durable runs: `runs/<run_id>/{evidence.jsonl, artifacts/}`,
      unique per execution.
- [x] **VERIFIED [2026-09]** — evidence is reconstructable from disk without console
      narration.
- [x] **VERIFIED [2026-09-27]** — seal verification detects tampering and deletion
      (head-mismatch / record-count-mismatch) on **every** governed run path.
      **The seal is unkeyed** — it proves integrity against accidents and edits, not
      against an attacker with write access to `runs/`.
- [x] **VERIFIED [2026-09]** — artifacts resolve; no missing/malformed evidence.
- [x] **VERIFIED / CLOSED [2026-09-27]** — tamper-evidence on every run path. Previously
      NOT VERIFIED: `harness/run.py::start_run` and `harness/telnet_run.py` closed their
      ledgers without writing a seal, so those two paths lacked chain-level
      delete/reorder detection. **Resolved in `beef7ef37`.** Proven by
      `tests/test_run_path_sealing.py`: intact run verifies, deleting a record invalidates,
      reordering records invalidates, and a missing seal stays `missing-seal`. The tests
      were reproduced failing 4/4 before the fix. *(Carried from `AUDIT_AGENT_6_TESTS.md`
      finding F-2; closed this pass.)*

---

## 7. Test integrity — resolved defects

All four were found by executing the system, and all are fixed. None was hidden, skipped,
xfailed, or reclassified. Detail in `reports/TEST_INTEGRITY_AUDIT.md` §6.

- [x] **RESOLVED `3150a3060`** — test code embedded an absolute repository path from
      another machine, failing 4 tests on any other checkout.
- [x] **RESOLVED `9bb6d095c`** — the test suite destroyed committed ablation and
      negative-control evidence on every run (3682 lines across 13–14 files), because
      `run_id` is deterministic and the runner wrote into a CWD-relative path.
- [x] **RESOLVED `6009afbc6`** — chat message ids came from a process-local counter that
      reset on restart, reissuing ids the durable transcript already held.
- [x] **RESOLVED `0cbcd263f`** *(historical)* — `demos/c1a_live_hero.py` no longer claims a
      behaviour probe it does not run.
- [x] **RESOLVED `beef7ef37`** — `start_run` and `run_telnet_mission` closed their ledgers
      without writing `seal.json`, leaving those two paths without chain-level
      delete/reorder detection. Both now seal after final evidence persistence on both
      exits, mirroring the network and model paths.

---

## 8. Documentation

- [x] **VERIFIED [2026-09-27]** — `reports/TEST_INTEGRITY_AUDIT.md` — integrity facts,
      resolved defects, skip/xfail/assertion analysis.
- [x] **VERIFIED [2026-09-27]** — `reports/FINAL_TEST_MATRIX.md` — measured test state and
      per-layer verification counts.
- [x] **VERIFIED [2026-09-27]** — `reports/SUBMISSION_NARRATIVE.md` — product story, with
      PROVEN / NEXT DEMONSTRATION separated.
- [x] **VERIFIED [2026-09-27]** — `docs/HACKATHON_DEMO.md` — 3-minute browser runbook.
- [x] **VERIFIED [2026-09-27]** — `docs/submission-checklist.md` — this file.

---

## 9. Not shipped, deliberately

Excluded from the product history on purpose, retained locally as working material:
`AUDIT_AGENT_2..7_*.md`, `FINAL_RAPHAEL_READINESS_AUDIT.md`, `raphael_current.md`,
`full_suite_output.txt`, `test_output.txt`, `r1.sh`, `audit_provider.py`, `audit_report.md`,
`verify_security.py`, `reports/_*.py`, `training/`.

---

## 10. Release gate

Submission-ready requires every submission-critical box above to be VERIFIED. The
outstanding items are:

1. **Real hosted-model demonstration** — BLOCKED on a credential in this environment.
2. **Kioptrix autonomous compromise / root** — NOT VERIFIED; target and governed
   reconnaissance are verified, compromise is not.
3. **Judge-portal archive** — not produced.

Closed this pass: **tamper-evidence on all run paths** — VERIFIED as of `beef7ef37`.

None of these is claimed as done. Each is stated here so the boundary of the submission is
explicit rather than implied.
