# FINAL TEST MATRIX

**Repository**: `/home/moiz/raphael-2.0-rbsv2r`
**Branch**: `hackathon/bob-assisted-raphael`
**HEAD**: `beef7ef37` — *fix: seal all governed run paths*
**Date of measurement**: 2026-09-27

---

## FULL SUITE — CURRENT

```
2160 passed, 1 skipped, 4 xfailed, 27 warnings, 297 subtests passed in 192.73s
```

| Metric | Value |
|--------|-------|
| passed | **2160** |
| failed | **0** |
| skipped | 1 |
| xfailed | 4 |
| subtests passed | 297 |
| duration | 199.15s |
| exit code | 0 |

The 4 xfails are the documented D17 `AutonomousLoop` reducer binding gap
(`tests/test_d17_hardening.py`) — a known limitation, not a suppressed failure.

---

## DELTA — HOW THIS STATE WAS REACHED

| Checkpoint | passed | failed | skipped | xfailed | subtests |
|------------|--------|--------|---------|---------|----------|
| `a7d4d1357` (real AI vertical slice, start of session) | 2148 | 6 | 1 | 4 | 295 |
| `8df8b6f39` (chat console) — after `_latest_discovery` fix | 2150 | 4 | 1 | 4 | 295 |
| `3150a3060` (test portability) | 2154 | 0 | 1 | 4 | 295 |
| `6009afbc6` / `0ebb9f389` (id durability + provider admission) | **2156** | **0** | 1 | 4 | **297** |
| `beef7ef37` (run-path sealing) — **latest verified checkpoint** | **2160** | **0** | 1 | 4 | **297** |

- **6 → 0 failures.** The 2 chat failures were a `NameError` on an unwritten helper
  (`_latest_discovery`) plus a missing `config` parameter; the 4 remaining were
  environment-specific absolute paths in test code.
- **+2 tests, +2 subtests** from the transcript-id durability regression tests, then
  **+4 tests** from the run-path sealing tests (`beef7ef37`).
- **Zero regressions introduced** at any step.

---

## VERIFICATION LAYERS

Each layer is a `-k` selection over the same suite. **Layers overlap by design** — a single
test can exercise discovery and governance together — so these counts must not be summed.

| Layer | Selection | Result |
|-------|-----------|--------|
| Agent / chat | `agent or chat` | 121 passed, 31 subtests |
| Provider / allow-list | `provider or allowlist or audit_model` | 248 passed, 8 subtests |
| Discovery | `discovery or recon` | 109 passed |
| SSH | `ssh` | 75 passed, 33 subtests |
| Governance | `governance or policy or broker or gate or evidence or seal` | 483 passed, 4 subtests |
| Sandbox / security | `sandbox or security` | 86 passed |
| Arena integrity | `budget_contract or evaluator_isolation or run_identity or repair_gate or prompted_agent or gate_b` | 50 passed |

### Arena integrity — post-fix assertion

```
$ git restore -- arena/results/raw
$ python3 -m pytest -q
$ git diff --stat -- arena/results/raw
(empty)
```

The suite no longer mutates committed ablation and negative-control artifacts. This is the
acceptance criterion for the defect resolved in `9bb6d095c`; see
`reports/TEST_INTEGRITY_AUDIT.md` §6.2.

---

## NON-SUITE VERIFICATION (executed, not asserted)

These checkpoints are not unit tests and are proven by execution, recorded here so the
matrix is not read as "tests only".

| Checkpoint | Evidence | Status |
|------------|----------|--------|
| Live browser → chat → governed turn | `GET /agent` renders 25 004 bytes with the chat panel; 16 `.msg` elements; `GOVERNED · MODEL PROPOSES ONLY` | **PROVEN** |
| Controlled target | `/home/moiz/lab-scratch/raphael-target` — `127.0.0.2:8080` and `127.0.0.2:2222` LISTEN; `verify_target.py` **14/14 passed** | **PROVEN** |
| Governed discovery against a real target | `network_service_discovery on 127.0.0.2` → Policy `ALLOW — ok` → execution `Completed` → evidence `127.0.0.2: 2222, 8080 (probed 2)` | **PROVEN** |
| Transcript id durability across restart | server process restarted; next turn continued at `C-USER-000011` with no collision | **PROVEN** |
| Real hosted-model (MiMo) mission | `a7d4d1357` vertical slice — governed discovery → SSH → evidence-driven replanning → user-to-root | **PROVEN at `a7d4d1357`; not re-run in this environment** |
| **Kioptrix Level 1 — verified target / governed reconnaissance** | live VulnHub VM: boot, reachability, `vulnhub` declaration, governed discovery -> ledger evidence `127.0.0.1: 2222, 8080`, governed HTTP GET executed through Broker -> Policy, scope/port/protocol denials verified, live run seal verified | **PROVEN** |
| Kioptrix autonomous compromise / root | — | **NOT DEMONSTRATED** — see capability boundary below |
| Run-path chain-level sealing | all four governed run paths seal; delete/reorder of evidence invalidates; missing seal stays `missing-seal`; reproduced 4/4 failing before `beef7ef37` | **PROVEN** |

---

## PROVIDER MATRIX

| Provider | Model id | Is an AI model | Purpose | Status |
|----------|----------|----------------|---------|--------|
| OpenRouter | `xiaomi/mimo-v2.6-flash` | **YES** | real autonomous pentesting demonstration | Validated at `a7d4d1357`; credential unavailable in the current environment |
| Local deterministic | `local-deterministic` | **NO** | reproducible offline UI/governance demo, no vendor credential | Admitted explicitly in `0ebb9f389`; drives the current browser checkpoint |

Audit allow-list (`raphael_ibm_bob/harness/api.py`):
`mimo-2.6-flash`, `muse-spark-1.3`, `mimo-v2.6-flash`, `local-deterministic`.

**The offline run is not evidence of autonomous model reasoning.** The deterministic
provider returns proposals from a fixed rule table; it proves the governed path, not the
model.

---

## KNOWN LIMITATIONS (unresolved, stated plainly)

1. **Real-model credential unavailable** in the current execution environment. The provider
   code fails closed and names `RAPHAEL_MODEL_ENDPOINT` / `RAPHAEL_MODEL_NAME` /
   `RAPHAEL_MODEL_API_KEY`.
2. **Kioptrix autonomous compromise has NOT been achieved.** The target itself is verified
   (boot, reachability, declaration, governed discovery, governed HTTP). Execution stops at
   the SSH authorization boundary, and the wider Kioptrix chain additionally requires an
   exploitation capability Raphael does not currently carry. See the capability boundary
   section below.
3. **4 xfails** remain for the D17 `AutonomousLoop` reducer gap, documented in `README.md`.
4. **1 skip** is environment-dependent (sandbox/bubblewrap-class).

---

## MEASURED CAPABILITY BOUNDARY — KIIOPTRIX LEVEL 1

Probed through the real production stack (`BOBPolicy` -> `BOBBroker` -> `BOBRuntime` ->
capability -> `EvidenceLedger`) against the live VM. HTTP requests hit the VM's real
Apache; nothing was stubbed.

| Step | Result |
|------|--------|
| Governed service discovery | ALLOW, executed |
| Governed HTTP GET | ALLOW, executed |
| Undeclared port / out-of-scope host | DENY — `network-target-mismatch` |
| Undeclared protocol (Telnet) | DENY — `telnet-target-mismatch` |
| SSH target (protocol + port declared) | **DENY — `ssh-no-session-spec`** |

The SSH target **is** authorized by the `TargetProfile`. Execution stops at
`ssh-no-session-spec`: the capability requires an explicitly declared SSH session
specification before it will execute. This is an **intentional authorization boundary, not
a Policy defect.**

The wider Kioptrix attack chain additionally requires an exploitation capability that
Raphael does not currently carry: `NETWORK_HTTP_REQUEST` is GET/HEAD only, with no
arbitrary method, no target-side write, and no command execution over HTTP.

No exploitation capability was added. Autonomous compromise and root access are
**NOT demonstrated**.

---

## PRIOR PATH-FIX PATCH — NOW APPLIED

The [2026-09-26] revision of this document carried a *proposed, unapplied* patch for the
hardcoded `/home/yaser/...` test paths. It was applied in `3150a3060`, using
`pathlib` (`REPO_ROOT = Path(__file__).resolve().parents[1]`) rather than the `os.path.join`
form proposed here. The intent is identical; the failures are gone. Retained for history —
it is no longer a pending action.
