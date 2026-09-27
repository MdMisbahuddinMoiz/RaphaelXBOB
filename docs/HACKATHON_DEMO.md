# RAPHAEL — 3-MINUTE HACKATHON DEMO RUNBOOK

**HEAD**: `3f13a7238` · **Branch**: `hackathon/bob-assisted-raphael` · **Python**: 3.14.4

This is the runbook for the live browser demonstration. Every command below was executed
and its output recorded; the transcript in §5 is verbatim, not illustrative.

**What this demo proves**: the governed chat path, end to end, in a browser —
operator message → model proposal → Broker → Policy → capability → ledger evidence →
transcript. The model proposes; Raphael alone authorises.

---

## 0. THE THREE STATES — read before demoing

| State | What it is | Status |
|---|---|---|
| **PROVEN** | Governed chat console in a real browser against a real controlled target | **Reproducible today** |
| **PROVEN (historical)** | Real MiMo V2.6 Flash vertical slice at `a7d4d1357` — governed discovery, SSH, evidence-driven replanning, user-to-root | Real, but not re-run in this environment |
| **CURRENT OFFLINE DEMO** | `local-deterministic` provider | **NOT an AI model.** Deterministic rule table. Proves governance, not reasoning |
| **VERIFIED TARGET** | Kioptrix Level 1 — live VulnHub VM, boot + reachability + `vulnhub` declaration + governed discovery + governed HTTP through Broker → Policy | **Proven.** Compromise and root are **NOT** achieved |

Never present the deterministic run as evidence that an AI model reasoned autonomously.

---

## 1. Bring up the controlled target

The demo target is a disposable local fixture that serves HTTP on `127.0.0.2:8080` and SSH
on `127.0.0.2:2222`.

```bash
cd /home/moiz/lab-scratch/raphael-target
python3 target_server.py          # leave running
```

In a second shell, verify before you demo:

```bash
ss -ltn | grep -E '127\.0\.0\.2:(8080|2222)'
# LISTEN 0  5  127.0.0.2:8080  0.0.0.0:*
# LISTEN 0  8  127.0.0.2:2222  0.0.0.0:*

cd /home/moiz/lab-scratch/raphael-target && python3 verify_target.py
# ---- 14/14 passed
```

---

## 2. Bring up the model provider

### 2a. Offline (no credential — the default demo path)

```bash
cd /home/moiz/raphael-2.0-rbsv2r
PYTHONPATH=. python3 -c "
import time
from demos.local_model_endpoint import LocalModelEndpoint
with LocalModelEndpoint(host='127.0.0.1', port=8799) as e:
    print('local model endpoint on', e.base_url, flush=True)
    time.sleep(3600)
"
```

This is the repo's own OpenAI-compatible endpoint. It labels itself `local-deterministic`
in every response, so no log, transcript, or evidence record can imply a hosted model ran.

### 2b. Real model (flagship demo — needs a credential you supply)

```bash
export RAPHAEL_MODEL_ENDPOINT=https://openrouter.ai/api/v1
export RAPHAEL_MODEL_NAME=xiaomi/mimo-v2.6-flash
export RAPHAEL_MODEL_API_KEY=<supplied at runtime; never committed>
```

Nothing else changes. The adapter path is identical.

---

## 3. Start Raphael

```bash
cd /home/moiz/raphael-2.0-rbsv2r

# offline
RAPHAEL_MODEL_ENDPOINT=http://127.0.0.1:8799/v1 \
RAPHAEL_MODEL_NAME=local-deterministic \
RAPHAEL_MODEL_API_KEY=local-offline-not-a-secret \
PYTHONPATH=. python3 -m raphael_ibm_bob.http.app
```

Binds `127.0.0.1:8787` (override with `RAPHAEL_HTTP_PORT`).

With no provider configured the server still starts and still serves the console; a chat
turn then fails closed with `MODEL_NOT_CONFIGURED` rather than pretending to run.

---

## 4. The 3-minute browser sequence

Open **http://127.0.0.1:8787/agent**.

| # | Beat | What the viewer sees |
|---|------|----------------------|
| 1 | Open the Agent console | Header `GOVERNED · MODEL PROPOSES ONLY`; mission panel, provider, target |
| 2 | Declare the authorized target | `127.0.0.2`, ports `8080,2222`, protocols `http,ssh`, scope locked to that host |
| 3 | Send a chat message | The operator turn appears in the transcript |
| 4 | Show provider identity | Name the provider out loud: `local-deterministic` (**not** an AI model) or `xiaomi/mimo-v2.6-flash` |
| 5 | Action proposal | `network_service_discovery on 127.0.0.2` — the model *proposes* |
| 6 | Broker / Policy decision | `ALLOW — ok` — Raphael *decides*, in its own visual language |
| 7 | Evidence | `127.0.0.2: 2222, 8080 (probed 2)` — read from the run ledger, not from the model's belief |
| 8 | Send a follow-up message | A second governed turn; prior turns and observations are carried forward |
| 9 | Stop the mission | `POST /agent/stop` — the chat refuses further turns; this is a real server-side gate |
| 10 | State the objective honestly | See the claim boundary below |

**Operator message to send:**

> Begin an authorized reconnaissance of the declared target and report your findings as you proceed.

If the console form is unavailable, the same turn via HTTP:

```bash
curl -sS -X POST -H 'Content-Type: application/json' \
  -d '{"host":"127.0.0.2","port_spec":"8080,2222","protocols":"http,ssh","authorization_ref":"local-lab","environment":"isolated-lab"}' \
  http://127.0.0.1:8787/agent/target

curl -sS -X POST -H 'Content-Type: application/json' \
  -d '{"message":"Begin an authorized reconnaissance of the declared target and report your findings as you proceed."}' \
  http://127.0.0.1:8787/agent/message
```

---

## 5. Expected transcript — VERBATIM

This is the actual recorded output of the run above, not a mock-up:

```
user        Begin an authorized reconnaissance of the declared target and report your findings as you proceed.
action      network_service_discovery on 127.0.0.2
policy      ALLOW — ok
execution   Completed
evidence    127.0.0.2: 2222, 8080 (probed 2)
```

Each message type renders in its own visual language — an operator instruction, a model
proposal, a governance decision, an execution outcome and evidence are not the same kind
of claim and must not look the same.

The evidence line is produced by reading `runs/<run_id>/evidence.jsonl`. A turn's
observation is what the model saw *before* it acted, so it cannot report the result of its
own action. If the ledger has no usable record, the transcript says **"no evidence
produced"** — it never invents services.

---

## 6. Governance — what is actually enforced

A proposal must pass, in order:

1. **Model authorisation** — the model id is checked against the audit allow-list
   *before* a provider is constructed. A rejected model never reaches a provider, the
   Broker, or Policy.
2. **Target declaration** — no `TargetProfile`, no run. The operator must name the
   authorised host, ports, and protocols; Raphael never infers them.
3. **Runtime** — the proposal becomes an `ActionRequest` submitted to the runtime.
4. **Broker → Policy** — the sole authority on whether a capability executes. The model
   cannot self-certify; a caller asserting success does not make it so.
5. **Evidence** — request → decision → result → evidence recorded in an append-only,
   causally chained ledger.
6. **QualityGate** — an independent verdict. `COMPLETE` only when the evidence satisfies
   its conditions; otherwise `REFUSE`.

**There is exactly one governed execution path.** No `chat → capability`, no
`chat → shell`, no `chat → subprocess`, no broker bypass. A chat message is context.

### QualityGate conditions

| # | Condition | Requirement |
|---|---|---|
| A | `A:mission-criterion` | non-empty mission criteria |
| B | `B:required-tests` | a `RUN_TEST` whose artifact reports `returncode == 0` |
| C | `C:regression` | a `producer="regression"` record + ≥ 2 distinct ALLOWed capabilities |
| D | `D:independent-behavior-probe` | a `producer="probe"` record with `payload.allowed is True` |
| E | `E:scope` | every target within the mission scope / TargetProfile scope |
| F | `F:evidence` | complete request → decision → result → evidence chain |
| G | `G:finding-state` | no unresolved UNVERIFIED, REFUTED-without-replan, or invalid VERIFIED findings |

> **COMPLETE can only come from the QualityGate.** No caller, provider, or model may emit
> it. Where required evidence is absent, the gate emits `REFUSE` rather than converting
> absence into a pass — and that refusal is reported as a refusal.

---

## 7. Showing a DENY

A denial is a stronger demo than a clean run: it shows the model asking for something and
Policy refusing.

The scripted demos exercise the refusal path directly:

```bash
./scripts/run_hackathon_demo.sh --refuse
# RESULT: REFUSE (honest: failure was not reported as COMPLETE)
```

In the chat UI a denial appears as a `policy` message reading `DENY — <reason>` in the
deny styling, with the reason shown. Whatever the model proposes, Policy remains
authoritative.

---

## 8. Evidence on disk

For any run, `runs/<run_id>/` contains:

| File | Contents |
|---|---|
| `harness.json` | the run record |
| `evidence.jsonl` | the append-only, causally chained ledger |
| `timeline.json` | the governed-loop projection rendered in the console |
| `artifacts/` | result payloads |
| `seal.json` | integrity seal (present on sealed runs) |

Re-export evidence for a run with:

```bash
python3 scripts/demo_export.py <run_id> demo/<name>
```

---

## 9. Known limitations — state them, do not hide them

- **The offline provider is not an AI model.** `local-deterministic` returns proposals from
  a fixed rule table. It proves the governed path; it proves nothing about model reasoning.
- **No real-model run in this environment.** A real MiMo V2.6 Flash mission was demonstrated
  at `a7d4d1357`; that is a historical validation, not something this environment reproduces.
- **Kioptrix Level 1 is a verified target, not a compromised one.** Boot, reachability,
  VulnHub declaration, governed discovery, governed HTTP and scope/port/protocol denials are
  all proven. Execution stops at the `ssh-no-session-spec` authorization boundary — an
  intentional boundary requiring an explicitly declared SSH session specification, not a
  Policy defect. The wider chain needs an exploitation capability Raphael does not carry.
  Autonomous compromise and root access are **NOT** claimed.
- **No exploitation in the governed capability set.** `NETWORK_HTTP_REQUEST` is HTTP
  GET/HEAD only. Privilege escalation and arbitrary methods are outside it.
- **Legacy substrate** under `src/` sits outside the governed runtime and is not imported by it.

### Claim boundary (explicit)

> **Claimed**: Raphael ran a governed chat turn in a browser against an authorised local
> target. The model proposed a discovery action; Broker and Policy authorised it; the
> capability executed; the result was written to the append-only ledger and rendered in the
> transcript from that ledger.

> Do **not** claim that "Raphael solved Breakout", that "Raphael captured and verified the
> Breakout root flag", that Kioptrix has been compromised, or that the deterministic
> offline run demonstrates autonomous AI reasoning.

On the earlier Breakout VM run specifically: that run reached QualityGate `COMPLETE` with
condition G satisfied as "no unresolved / refuted / invalid findings" — **not** by capturing
a flag. The Breakout VM did not expose its final root flag through the governed HTTP
capability (`NETWORK_HTTP_REQUEST` is GET/HEAD only, and Breakout's flags live in files).
That distinction is preserved here deliberately.

---

## 10. Reproducibility

1. Python ≥ 3.11 (validated on 3.14.4). The governed core requires no third-party packages.
2. Start the target (§1) and verify 14/14 before demoing.
3. Start a provider (§2) and the server (§3).
4. Run the browser sequence (§4).
5. Full suite: `python3 -m pytest -q` → **2161 passed, 0 failed, 1 skipped, 4 xfailed,
   297 subtests** at `3f13a7238`. The console is verified at **1920×1080** — open the
   browser full-screen at that resolution for the recording.
6. After any test run, `git diff --stat -- arena/results/raw` must be empty — the suite is
   isolated from committed evidence (resolved in `9bb6d095c`).
7. The submission archive reproduces this same result when extracted to a different
   directory — verified, not assumed (see `reports/TEST_INTEGRITY_AUDIT.md` §6.6).
