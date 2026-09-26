# SUBMISSION DEMO — AI-Assisted Governed Security Assessment

**One command. No credentials. No network. Under 5 seconds.**

> The model can propose. Raphael decides whether execution is permitted.

---

## MASTER COMMAND (copy-paste this)

```bash
cd /home/moiz/raphael-2.0-rbsv2r
PYTHONPATH=. python3 reports/assistant_demo.py
```

Every line of expected output below was produced by that exact command in this
checkout (Python 3.14.4). Nothing here is illustrative.

---

## THE FOUR ACTS

### DEMO A — ALLOW
`model proposal → Raphael validation → ALLOW → Broker → execution → evidence`

```
  model proposes : capability=read target=app.py
  policy decides : ALLOW  (reason=ok)
  broker invoked : True
  execution      : success=True
  evidence       : {'request': 1, 'decision': 1, 'evidence': 2, 'result': 1}
```
**Proves:** an authorized model proposal reaches execution, and every stage —
request, decision, result, evidence — is recorded. Note the model chose the
capability; Policy chose whether it runs.

### DEMO B — DENY
`unauthorized proposal → DENY → broker NOT invoked → denial evidenced`

```
  unknown capability     -> DENY  reason=capability-not-allowed:shell_exec
                            broker invoked=False  execution=None
  out-of-scope target    -> DENY  reason=scope-mismatch
                            broker invoked=False  execution=None
  capability invocations across both attempts: 0
  evidence: {'request': 2, 'decision': 2, 'evidence': 2}  (decision recorded, NO result record)
```
**Proves:** the model cannot reach execution for an unknown capability or an
out-of-scope target. `capability invocations: 0` is the load-bearing number.
A denial is *evidenced* (decision record exists) but produces **no result
record** — the ledger itself shows nothing ran.

### DEMO C — FEEDBACK
`failure → evidence → next context sees it → next proposal`

```
  turn 1 proposal : RUN_TEST test_generated.py
  decision        : ALLOW
  execution       : success=False error=TestFailed:returncode=5
  evidence after 1: 5 records
  turn 2 context  : evidence_count=5 (the model now SEES the failure)
  turn 2 decision : ALLOW  -> success=True
  evidence total  : 10 records  {'request': 2, 'decision': 2, 'evidence': 4, 'result': 2}
```
**Proves:** a failed action becomes evidence the next proposal can react to.
This is **AI-assisted iterative replanning** — the model is *shown* the failure
and chooses differently. It is not autonomous replanning, and the system never
claims it is.

### DEMO D — VERIFICATION  *(the most important act)*
`apparent success → QualityGate still REFUSES`

```
  action executed : success=True (the model may consider this a win)
  gate verdict    : REFUSE
  gate passed     : ['A:mission-criterion', 'E:scope', 'F:evidence', 'G:finding-state']
  gate failed     : ['B:required-tests', 'C:regression', 'D:independent-behavior-probe']
    - no RUN_TEST capability invocation in the ledger
    - regression_ok=True but no producer='regression' evidence record in the ledger (or it is not causally bound to an ALLOWed successful execution)
    - behavior_probe_ok=True but no producer='probe' evidence record with allowed=True
  evidence seal   : verified=True (seal-ok)
```
**Proves:** the model **cannot certify its own success.** The action genuinely
succeeded, and the caller even passed `regression_ok=True` and
`behavior_probe_ok=True` — i.e. *claiming* everything passed. The gate still
refuses, because no evidence record backs those claims. This is the single
strongest demonstration in the submission: **DECLARATION != AUTHORIZATION**, and
`BOBQualityGate` is the only authority permitted to emit COMPLETE.

---

## SCREEN-RECORDING CHECKLIST

Record ~90 seconds, in this order. Terminal at a readable font size.

| # | Show | Why it matters |
|---|---|---|
| 1 | Header: "Model proposes. Raphael decides." | States the thesis immediately |
| 2 | **Demo B first** — two DENYs, `invocations: 0` | Lead with the security property, not the happy path |
| 3 | Demo A — ALLOW with the 4-stage evidence dict | Shows the happy path is governed too |
| 4 | Demo C — `evidence_count=5` then `success=False` | Shows the feedback loop is real |
| 5 | **Demo D** — `REFUSE` + the three "but no evidence record" reasons | The money shot: model claims success, gate refuses |
| 6 | `evidence seal : verified=True (seal-ok)` | Tamper-evident provenance |

**Do not** present Demo A alone — an ungoverned-looking success is the wrong
first impression.

---

## OPTIONAL: EXISTING FULL DEMOS (already working, real exits)

```bash
PYTHONPATH=. python3 demos/authkit_hero.py                 # Gate: COMPLETE, exit 0
PYTHONPATH=. python3 demos/canonical_hero.py --mode raphael # RESULT: COMPLETE, exit 0
PYTHONPATH=. python3 demos/canonical_hero.py --mode refuse   # RESULT: REFUSE,   exit 1
PYTHONPATH=. python3 demos/c1a_live_hero.py                 # Gate: COMPLETE, exit 0
```
`--mode refuse` is valuable on camera: the *same* code path honestly refuses
when evidence is absent. `scripts/run_demo.sh --refuse` does the same at the
judge-demo level.

---

## LIVE-PROVIDER PATH (optional; NOT required)

The demo above is the **default** because it needs no credentials. If a real
OpenAI-compatible endpoint is configured, the identical governed path runs with
a real model:

```bash
export RAPHAEL_MODEL_ENDPOINT="https://<host>/v1"
export RAPHAEL_MODEL_NAME="<model-id>"
export RAPHAEL_MODEL_API_KEY="<key>"     # never commit; never logged
PYTHONPATH=. python3 -m raphael_ibm_bob.harness.cli run-start --model-provider openai-compatible
```

**Current status: BLOCKED — credentials unavailable.** No `RAPHAEL_MODEL_*`,
`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY` or
`NVIDIA_API_KEY` is set in this environment; there is no `.env` and no local
endpoint. The code fails closed:

```
ProviderConfigError: missing model configuration: RAPHAEL_MODEL_ENDPOINT, RAPHAEL_MODEL_NAME
```

No credential was requested, invented, or simulated. The credential-free path
above exercises the identical `ModelAdapter → Runtime → Broker → Policy →
evidence` seam, so the governance claims are fully demonstrable without one.

---

## WHAT EACH ACT MAPS TO THE ACCEPTANCE CRITERIA

| Act | Criterion | Executable proof |
|---|---|---|
| A | Authorized decisions reach the Broker | `AuthorizedProposalReachesBroker` |
| B | LLM cannot bypass authorization | `UnauthorizedCapabilityDenied`, `OutOfScopeTargetDenied` |
| C | Execution results return to model context | `FailureFeedsNextDecision` |
| D | LLM cannot self-certify success | `ModelCannotSelfCertify` |
| — | Evidence sealed + tamper-evident | `reports/EVIDENCE_FINAL.md` |

Run the executable suite:
```bash
PYTHONPATH=. python3 -m pytest tests/test_assistant_governed_loop.py -q
# 20 passed, 53 subtests
```
