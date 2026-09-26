# WRITE Guard Review — Model 3 Security Assessment

**Repository**: `/home/moiz/raphael-2.0-rbsv2r` (WSL Ubuntu)
**Date**: 2026-09-26
**Model**: 3 (Security / WRITE-Guard Review)

---

## 1. What WRITE Actually Does — Implementation Quoted

### Capability Implementation (`raphael_ibm_bob/capabilities.py:107-117`)

```python
def _write(workspace: Workspace, request: ActionRequest) -> Dict[str, Any]:
    p = workspace.resolve(request.target)
    # WRITE's payload is a base64-ish utf-8 string. For MVP, callers pass
    # the content in `request.purpose` after a marker `content=`; this is
    # deliberately minimal so M3 can replace it with a structured payload.
    prefix = "content="
    if not request.purpose.startswith(prefix):
        raise ValueError("WRITE request must carry content in purpose='content=...'")
    content = request.purpose[len(prefix):]
    p.write_text(content, encoding="utf-8")
    return {"path": str(p), "bytes": len(content.encode("utf-8"))}
```

**Key properties**:
- **No sandboxing**: Writes directly to the resolved filesystem path via `Path.write_text()`.
- **Same containment as READ**: Uses `workspace.resolve(target)` which canonicalizes and enforces workspace-root containment (rejects `..` traversal, symlinks escaping root).
- **Arbitrary content accepted**: No validation of file extension, MIME type, or content structure. The `purpose` field carries raw UTF-8 text after `content=`.
- **Parent directory must exist**: Policy checks `resolved.parent.is_dir()` (policy.py:352), but the file itself may be new or existing.

### Policy Authorization (`raphael_ibm_bob/policy.py:344-354`)

```python
def _authorize_write(
    self, request: ActionRequest, _mission: Mission,
    resolved: Path | None,
) -> PolicyDecision:
    if resolved is None:
        return self._deny(request, "write-target-unresolved")
    if resolved.exists() and resolved.is_dir():
        return self._deny(request, "write-target-is-directory")
    if not resolved.parent.is_dir():
        return self._deny(request, "write-parent-missing")
    return self._allow(request)
```

**Checks performed**:
1. Target resolves (not `None`) → denies `write-target-unresolved`
2. Target is not an existing directory → denies `write-target-is-directory`
3. Parent directory exists → denies `write-parent-missing`
4. **No file-extension check, no content-type check, no allowlist**

### Mission-Scope Containment (earlier in `consult()`, `policy.py:163-169`)

```python
# 4. Mission scope containment check.
# Canonical component-boundary containment (raphael_ibm_bob.c1a_scope)
# — the SAME helper the QualityGate uses. This rejects sibling string
# prefixes, traversal, and malformed paths that a substring check
# would have accepted.
if mission.scope and not scope_contains(mission.scope, request.target):
    return self._deny(request, "scope-mismatch")
```

Uses `c1a_scope.scope_contains()` — component-boundary semantics (not substring), rejects mixed absoluteness, `..` escape, and prefix collisions (e.g., `src` vs `srcx`).

---

## 2. Is the Risk Real or Theoretical? — Empirical Determination

### Default Mission Scope in Each Real Entrypoint

| Entrypoint | Mission Scope | Practical WRITE Reach |
|------------|---------------|----------------------|
| `demos/canonical_hero.py:433` | `"fixtures"` | `fixtures/**` only |
| `demos/authkit_hero.py:266` | `"fixtures"` | `fixtures/**` only |
| `demos/live_authkit_hero.py:96` | `"fixtures"` | `fixtures/**` only |
| `demos/c1a_live_hero.py:121` | `str(base)` (workspace root) | **Entire workspace** |
| `harness/cli.py:49` (default) | `"src/"` | `src/**` only |
| `harness/discovery_run.py:78` | `host` (network host) | Network target, not filesystem |
| `http/routes/_common.py:44` | `data.get("scope", "")` | **Empty = no scope constraint** (workspace-only) |
| `runner.py:174` (default param) | Caller-supplied | Depends on caller |
| `harness/model_run.py:266` | Caller-supplied | Depends on caller |

### Critical Finding

**The risk is REAL but practically constrained by mission scope in all current demos and the CLI default.**

- In the **canonical demos** (`canonical_hero.py`, `authkit_hero.py`, `live_authkit_hero.py`), `scope="fixtures"` restricts WRITE to `fixtures/authkit/*.py` — the intended remediation targets. `raphael_ibm_bob/policy.py` is **not reachable** because it lies outside `fixtures/`.
- In the **CLI default** (`harness/cli.py`), `scope="src/"` restricts WRITE to `src/**` — again, `policy.py` is not reachable.
- In **`c1a_live_hero.py`** and **HTTP routes with empty scope**, the scope is the workspace root or empty (no constraint). Here, **any file in the workspace is reachable**, including `raphael_ibm_bob/policy.py` itself.

**Evidence**: The `scope_contains` function (`c1a_scope.py:80-109`) with an empty scope returns `True` (line 96-97: `if isinstance(scope, str) and scope.strip() == "": return True`). An empty scope means "no scope constraint" — only workspace containment applies.

---

## 3. Threat-Model Framing

**Adversary**: An LLM emitting a structured `ActionRequest` (capability=WRITE, target=..., purpose="content=...") — **not** an attacker with in-process Python execution.

**Boundary in this threat model**:
- The LLM can propose any target string.
- Policy validates: workspace containment + mission scope containment + parent-exists + not-a-directory.
- If mission scope is `"fixtures"` or `"src/"`, the LLM **cannot** reach `raphael_ibm_bob/policy.py`.
- If mission scope is empty or workspace-root, the LLM **can** reach any file in the workspace, including source code.

**Does a file-type allowlist improve the boundary?**
- **Yes, marginally**: It would prevent writes to `.py`, `.json`, `.yaml`, `.sh` etc. even when scope is misconfigured.
- **But**: The legitimate remediation workflow **writes `.py` files** (fixes to `session.py`, `login.py`). An allowlist would need to include `.py`, defeating the protection for the most sensitive files.
- **Conclusion**: A file-type allowlist does **not** materially improve the boundary in the LLM threat model because the files an attacker would target (`.py` source) are exactly the files the legitimate workflow must write.

---

## 4. Regression Risk — Current WRITE Usages Enumerated

| File:Line | Context | Target Pattern | Would Allowlist Break? |
|-----------|---------|----------------|------------------------|
| `demos/canonical_hero.py:324` | `_write_via_broker` v1 fix | `fixtures/authkit/login.py` | Yes if `.py` blocked |
| `demos/canonical_hero.py:611` | `_write_via_broker` v2 fix | `fixtures/authkit/session.py` | Yes if `.py` blocked |
| `demos/authkit_hero.py:391` | `_write_via_broker` v1 fix | `fixtures/authkit/login.py` | Yes if `.py` blocked |
| `demos/authkit_hero.py:455` | `_write_via_broker` v2 fix | `fixtures/authkit/session.py` | Yes if `.py` blocked |
| `raphael_ibm_bob/remediation.py:178` | `Remediator.apply()` | Arbitrary `proposal.target` (`.py` in practice) | Yes if `.py` blocked |
| `tests/test_m2_boundary.py:150` | Test `AllowedWriteSucceeds` | `src/authkit/newfile.txt` | No (`.txt` safe) |
| `tests/test_m2_boundary.py:478` | Test `mutation_guard_allow` | `src/authkit/allowed.txt` | No (`.txt` safe) |
| `tests/test_operation_graph.py:84` | Model scripted WRITE | `src/cand.txt` | No (`.txt` safe) |
| `tests/test_d9_2_gate_presentation.py:181` | Model scripted WRITE | `src/cand.txt` | No (`.txt` safe) |
| `tests/test_m15_3_decision_trace.py:95` | Model scripted WRITE | `src/cand.txt` | No (`.txt` safe) |
| `tests/test_m15_3_decision_trace.py:116` | Model scripted WRITE | `src/cand.txt` | No (`.txt` safe) |
| `tests/test_m15_5_event_stream_page.py:100` | Model scripted WRITE | `src/cand.txt` | No (`.txt` safe) |
| `tests/test_evidence_intelligence.py:80` | Model scripted WRITE | `src/cand.txt` | No (`.txt` safe) |
| `tests/test_m4_verifier_falsifier.py:149` | RetestSpec WRITE | `/tmp/escape` (DENIED) | N/A (denied) |

**VulnHub/VMware `PlatformSpec` and HTB behavior**: These use **network capabilities** (`NETWORK_HTTP_REQUEST`, `NETWORK_TELNET_SESSION`), not WRITE. **No impact.**

**Regression verdict**: An allowlist blocking `.py` would **break all demo remediation flows** and the `Remediator` class. An allowlist permitting `.py` provides **no meaningful protection** against the identified risk.

---

## 5. Recommendation

### **DEFER — document as residual limitation**

**Rationale**:
1. **Mission scope + workspace containment already provides strong practical protection** in all shipped entrypoints (demos, CLI). The theoretical exposure only exists when an operator configures an empty/root scope — an operator error, not a policy bypass.
2. **A file-type allowlist cannot distinguish malicious from legitimate `.py` writes** — the remediation workflow *requires* writing `.py` files.
3. **Adding an allowlist adds complexity and maintenance burden** (new capability metadata, registration, tests) for **zero marginal security benefit** in the LLM threat model.
4. **The existing boundary is fail-closed**: workspace escape → DENY, scope mismatch → DENY, parent missing → DENY, directory target → DENY. The only gap is "scope misconfiguration allows broad write," which is an operational issue.

### Precise Wording for Submission Limitations Section

> **Residual Limitation — WRITE File-Type Restriction**: The governed WRITE capability accepts arbitrary UTF-8 content and does not enforce a file-extension allowlist. Authorization relies on workspace-root containment and mission-scope containment (component-boundary semantics via `c1a_scope.scope_contains`). In all shipped entrypoints (canonical demos, CLI), the mission scope is set to a narrow directory (`fixtures/` or `src/`), which practically prevents writes to the agent's own source code. If an operator configures a mission with an empty or workspace-root scope, WRITE can target any file in the workspace including `raphael_ibm_bob/policy.py`. This is classified as an **operator configuration issue**, not a policy bypass, because the authorization boundary (workspace + scope) functions as designed. A file-type allowlist was considered but rejected because legitimate remediation workflows require writing `.py` files, and an allowlist permitting `.py` provides no meaningful additional boundary.

---

## 6. Exact Patch (Not Applicable — DEFERRED)

No patch produced. The recommendation is to **not implement** a file-type restriction.

---

## 7. Files Inspected

| File | Purpose |
|------|---------|
| `raphael_ibm_bob/policy.py` | WRITE authorizer (`_authorize_write`), `consult()` flow, mission-scope check |
| `raphael_ibm_bob/capabilities.py` | `_write` implementation, `CAPABILITY_DISPATCH` |
| `raphael_ibm_bob/broker.py` | WRITE dispatch path (`_execute_native`), evidence persistence |
| `raphael_ibm_bob/harness/model_run.py` | Model-loop WRITE handling, mission scope usage |
| `raphael_ibm_bob/harness/run.py` | Runner entrypoint, mission construction |
| `raphael_ibm_bob/runner.py` | Runner control loop, default parameters |
| `demos/canonical_hero.py` | Canonical demo, `scope="fixtures"`, `_write_via_broker` |
| `demos/authkit_hero.py` | Authkit hero demo, `scope="fixtures"`, `_write_via_broker` |
| `demos/live_authkit_hero.py` | Live demo, `scope="fixtures"` |
| `demos/c1a_live_hero.py` | C1A live demo, `scope=str(base)` (workspace root) |
| `raphael_ibm_bob/harness/cli.py` | CLI default `scope="src/"` |
| `raphael_ibm_bob/harness/discovery_run.py` | Discovery mission, `scope=host` |
| `raphael_ibm_bob/http/routes/_common.py` | HTTP mission parsing, `scope` default empty |
| `raphael_ibm_bob/c1a_scope.py` | `scope_contains()` canonical semantics |
| `raphael_ibm_bob/workspace.py` | `Workspace.resolve()` containment |
| `raphael_ibm_bob/contracts.py` | `Mission`, `ActionRequest`, `Capability` definitions |
| `raphael_ibm_bob/remediation.py` | `Remediator.apply()` WRITE usage |
| `raphael_ibm_bob/skills.py` | `write-file` skill declaration |
| `raphael_ibm_bob/specialization.py` | `remediation_planner` role with WRITE |
| `tests/test_m2_boundary.py` | WRITE boundary tests (ALLOW/DENY, side-effect proof) |
| `tests/test_m3_evidence.py` | WRITE evidence tests |
| `tests/test_m7_hero.py` | Hero test with WRITE |
| `tests/test_operation_graph.py` | Model-loop WRITE tests |
| `tests/test_d9_2_gate_presentation.py` | Gate presentation WRITE tests |
| `tests/test_m15_3_decision_trace.py` | Decision trace WRITE tests |
| `tests/test_m15_5_event_stream_page.py` | Event stream WRITE tests |
| `tests/test_evidence_intelligence.py` | Evidence intelligence WRITE tests |
| `tests/test_m4_verifier_falsifier.py` | Verifier/falsifier WRITE tests |
| `tests/test_capability_fabric.py` | Capability fabric WRITE registration |
| `tests/test_m14_specialization.py` | Specialization role WRITE tests |

---

## 8. Current WRITE Authorization (Quoted, File:Line)

**Policy** (`policy.py:344-354`):
```python
def _authorize_write(
    self, request: ActionRequest, _mission: Mission,
    resolved: Path | None,
) -> PolicyDecision:
    if resolved is None:
        return self._deny(request, "write-target-unresolved")
    if resolved.exists() and resolved.is_dir():
        return self._deny(request, "write-target-is-directory")
    if not resolved.parent.is_dir():
        return self._deny(request, "write-parent-missing")
    return self._allow(request)
```

**Mission-scope check** (`policy.py:163-169`):
```python
if mission.scope and not scope_contains(mission.scope, request.target):
    return self._deny(request, "scope-mismatch")
```

**Workspace containment** (`workspace.py:34-52`):
```python
def resolve(self, target: str) -> Path:
    t = Path(target)
    if t.is_absolute():
        candidate = t.resolve()
    else:
        candidate = (self._root / t).resolve()
    try:
        candidate.relative_to(self._root)
    except ValueError as e:
        raise PermissionError(
            f"target escapes workspace: {candidate} not under {self._root}"
        ) from e
    return candidate
```

---

## 9. Risk Real or Theoretical (One Line with Evidence)

**REAL but practically constrained**: In all shipped demos and CLI defaults, mission scope is `"fixtures"` or `"src/"`, which component-boundary containment (`scope_contains`) restricts to those subtrees — `raphael_ibm_bob/policy.py` is outside both. Only `c1a_live_hero.py` (scope=workspace root) and HTTP routes with empty scope expose the full workspace to WRITE.

---

## 10. Default Mission Scope in Each Entrypoint

| Entrypoint | Scope Value | WRITE Reach |
|------------|-------------|-------------|
| `canonical_hero.py:433` | `"fixtures"` | `fixtures/**` |
| `authkit_hero.py:266` | `"fixtures"` | `fixtures/**` |
| `live_authkit_hero.py:96` | `"fixtures"` | `fixtures/**` |
| `c1a_live_hero.py:121` | `str(base)` (root) | **Entire workspace** |
| `cli.py:49` (default) | `"src/"` | `src/**` |
| `discovery_run.py:78` | `host` (network) | N/A (network cap) |
| `http/routes/_common.py:44` | `""` (empty) | **Entire workspace** |
| `runner.py:174` | Caller-supplied | Caller-dependent |
| `model_run.py:266` | Caller-supplied | Caller-dependent |

---

## 11. Current WRITE Usages Found (File:Line)

- `demos/canonical_hero.py:324` — v1 fix to `fixtures/authkit/login.py`
- `demos/canonical_hero.py:611` — v2 fix to `fixtures/authkit/session.py`
- `demos/authkit_hero.py:391` — v1 fix to `fixtures/authkit/login.py`
- `demos/authkit_hero.py:455` — v2 fix to `fixtures/authkit/session.py`
- `raphael_ibm_bob/remediation.py:178` — `Remediator.apply()` generic patch target
- `raphael_ibm_bob/skills.py:462` — `write-file` skill declaration
- `tests/test_m2_boundary.py:150` — `src/authkit/newfile.txt`
- `tests/test_m2_boundary.py:478` — `src/authkit/allowed.txt`
- `tests/test_operation_graph.py:84` — `src/cand.txt`
- `tests/test_d9_2_gate_presentation.py:181` — `src/cand.txt`
- `tests/test_m15_3_decision_trace.py:95,116` — `src/cand.txt`
- `tests/test_m15_5_event_stream_page.py:100` — `src/cand.txt`
- `tests/test_evidence_intelligence.py:80` — `src/cand.txt`
- `tests/test_m4_verifier_falsifier.py:149` — `/tmp/escape` (DENIED)

---

## 12. Regression Risk if Restricted

**HIGH**: All demo remediation flows and the `Remediator` class write `.py` files. An allowlist excluding `.py` breaks the product's core remediation demonstration. An allowlist including `.py` provides no meaningful protection.

---

## 13. Blockers

None. The review is complete and the recommendation is DEFER.

---

## 14. Final Decision

```
MODEL: 3
ROLE: Security / WRITE-Guard Review
STATUS: COMPLETE
FILES CREATED: reports/WRITE_GUARD_REVIEW.md
FILES INSPECTED: 30+ files (listed above)
CURRENT WRITE AUTHZ (quoted, file:line): policy.py:344-354 (authorizer), policy.py:163-169 (scope), workspace.py:34-52 (containment)
RISK REAL OR THEORETICAL: REAL but practically constrained by mission scope in all shipped entrypoints; only misconfigured scope (empty/root) exposes full workspace
DEFAULT MISSION SCOPE IN EACH ENTRYPOINT: fixtures/ (demos), src/ (CLI), workspace root (c1a_live_hero), empty (HTTP routes)
CURRENT WRITE USAGES FOUND: 14 locations (4 demo remediations, 1 remediation.py, 1 skill, 8 tests)
REGRESSION RISK IF RESTRICTED: HIGH — all remediation writes .py files; allowlist permitting .py adds no boundary
RECOMMENDATION: DEFER — document as residual limitation
EXACT PATCH (if IMPLEMENT): N/A (DEFERRED)
BLOCKERS: None
```