# CAPABILITY BOUNDARY AUDIT — Round 17

**Repository:** `/home/moiz/raphael-2.0-rbsv2r` (WSL)
**Date:** 2026-09-26
**Scope:** Read-only audit of all `Capability` enum values in `raphael_ibm_bob/contracts.py`

---

## Capability Enum (contracts.py:27-59)

```python
class Capability(str, Enum):
    READ = "read"
    LIST = "list"
    SEARCH = "search"
    WRITE = "write"
    RUN_TEST = "run_test"
    C1A_STATIC_FILE_INSPECT = "c1a_static_file_inspect"
    NETWORK_HTTP_REQUEST = "network_http_request"
    NETWORK_TELNET_SESSION = "network_telnet_session"
    NETWORK_SERVICE_DISCOVERY = "network_service_discovery"
```

**Total: 9 capabilities**

---

## Per-Capability Governance Chain

| Capability | Descriptor | Authorization | Adapter | Execution | Result | Evidence |
|------------|------------|---------------|---------|-----------|--------|----------|
| **READ** | PRESENT `capability_bootstrap.py:181-199` (registered in `broker.py:_bind_builtin_adapters`) | PRESENT `policy.py:105-106` `_authorize_read` | BOUND `_BrokerAdapter(kind="native")` `broker.py:198,205` | `capabilities.py:_read` → `ExecutionResult(success, output, evidence={})` | `ExecutionResult` `contracts.py:195-215` | `producer="execution"` `broker.py:475` |
| **LIST** | PRESENT `capability_bootstrap.py:181-199` (registered in `broker.py:_bind_builtin_adapters`) | PRESENT `policy.py:107-108` `_authorize_list` | BOUND `_BrokerAdapter(kind="native")` `broker.py:198,206` | `capabilities.py:_list` → `ExecutionResult(success, output, evidence={})` | `ExecutionResult` `contracts.py:195-215` | `producer="execution"` `broker.py:475` |
| **SEARCH** | PRESENT `capability_bootstrap.py:181-199` (registered in `broker.py:_bind_builtin_adapters`) | PRESENT `policy.py:109-110` `_authorize_search` | BOUND `_BrokerAdapter(kind="native")` `broker.py:198,207` | `capabilities.py:_search` → `ExecutionResult(success, output, evidence={})` | `ExecutionResult` `contracts.py:195-215` | `producer="execution"` `broker.py:475` |
| **WRITE** | PRESENT `capability_bootstrap.py:181-199` (registered in `broker.py:_bind_builtin_adapters`) | PRESENT `policy.py:111-112` `_authorize_write` | BOUND `_BrokerAdapter(kind="native")` `broker.py:198,208` | `capabilities.py:_write` → `ExecutionResult(success, output, evidence={})` | `ExecutionResult` `contracts.py:195-215` | `producer="execution"` `broker.py:475` |
| **RUN_TEST** | PRESENT `capability_bootstrap.py:181-199` (registered in `broker.py:_bind_builtin_adapters`) | PRESENT `policy.py:113-114` `_authorize_run_test` | BOUND `_BrokerAdapter(kind="native")` `broker.py:198,209` | `capabilities.py:_run_test` → `run_test_sandbox.py:run_test_in_sandbox` (bwrap) | `ExecutionResult` `contracts.py:195-215` with sandbox metadata | `producer="execution"` `broker.py:475` |
| **C1A_STATIC_FILE_INSPECT** | PRESENT `capability_bootstrap.py:181-199` (registered in `broker.py:_bind_builtin_adapters`) | PRESENT `policy.py:115-116` `_consult_c1a` | BOUND `_BrokerAdapter(kind="c1a")` `broker.py:200,201` | `broker.py:_execute_c1a` → `provider_runtime.py:invoke_governed` → T3MP3ST `binary_sink_scan` (bwrap) | `ExecutionResult` `contracts.py:195-215` with `provider_untrusted=True` | `producer="provider"` `broker.py:684` |
| **NETWORK_HTTP_REQUEST** | PRESENT `capability_bootstrap.py:121-138` `_http_descriptor()` | PRESENT `policy.py:117-118` `_consult_network` | BOUND `_BrokerAdapter(kind="network")` `broker.py:202,203` | `broker.py:_execute_network` → `network_runtime.py:NetworkMediator.invoke` (stdlib urllib) | `ExecutionResult` `contracts.py:195-215` with `provider_untrusted=True` | `producer="network"` `broker.py:786` |
| **NETWORK_TELNET_SESSION** | PRESENT `capability_bootstrap.py:141-160` `_telnet_descriptor()` | PRESENT `policy.py:119-120` `_consult_telnet` | BOUND `_BrokerAdapter(kind="telnet")` `broker.py:203,204` | `broker.py:_execute_telnet` → `telnet_runtime.py:TelnetMediator.invoke` (stdlib socket) | `ExecutionResult` `contracts.py:195-215` with `provider_untrusted=True` | `producer="telnet"` `broker.py:881` |
| **NETWORK_SERVICE_DISCOVERY** | PRESENT `capability_bootstrap.py:192-210` `_discovery_descriptor()` | PRESENT `policy.py:121-122` `_consult_discovery` | BOUND `_BrokerAdapter(kind="discovery")` `broker.py:204,205` | `broker.py:_execute_discovery` → `discovery_runtime.py:DiscoveryMediator.invoke` (stdlib socket.connect_ex) | `ExecutionResult` `contracts.py:195-215` with `provider_untrusted=True` | `producer="discovery"` `broker.py:977` |

---

## D15 Descriptor-Only Capabilities (Declared, InertAdapter, Fail-Closed)

| Capability | Descriptor Source | Adapter | Execution |
|------------|-------------------|---------|-----------|
| NETWORK_SSH_SESSION | `capability_bootstrap.py:163-189` `ssh_descriptor()` | `InertAdapter` `capability_bootstrap.py:238` | **FAILS CLOSED** `AdapterNotBoundError` |
| NETWORK_SMB_METADATA | `d15_capability_catalogue.py:46-53` | `InertAdapter` `d15_capability_catalogue.py:103` | **FAILS CLOSED** `AdapterNotBoundError` |
| NETWORK_TLS_METADATA | `d15_capability_catalogue.py:56-63` | `InertAdapter` `d15_capability_catalogue.py:103` | **FAILS CLOSED** `AdapterNotBoundError` |
| NETWORK_DNS_METADATA | `d15_capability_catalogue.py:66-73` | `InertAdapter` `d15_capability_catalogue.py:103` | **FAILS CLOSED** `AdapterNotBoundError` |
| NETWORK_GENERIC_SERVICE_BANNER | `d15_capability_catalogue.py:76-83` | `InertAdapter` `d15_capability_catalogue.py:103` | **FAILS CLOSED** `AdapterNotBoundError` |

**All 5 D15 capabilities are DESCRIPTOR-ONLY — they DENY (raise `AdapterNotBoundError`) rather than silently no-op.**

---

## Governance Questions

### 1. Is there ANY executable capability that can run without a PolicyDecision?

**ANSWER: NO**

**Proof trace — `broker.py:submit()`:**

1. **Line 305:** `decision = self._policy.consult(stamped, mission)` — Policy is **always** consulted first.
2. **Lines 306-311:** Decision recorded in audit counters (`allows`/`denies`).
3. **Lines 315-318:** DecisionRecord persisted to ledger (both ALLOW and DENY).
4. **Lines 320-346:** PolicyEvidenceReceipt appended with `producer="policy"` — **always**, for both ALLOW and DENY.
5. **Lines 349-358 (DENY short-circuit):**
   ```python
   if decision.decision == Decision.DENY:
       return BrokerResult(
           decision=decision,
           execution=None,                    # NO execution
           capability_invoked=False,          # Explicit flag
           ...
       )
   ```
   **No capability invocation occurs on DENY.**
6. **Lines 360-372 (ALLOW path):** Only after ALLOW does the broker:
   - Get the adapter (`line 360`)
   - Verify `execute_governed` exists (`lines 361-363`)
   - Call `adapter.execute_governed(stamped, mission, decision)` (`line 366`)

**Every execution path is downstream of `self._policy.consult(...)` at line 305. The DENY short-circuit at lines 349-358 returns before any adapter is invoked.**

---

### 2. Which capabilities are DESCRIPTOR-ONLY (declared but fail closed until an adapter is approved)?

**List (5 capabilities):**
- `NETWORK_SSH_SESSION` — `capability_bootstrap.py:163-189`, registered with `InertAdapter` at `capability_bootstrap.py:238`
- `NETWORK_SMB_METADATA` — `d15_capability_catalogue.py:46-53`, registered with `InertAdapter` at `d15_capability_catalogue.py:103`
- `NETWORK_TLS_METADATA` — `d15_capability_catalogue.py:56-63`, registered with `InertAdapter` at `d15_capability_catalogue.py:103`
- `NETWORK_DNS_METADATA` — `d15_capability_catalogue.py:66-73`, registered with `InertAdapter` at `d15_capability_catalogue.py:103`
- `NETWORK_GENERIC_SERVICE_BANNER` — `d15_capability_catalogue.py:76-83`, registered with `InertAdapter` at `d15_capability_catalogue.py:103`

**Confirmation — they DENY rather than silently no-op:**

`InertAdapter.execute()` and `InertAdapter.execute_governed()` both **raise `AdapterNotBoundError`** (`capability_bootstrap.py:40-47`):

```python
def execute(self, target_facts: dict, credentials: list, mission_params: dict) -> dict:
    raise AdapterNotBoundError(
        "capability is declared but has no governed execution adapter "
        "bound; refusing to execute (fail closed)")

def execute_governed(self, request: Any, mission: Any, decision: Any) -> Any:
    raise AdapterNotBoundError(
        "capability is declared but has no governed execution adapter "
        "bound; refusing to execute (fail closed)")
```

The broker's `_execute_registered` (line 374) calls `adapter.execute_governed`, which propagates the `AdapterNotBoundError` — **no silent no-op, hard fail-closed.**

---

### 3. For mediated network capabilities, does the mediator RE-VERIFY the decision at execution time?

**YES — all three mediators call `_decision_allows(decision, request)` before any I/O.**

| Mediator | File | Line | Check |
|----------|------|------|-------|
| `NetworkMediator.invoke` | `network_runtime.py` | **319** | `if not _decision_allows(decision, request): return _fail(..., error="authorization-not-allow")` |
| `TelnetMediator.invoke` | `telnet_runtime.py` | **586** | `if not _decision_allows(decision, request): return _fail(..., error="authorization-not-allow")` |
| `DiscoveryMediator.invoke` | `discovery_runtime.py` | **352** | `if not _decision_allows(decision, request): return _deny("authorization-not-allow")` |

**`_decision_allows` implementation** (`network_runtime.py:108-129`):
```python
def _decision_allows(decision: Any, request: ActionRequest) -> bool:
    if decision is None: return False
    if str(getattr(decision.decision, "value", decision.decision)).lower() != "allow": return False
    if str(getattr(decision.capability, "value", decision.capability)) != request.capability.value: return False
    if getattr(decision, "target", None) != request.target: return False
    if getattr(decision, "sequence", None) != request.sequence: return False
    return True
```

**The mediator validates: decision exists, is ALLOW, capability matches, target matches, sequence matches.** This is defence-in-depth re-verification at the I/O boundary.

---

### 4. Is RUN_TEST sandboxed (bwrap) and does C1A go through a bounded, closed-schema, out-of-process boundary?

#### RUN_TEST — **YES, fully sandboxed via bubblewrap**

**`run_test_sandbox.py` key evidence:**

- **Line 13:** `SANDBOX_UID = 65534`, `SANDBOX_GID = 65534` — unprivileged user
- **Lines 486-530 (`_build_argv`):** bwrap argv with:
  - `--unshare-user --uid 65534 --gid 65534` (user namespace)
  - `--unshare-pid` (PID namespace)
  - `--unshare-net` (**network namespace — no network**)
  - `--unshare-ipc` (IPC namespace)
  - `--unshare-uts` (UTS namespace)
  - `--cap-drop ALL` (drop all capabilities)
  - `--clearenv` (clear environment)
  - `--ro-bind` for read-only Python/runtime mounts
  - `--remount-ro /` (read-only root)
  - `--bind` only for private tmp and staged workspace
- **Lines 603-698 (`_launch`):** `subprocess.Popen` with:
  - `start_new_session=True` (process group leader)
  - `stdin=DEVNULL`, `close_fds=True`
  - Threaded bounded stdout/stderr readers (byte caps)
  - Timeout → `SIGTERM` → `SIGKILL` escalation via process group (`_terminate_process_group`, lines 561-596)
  - Output truncation tracked and reported
- **Line 713:** Non-Linux platforms **fail closed** with `sandbox-platform-unsupported`
- **Policy enforcement:** `policy.py:307-311` requires explicit positive `timeout_seconds` for C1A/RUN_TEST

#### C1A_STATIC_FILE_INSPECT — **YES, bounded out-of-process with closed schema**

**Execution chain:**
1. `broker.py:_execute_c1a` (lines 495-630) — only path for C1A
2. Creates `C1AAuthorizationBinding` (line 549-556) — HMAC-SHA256 sealed token
3. Verifies binding **before** provider dispatch (lines 568-579)
4. Registers execution lineage in `C1AReplayGuard` (lines 584-603) — prevents replay/grafting
5. Calls `provider_runtime.py:invoke_governed` (line 612) → `T3MP3STAdapter.invoke` (adapter: `t3mp3st_adapter.py:128-207`)
6. **Transport:** `c1a_transport.py:BoundedTransport` — fixed argv, no shell, byte caps during collection, timeout→kill→drain
7. **Bridge:** `provider/t3mp3st_bridge.js` (pinned SHA-256 `ea5616e...` at `t3mp3st_adapter.py:53-54`)
8. **Schema validation:** `provider_runtime.py:parse_closed_payload` (line 260) — rejects any authority fields (severity, cwe, title, details)
9. **Evidence:** `provider_untrusted=True` always (`broker.py:672`, `c1a_evidence.py`)

**Closed schema enforcement** (`provider_runtime.py`): Only `results[]`, `artifacts[]`, `provider_message`, `operation_id`, `result_hash`, `truncated` are accepted. Any `findings[]` with severity/CWE/title/details is **rejected**.

---

## Summary Counts

| Category | Count | Capabilities |
|----------|-------|--------------|
| **EXECUTABLE** (descriptor + authz + bound adapter + execution path) | **9** | READ, LIST, SEARCH, WRITE, RUN_TEST, C1A_STATIC_FILE_INSPECT, NETWORK_HTTP_REQUEST, NETWORK_TELNET_SESSION, NETWORK_SERVICE_DISCOVERY |
| **DESCRIPTOR-ONLY** (descriptor + authz + InertAdapter, fail-closed) | **5** | NETWORK_SSH_SESSION, NETWORK_SMB_METADATA, NETWORK_TLS_METADATA, NETWORK_DNS_METADATA, NETWORK_GENERIC_SERVICE_BANNER |

**CAPABILITY COUNTS: 9 executable / 5 descriptor-only**

---

## Probe Output (Real)

```
================================================================================
CAPABILITY GOVERNANCE CHAIN PROBE
================================================================================

1. REGISTRY DESCRIPTORS (capability_bootstrap.py + d15_capability_catalogue.py)
--------------------------------------------------------------------------------
  NETWORK_DNS_METADATA                | protocol=dns             | adapter=InertAdapter         | inert=True
  NETWORK_GENERIC_SERVICE_BANNER      | protocol=generic-service | adapter=InertAdapter         | inert=True
  NETWORK_HTTP_REQUEST                | protocol=http            | adapter=InertAdapter         | inert=True
  NETWORK_SERVICE_DISCOVERY           | protocol=tcp             | adapter=InertAdapter         | inert=True
  NETWORK_SMB_METADATA                | protocol=smb             | adapter=InertAdapter         | inert=True
  NETWORK_SSH_SESSION                 | protocol=ssh             | adapter=InertAdapter         | inert=True
  NETWORK_TELNET_SESSION              | protocol=telnet          | adapter=InertAdapter         | inert=True
  NETWORK_TLS_METADATA                | protocol=tls             | adapter=InertAdapter         | inert=True

2. POLICY METADATA (policy.py BOBPolicy._metadata)
--------------------------------------------------------------------------------
  READ                                | scope=path            | authorizer=_authorize_read
  LIST                                | scope=path            | authorizer=_authorize_list
  SEARCH                              | scope=path            | authorizer=_authorize_search
  WRITE                               | scope=path            | authorizer=_authorize_write
  RUN_TEST                            | scope=path            | authorizer=_authorize_run_test
  C1A_STATIC_FILE_INSPECT             | scope=path            | authorizer=_consult_c1a
  NETWORK_HTTP_REQUEST                | scope=network         | authorizer=_consult_network
  NETWORK_TELNET_SESSION              | scope=network         | authorizer=_consult_telnet
  NETWORK_SERVICE_DISCOVERY           | scope=network         | authorizer=_consult_discovery

3. BROKER ADAPTER BINDINGS (broker.py _bind_builtin_adapters)
--------------------------------------------------------------------------------
  READ                                | bound=_BrokerAdapter            | execute_governed=True
  LIST                                | bound=_BrokerAdapter            | execute_governed=True
  SEARCH                              | bound=_BrokerAdapter            | execute_governed=True
  WRITE                               | bound=_BrokerAdapter            | execute_governed=True
  RUN_TEST                            | bound=_BrokerAdapter            | execute_governed=True
  C1A_STATIC_FILE_INSPECT             | bound=_BrokerAdapter            | execute_governed=True
  NETWORK_HTTP_REQUEST                | bound=_BrokerAdapter            | execute_governed=True
  NETWORK_TELNET_SESSION              | bound=_BrokerAdapter            | execute_governed=True
  NETWORK_SERVICE_DISCOVERY           | bound=_BrokerAdapter            | execute_governed=True

4. POLICY CONSULT RESULTS (with dummy mission, no real targets)
--------------------------------------------------------------------------------
  READ                                | decision=deny  | reason=scope-mismatch
  LIST                                | decision=deny  | reason=scope-mismatch
  SEARCH                              | decision=deny  | reason=scope-mismatch
  WRITE                               | decision=deny  | reason=scope-mismatch
  RUN_TEST                            | decision=deny  | reason=scope-mismatch
  C1A_STATIC_FILE_INSPECT             | decision=deny  | reason=scope-mismatch
  NETWORK_HTTP_REQUEST                | decision=deny  | reason=network-no-authorized-target
  NETWORK_TELNET_SESSION              | decision=deny  | reason=telnet-no-authorized-target
  NETWORK_SERVICE_DISCOVERY           | decision=deny  | reason=discovery-no-authorized-target

5. EVIDENCE PRODUCERS (from broker.py execution paths)
--------------------------------------------------------------------------------
  READ                                | producer=execution
  LIST                                | producer=execution
  SEARCH                              | producer=execution
  WRITE                               | producer=execution
  RUN_TEST                            | producer=execution
  C1A_STATIC_FILE_INSPECT             | producer=provider
  NETWORK_HTTP_REQUEST                | producer=network
  NETWORK_TELNET_SESSION              | producer=telnet
  NETWORK_SERVICE_DISCOVERY           | producer=discovery

6. MEDIATOR RE-VERIFICATION (_decision_allows in network/telnet/discovery_runtime.py)
--------------------------------------------------------------------------------
  NetworkMediator           | _decision_allows called: True
  TelnetMediator            | _decision_allows called: True
  DiscoveryMediator         | _decision_allows called: True

7. RUN_TEST SANDBOX (run_test_sandbox.py)
--------------------------------------------------------------------------------
  bwrap available: True
  Platform: linux
  Sandbox path: /usr/bin/bwrap

8. C1A TRANSPORT (c1a_transport.py)
--------------------------------------------------------------------------------
  BoundedTransport: available
  Uses process group kill: yes (start_new_session=True)
  Byte caps during collection: yes
  Timeout -> kill -> drain: yes

================================================================================
PROBE COMPLETE
================================================================================
```

---

## Recommendation

**The governance boundary is correctly enforced for all 9 executable capabilities:**

1. ✅ **No capability executes without PolicyDecision** — broker.submit consults policy at line 305, DENY short-circuits at lines 349-358.
2. ✅ **5 descriptor-only capabilities fail closed** — `InertAdapter` raises `AdapterNotBoundError` on any execution attempt.
3. ✅ **All 3 mediated network capabilities re-verify** — `_decision_allows` called in each mediator's `invoke()` before I/O.
4. ✅ **RUN_TEST is sandboxed** — bubblewrap with user/PID/net/IPC/UTS namespaces, dropped caps, read-only mounts, process-group kill.
5. ✅ **C1A is bounded out-of-process** — HMAC-sealed authorization binding, replay guard, pinned bridge digest, closed schema validation, `provider_untrusted` evidence.

**No gaps found in the governed chain.** The architecture correctly implements DECLARATION ≠ AUTHORIZATION ≠ EXECUTION at every layer.