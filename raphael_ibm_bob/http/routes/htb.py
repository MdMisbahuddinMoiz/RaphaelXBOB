"""HTB target routes — operator-declared authorized network target (D9).

The target routes perform no network I/O: they record the mission-bound
TargetProfile that Policy and the QualityGate consult. ``/htb/discover``
performs no network I/O either — it only orchestrates the governed
Runtime -> Broker -> Policy -> DiscoveryMediator path.

    GET  /htb/target          current declared target (or null)
    POST /htb/target          declare/replace the target (stage=discovery|authorized)
    POST /htb/target/clear    clear the target
    POST /htb/discover        governed service discovery (NETWORK_SERVICE_DISCOVERY)
"""
from __future__ import annotations

from pathlib import Path

from raphael_ibm_bob.discovery_runtime import suggested_protocols
from raphael_ibm_bob.harness import api
from raphael_ibm_bob.http import errors
from raphael_ibm_bob.http.routes._common import body_object
from raphael_ibm_bob.target_profile import (
    TARGET_STAGE_AUTHORIZED,
    TargetProfileError,
    build_target_profile,
    get_target_store,
)

#: Upper bound for a single synchronous discovery invocation from the UI.
MAX_DISCOVERY_TIMEOUT = 300.0


def _store(config):
    store = getattr(config, "target_store", None)
    return store if store is not None else get_target_store()


def get_target(request, params, config):
    """GET /htb/target — the currently declared target (safe dict)."""
    profile = _store(config).current()
    return {"configured": profile is not None,
            "target": profile.to_dict() if profile else None}


def set_target(request, params, config):
    """POST /htb/target — declare/replace the authorized target.

    ``stage`` selects the lifecycle stage. The default ``authorized`` keeps
    the original D9 requirement of explicit non-empty port and protocol
    allow-lists. ``discovery`` permits an IP-only declaration so governed
    service discovery can run before the ports are known; such a profile
    authorizes NETWORK_SERVICE_DISCOVERY only.
    """
    body = body_object(request)
    try:
        profile = build_target_profile(
            mission_id=body.get("mission_id"),
            locator=body.get("locator"),
            allowed_ports=body.get("allowed_ports"),
            allowed_protocols=body.get("allowed_protocols"),
            scope=body.get("scope"),
            authorization_ref=body.get("authorization_ref"),
            platform=body.get("platform", "htb"),
            stage=body.get("stage", TARGET_STAGE_AUTHORIZED),
        )
    except TargetProfileError as exc:
        raise errors.invalid_input(str(exc)) from None
    _store(config).set_target(profile)
    return 201, {"configured": True, "target": profile.to_dict()}


def clear_target(request, params, config):
    """POST /htb/target/clear — remove the declared target."""
    _store(config).clear_target()
    return {"configured": False, "target": None}


def discover_services(request, params, config):
    """POST /htb/discover — governed service discovery (D13+).

    Orchestration only: delegates to harness.api.start_discovery_run, which
    routes through Runtime → Broker → Policy → DiscoveryMediator. This
    route never calls the discovery runtime directly and never bypasses
    the governed path.

    Request body (JSON):
        {
          "host":        "10.129.x.x",       required
          "mission_id":  "M-HTB-001",        required
          "port_spec":   "1-1024",            optional (default: well-known ports)
          "timeout":     30.0                 optional
        }

    Returns:
        {
          "allowed":      bool,
          "success":      bool,
          "ports_open":   [int, ...],
          "port_details": [{port, state, service, latency_ms}, ...],
          "ports_probed": int,
          "host":         str,
          "state":        str,
          "capped":       bool,
          "error":        str | null,
          "deny_reason":  str | null
        }
    """
    body = body_object(request)
    host = body.get("host")
    mission_id = body.get("mission_id")
    if not isinstance(host, str) or not host.strip():
        raise errors.invalid_input("host is required")
    if not isinstance(mission_id, str) or not mission_id.strip():
        raise errors.invalid_input("mission_id is required")
    port_spec = str(body.get("port_spec") or "").strip()
    timeout_raw = body.get("timeout")
    timeout: float | None = None
    if timeout_raw is not None:
        try:
            timeout = float(timeout_raw)
        except (TypeError, ValueError):
            raise errors.invalid_input("timeout must be a number") from None
        if not (0 < timeout <= MAX_DISCOVERY_TIMEOUT):
            raise errors.invalid_input(
                f"timeout must be in (0, {MAX_DISCOVERY_TIMEOUT}] seconds")

    # Resolve workspace root from config (same pattern as operations.py).
    workspace_root = getattr(config, "runs_root", None) or Path("runs")
    # Use the parent of runs_root as the workspace root for the ephemeral broker.
    workspace_root = Path(workspace_root).parent.resolve()
    if not workspace_root.is_dir():
        workspace_root = Path(".").resolve()

    try:
        result = api.start_discovery_run(
            host=host.strip(),
            mission_id=mission_id.strip(),
            workspace_root=workspace_root,
            port_spec=port_spec,
            target_store=_store(config),
            timeout_seconds=timeout,
        )
    except Exception as exc:
        raise errors.invalid_input(str(exc)) from None

    status = 200 if result.allowed else 403
    return status, {
        "allowed":      result.allowed,
        "success":      result.success,
        "ports_open":   result.ports_open,
        "port_details": result.port_details,
        "ports_probed": result.ports_probed,
        "host":         result.host,
        "state":        result.state,
        "capped":       result.capped,
        "error":        result.error,
        "deny_reason":  result.deny_reason,
        "invocation_id": result.invocation_id,
        "suggested_protocols": list(suggested_protocols(result.ports_open)),
    }


__all__ = ["MAX_DISCOVERY_TIMEOUT", "clear_target", "discover_services",
           "get_target", "set_target"]
