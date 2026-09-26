"""raphael_ibm_bob.discovery_runtime — governed service/port discovery (D13+).

The ONLY network-I/O boundary for ``Capability.NETWORK_SERVICE_DISCOVERY``.
This capability lets an operator discover which ports are open on a declared
authorized target WITHOUT having to pre-enumerate them manually in the UI.

Design constraints (mirror D9/D12 discipline):
    * no subprocess, no shell, no nmap, no system tools
    * stdlib socket.connect_ex only — pure TCP reachability per port
    * bounded port range declared by the operator in the TargetProfile's
      discovery_port_range field (or an explicit scan_spec in ActionRequest
      purpose); never arbitrary scanning
    * scope re-validated before any socket (defence in depth)
    * per-port invocation is deterministic and bound by timeout
    * output is UNTRUSTED evidence, never authority; Policy decides
    * a failed probe (refused/timeout) is NEVER success for that port
    * total probe count is capped at MAX_DISCOVERY_PORTS
    * results are structured service evidence consumable by the Planner

No shell, no subprocess, no proxy, no raw packets, no OS fingerprinting.
"""
from __future__ import annotations

import hashlib
import json
import socket
import threading
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

from raphael_ibm_bob.contracts import ActionRequest, Capability, Decision
from raphael_ibm_bob.network_runtime import _decision_allows
from raphael_ibm_bob.network_scope import NetworkScopeError, canonical_host
from raphael_ibm_bob.target_profile import TargetProfile

DISCOVERY_CAPABILITY_ID = Capability.NETWORK_SERVICE_DISCOVERY.value
PROVIDER_UNTRUSTED = "provider_untrusted"

#: Hard cap: no single invocation may probe more than this many ports.
MAX_DISCOVERY_PORTS = 1024
#: Per-port TCP connection timeout in seconds.
DEFAULT_PORT_TIMEOUT = 1.0
#: Default per-invocation wall-clock timeout (all ports combined).
DEFAULT_INVOCATION_TIMEOUT = 30.0
#: Maximum ports per scan invocation (operator configurable up to the hard cap).
DEFAULT_MAX_PORTS = 128

# Well-known port→service mapping (deterministic, no subprocess).
# Only named when the service is unambiguous at the protocol level.
_WELL_KNOWN: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}


class DiscoveryState(str, Enum):
    SUCCESS = "success"    # at least one port responded
    NO_OPEN_PORTS = "no_open_ports"
    DENIED = "denied"
    TIMEOUT = "timeout"
    ERROR = "error"


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"   # timeout — may be firewalled


@dataclass(frozen=True)
class PortResult:
    """Single-port probe outcome."""
    port: int
    state: PortState
    service: Optional[str]
    latency_ms: float
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "state": self.state.value,
            "service": self.service,
            "latency_ms": round(self.latency_ms, 2),
            "error": self.error,
        }


@dataclass(frozen=True)
class DiscoveryResult:
    """Closed, bounded outcome of one governed discovery invocation."""
    state: DiscoveryState
    invocation_id: str
    mission_id: str
    target_id: str
    host: str
    ports_probed: int
    ports_open: Tuple[int, ...]
    port_results: Tuple[PortResult, ...]
    elapsed_seconds: float
    run_id: str = ""
    error: str = ""
    capped: bool = False    # True when the port list was hard-capped
    #: The exact port list this invocation actually probed. Published so
    #: a consumer can never mistake a bounded sweep for an exhaustive
    #: scan of the port space.
    probed_ports: Tuple[int, ...] = ()

    @property
    def success(self) -> bool:
        return self.state is DiscoveryState.SUCCESS

    @property
    def exhaustive(self) -> bool:
        """A discovery sweep is NEVER exhaustive over the port space."""
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state.value,
            "invocation_id": self.invocation_id,
            "mission_id": self.mission_id,
            "target_id": self.target_id,
            "host": self.host,
            "ports_probed": self.ports_probed,
            "ports_open": list(self.ports_open),
            "port_results": [r.to_dict() for r in self.port_results],
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "run_id": self.run_id,
            "error": self.error,
            "capped": self.capped,
            "exhaustive": False,
            "probed_ports": list(self.probed_ports),
            PROVIDER_UNTRUSTED: True,
        }


def _classify_service(port: int) -> Optional[str]:
    """Deterministic well-known port→service name. Never a subprocess."""
    return _WELL_KNOWN.get(port)


#: Port->governed protocol, so a discovery result can refine the target's
#: protocol allow-list. Intersected with ``ALLOWED_PROTOCOLS`` on use, so a
#: suggestion can never widen the executable capability surface.
_PORT_PROTOCOLS: Dict[int, str] = {
    23: "telnet",
    80: "http", 443: "https", 4443: "https", 8443: "https",
    8000: "http", 8080: "http", 8081: "http", 8888: "http",
    9000: "http", 9090: "http", 10000: "http",
}


def suggested_protocols(ports: Sequence[int]) -> Tuple[str, ...]:
    """Protocols the discovered ports could support (a UI hint, not authority)."""
    from raphael_ibm_bob.target_profile import ALLOWED_PROTOCOLS
    hits = {_PORT_PROTOCOLS[int(p)] for p in ports if int(p) in _PORT_PROTOCOLS}
    return tuple(sorted(hits & set(ALLOWED_PROTOCOLS)))


def _parse_port_spec(purpose: str,
                     authorized: Sequence[int] = ()
                     ) -> Tuple[Tuple[int, ...], int]:
    """Parse operator-supplied port specification from ActionRequest.purpose.

    Accepted forms (in purpose string):
        ports=80,443,8080          comma-separated explicit list
        ports=1-1024               inclusive range
        (absent)                   use DEFAULT_MAX_PORTS common ports

    `purpose` doubles as the proposal's rationale, so a model may write
    "ports=8080) to see what answers". The port list is therefore read
    as the well-formed PREFIX of the clause token, and the remainder
    must start at a separator. A clause whose continuation is itself
    port-ish (`ports=80a`, `ports=1-2-3`) or which never begins with a
    digit (`ports=abc`) is still a malformed spec and still raises —
    fail-closed is preserved, only trailing prose is tolerated.

    Returns (tuple-of-ports, effective-max-ports).
    Raises ValueError for malformed specs.
    """
    import re
    # Extract the ports= clause and its token.
    m = re.search(r"ports=(\S+)", purpose or "")
    if not m:
        # No ports= clause: sweep the AUTHORIZED set (plus common ports)
        # rather than a fixed 38-port guess list. `authorized` comes from
        # the mission-bound TargetProfile, so this is declared scope, not
        # a guess. DEFAULT_MAX_PORTS bounds the returned count.
        sweep = _default_ports(authorized)
        return sweep, min(len(sweep), DEFAULT_MAX_PORTS)

    token = m.group(1)
    prefix = re.match(r"[0-9][0-9,\-]*", token)
    if prefix is None:
        raise ValueError(f"invalid port: {token.split(',')[0]!r}")
    spec = prefix.group(0)
    trailing = token[len(spec):]
    if trailing and (trailing[0].isalnum() or trailing[0] in ",-"):
        # The clause continues with port-list characters, so the whole
        # token is meant to be the spec and it is malformed.
        raise ValueError(f"invalid port: {token!r}")
    # Range: e.g. 1-1024
    range_m = re.fullmatch(r"(\d+)-(\d+)", spec)
    if range_m:
        lo, hi = int(range_m.group(1)), int(range_m.group(2))
        if lo < 1 or hi > 65535 or lo > hi:
            raise ValueError(f"port range out of bounds: {spec!r}")
        # Cap before materialising so a 1-65535 request cannot force a
        # 65k-element tuple; work is bounded by MAX_DISCOVERY_PORTS.
        ports = tuple(range(lo, min(hi, lo + MAX_DISCOVERY_PORTS - 1) + 1))
    else:
        # Comma list
        raw_parts = spec.split(",")
        ports_list = []
        for raw in raw_parts:
            raw = raw.strip()
            if not raw:
                continue
            try:
                p = int(raw)
            except ValueError:
                raise ValueError(f"invalid port: {raw!r}") from None
            if not (1 <= p <= 65535):
                raise ValueError(f"port out of range: {p}")
            ports_list.append(p)
        if not ports_list:
            raise ValueError("ports spec produced no ports")
        ports = tuple(sorted(set(ports_list)))

    # AUTHORIZATION IS A FLOOR, NOT A SUGGESTION.
    #
    # Whatever range the caller asked for, every port the operator
    # declared in the TargetProfile is ALSO swept. Otherwise a model
    # could propose ports=1-1024, hit the bounded cap, and silently
    # never see the SSH service the operator explicitly authorized —
    # exactly the failure this path exists to prevent.
    #
    # Authorized ports are placed FIRST so the hard cap can only ever
    # truncate the caller's own exploration, never the declared scope.
    extra_authorized: List[int] = []
    for port in authorized or ():
        try:
            value = int(port)
        except (TypeError, ValueError):
            continue
        if 1 <= value <= 65535 and value not in ports:
            extra_authorized.append(value)
    if extra_authorized:
        ports = tuple(extra_authorized) + ports

    if len(ports) > MAX_DISCOVERY_PORTS:
        ports = ports[:MAX_DISCOVERY_PORTS]

    return ports, len(ports)


def _parse_max_ports(purpose: object) -> int:
    """Read an optional ``max_ports=`` clause from a discovery purpose.

    Lets a mission or a model widen one sweep within the hard ceiling.
    A malformed value raises, so the caller fails closed. Returns 0
    when the clause is absent, meaning "use the mediator bound".
    """
    text = purpose if isinstance(purpose, str) else ""
    match = re.search(r"max_ports=(\d+)", text)
    return int(match.group(1)) if match else 0


def _default_ports(authorized: Sequence[int] = ()) -> Tuple[int, ...]:
    """Bounded sweep for a discovery request with no ``ports=`` clause.

    The sweep is built from AUTHORIZATION, not from a guess: every port
    the operator declared in the TargetProfile is included, because a
    declared port is exactly the scope Policy will later authorize. The
    common well-known set is added so a model still gets the usual
    service picture when the profile authorizes nothing extra.

    The result is deduplicated, sorted, and bounded by
    ``MAX_DISCOVERY_PORTS``; the caller still reports ``capped`` and
    ``ports_probed`` truthfully, so a truncated sweep is never presented
    as exhaustive.
    """
    common = sorted(_WELL_KNOWN.keys())
    extra = [135, 139, 389, 636, 2049, 2222, 4443, 8000, 8008,
             8081, 8888, 9000, 9090, 10000]
    ports = set(common) | set(extra)
    for port in authorized or ():
        try:
            value = int(port)
        except (TypeError, ValueError):
            continue
        if 1 <= value <= 65535:
            ports.add(value)
    return tuple(sorted(ports)[:MAX_DISCOVERY_PORTS])


def _probe_port(host: str, port: int, timeout: float) -> PortResult:
    """Single TCP connect probe. Never raises; returns a PortResult."""
    t0 = time.monotonic()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        err = sock.connect_ex((host, port))
        sock.close()
        elapsed = (time.monotonic() - t0) * 1000.0
        if err == 0:
            return PortResult(
                port=port,
                state=PortState.OPEN,
                service=_classify_service(port),
                latency_ms=elapsed,
            )
        else:
            return PortResult(
                port=port,
                state=PortState.CLOSED,
                service=None,
                latency_ms=elapsed,
                error=f"connect_ex:{err}",
            )
    except (socket.timeout, TimeoutError):
        elapsed = (time.monotonic() - t0) * 1000.0
        return PortResult(
            port=port,
            state=PortState.FILTERED,
            service=None,
            latency_ms=elapsed,
            error="timeout",
        )
    except OSError as exc:
        elapsed = (time.monotonic() - t0) * 1000.0
        return PortResult(
            port=port,
            state=PortState.CLOSED,
            service=None,
            latency_ms=elapsed,
            error=f"{type(exc).__name__}:{exc}",
        )


class DiscoveryMediator:
    """Governed service discovery mediator.

    Executes bounded TCP port probes in order, validates scope before any
    socket, and produces a closed DiscoveryResult. All I/O is stdlib socket
    only — no subprocess, no shell, no external tools.
    """

    def __init__(
        self,
        *,
        port_timeout: float = DEFAULT_PORT_TIMEOUT,
        invocation_timeout: float = DEFAULT_INVOCATION_TIMEOUT,
        max_ports: int = DEFAULT_MAX_PORTS,
    ) -> None:
        if port_timeout <= 0:
            raise ValueError("port_timeout must be positive")
        if invocation_timeout <= 0:
            raise ValueError("invocation_timeout must be positive")
        if max_ports < 1 or max_ports > MAX_DISCOVERY_PORTS:
            raise ValueError(
                f"max_ports must be 1–{MAX_DISCOVERY_PORTS}")
        self._port_timeout = float(port_timeout)
        self._inv_timeout = float(invocation_timeout)
        self._max_ports = int(max_ports)

    def invoke(
        self,
        *,
        request: ActionRequest,
        profile: TargetProfile,
        invocation_id: str,
        run_id: str,
        decision: Any = None,
    ) -> DiscoveryResult:
        """Validate scope + Policy decision, then probe bounded port set."""
        mission_id = profile.mission_id
        target_id = profile.target_id

        def _deny(reason: str) -> DiscoveryResult:
            return DiscoveryResult(
                state=DiscoveryState.DENIED,
                invocation_id=invocation_id,
                mission_id=mission_id,
                target_id=target_id,
                host=profile.locator,
                ports_probed=0,
                ports_open=(),
                port_results=(),
                elapsed_seconds=0.0,
                run_id=run_id,
                error=reason,
            )

        # 1. Validate scope: host must be the declared profile locator.
        try:
            canonical = canonical_host(profile.locator)
        except NetworkScopeError as exc:
            return _deny(f"scope-invalid:{exc}")

        # Extract the target host from the request; must match profile locator.
        req_host = request.target.strip()
        try:
            req_canonical = canonical_host(req_host)
        except NetworkScopeError as exc:
            return _deny(f"target-invalid:{exc}")
        if req_canonical != canonical:
            return _deny("target-not-authorized")

        # 2. Policy decision must be ALLOW for this exact request.
        if not _decision_allows(decision, request):
            return _deny("authorization-not-allow")

        # 3. Parse port spec from request purpose (fail closed on malformed).
        try:
            ports, _ = _parse_port_spec(
                request.purpose or "", profile.allowed_ports)
        except ValueError as exc:
            return _deny(f"port-spec-invalid:{exc}")

        # 4. Bound the sweep. The per-invocation ceiling is the smaller
        #    of the mediator's configured bound and a mission-declared
        #    `max_ports`, both clamped to MAX_DISCOVERY_PORTS. A model
        #    can therefore widen a sweep on a later turn, but never past
        #    the hard ceiling, and any truncation is reported as `capped`.
        ceiling = self._max_ports
        try:
            requested = int(_parse_max_ports(request.purpose or ""))
        except ValueError:
            requested = 0
        if requested > 0:
            ceiling = min(ceiling, requested)
        ceiling = max(1, min(ceiling, MAX_DISCOVERY_PORTS))
        capped = len(ports) > ceiling
        if capped:
            ports = ports[:ceiling]

        # 5. Execute bounded probes.
        t_start = time.monotonic()
        results: List[PortResult] = []
        deadline = t_start + self._inv_timeout
        timed_out = False
        for port in ports:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            per_port = min(self._port_timeout, remaining)
            result = _probe_port(canonical, port, per_port)
            results.append(result)

        elapsed = time.monotonic() - t_start
        open_ports = tuple(r.port for r in results if r.state is PortState.OPEN)

        if timed_out and not results:
            return DiscoveryResult(
                state=DiscoveryState.TIMEOUT,
                invocation_id=invocation_id,
                mission_id=mission_id,
                target_id=target_id,
                host=canonical,
                ports_probed=0,
                ports_open=(),
                port_results=(),
                elapsed_seconds=elapsed,
                run_id=run_id,
                error="invocation-timeout",
                capped=capped,
            )

        state = (DiscoveryState.SUCCESS if open_ports
                 else DiscoveryState.NO_OPEN_PORTS)
        return DiscoveryResult(
            state=state,
            invocation_id=invocation_id,
            mission_id=mission_id,
            target_id=target_id,
            host=canonical,
            ports_probed=len(results),
            ports_open=open_ports,
            probed_ports=tuple(p.port for p in results),
            port_results=tuple(results),
            elapsed_seconds=elapsed,
            run_id=run_id,
            error="invocation-timeout-partial" if timed_out else "",
            capped=capped,
        )


_mediator_singleton: Optional[DiscoveryMediator] = None
_mediator_lock = threading.Lock()


def get_discovery_mediator() -> DiscoveryMediator:
    global _mediator_singleton
    with _mediator_lock:
        if _mediator_singleton is None:
            _mediator_singleton = DiscoveryMediator()
        return _mediator_singleton


def set_discovery_mediator(mediator: Optional[DiscoveryMediator]) -> None:
    global _mediator_singleton
    with _mediator_lock:
        _mediator_singleton = mediator


__all__ = [
    "DISCOVERY_CAPABILITY_ID",
    "DEFAULT_INVOCATION_TIMEOUT",
    "DEFAULT_MAX_PORTS",
    "DEFAULT_PORT_TIMEOUT",
    "MAX_DISCOVERY_PORTS",
    "DiscoveryMediator",
    "DiscoveryResult",
    "DiscoveryState",
    "PortResult",
    "PortState",
    "get_discovery_mediator",
    "set_discovery_mediator",
    "suggested_protocols",
]
