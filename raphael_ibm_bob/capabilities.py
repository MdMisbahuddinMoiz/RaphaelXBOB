"""raphael_ibm_bob.capabilities — MVP capability implementations.

Each capability is a pure function over `(workspace, request) -> result_dict`.
The Broker invokes a capability only after Policy ALLOWs. Capabilities
themselves do NOT consult the Policy (separation of concerns); the
Broker is the single consultation point.

Implemented capabilities:
    READ      - read a regular file inside the workspace.
    LIST      - list a directory inside the workspace.
    SEARCH    - grep-search a directory inside the workspace.
    WRITE     - write a file inside the workspace.
    RUN_TEST  - invoke `python3 -m unittest <module>` for a single test file.

Network access: NONE.
Process execution: ONLY for RUN_TEST, scoped to `python3 -m unittest`.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict

from raphael_ibm_bob.contracts import ActionRequest, Capability
from raphael_ibm_bob.run_test_sandbox import run_test_in_sandbox
from raphael_ibm_bob.workspace import Workspace



# -----------------------------------------------------------------------------
# Resource bounds (Phase 1 hardening)
# -----------------------------------------------------------------------------

#: Maximum number of files SEARCH will inspect in one invocation.
MAX_SEARCH_FILES = 5000
#: Maximum number of matching lines SEARCH will return.
MAX_SEARCH_MATCHES = 1000
#: Maximum size (bytes) of a single file SEARCH will read.
MAX_SEARCH_FILE_BYTES = 1_000_000
#: Maximum length of a returned matching line (characters).
MAX_SEARCH_LINE = 200



def _read(workspace: Workspace, request: ActionRequest) -> Dict[str, Any]:
    p = workspace.resolve(request.target)
    return {"path": str(p), "content": p.read_text(encoding="utf-8", errors="replace")}


def _list(workspace: Workspace, request: ActionRequest) -> Dict[str, Any]:
    p = workspace.resolve(request.target)
    entries = sorted(e.name for e in p.iterdir())
    return {"path": str(p), "entries": entries}


def _search(workspace: Workspace, request: ActionRequest) -> Dict[str, Any]:
    """Regex-search a directory with explicit resource bounds.

    Bound (Phase 1 hardening): at most ``MAX_SEARCH_FILES`` files are
    inspected, files larger than ``MAX_SEARCH_FILE_BYTES`` are skipped,
    and at most ``MAX_SEARCH_MATCHES`` matching lines are returned. When
    any bound is hit the payload is marked ``truncated=True`` so callers
    never mistake a partial sweep for an exhaustive one.
    """
    p = workspace.resolve(request.target)
    pattern = request.purpose  # SEARCH uses `purpose` as the search pattern
    if not pattern:
        return {"path": str(p), "matches": [], "truncated": False,
                "scanned_files": 0, "skipped_files": 0}
    rx = re.compile(pattern)
    matches: list[Dict[str, Any]] = []
    scanned_files = 0
    skipped_files = 0
    truncated = False
    for path in p.rglob("*"):
        if not path.is_file():
            continue
        if scanned_files >= MAX_SEARCH_FILES:
            truncated = True
            break
        try:
            if path.stat().st_size > MAX_SEARCH_FILE_BYTES:
                skipped_files += 1
                continue
        except OSError:
            skipped_files += 1
            continue
        scanned_files += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), start=1):
            if rx.search(line):
                matches.append({"file": str(path), "line": i,
                                "text": line[:MAX_SEARCH_LINE]})
                if len(matches) >= MAX_SEARCH_MATCHES:
                    truncated = True
                    break
        if truncated and len(matches) >= MAX_SEARCH_MATCHES:
            break
    return {"path": str(p), "matches": matches, "truncated": truncated,
            "scanned_files": scanned_files, "skipped_files": skipped_files}



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


def _run_test(workspace: Workspace, request: ActionRequest) -> Dict[str, Any]:
    """Run one authorized test in the fail-closed Linux sandbox."""
    test_path = workspace.resolve(request.target)
    relative = test_path.relative_to(workspace.root).with_suffix("")
    module = ".".join(relative.parts)
    timeout = (
        request.timeout_seconds
        if request.timeout_seconds is not None
        else 30.0
    )
    result = run_test_in_sandbox(
        workspace_root=workspace.root,
        test_path=test_path,
        requested_target=request.target,
        module=module,
        timeout_seconds=timeout,
        fixture_manifest=request.purpose,
    )
    payload: Dict[str, Any] = {
        "module": module,
        "returncode": result.returncode,
        "sandboxed": result.sandboxed,
        "sandbox_provider": result.sandbox_provider,
        "network_isolated": result.network_isolated,
        "workspace_mount": result.workspace_mount,
        "sandbox_failure_reason": result.sandbox_failure_reason,
        "output_truncated": result.output_truncated,
        "process_group_managed": result.process_group_managed,
        "process_group_cleanup_verified": (
            result.process_group_cleanup_verified
        ),
        "resource_limits": dict(result.resource_limits),
        "approved_fixture_count": result.approved_fixture_count,
        "approved_fixture_bytes": result.approved_fixture_bytes,
    }
    if result.timed_out:
        payload.update({
            "timeout": True,
            "timeout_seconds": timeout,
            "partial_stdout": result.stdout,
            "partial_stderr": result.stderr,
            "stdout_truncated": result.stdout_truncated,
            "stderr_truncated": result.stderr_truncated,
        })
    else:
        payload.update({
            "stdout": result.stdout,
            "stderr": result.stderr,
            "stdout_truncated": result.stdout_truncated,
            "stderr_truncated": result.stderr_truncated,
        })
    return payload


CAPABILITY_DISPATCH = {
    Capability.READ: _read,
    Capability.LIST: _list,
    Capability.SEARCH: _search,
    Capability.WRITE: _write,
    Capability.RUN_TEST: _run_test,
}


def execute_capability(workspace: Workspace, request: ActionRequest) -> Dict[str, Any]:
    """Dispatch an allowed request to its capability implementation.

    The Broker guarantees that this function is reached only after
    Policy ALLOW. Capabilities themselves do NOT re-consult Policy.
    """
    handler = CAPABILITY_DISPATCH.get(request.capability)
    if handler is None:
        raise ValueError(f"no capability handler for {request.capability}")
    return handler(workspace, request)


__all__ = ["execute_capability"]