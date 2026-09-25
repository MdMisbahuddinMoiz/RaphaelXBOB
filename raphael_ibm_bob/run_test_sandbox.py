"""Fail-closed Linux bubblewrap executor for governed RUN_TEST requests.

The Broker and Policy remain authoritative.  This helper receives only an
already-authorized workspace and canonical test path, stages the test package's
Python source into a private temporary directory, and launches the unchanged
unittest command inside bubblewrap.

Security claims are intentionally narrow: the boundary depends on Linux user,
mount, PID, and network namespace support.  No seccomp policy, production
hardening claim, or fallback to direct host execution is provided here.
"""
from __future__ import annotations

import json
import math
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Dict, Optional, Tuple

DEFAULT_MAX_STDOUT_BYTES = 64 * 1024
DEFAULT_MAX_STDERR_BYTES = 16 * 1024
RETURN_TEXT_LIMIT = 4000
SANDBOX_UID = 65534
SANDBOX_GID = 65534
SANDBOX_WORKSPACE = "/workspace"
SANDBOX_PRIVATE_TMP = "/tmp/raphael-run-test"
SANDBOX_HOME = "/home/raphael"
MAX_FIXTURE_FILES = 4096
MAX_FIXTURE_BYTES = 32 * 1024 * 1024
FIXTURE_MANIFEST_PREFIX = "run-test-fixtures="
MAX_FIXTURE_MANIFEST_CHARS = 4096
MAX_APPROVED_FIXTURES = 128
CREDENTIAL_SUFFIXES = frozenset({
    ".crt", ".cer", ".der", ".env", ".key", ".keystore", ".kdbx",
    ".ovpn", ".p12", ".pem", ".pfx", ".ppk",
})
CREDENTIAL_NAME_MARKERS = (
    "api_key", "credential", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa",
    "password", "private_key", "secret", "token",
)
MAX_FIXTURE_FILE_BYTES = 4 * 1024 * 1024


class SandboxConfigurationError(Exception):
    """A non-secret, fail-closed sandbox configuration error."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class RunTestSandboxResult:
    """Bounded result of one sandbox launch attempt."""

    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool
    sandboxed: bool
    sandbox_provider: Optional[str]
    network_isolated: bool
    workspace_mount: str
    sandbox_failure_reason: Optional[str]
    output_truncated: bool
    process_group_managed: bool
    process_group_cleanup_verified: bool
    stdout_truncated: bool
    stderr_truncated: bool
    resource_limits: Dict[str, object]
    approved_fixture_count: int = 0
    approved_fixture_bytes: int = 0



@dataclass(frozen=True)
class _ApprovedFixture:
    relative_path: Path
    source_path: Path
    size: int

@dataclass
class _BoundedOutput:
    cap: int
    buffer: bytearray
    truncated: bool = False

    @classmethod
    def create(cls, cap: int) -> "_BoundedOutput":
        return cls(cap=cap, buffer=bytearray())

    def append(self, chunk: bytes) -> None:
        remaining = self.cap - len(self.buffer)
        if remaining > 0:
            self.buffer.extend(chunk[:remaining])
        if len(chunk) > max(remaining, 0):
            self.truncated = True


def _refusal(
    reason: str,
    *,
    provider: Optional[str] = None,
    timeout_seconds: Optional[float] = None,
    max_stdout_bytes: int = DEFAULT_MAX_STDOUT_BYTES,
    max_stderr_bytes: int = DEFAULT_MAX_STDERR_BYTES,
) -> RunTestSandboxResult:
    return RunTestSandboxResult(
        returncode=None,
        stdout="",
        stderr="",
        timed_out=False,
        sandboxed=False,
        sandbox_provider=provider,
        network_isolated=False,
        workspace_mount=f"{SANDBOX_WORKSPACE} (not mounted)",
        sandbox_failure_reason=reason,
        output_truncated=False,
        process_group_managed=False,
        process_group_cleanup_verified=False,
        stdout_truncated=False,
        stderr_truncated=False,
        resource_limits={
            "wall_clock_seconds": timeout_seconds,
            "stdout_capture_bytes": max_stdout_bytes,
            "stderr_capture_bytes": max_stderr_bytes,
            "cpu_time_enforced": False,
            "memory_limit_enforced": False,
            "process_count_limit_enforced": False,
        },
    )


def _finite_limit(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SandboxConfigurationError(f"{name}-invalid")
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise SandboxConfigurationError(f"{name}-invalid")
    return number


def _positive_int(value: object, name: str) -> int:
    number = _finite_limit(value, name)
    integer = int(number)
    if integer != number:
        raise SandboxConfigurationError(f"{name}-invalid")
    return integer


def _validate_workspace(workspace_root: Path) -> Path:
    try:
        root = Path(workspace_root)
        resolved = root.resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError):
        raise SandboxConfigurationError("workspace-invalid") from None
    if not resolved.is_dir() or resolved != root or not root.is_absolute():
        raise SandboxConfigurationError("workspace-invalid")
    return resolved


def _validate_test_path(
    workspace_root: Path,
    requested_target: str,
    test_path: Path,
    module: str,
) -> Path:
    if not isinstance(requested_target, str) or not requested_target:
        raise SandboxConfigurationError("test-path-invalid")
    raw = Path(requested_target)
    if not raw.is_absolute():
        raw = workspace_root / raw
    try:
        lexical = Path(os.path.abspath(os.fspath(raw)))
        relative = lexical.relative_to(workspace_root)
    except (OSError, TypeError, ValueError):
        raise SandboxConfigurationError("test-path-outside-workspace") from None

    current = workspace_root
    for part in relative.parts:
        current = current / part
        try:
            mode = os.lstat(current).st_mode
        except OSError:
            raise SandboxConfigurationError("test-path-missing") from None
        if stat.S_ISLNK(mode):
            raise SandboxConfigurationError("test-path-symlink")

    try:
        canonical = Path(test_path).resolve(strict=True)
        canonical.relative_to(workspace_root)
    except (OSError, RuntimeError, TypeError, ValueError):
        raise SandboxConfigurationError("test-path-invalid") from None
    try:
        mode = os.lstat(canonical).st_mode
    except OSError:
        raise SandboxConfigurationError("test-path-missing") from None
    if not stat.S_ISREG(mode):
        raise SandboxConfigurationError("test-path-not-regular")
    if canonical != lexical:
        raise SandboxConfigurationError("test-path-alternate")
    expected_module = ".".join(
        canonical.relative_to(workspace_root).with_suffix("").parts
    )
    if module != expected_module:
        raise SandboxConfigurationError("test-module-mismatch")
    return canonical.parent


def _credential_like_fixture(path: Path) -> bool:
    name = path.name.lower()
    return (
        path.suffix.lower() in CREDENTIAL_SUFFIXES
        or any(marker in name for marker in CREDENTIAL_NAME_MARKERS)
    )


def _parse_fixture_manifest(manifest: Optional[str]) -> Tuple[str, ...]:
    if manifest is None or not manifest.startswith(FIXTURE_MANIFEST_PREFIX):
        return ()
    if len(manifest) > MAX_FIXTURE_MANIFEST_CHARS:
        raise SandboxConfigurationError("fixture-manifest-invalid")
    try:
        raw_paths = json.loads(manifest[len(FIXTURE_MANIFEST_PREFIX):])
    except (TypeError, ValueError):
        raise SandboxConfigurationError("fixture-manifest-invalid") from None
    if not isinstance(raw_paths, list):
        raise SandboxConfigurationError("fixture-manifest-invalid")
    if len(raw_paths) > MAX_APPROVED_FIXTURES:
        raise SandboxConfigurationError("fixture-manifest-too-large")

    approved = []
    seen = set()
    for raw_path in raw_paths:
        if (not isinstance(raw_path, str) or not raw_path
                or len(raw_path) > 1024 or "\x00" in raw_path
                or "\\" in raw_path):
            raise SandboxConfigurationError("fixture-path-invalid")
        path = Path(raw_path)
        if path.is_absolute():
            raise SandboxConfigurationError("fixture-path-absolute")
        if path.as_posix() != raw_path or any(
                part in (".", "..") for part in path.parts):
            raise SandboxConfigurationError("fixture-path-traversal")
        if not path.parts or any(part.startswith(".") for part in path.parts):
            raise SandboxConfigurationError("fixture-hidden")
        if _credential_like_fixture(path):
            raise SandboxConfigurationError("fixture-credential")
        if raw_path in seen:
            raise SandboxConfigurationError("fixture-duplicate")
        seen.add(raw_path)
        approved.append(raw_path)
    return tuple(approved)


def _validate_approved_fixtures(
    workspace_root: Path,
    fixture_paths: Tuple[str, ...],
) -> Tuple[_ApprovedFixture, ...]:
    approved = []
    total_bytes = 0
    for relative_text in fixture_paths:
        relative_path = Path(relative_text)
        current = workspace_root
        try:
            for part in relative_path.parts:
                current = current / part
                mode = os.lstat(current).st_mode
                if stat.S_ISLNK(mode):
                    raise SandboxConfigurationError("fixture-symlink")
        except FileNotFoundError:
            raise SandboxConfigurationError("fixture-missing") from None
        except OSError:
            raise SandboxConfigurationError("fixture-unreadable") from None
        try:
            canonical = current.resolve(strict=True)
            canonical.relative_to(workspace_root)
        except (OSError, RuntimeError, ValueError):
            raise SandboxConfigurationError("fixture-invalid") from None
        if canonical != current:
            raise SandboxConfigurationError("fixture-path-alternate")
        mode = os.lstat(canonical).st_mode
        if not stat.S_ISREG(mode):
            raise SandboxConfigurationError("fixture-not-regular")
        size = canonical.stat().st_size
        if size > MAX_FIXTURE_FILE_BYTES:
            raise SandboxConfigurationError("fixture-file-too-large")
        total_bytes += size
        if total_bytes > MAX_FIXTURE_BYTES:
            raise SandboxConfigurationError("fixture-tree-too-large")
        approved.append(_ApprovedFixture(
            relative_path=relative_path,
            source_path=canonical,
            size=size,
        ))
    return tuple(approved)


def _copy_approved_fixtures(
    fixtures: Tuple[_ApprovedFixture, ...],
    staged_workspace: Path,
    *,
    remaining_files: int,
    remaining_bytes: int,
) -> Tuple[int, int]:
    if len(fixtures) > remaining_files:
        raise SandboxConfigurationError("fixture-too-many-files")
    copied_bytes = sum(item.size for item in fixtures)
    if copied_bytes > remaining_bytes:
        raise SandboxConfigurationError("fixture-tree-too-large")
    for fixture in fixtures:
        target = staged_workspace / fixture.relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copyfile(
                fixture.source_path, target, follow_symlinks=False)
        except OSError:
            raise SandboxConfigurationError("fixture-copy-failed") from None
    return len(fixtures), copied_bytes


def _copy_python_fixture_tree(
    source: Path,
    destination: Path,
) -> Tuple[int, int]:
    """Copy only Python source from the authorized test package directory.

    Non-Python files and hidden directories are not mounted.  Any Python
    symlink fails closed.  This keeps data files, host configuration, VCS
    metadata, and credential-like files outside the sandbox mount.
    """
    copied_files = 0
    copied_bytes = 0
    for current_text, dirnames, filenames in os.walk(
        source, topdown=True, followlinks=False
    ):
        current = Path(current_text)
        kept_dirs = []
        for name in sorted(dirnames):
            entry = current / name
            if name.startswith(".") or name == "__pycache__":
                continue
            if entry.is_symlink():
                raise SandboxConfigurationError("fixture-symlink")
            if not entry.is_dir():
                raise SandboxConfigurationError("fixture-not-directory")
            kept_dirs.append(name)
        dirnames[:] = kept_dirs

        for name in sorted(filenames):
            if name.startswith(".") or not name.endswith(".py"):
                continue
            entry = current / name
            try:
                mode = os.lstat(entry).st_mode
            except OSError:
                raise SandboxConfigurationError("fixture-unreadable") from None
            if stat.S_ISLNK(mode):
                raise SandboxConfigurationError("fixture-symlink")
            if not stat.S_ISREG(mode):
                raise SandboxConfigurationError("fixture-not-regular")
            size = entry.stat().st_size
            if size > MAX_FIXTURE_FILE_BYTES:
                raise SandboxConfigurationError("fixture-file-too-large")
            copied_files += 1
            copied_bytes += size
            if copied_files > MAX_FIXTURE_FILES:
                raise SandboxConfigurationError("fixture-too-many-files")
            if copied_bytes > MAX_FIXTURE_BYTES:
                raise SandboxConfigurationError("fixture-tree-too-large")
            target = destination / entry.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copyfile(entry, target, follow_symlinks=False)
            except OSError:
                raise SandboxConfigurationError("fixture-copy-failed") from None


    return copied_files, copied_bytes

def _find_bwrap() -> str:
    candidate = shutil.which("bwrap")
    if not candidate:
        raise SandboxConfigurationError("sandbox-unavailable")
    path = Path(candidate)
    if not path.is_absolute():
        raise SandboxConfigurationError("sandbox-path-invalid")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        raise SandboxConfigurationError("sandbox-path-invalid") from None
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise SandboxConfigurationError("sandbox-path-invalid")
    return str(resolved)


def _runtime_mounts() -> Tuple[Tuple[str, str], ...]:
    candidates = [Path("/usr"), Path("/lib"), Path("/lib64")]
    for value in (sys.prefix, sys.base_prefix, str(Path(sys.executable).parent)):
        candidate = Path(value)
        if candidate.is_absolute():
            candidates.append(candidate)

    mounts = []
    destinations = set()
    for candidate in candidates:
        if not candidate.is_absolute() or not candidate.is_dir():
            raise SandboxConfigurationError("runtime-mount-invalid")
        source = str(candidate.resolve(strict=True))
        destination = str(candidate)
        if destination in destinations:
            continue
        if any(destination.startswith(root + os.sep) for root in destinations):
            continue
        destinations.add(destination)
        mounts.append((source, destination))
    if not mounts:
        raise SandboxConfigurationError("runtime-mount-invalid")
    return tuple(mounts)


def _validate_runtime() -> str:
    executable = Path(sys.executable)
    if not executable.is_absolute() or not executable.is_file():
        raise SandboxConfigurationError("runtime-executable-invalid")
    if not os.access(executable, os.X_OK):
        raise SandboxConfigurationError("runtime-executable-invalid")
    return str(executable)


def _safe_parent_value(name: str, value: str, maximum: int = 256) -> bool:
    return bool(value) and len(value) <= maximum and "\x00" not in value


def _sandbox_environment(executable: str) -> Dict[str, str]:
    executable_dir = str(Path(executable).parent)
    env = {
        "PATH": executable_dir + ":/usr/bin:/bin",
        "HOME": SANDBOX_HOME,
        "LANG": "C.UTF-8",
        "TMPDIR": SANDBOX_PRIVATE_TMP,
        "PYTHONPATH": SANDBOX_WORKSPACE,
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONHASHSEED": "0",
        "PYTHONUTF8": "1",
    }
    for name in (
        "LANG",
        "LANGUAGE",
        "LC_ALL",
        "LC_COLLATE",
        "LC_CTYPE",
        "LC_MESSAGES",
        "LC_MONETARY",
        "LC_NUMERIC",
        "LC_TIME",
        "TERM",
        "PYTHONHASHSEED",
    ):
        value = os.environ.get(name)
        if value is not None and _safe_parent_value(name, value):
            env[name] = value
    return env


def _build_argv(
    *,
    bwrap: str,
    executable: str,
    module: str,
    staged_workspace: Path,
    private_tmp: Path,
    environment: Dict[str, str],
) -> list[str]:
    argv = [
        bwrap,
        "--new-session",
        "--die-with-parent",
        "--unshare-user",
        "--uid",
        str(SANDBOX_UID),
        "--gid",
        str(SANDBOX_GID),
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--cap-drop",
        "ALL",
        "--clearenv",
    ]
    argv.extend((
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/home",
        "--dir",
        SANDBOX_HOME,
    ))
    for source, destination in _runtime_mounts():
        argv.extend(("--ro-bind", source, destination))
    argv.extend(("--ro-bind", str(staged_workspace), SANDBOX_WORKSPACE))
    argv.extend((
        "--remount-ro",
        "/",
        "--bind",
        str(private_tmp),
        SANDBOX_PRIVATE_TMP,
        "--chdir",
        SANDBOX_WORKSPACE,
    ))
    for name in sorted(environment):
        argv.extend(("--setenv", name, environment[name]))
    argv.extend(("--", executable, "-m", "unittest", module, "-v"))
    return argv


def _read_bounded(stream, output: _BoundedOutput) -> None:
    try:
        while True:
            chunk = stream.read(4096)
            if not chunk:
                return
            output.append(chunk)
    except (OSError, ValueError):
        return
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _terminate_process_group(process: subprocess.Popen) -> bool:
    pgid = process.pid  # start_new_session=True makes the child its group leader.
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.terminate()
        except OSError:
            pass

    try:
        process.wait(timeout=0.25)
    except subprocess.TimeoutExpired:
        pass

    if _group_exists(pgid):
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            try:
                process.kill()
            except OSError:
                pass
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        return False

    deadline = time.monotonic() + 0.5
    while _group_exists(pgid) and time.monotonic() < deadline:
        time.sleep(0.01)
    return process.poll() is not None and not _group_exists(pgid)


def _tail_text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")[-RETURN_TEXT_LIMIT:]


def _launch(
    argv: list[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> RunTestSandboxResult:
    launcher_env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
    }
    try:
        process = subprocess.Popen(
            argv,
            cwd=str(cwd),
            env=launcher_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=(),
            start_new_session=True,
            bufsize=0,
        )
    except OSError:
        return _refusal("sandbox-start-failed", provider="bubblewrap")

    stdout = _BoundedOutput.create(max_stdout_bytes)
    stderr = _BoundedOutput.create(max_stderr_bytes)
    readers = [
        threading.Thread(
            target=_read_bounded,
            args=(process.stdout, stdout),
            name="raphael-run-test-stdout",
            daemon=True,
        ),
        threading.Thread(
            target=_read_bounded,
            args=(process.stderr, stderr),
            name="raphael-run-test-stderr",
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()

    timed_out = False
    cleanup_verified = False
    try:
        try:
            process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            cleanup_verified = _terminate_process_group(process)
    finally:
        for reader in readers:
            reader.join(timeout=2.0)

    drain_completed = all(not reader.is_alive() for reader in readers)
    if process.poll() is None:
        cleanup_verified = _terminate_process_group(process)
    stdout_text = _tail_text(bytes(stdout.buffer))
    stderr_text = _tail_text(bytes(stderr.buffer))
    launcher_failed = (
        process.returncode not in (None, 0)
        and stderr_text.lstrip().startswith("bwrap:")
    )
    return RunTestSandboxResult(
        returncode=process.returncode,
        stdout=stdout_text,
        stderr=stderr_text,
        timed_out=timed_out,
        sandboxed=not launcher_failed,
        sandbox_provider="bubblewrap",
        network_isolated=not launcher_failed,
        workspace_mount=(
            f"{SANDBOX_WORKSPACE} (read-only Python and approved fixtures)"
        ),
        sandbox_failure_reason=(
            "sandbox-start-failed" if launcher_failed else None
        ),
        output_truncated=bool(stdout.truncated or stderr.truncated),
        process_group_managed=True,
        process_group_cleanup_verified=bool(cleanup_verified and drain_completed),
        stdout_truncated=bool(stdout.truncated),
        stderr_truncated=bool(stderr.truncated),
        resource_limits={
            "wall_clock_seconds": timeout_seconds,
            "stdout_capture_bytes": max_stdout_bytes,
            "stderr_capture_bytes": max_stderr_bytes,
            "cpu_time_enforced": False,
            "memory_limit_enforced": False,
            "process_count_limit_enforced": False,
        },
    )


def run_test_in_sandbox(
    *,
    workspace_root: Path,
    test_path: Path,
    requested_target: str,
    module: str,
    timeout_seconds: float,
    fixture_manifest: Optional[str] = None,
    max_stdout_bytes: int = DEFAULT_MAX_STDOUT_BYTES,
    max_stderr_bytes: int = DEFAULT_MAX_STDERR_BYTES,
) -> RunTestSandboxResult:
    """Execute one authorized unittest module or return a structured refusal."""
    if sys.platform != "linux":
        return _refusal("sandbox-platform-unsupported")
    try:
        timeout = _finite_limit(timeout_seconds, "timeout")
        stdout_cap = _positive_int(max_stdout_bytes, "stdout-limit")
        stderr_cap = _positive_int(max_stderr_bytes, "stderr-limit")
        root = _validate_workspace(Path(workspace_root))
        fixture_root = _validate_test_path(root, requested_target, test_path, module)
        fixture_paths = _parse_fixture_manifest(fixture_manifest)
        approved_fixtures = _validate_approved_fixtures(root, fixture_paths)
        executable = _validate_runtime()
        bwrap = _find_bwrap()
        _runtime_mounts()
    except SandboxConfigurationError as exc:
        provider = None
        return _refusal(
            exc.reason,
            provider=provider,
            timeout_seconds=(
                float(timeout_seconds)
                if isinstance(timeout_seconds, (int, float))
                and not isinstance(timeout_seconds, bool)
                and math.isfinite(float(timeout_seconds))
                and float(timeout_seconds) > 0
                else None
            ),
            max_stdout_bytes=(
                int(max_stdout_bytes)
                if isinstance(max_stdout_bytes, int)
                and not isinstance(max_stdout_bytes, bool)
                and max_stdout_bytes > 0
                else DEFAULT_MAX_STDOUT_BYTES
            ),
            max_stderr_bytes=(
                int(max_stderr_bytes)
                if isinstance(max_stderr_bytes, int)
                and not isinstance(max_stderr_bytes, bool)
                and max_stderr_bytes > 0
                else DEFAULT_MAX_STDERR_BYTES
            ),
        )

    temp_root = Path(tempfile.mkdtemp(prefix="raphael-run-test-"))
    result: Optional[RunTestSandboxResult] = None
    try:
        staged_workspace = temp_root / "workspace"
        private_tmp = temp_root / "tmp"
        staged_workspace.mkdir(mode=0o700)
        private_tmp.mkdir(mode=0o700)
        test_relative_parent = fixture_root.relative_to(root)
        staged_fixture_root = staged_workspace / test_relative_parent
        staged_fixture_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            python_file_count, python_byte_count = _copy_python_fixture_tree(
                fixture_root, staged_fixture_root)
            approved_count, approved_bytes = _copy_approved_fixtures(
                approved_fixtures,
                staged_workspace,
                remaining_files=MAX_FIXTURE_FILES - python_file_count,
                remaining_bytes=MAX_FIXTURE_BYTES - python_byte_count,
            )
        except SandboxConfigurationError as exc:
            result = _refusal(exc.reason, provider="bubblewrap")
        else:
            environment = _sandbox_environment(executable)
            try:
                argv = _build_argv(
                    bwrap=bwrap,
                    executable=executable,
                    module=module,
                    staged_workspace=staged_workspace,
                    private_tmp=private_tmp,
                    environment=environment,
                )
            except SandboxConfigurationError as exc:
                result = _refusal(exc.reason, provider="bubblewrap")
            else:
                result = replace(
                    _launch(
                        argv,
                        cwd=temp_root,
                        timeout_seconds=timeout,
                        max_stdout_bytes=stdout_cap,
                        max_stderr_bytes=stderr_cap,
                    ),
                    approved_fixture_count=approved_count,
                    approved_fixture_bytes=approved_bytes,
                )
    except (OSError, ValueError, TypeError):
        result = _refusal("sandbox-setup-failed", provider="bubblewrap")
    finally:
        cleanup_ok = True
        for _ in range(3):
            try:
                shutil.rmtree(temp_root)
                break
            except FileNotFoundError:
                break
            except OSError:
                time.sleep(0.01)
        else:
            cleanup_ok = False
    if result is not None and not cleanup_ok:
        result = replace(
            result,
            sandbox_failure_reason=(
                result.sandbox_failure_reason or "sandbox-cleanup-failed"
            ),
        )
    return result


__all__ = [
    "DEFAULT_MAX_STDERR_BYTES",
    "DEFAULT_MAX_STDOUT_BYTES",
    "RunTestSandboxResult",
    "SandboxConfigurationError",
    "run_test_in_sandbox",
]
