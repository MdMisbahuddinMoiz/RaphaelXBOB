"""Focused security tests for the governed RUN_TEST bubblewrap executor."""
from __future__ import annotations

import json
import shutil
import socket
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from raphael_ibm_bob import run_test_sandbox as sandbox  # noqa: E402
from raphael_ibm_bob.broker import BOBBroker  # noqa: E402
from raphael_ibm_bob.contracts import (  # noqa: E402
    ActionRequest,
    Capability,
    Decision,
    Mission,
)
from raphael_ibm_bob.evidence_ledger import EvidenceLedger  # noqa: E402
from raphael_ibm_bob.policy import BOBPolicy  # noqa: E402
from raphael_ibm_bob.runtime import BOBRuntime  # noqa: E402
from raphael_ibm_bob.quality_gate import BOBQualityGate  # noqa: E402
from raphael_ibm_bob.workspace import Workspace  # noqa: E402


class _SandboxHarness(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="raphael-run-test-case-")
        self.addCleanup(self.temp.cleanup)
        self.host_root = Path(self.temp.name) / "host"
        self.workspace_root = self.host_root / "workspace"
        (self.workspace_root / "cases").mkdir(parents=True)
        self.ledger = EvidenceLedger(Path(self.temp.name) / "ledger")
        self.addCleanup(self.ledger.close)
        workspace = Workspace(self.workspace_root)
        broker = BOBBroker(BOBPolicy(workspace), workspace, ledger=self.ledger)
        self.runtime = BOBRuntime(broker)
        self.mission = Mission(
            mission_id="M-run-test-sandbox",
            description="local sandbox fixture",
            scope=str(self.workspace_root),
            criteria=["sandbox boundary"],
        )

    def write_test(self, source: str, name: str = "test_case.py") -> Path:
        path = self.workspace_root / "cases" / name
        path.write_text(textwrap.dedent(source).strip() + "\n", encoding="utf-8")
        return path

    def submit(
        self,
        path: Path,
        timeout: float = 5.0,
        purpose: str = "local security fixture",
    ):
        return self.runtime.submit(
            ActionRequest(
                sequence=0,
                requester="sandbox-test",
                capability=Capability.RUN_TEST,
                target=str(path),
                purpose=purpose,
                timeout_seconds=timeout,
            ),
            self.mission,
        )


class LinuxBubblewrapSecurity(_SandboxHarness):
    @unittest.skipUnless(
        sys.platform.startswith("linux") and shutil.which("bwrap"),
        "Linux bubblewrap is required for actual isolation tests",
    )
    def test_1_host_etc_passwd_read_is_denied(self) -> None:
        path = self.write_test("""
            import unittest
            from pathlib import Path

            class T(unittest.TestCase):
                def test_denied(self):
                    with self.assertRaises(OSError):
                        Path("/etc/passwd").read_text(encoding="utf-8")
        """)
        result = self.submit(path)
        self.assertTrue(result.execution.success, result.execution.error)
        self.assertEqual(result.execution.evidence["returncode"], 0)
        self.assertTrue(result.execution.evidence["sandboxed"])

    @unittest.skipUnless(
        sys.platform.startswith("linux") and shutil.which("bwrap"),
        "Linux bubblewrap is required for actual isolation tests",
    )
    def test_2_parent_repository_read_is_denied(self) -> None:
        outside = self.host_root / "outside-secret.txt"
        outside.write_text("host-only", encoding="utf-8")
        path = self.write_test(f"""
            import unittest
            from pathlib import Path

            class T(unittest.TestCase):
                def test_denied(self):
                    with self.assertRaises(OSError):
                        Path({str(outside)!r}).read_text(encoding="utf-8")
        """)
        result = self.submit(path)
        self.assertTrue(result.execution.success, result.execution.error)
        self.assertEqual(result.execution.evidence["returncode"], 0)

    @unittest.skipUnless(
        sys.platform.startswith("linux") and shutil.which("bwrap"),
        "Linux bubblewrap is required for actual isolation tests",
    )
    def test_3_write_outside_workspace_fails(self) -> None:
        path = self.write_test("""
            import unittest
            from pathlib import Path

            class T(unittest.TestCase):
                def test_denied(self):
                    with self.assertRaises(OSError):
                        Path("/escape.txt").write_text("no", encoding="utf-8")
        """)
        result = self.submit(path)
        self.assertTrue(result.execution.success, result.execution.error)
        self.assertEqual(result.execution.evidence["returncode"], 0)

    @unittest.skipUnless(
        sys.platform.startswith("linux") and shutil.which("bwrap"),
        "Linux bubblewrap is required for actual isolation tests",
    )
    def test_4_host_network_is_denied(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(1.0)
        port = listener.getsockname()[1]
        connected = threading.Event()

        def accept_once() -> None:
            try:
                connection, _ = listener.accept()
                connected.set()
                connection.close()
            except OSError:
                pass
            finally:
                listener.close()

        thread = threading.Thread(target=accept_once, daemon=True)
        thread.start()
        path = self.write_test(f"""
            import socket
            import unittest

            class T(unittest.TestCase):
                def test_denied(self):
                    with self.assertRaises(OSError):
                        socket.create_connection(("127.0.0.1", {port}), 0.2)
        """)
        try:
            result = self.submit(path)
        finally:
            thread.join(timeout=2.0)
            listener.close()
        self.assertTrue(result.execution.success, result.execution.error)
        self.assertFalse(connected.is_set())

    @unittest.skipUnless(
        sys.platform.startswith("linux") and shutil.which("bwrap"),
        "Linux bubblewrap is required for actual isolation tests",
    )
    def test_5_child_process_cannot_escape_mount_boundary(self) -> None:
        path = self.write_test("""
            import subprocess
            import sys
            import unittest

            class T(unittest.TestCase):
                def test_child_contained(self):
                    child = subprocess.run(
                        [sys.executable, "-c",
                         "from pathlib import Path; Path('/etc/passwd').read_text()"],
                        capture_output=True, text=True, timeout=2)
                    self.assertNotEqual(child.returncode, 0)
        """)
        result = self.submit(path)
        self.assertTrue(result.execution.success, result.execution.error)

    @unittest.skipUnless(
        sys.platform.startswith("linux") and shutil.which("bwrap"),
        "Linux bubblewrap is required for actual isolation tests",
    )
    def test_6_timeout_kills_complete_process_group(self) -> None:
        path = self.write_test("""
            import subprocess
            import sys
            import time
            import unittest

            class T(unittest.TestCase):
                def test_timeout(self):
                    subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
                    time.sleep(30)
        """)
        result = self.submit(path, timeout=0.25)
        self.assertFalse(result.execution.success)
        self.assertTrue(result.execution.evidence["timeout"])
        self.assertTrue(result.execution.evidence["sandboxed"])
        self.assertTrue(result.execution.evidence["process_group_managed"])
        self.assertTrue(
            result.execution.evidence["process_group_cleanup_verified"]
        )

    @unittest.skipUnless(
        sys.platform.startswith("linux") and shutil.which("bwrap"),
        "Linux bubblewrap is required for actual isolation tests",
    )
    def test_7_timeout_leaves_no_late_child_output(self) -> None:
        path = self.write_test("""
            import subprocess
            import sys
            import time
            import unittest

            class T(unittest.TestCase):
                def test_timeout(self):
                    subprocess.Popen([
                        sys.executable, "-c",
                        "import time; time.sleep(1); print('late-orphan', flush=True)",
                    ])
                    time.sleep(30)
        """)
        result = self.submit(path, timeout=0.25)
        evidence = result.execution.evidence
        self.assertFalse(result.execution.success)
        self.assertTrue(evidence["timeout"])
        self.assertTrue(evidence["process_group_cleanup_verified"])
        self.assertNotIn("late-orphan", evidence["partial_stdout"])
        self.assertNotIn("late-orphan", evidence["partial_stderr"])

    @unittest.skipUnless(
        sys.platform.startswith("linux") and shutil.which("bwrap"),
        "Linux bubblewrap is required for actual isolation tests",
    )
    def test_8_symlink_escape_is_denied_before_spawn(self) -> None:
        outside = self.host_root / "test_outside.py"
        outside.write_text("raise AssertionError('must not run')\n", encoding="utf-8")
        link = self.workspace_root / "cases" / "test_escape.py"
        link.symlink_to(outside)
        with mock.patch.object(sandbox.subprocess, "Popen") as popen:
            result = self.submit(link)
        popen.assert_not_called()
        self.assertIs(result.broker_result.decision.decision, Decision.DENY)
        self.assertFalse(result.broker_result.capability_invoked)

    @unittest.skipUnless(
        sys.platform.startswith("linux") and shutil.which("bwrap"),
        "Linux bubblewrap is required for actual isolation tests",
    )
    def test_9_stdout_overflow_is_bounded_and_fails(self) -> None:
        path = self.write_test("""
            import sys
            sys.stdout.write("x" * 70000)
        """)
        result = self.submit(path)
        evidence = result.execution.evidence
        self.assertFalse(result.execution.success)
        self.assertEqual(result.execution.error, "OutputLimitExceeded")
        self.assertTrue(evidence["output_truncated"])
        self.assertTrue(evidence["stdout_truncated"])
        self.assertLessEqual(len(evidence["stdout"]), 4000)

    @unittest.skipUnless(
        sys.platform.startswith("linux") and shutil.which("bwrap"),
        "Linux bubblewrap is required for actual isolation tests",
    )
    def test_10_stderr_overflow_is_bounded_and_fails(self) -> None:
        path = self.write_test("""
            import sys
            sys.stderr.write("y" * 20000)
        """)
        result = self.submit(path)
        evidence = result.execution.evidence
        self.assertFalse(result.execution.success)
        self.assertEqual(result.execution.error, "OutputLimitExceeded")
        self.assertTrue(evidence["output_truncated"])
        self.assertTrue(evidence["stderr_truncated"])
        self.assertLessEqual(len(evidence["stderr"]), 4000)

    @unittest.skipUnless(
        sys.platform.startswith("linux") and shutil.which("bwrap"),
        "Linux bubblewrap is required for actual isolation tests",
    )
    def test_failing_test_sets_failure_status(self) -> None:
        path = self.write_test("""
            import unittest

            class T(unittest.TestCase):
                def test_fail(self):
                    self.fail("expected")
        """)
        result = self.submit(path)
        self.assertFalse(result.execution.success)
        self.assertEqual(result.execution.output, "test-failed")
        self.assertEqual(result.execution.error, "TestFailed:returncode=1")
        self.assertEqual(result.execution.evidence["returncode"], 1)
        result_records = [
            record for record in self.ledger.all_records()
            if record.get("kind") == "result"
        ]
        self.assertEqual(len(result_records), 1)
        self.assertFalse(BOBQualityGate._artifact_reports_success(result_records[0]))

    @unittest.skipUnless(
        sys.platform.startswith("linux") and shutil.which("bwrap"),
        "Linux bubblewrap is required for actual isolation tests",
    )
    def test_13_valid_fixture_and_metadata_are_truthful(self) -> None:
        path = self.write_test("""
            import unittest

            class T(unittest.TestCase):
                def test_pass(self):
                    self.assertTrue(True)
        """)
        result = self.submit(path)
        evidence = result.execution.evidence
        self.assertTrue(result.execution.success, result.execution.error)
        self.assertIsNone(result.execution.error)
        self.assertEqual(evidence["returncode"], 0)
        self.assertTrue(evidence["sandboxed"])
        self.assertEqual(evidence["sandbox_provider"], "bubblewrap")
        self.assertTrue(evidence["network_isolated"])
        self.assertIn("/workspace", evidence["workspace_mount"])
        self.assertIsNone(evidence["sandbox_failure_reason"])
        self.assertFalse(evidence["output_truncated"])
        self.assertTrue(evidence["process_group_managed"])
        self.assertFalse(evidence["resource_limits"]["cpu_time_enforced"])
        self.assertFalse(evidence["resource_limits"]["memory_limit_enforced"])
        self.assertFalse(
            evidence["resource_limits"]["process_count_limit_enforced"]
        )
        self.assertNotIn(str(self.host_root), json_text(evidence))



class ExplicitFixtureSupport(_SandboxHarness):
    @unittest.skipUnless(
        sys.platform.startswith("linux") and shutil.which("bwrap"),
        "Linux bubblewrap is required for actual fixture tests",
    )
    def test_approved_data_fixture_is_readable(self) -> None:
        data = self.workspace_root / "data"
        data.mkdir()
        allowed = data / "allowed.txt"
        allowed.write_text("approved-data", encoding="utf-8")
        path = self.write_test("""
            import unittest
            from pathlib import Path

            class T(unittest.TestCase):
                def test_data_available(self):
                    target = Path(__file__).resolve().parents[1] / "data" / "allowed.txt"
                    self.assertTrue(target.is_file())
                    self.assertTrue(target.read_text(encoding="utf-8"))
        """)
        result = self.submit(
            path,
            purpose=fixture_manifest("data/allowed.txt"),
        )
        self.assertTrue(result.execution.success, result.execution.error)
        self.assertEqual(result.execution.evidence["returncode"], 0)
        self.assertEqual(result.execution.evidence["approved_fixture_count"], 1)
        self.assertEqual(
            result.execution.evidence["approved_fixture_bytes"],
            allowed.stat().st_size,
        )

    @unittest.skipUnless(
        sys.platform.startswith("linux") and shutil.which("bwrap"),
        "Linux bubblewrap is required for actual fixture tests",
    )
    def test_unapproved_data_fixture_is_not_staged(self) -> None:
        data = self.workspace_root / "data"
        data.mkdir()
        (data / "allowed.txt").write_text("not-approved", encoding="utf-8")
        path = self.write_test("""
            import unittest
            from pathlib import Path

            class T(unittest.TestCase):
                def test_data_not_staged(self):
                    target = Path(__file__).resolve().parents[1] / "data" / "allowed.txt"
                    with self.assertRaises(OSError):
                        target.read_text(encoding="utf-8")
        """)
        result = self.submit(path)
        self.assertTrue(result.execution.success, result.execution.error)
        self.assertEqual(result.execution.evidence["approved_fixture_count"], 0)


class ExplicitFixtureValidation(_SandboxHarness):
    def test_hidden_fixture_is_rejected_before_spawn(self) -> None:
        data = self.workspace_root / "data"
        data.mkdir()
        (data / ".allowed.txt").write_text("hidden", encoding="utf-8")
        path = self.write_test("unittest.TestCase")
        with mock.patch.object(sandbox.subprocess, "Popen") as popen:
            result = self.submit(
                path,
                purpose=fixture_manifest("data/.allowed.txt"),
            )
        popen.assert_not_called()
        self.assertFalse(result.execution.success)
        self.assertEqual(
            result.execution.evidence["sandbox_failure_reason"],
            "fixture-hidden",
        )

    def test_symlinked_fixture_is_rejected_before_spawn(self) -> None:
        data = self.workspace_root / "data"
        data.mkdir()
        target = data / "allowed.txt"
        target.write_text("safe", encoding="utf-8")
        (data / "linked.txt").symlink_to(target)
        path = self.write_test("unittest.TestCase")
        with mock.patch.object(sandbox.subprocess, "Popen") as popen:
            result = self.submit(
                path,
                purpose=fixture_manifest("data/linked.txt"),
            )
        popen.assert_not_called()
        self.assertEqual(
            result.execution.evidence["sandbox_failure_reason"],
            "fixture-symlink",
        )

    def test_outside_fixture_is_rejected_before_spawn(self) -> None:
        outside = self.host_root / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        path = self.write_test("unittest.TestCase")
        with mock.patch.object(sandbox.subprocess, "Popen") as popen:
            result = self.submit(
                path,
                purpose=fixture_manifest(str(outside)),
            )
        popen.assert_not_called()
        self.assertEqual(
            result.execution.evidence["sandbox_failure_reason"],
            "fixture-path-absolute",
        )

    def test_missing_fixture_is_rejected_before_spawn(self) -> None:
        path = self.write_test("unittest.TestCase")
        with mock.patch.object(sandbox.subprocess, "Popen") as popen:
            result = self.submit(
                path,
                purpose=fixture_manifest("data/missing.txt"),
            )
        popen.assert_not_called()
        self.assertEqual(
            result.execution.evidence["sandbox_failure_reason"],
            "fixture-missing",
        )

    def test_credential_like_fixture_is_rejected_before_spawn(self) -> None:
        data = self.workspace_root / "data"
        data.mkdir()
        (data / "credentials.txt").write_text("not-allowed", encoding="utf-8")
        path = self.write_test("unittest.TestCase")
        with mock.patch.object(sandbox.subprocess, "Popen") as popen:
            result = self.submit(
                path,
                purpose=fixture_manifest("data/credentials.txt"),
            )
        popen.assert_not_called()
        self.assertEqual(
            result.execution.evidence["sandbox_failure_reason"],
            "fixture-credential",
        )

    def test_directory_fixture_is_rejected_before_spawn(self) -> None:
        (self.workspace_root / "data").mkdir()
        path = self.write_test("unittest.TestCase")
        with mock.patch.object(sandbox.subprocess, "Popen") as popen:
            result = self.submit(
                path,
                purpose=fixture_manifest("data"),
            )
        popen.assert_not_called()
        self.assertEqual(
            result.execution.evidence["sandbox_failure_reason"],
            "fixture-not-regular",
        )

    def test_traversal_fixture_is_rejected_before_spawn(self) -> None:
        path = self.write_test("unittest.TestCase")
        with mock.patch.object(sandbox.subprocess, "Popen") as popen:
            result = self.submit(
                path,
                purpose=fixture_manifest("../outside.txt"),
            )
        popen.assert_not_called()
        self.assertEqual(
            result.execution.evidence["sandbox_failure_reason"],
            "fixture-path-traversal",
        )


class SandboxFailClosed(_SandboxHarness):
    def test_11_missing_bwrap_fails_closed(self) -> None:
        path = self.write_test("""
            import unittest
            class T(unittest.TestCase):
                def test_must_not_run(self):
                    self.fail("host fallback executed")
        """)
        with mock.patch.object(sandbox.shutil, "which", return_value=None):
            with mock.patch.object(sandbox.subprocess, "Popen") as popen:
                result = self.submit(path)
        popen.assert_not_called()
        self.assertFalse(result.execution.success)
        self.assertEqual(result.execution.output, "sandbox-refused")
        self.assertFalse(result.execution.evidence["sandboxed"])
        self.assertIsNone(result.execution.evidence["sandbox_provider"])
        self.assertEqual(
            result.execution.evidence["sandbox_failure_reason"],
            "sandbox-unavailable",
        )

    def test_12_invalid_workspace_fails_closed(self) -> None:
        missing = Path(self.temp.name) / "missing-workspace"
        test_path = missing / "cases" / "test_missing.py"
        with mock.patch.object(sandbox.subprocess, "Popen") as popen:
            result = sandbox.run_test_in_sandbox(
                workspace_root=missing,
                test_path=test_path,
                requested_target=str(test_path),
                module="cases.test_missing",
                timeout_seconds=1.0,
            )
        popen.assert_not_called()
        self.assertFalse(result.sandboxed)
        self.assertEqual(result.sandbox_failure_reason, "workspace-invalid")

    def test_13_invalid_test_path_fails_before_spawn(self) -> None:
        outside = self.host_root / "test_outside.py"
        outside.write_text("raise AssertionError('must not run')\n", encoding="utf-8")
        with mock.patch.object(sandbox.subprocess, "Popen") as popen:
            result = sandbox.run_test_in_sandbox(
                workspace_root=self.workspace_root,
                test_path=outside,
                requested_target=str(outside),
                module="cases.test_outside",
                timeout_seconds=1.0,
            )
        popen.assert_not_called()
        self.assertFalse(result.sandboxed)
        self.assertEqual(
            result.sandbox_failure_reason,
            "test-path-outside-workspace",
        )

    def test_14_broker_policy_denial_prevents_spawn(self) -> None:
        target = self.workspace_root / "cases" / "not_a_test.txt"
        target.write_text("not a test", encoding="utf-8")
        with mock.patch.object(sandbox.subprocess, "Popen") as popen:
            result = self.submit(target)
        popen.assert_not_called()
        self.assertIs(result.broker_result.decision.decision, Decision.DENY)
        self.assertFalse(result.broker_result.capability_invoked)
        self.assertIsNone(result.execution)

    def test_launch_failure_sets_failure_status(self) -> None:
        path = self.write_test("unittest.TestCase")
        with mock.patch.object(
                sandbox.subprocess, "Popen", side_effect=OSError("denied")):
            result = self.submit(path)
        self.assertFalse(result.execution.success)
        self.assertEqual(result.execution.output, "sandbox-refused")
        self.assertEqual(
            result.execution.evidence["sandbox_failure_reason"],
            "sandbox-start-failed",
        )

    def test_15_non_linux_fails_closed(self) -> None:
        path = self.write_test("""
            import unittest
            class T(unittest.TestCase):
                def test_must_not_run(self):
                    self.fail("host fallback executed")
        """)
        with mock.patch.object(sandbox.sys, "platform", "darwin"):
            result = self.submit(path)
        self.assertFalse(result.execution.success)
        self.assertEqual(
            result.execution.evidence["sandbox_failure_reason"],
            "sandbox-platform-unsupported",
        )


class WorkspaceRootTest(_SandboxHarness):
    """Regression: a test file at the workspace root must not produce
    sandbox-setup-failed.

    Defect: when fixture_root == workspace_root, the computed
    test_relative_parent is Path("."), staged_fixture_root resolves to
    staged_workspace (already created), and mkdir(parents=True) raised
    FileExistsError → caught as sandbox-setup-failed.

    Fix: exist_ok=True on that mkdir call.
    """

    def _write_test_at_root(self, name: str = "test_root.py") -> Path:
        """Write a minimal passing test directly at workspace_root."""
        path = self.workspace_root / name
        path.write_text(
            "import unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_ok(self):\n"
            "        self.assertTrue(True)\n",
            encoding="utf-8",
        )
        return path

    def _submit_root(self, path: Path, timeout: float = 5.0):
        return self.runtime.submit(
            ActionRequest(
                sequence=0,
                requester="sandbox-root-regression",
                capability=Capability.RUN_TEST,
                target=str(path),
                purpose="regression: test at workspace root",
                timeout_seconds=timeout,
            ),
            self.mission,
        )

    def test_root_test_setup_reaches_spawn(self) -> None:
        """Without the fix, FileExistsError surfaces as sandbox-setup-failed
        before bwrap is ever invoked.  With the fix, setup succeeds and Popen
        is called.

        This test does NOT require bwrap: it verifies only the mkdir setup
        path by intercepting Popen so we never reach the bwrap invocation.
        The mock Popen raises OSError to produce a clean sandbox-start-failed
        (not sandbox-setup-failed), confirming the defect path is gone.
        """
        path = self._write_test_at_root()
        with mock.patch.object(
            sandbox.subprocess, "Popen", side_effect=OSError("intercepted")
        ) as popen_mock:
            result = self._submit_root(path)

        # Popen was called → setup completed successfully (exist_ok fixed it).
        popen_mock.assert_called_once()
        # The result is sandbox-start-failed (Popen OSError), NOT setup-failed.
        self.assertFalse(result.execution.success)
        self.assertNotEqual(
            result.execution.evidence.get("sandbox_failure_reason"),
            "sandbox-setup-failed",
            "FileExistsError was NOT fixed: sandbox-setup-failed should not appear",
        )
        self.assertEqual(
            result.execution.evidence.get("sandbox_failure_reason"),
            "sandbox-start-failed",
        )

    @unittest.skipUnless(
        sys.platform.startswith("linux") and shutil.which("bwrap"),
        "Linux bubblewrap required for live root-test execution",
    )
    def test_root_test_executes_successfully(self) -> None:
        """End-to-end: a passing test at workspace_root reaches returncode 0."""
        path = self._write_test_at_root()
        result = self._submit_root(path)
        self.assertTrue(result.execution.success, result.execution.error)
        self.assertEqual(result.execution.evidence["returncode"], 0)
        self.assertTrue(result.execution.evidence["sandboxed"])
        self.assertIsNone(result.execution.evidence["sandbox_failure_reason"])


def fixture_manifest(*paths: str) -> str:
    return sandbox.FIXTURE_MANIFEST_PREFIX + json.dumps(list(paths))


def json_text(value) -> str:
    return json.dumps(value, sort_keys=True)


if __name__ == "__main__":
    unittest.main()
