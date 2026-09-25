"""tests.test_class_ab_inventory — capability classification tests.

F3 identifies the C1A provider seam.  F4 now requires RUN_TEST to use the
separate fail-closed bubblewrap executor.  F5 retains the existing seccomp
semantic tests for the C1A substrate; RUN_TEST does not claim seccomp isolation.
"""
from __future__ import annotations

import unittest
from pathlib import Path

from raphael_ibm_bob import provider_runtime
from raphael_ibm_bob.seccomp_policy import (
    ARG_FILTERED, CURATED_ALLOWLIST, DENIED_SYSCALLS, allowed_syscall_names)

REPO = Path(__file__).resolve().parents[1]
DOC = (REPO / "docs" / "integration" /
       "phase-2c-c1a-reconciliation-and-classification.md")


class C1AIdentifiers(unittest.TestCase):
    def test_1_operative_c1a_identifiers(self):
        self.assertEqual(provider_runtime.C1A_CAPABILITY_ID,
                         "C1A static_file_inspect")
        self.assertEqual(provider_runtime.C1A_PROVIDER_ID, "t3mp3st")
        self.assertEqual(provider_runtime.C1A_TOOL, "binary_sink_scan")

    def test_2_reconciliation_document_present(self):
        self.assertTrue(DOC.is_file(), DOC)
        text = DOC.read_text()
        self.assertIn("binary_sink_scan", text)
        self.assertIn("C1A static_file_inspect", text)
        self.assertIn("pure JS", text)
        # historical subject explicitly distinguished
        self.assertIn("runSubprocess", text)

    def test_2b_historical_design_doc_marks_c1_superseded(self):
        design = (REPO / "docs" / "integration" /
                  "phase-2b-provider-runtime-scope-result-design.md")
        text = design.read_text()
        self.assertIn("static_file_manifest", text)
        self.assertIn("HISTORICAL / SUPERSEDED", text)
        self.assertIn("C1A static_file_inspect", text)
        self.assertIn("binary_sink_scan", text)


class RunTestClassificationF4(unittest.TestCase):
    def test_3_run_test_sandbox_boundary_is_documented(self):
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        self.assertIn("Linux RUN_TEST requires `bwrap`", readme)
        self.assertIn("fail closed", readme.lower())
        self.assertIn("not a production security boundary", readme.lower())

    def test_4_run_test_is_not_a_class_a_capability(self):
        self.assertNotEqual(provider_runtime.C1A_TOOL, "run_test")
        self.assertNotEqual(provider_runtime.C1A_CAPABILITY_ID, "run_test")

    def test_5_run_test_uses_only_the_sandbox_executor(self):
        capabilities = (REPO / "raphael_ibm_bob" / "capabilities.py").read_text()
        helper = (REPO / "raphael_ibm_bob" / "run_test_sandbox.py").read_text()
        self.assertIn("run_test_in_sandbox", capabilities)
        self.assertNotIn("subprocess.run", capabilities)
        self.assertIn("subprocess.Popen", helper)
        self.assertIn('"--unshare-net"', helper)
        self.assertIn('"--unshare-user"', helper)
        self.assertIn('"--ro-bind"', helper)

    def test_5b_run_test_does_not_claim_seccomp_isolation(self):
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        helper = (REPO / "raphael_ibm_bob" / "run_test_sandbox.py").read_text()
        self.assertIn("No seccomp policy", readme)
        self.assertIn("is claimed for RUN_TEST", readme)
        self.assertNotIn("--seccomp", helper)


class SeccompExecveSemanticsF5(unittest.TestCase):
    def test_6_execve_allowed_execveat_denied(self):
        allowed = allowed_syscall_names()
        self.assertIn("execve", allowed)
        self.assertIn("execveat", DENIED_SYSCALLS)

    def test_7_clone_is_arg_filtered_not_unconditional(self):
        self.assertNotIn("clone", {e.name for e in CURATED_ALLOWLIST})
        self.assertIn("clone", {name for (name, *_r) in ARG_FILTERED})

    def test_8_reconciliation_documents_execve_semantics(self):
        text = DOC.read_text()
        self.assertIn("`execve`", text)
        self.assertIn("`execveat`", text)
        self.assertIn("argument-filtered", text)


if __name__ == "__main__":
    unittest.main()
