"""tests.test_run_test_env_scrub — RUN_TEST must not leak secrets."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from raphael_ibm_bob import run_test_sandbox as sandbox  # noqa: E402
from raphael_ibm_bob.broker import BOBBroker  # noqa: E402
from raphael_ibm_bob.contracts import ActionRequest, Capability, Mission  # noqa: E402
from raphael_ibm_bob.policy import BOBPolicy  # noqa: E402
from raphael_ibm_bob.workspace import Workspace  # noqa: E402
from raphael_ibm_bob.evidence_ledger import EvidenceLedger  # noqa: E402

_ENVIRONMENT_ASSERTION_TEST = '''\
import os
import unittest


class T(unittest.TestCase):
    def test_environment_is_scrubbed(self):
        forbidden = {
            "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE",
            "AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS",
            "GITHUB_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
            "SSH_AUTH_SOCK", "GIT_ASKPASS", "VPN_PASSWORD",
            "HTTP_PROXY", "HTTPS_PROXY", "DATABASE_PASSWORD",
        }
        self.assertTrue(forbidden.isdisjoint(os.environ))
        self.assertEqual(os.environ["HOME"], "/home/raphael")
        self.assertEqual(os.environ["TMPDIR"], "/tmp/raphael-run-test")
        self.assertEqual(os.environ["PYTHONPATH"], "/workspace")
        self.assertEqual(os.environ["PYTHONNOUSERSITE"], "1")
'''


class EnvScrub(unittest.TestCase):
    def test_sandbox_environment_excludes_secrets(self):
        with mock.patch.dict(os.environ, {
                "AWS_SECRET_ACCESS_KEY": "leak",
                "GITHUB_TOKEN": "leak2",
                "OPENAI_API_KEY": "leak3",
                "SSH_AUTH_SOCK": "/tmp/agent.sock",
                "HTTPS_PROXY": "http://credential.invalid",
                "LANG": "C"}, clear=False):
            env = sandbox._sandbox_environment(sys.executable)
        for name in (
                "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "OPENAI_API_KEY",
                "SSH_AUTH_SOCK", "HTTPS_PROXY"):
            self.assertNotIn(name, env)
        self.assertEqual(env["HOME"], "/home/raphael")
        self.assertEqual(env["TMPDIR"], "/tmp/raphael-run-test")
        self.assertEqual(env["PYTHONPATH"], "/workspace")

    def test_run_test_child_does_not_see_secrets(self):
        tmp = tempfile.TemporaryDirectory(prefix="run_test_env_")
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "src").mkdir()
        test_file = root / "src" / "test_envdump.py"
        test_file.write_text(_ENVIRONMENT_ASSERTION_TEST, encoding="utf-8")
        workspace = Workspace(root)
        policy = BOBPolicy(workspace)
        ledger = EvidenceLedger(root / "ledger")
        self.addCleanup(ledger.close)
        broker = BOBBroker(policy, workspace, ledger=ledger)
        mission = Mission(mission_id="M", description="x", scope=str(root),
                          criteria=["c"])
        secrets = {
            "AWS_SECRET_ACCESS_KEY": "aws-secret-value",
            "AZURE_CLIENT_SECRET": "azure-secret-value",
            "GOOGLE_APPLICATION_CREDENTIALS": "/secret/google.json",
            "GITHUB_TOKEN": "github-secret-value",
            "OPENAI_API_KEY": "model-secret-value",
            "ANTHROPIC_API_KEY": "anthropic-secret-value",
            "SSH_AUTH_SOCK": "/secret/agent.sock",
            "GIT_ASKPASS": "/secret/askpass",
            "VPN_PASSWORD": "vpn-secret-value",
            "HTTPS_PROXY": "http://proxy-secret@proxy.invalid",
            "DATABASE_PASSWORD": "database-secret-value",
        }
        with mock.patch.dict(os.environ, secrets, clear=False):
            result = broker.submit(ActionRequest(
                sequence=0, requester="t", capability=Capability.RUN_TEST,
                target=str(test_file), purpose="required-test",
                timeout_seconds=5.0), mission)
        self.assertTrue(result.execution.success,
                        msg=result.execution.error)
        evidence = result.execution.evidence
        self.assertTrue(evidence["sandboxed"])
        serialized = repr(evidence)
        for name, value in secrets.items():
            self.assertNotIn(name, serialized)
            self.assertNotIn(value, serialized)
        result_records = [
            record for record in ledger.all_records()
            if record.get("kind") == "result"
        ]
        self.assertEqual(len(result_records), 1)
        artifact = Path(result_records[0]["artifact_ref"])
        artifact_text = artifact.read_text(encoding="utf-8")
        for name, value in secrets.items():
            self.assertNotIn(name, artifact_text)
            self.assertNotIn(value, artifact_text)

if __name__ == "__main__":
    unittest.main()
