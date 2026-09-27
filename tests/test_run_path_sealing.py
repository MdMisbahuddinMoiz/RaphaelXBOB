"""tests.test_run_path_sealing — every governed run path is sealed.

`network_run` and `model_run` write `seal.json` after the ledger closes, so their
runs carry chain-level tamper evidence. `start_run` and `run_telnet_mission`
did not, so their run dirs verified as `(False, "missing-seal")` and chain-level
delete/reorder detection was absent on those paths.

For EACH affected path this proves three states, plus the distinction that
makes the seal meaningful:

    1. intact run                 -> verify_seal() is valid
    2. an evidence record deleted -> verify_seal() is invalid
    3. evidence records reordered -> verify_seal() is invalid
    4. seal.json absent           -> verify_seal() is NOT valid
                                     (a missing seal is a failure, never an
                                      implicit legacy-acceptable state)

Nothing here regenerates a seal to make a run pass, and no assertion is
weakened to accommodate the implementation.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from raphael_ibm_bob.contracts import Mission
from raphael_ibm_bob.harness import api
from raphael_ibm_bob.harness.api import create_session
from raphael_ibm_bob.harness.telnet_run import run_telnet_mission
from raphael_ibm_bob.seal import verify_seal
from raphael_ibm_bob.target_profile import TargetStore, build_target_profile
from raphael_ibm_bob.telnet_runtime import TelnetMediator

from test_d12_telnet import HOST, make_fake_session


def _lines(run_dir: Path) -> list:
    return [json.loads(line) for line
            in (run_dir / "evidence.jsonl").read_text(
                encoding="utf-8").splitlines() if line.strip()]


def _rewrite(run_dir: Path, records: list) -> None:
    (run_dir / "evidence.jsonl").write_text(
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in records),
        encoding="utf-8")


class _SealChecks:
    """Shared tamper assertions.

    Deliberately NOT a `unittest.TestCase`: pytest collects every
    `TestCase` subclass regardless of its name, which would run this base
    against its own unimplemented `_drive`. Concrete paths mix it in.
    """

    def assert_sealed_and_tamper_evident(self, run_dir: Path) -> None:
        # 1. intact -> valid
        self.assertTrue((run_dir / "seal.json").is_file(),
                        f"run {run_dir.name} was not sealed")
        ok, reason = verify_seal(run_dir)
        self.assertTrue(ok, f"intact run must verify: {reason}")
        self.assertEqual(reason, "seal-ok")

        original = _lines(run_dir)
        self.assertGreaterEqual(
            len(original), 2, "need >=2 records to prove reorder detection")

        # 2. delete a record -> invalid
        _rewrite(run_dir, original[:-1])
        ok, reason = verify_seal(run_dir)
        self.assertFalse(ok, "deleting a record must invalidate the seal")
        self.assertNotEqual(reason, "seal-ok")

        # 3. reorder records -> invalid
        reordered = [original[-1]] + original[:-1]
        self.assertNotEqual([r.get("seq") for r in reordered],
                            [r.get("seq") for r in original])
        _rewrite(run_dir, reordered)
        ok, reason = verify_seal(run_dir)
        self.assertFalse(ok, "reordering records must invalidate the seal")
        self.assertNotEqual(reason, "seal-ok")

        # restored content verifies again: the seal tracks content, and the
        # original bytes were never regenerated.
        _rewrite(run_dir, original)
        ok, reason = verify_seal(run_dir)
        self.assertTrue(ok, f"restored run must verify again: {reason}")

    def test_missing_seal_is_not_a_valid_run(self):
        """A missing seal stays a failure, never a legacy pass."""
        run_dir = self._drive()
        (run_dir / "seal.json").unlink()
        ok, reason = verify_seal(run_dir)
        self.assertFalse(ok)
        self.assertEqual(reason, "missing-seal")


class StartRunSealing(_SealChecks, unittest.TestCase):
    """`harness.run.start_run` must seal."""

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp(prefix="seal_startrun_"))
        self.addCleanup(shutil.rmtree, self.base, True)
        self.runs = self.base / "runs"
        self.sessions = self.base / "sessions"
        self.ws = self.base / "ws"
        (self.ws / "src").mkdir(parents=True)
        (self.ws / "src" / "cand.txt").write_text("OK\n", encoding="utf-8")

    def _drive(self) -> Path:
        mission = Mission(
            mission_id="M-seal", description="seal", scope="src/",
            criteria=["recover"],
            problem={"symptom_target": "src/cand.txt",
                     "capability": "read", "purpose": "seal:probe"})
        session = api.create_session(
            mission=mission, workspace_root=self.ws,
            sessions_root=self.sessions)
        run = api.start_run(session, sessions_root=self.sessions,
                            runs_root=self.runs)
        return self.runs / run.run_id

    def test_start_run_seals_and_detects_tampering(self):
        self.assert_sealed_and_tamper_evident(self._drive())


class TelnetRunSealing(_SealChecks, unittest.TestCase):
    """`harness.telnet_run.run_telnet_mission` must seal."""

    mission_id = "M-SEAL-TELNET"

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp(prefix="seal_telnet_"))
        self.addCleanup(shutil.rmtree, self.base, True)
        self.ws = self.base / "ws"
        self.ws.mkdir()
        (self.ws / "test_ok.py").write_text(
            "import unittest\nclass T(unittest.TestCase):\n"
            "    def test_ok(self):\n        self.assertTrue(True)\n",
            encoding="utf-8")
        self.sessions = self.base / "sessions"
        self.runs = self.base / "runs"

    def _mission(self) -> Mission:
        return Mission(
            mission_id=self.mission_id,
            description="governed telnet seal check", scope="",
            criteria=["obtain and verify the flag"],
            problem={
                "telnet": {
                    "username": "root", "password": "",
                    "commands": ["pwd", "ls", "cat flag.txt"],
                    "flag_command": "cat flag.txt",
                    "flag_pattern": "[0-9a-f]{32}",
                    "probe_command": "pwd",
                    "negative_control_command": "ls",
                    "timeout_seconds": 5,
                },
                "verification_tests": ["test_ok.py"],
            })

    def _drive(self) -> Path:
        store = TargetStore()
        store.set_target(build_target_profile(
            mission_id=self.mission_id, locator=HOST, allowed_ports=[23],
            allowed_protocols=["telnet"], scope=HOST,
            authorization_ref="SEAL-CHECK"))
        session = create_session(
            mission=self._mission(), workspace_root=self.ws,
            project_name="seal", sessions_root=self.sessions)
        result = run_telnet_mission(
            session, self._mission(), self.ws, runs_root=self.runs,
            sessions_root=self.sessions, target_store=store,
            mediator=TelnetMediator(session_fn=make_fake_session()))
        return self.runs / result.run.run_id

    def test_telnet_mission_seals_and_detects_tampering(self):
        self.assert_sealed_and_tamper_evident(self._drive())


if __name__ == "__main__":
    unittest.main()
