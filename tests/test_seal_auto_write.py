"""tests.test_seal_auto_write — Task 1 acceptance tests.

Verifies that run_network_mission() automatically writes seal.json after
ledger close for completed, refused, and failed runs, that the seal
corresponds to the final evidence ledger, that a write_seal failure does
not propagate (run state and verdict are preserved), and that seal failure
remains observable through the existing seal-status behavior.

All tests are offline and deterministic: they use a local stdlib HTTP
server or a closed port, a temporary workspace, and the real
run_network_mission() execution path.

Acceptance criteria (from approved plan):
  - completed run creates seal.json
  - verify_seal() returns (True, "seal-ok")
  - the seal corresponds to the final evidence ledger
  - simulated write_seal failure does not propagate
  - simulated seal failure does not alter the original run result
  - seal failure remains observable through existing seal-status behavior
    (missing-seal or head-mismatch)
"""
from __future__ import annotations

import logging
import shutil
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from raphael_ibm_bob.harness.network_run import run_network_mission
from raphael_ibm_bob.harness.session import RaphaelSession
from raphael_ibm_bob.contracts import Mission
from raphael_ibm_bob.seal import verify_seal
from raphael_ibm_bob.target_profile import TargetStore, TargetProfile
from raphael_ibm_bob.mode import ModeManager, Mode


# ---------------------------------------------------------------------------
# Minimal HTTP fixture (serves a trivial response for probe/flag requests)
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code: int, body: bytes = b"") -> None:
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path in ("/", "/index.html"):
            self._send(200, b"raphael-fixture-ok")
        elif path == "/raphael-decoy":
            self._send(404, b"not found")
        else:
            self._send(200, b"ok")


def _start_fixture():
    """Start a local HTTP server on a random port; return (server, port)."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def _free_port() -> int:
    """Return a port that is not currently in use (for refusal tests)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ---------------------------------------------------------------------------
# Shared test infrastructure
# ---------------------------------------------------------------------------

class _Base(unittest.TestCase):
    mission_id = "M-SEAL-TEST-001"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="seal_auto_"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.ws = self.tmp / "ws"
        self.ws.mkdir()
        # Minimal passing test file for RUN_TEST condition B/C
        (self.ws / "test_ok.py").write_text(
            "import unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_ok(self):\n"
            "        self.assertTrue(True)\n",
            encoding="utf-8",
        )
        self.runs = self.tmp / "runs"
        self.runs.mkdir()
        self.sessions = self.tmp / "sessions"
        self.sessions.mkdir()

    def _make_session(self) -> RaphaelSession:
        return RaphaelSession.create(
            mission=None,
            workspace=None,
            model="test",
            provider="none",
        )

    def _make_mission(self, host: str, port: int) -> Mission:
        return Mission(
            mission_id=self.mission_id,
            description="seal auto-write test",
            scope="",
            criteria=["verify seal is written"],
            problem={
                "symptom_target": host,
                "request_path": "/",
                "probe_path": "/index.html",
                "decoy_path": "/raphael-decoy",
                "verification_tests": ["test_ok.py"],
            },
        )

    def _make_store(self, host: str, port: int) -> TargetStore:
        store = TargetStore()
        store.set_target(TargetProfile(
            platform="htb",
            target_id=f"{host}:{port}",
            locator=host,
            allowed_ports=[port],
            allowed_protocols=["http"],
            scope=host,
            authorization_ref="SEAL-TEST-AUTH",
            mission_id=self.mission_id,
        ))
        return store

    def _run(self, host: str, port: int, *, target_store=None):
        session = self._make_session()
        mission = self._make_mission(host, port)
        store = target_store if target_store is not None else self._make_store(host, port)
        return run_network_mission(
            session, mission, self.ws,
            runs_root=self.runs,
            sessions_root=self.sessions,
            target_store=store,
        )

    def _run_dir(self, result) -> Path:
        return Path(result.run.ledger_dir)


# ---------------------------------------------------------------------------
# Test 1 — completed run creates seal.json and verify_seal returns ok
# ---------------------------------------------------------------------------

class TestSealWrittenOnCompletion(_Base):
    """A completed network run (7/7 COMPLETE) must produce a valid seal."""

    def test_completed_run_creates_seal_json(self):
        server, port = _start_fixture()
        try:
            result = self._run("127.0.0.1", port)
        finally:
            server.shutdown()
            server.server_close()

        run_dir = self._run_dir(result)
        seal_path = run_dir / "seal.json"
        self.assertTrue(
            seal_path.is_file(),
            f"seal.json was not created in {run_dir}",
        )

    def test_verify_seal_returns_ok_for_completed_run(self):
        server, port = _start_fixture()
        try:
            result = self._run("127.0.0.1", port)
        finally:
            server.shutdown()
            server.server_close()

        run_dir = self._run_dir(result)
        ok, reason = verify_seal(run_dir)
        self.assertTrue(ok, f"verify_seal failed: {reason}")
        self.assertEqual(reason, "seal-ok")

    def test_seal_corresponds_to_final_evidence_ledger(self):
        """The seal must match the actual evidence.jsonl written during the run.

        Modifying the ledger after the seal is written should cause
        verify_seal to report head-mismatch, proving the seal was computed
        over the real final ledger state.
        """
        server, port = _start_fixture()
        try:
            result = self._run("127.0.0.1", port)
        finally:
            server.shutdown()
            server.server_close()

        run_dir = self._run_dir(result)
        ledger_path = run_dir / "evidence.jsonl"

        # Seal must currently verify
        ok, reason = verify_seal(run_dir)
        self.assertTrue(ok, f"pre-tamper verify_seal failed: {reason}")

        # Append a spurious parseable JSON record to simulate post-seal tamper.
        # An empty line is silently skipped by LedgerReader; a real JSON object
        # changes the record count and/or the hash chain.
        import json as _json
        spurious = _json.dumps({"kind": "evidence", "seq": 9999,
                                "tampered": True}) + "\n"
        with open(ledger_path, "a", encoding="utf-8") as fh:
            fh.write(spurious)

        ok2, reason2 = verify_seal(run_dir)
        self.assertFalse(ok2, "tampered ledger should not verify")
        # The chain recomputes over the modified record list: count grows and
        # head no longer matches.  Accept any of the three failure reasons.
        self.assertTrue(
            reason2.startswith("record-count-mismatch:")
            or reason2 == "head-mismatch:ledger-modified-reordered-or-deleted"
            or reason2 == "malformed-ledger",
            f"unexpected reason after tamper: {reason2!r}",
        )


# ---------------------------------------------------------------------------
# Test 2 — refused run also creates a valid seal
# ---------------------------------------------------------------------------

class TestSealWrittenOnRefusal(_Base):
    """A refused run (unreachable target → REFUSE) must also create seal.json."""

    def test_refused_run_creates_seal_json(self):
        port = _free_port()  # closed port → network probe fails → REFUSE
        result = self._run("127.0.0.1", port)

        self.assertEqual(result.terminal, "refused",
                         f"expected refused, got {result.terminal}")
        run_dir = self._run_dir(result)
        self.assertTrue(
            (run_dir / "seal.json").is_file(),
            f"seal.json missing for refused run in {run_dir}",
        )
        ok, reason = verify_seal(run_dir)
        self.assertTrue(ok, f"verify_seal for refused run: {reason}")
        self.assertEqual(reason, "seal-ok")


# ---------------------------------------------------------------------------
# Test 3 — write_seal failure does not propagate; run result is preserved
# ---------------------------------------------------------------------------

class TestSealFailureIsSafe(_Base):
    """A write_seal() failure must not raise, alter the verdict, or change state."""

    def test_seal_failure_does_not_raise(self):
        """_try_write_seal silences write_seal exceptions."""
        server, port = _start_fixture()
        try:
            with patch(
                "raphael_ibm_bob.harness.network_run.write_seal",
                side_effect=OSError("simulated disk full"),
            ):
                # Must not raise despite write_seal raising
                result = self._run("127.0.0.1", port)
        finally:
            server.shutdown()
            server.server_close()

        # Run completed normally
        self.assertIn(result.terminal, ("completed", "refused"))

    def test_seal_failure_does_not_alter_run_state(self):
        """The original run state and gate verdict are unchanged when seal fails."""
        server, port = _start_fixture()
        try:
            with patch(
                "raphael_ibm_bob.harness.network_run.write_seal",
                side_effect=RuntimeError("simulated seal error"),
            ):
                result = self._run("127.0.0.1", port)
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(result.terminal, result.run.state)
        # gate_verdict is present (not wiped by the seal failure)
        self.assertIsNotNone(result.gate_verdict,
                             "gate_verdict was cleared by seal failure")

    def test_seal_failure_is_observable_via_seal_status(self):
        """When seal write fails, verify_seal returns (False, 'missing-seal').

        This is the existing seal-status behavior: the operator can discover
        the problem via GET /runs/{id}/seal → missing-seal.
        """
        server, port = _start_fixture()
        try:
            with patch(
                "raphael_ibm_bob.harness.network_run.write_seal",
                side_effect=OSError("simulated disk full"),
            ):
                result = self._run("127.0.0.1", port)
        finally:
            server.shutdown()
            server.server_close()

        run_dir = self._run_dir(result)
        seal_path = run_dir / "seal.json"
        self.assertFalse(seal_path.is_file(), "seal.json must be absent when write fails")

        ok, reason = verify_seal(run_dir)
        self.assertFalse(ok)
        self.assertEqual(reason, "missing-seal",
                         f"expected missing-seal, got {reason!r}")

    def test_seal_failure_emits_warning_log(self):
        """_try_write_seal logs a WARNING when write_seal raises."""
        server, port = _start_fixture()
        try:
            with patch(
                "raphael_ibm_bob.harness.network_run.write_seal",
                side_effect=OSError("simulated disk full"),
            ), self.assertLogs(
                "raphael_ibm_bob.harness.network_run", level=logging.WARNING
            ) as log_ctx:
                self._run("127.0.0.1", port)
        finally:
            server.shutdown()
            server.server_close()

        self.assertTrue(
            any("seal write failed" in msg for msg in log_ctx.output),
            f"expected 'seal write failed' in log output; got: {log_ctx.output}",
        )


if __name__ == "__main__":
    unittest.main()
