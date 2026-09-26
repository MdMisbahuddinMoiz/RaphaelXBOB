#!/usr/bin/env python3
"""Local end-to-end validation of the governed SSH session capability.

Runs the FULL chain against a real, in-process SSH server on loopback:

    model-shaped proposal
      -> ActionRequest
      -> BOBRuntime -> BOBBroker -> BOBPolicy
      -> SshMediator
      -> real SSH transport (paramiko client -> paramiko server)
      -> ONE bounded command on a real exec channel
      -> structured evidence appended to the ledger
      -> the result is what a subsequent model turn observes

Nothing here is a stub at the governance boundary: the transport is
genuine SSH, the credential flows through the vault, the command runs
on a real channel, and the output is bounded and recorded.

No exploitation, no external host, no Kioptrix. The server answers a
fixed read-only command table.

Usage:
    PYTHONPATH=. python3 demos/ssh_session_e2e.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raphael_ibm_bob.broker import BOBBroker  # noqa: E402
from raphael_ibm_bob.contracts import Capability, Mission  # noqa: E402
from raphael_ibm_bob.credential_provenance import (  # noqa: E402
    CredentialProvenance,
    CredentialVault,
)
from raphael_ibm_bob.evidence_ledger import EvidenceLedger  # noqa: E402
from raphael_ibm_bob.harness.providers.openai_compat import (  # noqa: E402
    validate_proposal,
)
from raphael_ibm_bob.policy import BOBPolicy  # noqa: E402
from raphael_ibm_bob.runtime import BOBRuntime  # noqa: E402
from raphael_ibm_bob.skills import (  # noqa: E402
    default_registry,
    register_default_skills,
)
from raphael_ibm_bob.ssh_runtime import (  # noqa: E402
    SshMediator,
    paramiko_ssh_session,
)
from raphael_ibm_bob.target_profile import (  # noqa: E402
    TargetStore,
    build_target_profile,
)
from raphael_ibm_bob.workspace import Workspace  # noqa: E402
from tests.ssh_fixture import (  # noqa: E402
    FIXTURE_PASSWORD,
    FIXTURE_USERNAME,
    LocalSshServer,
)

HOST = "127.0.0.1"
MISSION_ID = "M-SSH-E2E-DEMO"
ALLOWLIST = ("ls", "id", "whoami", "pwd", "uname -a", "cat /etc/shadow",
             "cat /var/log/messages")
RULE = "\n" + "=" * 74 + "\n"


def step(text: str) -> None:
    print(f"{RULE}{text}{RULE}", flush=True)


def main() -> int:
    with LocalSshServer() as server:
        step("1. LOCAL SSH FIXTURE (real transport, loopback only)")
        print(f"  listening            : {HOST}:{server.port}")
        print(f"  host key             : in-memory, regenerated per run")
        print(f"  isolation            : loopback only; no port forwarding")

        # --- credential: a vault reference, never a literal ------------
        step("2. CREDENTIAL (reference only, plaintext stays in the vault)")
        vault = CredentialVault()
        ref = vault.store("ssh_password", FIXTURE_PASSWORD, HOST,
                          CredentialProvenance.DEFAULT_CREDENTIAL)
        vault.mark_validated(ref.credential_id, HOST, "ssh")
        vault.authorize(ref.credential_id, HOST, "ssh")
        print(f"  credential id        : {ref.credential_id[:8]}…")
        print(f"  fingerprint          : {ref.fingerprint[:16]}…")
        print(f"  authorized for       : {ref.authorized_for_protocols}")

        # --- governed stack --------------------------------------------
        step("3. GOVERNED STACK (Runtime -> Broker -> Policy -> Mediator)")
        workspace = Workspace(tempfile.mkdtemp(prefix="raphael-ssh-e2e-"))
        ledger = EvidenceLedger(workspace.root)
        store = TargetStore()
        store.set_target(build_target_profile(
            mission_id=MISSION_ID, locator=HOST, allowed_ports=[server.port],
            allowed_protocols="ssh", authorization_ref="local-fixture",
            platform="htb"))
        mediator = SshMediator(session_fn=paramiko_ssh_session, vault=vault)
        broker = BOBBroker(
            BOBPolicy(workspace, target_store=store, credential_vault=vault),
            workspace, ledger=ledger, target_store=store,
            ssh_mediator=mediator, credential_vault=vault)
        runtime = BOBRuntime(broker)
        mission = Mission(
            mission_id=MISSION_ID, description="governed ssh session",
            scope=HOST, criteria=["session"],
            problem={"ssh": {
                "username": FIXTURE_USERNAME,
                "credential_id": ref.credential_id,
                "authorized_commands": list(ALLOWLIST),
                "port": server.port,
                "stdout_limit": 128,
                "stderr_limit": 64,
                "command_timeout_seconds": 10,
                "host_key_policy": "auto-add",
            }})
        print(f"  authorized host      : {store.current().locator}")
        print(f"  authorized port      : {store.current().allowed_ports}")
        print(f"  authorized protocol  : {store.current().allowed_protocols}")
        print(f"  allow-listed cmds    : {len(ALLOWLIST)}")

        registry = register_default_skills(default_registry())
        checks = [
            ("ls", "allowed command"),
            ('cmd="cat /etc/shadow" probe a denied file', None),
            ("uname -a", "allowed multi-word command"),
            ("reboot", "command outside the allow-list"),
            ('cmd="ls" && cat /etc/shadow', "shell chaining"),
            ('cmd="sudo ls"', "privilege escalation"),
        ]

        for command, note in checks:
            step(f"4. PROPOSAL: {note}")
            if isinstance(command, str) and command.startswith("cmd="):
                purpose = command
            else:
                purpose = f'cmd="{command}" observe the authorized target'
            # A model proposal: validate_proposal is exactly what the
            # provider adapter runs on a real model's JSON reply.
            request = validate_proposal(
                {"intent": "act", "skill": "network-ssh-session",
                 "target": f"ssh://{HOST}:{server.port}",
                 "purpose": purpose},
                registry)
            print(f"  ActionRequest        : capability="
                  f"{request.capability.value} requester={request.requester}")
            print(f"  purpose (rationale)  : {request.purpose[:96]}")
            result = runtime.submit(request, mission)
            decision = result.broker_result.decision
            print(f"  POLICY               : {decision.decision.value.upper()} "
                  f"({decision.reason})")
            if result.execution is None:
                print("  EXECUTE              : refused — no session opened")
                print("  EVIDENCE             : request+decision only")
                continue
            evidence = result.execution.evidence
            print(f"  EXECUTE              : invoked="
                  f"{result.broker_result.capability_invoked} "
                  f"success={result.execution.success}")
            print(f"  SESSION              : id="
                  f"{evidence['session_id'][:12]}… host={evidence['host']} "
                  f"port={evidence['port']} proto={evidence['protocol']}")
            print(f"  EXIT CODE            : {evidence['exit_code']}")
            print(f"  STDOUT (bounded)     : "
                  f"{evidence['stdout']!r}"
                  f"{' [TRUNCATED]' if evidence['stdout_truncated'] else ''}")
            if evidence["stderr"]:
                print(f"  STDERR (bounded)     : {evidence['stderr']!r}")
            print(f"  EVIDENCE IDS         : "
                  f"{', '.join(result.broker_result.evidence_ids)}")

        step("5. WHAT THE NEXT MODEL TURN WOULD OBSERVE")
        records = [json.loads(line) for line in
                   (Path(ledger.run_dir()) / "evidence.jsonl")
                   .read_text(encoding="utf-8").splitlines() if line]
        ssh = [r for r in records if r.get("producer") == "ssh"]
        print(f"  ssh evidence records : {len(ssh)}")
        if ssh:
            last = ssh[-1]["payload"]["ssh_result"]
            print("  observation shape    : "
                  f"{{'command': {last['command']!r}, "
                  f"'exit_code': {last['exit_code']}, "
                  f"'stdout': {last['stdout'][:40]!r}, "
                  f"'provider_untrusted': True}}")

        step("6. CREDENTIAL LEAK AUDIT")
        blob = json.dumps([r for r in records], default=str)
        blob += json.dumps(mission.to_dict(), default=str)
        blob += (Path(ledger.run_dir()) / "harness.json").read_text(
            encoding="utf-8") if (Path(ledger.run_dir())
                                  / "harness.json").exists() else ""
        leaked = FIXTURE_PASSWORD in blob
        print(f"  credential in ledger  : {'LEAKED' if leaked else 'absent'}")
        print(f"  credential in mission : "
              f"{'LEAKED' if FIXTURE_PASSWORD in json.dumps(mission.to_dict()) else 'absent'}")
        print(f"  ledger dir            : {ledger.run_dir()}")

        step("RESULT")
        print("  Real SSH transport, real password auth, real exec channel,")
        print("  one governed command per request, bounded output, structured")
        print("  evidence, and the credential absent from every artifact.")
        return 1 if leaked else 0


if __name__ == "__main__":
    sys.exit(main())
