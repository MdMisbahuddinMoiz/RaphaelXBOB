MODEL: 6
ROLE: Evidence / Provenance Specialist
STATUS: COMPLETE
FILES CREATED:
reports/EVIDENCE_FINAL.md
FILES INSPECTED:
raphael_ibm_bob/harness/model_run.py
raphael_ibm_bob/harness/network_run.py
raphael_ibm_bob/seal.py
raphael_ibm_bob/evidence_ledger.py
raphael_ibm_bob/harness/api.py
raphael_ibm_bob/harness/model.py
RECORD KINDS PRODUCED BY A MODEL RUN:
request, decision, result, evidence, finding, gate
  - Causal chain verification:
      * Request submitted: "result = runtime.submit(request, mission)" (model_run.py:338)
      * Decision extracted: "decision = result.broker_result.decision" (model_run.py:340)
      * Sequence extraction: "_latest_bound_execution(ledger)" returns (req_seq, dec_seq, res_seq) for latest ALLOWed success (model_run.py:183-209)
      * Evidence linkage: "_persist_proof" uses (req_seq, dec_seq, res_seq) to link evidence records (model_run.py:211-229)
RUN_ID LOCATION:
run directory name (e.g., runs/<run_id>/), GateRecord.run_id field, seal.json run_id field
FRESH SEAL: (True, 'seal-ok')
TAMPER A delete  -> (False, 'record-count-mismatch:sealed=7 observed=6') EXPECT FAIL
TAMPER B reorder -> (False, 'head-mismatch:ledger-modified-reordered-or-deleted') EXPECT FAIL
TAMPER C edit-in-place -> (False, 'head-mismatch:ledger-modified-reordered-or-deleted') EXPECT FAIL
TAMPER D append-forged -> (False, 'record-count-mismatch:sealed=7 observed=8') EXPECT FAIL
SINGLE LEDGER: YES
HONEST LIMITS (unkeyed seal):
The seal is UNKEYED SHA-256 integrity chain over canonical records plus a sidecar manifest (seal.json). It proves integrity against editing/accidents, not against an attacker holding write access (who could re-seal). No secrets are created, stored, or committed.
Per-record digests: evidence records carry a digest over the payload; finding and gate records carry a digest over the transition payload (which is not stored, so the digest is a presence check only); request, decision, and result records carry no digest and make no seal claim (chain-level sealing via seal.py still applies).
BLOCKERS:
None