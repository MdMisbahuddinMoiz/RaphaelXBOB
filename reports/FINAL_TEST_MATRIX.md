MODEL: 4
ROLE: Regression / Test Specialist
STATUS: COMPLETE
FILES CREATED:
reports/FINAL_TEST_MATRIX.md
FULL SUITE: passed=1941 failed=4 skipped=1 xfailed=4 subtests=236 duration=169.56s exit=1
PER-GROUP RESULTS: AI-assisted acceptance: passed=20 failed=0 skipped=0 xfailed=0 subtests=53; target authorization: passed=109 failed=0 skipped=0 xfailed=0 subtests=18; broker / policy / boundary: passed=61 failed=0 skipped=0 xfailed=0 subtests=0; evidence / seal / gate: passed=59 failed=0 skipped=0 xfailed=0 subtests=0; harness / model: passed=84 failed=0 skipped=0 xfailed=0 subtests=0; demos / hero: passed=43 failed=0 skipped=0 xfailed=0 subtests=0
PRE-EXISTING FAILURES: still the same 4? YES
REGRESSIONS INTRODUCED: NONE
DELTA EXPLANATION: The baseline had 4 failed, 1921 passed, 1 skipped, 4 xfailed, 183 subtests in 189.23s. The current run has 4 failed, 1941 passed, 1 skipped, 4 xfailed, 236 subtests in 169.56s. The increase in passed tests (20) and subtests (53) is due to new tests added. No new failures were introduced; the same 4 pre-existing failures persist due to hardcoded paths.
PROPOSED PATH-FIX PATCH (report only, not applied):
diff --git a/tests/test_budget_contract.py b/tests/test_budget_contract.py
index XXXXX..XXXXX 100644
--- a/tests/test_budget_contract.py
+++ b/tests/test_budget_contract.py
@@ -18,6 +18,7 @@
 
 import sys
+import os
 
 sys.path.insert(0, '/home/yaser/raphael-2.0-rbsv2r/src')
@@ -33,7 +34,10 @@
 
 def test_runner_no_hardcoded_iteration_literal():
     """The runner must bind to manifest constants, not a magic literal."""
-    src = open("/home/yaser/raphael-2.0-rbsv2r/src/arena/ablation_runner.py").read()
+    test_dir = os.path.dirname(__file__)
+    src_path = os.path.join(test_dir, "..", "src", "arena", "ablation_runner.py")
+    with open(src_path, 'r') as f:
+        src = f.read()
     # All three paths must reference the manifest import.
     assert src.count("max_iterations = ITERATION_BUDGET") == 3, (
         "Not all execution paths bind max_iterations to ITERATION_BUDGET"
     )
@@ -46,7 +50,10 @@
 
 def test_action_budget_guard_present():
     """Every loop must cap dispatched actions at ACTION_CAP (Gate B)."""
-    src = open("/home/yaser/raphael-2.0-rbsv2r/src/arena/ablation_runner.py").read()
+    test_dir = os.path.dirname(__file__)
+    src_path = os.path.join(test_dir, "..", "src", "arena", "ablation_runner.py")
+    with open(src_path, 'r') as f:
+        src = f.read()
     # Three execution paths (raphael, llm_only, scripted) each have the guard
     assert src.count("self.metrics.actions_dispatched < ACTION_CAP") == 3, (
         "Action-budget guard missing in an execution path"
     )
diff --git a/tests/test_evaluator_isolation.py b/tests/test_evaluator_isolation.py
index XXXXX..XXXXX 100644
--- a/tests/test_evaluator_isolation.py
+++ b/tests/test_evaluator_isolation.py
@@ -20,6 +20,7 @@
 
 import sys
+import os
 
 sys.path.insert(0, '/home/yaser/raphael-2.0-rbsv2r/src')
@@ -101,7 +102,10 @@
 
 def test_environment_no_global_import():
-    src = open("/home/yaser/raphael-2.0-rbsv2r/src/arena/environment.py").read()
+    test_dir = os.path.dirname(__file__)
+    src_path = os.path.join(test_dir, "..", "src", "arena", "environment.py")
+    with open(src_path, 'r') as f:
+        src = f.read()
     assert "get_evidence_graph" not in src, (
         "environment.py still references the global evidence graph"
     )
@@ -109,7 +115,10 @@
 
 def test_arena_entry_fresh_graph_fallback():
     """scripts/arena.py ArenaEntry must mint a fresh graph, never global."""
-    src = open("/home/yaser/raphael-2.0-rbsv2r/scripts/arena.py").read()
+    test_dir = os.path.dirname(__file__)
+    src_path = os.path.join(test_dir, "..", "scripts", "arena.py")
+    with open(src_path, 'r') as f:
+        src = f.read()
     assert "get_evidence_graph" not in src, (
         "scripts/arena.py still references the global evidence graph"
     )
     # default_factory must be EvidenceGraph (fresh per instance).
     assert "default_factory=EvidenceGraph" in src
BLOCKERS:
None