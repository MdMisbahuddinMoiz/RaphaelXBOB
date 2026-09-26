#!/usr/bin/env bash
# ==============================================================================
# RAPHAEL — AI Agent Vertical Slice Demo Runner
#
# Runs the complete governed AI pentester slice against a LOCAL fixture
# (127.0.0.1:8080) and a LOCAL OpenAI-compatible model endpoint. No vendor
# credential, no external network, no HTB.
#
# Usage:
#   ./scripts/run_agent_demo.sh              # full slice (default 4 turns)
#   ./scripts/run_agent_demo.sh --turns 6    # bound the governed loop
#   ./scripts/run_agent_demo.sh --port 9090  # move the fixture listener
#   ./scripts/run_agent_demo.sh --tests      # run the vertical-slice tests
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required but not found in PATH." >&2
    exit 2
fi

export PYTHONPATH="${REPO_ROOT}:${PYTHONPATH:-}"

if [ "${1:-}" = "--tests" ]; then
    exec python3 -m unittest tests.test_agent_vertical_slice
fi

echo "RAPHAEL — AI agent vertical slice (local fixture, no external network)"
exec python3 "${REPO_ROOT}/demos/agent_vertical_slice.py" "$@"
