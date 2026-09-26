#!/usr/bin/env bash
# ==============================================================================
# RAPHAEL — real-provider readiness check
#
# Proves the /agent path is credential-ready WITHOUT printing the
# credential: it builds the normalized ProviderConfig, runs the audit
# allow-list, and reports exactly which configuration is still missing.
#
# Reads the credential from the SERVER ENVIRONMENT only
# (RAPHAEL_MODEL_ENDPOINT / RAPHAEL_MODEL_NAME / RAPHAEL_MODEL_API_KEY),
# which is the existing operator mechanism. Nothing is written anywhere.
#
# Usage:
#   ./scripts/check_real_provider.sh              # report readiness
#   RAPHAEL_MODEL_ENDPOINT=https://openrouter.ai/api/v1 \
#   RAPHAEL_MODEL_NAME=mimo-2.6-flash \
#   RAPHAEL_MODEL_API_KEY=... ./scripts/check_real_provider.sh
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

export PYTHONPATH="${REPO_ROOT}:${PYTHONPATH:-}"
exec python3 "${REPO_ROOT}/demos/real_provider_check.py" "$@"
