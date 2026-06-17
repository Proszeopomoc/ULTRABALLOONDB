#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${1:?usage: RUN_SHARED_RUST_WORKSPACE_EXTRACTION_V00R3A1.sh REPO_ROOT [EVENT_COUNT]}"
EVENT_COUNT="${2:-100000}"
CORE_EVENT_COUNT="${3:-1000}"
QUERY_SAMPLES="${4:-100}"

python3 "$REPO_ROOT/python_ref/ultraballoondb_core/selftest/run_shared_rust_workspace_extraction_v00r3a1.py" \
  --repo-root "$REPO_ROOT" \
  --event-count "$EVENT_COUNT" \
  --core-event-count "$CORE_EVENT_COUNT" \
  --query-samples "$QUERY_SAMPLES" \
  --top-k 64 \
  --max-steps 2 \
  --energy-threshold 0.10 \
  --timeout-seconds 1800

echo "PASS_RUN_SHARED_RUST_WORKSPACE_EXTRACTION_V00R3A1_SH"
