#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="${1:-$(pwd)}"
CORE_EVENT_COUNT="${CORE_EVENT_COUNT:-10000}"
QUERY_SAMPLES="${QUERY_SAMPLES:-1000}"
TOP_K="${TOP_K:-64}"
MAX_STEPS="${MAX_STEPS:-2}"
ENERGY_THRESHOLD="${ENERGY_THRESHOLD:-0.10}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-1800}"

echo "=== ULTRABALLOONDB V00R2 RUST NATIVE RUNTIME BINDING (LINUX) ==="
python3 "$REPO_ROOT/python_ref/ultraballoondb_core/selftest/run_rust_native_runtime_binding_v00r2.py" \
  --repo-root "$REPO_ROOT" \
  --core-event-count "$CORE_EVENT_COUNT" \
  --query-samples "$QUERY_SAMPLES" \
  --top-k "$TOP_K" \
  --max-steps "$MAX_STEPS" \
  --energy-threshold "$ENERGY_THRESHOLD" \
  --timeout-seconds "$TIMEOUT_SECONDS"
echo "PASS_RUN_RUST_NATIVE_RUNTIME_BINDING_V00R2_SH"
