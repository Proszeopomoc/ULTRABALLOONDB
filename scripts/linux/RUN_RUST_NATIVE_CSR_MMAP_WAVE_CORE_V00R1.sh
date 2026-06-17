#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${1:?usage: $0 REPO_ROOT [EVENT_COUNT] [QUERY_SAMPLES]}"
EVENT_COUNT="${2:-1000000}"
QUERY_SAMPLES="${3:-5000}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

copy_safe() {
  local src="$1"
  local dst="$2"
  mkdir -p "$(dirname "$dst")"
  if [[ "$(realpath -m "$src")" != "$(realpath -m "$dst")" ]]; then
    cp -f "$src" "$dst"
  fi
}

files=(
  "rust_native/ultraballoondb_rust_core/Cargo.toml"
  "rust_native/ultraballoondb_rust_core/Cargo.lock"
  "rust_native/ultraballoondb_rust_core/rust-toolchain.toml"
  "rust_native/ultraballoondb_rust_core/src/main.rs"
  "python_ref/ultraballoondb_core/selftest/run_rust_native_csr_mmap_wave_core_v00r1.py"
  "docs/V00R1_RUST_NATIVE_CSR_MMAP_WAVE_CORE_CANDIDATE.md"
  "docs/alignment/V00R1_RUST_NATIVE_CSR_MMAP_WAVE_CORE_CANDIDATE.json"
  "scripts/windows/RUN_RUST_NATIVE_CSR_MMAP_WAVE_CORE_V00R1.ps1"
)
for relative in "${files[@]}"; do
  copy_safe "$PACKAGE_ROOT/$relative" "$REPO_ROOT/$relative"
done
copy_safe "$0" "$REPO_ROOT/scripts/linux/RUN_RUST_NATIVE_CSR_MMAP_WAVE_CORE_V00R1.sh"

if ! command -v cargo >/dev/null 2>&1; then
  echo "NO_GO_ULTRABALLOONDB_V00R1_CARGO_NOT_FOUND"
  echo "INSTALL_COMMAND=curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
  exit 3
fi

python3 "$REPO_ROOT/python_ref/ultraballoondb_core/selftest/run_rust_native_csr_mmap_wave_core_v00r1.py" \
  --repo-root "$REPO_ROOT" \
  --event-count "$EVENT_COUNT" \
  --query-samples "$QUERY_SAMPLES" \
  --top-k 64 \
  --max-steps 2 \
  --energy-threshold 0.10 \
  --min-query-speedup 1.25 \
  --timeout-seconds 1800

echo "PASS_ULTRABALLOONDB_V00R1_ALIGNMENT_CHECK"
echo "PASS_RUN_RUST_NATIVE_CSR_MMAP_WAVE_CORE_V00R1_SH"
