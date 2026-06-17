#!/usr/bin/env bash
set -euo pipefail

archive=""
q_script=""
windows_fixture=""
windows_manifest=""
windows_evidence_dir=""
run_id=""
event_count="100000"
core_event_count="1000"
timeout_seconds="600"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --archive) archive="$2"; shift 2 ;;
    --q-script) q_script="$2"; shift 2 ;;
    --windows-fixture) windows_fixture="$2"; shift 2 ;;
    --windows-manifest) windows_manifest="$2"; shift 2 ;;
    --windows-evidence-dir) windows_evidence_dir="$2"; shift 2 ;;
    --run-id) run_id="$2"; shift 2 ;;
    --event-count) event_count="$2"; shift 2 ;;
    --core-event-count) core_event_count="$2"; shift 2 ;;
    --timeout-seconds) timeout_seconds="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

for required in archive q_script windows_fixture windows_manifest windows_evidence_dir run_id; do
  if [[ -z "${!required}" ]]; then
    echo "Missing --${required//_/-}" >&2
    exit 2
  fi
done

command -v python3 >/dev/null 2>&1 || { echo "NO_GO: python3 missing in WSL" >&2; exit 3; }
command -v tar >/dev/null 2>&1 || { echo "NO_GO: tar missing in WSL" >&2; exit 3; }

native_root="$HOME/.ultraballoondb_v00q1/$run_id"
source_root="$native_root/source"
win_fixture_native="$native_root/windows_fixture"
linux_fixture_native="$native_root/linux_fixture"
linux_manifest_native="$native_root/linux_fixture_manifest.json"
linux_report_native="$native_root/wsl2_native_linux_runtime_report.json"

rm -rf "$native_root"
mkdir -p "$source_root" "$win_fixture_native" "$linux_fixture_native"

tar -xf "$archive" -C "$source_root"
mkdir -p "$source_root/python_ref/ultraballoondb_core/selftest"
cp "$q_script" "$source_root/python_ref/ultraballoondb_core/selftest/run_wsl2_native_linux_runtime_validation_v00q1.py"
cp -a "$windows_fixture/." "$win_fixture_native/"
cp "$windows_manifest" "$native_root/windows_fixture_manifest.json"

fs_type="$(stat -f -c %T "$native_root" 2>/dev/null || true)"
echo "WSL_NATIVE_ROOT=$native_root"
echo "WSL_NATIVE_FS_TYPE=$fs_type"
echo "WSL_UNAME=$(uname -a)"
echo "WSL_PYTHON=$(python3 --version 2>&1)"

PYTHONPATH="$source_root/python_ref${PYTHONPATH:+:$PYTHONPATH}" \
python3 "$source_root/python_ref/ultraballoondb_core/selftest/run_wsl2_native_linux_runtime_validation_v00q1.py" \
  linux-suite \
  --repo-root "$source_root" \
  --windows-fixture-dir "$win_fixture_native" \
  --windows-fixture-manifest "$native_root/windows_fixture_manifest.json" \
  --linux-fixture-dir "$linux_fixture_native" \
  --linux-fixture-manifest "$linux_manifest_native" \
  --report-path "$linux_report_native" \
  --event-count "$event_count" \
  --core-event-count "$core_event_count" \
  --timeout-seconds "$timeout_seconds"

mkdir -p "$windows_evidence_dir/linux_fixture_from_wsl"
rm -rf "$windows_evidence_dir/linux_fixture_from_wsl"/*
cp -a "$linux_fixture_native/." "$windows_evidence_dir/linux_fixture_from_wsl/"
cp "$linux_manifest_native" "$windows_evidence_dir/linux_fixture_manifest.json"
cp "$linux_report_native" "$windows_evidence_dir/wsl2_native_linux_runtime_report.json"

sha256sum "$linux_report_native" "$linux_manifest_native"
echo "PASS_RUN_WSL2_NATIVE_LINUX_RUNTIME_V00Q1_SH"
