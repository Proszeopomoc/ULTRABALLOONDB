#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


def run(cmd: list[str], *, cwd: Path | None = None, timeout: int = 1800) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    print(proc.stdout, end="")
    if proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)}")
    return proc


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--event-count", type=int, default=100000)
    parser.add_argument("--core-event-count", type=int, default=1000)
    parser.add_argument("--query-samples", type=int, default=100)
    parser.add_argument("--top-k", type=int, default=64)
    parser.add_argument("--max-steps", type=int, default=2)
    parser.add_argument("--energy-threshold", type=float, default=0.10)
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    args = parser.parse_args()

    repo = Path(args.repo_root).resolve()
    rust_root = repo / "rust_native"
    compat_crate = rust_root / "ultraballoondb_rust_core"
    cargo = shutil.which("cargo")
    if not cargo:
        print("NO_GO_ULTRABALLOONDB_V00R3A1_CARGO_NOT_FOUND")
        return 3

    audit = repo / "audit" / "v00r3a1_shared_rust_workspace_extraction" / time.strftime("RUN_%Y%m%d_%H%M%S")
    audit.mkdir(parents=True, exist_ok=True)

    metadata_proc = run(
        [cargo, "metadata", "--format-version", "1", "--no-deps", "--locked"],
        cwd=rust_root,
        timeout=args.timeout_seconds,
    )
    metadata = json.loads(metadata_proc.stdout)
    package_names = sorted(pkg["name"] for pkg in metadata["packages"])

    run([cargo, "fmt", "--all", "--", "--check"], cwd=rust_root, timeout=args.timeout_seconds)
    run([cargo, "test", "--workspace", "--release", "--locked"], cwd=rust_root, timeout=args.timeout_seconds)
    run([cargo, "build", "--workspace", "--release", "--locked"], cwd=rust_root, timeout=args.timeout_seconds)

    binary = compat_crate / "target" / "release" / (
        "ultraballoondb_rust_core.exe" if os.name == "nt" else "ultraballoondb_rust_core"
    )
    if not binary.exists():
        raise FileNotFoundError(binary)

    help_result = run([str(binary), "help"], timeout=args.timeout_seconds)
    help_contract_preserved = "UltraBalloonDB Rust native core V00R2" in help_result.stdout

    layout = audit / "rust_layout"
    build_json = audit / "rust_build.json"
    query_json = audit / "rust_query.json"

    run(
        [
            str(binary),
            "build-synthetic",
            "--layout-dir", str(layout),
            "--event-count", str(args.event_count),
            "--output", str(build_json),
        ],
        timeout=args.timeout_seconds,
    )
    run(
        [
            str(binary),
            "query",
            "--layout-dir", str(layout),
            "--seeds", f"1,{max(1, args.event_count // 2)},{args.event_count}",
            "--max-steps", str(args.max_steps),
            "--top-k", str(args.top_k),
            "--energy-threshold", str(args.energy_threshold),
            "--export-limit", "128",
            "--output", str(query_json),
        ],
        timeout=args.timeout_seconds,
    )

    build_result = json.loads(build_json.read_text(encoding="utf-8"))
    query_result = json.loads(query_json.read_text(encoding="utf-8"))

    # Run the existing active-binding regression without changing its semantics.
    v00r2_test = repo / "python_ref" / "ultraballoondb_core" / "selftest" / "run_rust_native_runtime_binding_v00r2.py"
    if not v00r2_test.exists():
        raise FileNotFoundError(v00r2_test)
    v00r2_proc = run(
        [
            sys.executable,
            str(v00r2_test),
            "--repo-root", str(repo),
            "--core-event-count", str(args.core_event_count),
            "--query-samples", str(args.query_samples),
            "--top-k", str(args.top_k),
            "--max-steps", str(args.max_steps),
            "--energy-threshold", str(args.energy_threshold),
            "--timeout-seconds", str(args.timeout_seconds),
        ],
        timeout=args.timeout_seconds,
    )
    v00r2_binding_regression_pass = (
        "PASS_ULTRABALLOONDB_V00R2_RUST_NATIVE_RUNTIME_BINDING" in v00r2_proc.stdout
        and "ACTIVE_RUST_QUERY_BINDING=TRUE" in v00r2_proc.stdout
    )

    lib_rs = rust_root / "ultraballoondb-core" / "src" / "lib.rs"
    main_rs = compat_crate / "src" / "main.rs"
    checks = {
        "workspace_contains_shared_core_and_compat_binary": package_names == [
            "ultraballoondb-core",
            "ultraballoondb_rust_core",
        ],
        "shared_core_library_exists": lib_rs.exists(),
        "compatibility_binary_is_thin": main_rs.exists() and len(main_rs.read_text(encoding="utf-8").splitlines()) <= 5,
        "old_binary_name_preserved": binary.name.startswith("ultraballoondb_rust_core"),
        "old_binary_location_preserved": binary.parent == compat_crate / "target" / "release",
        "help_contract_preserved": help_contract_preserved,
        "synthetic_build_pass": bool(build_result.get("pass")),
        "query_pass": bool(query_result.get("pass")),
        "mmap_active": bool(query_result.get("mmap_active")),
        "full_scan_counter_zero": int(query_result.get("full_scan_counter", -1)) == 0,
        "v00r2_active_binding_regression_pass": v00r2_binding_regression_pass,
        "third_party_rust_crates_zero": int(build_result.get("third_party_rust_crates", -1)) == 0,
    }
    passed = all(checks.values())

    summary = {
        "milestone": "V00R3A1_SHARED_RUST_WORKSPACE_EXTRACTION",
        "role": "CORE",
        "workspace_packages": package_names,
        "shared_core_crate": "ultraballoondb-core",
        "compatibility_binary_crate": "ultraballoondb_rust_core",
        "canonical_semantics_duplicated": False,
        "delivery_modes_enabled_by_shared_core": [
            "PURE_RUST_BINARY",
            "PYO3_NATIVE_EXTENSION",
            "ISOLATED_RUST_DAEMON",
            "STABLE_C_ABI_EMBEDDED_LIBRARY",
        ],
        "active_full_runtime_replacement": False,
        "v00r2_active_query_binding_preserved": v00r2_binding_regression_pass,
        "binary_sha256": sha256_file(binary),
        "library_source_sha256": sha256_file(lib_rs),
        "event_count": args.event_count,
        "edge_count": int(build_result.get("edge_count", 0)),
        "wave_rows": len(query_result.get("wave", [])),
        "full_scan_counter": int(query_result.get("full_scan_counter", -1)),
        "checks": checks,
        "next_gate": "V00R3B_PURE_RUST_STORAGE_WAL_CHECKPOINT_RECOVERY",
    }

    report = audit / "shared_rust_workspace_extraction_report.json"
    report.write_text(
        json.dumps({"pass": passed, "summary": summary}, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    print(
        "PASS_ULTRABALLOONDB_V00R3A1_SHARED_RUST_WORKSPACE_EXTRACTION"
        if passed else
        "NO_GO_ULTRABALLOONDB_V00R3A1_SHARED_RUST_WORKSPACE_EXTRACTION"
    )
    print(f"REPORT={report}")
    print("SUMMARY=" + json.dumps(summary, sort_keys=True))
    print(f"V00R2_ACTIVE_QUERY_BINDING_PRESERVED={str(v00r2_binding_regression_pass).upper()}")
    print("ACTIVE_FULL_RUNTIME_REPLACEMENT=FALSE")
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
