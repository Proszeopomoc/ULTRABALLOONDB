#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import compileall
import hashlib
import importlib
import json
import os
import platform
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, Iterable, List, Sequence, Tuple

HERE = Path(__file__).resolve()
PYTHON_REF = HERE.parents[2]
if str(PYTHON_REF) not in sys.path:
    sys.path.insert(0, str(PYTHON_REF))

from ultraballoondb_core.csr_mmap_hotpath import CsrMmapHotGraph

VERSION = "V00Q1_WSL2_NATIVE_LINUX_RUNTIME_VALIDATION"
PASS_FIXTURE = "PASS_ULTRABALLOONDB_V00Q1_CSR_FIXTURE"
PASS_LINUX = "PASS_ULTRABALLOONDB_V00Q1_WSL2_NATIVE_LINUX_RUNTIME"
NO_GO = "NO_GO_ULTRABALLOONDB_V00Q1_WSL2_NATIVE_LINUX_RUNTIME"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def wave_signature(graph: CsrMmapHotGraph, seeds: Sequence[int], *, top_k: int = 64) -> List[Tuple[int, float, int, int]]:
    rows = graph.wave_activation(
        list(map(int, seeds)),
        max_steps=2,
        energy_threshold=0.10,
        top_k=int(top_k),
    )
    return [(int(r.node_id), round(float(r.energy), 12), int(r.predecessor), int(r.edge_type)) for r in rows]


def fixture_document(layout: Path, event_count: int) -> Dict[str, Any]:
    graph = CsrMmapHotGraph(layout)
    try:
        seeds = [1, max(1, event_count // 2), event_count]
        doc = {
            "version": VERSION,
            "event_count": int(event_count),
            "edge_count": int(graph.edge_count),
            "layout_sha256": graph.layout_sha256(),
            "nodes_sha256": sha256_file(layout / "csr_nodes.bin"),
            "edges_sha256": sha256_file(layout / "csr_edges.bin"),
            "manifest_sha256": sha256_file(layout / "csr_manifest.json"),
            "seeds": seeds,
            "wave_signature": wave_signature(graph, seeds),
            "mmap_active": bool(graph.mmap_active),
            "full_scan_counter": int(graph.full_scan_counter),
            "platform": platform.platform(),
            "python": sys.version,
        }
        return doc
    finally:
        graph.close()


def create_fixture(layout: Path, manifest: Path, event_count: int) -> int:
    if layout.exists():
        shutil.rmtree(layout)
    layout.mkdir(parents=True, exist_ok=True)
    graph = CsrMmapHotGraph.build_synthetic(layout, int(event_count))
    graph.close()
    doc = fixture_document(layout, int(event_count))
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
    ok = bool(doc["mmap_active"]) and int(doc["full_scan_counter"]) == 0
    print(PASS_FIXTURE if ok else NO_GO)
    print(f"FIXTURE_LAYOUT={layout}")
    print(f"FIXTURE_MANIFEST={manifest}")
    print("SUMMARY=" + json.dumps(doc, sort_keys=True))
    return 0 if ok else 2


def verify_fixture(layout: Path, manifest: Path) -> Tuple[bool, Dict[str, Any]]:
    expected = json.loads(manifest.read_text(encoding="utf-8"))
    actual = fixture_document(layout, int(expected["event_count"]))
    checks = {
        "layout_sha_match": actual["layout_sha256"] == expected["layout_sha256"],
        "nodes_sha_match": actual["nodes_sha256"] == expected["nodes_sha256"],
        "edges_sha_match": actual["edges_sha256"] == expected["edges_sha256"],
        "manifest_sha_match": actual["manifest_sha256"] == expected["manifest_sha256"],
        "event_count_match": int(actual["event_count"]) == int(expected["event_count"]),
        "edge_count_match": int(actual["edge_count"]) == int(expected["edge_count"]),
        "wave_signature_match": actual["wave_signature"] == [tuple(x) for x in expected["wave_signature"]],
        "mmap_active": bool(actual["mmap_active"]),
        "full_scan_counter_zero": int(actual["full_scan_counter"]) == 0,
    }
    ok = all(checks.values())
    result = {"ok": ok, "checks": checks, "expected": expected, "actual": actual}
    return ok, result


def run_command(cmd: Sequence[str], *, cwd: Path, env: Dict[str, str], timeout: int) -> Dict[str, Any]:
    started = time.perf_counter()
    proc = subprocess.run(
        list(cmd),
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return {
        "command": list(cmd),
        "returncode": int(proc.returncode),
        "elapsed_seconds": time.perf_counter() - started,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def run_existing_selftest(
    repo: Path,
    relative_script: str,
    pass_line: str,
    extra_args: Sequence[str],
    *,
    timeout: int,
) -> Dict[str, Any]:
    script = repo / relative_script
    if not script.exists():
        return {
            "exists": False,
            "pass": False,
            "reason": f"missing selftest: {relative_script}",
        }
    env = dict(os.environ)
    env["PYTHONPATH"] = str(repo / "python_ref") + os.pathsep + env.get("PYTHONPATH", "")
    result = run_command(
        [sys.executable, str(script), "--repo-root", str(repo), *extra_args],
        cwd=repo,
        env=env,
        timeout=timeout,
    )
    result["exists"] = True
    result["pass"] = result["returncode"] == 0 and pass_line in result["stdout"]
    result["pass_line"] = pass_line
    return result


def filesystem_type(path: Path) -> str:
    try:
        proc = subprocess.run(
            ["stat", "-f", "-c", "%T", str(path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return proc.stdout.strip() if proc.returncode == 0 else "UNKNOWN"
    except Exception:
        return "UNKNOWN"


def linux_suite(args: argparse.Namespace) -> int:
    repo = Path(args.repo_root).resolve()
    windows_layout = Path(args.windows_fixture_dir).resolve()
    windows_manifest = Path(args.windows_fixture_manifest).resolve()
    linux_layout = Path(args.linux_fixture_dir).resolve()
    linux_manifest = Path(args.linux_fixture_manifest).resolve()
    report_path = Path(args.report_path).resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)

    fs_type = filesystem_type(repo)
    is_wsl = bool(os.environ.get("WSL_INTEROP")) or "microsoft" in platform.release().lower() or "microsoft" in platform.version().lower()
    is_linux = platform.system() == "Linux" and os.name == "posix"
    repo_on_windows_mount = str(repo).startswith("/mnt/")
    non_native_fs = fs_type.lower() in {"9p", "drvfs", "fuseblk", "ntfs", "cifs", "smb2"}

    compile_ok = compileall.compile_dir(str(repo / "python_ref"), quiet=1, force=False)

    import_names = [
        "ultraballoondb_core.csr_mmap_hotpath",
        "ultraballoondb_core.unified_runtime",
        "ultraballoondb_core.durable_runtime",
        "ultraballoondb_core.database_api",
        "ultraballoondb_core.http_transport",
        "ultraballoondb_core.cli",
    ]
    import_results: Dict[str, Any] = {}
    for name in import_names:
        try:
            importlib.import_module(name)
            import_results[name] = {"ok": True}
        except Exception as exc:
            import_results[name] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    win_to_linux_ok, win_to_linux = verify_fixture(windows_layout, windows_manifest)

    create_rc = create_fixture(linux_layout, linux_manifest, int(args.event_count))
    linux_fixture_doc = json.loads(linux_manifest.read_text(encoding="utf-8")) if linux_manifest.exists() else {}

    tests = {
        "v00m_unified_l0_l7": run_existing_selftest(
            repo,
            "python_ref/ultraballoondb_core/selftest/run_unified_l0_l7_database_runtime_v00m.py",
            "PASS_ULTRABALLOONDB_UNIFIED_L0_L7_DATABASE_RUNTIME_V00M",
            ["--event-count", str(args.core_event_count), "--seed-queries", "8", "--top-k-per-seed", "8", "--payload-top-k", "16"],
            timeout=args.timeout_seconds,
        ),
        "v00n_wal_recovery": run_existing_selftest(
            repo,
            "python_ref/ultraballoondb_core/selftest/run_durable_writes_wal_crash_recovery_v00n.py",
            "PASS_ULTRABALLOONDB_DURABLE_WRITES_WAL_CRASH_RECOVERY_V00N",
            ["--event-count", str(args.core_event_count), "--checkpoint-records", "4", "--replay-records", "4", "--query-top-k", "64"],
            timeout=args.timeout_seconds,
        ),
        "v00o_api_cli_http": run_existing_selftest(
            repo,
            "python_ref/ultraballoondb_core/selftest/run_stable_database_api_cli_transport_v00o.py",
            "PASS_ULTRABALLOONDB_STABLE_DATABASE_API_CLI_TRANSPORT_V00O",
            ["--event-count", str(args.core_event_count), "--query-top-k", "64"],
            timeout=args.timeout_seconds,
        ),
        "v00p1_csr_mmap": run_existing_selftest(
            repo,
            "python_ref/ultraballoondb_core/selftest/run_csr_mmap_core_hotpath_binding_v00p1.py",
            "PASS_ULTRABALLOONDB_CSR_MMAP_CORE_HOTPATH_BINDING_V00P1",
            ["--event-count", str(args.event_count), "--seed-queries", "16", "--top-k", "64", "--max-steps", "2", "--energy-threshold", "0.10"],
            timeout=args.timeout_seconds,
        ),
    }

    checks = {
        "platform_linux": is_linux,
        "wsl_environment_detected": is_wsl,
        "repo_copied_to_wsl_native_home": not repo_on_windows_mount,
        "native_linux_filesystem": not non_native_fs and fs_type != "UNKNOWN",
        "python_compileall": bool(compile_ok),
        "all_core_imports": all(v.get("ok") for v in import_results.values()),
        "windows_to_linux_csr_binary_compatible": bool(win_to_linux_ok),
        "linux_fixture_created": create_rc == 0 and bool(linux_fixture_doc),
        "linux_mmap_active": bool(linux_fixture_doc.get("mmap_active")),
        "linux_full_scan_counter_zero": int(linux_fixture_doc.get("full_scan_counter", -1)) == 0,
        "all_existing_core_selftests_pass": all(v.get("pass") for v in tests.values()),
    }
    failures = {name: "check failed" for name, ok in checks.items() if not ok}
    status = PASS_LINUX if not failures else NO_GO

    report: Dict[str, Any] = {
        "version": VERSION,
        "status": status,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python": sys.version,
            "os_name": os.name,
            "wsl_interop_present": bool(os.environ.get("WSL_INTEROP")),
            "filesystem_type": fs_type,
            "repo_root": str(repo),
        },
        "alignment": {
            "role": "SUPPORT",
            "touches_core_layers": [],
            "uses_auxiliary_layers": [],
            "must_preserve": ["L0", "L1", "L2", "L3", "L4", "L5", "L6", "L7"],
            "runtime_impact": "CROSS_PLATFORM_VALIDATION_ONLY",
            "roadmap_status": "ALIGNED",
        },
        "params": {
            "event_count": int(args.event_count),
            "core_event_count": int(args.core_event_count),
            "timeout_seconds": int(args.timeout_seconds),
        },
        "imports": import_results,
        "windows_to_linux_fixture": win_to_linux,
        "linux_fixture": linux_fixture_doc,
        "existing_selftests": tests,
        "checks": checks,
        "failures": failures,
        "scope": {
            "validates": [
                "WSL2 Linux kernel runtime",
                "native WSL Linux filesystem",
                "Python source compilation and imports",
                "L0-L7 unified runtime",
                "WAL crash recovery",
                "API/CLI/HTTP",
                "CSR mmap hotpath",
                "Windows-to-Linux CSR binary compatibility",
            ],
            "does_not_validate": [
                "independent bare-metal Linux distribution",
                "macOS runtime",
                "Linux-to-Windows compatibility until Windows post-verification completes",
            ],
        },
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    print(status)
    print(f"REPORT={report_path}")
    print("SUMMARY=" + json.dumps({
        "filesystem_type": fs_type,
        "imports_ok": checks["all_core_imports"],
        "windows_to_linux": checks["windows_to_linux_csr_binary_compatible"],
        "core_selftests": {k: bool(v.get("pass")) for k, v in tests.items()},
        "linux_layout_sha256": linux_fixture_doc.get("layout_sha256"),
        "failures": sorted(failures),
    }, sort_keys=True))
    return 0 if not failures else 2


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)

    p_create = sub.add_parser("create-fixture")
    p_create.add_argument("--layout-dir", required=True)
    p_create.add_argument("--manifest-path", required=True)
    p_create.add_argument("--event-count", type=int, default=10000)

    p_verify = sub.add_parser("verify-fixture")
    p_verify.add_argument("--layout-dir", required=True)
    p_verify.add_argument("--manifest-path", required=True)
    p_verify.add_argument("--report-path", required=False)

    p_linux = sub.add_parser("linux-suite")
    p_linux.add_argument("--repo-root", required=True)
    p_linux.add_argument("--windows-fixture-dir", required=True)
    p_linux.add_argument("--windows-fixture-manifest", required=True)
    p_linux.add_argument("--linux-fixture-dir", required=True)
    p_linux.add_argument("--linux-fixture-manifest", required=True)
    p_linux.add_argument("--report-path", required=True)
    p_linux.add_argument("--event-count", type=int, default=100000)
    p_linux.add_argument("--core-event-count", type=int, default=1000)
    p_linux.add_argument("--timeout-seconds", type=int, default=600)

    args = ap.parse_args()
    if args.mode == "create-fixture":
        return create_fixture(Path(args.layout_dir), Path(args.manifest_path), args.event_count)
    if args.mode == "verify-fixture":
        ok, result = verify_fixture(Path(args.layout_dir), Path(args.manifest_path))
        if args.report_path:
            Path(args.report_path).write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        print(PASS_FIXTURE if ok else NO_GO)
        print("SUMMARY=" + json.dumps(result["checks"], sort_keys=True))
        return 0 if ok else 2
    if args.mode == "linux-suite":
        return linux_suite(args)
    raise AssertionError(args.mode)


if __name__ == "__main__":
    raise SystemExit(main())
