#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ultraballoondb_core.csr_mmap_hotpath import CsrMmapHotGraph


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def files_identical(left: Path, right: Path) -> bool:
    if left.stat().st_size != right.stat().st_size:
        return False
    with left.open("rb") as a, right.open("rb") as b:
        while True:
            ca = a.read(1024 * 1024)
            cb = b.read(1024 * 1024)
            if ca != cb:
                return False
            if not ca:
                return True


def wave_signature(rows: Any) -> list[list[Any]]:
    return [
        [int(row.node_id), round(float(row.energy), 12), int(row.predecessor), int(row.edge_type)]
        for row in rows
    ]


def percentile_ms(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = round((len(ordered) - 1) * q)
    return ordered[index] * 1000.0


def run(command: list[str], *, cwd: Path | None = None, timeout: int = 1800) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    print(proc.stdout, end="")
    if proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(command)}")
    return proc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--event-count", type=int, default=1_000_000)
    parser.add_argument("--query-samples", type=int, default=5_000)
    parser.add_argument("--top-k", type=int, default=64)
    parser.add_argument("--max-steps", type=int, default=2)
    parser.add_argument("--energy-threshold", type=float, default=0.10)
    parser.add_argument("--min-query-speedup", type=float, default=1.25)
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    args = parser.parse_args()

    repo = Path(args.repo_root).resolve()
    crate = repo / "rust_native" / "ultraballoondb_rust_core"
    cargo = shutil.which("cargo")
    if not cargo:
        print("NO_GO_ULTRABALLOONDB_V00R1_CARGO_NOT_FOUND")
        print("INSTALL_WINDOWS=winget install --exact --id Rustlang.Rustup")
        print("INSTALL_LINUX=curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh")
        return 3

    audit = repo / "audit" / "v00r1_rust_native_csr_mmap_wave_core" / time.strftime("RUN_%Y%m%d_%H%M%S")
    py_layout = audit / "python_layout"
    rust_layout = audit / "rust_layout"
    rust_bench_layout = audit / "rust_bench_layout"
    audit.mkdir(parents=True, exist_ok=True)

    cargo_version = run([cargo, "--version"], timeout=args.timeout_seconds).stdout.strip()
    rustc = shutil.which("rustc") or "rustc"
    rustc_version = run([rustc, "--version"], timeout=args.timeout_seconds).stdout.strip()

    compile_started = time.perf_counter()
    run([cargo, "build", "--release", "--locked"], cwd=crate, timeout=args.timeout_seconds)
    compile_seconds = time.perf_counter() - compile_started

    binary = crate / "target" / "release" / ("ultraballoondb_rust_core.exe" if os.name == "nt" else "ultraballoondb_rust_core")
    if not binary.exists():
        raise FileNotFoundError(binary)

    py_build_started = time.perf_counter()
    py_graph = CsrMmapHotGraph.build_synthetic(py_layout, args.event_count)
    python_build_seconds = time.perf_counter() - py_build_started

    rust_build_json = audit / "rust_build.json"
    run(
        [
            str(binary),
            "build-synthetic",
            "--layout-dir",
            str(rust_layout),
            "--event-count",
            str(args.event_count),
            "--output",
            str(rust_build_json),
        ],
        timeout=args.timeout_seconds,
    )
    rust_build = json.loads(rust_build_json.read_text(encoding="utf-8"))

    python_nodes_sha = sha256_file(py_layout / "csr_nodes.bin")
    python_edges_sha = sha256_file(py_layout / "csr_edges.bin")
    rust_nodes_sha = sha256_file(rust_layout / "csr_nodes.bin")
    rust_edges_sha = sha256_file(rust_layout / "csr_edges.bin")
    node_bytes_identical = files_identical(py_layout / "csr_nodes.bin", rust_layout / "csr_nodes.bin")
    edge_bytes_identical = files_identical(py_layout / "csr_edges.bin", rust_layout / "csr_edges.bin")

    seeds = sorted({1, max(1, args.event_count // 2), args.event_count})
    py_wave = py_graph.wave_activation(
        seeds,
        max_steps=args.max_steps,
        energy_threshold=args.energy_threshold,
        top_k=args.top_k,
    )
    selected = [row.node_id for row in py_wave[:128]]
    py_subgraph = py_graph.export_subgraph(selected)
    python_wave_signature = wave_signature(py_wave)
    python_subgraph_nodes = list(py_subgraph.nodes)
    python_subgraph_edges = [list(edge) for edge in py_subgraph.edges]

    rust_query_json = audit / "rust_query.json"
    run(
        [
            str(binary),
            "query",
            "--layout-dir",
            str(rust_layout),
            "--seeds",
            ",".join(map(str, seeds)),
            "--max-steps",
            str(args.max_steps),
            "--top-k",
            str(args.top_k),
            "--energy-threshold",
            str(args.energy_threshold),
            "--export-limit",
            "128",
            "--output",
            str(rust_query_json),
        ],
        timeout=args.timeout_seconds,
    )
    rust_query = json.loads(rust_query_json.read_text(encoding="utf-8"))
    rust_wave_signature = [
        [int(row["node_id"]), round(float(row["energy"]), 12), int(row["predecessor"]), int(row["edge_type"])]
        for row in rust_query["wave"]
    ]
    rust_subgraph_nodes = [int(v) for v in rust_query["subgraph"]["nodes"]]
    rust_subgraph_edges = [[int(x) for x in edge] for edge in rust_query["subgraph"]["edges"]]

    wave_parity = rust_wave_signature == python_wave_signature
    subgraph_parity = (
        rust_subgraph_nodes == python_subgraph_nodes
        and rust_subgraph_edges == python_subgraph_edges
    )

    query_durations: list[float] = []
    python_rows = 0
    python_batch_started = time.perf_counter()
    for index in range(args.query_samples):
        seed = (index % args.event_count) + 1
        started = time.perf_counter()
        rows = py_graph.wave_activation(
            [seed],
            max_steps=args.max_steps,
            energy_threshold=args.energy_threshold,
            top_k=args.top_k,
        )
        query_durations.append(time.perf_counter() - started)
        python_rows += len(rows)
    python_batch_seconds = time.perf_counter() - python_batch_started
    python_counters = {
        "slice_lookups": py_graph.slice_lookup_counter,
        "node_rows_read": py_graph.node_rows_read_counter,
        "edge_records_read": py_graph.edge_records_read_counter,
        "full_scan_counter": py_graph.full_scan_counter,
    }
    py_graph.close()

    rust_bench_json = audit / "rust_bench.json"
    run(
        [
            str(binary),
            "bench",
            "--layout-dir",
            str(rust_bench_layout),
            "--event-count",
            str(args.event_count),
            "--query-samples",
            str(args.query_samples),
            "--max-steps",
            str(args.max_steps),
            "--top-k",
            str(args.top_k),
            "--energy-threshold",
            str(args.energy_threshold),
            "--output",
            str(rust_bench_json),
        ],
        timeout=args.timeout_seconds,
    )
    rust_bench = json.loads(rust_bench_json.read_text(encoding="utf-8"))

    rust_batch_seconds = float(rust_bench["batch_query_seconds"])
    query_speedup = python_batch_seconds / max(rust_batch_seconds, 1e-12)
    diagnostic_build_speedup = python_build_seconds / max(float(rust_build["build_seconds"]), 1e-12)

    technical_pass = all(
        [
            node_bytes_identical,
            edge_bytes_identical,
            python_nodes_sha == rust_nodes_sha,
            python_edges_sha == rust_edges_sha,
            wave_parity,
            subgraph_parity,
            bool(rust_query["mmap_active"]),
            int(rust_query["full_scan_counter"]) == 0,
            int(rust_bench["full_scan_counter"]) == 0,
            int(rust_bench["third_party_rust_crates"]) == 0,
            python_counters["full_scan_counter"] == 0,
        ]
    )
    promotion_ready = technical_pass and query_speedup >= args.min_query_speedup

    summary = {
        "milestone": "V00R1_RUST_NATIVE_CSR_MMAP_WAVE_CORE_CANDIDATE",
        "event_count": args.event_count,
        "edge_count": args.event_count * 3,
        "query_samples": args.query_samples,
        "cargo_version": cargo_version,
        "rustc_version": rustc_version,
        "compile_seconds": compile_seconds,
        "third_party_rust_crates": 0,
        "python_runtime_required_by_rust_binary": False,
        "node_bytes_identical": node_bytes_identical,
        "edge_bytes_identical": edge_bytes_identical,
        "python_nodes_sha256": python_nodes_sha,
        "rust_nodes_sha256": rust_nodes_sha,
        "python_edges_sha256": python_edges_sha,
        "rust_edges_sha256": rust_edges_sha,
        "wave_parity": wave_parity,
        "subgraph_parity": subgraph_parity,
        "rust_mmap_active": bool(rust_query["mmap_active"]),
        "rust_full_scan_counter": int(rust_bench["full_scan_counter"]),
        "python_full_scan_counter": python_counters["full_scan_counter"],
        "python_build_seconds": python_build_seconds,
        "rust_build_seconds": float(rust_build["build_seconds"]),
        "diagnostic_build_speedup": diagnostic_build_speedup,
        "python_batch_query_seconds": python_batch_seconds,
        "rust_batch_query_seconds": rust_batch_seconds,
        "query_speedup": query_speedup,
        "minimum_query_speedup_gate": args.min_query_speedup,
        "python_queries_per_second": args.query_samples / max(python_batch_seconds, 1e-12),
        "rust_queries_per_second": float(rust_bench["queries_per_second"]),
        "python_query_p50_us": percentile_ms(query_durations, 0.50) * 1000.0,
        "python_query_p95_us": percentile_ms(query_durations, 0.95) * 1000.0,
        "python_query_p99_us": percentile_ms(query_durations, 0.99) * 1000.0,
        "rust_query_p50_us": float(rust_bench["query_p50_us"]),
        "rust_query_p95_us": float(rust_bench["query_p95_us"]),
        "rust_query_p99_us": float(rust_bench["query_p99_us"]),
        "python_wave_rows": python_rows,
        "rust_wave_rows": int(rust_bench["wave_rows"]),
        "technical_parity_pass": technical_pass,
        "active_promotion_ready": promotion_ready,
        "runtime_replaced": False,
        "python_hotpath_removed": False,
        "next_gate": (
            "V00R2_RUST_NATIVE_RUNTIME_BINDING" if promotion_ready
            else "KEEP_PYTHON_ACTIVE_REVIEW_RUST_PROFILE"
        ),
    }

    report = audit / "rust_native_csr_mmap_wave_core_candidate_report.json"
    report.write_text(
        json.dumps({"pass": technical_pass, "summary": summary}, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    print(
        "PASS_ULTRABALLOONDB_V00R1_RUST_NATIVE_CSR_MMAP_WAVE_CORE_CANDIDATE"
        if technical_pass
        else "NO_GO_ULTRABALLOONDB_V00R1_RUST_NATIVE_CSR_MMAP_WAVE_CORE_CANDIDATE"
    )
    print(f"REPORT={report}")
    print("SUMMARY=" + json.dumps(summary, sort_keys=True))
    print(f"ACTIVE_PROMOTION_READY={str(promotion_ready).upper()}")
    return 0 if technical_pass else 2


if __name__ == "__main__":
    raise SystemExit(main())
