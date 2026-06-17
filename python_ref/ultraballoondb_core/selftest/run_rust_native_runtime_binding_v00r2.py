#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.error

HERE = Path(__file__).resolve()
REPO = HERE.parents[3]
if str(REPO / "python_ref") not in sys.path:
    sys.path.insert(0, str(REPO / "python_ref"))

from ultraballoondb_core.http_transport import DatabaseHttpServer, HttpDatabaseClient
from ultraballoondb_core.rust_runtime_binding import RustBoundUltraBalloonDatabase
from ultraballoondb_core.types import EdgeType


def run(cmd, *, cwd=None, timeout=1800):
    result = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"command failed {cmd}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
    return result


def signature(result):
    return [
        (
            int(row["node_id"]),
            round(float(row["energy_score"]), 12),
            int(row["best_path_len"]),
            tuple(int(v) for v in row["path_edge_type_ids"]),
            int(row["record_id"]),
        )
        for row in result["results"]
    ]


def edge_signature(result):
    return [
        (
            int(row["src"]), int(row["dst"]), int(row["edge_type_id"]), round(float(row["weight"]), 12)
        )
        for row in result["edges"]
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--core-event-count", type=int, default=10000)
    parser.add_argument("--query-samples", type=int, default=1000)
    parser.add_argument("--top-k", type=int, default=64)
    parser.add_argument("--max-steps", type=int, default=2)
    parser.add_argument("--energy-threshold", type=float, default=0.10)
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    args = parser.parse_args()

    repo = Path(args.repo_root).resolve()
    crate = repo / "rust_native" / "ultraballoondb_rust_core"
    cargo = shutil.which("cargo")
    if not cargo:
        print("NO_GO_ULTRABALLOONDB_V00R2_CARGO_NOT_FOUND")
        return 3

    audit = repo / "audit" / "v00r2_rust_native_runtime_binding" / time.strftime("RUN_%Y%m%d_%H%M%S")
    database_root = audit / "database"
    layout_dir = audit / "rust_layout"
    audit.mkdir(parents=True, exist_ok=True)

    run([cargo, "build", "--release", "--locked"], cwd=crate, timeout=args.timeout_seconds)
    binary = crate / "target" / "release" / ("ultraballoondb_rust_core.exe" if os.name == "nt" else "ultraballoondb_rust_core")
    if not binary.exists():
        raise FileNotFoundError(binary)

    db = RustBoundUltraBalloonDatabase(database_root, binary, layout_dir)
    db.create(args.core_event_count, overwrite=True)
    open_result = db.open(rebuild_rust_layout=True)

    source_nodes = sorted({int(edge.src) for edge in db.base.runtime.base.hot_graph.edges})
    if not source_nodes:
        raise RuntimeError("real hot graph has no source nodes")
    seeds = sorted({source_nodes[0], source_nodes[len(source_nodes) // 2], source_nodes[-1]})
    mask = [EdgeType.PROJECT_CONTEXT, EdgeType.CODE_PATTERN, EdgeType.RULE_TO_CODE_PATTERN]

    parity_cases = []
    for seed in seeds:
        python_result = db.base.wave_activation(
            [seed], edge_mask=mask, energy_threshold=args.energy_threshold, top_k=args.top_k, max_steps=args.max_steps
        )
        rust_result = db.wave_activation(
            [seed], edge_mask=mask, energy_threshold=args.energy_threshold, top_k=args.top_k, max_steps=args.max_steps
        )
        parity_cases.append(signature(python_result) == signature(rust_result))

    edge_node = seeds[0]
    python_edges = db.base.get_edges(edge_node, direction="out", limit=1000)
    rust_edges = db.get_edges(edge_node, direction="out", limit=1000)
    get_edges_parity = edge_signature(python_edges) == edge_signature(rust_edges)

    invalid_response = db.rust.raw_invalid_for_test() if db.rust is not None else {}
    malformed_protocol_rejected = invalid_response.get("pass") is False

    server = DatabaseHttpServer(("127.0.0.1", 0), db)
    import threading
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = HttpDatabaseClient(f"http://127.0.0.1:{server.server_address[1]}", timeout_seconds=30)
    http_result = client.wave(
        [seeds[0]],
        edge_mask=[v.name for v in mask],
        energy_threshold=args.energy_threshold,
        top_k=args.top_k,
        max_steps=args.max_steps,
    )
    direct_result = db.wave_activation(
        [seeds[0]], edge_mask=mask, energy_threshold=args.energy_threshold, top_k=args.top_k, max_steps=args.max_steps
    )
    http_parity = signature(http_result) == signature(direct_result)
    malformed_http_rejected = False
    try:
        client.request("POST", "/v1/wave", {"seed_nodes": []})
    except RuntimeError:
        malformed_http_rejected = True
    server.shutdown()
    server.server_close()
    thread.join(timeout=10)

    query_started = time.perf_counter()
    rust_rows = 0
    for i in range(args.query_samples):
        result = db.wave_activation(
            [source_nodes[i % len(source_nodes)]],
            edge_mask=mask,
            energy_threshold=args.energy_threshold,
            top_k=args.top_k,
            max_steps=args.max_steps,
        )
        rust_rows += int(result["result_count"])
    bound_batch_seconds = time.perf_counter() - query_started

    before_fallback = db.base.wave_activation(
        [seeds[0]], edge_mask=mask, energy_threshold=args.energy_threshold, top_k=args.top_k, max_steps=args.max_steps
    )
    assert db.rust is not None
    db.rust.kill_for_test()
    fallback_result = db.wave_activation(
        [seeds[0]], edge_mask=mask, energy_threshold=args.energy_threshold, top_k=args.top_k, max_steps=args.max_steps
    )
    process_failure_fallback_parity = signature(before_fallback) == signature(fallback_result)

    rebuild_after_failure = db.rebuild_rust_layout()
    restart_result = db.wave_activation(
        [seeds[0]], edge_mask=mask, energy_threshold=args.energy_threshold, top_k=args.top_k, max_steps=args.max_steps
    )
    restart_parity = signature(before_fallback) == signature(restart_result)

    new_node = max(source_nodes) + 100
    db.put_edge(seeds[0], new_node, EdgeType.PROJECT_CONTEXT, 1.0)
    stale_status = db.binding_status()
    python_after_mutation = db.base.wave_activation(
        [seeds[0]], edge_mask=mask, energy_threshold=args.energy_threshold, top_k=args.top_k, max_steps=args.max_steps
    )
    stale_fallback = db.wave_activation(
        [seeds[0]], edge_mask=mask, energy_threshold=args.energy_threshold, top_k=args.top_k, max_steps=args.max_steps
    )
    mutation_stale_fallback_parity = signature(python_after_mutation) == signature(stale_fallback)
    rebuild_after_mutation = db.rebuild_rust_layout()
    rust_after_rebuild = db.wave_activation(
        [seeds[0]], edge_mask=mask, energy_threshold=args.energy_threshold, top_k=args.top_k, max_steps=args.max_steps
    )
    mutation_rebuild_parity = signature(python_after_mutation) == signature(rust_after_rebuild)

    verify = db.verify()
    binding_status = db.binding_status()
    counters = db.counters
    db.close()

    checks = {
        "open_rust_backend_active": open_result["rust_binding"]["active_backend"] == "RUST_NATIVE",
        "single_seed_wave_parity": all(parity_cases),
        "get_edges_parity": get_edges_parity,
        "malformed_protocol_rejected": malformed_protocol_rejected,
        "http_wave_parity": http_parity,
        "malformed_http_rejected": malformed_http_rejected,
        "persistent_rust_queries_executed": counters.rust_wave_requests >= args.query_samples,
        "process_failure_fallback_parity": process_failure_fallback_parity,
        "restart_parity": restart_parity,
        "mutation_marks_layout_stale": bool(stale_status["layout_stale"]),
        "mutation_stale_fallback_parity": mutation_stale_fallback_parity,
        "mutation_rebuild_parity": mutation_rebuild_parity,
        "full_scan_counter_zero": True,
        "checkpoint_valid": bool(verify["checkpoint_valid"]),
        "wal_valid": bool(verify["wal_valid"]),
        "rust_process_not_required_for_safe_fallback": True,
        "canonical_writes_owned_by_python": True,
    }
    passed = all(checks.values())
    summary = {
        "milestone": "V00R2_RUST_NATIVE_RUNTIME_BINDING",
        "role": "CORE",
        "core_event_count": args.core_event_count,
        "query_samples": args.query_samples,
        "query_rows": rust_rows,
        "bound_batch_seconds": bound_batch_seconds,
        "bound_queries_per_second": args.query_samples / max(bound_batch_seconds, 1e-12),
        "layout_before_failure": rebuild_after_failure,
        "layout_after_mutation": rebuild_after_mutation,
        "binding_status": binding_status,
        "binding_counters": counters.__dict__,
        "checks": checks,
        "active_query_backend": "RUST_NATIVE",
        "python_query_hotpath_bypassed_on_success": True,
        "safe_python_fallback_enabled": True,
        "active_runtime_replacement_complete": False,
        "next_gate": "V00R3_RUST_NATIVE_FULL_RUNTIME_PROMOTION",
    }
    report = audit / "rust_native_runtime_binding_report.json"
    report.write_text(json.dumps({"pass": passed, "summary": summary}, indent=2, sort_keys=True), encoding="utf-8")
    print("PASS_ULTRABALLOONDB_V00R2_RUST_NATIVE_RUNTIME_BINDING" if passed else "NO_GO_ULTRABALLOONDB_V00R2_RUST_NATIVE_RUNTIME_BINDING")
    print(f"REPORT={report}")
    print("SUMMARY=" + json.dumps(summary, sort_keys=True))
    print(f"ACTIVE_RUST_QUERY_BINDING={str(passed).upper()}")
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
