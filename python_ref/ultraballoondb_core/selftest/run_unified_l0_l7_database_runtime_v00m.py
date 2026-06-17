#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Dict

HERE = Path(__file__).resolve()
CORE_ROOT = HERE.parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from ultraballoondb_core.floating_subgraph import decode_stream
from ultraballoondb_core.hot_snapshot import archive_paths, sha256_file, snapshot_paths
from ultraballoondb_core.unified_runtime import UnifiedDatabaseRuntime

VERSION = "V00M_UNIFIED_L0_L7_DATABASE_RUNTIME"
PASS_LINE = "PASS_ULTRABALLOONDB_UNIFIED_L0_L7_DATABASE_RUNTIME_V00M"
NO_GO_LINE = "NO_GO_ULTRABALLOONDB_UNIFIED_L0_L7_DATABASE_RUNTIME_V00M"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--event-count", type=int, default=10000)
    ap.add_argument("--seed-queries", type=int, default=16)
    ap.add_argument("--top-k-per-seed", type=int, default=8)
    ap.add_argument("--max-steps", type=int, default=2)
    ap.add_argument("--energy-threshold", type=float, default=0.10)
    ap.add_argument("--payload-top-k", type=int, default=16)
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    if not repo_root.exists():
        print(f"{NO_GO_LINE}: repo root missing")
        return 1
    if args.event_count < 64 or args.seed_queries < 1 or args.payload_top_k < 1:
        print(f"{NO_GO_LINE}: invalid parameters")
        return 1

    run_id = time.strftime("RUN_%Y%m%d_%H%M%S")
    run_dir = repo_root / "audit" / "v00m_unified_l0_l7_database_runtime" / run_id
    database_root = run_dir / "database"
    run_dir.mkdir(parents=True, exist_ok=True)

    tracemalloc.start()
    started = time.perf_counter()

    runtime = UnifiedDatabaseRuntime(database_root)
    create_manifest = runtime.create(args.event_count)
    status_a = runtime.open()

    apaths = archive_paths(database_root / "archive")
    spaths = snapshot_paths(database_root / "hot_snapshot")
    static_hashes_before = {
        "records": sha256_file(apaths.records_path),
        "payloads": sha256_file(apaths.payloads_path),
        "edges": sha256_file(spaths.edges_path),
        "crystals": sha256_file(spaths.crystals_path),
    }

    seed_event_ids = tuple(range(min(args.seed_queries, args.event_count)))
    query_a = runtime.wave_query(
        seed_event_ids,
        energy_threshold=args.energy_threshold,
        top_k_per_seed=args.top_k_per_seed,
        max_steps=args.max_steps,
    )
    fetch_a = runtime.fetch_payloads_for_wave(query_a, max_records=args.payload_top_k)
    stream_a = runtime.export_wave_subgraph(query_a)
    content_a = decode_stream(stream_a)
    import_a = runtime.import_wave_subgraph(stream_a)
    import_duplicate = runtime.import_wave_subgraph(stream_a)

    exact_record = runtime.get_event_record(0)
    payload_verified = runtime.verify_event_payload(0)
    runtime.close()

    reopened = UnifiedDatabaseRuntime(database_root)
    status_b = reopened.open()
    query_b = reopened.wave_query(
        seed_event_ids,
        energy_threshold=args.energy_threshold,
        top_k_per_seed=args.top_k_per_seed,
        max_steps=args.max_steps,
    )
    fetch_b = reopened.fetch_payloads_for_wave(query_b, max_records=args.payload_top_k)
    stream_b = reopened.export_wave_subgraph(query_b)

    static_hashes_after = {
        "records": sha256_file(apaths.records_path),
        "payloads": sha256_file(apaths.payloads_path),
        "edges": sha256_file(spaths.edges_path),
        "crystals": sha256_file(spaths.crystals_path),
    }

    relation_known_count = sum(
        1 for d in query_a.relation_derivations
        if not d.blocked and d.result_relation not in ("UNKNOWN_PATH", "EMPTY_PATH")
    )
    path_evidence_count = sum(1 for row in query_a.rows if row.result.path_edge_types)
    all_layers = set(status_a.get("layers_ready", []))
    expected_layers = {f"L{i}" for i in range(8)}

    checks = {
        "one_runtime_opened_all_layers": all_layers == expected_layers,
        "l0_archive_exists": apaths.records_path.exists() and apaths.payloads_path.exists(),
        "l1_exact_event_lookup": int(exact_record.event_id) == 0,
        "l1_node_index_present": int(status_a["exact_index_node_count"]) > 0,
        "l2_typed_graph_loaded": int(status_a["typed_edge_count"]) == args.event_count * 3,
        "l3_wave_rows_present": len(query_a.rows) > len(seed_event_ids),
        "l3_path_evidence_present": path_evidence_count > 0,
        "l2_relation_algebra_bound": relation_known_count > 0,
        "l4_hot_snapshot_loaded": len(str(status_a["hot_snapshot_sha256"])) == 64,
        "l5_coalesced_payload_fetch": len(fetch_a.result.payloads) > 0 and fetch_a.planned_span_count > 0,
        "l5_payload_integrity": payload_verified and fetch_a.digest == fetch_b.digest,
        "l6_crystallization_present": int(status_a["crystal_count"]) > 0,
        "l7_floating_subgraph_has_nodes": len(content_a["nodes"]) > 0,
        "l7_floating_subgraph_has_edges": len(content_a["edges"]) > 0,
        "l7_import_succeeded": import_a.get("status") == "IMPORTED",
        "l7_duplicate_import_idempotent": import_duplicate.get("status") == "ALREADY_IMPORTED",
        "restart_reopen_succeeded": bool(status_b.get("opened")),
        "restart_wave_deterministic": query_a.rows == query_b.rows,
        "restart_stream_deterministic": stream_a == stream_b,
        "canonical_files_unchanged": static_hashes_before == static_hashes_after,
        "runtime_manifest_disallows_l2_l3_replacement": not bool(create_manifest["compression_replaces_l2_l3"]),
        "no_durable_mutation_claim": not bool(create_manifest["durable_mutation_wal_included"]),
    }

    failures = {name: "check failed" for name, ok in checks.items() if not ok}
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    status = PASS_LINE if not failures else NO_GO_LINE

    report: Dict[str, object] = {
        "version": VERSION,
        "status": status,
        "repo_root": str(repo_root),
        "run_dir": str(run_dir),
        "database_root": str(database_root),
        "elapsed_seconds": time.perf_counter() - started,
        "memory_current_bytes": current,
        "memory_peak_bytes": peak,
        "params": vars(args),
        "alignment": {
            "role": "CORE",
            "touches_core_layers": ["L0", "L1", "L2", "L3", "L4", "L5", "L6", "L7"],
            "uses_auxiliary_layers": [],
            "must_preserve": ["L2_TYPED_EDGE_GRAPH", "L3_WAVE_ACTIVATION"],
            "runtime_impact": "UNIFIED_REFERENCE_RUNTIME",
            "roadmap_status": "ALIGNED",
        },
        "create_manifest": create_manifest,
        "status_first_open": status_a,
        "status_reopen": status_b,
        "runtime_summary": {
            "wave_rows": len(query_a.rows),
            "path_evidence": path_evidence_count,
            "known_relation_derivations": relation_known_count,
            "payload_count": len(fetch_a.result.payloads),
            "payload_physical_reads": fetch_a.result.physical_read_count,
            "payload_digest": fetch_a.digest,
            "floating_nodes": len(content_a["nodes"]),
            "floating_edges": len(content_a["edges"]),
            "floating_stream_bytes": len(stream_a),
            "crystal_count": int(status_a["crystal_count"]),
            "typed_edge_count": int(status_a["typed_edge_count"]),
            "restart_deterministic": query_a.rows == query_b.rows and stream_a == stream_b,
        },
        "checks": checks,
        "failures": failures,
    }
    report_path = run_dir / "unified_l0_l7_database_runtime_report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    summary = {
        "event_count": args.event_count,
        "typed_edges": int(status_a["typed_edge_count"]),
        "exact_index_nodes": int(status_a["exact_index_node_count"]),
        "wave_rows": len(query_a.rows),
        "path_evidence": path_evidence_count,
        "relation_derivations": relation_known_count,
        "payloads": len(fetch_a.result.payloads),
        "physical_reads": fetch_a.result.physical_read_count,
        "crystals": int(status_a["crystal_count"]),
        "floating_nodes": len(content_a["nodes"]),
        "floating_edges": len(content_a["edges"]),
        "restart_deterministic": query_a.rows == query_b.rows and stream_a == stream_b,
        "canonical_unchanged": static_hashes_before == static_hashes_after,
    }
    print(status)
    print(f"REPORT={report_path}")
    print("SUMMARY=" + json.dumps(summary, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
