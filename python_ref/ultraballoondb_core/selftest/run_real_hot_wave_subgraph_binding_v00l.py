#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Dict, List

HERE = Path(__file__).resolve()
CORE_ROOT = HERE.parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from ultraballoondb_core.floating_subgraph import (
    FloatingSubgraphError,
    SyntheticHotSnapshot,
    decode_stream,
    hot_patch_subgraph,
    target_patch_fingerprint,
    verify_stream,
)
from ultraballoondb_core.hot_snapshot import (
    build_hot_snapshot_from_archive,
    sha256_file,
    snapshot_paths,
    write_lossless_archive,
)
from ultraballoondb_core.hot_wave_subgraph_binding import (
    export_wave_rows_as_floating_subgraph,
    load_real_hot_wave_graph,
    run_seed_waves,
    stream_sha256,
)
from ultraballoondb_core.types import EdgeType

VERSION = "V00L_REAL_HOT_WAVE_SUBGRAPH_BINDING"
PASS_LINE = "PASS_ULTRABALLOONDB_REAL_HOT_WAVE_SUBGRAPH_BINDING_V00L"
NO_GO_LINE = "NO_GO_ULTRABALLOONDB_REAL_HOT_WAVE_SUBGRAPH_BINDING_V00L"


def _tamper(stream: bytes) -> bytes:
    obj = json.loads(stream.decode("utf-8"))
    obj["content"]["nodes"][0]["best_energy"] = 0.123456789
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _rejects_tamper(stream: bytes) -> bool:
    try:
        decode_stream(_tamper(stream))
    except FloatingSubgraphError:
        return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--event-count", type=int, default=10000)
    ap.add_argument("--seed-queries", type=int, default=16)
    ap.add_argument("--top-k-per-seed", type=int, default=8)
    ap.add_argument("--max-steps", type=int, default=2)
    ap.add_argument("--energy-threshold", type=float, default=0.10)
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    if not repo_root.exists():
        print(f"{NO_GO_LINE}: repo root missing")
        return 1
    if args.event_count < 64 or args.seed_queries < 1 or args.top_k_per_seed < 1:
        print(f"{NO_GO_LINE}: invalid parameters")
        return 1

    run_id = time.strftime("RUN_%Y%m%d_%H%M%S")
    run_dir = repo_root / "audit" / "v00l_real_hot_wave_subgraph_binding" / run_id
    archive_dir = run_dir / "archive"
    snapshot_dir = run_dir / "hot_snapshot"
    run_dir.mkdir(parents=True, exist_ok=True)

    tracemalloc.start()
    started = time.perf_counter()

    archive_manifest = write_lossless_archive(args.event_count, archive_dir)
    snapshot_manifest = build_hot_snapshot_from_archive(archive_dir, snapshot_dir)
    sp = snapshot_paths(snapshot_dir)
    archive_hashes_before = {
        "records": sha256_file(archive_dir / "lossless_records.bin"),
        "payloads": sha256_file(archive_dir / "payload_store.bin"),
    }
    snapshot_hashes_before = {
        "edges": sha256_file(sp.edges_path),
        "crystals": sha256_file(sp.crystals_path),
    }

    loaded = load_real_hot_wave_graph(snapshot_dir)
    seed_nodes = [1_000_000_000 + i for i in range(min(args.seed_queries, args.event_count))]
    wave_rows, wave_stats = run_seed_waves(
        loaded,
        seed_nodes,
        edge_mask=(EdgeType.PROJECT_CONTEXT, EdgeType.CODE_PATTERN, EdgeType.RULE_TO_CODE_PATTERN),
        energy_threshold=args.energy_threshold,
        top_k_per_seed=args.top_k_per_seed,
        max_steps=args.max_steps,
    )
    export_params = {
        "seed_nodes": seed_nodes,
        "top_k_per_seed": args.top_k_per_seed,
        "max_steps": args.max_steps,
        "energy_threshold": args.energy_threshold,
        "edge_mask": ["PROJECT_CONTEXT", "CODE_PATTERN", "RULE_TO_CODE_PATTERN"],
    }
    stream_a = export_wave_rows_as_floating_subgraph(
        loaded,
        wave_rows,
        export_params=export_params,
        wave_stats=wave_stats,
    )
    stream_b = export_wave_rows_as_floating_subgraph(
        loaded,
        wave_rows,
        export_params=export_params,
        wave_stats=wave_stats,
    )
    verified_stream_hash = verify_stream(stream_a)
    content = decode_stream(stream_a)

    target = SyntheticHotSnapshot(logical_event_count=10_000_000_000)
    import_receipt = hot_patch_subgraph(target, stream_a)
    fingerprint_after_first = target_patch_fingerprint(target)
    duplicate_receipt = hot_patch_subgraph(target, stream_a)
    fingerprint_after_duplicate = target_patch_fingerprint(target)

    archive_hashes_after = {
        "records": sha256_file(archive_dir / "lossless_records.bin"),
        "payloads": sha256_file(archive_dir / "payload_store.bin"),
    }
    snapshot_hashes_after = {
        "edges": sha256_file(sp.edges_path),
        "crystals": sha256_file(sp.crystals_path),
    }

    unique_nodes = {int(row.result.node_id) for row in wave_rows}
    path_evidence_count = sum(1 for row in wave_rows if row.result.path_edge_types)
    checks = {
        "real_hot_snapshot_edge_count_matches": len(loaded.edges) == int(snapshot_manifest["edge_count"]),
        "typed_edge_graph_loaded": loaded.graph.edge_count == int(snapshot_manifest["edge_count"]),
        "wave_activation_returned_rows": len(wave_rows) > 0,
        "wave_selected_more_than_seed_roots": len(unique_nodes) > len(seed_nodes),
        "wave_path_evidence_present": path_evidence_count > 0,
        "floating_export_deterministic": stream_a == stream_b,
        "floating_stream_hash_verified": verified_stream_hash == stream_sha256(stream_a),
        "floating_stream_has_edges": len(content["edges"]) > 0,
        "floating_stream_has_exact_pointers": all("record_pointer" in node for node in content["nodes"]),
        "hot_import_succeeded": import_receipt.get("status") == "IMPORTED",
        "duplicate_import_idempotent": duplicate_receipt.get("status") == "ALREADY_IMPORTED",
        "duplicate_import_did_not_change_target": fingerprint_after_first == fingerprint_after_duplicate,
        "tamper_rejected": _rejects_tamper(stream_a),
        "archive_unchanged": archive_hashes_before == archive_hashes_after,
        "hot_snapshot_unchanged": snapshot_hashes_before == snapshot_hashes_after,
        "payload_bytes_not_exported": content.get("payload_policy") == "POINTERS_ONLY_NO_PAYLOAD_BYTES",
        "l2_typed_graph_preserved": bool(content["core_binding"]["L2_typed_edge_graph"]),
        "l3_wave_activation_preserved": bool(content["core_binding"]["L3_wave_activation"]),
        "compression_did_not_replace_l2_l3": not bool(content["core_binding"]["compression_replaces_graph_or_wave"]),
        "no_agent_policy": content.get("agent_policy") == "NO_AGENT_POLICY_NO_LLM_NO_SEMANTIC_INTERPRETATION",
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
        "elapsed_seconds": time.perf_counter() - started,
        "memory_current_bytes": current,
        "memory_peak_bytes": peak,
        "params": vars(args),
        "alignment": {
            "role": "CORE",
            "touches_core_layers": ["L1", "L2", "L3", "L4", "L7"],
            "uses_auxiliary_layers": [],
            "must_preserve": ["L2_TYPED_EDGE_GRAPH", "L3_WAVE_ACTIVATION"],
            "runtime_impact": "REFERENCE_CORE_BINDING",
            "roadmap_status": "ALIGNED",
        },
        "archive": archive_manifest,
        "snapshot": snapshot_manifest,
        "binding": {
            "loaded_edge_count": len(loaded.edges),
            "seed_query_count": len(seed_nodes),
            "wave_row_count": len(wave_rows),
            "unique_wave_node_count": len(unique_nodes),
            "path_evidence_count": path_evidence_count,
            "floating_stream_bytes": len(stream_a),
            "floating_stream_sha256": verified_stream_hash,
            "floating_node_count": len(content["nodes"]),
            "floating_edge_count": len(content["edges"]),
            "import_receipt": import_receipt,
            "duplicate_receipt": duplicate_receipt,
        },
        "checks": checks,
        "failures": failures,
    }
    report_path = run_dir / "real_hot_wave_subgraph_binding_report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    summary = {
        "loaded_edges": len(loaded.edges),
        "seed_queries": len(seed_nodes),
        "wave_rows": len(wave_rows),
        "unique_nodes": len(unique_nodes),
        "path_evidence": path_evidence_count,
        "floating_nodes": len(content["nodes"]),
        "floating_edges": len(content["edges"]),
        "stream_bytes": len(stream_a),
        "deterministic": stream_a == stream_b,
        "imported": import_receipt.get("status") == "IMPORTED",
        "duplicate_idempotent": duplicate_receipt.get("status") == "ALREADY_IMPORTED",
        "archive_unchanged": archive_hashes_before == archive_hashes_after,
        "snapshot_unchanged": snapshot_hashes_before == snapshot_hashes_after,
    }
    print(status)
    print(f"REPORT={report_path}")
    print("SUMMARY=" + json.dumps(summary, sort_keys=True))
    if failures:
        print("FAILURES=" + json.dumps(failures, sort_keys=True))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
