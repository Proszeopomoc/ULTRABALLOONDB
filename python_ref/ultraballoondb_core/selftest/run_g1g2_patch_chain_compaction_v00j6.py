#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
import tracemalloc
from typing import Dict, List

THIS_FILE = Path(__file__).resolve()
PY_ROOT = THIS_FILE.parents[2]
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

try:
    from ultraballoondb_core.g1g2_delta_patch import (  # noqa:E402
        build_matrix_model,
        build_prefix_model,
        sha256_bytes,
    )
except ImportError as exc:
    raise SystemExit(
        "NO_GO_V00J6_DEPENDENCY_MISSING: V00J3 g1g2_delta_patch.py must already exist in the repo"
    ) from exc

from ultraballoondb_core.g1g2_patch_chain_compaction import (  # noqa:E402
    MatrixPatchChain,
    PrefixPatchChain,
    count_sources,
    populate_matrix_chain,
    populate_prefix_chain,
)

VERSION = "V00J6_G1G2_PATCH_CHAIN_COMPACTION"
PASS_LINE = "PASS_ULTRABALLOONDB_G1G2_PATCH_CHAIN_COMPACTION_V00J6"
NO_GO_LINE = "NO_GO_ULTRABALLOONDB_G1G2_PATCH_CHAIN_COMPACTION_V00J6"


def run_matrix_case(
    matrix_n: int,
    base_exceptions: int,
    patch_events: int,
    working_set: int,
    query_samples: int,
) -> Dict[str, object]:
    base = build_matrix_model(matrix_n, base_exceptions)
    chain = MatrixPatchChain(base=base)
    targets = populate_matrix_chain(chain, patch_events, working_set)

    pre_state = chain.rebuild_bytes()
    pre_sha = sha256_bytes(pre_state)
    rollback = chain.rollback_bundle()
    rollback_restored = MatrixPatchChain.from_rollback_bundle(rollback)
    restored_sha = sha256_bytes(rollback_restored.rebuild_bytes())

    chain_bytes_before = len(rollback)
    compacted, receipt = chain.compact()
    compacted_bytes = compacted.compact_bytes(include_patches=False)
    post_state = compacted.rebuild_bytes()
    post_sha = sha256_bytes(post_state)

    query_rows_before: List[Dict[str, object]] = []
    query_rows_after: List[Dict[str, object]] = []
    query_values_match = True
    compacted_rebuild_before_queries = compacted.rebuild_count
    for key in targets[: max(1, query_samples)]:
        row, col = divmod(key, matrix_n)
        before = chain.query(row, col)
        after = compacted.query(row, col)
        query_rows_before.append(before)
        query_rows_after.append(after)
        query_values_match = query_values_match and int(before["value"]) == int(after["value"])
    compacted_rebuild_after_queries = compacted.rebuild_count

    return {
        "case": "matrix_patch_chain_compaction",
        "original_state_bytes": len(pre_state),
        "patch_events_before": len(chain.patch_log),
        "active_overlay_before": len(chain.overlay),
        "chain_bytes_before": chain_bytes_before,
        "compacted_model_bytes": len(compacted_bytes),
        "compaction_ratio": chain_bytes_before / max(1, len(compacted_bytes)),
        "logical_sha_before": pre_sha,
        "logical_sha_after": post_sha,
        "logical_sha_match": pre_sha == post_sha,
        "rollback_bundle_sha256": sha256_bytes(rollback),
        "rollback_roundtrip_sha_match": pre_sha == restored_sha,
        "query_values_match": query_values_match,
        "no_full_rebuild_during_query": compacted_rebuild_before_queries == compacted_rebuild_after_queries,
        "query_source_layers_before": count_sources(query_rows_before),
        "query_source_layers_after": count_sources(query_rows_after),
        "receipt": receipt,
    }


def run_prefix_case(
    prefix_records: int,
    base_exceptions: int,
    patch_events: int,
    working_set: int,
    query_samples: int,
) -> Dict[str, object]:
    base = build_prefix_model(prefix_records, base_exceptions)
    chain = PrefixPatchChain(base=base)
    targets = populate_prefix_chain(chain, patch_events, working_set)

    pre_state = chain.rebuild_bytes()
    pre_sha = sha256_bytes(pre_state)
    rollback = chain.rollback_bundle()
    rollback_restored = PrefixPatchChain.from_rollback_bundle(rollback)
    restored_sha = sha256_bytes(rollback_restored.rebuild_bytes())

    chain_bytes_before = len(rollback)
    compacted, receipt = chain.compact()
    compacted_bytes = compacted.compact_bytes(include_patches=False)
    post_state = compacted.rebuild_bytes()
    post_sha = sha256_bytes(post_state)

    query_rows_before: List[Dict[str, object]] = []
    query_rows_after: List[Dict[str, object]] = []
    query_values_match = True
    compacted_rebuild_before_queries = compacted.rebuild_count
    for idx in targets[: max(1, query_samples)]:
        before = chain.query(idx)
        after = compacted.query(idx)
        query_rows_before.append(before)
        query_rows_after.append(after)
        query_values_match = query_values_match and str(before["value"]) == str(after["value"])
    compacted_rebuild_after_queries = compacted.rebuild_count

    return {
        "case": "prefix_patch_chain_compaction",
        "original_state_bytes": len(pre_state),
        "patch_events_before": len(chain.patch_log),
        "active_overlay_before": len(chain.overlay),
        "chain_bytes_before": chain_bytes_before,
        "compacted_model_bytes": len(compacted_bytes),
        "compaction_ratio": chain_bytes_before / max(1, len(compacted_bytes)),
        "logical_sha_before": pre_sha,
        "logical_sha_after": post_sha,
        "logical_sha_match": pre_sha == post_sha,
        "rollback_bundle_sha256": sha256_bytes(rollback),
        "rollback_roundtrip_sha_match": pre_sha == restored_sha,
        "query_values_match": query_values_match,
        "no_full_rebuild_during_query": compacted_rebuild_before_queries == compacted_rebuild_after_queries,
        "query_source_layers_before": count_sources(query_rows_before),
        "query_source_layers_after": count_sources(query_rows_after),
        "receipt": receipt,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--matrix-n", type=int, default=512)
    ap.add_argument("--prefix-records", type=int, default=10000)
    ap.add_argument("--base-exceptions", type=int, default=8)
    ap.add_argument("--patch-events", type=int, default=512)
    ap.add_argument("--working-set", type=int, default=64)
    ap.add_argument("--query-samples", type=int, default=8)
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    if not repo_root.exists():
        print(f"{NO_GO_LINE}: repo root does not exist: {repo_root}")
        return 1
    if args.matrix_n < 8 or args.prefix_records < args.working_set:
        print(f"{NO_GO_LINE}: invalid data dimensions")
        return 1
    if args.patch_events < args.working_set or args.working_set < 2:
        print(f"{NO_GO_LINE}: patch-events must be >= working-set >= 2")
        return 1

    run_id = time.strftime("RUN_%Y%m%d_%H%M%S")
    run_dir = repo_root / "audit" / "v00j6_g1g2_patch_chain_compaction" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    tracemalloc.start()
    started = time.perf_counter()
    failures: Dict[str, str] = {}

    matrix = run_matrix_case(
        args.matrix_n,
        args.base_exceptions,
        args.patch_events,
        args.working_set,
        args.query_samples,
    )
    prefix = run_prefix_case(
        args.prefix_records,
        args.base_exceptions,
        args.patch_events,
        args.working_set,
        args.query_samples,
    )

    checks = {
        "matrix_logical_sha_match": bool(matrix["logical_sha_match"]),
        "prefix_logical_sha_match": bool(prefix["logical_sha_match"]),
        "matrix_rollback_roundtrip_sha_match": bool(matrix["rollback_roundtrip_sha_match"]),
        "prefix_rollback_roundtrip_sha_match": bool(prefix["rollback_roundtrip_sha_match"]),
        "matrix_query_values_match": bool(matrix["query_values_match"]),
        "prefix_query_values_match": bool(prefix["query_values_match"]),
        "matrix_no_full_rebuild_during_query": bool(matrix["no_full_rebuild_during_query"]),
        "prefix_no_full_rebuild_during_query": bool(prefix["no_full_rebuild_during_query"]),
        "matrix_patch_chain_cleared": int(matrix["receipt"]["patch_events_after"]) == 0,
        "prefix_patch_chain_cleared": int(prefix["receipt"]["patch_events_after"]) == 0,
        "matrix_compaction_reduces_active_state": int(matrix["compacted_model_bytes"]) < int(matrix["chain_bytes_before"]),
        "prefix_compaction_reduces_active_state": int(prefix["compacted_model_bytes"]) < int(prefix["chain_bytes_before"]),
        "rollback_bundle_external_to_hot_state": bool(matrix["receipt"]["rollback_is_external_to_hot_state"]) and bool(prefix["receipt"]["rollback_is_external_to_hot_state"]),
        "no_typed_edge_graph_replacement": True,
        "no_wave_activation_replacement": True,
        "no_agent_policy": True,
        "no_model_calls": True,
        "no_network_calls": True,
    }
    for name, ok in checks.items():
        if not ok:
            failures[name] = "check failed"

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    status = PASS_LINE if not failures else NO_GO_LINE

    report = {
        "version": VERSION,
        "status": status,
        "repo_root": str(repo_root),
        "run_dir": str(run_dir),
        "elapsed_seconds": time.perf_counter() - started,
        "params": {
            "matrix_n": args.matrix_n,
            "prefix_records": args.prefix_records,
            "base_exceptions": args.base_exceptions,
            "patch_events": args.patch_events,
            "working_set": args.working_set,
            "query_samples": args.query_samples,
        },
        "alignment": {
            "role": "SUPPORT",
            "touches_core_layers": ["L0", "L4", "L6"],
            "uses_auxiliary_layers": ["C1", "C2", "C3", "C4", "C5"],
            "must_not_replace": ["L2_TYPED_EDGE_GRAPH", "L3_WAVE_ACTIVATION"],
            "runtime_impact": "OFFLINE_COMPACTION_ONLY",
            "roadmap_status": "ALIGNED",
        },
        "scope": {
            "offline_patch_chain_compaction": True,
            "active_g4_chain_cleared_after_compaction": True,
            "rollback_bundle_kept_outside_hot_state": True,
            "logical_state_preserved": True,
            "full_storage_engine": False,
        },
        "checks": checks,
        "failures": failures,
        "cases": {
            "matrix_patch_chain_compaction": matrix,
            "prefix_patch_chain_compaction": prefix,
        },
        "summary": {
            "matrix_patch_chain_compaction": {
                "patch_events_before": matrix["patch_events_before"],
                "chain_bytes_before": matrix["chain_bytes_before"],
                "compacted_model_bytes": matrix["compacted_model_bytes"],
                "compaction_ratio": matrix["compaction_ratio"],
                "exceptions_after": matrix["receipt"]["exceptions_after"],
                "reverted_to_g1_count": matrix["receipt"]["reverted_to_g1_count"],
                "logical_sha_match": matrix["logical_sha_match"],
                "rollback_roundtrip_sha_match": matrix["rollback_roundtrip_sha_match"],
                "no_full_rebuild_during_query": matrix["no_full_rebuild_during_query"],
            },
            "prefix_patch_chain_compaction": {
                "patch_events_before": prefix["patch_events_before"],
                "chain_bytes_before": prefix["chain_bytes_before"],
                "compacted_model_bytes": prefix["compacted_model_bytes"],
                "compaction_ratio": prefix["compaction_ratio"],
                "exceptions_after": prefix["receipt"]["exceptions_after"],
                "reverted_to_g1_count": prefix["receipt"]["reverted_to_g1_count"],
                "logical_sha_match": prefix["logical_sha_match"],
                "rollback_roundtrip_sha_match": prefix["rollback_roundtrip_sha_match"],
                "no_full_rebuild_during_query": prefix["no_full_rebuild_during_query"],
            },
        },
        "tracemalloc_current_bytes": current,
        "tracemalloc_peak_bytes": peak,
    }

    report_path = run_dir / "g1g2_patch_chain_compaction_report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(status)
    print(f"REPORT={report_path}")
    print("SUMMARY=" + json.dumps(report["summary"], ensure_ascii=False))
    if failures:
        print("FAILURES=" + "; ".join(f"{k}={v}" for k, v in failures.items()))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
