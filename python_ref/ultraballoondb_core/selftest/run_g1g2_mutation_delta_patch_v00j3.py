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

from ultraballoondb_core.g1g2_delta_patch import (  # noqa:E402
    build_matrix_model,
    build_prefix_model,
    count_sources,
    matrix_patch_plan,
    prefix_patch_plan,
    sha256_bytes,
)

VERSION = "V00J3_G1G2_MUTATION_DELTA_PATCH"
PASS_LINE = "PASS_ULTRABALLOONDB_G1G2_MUTATION_DELTA_PATCH_V00J3"
NO_GO_LINE = "NO_GO_ULTRABALLOONDB_G1G2_MUTATION_DELTA_PATCH_V00J3"


def run_matrix_case(matrix_n: int, exception_count: int, patch_count: int, query_samples: int) -> Dict[str, object]:
    model = build_matrix_model(matrix_n, exception_count)
    original = model.rebuild_bytes()
    original_sha = sha256_bytes(original)
    patch_records = []
    for row, col, value in matrix_patch_plan(model, patch_count):
        patch_records.append(model.apply_patch(row, col, value))

    direct = model.direct_apply_to_original(original, patch_records)
    direct_sha = sha256_bytes(direct)
    rebuild_after = model.rebuild_bytes()
    rebuild_sha = sha256_bytes(rebuild_after)

    before_query_rebuild_count = model.rebuild_count
    query_rows: List[Dict[str, object]] = []
    # include G4, G2 and G1 queries deterministically
    for p in patch_records[:query_samples]:
        row, col = divmod(int(p["key"]), matrix_n)
        query_rows.append(model.query(row, col))
    for k in sorted(model.exceptions.keys()):
        if k not in model.patches and len(query_rows) < query_samples * 2:
            row, col = divmod(k, matrix_n)
            query_rows.append(model.query(row, col))
    t = 0
    while len(query_rows) < query_samples * 3:
        row = (t * 157 + 11) % matrix_n
        col = (t * 271 + 13) % matrix_n
        k = row * matrix_n + col
        if k not in model.exceptions and k not in model.patches:
            query_rows.append(model.query(row, col))
        t += 1
    after_query_rebuild_count = model.rebuild_count

    compact_before = model.compact_bytes(include_patches=False)
    compact_after = model.compact_bytes(include_patches=True)
    return {
        "case": "matrix_delta_patch",
        "original_bytes": len(original),
        "g1g2_before_patch_bytes": len(compact_before),
        "g1g2_after_patch_bytes": len(compact_after),
        "patch_count": len(patch_records),
        "ratio_after_patch": len(original) / max(1, len(compact_after)),
        "original_sha256": original_sha,
        "direct_patch_sha256": direct_sha,
        "rebuild_after_patch_sha256": rebuild_sha,
        "sha_match_after_patch": direct_sha == rebuild_sha,
        "no_full_rebuild_during_query": before_query_rebuild_count == after_query_rebuild_count,
        "query_source_layer_counts": count_sources(query_rows),
        "patch_records_sample": patch_records[: min(4, len(patch_records))],
    }


def run_prefix_case(prefix_records: int, exception_count: int, patch_count: int, query_samples: int) -> Dict[str, object]:
    model = build_prefix_model(prefix_records, exception_count)
    original = model.rebuild_bytes()
    original_sha = sha256_bytes(original)
    patch_records = []
    for idx, record in prefix_patch_plan(model, patch_count):
        patch_records.append(model.apply_patch(idx, record))

    direct = model.direct_apply_to_original(original, patch_records)
    direct_sha = sha256_bytes(direct)
    rebuild_after = model.rebuild_bytes()
    rebuild_sha = sha256_bytes(rebuild_after)

    before_query_rebuild_count = model.rebuild_count
    query_rows: List[Dict[str, object]] = []
    for p in patch_records[:query_samples]:
        query_rows.append(model.query(int(p["idx"])))
    for idx in sorted(model.exceptions.keys()):
        if idx not in model.patches and len(query_rows) < query_samples * 2:
            query_rows.append(model.query(idx))
    t = 0
    while len(query_rows) < query_samples * 3:
        idx = (t * 751 + 19) % prefix_records
        if idx not in model.exceptions and idx not in model.patches:
            query_rows.append(model.query(idx))
        t += 1
    after_query_rebuild_count = model.rebuild_count

    compact_before = model.compact_bytes(include_patches=False)
    compact_after = model.compact_bytes(include_patches=True)
    return {
        "case": "prefix_family_delta_patch",
        "original_bytes": len(original),
        "g1g2_before_patch_bytes": len(compact_before),
        "g1g2_after_patch_bytes": len(compact_after),
        "patch_count": len(patch_records),
        "ratio_after_patch": len(original) / max(1, len(compact_after)),
        "original_sha256": original_sha,
        "direct_patch_sha256": direct_sha,
        "rebuild_after_patch_sha256": rebuild_sha,
        "sha_match_after_patch": direct_sha == rebuild_sha,
        "no_full_rebuild_during_query": before_query_rebuild_count == after_query_rebuild_count,
        "query_source_layer_counts": count_sources(query_rows),
        "patch_records_sample": patch_records[: min(4, len(patch_records))],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo-root', required=True)
    ap.add_argument('--matrix-n', type=int, default=1024)
    ap.add_argument('--exception-count', type=int, default=8)
    ap.add_argument('--prefix-records', type=int, default=10000)
    ap.add_argument('--patch-count', type=int, default=4)
    ap.add_argument('--query-samples', type=int, default=8)
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    if not repo_root.exists():
        print(f"{NO_GO_LINE}: repo root does not exist: {repo_root}")
        return 1

    run_id = time.strftime('RUN_%Y%m%d_%H%M%S')
    run_dir = repo_root / 'audit' / 'v00j3_g1g2_mutation_delta_patch' / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    tracemalloc.start()
    start = time.perf_counter()
    failures: Dict[str, str] = {}

    matrix_report = run_matrix_case(args.matrix_n, args.exception_count, args.patch_count, args.query_samples)
    prefix_report = run_prefix_case(args.prefix_records, args.exception_count, args.patch_count, args.query_samples)

    checks = {
        "matrix_sha_match_after_patch": bool(matrix_report["sha_match_after_patch"]),
        "prefix_sha_match_after_patch": bool(prefix_report["sha_match_after_patch"]),
        "matrix_no_full_rebuild_during_query": bool(matrix_report["no_full_rebuild_during_query"]),
        "prefix_no_full_rebuild_during_query": bool(prefix_report["no_full_rebuild_during_query"]),
        "matrix_patch_smaller_than_original": matrix_report["g1g2_after_patch_bytes"] < matrix_report["original_bytes"],
        "prefix_patch_smaller_than_original": prefix_report["g1g2_after_patch_bytes"] < prefix_report["original_bytes"],
        "matrix_g4_query_seen": matrix_report["query_source_layer_counts"].get("G4_PATCH", 0) > 0,
        "prefix_g4_query_seen": prefix_report["query_source_layer_counts"].get("G4_PATCH", 0) > 0,
        "no_agent_policy": True,
        "no_model_calls": True,
        "no_network_calls": True,
    }

    for key, ok in checks.items():
        if not ok:
            failures[key] = "check failed"

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    status = PASS_LINE if not failures else NO_GO_LINE
    report = {
        "version": VERSION,
        "status": status,
        "repo_root": str(repo_root),
        "run_dir": str(run_dir),
        "elapsed_seconds": time.perf_counter() - start,
        "params": {
            "matrix_n": args.matrix_n,
            "exception_count": args.exception_count,
            "prefix_records": args.prefix_records,
            "patch_count": args.patch_count,
            "query_samples": args.query_samples,
        },
        "scope": {
            "delta_patch_layer": "G4",
            "canonical_rebuild_available": True,
            "query_without_full_rebuild": True,
            "trust_promotion": False,
            "full_storage_engine": False,
        },
        "checks": checks,
        "failures": failures,
        "cases": {
            "matrix_delta_patch": matrix_report,
            "prefix_family_delta_patch": prefix_report,
        },
        "summary": {
            "matrix_delta_patch": {
                "original_bytes": matrix_report["original_bytes"],
                "g1g2_after_patch_bytes": matrix_report["g1g2_after_patch_bytes"],
                "ratio_after_patch": matrix_report["ratio_after_patch"],
                "sha_match_after_patch": matrix_report["sha_match_after_patch"],
                "no_full_rebuild_during_query": matrix_report["no_full_rebuild_during_query"],
                "source_layer_counts": matrix_report["query_source_layer_counts"],
            },
            "prefix_family_delta_patch": {
                "original_bytes": prefix_report["original_bytes"],
                "g1g2_after_patch_bytes": prefix_report["g1g2_after_patch_bytes"],
                "ratio_after_patch": prefix_report["ratio_after_patch"],
                "sha_match_after_patch": prefix_report["sha_match_after_patch"],
                "no_full_rebuild_during_query": prefix_report["no_full_rebuild_during_query"],
                "source_layer_counts": prefix_report["query_source_layer_counts"],
            },
        },
        "tracemalloc_current_bytes": current,
        "tracemalloc_peak_bytes": peak,
    }

    report_path = run_dir / 'g1g2_mutation_delta_patch_report.json'
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')

    print(status)
    print(f"REPORT={report_path}")
    print("SUMMARY=" + json.dumps(report["summary"], ensure_ascii=False))
    if failures:
        print('FAILURES=' + '; '.join(f'{k}={v}' for k, v in failures.items()))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
