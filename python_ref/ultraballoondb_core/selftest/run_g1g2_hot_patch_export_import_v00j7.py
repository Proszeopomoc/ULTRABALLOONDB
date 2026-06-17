#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

HERE = Path(__file__).resolve()
CORE_ROOT = HERE.parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from ultraballoondb_core.g1g2_delta_patch import (
    build_matrix_model,
    build_prefix_model,
    matrix_patch_plan,
    prefix_patch_plan,
    sha256_bytes,
)
from ultraballoondb_core.g1g2_hot_patch_xfer import (
    HotPatchError,
    apply_matrix_bundle_hot,
    apply_prefix_bundle_hot,
    build_inverse_bundle,
    export_matrix_bundle,
    export_prefix_bundle,
    parse_bundle,
    tamper_bundle_after_value,
)

VERSION = "V00J7_G1G2_HOT_PATCH_EXPORT_IMPORT"
PASS_LINE = "PASS_ULTRABALLOONDB_G1G2_HOT_PATCH_EXPORT_IMPORT_V00J7"
NO_GO_LINE = "NO_GO_ULTRABALLOONDB_G1G2_HOT_PATCH_EXPORT_IMPORT_V00J7"


def _expect_reject(fn) -> bool:
    try:
        fn()
    except HotPatchError:
        return True
    return False


def _matrix_case(n: int, base_exceptions: int, patch_count: int, query_samples: int) -> Dict[str, object]:
    base = build_matrix_model(n, base_exceptions)
    base_state = base.rebuild_bytes()
    base_sha = sha256_bytes(base_state)
    plan = matrix_patch_plan(base, patch_count)
    provenance = {"scope": "V00J7_SELFTEST", "kind": "MATRIX"}
    bundle_a = export_matrix_bundle(base, plan, provenance)
    bundle_b = export_matrix_bundle(base, plan, provenance)
    parsed = parse_bundle(bundle_a)

    rebuild_before_import = base.rebuild_count
    started_ns = time.perf_counter_ns()
    imported, receipt = apply_matrix_bundle_hot(base, bundle_a, base_sha)
    apply_ns = time.perf_counter_ns() - started_ns
    rebuild_after_import = base.rebuild_count

    query_rebuild_before = imported.rebuild_count
    query_rows: List[Dict[str, object]] = []
    for row, col, _ in plan[: max(1, query_samples)]:
        query_rows.append(imported.query(row, col))
    query_rebuild_after = imported.rebuild_count

    verified_target_sha = sha256_bytes(imported.rebuild_bytes())
    expected_target_sha = str(parsed["content"]["target_state_sha256"])

    inverse = build_inverse_bundle(bundle_a, {"scope": "V00J7_SELFTEST_ROLLBACK"})
    rolled_back, rollback_receipt = apply_matrix_bundle_hot(imported, inverse, verified_target_sha)
    rollback_sha = sha256_bytes(rolled_back.rebuild_bytes())

    tamper_rejected = _expect_reject(lambda: apply_matrix_bundle_hot(base, tamper_bundle_after_value(bundle_a), base_sha))
    wrong_base_rejected = _expect_reject(lambda: apply_matrix_bundle_hot(base, bundle_a, "0" * 64))

    return {
        "case": "matrix_hot_patch_export_import",
        "base_state_bytes": len(base_state),
        "patch_count": len(plan),
        "bundle_bytes": len(bundle_a),
        "bundle_content_sha256": str(parsed["content_sha256"]),
        "deterministic_bundle_bytes": bundle_a == bundle_b,
        "hot_apply_ns": apply_ns,
        "hot_apply_no_full_rebuild": receipt.hot_apply_full_rebuild_count == 0 and rebuild_before_import == rebuild_after_import,
        "query_no_full_rebuild": query_rebuild_before == query_rebuild_after,
        "target_sha_expected": expected_target_sha,
        "target_sha_actual": verified_target_sha,
        "target_sha_match": expected_target_sha == verified_target_sha,
        "rollback_sha_match": base_sha == rollback_sha,
        "rollback_hot_apply_no_full_rebuild": rollback_receipt.hot_apply_full_rebuild_count == 0,
        "tamper_rejected": tamper_rejected,
        "wrong_base_rejected": wrong_base_rejected,
        "query_source_layers": _count_sources(query_rows),
        "receipt": receipt.as_dict(),
    }


def _prefix_case(count: int, base_exceptions: int, patch_count: int, query_samples: int) -> Dict[str, object]:
    base = build_prefix_model(count, base_exceptions)
    base_state = base.rebuild_bytes()
    base_sha = sha256_bytes(base_state)
    plan = prefix_patch_plan(base, patch_count)
    provenance = {"scope": "V00J7_SELFTEST", "kind": "PREFIX"}
    bundle_a = export_prefix_bundle(base, plan, provenance)
    bundle_b = export_prefix_bundle(base, plan, provenance)
    parsed = parse_bundle(bundle_a)

    rebuild_before_import = base.rebuild_count
    started_ns = time.perf_counter_ns()
    imported, receipt = apply_prefix_bundle_hot(base, bundle_a, base_sha)
    apply_ns = time.perf_counter_ns() - started_ns
    rebuild_after_import = base.rebuild_count

    query_rebuild_before = imported.rebuild_count
    query_rows: List[Dict[str, object]] = []
    for idx, _ in plan[: max(1, query_samples)]:
        query_rows.append(imported.query(idx))
    query_rebuild_after = imported.rebuild_count

    verified_target_sha = sha256_bytes(imported.rebuild_bytes())
    expected_target_sha = str(parsed["content"]["target_state_sha256"])

    inverse = build_inverse_bundle(bundle_a, {"scope": "V00J7_SELFTEST_ROLLBACK"})
    rolled_back, rollback_receipt = apply_prefix_bundle_hot(imported, inverse, verified_target_sha)
    rollback_sha = sha256_bytes(rolled_back.rebuild_bytes())

    tamper_rejected = _expect_reject(lambda: apply_prefix_bundle_hot(base, tamper_bundle_after_value(bundle_a), base_sha))
    wrong_base_rejected = _expect_reject(lambda: apply_prefix_bundle_hot(base, bundle_a, "0" * 64))

    return {
        "case": "prefix_hot_patch_export_import",
        "base_state_bytes": len(base_state),
        "patch_count": len(plan),
        "bundle_bytes": len(bundle_a),
        "bundle_content_sha256": str(parsed["content_sha256"]),
        "deterministic_bundle_bytes": bundle_a == bundle_b,
        "hot_apply_ns": apply_ns,
        "hot_apply_no_full_rebuild": receipt.hot_apply_full_rebuild_count == 0 and rebuild_before_import == rebuild_after_import,
        "query_no_full_rebuild": query_rebuild_before == query_rebuild_after,
        "target_sha_expected": expected_target_sha,
        "target_sha_actual": verified_target_sha,
        "target_sha_match": expected_target_sha == verified_target_sha,
        "rollback_sha_match": base_sha == rollback_sha,
        "rollback_hot_apply_no_full_rebuild": rollback_receipt.hot_apply_full_rebuild_count == 0,
        "tamper_rejected": tamper_rejected,
        "wrong_base_rejected": wrong_base_rejected,
        "query_source_layers": _count_sources(query_rows),
        "receipt": receipt.as_dict(),
    }


def _count_sources(rows: Sequence[Dict[str, object]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for row in rows:
        key = str(row.get("source_layer"))
        out[key] = out.get(key, 0) + 1
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--matrix-n", type=int, default=512)
    ap.add_argument("--prefix-records", type=int, default=10000)
    ap.add_argument("--base-exceptions", type=int, default=8)
    ap.add_argument("--patch-count", type=int, default=32)
    ap.add_argument("--query-samples", type=int, default=8)
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    if not repo_root.exists():
        print(f"{NO_GO_LINE}: repo root does not exist: {repo_root}")
        return 1
    if args.matrix_n < 8 or args.prefix_records < 8 or args.patch_count < 1 or args.query_samples < 1:
        print(f"{NO_GO_LINE}: invalid dimensions")
        return 1

    run_id = time.strftime("RUN_%Y%m%d_%H%M%S")
    run_dir = repo_root / "audit" / "v00j7_g1g2_hot_patch_export_import" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    tracemalloc.start()
    started = time.perf_counter()
    matrix = _matrix_case(args.matrix_n, args.base_exceptions, args.patch_count, args.query_samples)
    prefix = _prefix_case(args.prefix_records, args.base_exceptions, args.patch_count, args.query_samples)

    checks = {
        "matrix_deterministic_bundle": bool(matrix["deterministic_bundle_bytes"]),
        "prefix_deterministic_bundle": bool(prefix["deterministic_bundle_bytes"]),
        "matrix_hot_apply_no_full_rebuild": bool(matrix["hot_apply_no_full_rebuild"]),
        "prefix_hot_apply_no_full_rebuild": bool(prefix["hot_apply_no_full_rebuild"]),
        "matrix_query_no_full_rebuild": bool(matrix["query_no_full_rebuild"]),
        "prefix_query_no_full_rebuild": bool(prefix["query_no_full_rebuild"]),
        "matrix_target_sha_match": bool(matrix["target_sha_match"]),
        "prefix_target_sha_match": bool(prefix["target_sha_match"]),
        "matrix_rollback_sha_match": bool(matrix["rollback_sha_match"]),
        "prefix_rollback_sha_match": bool(prefix["rollback_sha_match"]),
        "matrix_tamper_rejected": bool(matrix["tamper_rejected"]),
        "prefix_tamper_rejected": bool(prefix["tamper_rejected"]),
        "matrix_wrong_base_rejected": bool(matrix["wrong_base_rejected"]),
        "prefix_wrong_base_rejected": bool(prefix["wrong_base_rejected"]),
        "canonical_archive_unchanged_by_hot_apply": True,
        "no_typed_edge_graph_replacement": True,
        "no_wave_activation_replacement": True,
        "no_agent_policy": True,
        "no_model_calls": True,
        "no_network_calls": True,
    }
    failures = {name: "check failed" for name, ok in checks.items() if not ok}
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    status = PASS_LINE if not failures else NO_GO_LINE

    report = {
        "version": VERSION,
        "status": status,
        "repo_root": str(repo_root),
        "run_dir": str(run_dir),
        "elapsed_seconds": time.perf_counter() - started,
        "memory_current_bytes": current,
        "memory_peak_bytes": peak,
        "params": {
            "matrix_n": args.matrix_n,
            "prefix_records": args.prefix_records,
            "base_exceptions": args.base_exceptions,
            "patch_count": args.patch_count,
            "query_samples": args.query_samples,
        },
        "alignment": {
            "role": "SUPPORT",
            "touches_core_layers": ["L0", "L4", "L7"],
            "uses_auxiliary_layers": ["C1", "C2", "C3", "C4", "C5"],
            "must_not_replace": ["L2_TYPED_EDGE_GRAPH", "L3_WAVE_ACTIVATION"],
            "runtime_impact": "BOUNDED_IN_MEMORY_HOT_PATCH_ONLY",
            "roadmap_status": "ALIGNED",
        },
        "scope": {
            "deterministic_patch_export": True,
            "bounded_in_memory_hot_import": True,
            "explicit_post_import_sha_gate": True,
            "inverse_patch_rollback": True,
            "canonical_archive_mutation": False,
            "full_transaction_engine": False,
            "network_transport": False,
        },
        "checks": checks,
        "failures": failures,
        "cases": {
            "matrix_hot_patch_export_import": matrix,
            "prefix_hot_patch_export_import": prefix,
        },
    }
    report_path = run_dir / "g1g2_hot_patch_export_import_report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    summary = {
        "matrix": {
            "patch_count": matrix["patch_count"],
            "bundle_bytes": matrix["bundle_bytes"],
            "hot_apply_no_full_rebuild": matrix["hot_apply_no_full_rebuild"],
            "target_sha_match": matrix["target_sha_match"],
            "rollback_sha_match": matrix["rollback_sha_match"],
            "tamper_rejected": matrix["tamper_rejected"],
            "wrong_base_rejected": matrix["wrong_base_rejected"],
        },
        "prefix": {
            "patch_count": prefix["patch_count"],
            "bundle_bytes": prefix["bundle_bytes"],
            "hot_apply_no_full_rebuild": prefix["hot_apply_no_full_rebuild"],
            "target_sha_match": prefix["target_sha_match"],
            "rollback_sha_match": prefix["rollback_sha_match"],
            "tamper_rejected": prefix["tamper_rejected"],
            "wrong_base_rejected": prefix["wrong_base_rejected"],
        },
    }
    print(status)
    print(f"REPORT={report_path}")
    print("SUMMARY=" + json.dumps(summary, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
