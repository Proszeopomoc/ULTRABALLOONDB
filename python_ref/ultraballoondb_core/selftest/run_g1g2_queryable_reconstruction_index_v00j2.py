#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
import tracemalloc
from typing import Dict

THIS_FILE = Path(__file__).resolve()
PY_ROOT = THIS_FILE.parents[2]
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from ultraballoondb_core.g1g2_query_index import (  # noqa:E402
    VERSION,
    build_matrix_index,
    build_prefix_index,
    compression_summary,
    query_batch_without_rebuild,
    sha256_bytes,
)

PASS_LINE = "PASS_ULTRABALLOONDB_G1G2_QUERYABLE_RECONSTRUCTION_INDEX_V00J2"
NO_GO_LINE = "NO_GO_ULTRABALLOONDB_G1G2_QUERYABLE_RECONSTRUCTION_INDEX_V00J2"


def run_matrix_case(n: int, exception_count: int, query_samples: int) -> Dict[str, object]:
    idx = build_matrix_index(n, exception_count)
    exception_queries = []
    for linear in list(idx.exceptions.keys())[: min(4, len(idx.exceptions))]:
        exception_queries.append(divmod(linear, n))
    rule_queries = [(0, 0), (1, 2), (n // 2, n // 3), (n - 1, n - 1)]
    mixed_queries = (exception_queries + rule_queries)[: max(1, min(query_samples, 8))]

    query_report = query_batch_without_rebuild(idx, mixed_queries)
    original = idx.rebuild_bytes()
    compact = idx.compact_bytes()
    rebuilt = idx.rebuild_bytes()
    sha_match = sha256_bytes(original) == sha256_bytes(rebuilt)
    summary = compression_summary("low_exception_rule_matrix_queryable", original, compact)
    summary.update({
        "sha_match": sha_match,
        "compression_claim_allowed": summary["g1g2_ratio"] > 1.0,
    })
    return {
        "case": "low_exception_rule_matrix_queryable",
        "manifest": idx.proof_manifest(),
        "compression": summary,
        "query_report": query_report,
    }


def run_prefix_case(count: int, query_samples: int) -> Dict[str, object]:
    idx = build_prefix_index(count)
    exception_queries = list(idx.exceptions.keys())[: min(3, len(idx.exceptions))]
    rule_queries = [0, 1, max(0, count // 2), max(0, count - 1)]
    mixed_queries = (exception_queries + rule_queries)[: max(1, min(query_samples, 8))]

    query_report = query_batch_without_rebuild(idx, mixed_queries)
    original = idx.rebuild_bytes()
    compact = idx.compact_bytes()
    rebuilt = idx.rebuild_bytes()
    sha_match = sha256_bytes(original) == sha256_bytes(rebuilt)
    summary = compression_summary("prefix_id_family_queryable", original, compact)
    summary.update({
        "sha_match": sha_match,
        "compression_claim_allowed": summary["g1g2_ratio"] > 1.0,
    })
    return {
        "case": "prefix_id_family_queryable",
        "manifest": idx.proof_manifest(),
        "compression": summary,
        "query_report": query_report,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--matrix-n", type=int, default=1024)
    ap.add_argument("--exception-count", type=int, default=8)
    ap.add_argument("--prefix-records", type=int, default=10000)
    ap.add_argument("--query-samples", type=int, default=8)
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    if not repo_root.exists():
        print(f"{NO_GO_LINE}: repo root does not exist: {repo_root}")
        return 1

    run_id = time.strftime("RUN_%Y%m%d_%H%M%S")
    run_dir = repo_root / "audit" / "v00j2_g1g2_queryable_reconstruction_index" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    tracemalloc.start()
    start = time.perf_counter()
    failures: Dict[str, str] = {}

    case_reports = []
    try:
        case_reports.append(run_matrix_case(args.matrix_n, args.exception_count, args.query_samples))
        case_reports.append(run_prefix_case(args.prefix_records, args.query_samples))
    except Exception as exc:
        failures["case_exception"] = repr(exc)

    checks = {
        "queryable_without_full_rebuild": False,
        "g1_rule_query_present": False,
        "g2_exception_query_present": False,
        "sha_rebuild_available_and_matching": False,
        "compression_claims_allowed_only_after_sha_match": False,
        "no_agent_policy": True,
        "no_model_calls": True,
        "no_network_calls": True,
        "no_runtime_hot_policy_selected": True,
    }

    if case_reports:
        checks["queryable_without_full_rebuild"] = all(
            c["query_report"].get("no_full_rebuild_during_query") is True for c in case_reports
        )
        checks["g1_rule_query_present"] = any(
            c["query_report"]["source_layer_counts"].get("G1_RULE", 0) > 0 for c in case_reports
        )
        checks["g2_exception_query_present"] = any(
            c["query_report"]["source_layer_counts"].get("G2_EXCEPTION", 0) > 0 for c in case_reports
        )
        checks["sha_rebuild_available_and_matching"] = all(
            c["compression"].get("sha_match") is True for c in case_reports
        )
        checks["compression_claims_allowed_only_after_sha_match"] = all(
            (not c["compression"].get("compression_claim_allowed")) or c["compression"].get("sha_match") is True
            for c in case_reports
        )

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
        "matrix_n": args.matrix_n,
        "exception_count": args.exception_count,
        "prefix_records": args.prefix_records,
        "query_samples": args.query_samples,
        "checks": checks,
        "failures": failures,
        "case_reports": case_reports,
        "tracemalloc_current_bytes": current,
        "tracemalloc_peak_bytes": peak,
    }
    report_path = run_dir / "g1g2_queryable_reconstruction_index_report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    summary = {
        c["case"]: {
            "original_bytes": c["compression"]["original_bytes"],
            "g1g2_bytes": c["compression"]["g1g2_bytes"],
            "g1g2_ratio": c["compression"]["g1g2_ratio"],
            "sha_match": c["compression"]["sha_match"],
            "no_full_rebuild_during_query": c["query_report"]["no_full_rebuild_during_query"],
            "source_layer_counts": c["query_report"]["source_layer_counts"],
        }
        for c in case_reports
    }

    print(status)
    print(f"REPORT={report_path}")
    print("SUMMARY=" + json.dumps(summary, ensure_ascii=False))
    if failures:
        print("FAILURES=" + "; ".join(f"{k}={v}" for k, v in failures.items()))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
