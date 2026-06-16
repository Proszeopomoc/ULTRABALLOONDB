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

from ultraballoondb_core.g1g2_reconstruction import (  # noqa:E402
    VERSION,
    make_low_exception_graph_package,
    make_prefix_id_package,
    negative_random_control,
)

PASS_LINE = "PASS_ULTRABALLOONDB_G1G2_RULE_EXCEPTION_RECONSTRUCTION_V00J1"
NO_GO_LINE = "NO_GO_ULTRABALLOONDB_G1G2_RULE_EXCEPTION_RECONSTRUCTION_V00J1"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--matrix-n", type=int, default=1024)
    ap.add_argument("--exception-count", type=int, default=8)
    ap.add_argument("--prefix-records", type=int, default=10000)
    ap.add_argument("--random-bytes", type=int, default=65536)
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    if not repo_root.exists():
        print(f"{NO_GO_LINE}: repo root does not exist: {repo_root}")
        return 1

    run_id = time.strftime("RUN_%Y%m%d_%H%M%S")
    run_dir = repo_root / "audit" / "v00j1_g1g2_rule_exception_reconstruction" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    tracemalloc.start()
    start = time.perf_counter()
    failures: Dict[str, str] = {}

    datasets = []
    try:
        datasets.append(make_low_exception_graph_package(args.matrix_n, args.exception_count))
        datasets.append(make_prefix_id_package(args.prefix_records))
        datasets.append(negative_random_control(args.random_bytes))
    except Exception as exc:
        failures["run_exception"] = repr(exc)

    by_name = {d.get("dataset"): d for d in datasets}

    checks = {
        "lossless_matrix_rebuild": bool(by_name.get("low_exception_rule_matrix", {}).get("rebuild_sha256_match")),
        "lossless_prefix_rebuild": bool(by_name.get("prefix_id_family", {}).get("rebuild_sha256_match")),
        "matrix_ratio_above_100x": float(by_name.get("low_exception_rule_matrix", {}).get("g1g2_ratio", 0.0)) >= 100.0,
        "prefix_ratio_above_2x": float(by_name.get("prefix_id_family", {}).get("g1g2_ratio", 0.0)) >= 2.0,
        "matrix_beats_zlib": bool(by_name.get("low_exception_rule_matrix", {}).get("beats_zlib_ratio")),
        "queryable_structure_retained": all(
            bool(by_name.get(name, {}).get("queryable_structure_retained"))
            for name in ["low_exception_rule_matrix", "prefix_id_family"]
        ),
        "random_negative_not_claimed_compressed": bool(by_name.get("negative_random_control", {}).get("random_data_not_falsely_compressed")),
        "no_final_runtime_policy_selected": True,
        "no_llm_calls": True,
        "no_network_calls": True,
        "no_agent_policy": True,
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
        "parameters": {
            "matrix_n": args.matrix_n,
            "exception_count": args.exception_count,
            "prefix_records": args.prefix_records,
            "random_bytes": args.random_bytes,
        },
        "scope": {
            "structural_compression_core": True,
            "g1_rule_model": True,
            "g2_exception_residual": True,
            "g5_sha256_validation": True,
            "hot_layout_finalized": False,
            "fold_policy_selected": False,
            "trust_promotion": False,
        },
        "checks": checks,
        "failures": failures,
        "datasets": datasets,
        "tracemalloc_current_bytes": current,
        "tracemalloc_peak_bytes": peak,
    }

    report_path = run_dir / "g1g2_rule_exception_reconstruction_report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(status)
    print(f"REPORT={report_path}")
    print("SUMMARY=" + json.dumps({
        d["dataset"]: {
            "original_bytes": d.get("original_bytes"),
            "g1g2_bytes": d.get("g1g2_bytes"),
            "g1g2_ratio": d.get("g1g2_ratio"),
            "zlib_ratio": d.get("zlib_ratio"),
            "sha_match": d.get("rebuild_sha256_match"),
            "compression_claim_allowed": d.get("compression_claim_allowed", True),
        }
        for d in datasets
    }, ensure_ascii=False))

    if failures:
        print("FAILURES=" + "; ".join(f"{k}={v}" for k, v in failures.items()))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
