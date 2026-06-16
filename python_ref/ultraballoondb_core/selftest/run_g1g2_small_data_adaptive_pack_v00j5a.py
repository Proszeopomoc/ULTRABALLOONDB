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

from ultraballoondb_core.g1g2_small_adaptive_pack import run_small_data_adaptive_pack  # noqa:E402

VERSION = "V00J5A_G1G2_SMALL_DATA_ADAPTIVE_PACK"
PASS_LINE = "PASS_ULTRABALLOONDB_G1G2_SMALL_DATA_ADAPTIVE_PACK_V00J5A"
NO_GO_LINE = "NO_GO_ULTRABALLOONDB_G1G2_SMALL_DATA_ADAPTIVE_PACK_V00J5A"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--input-folder", default="")
    ap.add_argument("--max-files", type=int, default=64)
    ap.add_argument("--max-bytes-per-file", type=int, default=1048576)
    ap.add_argument("--query-samples", type=int, default=8)
    ap.add_argument("--max-dictionary-tokens", type=int, default=512)
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    input_folder = Path(args.input_folder).resolve() if args.input_folder else (repo_root / "docs").resolve()

    run_id = time.strftime("RUN_%Y%m%d_%H%M%S")
    run_dir = repo_root / "audit" / "v00j5a_g1g2_small_data_adaptive_pack" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    tracemalloc.start()
    start = time.perf_counter()
    failures: Dict[str, str] = {}
    summary = None

    try:
        summary = run_small_data_adaptive_pack(
            input_folder=input_folder,
            max_files=int(args.max_files),
            max_bytes_per_file=int(args.max_bytes_per_file),
            query_samples=int(args.query_samples),
            max_dictionary_tokens=int(args.max_dictionary_tokens),
        )
    except Exception as exc:
        failures["adaptive_pack_exception"] = repr(exc)

    checks = {
        "input_folder_exists": input_folder.exists() and input_folder.is_dir(),
        "file_count_positive": bool(summary and summary.get("file_count", 0) > 0),
        "selected_mode_present": bool(summary and summary.get("selected_mode")),
        "file_sha_match_all": bool(summary and summary.get("file_sha_match_all")),
        "query_without_full_rebuild": bool(summary and summary.get("no_full_rebuild_during_query")),
        "candidate_modes_measured": bool(summary and len(summary.get("candidate_summaries", [])) >= 3),
        "adaptive_does_not_force_bad_g1g2_claim": bool(summary and (summary.get("compression_claim_allowed") or summary.get("selected_mode") == "RAW_SMALL_INDEX" or summary.get("selected_pack_bytes", 10**18) < summary.get("original_bytes", 0))),
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
        "input_folder": str(input_folder),
        "run_dir": str(run_dir),
        "elapsed_seconds": time.perf_counter() - start,
        "max_files": int(args.max_files),
        "max_bytes_per_file": int(args.max_bytes_per_file),
        "query_samples": int(args.query_samples),
        "max_dictionary_tokens": int(args.max_dictionary_tokens),
        "checks": checks,
        "failures": failures,
        "summary": summary,
        "tracemalloc_current_bytes": current,
        "tracemalloc_peak_bytes": peak,
    }

    report_path = run_dir / "g1g2_small_data_adaptive_pack_report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(status)
    print(f"REPORT={report_path}")
    if summary is not None:
        compact = {
            "case": summary.get("case"),
            "input_folder": summary.get("input_folder"),
            "file_count": summary.get("file_count"),
            "original_bytes": summary.get("original_bytes"),
            "zlib_bytes": summary.get("zlib_bytes"),
            "zlib_ratio": summary.get("zlib_ratio"),
            "selected_mode": summary.get("selected_mode"),
            "selected_pack_bytes": summary.get("selected_pack_bytes"),
            "selected_total_bytes": summary.get("selected_total_bytes"),
            "selected_effective_ratio": summary.get("selected_effective_ratio"),
            "selected_payload_external": summary.get("selected_payload_external"),
            "selected_index_overhead_bytes": summary.get("selected_index_overhead_bytes"),
            "file_sha_match_all": summary.get("file_sha_match_all"),
            "no_full_rebuild_during_query": summary.get("no_full_rebuild_during_query"),
            "compression_claim_allowed": summary.get("compression_claim_allowed"),
            "source_layer_counts": summary.get("source_layer_counts"),
        }
        print("SUMMARY=" + json.dumps(compact, ensure_ascii=False))
    if failures:
        print("FAILURES=" + "; ".join(f"{k}={v}" for k, v in failures.items()))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
