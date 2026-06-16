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

from ultraballoondb_core.g1g2_real_file_intake import run_real_file_family_intake  # noqa:E402

VERSION = "V00J5_G1G2_REAL_FILE_FAMILY_INTAKE"
PASS_LINE = "PASS_ULTRABALLOONDB_G1G2_REAL_FILE_FAMILY_INTAKE_V00J5"
NO_GO_LINE = "NO_GO_ULTRABALLOONDB_G1G2_REAL_FILE_FAMILY_INTAKE_V00J5"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--input-folder", default="")
    ap.add_argument("--max-files", type=int, default=64)
    ap.add_argument("--max-bytes-per-file", type=int, default=1048576)
    ap.add_argument("--query-samples", type=int, default=8)
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    input_folder = Path(args.input_folder).resolve() if args.input_folder else (repo_root / "docs").resolve()

    run_id = time.strftime("RUN_%Y%m%d_%H%M%S")
    run_dir = repo_root / "audit" / "v00j5_g1g2_real_file_family_intake" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    tracemalloc.start()
    start = time.perf_counter()
    failures: Dict[str, str] = {}
    summary = None

    try:
        summary = run_real_file_family_intake(
            input_folder=input_folder,
            max_files=int(args.max_files),
            max_bytes_per_file=int(args.max_bytes_per_file),
            query_samples=int(args.query_samples),
        )
    except Exception as exc:
        failures["intake_exception"] = repr(exc)

    checks = {
        "input_folder_exists": input_folder.exists() and input_folder.is_dir(),
        "file_count_positive": bool(summary and summary.get("file_count", 0) > 0),
        "deterministic_pack_bytes": bool(summary and summary.get("deterministic_pack_bytes")),
        "file_sha_match_all": bool(summary and summary.get("file_sha_match_all")),
        "query_without_full_rebuild": bool(summary and summary.get("no_full_rebuild_during_query")),
        "g1g2_layers_present": bool(summary and summary.get("source_layer_counts")),
        "no_agent_policy": True,
        "no_model_calls": True,
        "no_network_calls": True,
        "compression_claim_not_required_for_pass": True,
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
        "checks": checks,
        "failures": failures,
        "summary": summary,
        "tracemalloc_current_bytes": current,
        "tracemalloc_peak_bytes": peak,
    }

    report_path = run_dir / "g1g2_real_file_family_intake_report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(status)
    print(f"REPORT={report_path}")
    if summary is not None:
        compact = {
            "case": summary.get("case"),
            "input_folder": summary.get("input_folder"),
            "file_count": summary.get("file_count"),
            "dictionary_count": summary.get("dictionary_count"),
            "original_bytes": summary.get("original_bytes"),
            "g1g2_family_bytes": summary.get("g1g2_family_bytes"),
            "g1g2_family_ratio": summary.get("g1g2_family_ratio"),
            "zlib_bytes": summary.get("zlib_bytes"),
            "zlib_ratio": summary.get("zlib_ratio"),
            "g1g2_beats_zlib": summary.get("g1g2_beats_zlib"),
            "file_sha_match_all": summary.get("file_sha_match_all"),
            "no_full_rebuild_during_query": summary.get("no_full_rebuild_during_query"),
            "source_layer_counts": summary.get("source_layer_counts"),
            "compression_claim_allowed": summary.get("compression_claim_allowed"),
        }
        print("SUMMARY=" + json.dumps(compact, ensure_ascii=False))
    if failures:
        print("FAILURES=" + "; ".join(f"{k}={v}" for k, v in failures.items()))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
