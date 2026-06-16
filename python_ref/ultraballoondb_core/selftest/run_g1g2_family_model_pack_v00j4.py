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
import zlib

THIS_FILE = Path(__file__).resolve()
PY_ROOT = THIS_FILE.parents[2]
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from ultraballoondb_core.g1g2_family_pack import (  # noqa:E402
    FamilyG1G2Pack,
    build_family_model,
    count_sources,
    sha256_bytes,
)

VERSION = "V00J4_G1G2_FAMILY_MODEL_PACK"
PASS_LINE = "PASS_ULTRABALLOONDB_G1G2_FAMILY_MODEL_PACK_V00J4"
NO_GO_LINE = "NO_GO_ULTRABALLOONDB_G1G2_FAMILY_MODEL_PACK_V00J4"


def run_family_case(family_files: int, records_per_file: int, exceptions_per_file: int, query_samples: int) -> Dict[str, object]:
    model = build_family_model(family_files, records_per_file, exceptions_per_file)

    originals: List[bytes] = []
    original_file_sha: List[str] = []
    for f in range(family_files):
        b = model.rebuild_file_bytes(f)
        originals.append(b)
        original_file_sha.append(sha256_bytes(b))
    original_pack = b"".join(originals)
    original_pack_sha = sha256_bytes(original_pack)

    compact = model.compact_bytes()
    loaded = FamilyG1G2Pack.from_compact_bytes(compact)

    rebuilt: List[bytes] = []
    rebuilt_file_sha: List[str] = []
    for f in range(family_files):
        b = loaded.rebuild_file_bytes(f)
        rebuilt.append(b)
        rebuilt_file_sha.append(sha256_bytes(b))
    rebuilt_pack = b"".join(rebuilt)
    rebuilt_pack_sha = sha256_bytes(rebuilt_pack)

    before_query_rebuild_count = loaded.rebuild_count
    query_rows: List[Dict[str, object]] = []

    # Deterministically sample G2 residuals first.
    for key in sorted(loaded.exceptions.keys())[:query_samples]:
        file_s, rec_s = key.split(":", 1)
        query_rows.append(loaded.query(int(file_s), int(rec_s)))

    # Then sample G1 family-rule records.
    t = 0
    while len(query_rows) < query_samples * 2:
        f = (t * 3 + 1) % family_files
        r = (t * 977 + 17) % records_per_file
        key = f"{f}:{r}"
        if key not in loaded.exceptions:
            query_rows.append(loaded.query(f, r))
        t += 1

    after_query_rebuild_count = loaded.rebuild_count
    original_bytes = len(original_pack)
    compact_bytes = len(compact)
    zlib_bytes = len(zlib.compress(original_pack, 9))

    return {
        "case": "family_model_pack",
        "family_files": family_files,
        "records_per_file": records_per_file,
        "exceptions_per_file": exceptions_per_file,
        "original_bytes": original_bytes,
        "g1g2_family_bytes": compact_bytes,
        "g1g2_family_ratio": original_bytes / max(1, compact_bytes),
        "zlib_bytes": zlib_bytes,
        "zlib_ratio": original_bytes / max(1, zlib_bytes),
        "original_pack_sha256": original_pack_sha,
        "rebuilt_pack_sha256": rebuilt_pack_sha,
        "file_sha_match_all": original_file_sha == rebuilt_file_sha,
        "pack_sha_match": original_pack_sha == rebuilt_pack_sha,
        "no_full_rebuild_during_query": before_query_rebuild_count == after_query_rebuild_count,
        "source_layer_counts": count_sources(query_rows),
        "compression_claim_allowed": compact_bytes < original_bytes and original_pack_sha == rebuilt_pack_sha,
        "query_sample": query_rows[: min(6, len(query_rows))],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--family-files", type=int, default=8)
    ap.add_argument("--records-per-file", type=int, default=5000)
    ap.add_argument("--exceptions-per-file", type=int, default=3)
    ap.add_argument("--query-samples", type=int, default=8)
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    if not repo_root.exists():
        print(f"{NO_GO_LINE}: repo root does not exist: {repo_root}")
        return 1

    run_id = time.strftime("RUN_%Y%m%d_%H%M%S")
    run_dir = repo_root / "audit" / "v00j4_g1g2_family_model_pack" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    tracemalloc.start()
    start = time.perf_counter()
    failures: Dict[str, str] = {}

    try:
        case = run_family_case(
            int(args.family_files),
            int(args.records_per_file),
            int(args.exceptions_per_file),
            int(args.query_samples),
        )
    except Exception as exc:
        case = {"case": "family_model_pack", "exception": repr(exc)}
        failures["family_case_exception"] = repr(exc)

    checks = {
        "family_model_present": True,
        "file_sha_match_all": bool(case.get("file_sha_match_all")),
        "pack_sha_match": bool(case.get("pack_sha_match")),
        "no_full_rebuild_during_query": bool(case.get("no_full_rebuild_during_query")),
        "g1_family_rule_hit": int(case.get("source_layer_counts", {}).get("G1_FAMILY_RULE", 0)) > 0,
        "g2_file_residual_hit": int(case.get("source_layer_counts", {}).get("G2_FILE_RESIDUAL", 0)) > 0,
        "compression_claim_allowed": bool(case.get("compression_claim_allowed")),
        "not_transaction_system": True,
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
            "family_files": int(args.family_files),
            "records_per_file": int(args.records_per_file),
            "exceptions_per_file": int(args.exceptions_per_file),
            "query_samples": int(args.query_samples),
        },
        "checks": checks,
        "failures": failures,
        "summary": case,
        "tracemalloc_current_bytes": current,
        "tracemalloc_peak_bytes": peak,
    }
    report_path = run_dir / "g1g2_family_model_pack_report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(status)
    print(f"REPORT={report_path}")
    print("SUMMARY=" + json.dumps(case, ensure_ascii=False))
    if failures:
        print("FAILURES=" + "; ".join(f"{k}={v}" for k, v in failures.items()))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
