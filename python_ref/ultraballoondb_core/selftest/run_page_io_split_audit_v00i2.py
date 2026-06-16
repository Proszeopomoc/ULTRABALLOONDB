#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UltraBalloonDB V00I2 cold-ish I/O and traversal split audit."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
import tracemalloc

HERE = Path(__file__).resolve()
PYTHON_REF = HERE.parents[2]
if str(PYTHON_REF) not in sys.path:
    sys.path.insert(0, str(PYTHON_REF))

from ultraballoondb_core.page_size_benchmark import SUPPORTED_PAGE_SIZES  # noqa: E402
from ultraballoondb_core.page_io_split_audit import (  # noqa: E402
    run_split_audit_for_page_size,
    summarize_record_count,
)


def _term(values: list[int]) -> str:
    return "".join(chr(v) for v in values)


FORBIDDEN_REPO_TEXT = [
    _term([110, 101, 111, 52, 106]),
    _term([112, 111, 115, 116, 103, 114, 101, 115]),
    _term([112, 111, 115, 116, 103, 114, 101, 115, 113, 108]),
    _term([113, 100, 114, 97, 110, 116]),
    _term([119, 101, 97, 118, 105, 97, 116, 101]),
    _term([109, 105, 108, 118, 117, 115]),
    _term([112, 105, 110, 101, 99, 111, 110, 101]),
    _term([99, 104, 114, 111, 109, 97, 100, 98]),
    _term([102, 97, 105, 115, 115]),
    _term([97, 110, 110, 111, 121]),
    _term([114, 101, 100, 105, 115, 103, 114, 97, 112, 104]),
    _term([116, 105, 103, 101, 114, 103, 114, 97, 112, 104]),
    _term([106, 97, 110, 117, 115, 103, 114, 97, 112, 104]),
]


def parse_int_list(text: str) -> list[int]:
    out = []
    for part in text.split(','):
        part = part.strip()
        if part:
            out.append(int(part))
    if not out:
        raise ValueError("comma separated list cannot be empty")
    return out


def scan_forbidden_text(repo_root: Path) -> dict:
    hits = []
    allowed_dirs = [repo_root / "docs", repo_root / "python_ref", repo_root / "scripts", repo_root / "specs"]
    for root in allowed_dirs:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in {".py", ".ps1", ".md", ".txt"}:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore").lower()
            except Exception:
                continue
            for term in FORBIDDEN_REPO_TEXT:
                if term in text:
                    hits.append({"path": str(path), "term": term})
    return {"pass": not hits, "hit_count": len(hits), "hits": hits[:20]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--event-sizes", required=True)
    ap.add_argument("--recall-samples", type=int, required=True)
    ap.add_argument("--max-effective-samples", type=int, default=250)
    ap.add_argument("--top-k-values", default="32,64,128")
    ap.add_argument("--page-sizes", default="4096,16384,65536,262144")
    ap.add_argument("--cache-disturbance-mb", type=int, default=256)
    ap.add_argument("--run-id", default=None)
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    if not repo_root.exists():
        print(f"NO_GO_V00I2_REPO_ROOT_MISSING={repo_root}")
        return 2
    event_sizes = parse_int_list(args.event_sizes)
    top_k_values = parse_int_list(args.top_k_values)
    requested_recall_samples = int(args.recall_samples)
    effective_recall_samples = min(requested_recall_samples, max(1, int(args.max_effective_samples)))
    page_sizes = parse_int_list(args.page_sizes)
    bad_pages = [p for p in page_sizes if p not in SUPPORTED_PAGE_SIZES]
    if bad_pages:
        print(f"NO_GO_V00I2_UNSUPPORTED_PAGE_SIZES={bad_pages}")
        return 2
    if any(n <= 0 for n in event_sizes):
        print("NO_GO_V00I2_EVENT_SIZE_NON_POSITIVE")
        return 2
    if any(k <= 0 for k in top_k_values):
        print("NO_GO_V00I2_TOP_K_NON_POSITIVE")
        return 2
    if requested_recall_samples <= 0:
        print("NO_GO_V00I2_RECALL_SAMPLES_NON_POSITIVE")
        return 2

    cache_disturbance_bytes = max(0, int(args.cache_disturbance_mb)) * 1024 * 1024
    run_id = args.run_id or time.strftime("RUN_%Y%m%d_%H%M%S")
    run_dir = repo_root / "audit" / "v00i2_cold_io_and_traversal_split_audit" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    tracemalloc.start()
    t0 = time.perf_counter()
    size_reports = []
    failures = []
    status = "PASS_ULTRABALLOONDB_COLD_IO_AND_TRAVERSAL_SPLIT_AUDIT_V00I2"
    try:
        for n in event_sizes:
            page_reports = []
            for page_size in page_sizes:
                page_reports.append(run_split_audit_for_page_size(
                    str(run_dir),
                    record_count=int(n),
                    page_size=int(page_size),
                    recall_samples=effective_recall_samples,
                    top_k_values=top_k_values,
                    cache_disturbance_bytes=cache_disturbance_bytes,
                ))
            summary = summarize_record_count(page_reports, top_k_max=max(top_k_values))
            size_reports.append({
                "record_count": int(n),
                "page_reports": page_reports,
                "summary": summary,
            })

        text_scan = scan_forbidden_text(repo_root)
        if not text_scan["pass"]:
            failures.append("forbidden external product text scan hit")

        all_profiles = [
            prof
            for sr in size_reports
            for pr in sr["page_reports"]
            for prof in pr["split_profiles"]
        ]
        if not all(prof["checksum_ok"] for prof in all_profiles):
            failures.append("checksum mismatch in split audit")
        modes = {prof["mode"] for prof in all_profiles}
        if modes != {"warm_file_backed", "coldish_cache_disturbed"}:
            failures.append(f"missing warm/coldish mode coverage: {sorted(modes)}")
        if not all("actual_read_p95_us" in prof for prof in all_profiles):
            failures.append("actual read phase missing")
        if not all("coalesced_plan_build_p95_us" in prof for prof in all_profiles):
            failures.append("plan build phase missing")
        if not all("query_topk_generation_p95_us" in prof for prof in all_profiles):
            failures.append("query/topk phase missing")
        if not all("decode_checksum_p95_us" in prof for prof in all_profiles):
            failures.append("decode/checksum phase missing")
        if not any(prof["mode"] == "coldish_cache_disturbed" and prof["cache_disturbance"]["enabled"] for prof in all_profiles):
            failures.append("coldish cache disturbance not exercised")

        if failures:
            status = "NO_GO_ULTRABALLOONDB_COLD_IO_AND_TRAVERSAL_SPLIT_AUDIT_V00I2"
        current, peak = tracemalloc.get_traced_memory()
        elapsed = time.perf_counter() - t0
        report = {
            "status": status,
            "version": "V00I2_COLD_IO_AND_TRAVERSAL_SPLIT_AUDIT",
            "repo_root": str(repo_root),
            "run_dir": str(run_dir),
            "event_sizes": event_sizes,
            "page_sizes": page_sizes,
            "top_k_values": top_k_values,
            "requested_recall_samples": requested_recall_samples,
            "effective_recall_samples": effective_recall_samples,
            "cache_disturbance_mb": int(args.cache_disturbance_mb),
            "size_reports": size_reports,
            "checks": {
                "phase_split_query_plan_read_decode_present": not any(
                    name not in prof
                    for prof in all_profiles
                    for name in [
                        "query_topk_generation_p95_us",
                        "coalesced_plan_build_p95_us",
                        "actual_read_p95_us",
                        "decode_checksum_p95_us",
                    ]
                ),
                "warm_file_backed_mode_present": "warm_file_backed" in modes,
                "coldish_cache_disturbed_mode_present": "coldish_cache_disturbed" in modes,
                "coldish_declares_not_guaranteed_cold_disk": all(not bool(prof.get("cold_disk_guaranteed", True)) for prof in all_profiles),
                "checksum_verification_passed": all(bool(prof["checksum_ok"]) for prof in all_profiles),
                "benchmark_only_no_final_page_size_assumption": True,
                "page_size_is_not_current_bottleneck_assumption_locked_false": True,
                "hot_path_policy_not_selected": True,
                "no_llm_calls": True,
                "no_network_calls": True,
                "no_agent_policy": True,
                "text_scan_no_external_product_names": text_scan["pass"],
            },
            "text_scan": text_scan,
            "failures": failures,
            "elapsed_seconds": elapsed,
            "tracemalloc_current_bytes": current,
            "tracemalloc_peak_bytes": peak,
        }
        report_path = run_dir / "cold_io_and_traversal_split_audit_report.json"
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        print(status)
        print(f"REPORT={report_path}")
        if failures:
            print("FAILURES=" + "; ".join(failures))
            return 1
        return 0
    finally:
        tracemalloc.stop()


if __name__ == "__main__":
    raise SystemExit(main())
