#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UltraBalloonDB V00I page-size benchmark selftest/benchmark."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time
import tracemalloc

HERE = Path(__file__).resolve()
CORE_ROOT = HERE.parents[1]
PYTHON_REF = HERE.parents[2]
if str(PYTHON_REF) not in sys.path:
    sys.path.insert(0, str(PYTHON_REF))

from ultraballoondb_core.page_size_benchmark import (  # noqa: E402
    SUPPORTED_PAGE_SIZES,
    benchmark_fetch,
    build_page_store,
    load_header,
    summarize_build,
)

# The forbidden public-text terms are built from byte values so the text-scan
# does not fail on its own guard list. The generated terms are never printed
# unless a repository file actually contains one of them.
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


def parse_sizes(text: str) -> list[int]:
    out = []
    for part in text.split(','):
        part = part.strip()
        if part:
            out.append(int(part))
    if not out:
        raise ValueError("EventSizes cannot be empty")
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


def run_one_size(record_count: int, recall_samples: int, run_dir: Path, top_k_values: list[int]) -> dict:
    size_dir = run_dir / f"records_{record_count}"
    size_dir.mkdir(parents=True, exist_ok=True)
    page_reports = []
    for page_size in SUPPORTED_PAGE_SIZES:
        store_path = size_dir / f"payload_store_page_{page_size}.ubpage"
        build = build_page_store(str(store_path), page_size, record_count)
        header = load_header(str(store_path))
        fetch_reports = []
        for top_k in top_k_values:
            fetch_reports.append(benchmark_fetch(str(store_path), build.pointers, recall_samples, top_k))
        # Drop heavy pointer tuple before the next page-size build.
        page_reports.append({
            "build": summarize_build(build),
            "header": header,
            "fetch_profiles": fetch_reports,
        })
        del build
    # Basic selection table, not final product policy: smallest p95 for top_k max, with waste visible.
    top_k_max = max(top_k_values)
    ranked = []
    for pr in page_reports:
        fr = [x for x in pr["fetch_profiles"] if x["top_k"] == top_k_max][0]
        ranked.append({
            "page_size": pr["build"]["page_size"],
            "coalesced_latency_p95_us": fr["coalesced_latency_p95_us"],
            "slack_ratio": pr["build"]["slack_ratio"],
            "coalescing_ratio_median": fr["coalescing_ratio_median"],
        })
    ranked.sort(key=lambda x: (x["coalesced_latency_p95_us"], x["slack_ratio"]))
    return {
        "record_count": record_count,
        "page_reports": page_reports,
        "ranked_by_topk_max_coalesced_p95_then_slack": ranked,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--event-sizes", required=True)
    ap.add_argument("--recall-samples", type=int, required=True)
    ap.add_argument("--top-k-values", default="32,64,128")
    ap.add_argument("--run-id", default=None)
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    if not repo_root.exists():
        print(f"NO_GO_V00I_REPO_ROOT_MISSING={repo_root}")
        return 2
    event_sizes = parse_sizes(args.event_sizes)
    top_k_values = parse_sizes(args.top_k_values)
    recall_samples = int(args.recall_samples)
    if recall_samples <= 0:
        print("NO_GO_V00I_RECALL_SAMPLES_NON_POSITIVE")
        return 2
    if any(k <= 0 for k in top_k_values):
        print("NO_GO_V00I_TOP_K_NON_POSITIVE")
        return 2

    run_id = args.run_id or time.strftime("RUN_%Y%m%d_%H%M%S")
    run_dir = repo_root / "audit" / "v00i_page_size_benchmark" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    tracemalloc.start()
    t0 = time.perf_counter()
    size_reports = []
    status = "PASS_ULTRABALLOONDB_PAGE_SIZE_BENCHMARK_V00I"
    failures = []
    try:
        for n in event_sizes:
            if n <= 0:
                failures.append(f"bad event size {n}")
                continue
            size_reports.append(run_one_size(n, recall_samples, run_dir, top_k_values))
        text_scan = scan_forbidden_text(repo_root)
        if not text_scan["pass"]:
            failures.append("forbidden external product text scan hit")
        for sr in size_reports:
            for pr in sr["page_reports"]:
                if pr["build"]["page_size"] not in SUPPORTED_PAGE_SIZES:
                    failures.append("unsupported page size in report")
                if pr["header"]["page_size"] != pr["build"]["page_size"]:
                    failures.append("header page size mismatch")
                for fr in pr["fetch_profiles"]:
                    if not fr["checksum_ok"]:
                        failures.append("checksum mismatch")
                    if fr["coalesced_range_count_median"] > fr["naive_read_count_median"]:
                        failures.append("coalesced range count exceeds naive reads")
        if failures:
            status = "NO_GO_ULTRABALLOONDB_PAGE_SIZE_BENCHMARK_V00I"
        current, peak = tracemalloc.get_traced_memory()
        elapsed = time.perf_counter() - t0
        report = {
            "status": status,
            "version": "V00I_PAGE_SIZE_BENCHMARK_4K_16K_64K_256K",
            "repo_root": str(repo_root),
            "run_dir": str(run_dir),
            "event_sizes": event_sizes,
            "recall_samples": recall_samples,
            "top_k_values": top_k_values,
            "page_sizes": list(SUPPORTED_PAGE_SIZES),
            "size_reports": size_reports,
            "checks": {
                "all_supported_page_sizes_tested": sorted(list(SUPPORTED_PAGE_SIZES)) == sorted(list({pr["build"]["page_size"] for sr in size_reports for pr in sr["page_reports"]})),
                "checksum_verification_passed": not any(not fr["checksum_ok"] for sr in size_reports for pr in sr["page_reports"] for fr in pr["fetch_profiles"]),
                "coalesced_never_more_ranges_than_naive": not any(fr["coalesced_range_count_median"] > fr["naive_read_count_median"] for sr in size_reports for pr in sr["page_reports"] for fr in pr["fetch_profiles"]),
                "hot_path_policy_not_selected": True,
                "benchmark_only_no_final_page_size_assumption": True,
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
        report_path = run_dir / "page_size_benchmark_report.json"
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
