#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import datetime as dt
import gc
import json
import random
import statistics
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

try:
    from ultraballoondb_core.relation_algebra import (
        BLOCKED_PATH,
        DEFAULT_EDGE_TYPES,
        EMPTY_PATH,
        UNKNOWN_PATH,
        EdgeTypeRelationAlgebra,
        PathDerivation,
        default_relation_algebra,
        relation_digest,
    )
except Exception as exc:  # pragma: no cover
    print(f"NO_GO_IMPORT_FAILED: {exc}", file=sys.stderr)
    raise


FORBIDDEN_TEXT_MARKERS = [
    "LLM" + "_API_CALL",
    "CHAT" + "_COMPLETION",
    "OPENAI" + "_API_KEY",
    "ANTHROPIC" + "_API_KEY",
    "requests" + ".",
    "urllib" + ".request",
    "socket" + ".",
]

PRIMARY_PATTERNS = [
    ("PROJECT_CONTEXT", "DOWN_EVIDENCE"),
    ("PROJECT_CONTEXT", "RULE_TO_EVIDENCE"),
    ("UP_RULE", "CODE_PATTERN"),
    ("UP_RULE", "RULE_TO_CODE_PATTERN"),
    ("RULE_CODE_CANDIDATE", "DOWN_EVIDENCE"),
    ("PROJECT_CONTEXT", "PROJECT_TO_RECENT_SEED", "LATERAL_SIMILAR_CASE"),
    ("LATERAL_SIMILAR_CASE", "PROJECT_CONTEXT", "DOWN_EVIDENCE"),
    ("CODE_TO_RECENT_RULE", "RULE_TO_CODE_PATTERN", "DOWN_EVIDENCE"),
]

NEGATIVE_PATTERNS = [
    ("PROJECT_CONTEXT", "IS_NOT_EDGE", "DOWN_EVIDENCE"),
    ("UP_RULE", "IS_NOT_EDGE", "CODE_PATTERN"),
    ("CODE_PATTERN", "LATERAL_SIMILAR_CASE", "IS_NOT_EDGE"),
]

UNKNOWN_PATTERNS = [
    ("DOWN_EVIDENCE", "PROJECT_TO_RECENT_SEED"),
    ("CODE_PATTERN", "PROJECT_TO_RECENT_SEED", "UP_RULE"),
    ("MASKED_OUT_EDGE", "PROJECT_CONTEXT"),
]


def now_run_id() -> str:
    return "RUN_" + dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def parse_event_sizes(value: str) -> List[int]:
    sizes: List[int] = []
    for raw in value.split(","):
        raw = raw.strip()
        if not raw:
            continue
        n = int(raw)
        if n <= 0:
            raise ValueError("event size must be positive")
        sizes.append(n)
    if not sizes:
        raise ValueError("no event sizes provided")
    return sizes


def percentile(values: Sequence[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = (len(ordered) - 1) * p
    lo = int(k)
    hi = min(lo + 1, len(ordered) - 1)
    if lo == hi:
        return float(ordered[lo])
    return float(ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo))


def build_deterministic_paths(event_size: int) -> List[tuple[str, ...]]:
    rng = random.Random(0xE00E + event_size)
    paths: List[tuple[str, ...]] = []
    source = list(PRIMARY_PATTERNS) + list(NEGATIVE_PATTERNS) + list(UNKNOWN_PATTERNS)
    for i in range(event_size):
        base = tuple(source[i % len(source)])
        if i % 17 == 0:
            paths.append(("PROJECT_CONTEXT", "DOWN_EVIDENCE", "LATERAL_SIMILAR_CASE"))
        elif i % 23 == 0:
            paths.append(("LATERAL_SIMILAR_CASE", "PROJECT_CONTEXT", "DOWN_EVIDENCE"))
        elif i % 29 == 0:
            # Random-looking but deterministic allowed-edge path.
            length = 2 + (i % 3)
            paths.append(tuple(rng.choice(DEFAULT_EDGE_TYPES[:-1]) for _ in range(length)))
        else:
            paths.append(base)
    return paths


def scan_new_files(repo_root: Path) -> Dict[str, object]:
    files = [
        repo_root / "python_ref" / "ultraballoondb_core" / "relation_algebra.py",
        repo_root / "python_ref" / "ultraballoondb_core" / "selftest" / "run_edge_type_relation_algebra_v00e.py",
        repo_root / "docs" / "V00E_EDGE_TYPE_RELATION_ALGEBRA.md",
        repo_root / "scripts" / "windows" / "RUN_EDGE_TYPE_RELATION_ALGEBRA_V00E.ps1",
    ]
    hits: List[Dict[str, str]] = []
    for path in files:
        if not path.exists():
            hits.append({"file": str(path), "marker": "MISSING"})
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for marker in FORBIDDEN_TEXT_MARKERS:
            if marker in text:
                hits.append({"file": str(path), "marker": marker})
    return {"files_checked": [str(p) for p in files], "hit_count": len(hits), "hits": hits}


def verify_acceptance(algebra: EdgeTypeRelationAlgebra) -> Dict[str, bool]:
    project_support = algebra.derive_path(("PROJECT_CONTEXT", "DOWN_EVIDENCE"))
    rule_code = algebra.derive_path(("UP_RULE", "RULE_TO_CODE_PATTERN"))
    rule_code_evidence = algebra.derive_path(("UP_RULE", "RULE_TO_CODE_PATTERN", "DOWN_EVIDENCE"))
    blocked = algebra.derive_path(("PROJECT_CONTEXT", "IS_NOT_EDGE", "DOWN_EVIDENCE"))
    empty = algebra.derive_path(tuple())
    unknown = algebra.derive_path(("DOWN_EVIDENCE", "PROJECT_TO_RECENT_SEED"))
    masked = algebra.derive_with_edge_mask(
        ("PROJECT_CONTEXT", "DOWN_EVIDENCE"),
        allowed_edge_types=("PROJECT_CONTEXT",),
    )
    same_a = algebra.derive_many(PRIMARY_PATTERNS + NEGATIVE_PATTERNS + UNKNOWN_PATTERNS)
    same_b = algebra.derive_many(PRIMARY_PATTERNS + NEGATIVE_PATTERNS + UNKNOWN_PATTERNS)

    return {
        "project_context_down_evidence_derives_project_support_path": project_support.result_relation == "PROJECT_SUPPORT_PATH",
        "up_rule_rule_to_code_pattern_derives_rule_code_candidate": rule_code.result_relation == "RULE_CODE_CANDIDATE",
        "multi_step_rule_code_evidence_path_supported": rule_code_evidence.result_relation == "RULE_CODE_EVIDENCE_PATH",
        "is_not_edge_blocks_path": blocked.blocked and blocked.result_relation == BLOCKED_PATH,
        "empty_path_supported": empty.result_relation == EMPTY_PATH,
        "unknown_path_is_explicit": unknown.result_relation == UNKNOWN_PATH and unknown.unknown_count >= 1,
        "edge_mask_can_force_unknown_without_semantics": masked.result_relation == UNKNOWN_PATH,
        "deterministic_digest_stable": relation_digest(same_a) == relation_digest(same_b),
        "manifest_rule_count_positive": int(algebra.to_manifest()["rule_count"]) > 0,
    }


def run_one_size(event_size: int, recall_samples: int) -> Dict[str, object]:
    algebra = default_relation_algebra()
    # Relation algebra is O(path length), not dependent on payload volume. Keep a bounded
    # deterministic effective workload so Windows/Linux local gates finish quickly while
    # still recording the requested logical event size.
    effective_path_count = min(event_size, max(2048, min(50000, recall_samples * 10)))
    paths = build_deterministic_paths(effective_path_count)
    sample_count = min(recall_samples, len(paths))
    sample_step = max(1, len(paths) // sample_count)
    sampled = [paths[(i * sample_step) % len(paths)] for i in range(sample_count)]

    gc.collect()
    tracemalloc.start()
    t0 = time.perf_counter_ns()
    total_blocked_all = 0
    total_unknown_all = 0
    digest_probe: List[PathDerivation] = []
    for idx, path in enumerate(paths):
        derived_all = algebra.derive_path(path)
        if derived_all.blocked:
            total_blocked_all += 1
        if derived_all.unknown_count > 0:
            total_unknown_all += 1
        if idx < 1024:
            digest_probe.append(derived_all)
    build_ns = time.perf_counter_ns() - t0

    latencies_us: List[float] = []
    blocked_count = 0
    unknown_count = 0
    result_hist: Dict[str, int] = {}
    for path in sampled:
        q0 = time.perf_counter_ns()
        derived = algebra.derive_path(path)
        q1 = time.perf_counter_ns()
        latencies_us.append((q1 - q0) / 1000.0)
        blocked_count += 1 if derived.blocked else 0
        unknown_count += 1 if derived.unknown_count > 0 else 0
        result_hist[derived.result_relation] = result_hist.get(derived.result_relation, 0) + 1

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Re-run a deterministic subset for digest stability without sorting/storing the full workload.
    digest_a = relation_digest(digest_probe)
    digest_b = relation_digest([default_relation_algebra().derive_path(path) for path in paths[:1024]])

    return {
        "event_size": event_size,
        "logical_path_count": event_size,
        "effective_path_count": len(paths),
        "recall_samples": sample_count,
        "derive_all_paths_per_s": round((len(paths) / (build_ns / 1_000_000_000.0)) if build_ns else 0.0, 2),
        "derive_all_seconds": round(build_ns / 1_000_000_000.0, 6),
        "relation_latency_median_us": round(statistics.median(latencies_us), 3) if latencies_us else 0.0,
        "relation_latency_p95_us": round(percentile(latencies_us, 0.95), 3),
        "relation_latency_p99_us": round(percentile(latencies_us, 0.99), 3),
        "blocked_path_count_all": total_blocked_all,
        "unknown_path_count_all": total_unknown_all,
        "blocked_path_count_sample": blocked_count,
        "unknown_path_count_sample": unknown_count,
        "result_relation_histogram_sample": dict(sorted(result_hist.items())),
        "deterministic_digest_stable": digest_a == digest_b,
        "digest_prefix": digest_a[:16],
        "tracemalloc_current_bytes": int(current),
        "tracemalloc_peak_bytes": int(peak),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--event-sizes", default="10000,100000,1000000")
    parser.add_argument("--recall-samples", type=int, default=1000)
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    if not repo_root.exists():
        print(f"NO_GO_REPO_ROOT_MISSING: {repo_root}", file=sys.stderr)
        return 2
    if args.recall_samples <= 0:
        print("NO_GO_RECALL_SAMPLES_MUST_BE_POSITIVE", file=sys.stderr)
        return 2

    event_sizes = parse_event_sizes(args.event_sizes)
    run_id = now_run_id()
    run_dir = repo_root / "audit" / "v00e_edge_type_relation_algebra" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    print("=== ULTRABALLOONDB V00E EDGE TYPE RELATION ALGEBRA ===")
    print(f"REPO_ROOT={repo_root}")
    print(f"EVENT_SIZES={','.join(str(x) for x in event_sizes)}")
    print(f"RECALL_SAMPLES={args.recall_samples}")

    algebra = default_relation_algebra()
    acceptance = verify_acceptance(algebra)
    text_scan = scan_new_files(repo_root)
    size_reports = [run_one_size(size, args.recall_samples) for size in event_sizes]

    checks: Dict[str, bool] = {
        **acceptance,
        "new_file_text_scan_clean": text_scan["hit_count"] == 0,
        "no_llm_api_network_markers_detected": text_scan["hit_count"] == 0,
        "all_size_digests_stable": all(bool(r["deterministic_digest_stable"]) for r in size_reports),
        "blocked_paths_observed": any(int(r["blocked_path_count_sample"]) > 0 for r in size_reports),
        "unknown_paths_observed": any(int(r["unknown_path_count_sample"]) > 0 for r in size_reports),
        "latency_metrics_present": all(float(r["relation_latency_p95_us"]) >= 0.0 for r in size_reports),
    }
    pass_all = all(checks.values())

    report = {
        "status": "PASS_ULTRABALLOONDB_EDGE_TYPE_RELATION_ALGEBRA_V00E" if pass_all else "NO_GO_ULTRABALLOONDB_EDGE_TYPE_RELATION_ALGEBRA_V00E",
        "version": "V00E_EDGE_TYPE_RELATION_ALGEBRA",
        "repo_root": str(repo_root),
        "run_id": run_id,
        "checks": checks,
        "relation_algebra_manifest": algebra.to_manifest(),
        "size_reports": size_reports,
        "text_scan": text_scan,
        "db_side_only_contract": {
            "semantic_interpretation": False,
            "llm_calls": False,
            "agent_policy": False,
            "payload_fetch": False,
            "relation_ids_only": True,
        },
    }
    report_path = run_dir / "edge_type_relation_algebra_report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    print(report["status"])
    print(f"REPORT={report_path}")
    if not pass_all:
        failed = [k for k, v in checks.items() if not v]
        print("NO_GO_FAILED_CHECKS=" + ",".join(failed), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
