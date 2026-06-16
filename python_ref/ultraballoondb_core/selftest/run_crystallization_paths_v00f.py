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
from typing import Dict, Iterable, List, Sequence, Tuple

try:
    from ultraballoondb_core.crystallization import (
        ACTIVE,
        REVOKED,
        CrystalNode,
        CrystallizationConfig,
        CrystallizationPathBuilder,
        PathObservation,
        build_crystal_manifest,
        crystallization_digest,
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

PRIMARY_MOTIFS: Tuple[Tuple[str, ...], ...] = (
    ("PROJECT_CONTEXT", "DOWN_EVIDENCE"),
    ("UP_RULE", "RULE_TO_CODE_PATTERN", "DOWN_EVIDENCE"),
    ("PROJECT_CONTEXT", "PROJECT_TO_RECENT_SEED", "LATERAL_SIMILAR_CASE"),
    ("LATERAL_SIMILAR_CASE", "PROJECT_CONTEXT", "DOWN_EVIDENCE"),
    ("CODE_TO_RECENT_RULE", "RULE_TO_CODE_PATTERN", "DOWN_EVIDENCE"),
)

RARE_MOTIFS: Tuple[Tuple[str, ...], ...] = (
    ("DOWN_EVIDENCE", "PROJECT_TO_RECENT_SEED"),
    ("CODE_PATTERN", "PROJECT_TO_RECENT_SEED", "UP_RULE"),
    ("RULE_TO_EVIDENCE", "PROJECT_CONTEXT"),
    ("LATERAL_SIMILAR_CASE", "CODE_PATTERN"),
)

BLOCKED_MOTIFS: Tuple[Tuple[str, ...], ...] = (
    ("PROJECT_CONTEXT", "IS_NOT_EDGE", "DOWN_EVIDENCE"),
    ("UP_RULE", "IS_NOT_EDGE", "CODE_PATTERN"),
)


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


def build_observations(logical_event_size: int, effective_count: int) -> List[PathObservation]:
    rng = random.Random(0xF00F + logical_event_size)
    observations: List[PathObservation] = []
    for i in range(effective_count):
        if i % 31 == 0:
            motif = BLOCKED_MOTIFS[(i // 31) % len(BLOCKED_MOTIFS)]
            blocked = True
        elif i % 19 == 0:
            motif = RARE_MOTIFS[(i // 19) % len(RARE_MOTIFS)]
            blocked = False
        elif i % 7 == 0:
            motif = PRIMARY_MOTIFS[(i // 7) % len(PRIMARY_MOTIFS)]
            blocked = False
        else:
            motif = PRIMARY_MOTIFS[i % len(PRIMARY_MOTIFS)]
            blocked = False

        # Deterministic light jitter to create some low-support tails without semantics.
        if not blocked and i % 997 == 0:
            motif = tuple(list(motif) + [rng.choice(("CODE_PATTERN", "RULE_TO_EVIDENCE", "PROJECT_CONTEXT"))])

        observations.append(
            PathObservation(
                path_id=f"P{logical_event_size:08d}_{i:08d}",
                edge_types=tuple(motif),
                record_ids=(f"R{logical_event_size:08d}_{i:08d}", f"R{logical_event_size:08d}_{(i * 3) % max(1, effective_count):08d}"),
                weight=1.0 + ((i % 5) * 0.05),
                blocked=blocked,
            )
        )
    return observations


def scan_new_files(repo_root: Path) -> Dict[str, object]:
    files = [
        repo_root / "python_ref" / "ultraballoondb_core" / "crystallization.py",
        repo_root / "python_ref" / "ultraballoondb_core" / "selftest" / "run_crystallization_paths_v00f.py",
        repo_root / "docs" / "V00F_CRYSTALLIZATION_PATHS.md",
        repo_root / "scripts" / "windows" / "RUN_CRYSTALLIZATION_PATHS_V00F.ps1",
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


def verify_acceptance() -> Dict[str, bool]:
    cfg = CrystallizationConfig(min_support=3, min_weighted_support=3.0, max_crystals=16, max_provenance_links_per_crystal=8)
    builder = CrystallizationPathBuilder(cfg)
    observations = [
        PathObservation("P_A1", ("PROJECT_CONTEXT", "DOWN_EVIDENCE"), ("R_A1",)),
        PathObservation("P_A2", ("PROJECT_CONTEXT", "DOWN_EVIDENCE"), ("R_A2",)),
        PathObservation("P_A3", ("PROJECT_CONTEXT", "DOWN_EVIDENCE"), ("R_A3",)),
        PathObservation("P_B1", ("UP_RULE", "IS_NOT_EDGE", "CODE_PATTERN"), ("R_B1",), blocked=True),
        PathObservation("P_C1", ("CODE_PATTERN", "PROJECT_TO_RECENT_SEED"), ("R_C1",)),
    ]
    result_a = builder.crystallize(observations)
    result_b = builder.crystallize(list(observations))
    active = result_a.active_crystals()
    first = active[0] if active else None
    revoked = builder.revoke_crystal(first, reason="REVOCATION_SELFTEST", evidence_ids=("NEG_R1",)) if first else None

    return {
        "repeated_path_creates_crystal": bool(first and first.signature == ("PROJECT_CONTEXT", "DOWN_EVIDENCE")),
        "provenance_path_ids_preserved": bool(first and len(first.provenance_path_ids) >= 3),
        "provenance_record_ids_preserved": bool(first and len(first.provenance_record_ids) >= 3),
        "blocked_paths_not_crystallized": result_a.skipped_blocked_count == 1 and all("IS_NOT_EDGE" not in c.signature for c in result_a.crystals),
        "low_support_not_crystallized": all(c.signature != ("CODE_PATTERN", "PROJECT_TO_RECENT_SEED") for c in result_a.crystals),
        "deterministic_digest_stable": crystallization_digest(result_a.crystals) == crystallization_digest(result_b.crystals),
        "revocation_supported": bool(revoked and revoked.status == REVOKED and revoked.revocation_evidence_ids == ("NEG_R1",)),
        "active_crystal_status_supported": bool(first and first.status == ACTIVE),
        "archive_delete_operation_count_zero": result_a.archive_delete_operation_count == 0,
        "max_crystals_respected": len(result_a.crystals) <= cfg.max_crystals,
    }


def run_one_size(event_size: int, recall_samples: int) -> Dict[str, object]:
    effective_observation_count = min(event_size, max(4096, min(60000, recall_samples * 20)))
    observations = build_observations(event_size, effective_observation_count)
    cfg = CrystallizationConfig(min_support=8, min_weighted_support=8.0, max_crystals=256, max_provenance_links_per_crystal=64)
    builder = CrystallizationPathBuilder(cfg)

    gc.collect()
    tracemalloc.start()
    t0 = time.perf_counter_ns()
    result = builder.crystallize(observations)
    elapsed_ns = time.perf_counter_ns() - t0
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Query-like latency: crystallize bounded deterministic windows.
    latencies_us: List[float] = []
    window = min(128, len(observations))
    sample_count = min(recall_samples, 1000)
    for i in range(sample_count):
        start = (i * 37) % max(1, len(observations) - window + 1)
        subset = observations[start : start + window]
        q0 = time.perf_counter_ns()
        builder.crystallize(subset)
        q1 = time.perf_counter_ns()
        latencies_us.append((q1 - q0) / 1000.0)

    active = result.active_crystals()
    provenance_path_counts = [len(c.provenance_path_ids) for c in active]
    provenance_record_counts = [len(c.provenance_record_ids) for c in active]
    support_counts = [c.support_count for c in active]
    digest_a = builder.result_digest(result)
    digest_b = builder.result_digest(builder.crystallize(list(observations)))

    manifest = build_crystal_manifest(result, cfg)
    return {
        "event_size": event_size,
        "logical_observation_count": event_size,
        "effective_observation_count": len(observations),
        "recall_samples": sample_count,
        "crystallization_seconds": round(elapsed_ns / 1_000_000_000.0, 6),
        "crystallization_observations_per_s": round((len(observations) / (elapsed_ns / 1_000_000_000.0)) if elapsed_ns else 0.0, 2),
        "window_crystallization_latency_median_us": round(statistics.median(latencies_us), 3) if latencies_us else 0.0,
        "window_crystallization_latency_p95_us": round(percentile(latencies_us, 0.95), 3),
        "window_crystallization_latency_p99_us": round(percentile(latencies_us, 0.99), 3),
        "crystal_count": len(result.crystals),
        "active_crystal_count": len(active),
        "skipped_blocked_count": result.skipped_blocked_count,
        "skipped_low_support_count": result.skipped_low_support_count,
        "support_count_median": round(statistics.median(support_counts), 3) if support_counts else 0.0,
        "support_count_p95": round(percentile([float(x) for x in support_counts], 0.95), 3) if support_counts else 0.0,
        "provenance_path_links_median": round(statistics.median(provenance_path_counts), 3) if provenance_path_counts else 0.0,
        "provenance_record_links_median": round(statistics.median(provenance_record_counts), 3) if provenance_record_counts else 0.0,
        "archive_delete_operation_count": result.archive_delete_operation_count,
        "max_crystals_respected": len(result.crystals) <= cfg.max_crystals,
        "deterministic_digest_stable": digest_a == digest_b,
        "digest": digest_a,
        "manifest_digest": manifest["digest"],
        "tracemalloc_current_bytes": int(current),
        "tracemalloc_peak_bytes": int(peak),
    }


def write_json(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="UltraBalloonDB V00F crystallization paths selftest")
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--event-sizes", default="10000,100000,1000000")
    parser.add_argument("--recall-samples", type=int, default=1000)
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    event_sizes = parse_event_sizes(args.event_sizes)
    recall_samples = int(args.recall_samples)
    if recall_samples <= 0:
        raise ValueError("recall samples must be positive")

    run_id = now_run_id()
    run_dir = repo_root / "audit" / "v00f_crystallization_paths" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    acceptance = verify_acceptance()
    text_scan = scan_new_files(repo_root)

    size_reports: List[Dict[str, object]] = []
    for n in event_sizes:
        size_reports.append(run_one_size(n, recall_samples))

    checks: Dict[str, bool] = {
        **acceptance,
        "repo_text_scan_no_forbidden_markers": text_scan["hit_count"] == 0,
        "all_size_digests_stable": all(bool(x["deterministic_digest_stable"]) for x in size_reports),
        "all_size_max_crystals_respected": all(bool(x["max_crystals_respected"]) for x in size_reports),
        "all_size_archive_delete_zero": all(int(x["archive_delete_operation_count"]) == 0 for x in size_reports),
        "at_least_one_crystal_each_size": all(int(x["crystal_count"]) > 0 for x in size_reports),
        "blocked_paths_observed_and_skipped": all(int(x["skipped_blocked_count"]) > 0 for x in size_reports),
    }

    report: Dict[str, object] = {
        "schema": "ULTRABALLOONDB_V00F_CRYSTALLIZATION_PATHS_REPORT",
        "status": "PASS_ULTRABALLOONDB_CRYSTALLIZATION_PATHS_V00F" if all(checks.values()) else "NO_GO_ULTRABALLOONDB_CRYSTALLIZATION_PATHS_V00F",
        "run_id": run_id,
        "repo_root": str(repo_root),
        "event_sizes": event_sizes,
        "recall_samples": recall_samples,
        "checks": checks,
        "text_scan": text_scan,
        "size_reports": size_reports,
        "constraints": {
            "db_side_only": True,
            "semantic_interpretation": False,
            "llm_calls": False,
            "agent_policy_logic": False,
            "archive_delete_operation_count": 0,
            "lossless_archive_preserved": True,
        },
    }

    report_path = run_dir / "crystallization_paths_report.json"
    write_json(report_path, report)

    if report["status"] == "PASS_ULTRABALLOONDB_CRYSTALLIZATION_PATHS_V00F":
        print("PASS_ULTRABALLOONDB_CRYSTALLIZATION_PATHS_V00F")
        print(f"REPORT={report_path}")
        return 0

    print("NO_GO_ULTRABALLOONDB_CRYSTALLIZATION_PATHS_V00F", file=sys.stderr)
    print(f"REPORT={report_path}", file=sys.stderr)
    failed = [k for k, v in checks.items() if not v]
    print("FAILED_CHECKS=" + json.dumps(failed), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
