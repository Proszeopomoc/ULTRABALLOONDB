#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UltraBalloonDB V00I2 page I/O split audit core.

This module is database-side and semantic-blind. It splits measured time into:
query/top_k id generation, coalesced plan build, actual file-backed read,
and decode/checksum verification. It does not select final page-size policy.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import time
from typing import Dict, List, Sequence, Tuple

from ultraballoondb_core.page_size_benchmark import (
    CoalescedReadRange,
    PageRecordPointer,
    RECORD_LEN_STRUCT,
    SUPPORTED_PAGE_SIZES,
    _portable_pread,
    build_coalesced_plan,
    build_page_store,
    deterministic_payload,
    deterministic_query_ids,
    load_header,
    percentile_us,
    summarize_build,
)


@dataclass(frozen=True, slots=True)
class SplitReadBlocks:
    plan: Tuple[CoalescedReadRange, ...]
    blocks: Tuple[bytes, ...]
    bytes_read: int


def median_float(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    xs = sorted(values)
    n = len(xs)
    mid = n // 2
    if n % 2:
        return float(xs[mid])
    return float((xs[mid - 1] + xs[mid]) / 2.0)


def ensure_cache_disturbance_file(path: str, size_bytes: int) -> Dict[str, int | str | bool]:
    """Create a deterministic cache-disturbance file if requested.

    This is not a true OS cache flush. It is an explicit, measurable attempt to
    disturb the filesystem cache before a cold-ish profile.
    """
    if size_bytes <= 0:
        return {"enabled": False, "path": path, "size_bytes": 0, "sha256": ""}
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path) and os.path.getsize(path) == size_bytes:
        return {"enabled": True, "path": path, "size_bytes": int(size_bytes), "sha256": sha256_file(path)}
    seed = hashlib.blake2b(b"UBDB-V00I2-CACHE-DISTURBANCE", digest_size=64).digest()
    chunk = seed * (1024 * 1024 // len(seed))
    written = 0
    with open(path, "wb") as f:
        while written < size_bytes:
            take = min(len(chunk), size_bytes - written)
            f.write(chunk[:take])
            written += take
        f.flush()
        os.fsync(f.fileno())
    return {"enabled": True, "path": path, "size_bytes": int(size_bytes), "sha256": sha256_file(path)}


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest().upper()


def disturb_cache_once(path: str, bytes_to_read: int) -> Dict[str, float | int | str | bool]:
    """Read a side file to disturb warm cache. This is cold-ish, not guaranteed cold."""
    if bytes_to_read <= 0 or not os.path.exists(path):
        return {
            "enabled": False,
            "bytes_requested": int(max(0, bytes_to_read)),
            "bytes_read": 0,
            "elapsed_ms": 0.0,
            "sha256_prefix": "",
            "guaranteed_cold_disk": False,
        }
    h = hashlib.sha256()
    total = 0
    t0 = time.perf_counter()
    with open(path, "rb") as f:
        while total < bytes_to_read:
            chunk = f.read(min(1024 * 1024, bytes_to_read - total))
            if not chunk:
                break
            total += len(chunk)
            h.update(chunk)
    elapsed = time.perf_counter() - t0
    return {
        "enabled": True,
        "bytes_requested": int(bytes_to_read),
        "bytes_read": int(total),
        "elapsed_ms": elapsed * 1000.0,
        "sha256_prefix": h.hexdigest().upper()[:16],
        "guaranteed_cold_disk": False,
    }


def read_coalesced_blocks_fd(fd: int, plan: Sequence[CoalescedReadRange]) -> SplitReadBlocks:
    blocks: List[bytes] = []
    total = 0
    for rr in plan:
        block = _portable_pread(fd, rr.length, rr.start)
        if len(block) != rr.length:
            raise IOError("short coalesced read in V00I2")
        blocks.append(block)
        total += len(block)
    return SplitReadBlocks(plan=tuple(plan), blocks=tuple(blocks), bytes_read=total)


def decode_and_verify_blocks(blocks: SplitReadBlocks, selected: Sequence[PageRecordPointer]) -> bool:
    ok = True
    for rr, block in zip(blocks.plan, blocks.blocks):
        for idx in rr.pointer_indices:
            ptr = selected[idx]
            rel = ptr.absolute_offset - rr.start
            raw = block[rel:rel + ptr.stored_length]
            if len(raw) != ptr.stored_length:
                ok = False
                continue
            (n,) = RECORD_LEN_STRUCT.unpack(raw[:RECORD_LEN_STRUCT.size])
            payload = raw[RECORD_LEN_STRUCT.size:]
            if n != ptr.payload_length or payload != deterministic_payload(ptr.record_id):
                ok = False
    return ok


def measure_split_profile(
    path: str,
    pointers: Sequence[PageRecordPointer],
    recall_samples: int,
    top_k: int,
    mode: str,
    cache_disturbance_path: str = "",
    cache_disturbance_bytes: int = 0,
) -> Dict[str, float | int | bool | str | dict]:
    if mode not in {"warm_file_backed", "coldish_cache_disturbed"}:
        raise ValueError(f"unsupported split audit mode: {mode}")
    if recall_samples <= 0:
        raise ValueError("recall_samples must be positive")
    if top_k <= 0:
        raise ValueError("top_k must be positive")

    disturbance_report: Dict[str, float | int | str | bool]
    if mode == "coldish_cache_disturbed":
        disturbance_report = disturb_cache_once(cache_disturbance_path, cache_disturbance_bytes)
    else:
        disturbance_report = {
            "enabled": False,
            "bytes_requested": 0,
            "bytes_read": 0,
            "elapsed_ms": 0.0,
            "sha256_prefix": "",
            "guaranteed_cold_disk": False,
        }

    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:
        query_times: List[float] = []
        plan_times: List[float] = []
        actual_read_times: List[float] = []
        decode_times: List[float] = []
        total_times: List[float] = []
        range_counts: List[float] = []
        selected_counts: List[float] = []
        bytes_read_values: List[float] = []
        checksum_ok = True
        for s in range(recall_samples):
            t0 = time.perf_counter()
            ids = deterministic_query_ids(len(pointers), s, top_k)
            selected = [pointers[i] for i in ids]
            t1 = time.perf_counter()
            plan = build_coalesced_plan(selected, max_gap_bytes=0)
            t2 = time.perf_counter()
            blocks = read_coalesced_blocks_fd(fd, plan)
            t3 = time.perf_counter()
            ok = decode_and_verify_blocks(blocks, selected)
            t4 = time.perf_counter()
            checksum_ok = checksum_ok and ok
            query_times.append(t1 - t0)
            plan_times.append(t2 - t1)
            actual_read_times.append(t3 - t2)
            decode_times.append(t4 - t3)
            total_times.append(t4 - t0)
            range_counts.append(float(len(plan)))
            selected_counts.append(float(len(selected)))
            bytes_read_values.append(float(blocks.bytes_read))

        phase_p95s = {
            "query_topk_generation_p95_us": percentile_us(query_times, 0.95),
            "coalesced_plan_build_p95_us": percentile_us(plan_times, 0.95),
            "actual_read_p95_us": percentile_us(actual_read_times, 0.95),
            "decode_checksum_p95_us": percentile_us(decode_times, 0.95),
        }
        dominant_phase = max(phase_p95s.items(), key=lambda item: item[1])[0].replace("_p95_us", "")
        total_p95 = percentile_us(total_times, 0.95)
        actual_read_share = phase_p95s["actual_read_p95_us"] / max(1e-12, total_p95)
        return {
            "mode": mode,
            "top_k": int(top_k),
            "recall_samples": int(recall_samples),
            "checksum_ok": bool(checksum_ok),
            "query_topk_generation_p50_us": percentile_us(query_times, 0.50),
            "query_topk_generation_p95_us": phase_p95s["query_topk_generation_p95_us"],
            "query_topk_generation_p99_us": percentile_us(query_times, 0.99),
            "coalesced_plan_build_p50_us": percentile_us(plan_times, 0.50),
            "coalesced_plan_build_p95_us": phase_p95s["coalesced_plan_build_p95_us"],
            "coalesced_plan_build_p99_us": percentile_us(plan_times, 0.99),
            "actual_read_p50_us": percentile_us(actual_read_times, 0.50),
            "actual_read_p95_us": phase_p95s["actual_read_p95_us"],
            "actual_read_p99_us": percentile_us(actual_read_times, 0.99),
            "decode_checksum_p50_us": percentile_us(decode_times, 0.50),
            "decode_checksum_p95_us": phase_p95s["decode_checksum_p95_us"],
            "decode_checksum_p99_us": percentile_us(decode_times, 0.99),
            "total_context_p50_us": percentile_us(total_times, 0.50),
            "total_context_p95_us": total_p95,
            "total_context_p99_us": percentile_us(total_times, 0.99),
            "dominant_phase_by_p95": dominant_phase,
            "actual_read_share_of_total_p95": actual_read_share,
            "coalesced_range_count_median": median_float(range_counts),
            "selected_count_median": median_float(selected_counts),
            "coalescing_ratio_median": median_float(range_counts) / max(1.0, median_float(selected_counts)),
            "bytes_read_median": median_float(bytes_read_values),
            "cache_disturbance": disturbance_report,
            "cold_disk_guaranteed": False,
        }
    finally:
        os.close(fd)


def run_split_audit_for_page_size(
    run_dir: str,
    record_count: int,
    page_size: int,
    recall_samples: int,
    top_k_values: Sequence[int],
    cache_disturbance_bytes: int,
) -> Dict[str, object]:
    size_dir = os.path.join(run_dir, f"records_{record_count}")
    os.makedirs(size_dir, exist_ok=True)
    store_path = os.path.join(size_dir, f"payload_store_page_{page_size}.ubpage")
    build = build_page_store(store_path, page_size, record_count)
    header = load_header(store_path)
    disturbance_path = os.path.join(size_dir, f"cache_disturbance_{cache_disturbance_bytes}.bin")
    disturbance_file = ensure_cache_disturbance_file(disturbance_path, cache_disturbance_bytes)

    profiles: List[Dict[str, object]] = []
    for top_k in top_k_values:
        profiles.append(measure_split_profile(
            store_path,
            build.pointers,
            recall_samples,
            int(top_k),
            mode="warm_file_backed",
        ))
        profiles.append(measure_split_profile(
            store_path,
            build.pointers,
            recall_samples,
            int(top_k),
            mode="coldish_cache_disturbed",
            cache_disturbance_path=disturbance_path,
            cache_disturbance_bytes=cache_disturbance_bytes,
        ))

    return {
        "build": summarize_build(build),
        "header": header,
        "cache_disturbance_file": disturbance_file,
        "split_profiles": profiles,
    }


def summarize_record_count(page_reports: Sequence[Dict[str, object]], top_k_max: int) -> Dict[str, object]:
    ranking = []
    dominant_counts: Dict[str, int] = {}
    for pr in page_reports:
        build = pr["build"]  # type: ignore[index]
        for prof in pr["split_profiles"]:  # type: ignore[index]
            if int(prof["top_k"]) != int(top_k_max):  # type: ignore[index]
                continue
            phase = str(prof["dominant_phase_by_p95"])  # type: ignore[index]
            dominant_counts[phase] = dominant_counts.get(phase, 0) + 1
            ranking.append({
                "page_size": build["page_size"],  # type: ignore[index]
                "mode": prof["mode"],  # type: ignore[index]
                "top_k": prof["top_k"],  # type: ignore[index]
                "total_context_p95_us": prof["total_context_p95_us"],  # type: ignore[index]
                "actual_read_p95_us": prof["actual_read_p95_us"],  # type: ignore[index]
                "actual_read_share_of_total_p95": prof["actual_read_share_of_total_p95"],  # type: ignore[index]
                "dominant_phase_by_p95": phase,
                "slack_ratio": build["slack_ratio"],  # type: ignore[index]
            })
    ranking.sort(key=lambda x: (float(x["total_context_p95_us"]), float(x["actual_read_p95_us"]), float(x["slack_ratio"])))
    return {
        "ranked_by_topk_max_total_p95_then_read_then_slack": ranking,
        "dominant_phase_counts_at_topk_max": dominant_counts,
        "final_page_size_selected": False,
    }
