#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UltraBalloonDB V00I3 decode/checksum hot-path split.

This module is database-core measurement code only. It does not perform
semantic interpretation, agent planning, network calls, or model calls.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import random
import struct
import time
import zlib
from typing import Dict, Iterable, List, Sequence, Tuple

RECORD_MAGIC = b"UBR3"
RECORD_VERSION = 1
# magic, version, flags, record_id, payload_len, checksum, aux
RECORD_HEADER = struct.Struct("<4sHHQIIQ")
RECORD_HEADER_SIZE = RECORD_HEADER.size


@dataclass(frozen=True)
class PayloadPointer:
    record_id: int
    offset: int
    length: int
    page_id: int
    page_size: int


@dataclass(frozen=True)
class CoalescedRange:
    offset: int
    length: int
    pointer_indices: Tuple[int, ...]


def now_ns() -> int:
    return time.perf_counter_ns()


def ns_to_us(ns: int) -> float:
    return ns / 1000.0


def percentile(values: Sequence[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    idx = (len(ordered) - 1) * p
    lo = int(idx)
    hi = min(lo + 1, len(ordered) - 1)
    frac = idx - lo
    return ordered[lo] * (1.0 - frac) + ordered[hi] * frac


def stable_payload(record_id: int, payload_size: int) -> bytes:
    # Deterministic non-semantic bytes. The pattern avoids compression tricks.
    seed = (record_id * 11400714819323198485) & 0xFFFFFFFFFFFFFFFF
    out = bytearray(payload_size)
    x = seed
    for i in range(payload_size):
        x ^= (x << 13) & 0xFFFFFFFFFFFFFFFF
        x ^= (x >> 7)
        x ^= (x << 17) & 0xFFFFFFFFFFFFFFFF
        out[i] = (x + i + record_id) & 0xFF
    return bytes(out)


def make_record(record_id: int, payload_size: int) -> bytes:
    payload = stable_payload(record_id, payload_size)
    checksum = zlib.crc32(payload) & 0xFFFFFFFF
    header = RECORD_HEADER.pack(
        RECORD_MAGIC,
        RECORD_VERSION,
        0,
        int(record_id),
        len(payload),
        checksum,
        (record_id ^ payload_size) & 0xFFFFFFFFFFFFFFFF,
    )
    return header + payload


def build_page_store(path: Path, record_count: int, page_size: int, payload_size: int = 96) -> List[PayloadPointer]:
    """Write a deterministic page store and return record pointers.

    Records never cross page boundaries. This makes page-size slack measurable
    while keeping decode/checksum measurements focused and deterministic.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    pointers: List[PayloadPointer] = []
    offset = 0
    page_id = 0
    in_page = 0
    with path.open("wb") as f:
        for rid in range(record_count):
            rec = make_record(rid, payload_size)
            if len(rec) > page_size:
                raise ValueError(f"record length {len(rec)} exceeds page size {page_size}")
            if in_page + len(rec) > page_size:
                pad = page_size - in_page
                if pad:
                    f.write(b"\x00" * pad)
                    offset += pad
                page_id += 1
                in_page = 0
            pointers.append(PayloadPointer(rid, offset, len(rec), page_id, page_size))
            f.write(rec)
            offset += len(rec)
            in_page += len(rec)
        if in_page:
            f.write(b"\x00" * (page_size - in_page))
    try:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        # Some platforms do not allow fsync on read-only fd. The file exists and
        # the benchmark remains file-backed; cache state is reported separately.
        pass
    return pointers


def portable_pread(fd: int, length: int, offset: int) -> bytes:
    pread = getattr(os, "pread", None)
    if pread is not None:
        return pread(fd, length, offset)
    os.lseek(fd, offset, os.SEEK_SET)
    chunks = []
    remaining = length
    while remaining > 0:
        data = os.read(fd, remaining)
        if not data:
            break
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def make_topk_indices(record_count: int, sample_index: int, top_k: int) -> List[int]:
    # Deterministic pseudo-random top_k without replacement for stable tests.
    rng = random.Random((record_count << 16) ^ (sample_index * 1315423911) ^ top_k)
    if top_k >= record_count:
        return list(range(record_count))
    return sorted(rng.sample(range(record_count), top_k))


def coalesce_pointers(pointers: Sequence[PayloadPointer], max_gap_bytes: int = 0) -> List[CoalescedRange]:
    if not pointers:
        return []
    indexed = sorted(enumerate(pointers), key=lambda x: (x[1].offset, x[1].length))
    ranges: List[CoalescedRange] = []
    start = indexed[0][1].offset
    end = indexed[0][1].offset + indexed[0][1].length
    ids = [indexed[0][0]]
    for idx, ptr in indexed[1:]:
        ptr_start = ptr.offset
        ptr_end = ptr.offset + ptr.length
        if ptr_start <= end + max_gap_bytes:
            end = max(end, ptr_end)
            ids.append(idx)
        else:
            ranges.append(CoalescedRange(start, end - start, tuple(ids)))
            start, end, ids = ptr_start, ptr_end, [idx]
    ranges.append(CoalescedRange(start, end - start, tuple(ids)))
    return ranges


def read_coalesced(fd: int, ranges: Sequence[CoalescedRange]) -> List[Tuple[CoalescedRange, bytes]]:
    return [(r, portable_pread(fd, r.length, r.offset)) for r in ranges]


def slice_records(selected: Sequence[PayloadPointer], chunks: Sequence[Tuple[CoalescedRange, bytes]]) -> List[bytes]:
    out: List[bytes] = [b""] * len(selected)
    for rng, data in chunks:
        for ptr_idx in rng.pointer_indices:
            ptr = selected[ptr_idx]
            rel = ptr.offset - rng.offset
            out[ptr_idx] = bytes(data[rel : rel + ptr.length])
    return out


def header_parse(records: Sequence[bytes]) -> List[Tuple[int, int, int]]:
    parsed: List[Tuple[int, int, int]] = []
    for rec in records:
        magic, version, _flags, record_id, payload_len, checksum, _aux = RECORD_HEADER.unpack_from(rec, 0)
        if magic != RECORD_MAGIC or version != RECORD_VERSION:
            raise ValueError("bad record header")
        parsed.append((int(record_id), int(payload_len), int(checksum)))
    return parsed


def decode_records(records: Sequence[bytes], parsed_headers: Sequence[Tuple[int, int, int]]) -> int:
    # Fixed binary decode simulation: derive numeric evidence from byte payloads,
    # without constructing semantic objects.
    acc = 0
    for rec, (record_id, payload_len, _checksum) in zip(records, parsed_headers):
        payload = rec[RECORD_HEADER_SIZE : RECORD_HEADER_SIZE + payload_len]
        if payload_len:
            acc ^= (payload[0] << 1) ^ payload[-1] ^ (record_id & 0xFF)
        else:
            acc ^= record_id & 0xFF
    return acc


def verify_checksums(records: Sequence[bytes], parsed_headers: Sequence[Tuple[int, int, int]], mode: str) -> Tuple[int, int]:
    """Return (verified_count, checksum_accumulator)."""
    verified = 0
    acc = 0
    if mode == "checksum_disabled_trusted_hot_snapshot":
        return 0, 0
    stride = 1
    if mode == "checksum_sampled_1_of_8":
        stride = 8
    elif mode != "checksum_full":
        raise ValueError(f"unknown checksum mode: {mode}")
    for i, (rec, (_record_id, payload_len, expected)) in enumerate(zip(records, parsed_headers)):
        if i % stride != 0:
            continue
        payload = rec[RECORD_HEADER_SIZE : RECORD_HEADER_SIZE + payload_len]
        got = zlib.crc32(payload) & 0xFFFFFFFF
        if got != expected:
            raise ValueError("checksum mismatch")
        acc ^= got
        verified += 1
    return verified, acc


def benchmark_once(
    fd: int,
    pointers: Sequence[PayloadPointer],
    sample_index: int,
    top_k: int,
    checksum_mode: str,
) -> Dict[str, float | str | int]:
    t0 = now_ns()
    idxs = make_topk_indices(len(pointers), sample_index, top_k)
    selected = [pointers[i] for i in idxs]
    t1 = now_ns()

    ranges = coalesce_pointers(selected)
    t2 = now_ns()

    chunks = read_coalesced(fd, ranges)
    t3 = now_ns()

    records = slice_records(selected, chunks)
    t4 = now_ns()

    # Isolate Python loop overhead with minimal work on the exact same cardinality.
    dummy = 0
    loop_start = now_ns()
    for _ in records:
        dummy += 1
    loop_end = now_ns()

    parsed = header_parse(records)
    t5 = now_ns()

    decode_acc = decode_records(records, parsed)
    t6 = now_ns()

    verified_count, checksum_acc = verify_checksums(records, parsed, checksum_mode)
    t7 = now_ns()

    phases = {
        "query_topk_generation_us": ns_to_us(t1 - t0),
        "coalesced_plan_build_us": ns_to_us(t2 - t1),
        "actual_read_us": ns_to_us(t3 - t2),
        "slice_copy_us": ns_to_us(t4 - t3),
        "python_loop_overhead_us": ns_to_us(loop_end - loop_start),
        "header_parse_us": ns_to_us(t5 - loop_end),
        "record_decode_us": ns_to_us(t6 - t5),
        "checksum_us": ns_to_us(t7 - t6),
    }
    total = sum(phases.values())
    dominant_phase = max(phases, key=phases.get)
    return {
        **phases,
        "total_context_us": total,
        "dominant_phase": dominant_phase.replace("_us", ""),
        "range_count": len(ranges),
        "record_count": len(records),
        "verified_count": verified_count,
        "checksum_acc": checksum_acc,
        "decode_acc": decode_acc ^ dummy,
    }


def summarize_samples(samples: Sequence[Dict[str, float | str | int]]) -> Dict[str, object]:
    numeric_keys = [
        "query_topk_generation_us",
        "coalesced_plan_build_us",
        "actual_read_us",
        "slice_copy_us",
        "python_loop_overhead_us",
        "header_parse_us",
        "record_decode_us",
        "checksum_us",
        "total_context_us",
        "range_count",
        "record_count",
        "verified_count",
    ]
    out: Dict[str, object] = {}
    for key in numeric_keys:
        vals = [float(s[key]) for s in samples]
        out[key.replace("_us", "") + "_p50_us" if key.endswith("_us") else key + "_median"] = percentile(vals, 0.50)
        out[key.replace("_us", "") + "_p95_us" if key.endswith("_us") else key + "_p95"] = percentile(vals, 0.95)
        out[key.replace("_us", "") + "_p99_us" if key.endswith("_us") else key + "_p99"] = percentile(vals, 0.99)
    counts: Dict[str, int] = {}
    for s in samples:
        phase = str(s["dominant_phase"])
        counts[phase] = counts.get(phase, 0) + 1
    out["dominant_phase_counts"] = dict(sorted(counts.items()))
    out["dominant_phase_by_p95"] = max(
        [
            "query_topk_generation",
            "coalesced_plan_build",
            "actual_read",
            "slice_copy",
            "python_loop_overhead",
            "header_parse",
            "record_decode",
            "checksum",
        ],
        key=lambda phase: float(out[f"{phase}_p95_us"]),
    )
    total_p95 = float(out["total_context_p95_us"])
    out["actual_read_share_of_total_p95"] = float(out["actual_read_p95_us"]) / total_p95 if total_p95 else 0.0
    out["checksum_share_of_total_p95"] = float(out["checksum_p95_us"]) / total_p95 if total_p95 else 0.0
    out["decode_plus_header_share_of_total_p95"] = (
        float(out["header_parse_p95_us"]) + float(out["record_decode_p95_us"])
    ) / total_p95 if total_p95 else 0.0
    return out


def run_split_profile(
    store_path: Path,
    pointers: Sequence[PayloadPointer],
    recall_samples: int,
    top_k: int,
    checksum_mode: str,
) -> Dict[str, object]:
    samples: List[Dict[str, float | str | int]] = []
    fd = os.open(str(store_path), os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:
        for i in range(recall_samples):
            samples.append(benchmark_once(fd, pointers, i, top_k, checksum_mode))
    finally:
        os.close(fd)
    summary = summarize_samples(samples)
    return {
        "top_k": top_k,
        "checksum_mode": checksum_mode,
        "summary": summary,
        "sample_count": recall_samples,
    }
