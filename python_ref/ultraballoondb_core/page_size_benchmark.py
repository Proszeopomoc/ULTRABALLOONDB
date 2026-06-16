#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UltraBalloonDB V00I page-size benchmark core.

This module is database-side and intentionally semantic-blind. It benchmarks
physical page sizes for payload storage after top_k selection. It does not call
LLMs, does not interpret payload meaning, and does not own agent policy.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import struct
import time
from typing import Dict, Iterable, List, Sequence, Tuple

MAGIC = b"UBDBV00I"
HEADER_STRUCT = struct.Struct("<8sIIQQ")  # magic, page_size, flags, page_count, record_count
RECORD_LEN_STRUCT = struct.Struct("<I")
SUPPORTED_PAGE_SIZES = (4096, 16384, 65536, 262144)


@dataclass(frozen=True, slots=True)
class PageRecordPointer:
    record_id: int
    page_size: int
    page_id: int
    page_offset: int
    absolute_offset: int
    payload_length: int
    stored_length: int


@dataclass(frozen=True, slots=True)
class CoalescedReadRange:
    start: int
    length: int
    pointer_indices: Tuple[int, ...]


@dataclass(frozen=True, slots=True)
class PageStoreBuildResult:
    page_size: int
    path: str
    record_count: int
    page_count: int
    payload_bytes: int
    stored_record_bytes: int
    file_size_bytes: int
    slack_bytes: int
    write_seconds: float
    build_records_per_s: float
    build_mb_per_s: float
    sha256: str
    pointers: Tuple[PageRecordPointer, ...]


def _portable_pread(fd: int, length: int, offset: int) -> bytes:
    """Portable positioned read. Uses os.pread when available; falls back on lseek/read."""
    if hasattr(os, "pread"):
        return os.pread(fd, length, offset)  # type: ignore[attr-defined]
    current = os.lseek(fd, 0, os.SEEK_CUR)
    try:
        os.lseek(fd, offset, os.SEEK_SET)
        chunks: List[bytes] = []
        remaining = length
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.lseek(fd, current, os.SEEK_SET)


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest().upper()


def deterministic_payload(record_id: int) -> bytes:
    """Small deterministic payload with variable length, no semantic content."""
    payload_len = 48 + ((record_id * 1315423911 + 2654435761) & 0x7F)  # 48..175
    seed = hashlib.blake2b(f"UBDB-V00I-{record_id}".encode("ascii"), digest_size=32).digest()
    repeats = (payload_len + len(seed) - 1) // len(seed)
    return (seed * repeats)[:payload_len]


def _write_header(f, page_size: int, page_count: int, record_count: int) -> None:
    f.seek(0)
    f.write(HEADER_STRUCT.pack(MAGIC, page_size, 0, page_count, record_count))


class PagedPayloadWriter:
    def __init__(self, path: str, page_size: int) -> None:
        if page_size not in SUPPORTED_PAGE_SIZES:
            raise ValueError(f"unsupported page size: {page_size}")
        self.path = path
        self.page_size = int(page_size)
        self.f = open(path, "wb")
        _write_header(self.f, self.page_size, 0, 0)
        self.page_id = 0
        self.page_offset = 0
        self.page = bytearray(self.page_size)
        self.record_count = 0
        self.payload_bytes = 0
        self.stored_record_bytes = 0
        self.pointers: List[PageRecordPointer] = []

    @property
    def data_base_offset(self) -> int:
        return HEADER_STRUCT.size

    def _flush_page(self) -> None:
        self.f.write(self.page)
        self.page_id += 1
        self.page_offset = 0
        self.page = bytearray(self.page_size)

    def write_record(self, record_id: int, payload: bytes) -> PageRecordPointer:
        stored_length = RECORD_LEN_STRUCT.size + len(payload)
        if stored_length > self.page_size:
            raise ValueError("record larger than page; V00I synthetic workload must fit in one page")
        if self.page_offset + stored_length > self.page_size:
            self._flush_page()
        absolute_offset = self.data_base_offset + self.page_id * self.page_size + self.page_offset
        ptr = PageRecordPointer(
            record_id=record_id,
            page_size=self.page_size,
            page_id=self.page_id,
            page_offset=self.page_offset,
            absolute_offset=absolute_offset,
            payload_length=len(payload),
            stored_length=stored_length,
        )
        self.page[self.page_offset:self.page_offset + RECORD_LEN_STRUCT.size] = RECORD_LEN_STRUCT.pack(len(payload))
        start = self.page_offset + RECORD_LEN_STRUCT.size
        self.page[start:start + len(payload)] = payload
        self.page_offset += stored_length
        self.record_count += 1
        self.payload_bytes += len(payload)
        self.stored_record_bytes += stored_length
        self.pointers.append(ptr)
        return ptr

    def close(self) -> None:
        if self.page_offset > 0 or self.page_id == 0:
            self._flush_page()
        page_count = self.page_id
        _write_header(self.f, self.page_size, page_count, self.record_count)
        self.f.flush()
        os.fsync(self.f.fileno())
        self.f.close()


def build_page_store(path: str, page_size: int, record_count: int) -> PageStoreBuildResult:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        os.remove(path)
    t0 = time.perf_counter()
    writer = PagedPayloadWriter(path, page_size)
    try:
        for rid in range(record_count):
            writer.write_record(rid, deterministic_payload(rid))
    finally:
        writer.close()
    t1 = time.perf_counter()
    file_size = os.path.getsize(path)
    total_page_bytes = writer.page_id * page_size
    slack = max(0, total_page_bytes - writer.stored_record_bytes)
    seconds = max(t1 - t0, 1e-12)
    sha = sha256_file(path)
    return PageStoreBuildResult(
        page_size=page_size,
        path=path,
        record_count=writer.record_count,
        page_count=writer.page_id,
        payload_bytes=writer.payload_bytes,
        stored_record_bytes=writer.stored_record_bytes,
        file_size_bytes=file_size,
        slack_bytes=slack,
        write_seconds=seconds,
        build_records_per_s=writer.record_count / seconds,
        build_mb_per_s=(file_size / (1024 * 1024)) / seconds,
        sha256=sha,
        pointers=tuple(writer.pointers),
    )


def load_header(path: str) -> Dict[str, int | str]:
    with open(path, "rb") as f:
        b = f.read(HEADER_STRUCT.size)
    magic, page_size, flags, page_count, record_count = HEADER_STRUCT.unpack(b)
    if magic != MAGIC:
        raise ValueError("invalid V00I store magic")
    return {
        "magic": magic.decode("ascii"),
        "page_size": int(page_size),
        "flags": int(flags),
        "page_count": int(page_count),
        "record_count": int(record_count),
    }


def read_payload_by_pointer(fd: int, ptr: PageRecordPointer) -> bytes:
    raw = _portable_pread(fd, ptr.stored_length, ptr.absolute_offset)
    if len(raw) != ptr.stored_length:
        raise IOError("short read")
    (n,) = RECORD_LEN_STRUCT.unpack(raw[:RECORD_LEN_STRUCT.size])
    if n != ptr.payload_length:
        raise ValueError("payload length mismatch")
    return raw[RECORD_LEN_STRUCT.size:]


def build_coalesced_plan(pointers: Sequence[PageRecordPointer], max_gap_bytes: int = 0) -> List[CoalescedReadRange]:
    indexed = sorted(enumerate(pointers), key=lambda x: (x[1].absolute_offset, x[1].stored_length))
    ranges: List[CoalescedReadRange] = []
    if not indexed:
        return ranges
    cur_start = indexed[0][1].absolute_offset
    cur_end = indexed[0][1].absolute_offset + indexed[0][1].stored_length
    cur_indices = [indexed[0][0]]
    last_page_size = indexed[0][1].page_size
    for original_idx, ptr in indexed[1:]:
        start = ptr.absolute_offset
        end = ptr.absolute_offset + ptr.stored_length
        same_page_window = ptr.page_size == last_page_size and start <= cur_end + max_gap_bytes
        if same_page_window:
            cur_end = max(cur_end, end)
            cur_indices.append(original_idx)
        else:
            ranges.append(CoalescedReadRange(cur_start, cur_end - cur_start, tuple(cur_indices)))
            cur_start, cur_end, cur_indices = start, end, [original_idx]
            last_page_size = ptr.page_size
    ranges.append(CoalescedReadRange(cur_start, cur_end - cur_start, tuple(cur_indices)))
    return ranges


def fetch_payloads_coalesced_fd(fd: int, pointers: Sequence[PageRecordPointer], max_gap_bytes: int = 0) -> Tuple[List[bytes], List[CoalescedReadRange], int]:
    plan = build_coalesced_plan(pointers, max_gap_bytes=max_gap_bytes)
    out: List[bytes | None] = [None] * len(pointers)
    bytes_read = 0
    for rr in plan:
        block = _portable_pread(fd, rr.length, rr.start)
        if len(block) != rr.length:
            raise IOError("short coalesced read")
        bytes_read += len(block)
        for idx in rr.pointer_indices:
            ptr = pointers[idx]
            rel = ptr.absolute_offset - rr.start
            raw = block[rel:rel + ptr.stored_length]
            (n,) = RECORD_LEN_STRUCT.unpack(raw[:RECORD_LEN_STRUCT.size])
            if n != ptr.payload_length:
                raise ValueError("payload length mismatch inside coalesced read")
            out[idx] = raw[RECORD_LEN_STRUCT.size:]
    return [x if x is not None else b"" for x in out], plan, bytes_read


def deterministic_query_ids(record_count: int, sample_index: int, top_k: int) -> List[int]:
    """Clustered deterministic IDs to model top_k candidates near a topology neighborhood."""
    if record_count <= 0:
        return []
    stride = max(1, record_count // max(1, top_k * 4))
    base = ((sample_index + 1) * 11400714819323198485) % record_count
    # Half local, half scattered; this exposes page-size coalescing and fragmentation tradeoffs.
    ids: List[int] = []
    local_start = base % max(1, record_count)
    for j in range(top_k):
        if j % 4 == 0:
            rid = (base + j * stride + (j * j * 17)) % record_count
        else:
            rid = (local_start + j) % record_count
        ids.append(int(rid))
    # Stable dedupe while preserving length as much as possible.
    seen = set()
    deduped: List[int] = []
    filler = 0
    for rid in ids:
        if rid not in seen:
            seen.add(rid)
            deduped.append(rid)
    while len(deduped) < top_k:
        rid = (base + filler * 65537) % record_count
        if rid not in seen:
            seen.add(rid)
            deduped.append(int(rid))
        filler += 1
    return deduped[:top_k]


def percentile_us(values: Sequence[float], p: float) -> float:
    if not values:
        return 0.0
    xs = sorted(values)
    idx = int(round((len(xs) - 1) * p))
    return xs[max(0, min(idx, len(xs) - 1))] * 1_000_000.0


def median(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    xs = sorted(values)
    n = len(xs)
    mid = n // 2
    if n % 2:
        return xs[mid]
    return (xs[mid - 1] + xs[mid]) / 2.0


def benchmark_fetch(path: str, pointers: Sequence[PageRecordPointer], recall_samples: int, top_k: int) -> Dict[str, float | int | bool]:
    if recall_samples <= 0:
        raise ValueError("recall_samples must be positive")
    if top_k <= 0:
        raise ValueError("top_k must be positive")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:
        naive_times: List[float] = []
        coalesced_times: List[float] = []
        coalesced_range_counts: List[float] = []
        naive_read_counts: List[float] = []
        coalesced_bytes: List[float] = []
        naive_bytes: List[float] = []
        checksum_ok = True
        for s in range(recall_samples):
            ids = deterministic_query_ids(len(pointers), s, top_k)
            selected = [pointers[i] for i in ids]
            t0 = time.perf_counter()
            naive_payloads = [read_payload_by_pointer(fd, ptr) for ptr in selected]
            t1 = time.perf_counter()
            coalesced_payloads, plan, bytes_read = fetch_payloads_coalesced_fd(fd, selected, max_gap_bytes=0)
            t2 = time.perf_counter()
            if naive_payloads != coalesced_payloads:
                checksum_ok = False
            naive_times.append(t1 - t0)
            coalesced_times.append(t2 - t1)
            coalesced_range_counts.append(float(len(plan)))
            naive_read_counts.append(float(len(selected)))
            coalesced_bytes.append(float(bytes_read))
            naive_bytes.append(float(sum(ptr.stored_length for ptr in selected)))
        return {
            "top_k": int(top_k),
            "recall_samples": int(recall_samples),
            "checksum_ok": bool(checksum_ok),
            "naive_latency_p50_us": percentile_us(naive_times, 0.50),
            "naive_latency_p95_us": percentile_us(naive_times, 0.95),
            "naive_latency_p99_us": percentile_us(naive_times, 0.99),
            "coalesced_latency_p50_us": percentile_us(coalesced_times, 0.50),
            "coalesced_latency_p95_us": percentile_us(coalesced_times, 0.95),
            "coalesced_latency_p99_us": percentile_us(coalesced_times, 0.99),
            "naive_read_count_median": median(naive_read_counts),
            "coalesced_range_count_median": median(coalesced_range_counts),
            "coalesced_range_count_p95": percentile_us([x / 1_000_000.0 for x in coalesced_range_counts], 0.95),
            "coalescing_ratio_median": (median(coalesced_range_counts) / max(1.0, median(naive_read_counts))),
            "naive_bytes_median": median(naive_bytes),
            "coalesced_bytes_median": median(coalesced_bytes),
        }
    finally:
        os.close(fd)


def summarize_build(build: PageStoreBuildResult) -> Dict[str, float | int | str]:
    return {
        "page_size": build.page_size,
        "record_count": build.record_count,
        "page_count": build.page_count,
        "payload_bytes": build.payload_bytes,
        "stored_record_bytes": build.stored_record_bytes,
        "file_size_bytes": build.file_size_bytes,
        "slack_bytes": build.slack_bytes,
        "slack_ratio": build.slack_bytes / max(1, build.page_count * build.page_size),
        "avg_records_per_page": build.record_count / max(1, build.page_count),
        "write_seconds": build.write_seconds,
        "build_records_per_s": build.build_records_per_s,
        "build_mb_per_s": build.build_mb_per_s,
        "sha256": build.sha256,
    }
