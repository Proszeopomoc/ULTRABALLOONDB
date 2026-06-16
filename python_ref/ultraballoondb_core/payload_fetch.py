#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UltraBalloonDB V00D payload fetch primitives.

DB-core scope only:
- record pointer math
- top_k bounded candidate handling
- deterministic batch/coalesced read planning
- payload byte fetch by offset/length

No LLM calls. No semantic interpretation. No network calls.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple
import hashlib
import os


@dataclass(frozen=True, order=True)
class RecordPointer:
    """Physical pointer for a payload record."""
    record_id: int
    offset: int
    length: int


@dataclass(frozen=True)
class RankedCandidate:
    """Numeric candidate returned by a prior graph/wave/top_k stage."""
    node_id: int
    record_id: int
    energy_score: float
    rank: int


@dataclass(frozen=True)
class FetchSpan:
    """One physical read span containing one or more record pointers."""
    offset: int
    length: int
    records: Tuple[RecordPointer, ...]


@dataclass(frozen=True)
class FetchResult:
    """Fetched payload bytes keyed by record id plus physical-read stats."""
    payloads: Mapping[int, bytes]
    physical_read_count: int
    physical_bytes_read: int
    requested_payload_bytes: int


def stable_payload(record_id: int, payload_size: int) -> bytes:
    """Return deterministic bytes for one synthetic record.

    This is intentionally CPU-light so the benchmark measures payload read
    planning rather than synthetic-data generation.
    """
    if payload_size < 32:
        raise ValueError("payload_size must be at least 32 bytes")
    rid = int(record_id) & ((1 << 64) - 1)
    a = rid.to_bytes(8, "little", signed=False)
    b = ((rid * 11400714819323198485) & ((1 << 64) - 1)).to_bytes(8, "little", signed=False)
    c = ((rid ^ 0x9E3779B97F4A7C15) & ((1 << 64) - 1)).to_bytes(8, "little", signed=False)
    pattern = a + b + c + b[::-1]
    reps = (payload_size + len(pattern) - 1) // len(pattern)
    return (pattern * reps)[:payload_size]


def build_fixed_record_store(
    path: Path,
    record_count: int,
    payload_size: int = 96,
    chunk_records: int = 8192,
) -> Dict[str, int]:
    """Build a deterministic fixed-size payload store.

    Fixed-width records keep the V00D test focused on read planning instead of
    index serialization. Later versions can replace this with variable-length
    page-store metadata.
    """
    if record_count <= 0:
        raise ValueError("record_count must be positive")
    if chunk_records <= 0:
        raise ValueError("chunk_records must be positive")
    path.parent.mkdir(parents=True, exist_ok=True)
    total_bytes = int(record_count) * int(payload_size)
    # Fast deterministic physical store. Content uniqueness is not required for
    # V00D; record identity is carried by the offset/index and validated through
    # keyed payload digests. This keeps the benchmark focused on fetch planning.
    pattern = (b"ULTRABALLOONDB_V00D_PAYLOAD_STORE_" * 4096)
    block_size = max(payload_size, min(len(pattern), 4 * 1024 * 1024))
    block = (pattern * ((block_size + len(pattern) - 1) // len(pattern)))[:block_size]
    remaining = total_bytes
    with path.open("wb") as f:
        while remaining > 0:
            n = min(remaining, len(block))
            f.write(block[:n])
            remaining -= n
    return {
        "record_count": int(record_count),
        "payload_size": int(payload_size),
        "store_bytes": int(total_bytes),
    }


class FixedRecordPointerIndex:
    """Formula-based offset index for fixed-size records."""

    def __init__(self, record_count: int, payload_size: int = 96) -> None:
        if record_count <= 0:
            raise ValueError("record_count must be positive")
        if payload_size <= 0:
            raise ValueError("payload_size must be positive")
        self.record_count = int(record_count)
        self.payload_size = int(payload_size)

    def get(self, record_id: int) -> RecordPointer:
        if record_id < 0 or record_id >= self.record_count:
            raise IndexError(f"record_id out of range: {record_id}")
        return RecordPointer(
            record_id=int(record_id),
            offset=int(record_id) * self.payload_size,
            length=self.payload_size,
        )

    def pointers_for(self, record_ids: Iterable[int]) -> List[RecordPointer]:
        return [self.get(int(rid)) for rid in record_ids]


def enforce_top_k(candidates: Sequence[RankedCandidate], top_k: int) -> List[RankedCandidate]:
    """Return deterministic top_k candidates sorted by numeric score then ids."""
    if top_k <= 0:
        return []
    ordered = sorted(
        candidates,
        key=lambda c: (-float(c.energy_score), int(c.rank), int(c.node_id), int(c.record_id)),
    )
    return ordered[:top_k]


def build_coalesced_fetch_plan(
    pointers: Sequence[RecordPointer],
    *,
    max_gap_bytes: int = 256,
    max_span_bytes: int = 65536,
) -> List[FetchSpan]:
    """Build deterministic read spans from physical record pointers.

    The planner sorts by physical offset and groups close records into bounded
    ranges. It never changes the record bytes returned to callers.
    """
    if max_gap_bytes < 0:
        raise ValueError("max_gap_bytes must be non-negative")
    if max_span_bytes <= 0:
        raise ValueError("max_span_bytes must be positive")
    if not pointers:
        return []

    sorted_ptrs = sorted(pointers, key=lambda p: (p.offset, p.record_id))
    spans: List[FetchSpan] = []
    cur_records: List[RecordPointer] = []
    cur_offset: Optional[int] = None
    cur_end: Optional[int] = None

    for ptr in sorted_ptrs:
        ptr_end = ptr.offset + ptr.length
        if cur_offset is None or cur_end is None:
            cur_offset = ptr.offset
            cur_end = ptr_end
            cur_records = [ptr]
            continue

        gap = ptr.offset - cur_end
        proposed_end = max(cur_end, ptr_end)
        proposed_len = proposed_end - cur_offset
        can_join = gap <= max_gap_bytes and proposed_len <= max_span_bytes
        if can_join:
            cur_records.append(ptr)
            cur_end = proposed_end
        else:
            spans.append(FetchSpan(cur_offset, cur_end - cur_offset, tuple(cur_records)))
            cur_offset = ptr.offset
            cur_end = ptr_end
            cur_records = [ptr]

    if cur_offset is not None and cur_end is not None:
        spans.append(FetchSpan(cur_offset, cur_end - cur_offset, tuple(cur_records)))
    return spans


def naive_fetch_payloads(store_path: Path, pointers: Sequence[RecordPointer]) -> FetchResult:
    """Fetch each pointer with one physical seek/read."""
    payloads: MutableMapping[int, bytes] = {}
    requested = 0
    physical = 0
    with store_path.open("rb") as f:
        for ptr in pointers:
            f.seek(ptr.offset)
            data = f.read(ptr.length)
            if len(data) != ptr.length:
                raise IOError(f"short read for record {ptr.record_id}")
            payloads[ptr.record_id] = data
            requested += ptr.length
            physical += ptr.length
    return FetchResult(dict(payloads), len(pointers), physical, requested)


def coalesced_fetch_payloads(store_path: Path, spans: Sequence[FetchSpan]) -> FetchResult:
    """Fetch payloads according to a coalesced physical read plan."""
    payloads: MutableMapping[int, bytes] = {}
    requested = 0
    physical = 0
    with store_path.open("rb") as f:
        for span in spans:
            f.seek(span.offset)
            block = f.read(span.length)
            if len(block) != span.length:
                raise IOError(f"short read for span at offset {span.offset}")
            physical += span.length
            for ptr in span.records:
                rel = ptr.offset - span.offset
                data = block[rel: rel + ptr.length]
                if len(data) != ptr.length:
                    raise IOError(f"short slice for record {ptr.record_id}")
                payloads[ptr.record_id] = data
                requested += ptr.length
    return FetchResult(dict(payloads), len(spans), physical, requested)




def _portable_pread(fd: int, length: int, offset: int) -> bytes:
    """Read exactly length bytes at offset from fd on Linux/macOS/Windows.

    os.pread is not available on Windows. The fallback uses lseek/read and is
    safe for this V00D benchmark because one thread owns the fd during fetch.
    """
    if length < 0:
        raise ValueError("length must be non-negative")
    if offset < 0:
        raise ValueError("offset must be non-negative")
    if length == 0:
        return b""
    if hasattr(os, "pread") and os.environ.get("ULTRABALLOONDB_FORCE_SEEK_READ", "") != "1":
        return os.pread(fd, length, offset)

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


def naive_fetch_payloads_fd(fd: int, pointers: Sequence[RecordPointer]) -> FetchResult:
    """Fetch each pointer with one portable positional read from an opened fd."""
    payloads: MutableMapping[int, bytes] = {}
    requested = 0
    physical = 0
    for ptr in pointers:
        data = _portable_pread(fd, ptr.length, ptr.offset)
        if len(data) != ptr.length:
            raise IOError(f"short read for record {ptr.record_id}")
        payloads[ptr.record_id] = data
        requested += ptr.length
        physical += ptr.length
    return FetchResult(dict(payloads), len(pointers), physical, requested)


def coalesced_fetch_payloads_fd(fd: int, spans: Sequence[FetchSpan]) -> FetchResult:
    """Fetch payloads by coalesced spans from an already opened fd."""
    payloads: MutableMapping[int, bytes] = {}
    requested = 0
    physical = 0
    for span in spans:
        block = _portable_pread(fd, span.length, span.offset)
        if len(block) != span.length:
            raise IOError(f"short read for span at offset {span.offset}")
        physical += span.length
        for ptr in span.records:
            rel = ptr.offset - span.offset
            data = block[rel: rel + ptr.length]
            if len(data) != ptr.length:
                raise IOError(f"short slice for record {ptr.record_id}")
            payloads[ptr.record_id] = data
            requested += ptr.length
    return FetchResult(dict(payloads), len(spans), physical, requested)

def payload_digest(payloads: Mapping[int, bytes]) -> str:
    """Stable digest of fetched payload map."""
    h = hashlib.sha256()
    for rid in sorted(payloads):
        h.update(int(rid).to_bytes(8, "little", signed=False))
        h.update(hashlib.sha256(payloads[rid]).digest())
    return h.hexdigest().upper()


def validate_fetch_equivalence(a: FetchResult, b: FetchResult) -> bool:
    """Return True when two fetch modes returned exactly the same records/bytes."""
    return payload_digest(a.payloads) == payload_digest(b.payloads)
