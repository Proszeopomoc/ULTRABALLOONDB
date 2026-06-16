#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UltraBalloonDB V00G hot snapshot / lossless archive split.

This module is intentionally DB-core only:
- numeric node identifiers
- typed edge records
- compact hot snapshot files
- lossless archive records and payload offsets
- deterministic rebuild and revocation support

It does not interpret payload meaning and does not call external services.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

VERSION = "V00G_HOT_SNAPSHOT_ARCHIVE_SPLIT"
ARCHIVE_RECORD_STRUCT = struct.Struct("<QQQQQQIQI")
HOT_EDGE_STRUCT = struct.Struct("<QQHHi")
CRYSTAL_STRUCT = struct.Struct("<QQIIQQ")
PAYLOAD_BYTES_PER_RECORD = 8

EDGE_PROJECT_CONTEXT = 4
EDGE_CODE_PATTERN = 5
EDGE_RULE_TO_CODE_PATTERN = 7
EDGE_PROJECT_TO_RECENT_SEED = 8

REL_PROJECT = 101
REL_CODE = 102
REL_RULE_CODE = 103
REL_RECENT = 104

SNAPSHOT_REQUIRED_FILES = (
    "snapshot_manifest.json",
    "hot_edges.bin",
    "hot_crystals.bin",
)


@dataclass(frozen=True)
class ArchivePaths:
    archive_dir: Path
    records_path: Path
    payloads_path: Path
    manifest_path: Path
    revocations_path: Path


@dataclass(frozen=True)
class SnapshotPaths:
    snapshot_dir: Path
    manifest_path: Path
    edges_path: Path
    crystals_path: Path


@dataclass(frozen=True)
class ArchiveRecord:
    event_id: int
    seed_node: int
    project_node: int
    code_node: int
    rule_node: int
    payload_offset: int
    payload_len: int
    payload_hash64: int
    flags: int


@dataclass(frozen=True)
class HotSnapshotLoaded:
    manifest: Mapping[str, object]
    edge_count: int
    crystal_count: int
    edges_bytes: int
    crystals: Tuple[Tuple[int, int, int, int, int, int], ...]


def stable_hash64_bytes(data: bytes) -> int:
    return int.from_bytes(hashlib.blake2b(data, digest_size=8).digest(), "little")


def stable_hash64_text(text: str) -> int:
    return stable_hash64_bytes(text.encode("utf-8"))


def synthetic_payload(event_id: int) -> bytes:
    # Compact deterministic payload token. Full semantic payloads belong to archive/payload layer,
    # not to the hot snapshot.
    return hashlib.blake2b(f"ubdb-v00g-payload-{event_id}".encode("ascii"), digest_size=PAYLOAD_BYTES_PER_RECORD).digest()


def synthetic_record(event_id: int, payload_offset: int) -> ArchiveRecord:
    project_mod = 4096
    code_mod = 8192
    rule_mod = 2048
    seed_node = 1_000_000_000 + event_id
    project_node = 2_000_000_000 + (event_id % project_mod)
    code_node = 3_000_000_000 + (event_id % code_mod)
    rule_node = 4_000_000_000 + (event_id % rule_mod)
    payload = synthetic_payload(event_id)
    return ArchiveRecord(
        event_id=event_id,
        seed_node=seed_node,
        project_node=project_node,
        code_node=code_node,
        rule_node=rule_node,
        payload_offset=payload_offset,
        payload_len=len(payload),
        payload_hash64=stable_hash64_bytes(payload),
        flags=0,
    )


def archive_paths(archive_dir: Path) -> ArchivePaths:
    archive_dir = Path(archive_dir)
    return ArchivePaths(
        archive_dir=archive_dir,
        records_path=archive_dir / "lossless_records.bin",
        payloads_path=archive_dir / "payload_store.bin",
        manifest_path=archive_dir / "archive_manifest.json",
        revocations_path=archive_dir / "revocations.tsv",
    )


def snapshot_paths(snapshot_dir: Path) -> SnapshotPaths:
    snapshot_dir = Path(snapshot_dir)
    return SnapshotPaths(
        snapshot_dir=snapshot_dir,
        manifest_path=snapshot_dir / "snapshot_manifest.json",
        edges_path=snapshot_dir / "hot_edges.bin",
        crystals_path=snapshot_dir / "hot_crystals.bin",
    )


def pack_archive_record(record: ArchiveRecord) -> bytes:
    return ARCHIVE_RECORD_STRUCT.pack(
        record.event_id,
        record.seed_node,
        record.project_node,
        record.code_node,
        record.rule_node,
        record.payload_offset,
        record.payload_len,
        record.payload_hash64,
        record.flags,
    )


def unpack_archive_record(chunk: bytes) -> ArchiveRecord:
    vals = ARCHIVE_RECORD_STRUCT.unpack(chunk)
    return ArchiveRecord(*vals)


def iter_archive_records(records_path: Path) -> Iterator[ArchiveRecord]:
    size = ARCHIVE_RECORD_STRUCT.size
    with open(records_path, "rb") as f:
        while True:
            chunk = f.read(size)
            if not chunk:
                break
            if len(chunk) != size:
                raise ValueError(f"partial archive record in {records_path}")
            yield unpack_archive_record(chunk)


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().upper()


def sha256_tree(paths: Sequence[Path]) -> str:
    h = hashlib.sha256()
    for path in sorted((Path(p) for p in paths), key=lambda p: p.name):
        h.update(path.name.encode("utf-8"))
        h.update(b"\0")
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
    return h.hexdigest().upper()


def load_revocations(revocations_path: Path) -> set[int]:
    revoked: set[int] = set()
    if not revocations_path.exists():
        return revoked
    with open(revocations_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            try:
                revoked.add(int(parts[0]))
            except (ValueError, IndexError):
                raise ValueError(f"bad revocation line in {revocations_path}: {line!r}")
    return revoked


def append_crystal_revocation(revocations_path: Path, crystal_id: int, reason_code: str = "LOCAL_TEST_REVOCATION") -> None:
    revocations_path.parent.mkdir(parents=True, exist_ok=True)
    with open(revocations_path, "a", encoding="utf-8", newline="\n") as f:
        f.write(f"{int(crystal_id)}\t{reason_code}\n")


def write_lossless_archive(event_count: int, archive_dir: Path) -> Dict[str, object]:
    if event_count <= 0:
        raise ValueError("event_count must be positive")
    paths = archive_paths(archive_dir)
    paths.archive_dir.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    payload_offset = 0
    with open(paths.records_path, "wb") as records_f, open(paths.payloads_path, "wb") as payloads_f:
        for event_id in range(event_count):
            payload = synthetic_payload(event_id)
            record = synthetic_record(event_id, payload_offset)
            payloads_f.write(payload)
            records_f.write(pack_archive_record(record))
            payload_offset += len(payload)
    elapsed = time.perf_counter() - started
    manifest = {
        "version": VERSION,
        "archive_role": "LOSSLESS_SOURCE_OF_TRUTH",
        "event_count": event_count,
        "archive_record_struct_size": ARCHIVE_RECORD_STRUCT.size,
        "payload_bytes_per_record": PAYLOAD_BYTES_PER_RECORD,
        "records_bytes": paths.records_path.stat().st_size,
        "payload_bytes": paths.payloads_path.stat().st_size,
        "records_sha256": sha256_file(paths.records_path),
        "payloads_sha256": sha256_file(paths.payloads_path),
        "write_seconds": elapsed,
        "db_core_only": True,
        "semantic_interpretation_inside_db": False,
    }
    paths.manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8", newline="\n")
    return manifest


def _motif_hash(record: ArchiveRecord) -> int:
    # Motif is purely numeric/topological: shared project/code/rule residue, no payload interpretation.
    return stable_hash64_text(f"{record.project_node % 64}:{record.code_node % 64}:{record.rule_node % 64}")


def _crystal_id_from_motif(motif_hash: int) -> int:
    return 9_000_000_000 + (motif_hash % 1_000_000_000)


def build_hot_snapshot_from_archive(archive_dir: Path, snapshot_dir: Path, *, crystal_support_threshold: int = 3) -> Dict[str, object]:
    ap = archive_paths(archive_dir)
    sp = snapshot_paths(snapshot_dir)
    if not ap.records_path.exists() or not ap.payloads_path.exists() or not ap.manifest_path.exists():
        raise FileNotFoundError("lossless archive is incomplete")
    sp.snapshot_dir.mkdir(parents=True, exist_ok=True)
    revoked = load_revocations(ap.revocations_path)
    started = time.perf_counter()
    motif_counts: Dict[int, int] = {}
    motif_first_event: Dict[int, int] = {}
    event_count = 0
    edge_count = 0
    with open(sp.edges_path, "wb") as edges_f:
        for record in iter_archive_records(ap.records_path):
            event_count += 1
            motif = _motif_hash(record)
            motif_counts[motif] = motif_counts.get(motif, 0) + 1
            motif_first_event.setdefault(motif, record.event_id)
            # Compact hot edges: enough for recall/wave, no payload bytes.
            edges_f.write(HOT_EDGE_STRUCT.pack(record.seed_node, record.project_node, EDGE_PROJECT_CONTEXT, REL_PROJECT, 750))
            edges_f.write(HOT_EDGE_STRUCT.pack(record.seed_node, record.code_node, EDGE_CODE_PATTERN, REL_CODE, 900))
            edges_f.write(HOT_EDGE_STRUCT.pack(record.rule_node, record.code_node, EDGE_RULE_TO_CODE_PATTERN, REL_RULE_CODE, 700))
            edge_count += 3
    crystal_count = 0
    revoked_excluded_count = 0
    with open(sp.crystals_path, "wb") as crystals_f:
        for motif_hash in sorted(motif_counts):
            support = motif_counts[motif_hash]
            if support < crystal_support_threshold:
                continue
            crystal_id = _crystal_id_from_motif(motif_hash)
            if crystal_id in revoked:
                revoked_excluded_count += 1
                continue
            first_event = motif_first_event[motif_hash]
            crystals_f.write(CRYSTAL_STRUCT.pack(crystal_id, motif_hash, support, 0, first_event, support))
            crystal_count += 1
    elapsed = time.perf_counter() - started
    archive_manifest = json.loads(ap.manifest_path.read_text(encoding="utf-8"))
    manifest = {
        "version": VERSION,
        "snapshot_role": "HOT_COMPACT_WORKING_MEMORY",
        "archive_role": "LOSSLESS_SOURCE_OF_TRUTH",
        "event_count": event_count,
        "edge_count": edge_count,
        "crystal_count": crystal_count,
        "revoked_crystal_excluded_count": revoked_excluded_count,
        "hot_edge_struct_size": HOT_EDGE_STRUCT.size,
        "crystal_struct_size": CRYSTAL_STRUCT.size,
        "source_archive_records_sha256": archive_manifest.get("records_sha256"),
        "source_archive_payloads_sha256": archive_manifest.get("payloads_sha256"),
        "edges_bytes": sp.edges_path.stat().st_size,
        "crystals_bytes": sp.crystals_path.stat().st_size,
        "payload_bytes_in_snapshot": 0,
        "lossless_archive_preserved": ap.records_path.exists() and ap.payloads_path.exists(),
        "build_seconds": elapsed,
        "db_core_only": True,
        "semantic_interpretation_inside_db": False,
    }
    sp.manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8", newline="\n")
    manifest["snapshot_sha256"] = sha256_tree([sp.edges_path, sp.crystals_path])
    sp.manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8", newline="\n")
    return manifest


def load_hot_snapshot(snapshot_dir: Path, *, load_crystals: bool = True) -> HotSnapshotLoaded:
    sp = snapshot_paths(snapshot_dir)
    for name in SNAPSHOT_REQUIRED_FILES:
        if not (sp.snapshot_dir / name).exists():
            raise FileNotFoundError(f"missing hot snapshot file: {name}")
    manifest = json.loads(sp.manifest_path.read_text(encoding="utf-8"))
    edge_bytes = sp.edges_path.stat().st_size
    if edge_bytes % HOT_EDGE_STRUCT.size != 0:
        raise ValueError("hot edge file has invalid size")
    edge_count = edge_bytes // HOT_EDGE_STRUCT.size
    crystal_bytes = sp.crystals_path.stat().st_size
    if crystal_bytes % CRYSTAL_STRUCT.size != 0:
        raise ValueError("crystal file has invalid size")
    crystal_count = crystal_bytes // CRYSTAL_STRUCT.size
    crystals: List[Tuple[int, int, int, int, int, int]] = []
    if load_crystals:
        with open(sp.crystals_path, "rb") as f:
            while True:
                chunk = f.read(CRYSTAL_STRUCT.size)
                if not chunk:
                    break
                crystals.append(CRYSTAL_STRUCT.unpack(chunk))
    return HotSnapshotLoaded(
        manifest=manifest,
        edge_count=edge_count,
        crystal_count=crystal_count,
        edges_bytes=edge_bytes,
        crystals=tuple(crystals),
    )


def verify_payload_from_archive(archive_dir: Path, record_index: int) -> bool:
    ap = archive_paths(archive_dir)
    rec_offset = record_index * ARCHIVE_RECORD_STRUCT.size
    with open(ap.records_path, "rb") as records_f:
        records_f.seek(rec_offset)
        chunk = records_f.read(ARCHIVE_RECORD_STRUCT.size)
    if len(chunk) != ARCHIVE_RECORD_STRUCT.size:
        return False
    record = unpack_archive_record(chunk)
    with open(ap.payloads_path, "rb") as payloads_f:
        payloads_f.seek(record.payload_offset)
        payload = payloads_f.read(record.payload_len)
    return stable_hash64_bytes(payload) == record.payload_hash64
