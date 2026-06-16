#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UltraBalloonDB V00J compact computable hot layout.

The module is intentionally small and deterministic. It demonstrates a hot
snapshot whose binary files are already in the shape used by recall:
fixed-width node rows, fixed-width edge rows and CSR-style edge ranges.

No semantic interpretation, no model calls, no network calls, no agent policy.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import mmap
from pathlib import Path
import struct
import time
from typing import Dict, Iterable, List, Mapping, MutableMapping, Sequence, Tuple

MAGIC = "UBHOTJ00"
VERSION = 1
LAYOUT = "V00J_COMPACT_COMPUTABLE_HOT_LAYOUT"

# node_id_u64, first_edge_u64, edge_count_u32, flags_u16, energy_base_u16
NODE_STRUCT = struct.Struct("<QQIHH")
NODE_SIZE = NODE_STRUCT.size

# dst_node_u64, edge_type_u8, attenuation_u8, relation_code_u16,
# flags_u16, payload_ref_u64, reserved_u16
EDGE_STRUCT = struct.Struct("<QBBHHQH")
EDGE_SIZE = EDGE_STRUCT.size

DEFAULT_EDGE_TYPES = {
    "UP_RULE": 1,
    "DOWN_EVIDENCE": 2,
    "PROJECT_CONTEXT": 3,
    "CODE_PATTERN": 4,
    "LATERAL": 5,
    "FOLD_DERIVED": 31,
    "IS_NOT_EDGE": 255,
}

DEFAULT_RELATIONS = {
    "UNKNOWN": 0,
    "PROJECT_SUPPORT_PATH": 1,
    "CODE_RULE_PATH": 2,
    "FOLD_SHORTCUT_PATH": 3,
    "BLOCKED_PATH": 65535,
}

DEFAULT_ATTENUATION_CODES = {
    "ZERO": 0,
    "WEAK": 64,
    "MID": 128,
    "STRONG": 192,
    "NEAR_KEEP": 230,
    "KEEP": 255,
}


@dataclass(frozen=True)
class SyntheticBuild:
    record_count: int
    node_count: int
    edge_count: int
    avg_payload_bytes_estimate: int
    canonical_archive_estimated_bytes: int
    hot_snapshot_bytes: int
    hot_to_canonical_ratio: float
    manifest_path: str
    content_hash: str


@dataclass(frozen=True)
class RecallResult:
    seed_node_id: int
    theta: int
    top_k: int
    fired_count: int
    touched_edges: int
    payload_decode_count: int
    top_nodes: Tuple[Tuple[int, int], ...]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def write_json(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def quantize_attenuation(float_value: float) -> int:
    if float_value <= 0:
        return 0
    if float_value >= 1:
        return 255
    return max(0, min(255, int(round(float_value * 255.0))))


def apply_attenuation_u16(energy_u16: int, attenuation_u8: int) -> int:
    return (int(energy_u16) * int(attenuation_u8)) >> 8


def _edge_type_for_index(i: int) -> int:
    # Deterministic typed pattern. No strings enter the hot edge file.
    if i % 11 == 0:
        return DEFAULT_EDGE_TYPES["DOWN_EVIDENCE"]
    if i % 7 == 0:
        return DEFAULT_EDGE_TYPES["PROJECT_CONTEXT"]
    if i % 5 == 0:
        return DEFAULT_EDGE_TYPES["CODE_PATTERN"]
    return DEFAULT_EDGE_TYPES["UP_RULE"]


def _relation_for_edge_type(edge_type: int) -> int:
    if edge_type == DEFAULT_EDGE_TYPES["DOWN_EVIDENCE"]:
        return DEFAULT_RELATIONS["PROJECT_SUPPORT_PATH"]
    if edge_type == DEFAULT_EDGE_TYPES["CODE_PATTERN"]:
        return DEFAULT_RELATIONS["CODE_RULE_PATH"]
    return DEFAULT_RELATIONS["UNKNOWN"]


def _attenuation_for_index(i: int) -> int:
    # Fixed-point attenuation code; no float in the hot edge row.
    cycle = i % 4
    if cycle == 0:
        return DEFAULT_ATTENUATION_CODES["NEAR_KEEP"]
    if cycle == 1:
        return DEFAULT_ATTENUATION_CODES["STRONG"]
    if cycle == 2:
        return DEFAULT_ATTENUATION_CODES["MID"]
    return DEFAULT_ATTENUATION_CODES["WEAK"]


def _payload_ref(i: int) -> int:
    # A deterministic reference to the cold payload archive. Hot recall never resolves it.
    digest = hashlib.sha256(f"payload:{i}".encode("ascii")).digest()
    return int.from_bytes(digest[:8], "little")


def canonical_archive_estimate(record_count: int, avg_payload_bytes: int, edge_count: int) -> int:
    # Estimate only. The archive is not written in this selftest because V00J tests
    # the hot layout, not full payload storage. The canonical archive remains the
    # lossless source of truth in the architecture.
    node_meta_overhead = 96
    edge_meta_overhead = 72
    return (record_count * (avg_payload_bytes + node_meta_overhead)) + (edge_count * edge_meta_overhead)


def build_compact_hot_snapshot(
    out_dir: Path,
    record_count: int,
    avg_payload_bytes_estimate: int = 8192,
    fanout: int = 2,
) -> SyntheticBuild:
    if record_count <= 0:
        raise ValueError("record_count must be positive")
    if fanout < 1:
        raise ValueError("fanout must be >= 1")

    out_dir.mkdir(parents=True, exist_ok=True)
    nodes_path = out_dir / "nodes.ubhnode"
    edges_path = out_dir / "edges.ubhedge"
    fold_path = out_dir / "folds.ubhfold"
    manifest_path = out_dir / "manifest.ubm.json"

    edge_rows: List[Tuple[int, int, int, int, int, int, int]] = []
    first_edge_by_node: List[int] = [0] * (record_count + 1)
    edge_count_by_node: List[int] = [0] * (record_count + 1)

    with edges_path.open("wb") as ef:
        edge_index = 0
        for src in range(1, record_count + 1):
            first_edge_by_node[src] = edge_index
            local_count = 0
            for jump in range(1, fanout + 1):
                dst = src + jump
                if dst > record_count:
                    continue
                edge_type = _edge_type_for_index(src + jump)
                attenuation = _attenuation_for_index(src + jump)
                relation = _relation_for_edge_type(edge_type)
                flags = 0
                payload_ref = _payload_ref(dst)
                reserved = 0
                ef.write(EDGE_STRUCT.pack(dst, edge_type, attenuation, relation, flags, payload_ref, reserved))
                edge_index += 1
                local_count += 1
            edge_count_by_node[src] = local_count

    with nodes_path.open("wb") as nf:
        for node_id in range(1, record_count + 1):
            first_edge = first_edge_by_node[node_id]
            edge_count = edge_count_by_node[node_id]
            flags = 0
            energy_base = 65535 if node_id == 1 else 0
            nf.write(NODE_STRUCT.pack(node_id, first_edge, edge_count, flags, energy_base))

    # Derived fold index. It is intentionally outside the canonical content hash.
    with fold_path.open("wb") as ff:
        # Minimal deterministic fold rows: src_u64, dst_u64, represented_hops_u16, reserved_u16.
        fold_struct = struct.Struct("<QQHH")
        for src in range(1, min(record_count, 1024) + 1, 8):
            dst = min(record_count, src + 4)
            if dst > src:
                ff.write(fold_struct.pack(src, dst, 4, 0))

    file_hashes = {
        "nodes.ubhnode": sha256_file(nodes_path),
        "edges.ubhedge": sha256_file(edges_path),
    }
    canonical_content_hash = sha256_bytes(
        (file_hashes["nodes.ubhnode"] + file_hashes["edges.ubhedge"] + LAYOUT).encode("ascii")
    )
    hot_bytes = nodes_path.stat().st_size + edges_path.stat().st_size
    edge_count = edges_path.stat().st_size // EDGE_SIZE
    canonical_est = canonical_archive_estimate(record_count, avg_payload_bytes_estimate, edge_count)
    ratio = float(canonical_est) / float(max(1, hot_bytes))

    manifest = {
        "magic": MAGIC,
        "version": VERSION,
        "layout": LAYOUT,
        "node_record_size": NODE_SIZE,
        "edge_record_size": EDGE_SIZE,
        "node_count": record_count,
        "edge_count": edge_count,
        "fanout": fanout,
        "edge_type_codebook": DEFAULT_EDGE_TYPES,
        "relation_codebook": DEFAULT_RELATIONS,
        "attenuation_codebook": DEFAULT_ATTENUATION_CODES,
        "file_hashes": file_hashes,
        "canonical_content_hash_excludes_folds": canonical_content_hash,
        "derived_fold_index_present": True,
        "derived_fold_index_in_canonical_hash": False,
        "canonical_archive_estimated_bytes": canonical_est,
        "hot_snapshot_bytes": hot_bytes,
        "hot_to_canonical_ratio": ratio,
        "truth_boundary": {
            "canonical_archive_is_source_of_truth": True,
            "hot_snapshot_is_rebuildable_compute_layout": True,
            "fold_index_is_derived_cache": True,
            "activation_never_promotes_trust": True,
            "payload_decode_only_after_top_k": True,
        },
    }
    write_json(manifest_path, manifest)

    return SyntheticBuild(
        record_count=record_count,
        node_count=record_count,
        edge_count=edge_count,
        avg_payload_bytes_estimate=avg_payload_bytes_estimate,
        canonical_archive_estimated_bytes=canonical_est,
        hot_snapshot_bytes=hot_bytes,
        hot_to_canonical_ratio=ratio,
        manifest_path=str(manifest_path),
        content_hash=canonical_content_hash,
    )


class CompactHotSnapshotReader:
    def __init__(self, snapshot_dir: Path):
        self.snapshot_dir = snapshot_dir
        self.manifest_path = snapshot_dir / "manifest.ubm.json"
        self.nodes_path = snapshot_dir / "nodes.ubhnode"
        self.edges_path = snapshot_dir / "edges.ubhedge"
        self.manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self._node_f = self.nodes_path.open("rb")
        self._edge_f = self.edges_path.open("rb")
        self.nodes = mmap.mmap(self._node_f.fileno(), 0, access=mmap.ACCESS_READ)
        self.edges = mmap.mmap(self._edge_f.fileno(), 0, access=mmap.ACCESS_READ)
        self.node_count = int(self.manifest["node_count"])
        self.edge_count = int(self.manifest["edge_count"])

    def close(self) -> None:
        self.nodes.close()
        self.edges.close()
        self._node_f.close()
        self._edge_f.close()

    def __enter__(self) -> "CompactHotSnapshotReader":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def verify_manifest(self) -> bool:
        expected = self.manifest.get("file_hashes", {})
        return (
            expected.get("nodes.ubhnode") == sha256_file(self.nodes_path)
            and expected.get("edges.ubhedge") == sha256_file(self.edges_path)
        )

    def read_node_by_index(self, index: int) -> Tuple[int, int, int, int, int]:
        start = index * NODE_SIZE
        return NODE_STRUCT.unpack_from(self.nodes, start)

    def find_node_index(self, node_id: int) -> int:
        # Node ids are sorted. This binary search is deterministic and decode-free.
        lo, hi = 0, self.node_count - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            mid_id, _first, _count, _flags, _energy = self.read_node_by_index(mid)
            if mid_id == node_id:
                return mid
            if mid_id < node_id:
                lo = mid + 1
            else:
                hi = mid - 1
        return -1

    def iter_edges_for_node_index(self, node_index: int):
        node_id, first_edge, edge_count, _flags, _energy = self.read_node_by_index(node_index)
        base = first_edge * EDGE_SIZE
        for i in range(edge_count):
            start = base + (i * EDGE_SIZE)
            dst, edge_type, attenuation, relation_code, flags, payload_ref, reserved = EDGE_STRUCT.unpack_from(self.edges, start)
            yield dst, edge_type, attenuation, relation_code, flags, payload_ref, reserved

    def threshold_wave_recall(self, seed_node_id: int, theta: int, top_k: int, max_steps: int = 8) -> RecallResult:
        if theta < 0 or theta > 65535:
            raise ValueError("theta must be u16 range")
        if top_k <= 0:
            raise ValueError("top_k must be positive")

        energies: Dict[int, int] = {int(seed_node_id): 65535}
        frontier: Dict[int, int] = {int(seed_node_id): 65535}
        fired: Dict[int, int] = {}
        touched_edges = 0
        payload_decode_count = 0

        for _step in range(max_steps):
            if not frontier:
                break
            contributions: Dict[int, List[int]] = {}
            for node_id in sorted(frontier):
                energy = frontier[node_id]
                if energy < theta:
                    continue
                if node_id in fired:
                    continue
                fired[node_id] = energy
                node_index = self.find_node_index(node_id)
                if node_index < 0:
                    continue
                for dst, edge_type, attenuation, relation_code, flags, payload_ref, reserved in self.iter_edges_for_node_index(node_index):
                    touched_edges += 1
                    if edge_type == DEFAULT_EDGE_TYPES["IS_NOT_EDGE"]:
                        continue
                    next_energy = apply_attenuation_u16(energy, attenuation)
                    if next_energy >= theta:
                        contributions.setdefault(int(dst), []).append(next_energy)
                    # payload_ref is deliberately not dereferenced in hot recall.
                    _ = payload_ref

            next_frontier: Dict[int, int] = {}
            for dst in sorted(contributions):
                # Deterministic accumulation: sort contributions before saturating sum.
                total = 0
                for value in sorted(contributions[dst]):
                    total = min(65535, total + int(value))
                if total > energies.get(dst, 0):
                    energies[dst] = total
                    next_frontier[dst] = total
            frontier = next_frontier

        ranked = tuple(sorted(fired.items(), key=lambda kv: (-kv[1], kv[0]))[:top_k])
        return RecallResult(
            seed_node_id=int(seed_node_id),
            theta=int(theta),
            top_k=int(top_k),
            fired_count=len(fired),
            touched_edges=touched_edges,
            payload_decode_count=payload_decode_count,
            top_nodes=ranked,
        )


def verify_fail_closed(snapshot_dir: Path) -> Dict[str, bool]:
    with CompactHotSnapshotReader(snapshot_dir) as reader:
        clean_ok = reader.verify_manifest()
    edges_path = snapshot_dir / "edges.ubhedge"
    original = edges_path.read_bytes()
    try:
        if original:
            tampered = bytearray(original)
            tampered[-1] ^= 0x01
            edges_path.write_bytes(bytes(tampered))
            with CompactHotSnapshotReader(snapshot_dir) as reader:
                tamper_rejected = not reader.verify_manifest()
        else:
            tamper_rejected = False
    finally:
        edges_path.write_bytes(original)
    return {"clean_manifest_ok": clean_ok, "tamper_rejected": tamper_rejected}
