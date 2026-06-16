#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UltraBalloonDB V00H: deterministic floating subgraph export/import.

DB-side only. This module exports compact topology fragments from a hot snapshot
and imports/hot-patches them into another in-memory instance. It stores node ids,
edge types, record pointers, numeric energy, provenance, and hashes. It does not
call any model, interpret text, summarize payloads, or make agent decisions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import heapq
import json
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Set, Tuple

STREAM_MAGIC = "ULTRABALLOONDB_FLOATING_SUBGRAPH_V00H"
STREAM_VERSION = 1

EDGE_TYPES: Tuple[str, ...] = (
    "UP_RULE",
    "DOWN_EVIDENCE",
    "LATERAL_SIMILAR_CASE",
    "PROJECT_CONTEXT",
    "CODE_PATTERN",
    "RULE_TO_EVIDENCE",
    "RULE_TO_CODE_PATTERN",
    "PROJECT_TO_RECENT_SEED",
    "CODE_TO_RECENT_RULE",
    "IS_NOT_EDGE",
)

DEFAULT_ATTENUATION: Mapping[str, float] = {
    "UP_RULE": 0.70,
    "DOWN_EVIDENCE": 0.25,
    "LATERAL_SIMILAR_CASE": 0.40,
    "PROJECT_CONTEXT": 0.75,
    "CODE_PATTERN": 0.90,
    "RULE_TO_EVIDENCE": 0.62,
    "RULE_TO_CODE_PATTERN": 0.66,
    "PROJECT_TO_RECENT_SEED": 0.58,
    "CODE_TO_RECENT_RULE": 0.64,
    "IS_NOT_EDGE": 0.0,
}

NODE_TYPES: Tuple[str, ...] = (
    "SEED",
    "BRIDGE",
    "RULE_CANDIDATE",
    "EVIDENCE",
    "CODE_PATTERN_NODE",
    "CRYSTAL_NODE",
)


class FloatingSubgraphError(ValueError):
    """Raised when a floating subgraph byte stream fails validation."""


@dataclass(frozen=True)
class HotEdge:
    src: int
    dst: int
    edge_type: str
    weight: float
    provenance_id: str


@dataclass(frozen=True)
class ExportParams:
    root_node: int
    max_steps: int
    edge_mask: Tuple[str, ...]
    energy_threshold: float
    top_k: int
    rigor_multiplier: float = 1.0

    def normalized(self) -> "ExportParams":
        mask = tuple(sorted(set(self.edge_mask)))
        if self.root_node < 0:
            raise FloatingSubgraphError("root_node must be >= 0")
        if self.max_steps < 0:
            raise FloatingSubgraphError("max_steps must be >= 0")
        if self.energy_threshold < 0.0:
            raise FloatingSubgraphError("energy_threshold must be >= 0")
        if self.top_k <= 0:
            raise FloatingSubgraphError("top_k must be > 0")
        if self.rigor_multiplier <= 0.0:
            raise FloatingSubgraphError("rigor_multiplier must be > 0")
        unknown = [x for x in mask if x not in EDGE_TYPES]
        if unknown:
            raise FloatingSubgraphError("unknown edge types in edge_mask: " + ",".join(unknown))
        return ExportParams(
            root_node=int(self.root_node),
            max_steps=int(self.max_steps),
            edge_mask=mask,
            energy_threshold=float(self.energy_threshold),
            top_k=int(self.top_k),
            rigor_multiplier=float(self.rigor_multiplier),
        )


@dataclass
class SyntheticHotSnapshot:
    """
    Deterministic synthetic hot snapshot used for V00H selftests.

    It intentionally generates adjacency lazily from node id and logical size,
    so million-event tests measure export/import behavior without allocating
    a huge archive. The lossless archive remains represented by stable record
    pointers and provenance ids only.
    """

    logical_event_count: int
    schema_version: str = "V00H_SYNTHETIC_HOT_SNAPSHOT"
    imported_nodes: Dict[int, Mapping[str, object]] = field(default_factory=dict)
    imported_edges: List[Mapping[str, object]] = field(default_factory=list)
    imported_stream_hashes: Set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if self.logical_event_count <= 0:
            raise FloatingSubgraphError("logical_event_count must be > 0")

    def normalize_node(self, node_id: int) -> int:
        return int(node_id) % self.logical_event_count

    def node_type(self, node_id: int) -> str:
        return NODE_TYPES[self.normalize_node(node_id) % len(NODE_TYPES)]

    def record_pointer(self, node_id: int) -> Mapping[str, object]:
        nid = self.normalize_node(node_id)
        # Pointer only. No payload bytes are exported in V00H.
        return {
            "record_id": f"rec:{self.logical_event_count}:{nid}",
            "page_id": nid // 256,
            "offset": (nid % 256) * 64,
            "length": 64,
        }

    def provenance_id(self, src: int, dst: int, edge_type: str) -> str:
        src_n = self.normalize_node(src)
        dst_n = self.normalize_node(dst)
        return f"prov:{self.logical_event_count}:{src_n}:{edge_type}:{dst_n}"

    def fingerprint(self) -> str:
        payload = {
            "logical_event_count": self.logical_event_count,
            "schema_version": self.schema_version,
            "edge_types": EDGE_TYPES,
            "node_types": NODE_TYPES,
        }
        return sha256_hex(canonical_json_bytes(payload))

    def edges_from(self, node_id: int) -> List[HotEdge]:
        n = self.logical_event_count
        src = self.normalize_node(node_id)
        candidates = (
            ((src + 1) % n, "PROJECT_CONTEXT", 1.00),
            ((src * 31 + 7) % n, "CODE_PATTERN", 0.96),
            ((src + 1024) % n, "LATERAL_SIMILAR_CASE", 0.78),
            ((src * 17 + 3) % n, "RULE_TO_EVIDENCE", 0.88),
            ((src * 19 + 11) % n, "RULE_TO_CODE_PATTERN", 0.84),
            ((src + 13) % n, "IS_NOT_EDGE", 1.00),
        )
        edges = [
            HotEdge(src=src, dst=dst, edge_type=edge_type, weight=float(weight), provenance_id=self.provenance_id(src, dst, edge_type))
            for dst, edge_type, weight in candidates
        ]
        return sorted(edges, key=lambda e: (e.edge_type, e.dst, e.provenance_id))


@dataclass
class ExportReport:
    stream_hash: str
    byte_length: int
    node_count: int
    edge_count: int
    provenance_ref_count: int
    blocked_path_count: int
    max_depth_seen: int


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def _round_energy(x: float) -> float:
    # Keeps byte streams stable across platforms while preserving ordering.
    return round(float(x), 12)


def _stream_envelope(content: Mapping[str, object]) -> Mapping[str, object]:
    content_bytes = canonical_json_bytes(content)
    return {
        "magic": STREAM_MAGIC,
        "version": STREAM_VERSION,
        "content_sha256": sha256_hex(content_bytes),
        "content": content,
    }


def encode_stream(content: Mapping[str, object]) -> bytes:
    return canonical_json_bytes(_stream_envelope(content))


def decode_stream(stream: bytes) -> Mapping[str, object]:
    try:
        envelope = json.loads(stream.decode("utf-8"))
    except Exception as exc:
        raise FloatingSubgraphError(f"invalid floating subgraph stream: {exc}") from exc
    if envelope.get("magic") != STREAM_MAGIC:
        raise FloatingSubgraphError("invalid floating subgraph magic")
    if envelope.get("version") != STREAM_VERSION:
        raise FloatingSubgraphError("unsupported floating subgraph version")
    content = envelope.get("content")
    if not isinstance(content, dict):
        raise FloatingSubgraphError("missing content")
    expected = envelope.get("content_sha256")
    actual = sha256_hex(canonical_json_bytes(content))
    if expected != actual:
        raise FloatingSubgraphError("content hash mismatch")
    # Re-encode to ensure no alternate serialization is accepted silently.
    if sha256_hex(encode_stream(content)) != sha256_hex(stream):
        raise FloatingSubgraphError("non-canonical floating subgraph stream")
    return content


def verify_stream(stream: bytes) -> str:
    decode_stream(stream)
    return sha256_hex(stream)


def export_floating_subgraph(hot_snapshot: SyntheticHotSnapshot, params: ExportParams) -> Tuple[bytes, ExportReport]:
    p = params.normalized()
    root = hot_snapshot.normalize_node(p.root_node)
    edge_mask = set(p.edge_mask)
    blocked_path_count = 0
    max_depth_seen = 0

    # max-heap using negative energy; node_id tie keeps deterministic ordering.
    heap: List[Tuple[float, int, int, Tuple[str, ...]]] = []
    start_energy = _round_energy(1.0 * p.rigor_multiplier)
    heapq.heappush(heap, (-start_energy, root, 0, tuple()))

    best_energy: Dict[int, float] = {}
    best_depth: Dict[int, int] = {}
    best_path_types: Dict[int, Tuple[str, ...]] = {}
    selected_order: List[int] = []
    traversed_edges: Dict[Tuple[int, int, str], HotEdge] = {}
    provenance_refs: Set[str] = set()

    while heap and len(selected_order) < p.top_k:
        neg_energy, node_id, depth, path_types = heapq.heappop(heap)
        energy = _round_energy(-neg_energy)
        if energy < p.energy_threshold:
            continue
        prev = best_energy.get(node_id)
        if prev is not None and prev >= energy:
            continue

        best_energy[node_id] = energy
        best_depth[node_id] = depth
        best_path_types[node_id] = path_types
        selected_order.append(node_id)
        max_depth_seen = max(max_depth_seen, depth)

        if depth >= p.max_steps:
            continue

        for edge in hot_snapshot.edges_from(node_id):
            if edge.edge_type == "IS_NOT_EDGE":
                blocked_path_count += 1
                continue
            if edge.edge_type not in edge_mask:
                continue
            attenuation = float(DEFAULT_ATTENUATION[edge.edge_type])
            next_energy = _round_energy(energy * attenuation * edge.weight)
            if next_energy < p.energy_threshold:
                continue
            dst = hot_snapshot.normalize_node(edge.dst)
            edge_key = (edge.src, dst, edge.edge_type)
            traversed_edges[edge_key] = edge
            provenance_refs.add(edge.provenance_id)
            heapq.heappush(heap, (-next_energy, dst, depth + 1, path_types + (edge.edge_type,)))

    selected_nodes = sorted(best_energy.keys())
    selected_set = set(selected_nodes)
    edges_out = []
    for key in sorted(traversed_edges.keys(), key=lambda k: (k[0], k[2], k[1])):
        src, dst, edge_type = key
        if src in selected_set and dst in selected_set:
            e = traversed_edges[key]
            edges_out.append({
                "src": int(src),
                "dst": int(dst),
                "edge_type": edge_type,
                "weight": _round_energy(e.weight),
                "provenance_id": e.provenance_id,
            })

    nodes_out = []
    for nid in selected_nodes:
        nodes_out.append({
            "node_id": int(nid),
            "node_type": hot_snapshot.node_type(nid),
            "best_energy": _round_energy(best_energy[nid]),
            "best_depth": int(best_depth[nid]),
            "path_edge_types": list(best_path_types[nid]),
            "record_pointer": dict(hot_snapshot.record_pointer(nid)),
        })

    content = {
        "format": "floating_subgraph",
        "format_version": "V00H",
        "source_hot_snapshot_hash": hot_snapshot.fingerprint(),
        "export_params": {
            "root_node": root,
            "max_steps": p.max_steps,
            "edge_mask": list(p.edge_mask),
            "energy_threshold": _round_energy(p.energy_threshold),
            "top_k": p.top_k,
            "rigor_multiplier": _round_energy(p.rigor_multiplier),
        },
        "nodes": nodes_out,
        "edges": edges_out,
        "provenance_refs": sorted(provenance_refs),
        "blocked_path_count": int(blocked_path_count),
        "payload_policy": "POINTERS_ONLY_NO_PAYLOAD_BYTES",
        "agent_policy": "NO_AGENT_POLICY_NO_LLM_NO_SEMANTIC_INTERPRETATION",
    }
    stream = encode_stream(content)
    report = ExportReport(
        stream_hash=sha256_hex(stream),
        byte_length=len(stream),
        node_count=len(nodes_out),
        edge_count=len(edges_out),
        provenance_ref_count=len(provenance_refs),
        blocked_path_count=blocked_path_count,
        max_depth_seen=max_depth_seen,
    )
    return stream, report


def import_floating_subgraph(stream: bytes) -> Mapping[str, object]:
    content = decode_stream(stream)
    required = ("nodes", "edges", "provenance_refs", "source_hot_snapshot_hash", "export_params")
    for key in required:
        if key not in content:
            raise FloatingSubgraphError(f"missing content key: {key}")
    if content.get("payload_policy") != "POINTERS_ONLY_NO_PAYLOAD_BYTES":
        raise FloatingSubgraphError("unexpected payload policy")
    return content


def hot_patch_subgraph(target_snapshot: SyntheticHotSnapshot, stream: bytes) -> Mapping[str, object]:
    content = import_floating_subgraph(stream)
    stream_hash = sha256_hex(stream)
    if stream_hash in target_snapshot.imported_stream_hashes:
        return {
            "status": "ALREADY_IMPORTED",
            "stream_hash": stream_hash,
            "imported_node_count": 0,
            "imported_edge_count": 0,
        }

    nodes = content["nodes"]
    edges = content["edges"]
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise FloatingSubgraphError("nodes and edges must be lists")

    for node in nodes:
        if not isinstance(node, dict) or "node_id" not in node:
            raise FloatingSubgraphError("invalid node record")
        target_snapshot.imported_nodes[int(node["node_id"])] = node
    before_edges = len(target_snapshot.imported_edges)
    for edge in edges:
        if not isinstance(edge, dict):
            raise FloatingSubgraphError("invalid edge record")
        target_snapshot.imported_edges.append(edge)
    target_snapshot.imported_stream_hashes.add(stream_hash)

    return {
        "status": "IMPORTED",
        "stream_hash": stream_hash,
        "source_hot_snapshot_hash": content["source_hot_snapshot_hash"],
        "imported_node_count": len(nodes),
        "imported_edge_count": len(target_snapshot.imported_edges) - before_edges,
        "provenance_ref_count": len(content["provenance_refs"]),
    }


def target_patch_fingerprint(target_snapshot: SyntheticHotSnapshot) -> str:
    payload = {
        "logical_event_count": target_snapshot.logical_event_count,
        "imported_nodes": target_snapshot.imported_nodes,
        "imported_edges": target_snapshot.imported_edges,
        "imported_stream_hashes": sorted(target_snapshot.imported_stream_hashes),
    }
    return sha256_hex(canonical_json_bytes(payload))
