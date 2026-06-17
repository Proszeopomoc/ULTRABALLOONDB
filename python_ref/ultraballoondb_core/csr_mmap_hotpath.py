#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UltraBalloonDB V00P1 persistent CSR + mmap hot path reference.

Derived, rebuildable compute layout for L1/L2/L3/L4/L7. Canonical graph truth
is not changed. Base edges are stored as fixed-width binary columns and queried
through mmap CSR slices; no persistent Python object is created per base edge.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import mmap
from pathlib import Path
import struct
from typing import Iterable, Iterator, List, Sequence, Tuple

NODE_STRUCT = struct.Struct("<QQQ")  # node_id, first_edge, edge_count
EDGE_STRUCT = struct.Struct("<QIId")  # dst, edge_type, attenuation_class, weight


@dataclass(frozen=True)
class CsrEdge:
    src: int
    dst: int
    edge_type: int
    attenuation_class: int
    weight: float


@dataclass(frozen=True)
class WaveRow:
    node_id: int
    energy: float
    predecessor: int
    edge_type: int


@dataclass(frozen=True)
class FloatingSubgraph:
    nodes: Tuple[int, ...]
    edges: Tuple[Tuple[int, int, int], ...]
    stream_sha256: str


def synthetic_edges_for_node(node_id: int, event_count: int) -> Tuple[Tuple[int, int, int, int, float], ...]:
    i = int(node_id) - 1
    n = int(event_count)
    return (
        (node_id, ((i + 1) % n) + 1, 1, 1, 0.91),
        (node_id, ((i + 7) % n) + 1, 2, 1, 0.73),
        (node_id, ((i * 17 + 11) % n) + 1, 3, 2, 0.61),
    )


def iter_synthetic_edges(event_count: int) -> Iterator[Tuple[int, int, int, int, float]]:
    for node_id in range(1, int(event_count) + 1):
        yield from synthetic_edges_for_node(node_id, int(event_count))


class CsrMmapHotGraph:
    def __init__(self, layout_dir: Path):
        self.layout_dir = Path(layout_dir)
        self.nodes_path = self.layout_dir / "csr_nodes.bin"
        self.edges_path = self.layout_dir / "csr_edges.bin"
        self.manifest_path = self.layout_dir / "csr_manifest.json"
        if not (self.nodes_path.exists() and self.edges_path.exists() and self.manifest_path.exists()):
            raise FileNotFoundError("CSR mmap layout is incomplete")
        self.manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.node_count = int(self.manifest["node_count"])
        self.edge_count = int(self.manifest["edge_count"])
        if self.nodes_path.stat().st_size != self.node_count * NODE_STRUCT.size:
            raise ValueError("CSR node file size mismatch")
        if self.edges_path.stat().st_size != self.edge_count * EDGE_STRUCT.size:
            raise ValueError("CSR edge file size mismatch")
        self._nodes_file = self.nodes_path.open("rb")
        self._edges_file = self.edges_path.open("rb")
        self._nodes_mm = mmap.mmap(self._nodes_file.fileno(), 0, access=mmap.ACCESS_READ)
        self._edges_mm = mmap.mmap(self._edges_file.fileno(), 0, access=mmap.ACCESS_READ)
        self.slice_lookup_counter = 0
        self.node_rows_read_counter = 0
        self.edge_records_read_counter = 0
        self.full_scan_counter = 0

    @classmethod
    def build_from_sorted_edges(
        cls,
        layout_dir: Path,
        edges: Iterable[Tuple[int, int, int, int, float]],
    ) -> "CsrMmapHotGraph":
        layout_dir = Path(layout_dir)
        layout_dir.mkdir(parents=True, exist_ok=True)
        nodes_path = layout_dir / "csr_nodes.bin"
        edges_path = layout_dir / "csr_edges.bin"
        manifest_path = layout_dir / "csr_manifest.json"

        node_count = 0
        edge_count = 0
        current_src = None
        current_first = 0
        current_count = 0
        previous_key = None

        with nodes_path.open("wb", buffering=1024 * 1024) as nf, edges_path.open("wb", buffering=1024 * 1024) as ef:
            for src, dst, edge_type, attenuation_class, weight in edges:
                src = int(src)
                dst = int(dst)
                edge_type = int(edge_type)
                attenuation_class = int(attenuation_class)
                key = (src, edge_type, dst, attenuation_class)
                if previous_key is not None and key < previous_key:
                    raise ValueError("edges must be sorted by source/type/target")
                previous_key = key
                if current_src is None:
                    current_src = src
                    current_first = edge_count
                elif src != current_src:
                    nf.write(NODE_STRUCT.pack(current_src, current_first, current_count))
                    node_count += 1
                    current_src = src
                    current_first = edge_count
                    current_count = 0
                ef.write(EDGE_STRUCT.pack(dst, edge_type, attenuation_class, float(weight)))
                current_count += 1
                edge_count += 1
            if current_src is not None:
                nf.write(NODE_STRUCT.pack(current_src, current_first, current_count))
                node_count += 1

        manifest = {
            "version": "V00P1_R02",
            "role": "DERIVED_REBUILDABLE_CSR_MMAP_INDEX",
            "node_count": node_count,
            "edge_count": edge_count,
            "node_record_bytes": NODE_STRUCT.size,
            "edge_record_bytes": EDGE_STRUCT.size,
            "nodes_sha256": hashlib.sha256(nodes_path.read_bytes()).hexdigest().upper(),
            "edges_sha256": hashlib.sha256(edges_path.read_bytes()).hexdigest().upper(),
            "canonical_graph_mutated": False,
            "full_graph_scan_per_query": False,
            "python_edge_objects_per_base_edge": 0,
        }
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
        return cls(layout_dir)

    @classmethod
    def build_synthetic(cls, layout_dir: Path, event_count: int) -> "CsrMmapHotGraph":
        return cls.build_from_sorted_edges(layout_dir, iter_synthetic_edges(event_count))

    def close(self) -> None:
        self._nodes_mm.close()
        self._edges_mm.close()
        self._nodes_file.close()
        self._edges_file.close()

    def __enter__(self) -> "CsrMmapHotGraph":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @property
    def mmap_active(self) -> bool:
        return isinstance(self._nodes_mm, mmap.mmap) and isinstance(self._edges_mm, mmap.mmap)

    def _node_row(self, index: int) -> Tuple[int, int, int]:
        self.node_rows_read_counter += 1
        return tuple(int(x) for x in NODE_STRUCT.unpack_from(self._nodes_mm, index * NODE_STRUCT.size))

    def _find_range(self, node_id: int) -> Tuple[int, int] | None:
        self.slice_lookup_counter += 1
        target = int(node_id)
        lo, hi = 0, self.node_count
        while lo < hi:
            mid = (lo + hi) // 2
            row_node, first, count = self._node_row(mid)
            if row_node < target:
                lo = mid + 1
            elif row_node > target:
                hi = mid
            else:
                return first, count
        return None

    def get_edges(self, node_id: int) -> List[CsrEdge]:
        found = self._find_range(node_id)
        if found is None:
            return []
        first, count = found
        rows: List[CsrEdge] = []
        for edge_index in range(first, first + count):
            dst, edge_type, attenuation_class, weight = EDGE_STRUCT.unpack_from(
                self._edges_mm, edge_index * EDGE_STRUCT.size
            )
            self.edge_records_read_counter += 1
            rows.append(CsrEdge(int(node_id), int(dst), int(edge_type), int(attenuation_class), float(weight)))
        return rows

    def wave_activation(
        self,
        seed_nodes: Sequence[int],
        *,
        max_steps: int,
        energy_threshold: float,
        top_k: int,
        edge_mask: int = 0xFFFFFFFF,
    ) -> List[WaveRow]:
        frontier = {int(n): 1.0 for n in seed_nodes}
        best = dict(frontier)
        pred = {int(n): (-1, 0) for n in seed_nodes}
        for _ in range(max_steps):
            nxt = {}
            for src, energy in sorted(frontier.items()):
                for edge in self.get_edges(src):
                    if not ((1 << (edge.edge_type % 31)) & edge_mask):
                        continue
                    out = energy * edge.weight
                    if out < energy_threshold:
                        continue
                    if out > nxt.get(edge.dst, -1.0):
                        nxt[edge.dst] = out
                    if out > best.get(edge.dst, -1.0):
                        best[edge.dst] = out
                        pred[edge.dst] = (src, edge.edge_type)
            frontier = nxt
            if not frontier:
                break
        rows = [
            WaveRow(node_id, energy, pred.get(node_id, (-1, 0))[0], pred.get(node_id, (-1, 0))[1])
            for node_id, energy in best.items()
            if energy >= energy_threshold
        ]
        rows.sort(key=lambda row: (-row.energy, row.node_id))
        return rows[:top_k]

    def export_subgraph(self, selected_nodes: Sequence[int]) -> FloatingSubgraph:
        node_set = set(map(int, selected_nodes))
        edges: List[Tuple[int, int, int]] = []
        for src in sorted(node_set):
            for edge in self.get_edges(src):
                if edge.dst in node_set:
                    edges.append((edge.src, edge.dst, edge.edge_type))
        stream = json.dumps(
            {"nodes": sorted(node_set), "edges": edges}, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        return FloatingSubgraph(tuple(sorted(node_set)), tuple(edges), hashlib.sha256(stream).hexdigest().upper())

    def layout_sha256(self) -> str:
        h = hashlib.sha256()
        with self.nodes_path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        with self.edges_path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest().upper()
