#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UltraBalloonDB V00L real hot snapshot -> wave -> floating subgraph binding.

This is a core integration layer. It binds the existing product layers:
- L1 exact byte references into the hot edge file,
- L2 typed edge graph,
- L3 deterministic wave activation,
- L4 real hot snapshot,
- L7 deterministic floating subgraph export/import.

It does not interpret payload meaning, call models, or replace the typed graph or
wave activation with a compression or embedding subsystem.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple

from ultraballoondb_core.floating_subgraph import encode_stream, sha256_hex
from ultraballoondb_core.hot_snapshot import HOT_EDGE_STRUCT, load_hot_snapshot, snapshot_paths
from ultraballoondb_core.types import EdgeType, WaveConfig, WaveResult
from ultraballoondb_core.wave import TypedGraph, wave_activation

VERSION = "V00L_REAL_HOT_WAVE_SUBGRAPH_BINDING"
DEFAULT_PAGE_SIZE = 4096


@dataclass(frozen=True)
class HotEdgeRecord:
    edge_index: int
    byte_offset: int
    src: int
    dst: int
    edge_type: EdgeType
    relation_id: int
    weight: float


@dataclass(frozen=True)
class LoadedHotWaveGraph:
    snapshot_dir: Path
    snapshot_sha256: str
    manifest: Mapping[str, object]
    graph: TypedGraph
    edges: Tuple[HotEdgeRecord, ...]
    node_first_edge: Mapping[int, int]
    page_size: int = DEFAULT_PAGE_SIZE


@dataclass(frozen=True)
class SeedWaveRow:
    seed_node: int
    result: WaveResult


def _snapshot_hash(manifest: Mapping[str, object]) -> str:
    value = str(manifest.get("snapshot_sha256", ""))
    if len(value) != 64:
        raise ValueError("hot snapshot manifest is missing snapshot_sha256")
    return value.upper()


def load_real_hot_wave_graph(snapshot_dir: Path, *, page_size: int = DEFAULT_PAGE_SIZE) -> LoadedHotWaveGraph:
    if page_size <= 0:
        raise ValueError("page_size must be positive")
    snapshot_dir = Path(snapshot_dir).resolve()
    loaded = load_hot_snapshot(snapshot_dir, load_crystals=False)
    paths = snapshot_paths(snapshot_dir)
    graph = TypedGraph()
    records: List[HotEdgeRecord] = []
    node_first_edge: Dict[int, int] = {}

    with open(paths.edges_path, "rb") as f:
        edge_index = 0
        while True:
            byte_offset = f.tell()
            chunk = f.read(HOT_EDGE_STRUCT.size)
            if not chunk:
                break
            if len(chunk) != HOT_EDGE_STRUCT.size:
                raise ValueError("partial hot edge record")
            src, dst, edge_type_raw, relation_id, weight_milli = HOT_EDGE_STRUCT.unpack(chunk)
            try:
                edge_type = EdgeType(int(edge_type_raw))
            except ValueError as exc:
                raise ValueError(f"unknown edge type code in hot snapshot: {edge_type_raw}") from exc
            weight = float(weight_milli) / 1000.0
            if weight < 0.0 or weight > 1.0:
                raise ValueError("hot edge weight outside [0,1]")
            graph.add_edge(int(src), int(dst), edge_type, weight)
            record = HotEdgeRecord(
                edge_index=edge_index,
                byte_offset=byte_offset,
                src=int(src),
                dst=int(dst),
                edge_type=edge_type,
                relation_id=int(relation_id),
                weight=weight,
            )
            records.append(record)
            node_first_edge.setdefault(int(src), edge_index)
            node_first_edge.setdefault(int(dst), edge_index)
            edge_index += 1

    if len(records) != int(loaded.edge_count):
        raise ValueError("hot edge count mismatch")

    return LoadedHotWaveGraph(
        snapshot_dir=snapshot_dir,
        snapshot_sha256=_snapshot_hash(loaded.manifest),
        manifest=loaded.manifest,
        graph=graph,
        edges=tuple(records),
        node_first_edge=dict(node_first_edge),
        page_size=int(page_size),
    )


def run_seed_waves(
    loaded: LoadedHotWaveGraph,
    seed_nodes: Iterable[int],
    *,
    edge_mask: Sequence[EdgeType],
    energy_threshold: float,
    top_k_per_seed: int,
    max_steps: int,
    rigor_multiplier: float = 1.0,
) -> Tuple[Tuple[SeedWaveRow, ...], Mapping[str, int | float]]:
    seeds = tuple(sorted(set(int(x) for x in seed_nodes)))
    if not seeds:
        raise ValueError("at least one seed node is required")

    rows: List[SeedWaveRow] = []
    aggregate = {
        "seed_query_count": len(seeds),
        "expanded_nodes": 0,
        "filtered_by_mask": 0,
        "filtered_by_threshold": 0,
        "blocked_path_count": 0,
        "result_count_before_top_k": 0,
        "result_count_after_top_k": 0,
    }
    for seed in seeds:
        results, stats = wave_activation(
            loaded.graph,
            WaveConfig(
                seed_node=seed,
                edge_mask=tuple(edge_mask),
                energy_threshold=float(energy_threshold),
                top_k=int(top_k_per_seed),
                max_steps=int(max_steps),
                rigor_multiplier=float(rigor_multiplier),
            ),
        )
        rows.extend(SeedWaveRow(seed_node=seed, result=result) for result in results)
        for key in aggregate:
            if key == "seed_query_count":
                continue
            aggregate[key] = int(aggregate[key]) + int(stats.get(key, 0))

    rows.sort(
        key=lambda row: (
            row.seed_node,
            -row.result.energy_score,
            row.result.best_path_len,
            row.result.node_id,
        )
    )
    return tuple(rows), aggregate


def _node_pointer(loaded: LoadedHotWaveGraph, node_id: int) -> Mapping[str, object]:
    edge_index = int(loaded.node_first_edge.get(int(node_id), -1))
    if edge_index < 0:
        return {
            "record_id": f"hotnode:{node_id}",
            "page_id": -1,
            "offset": -1,
            "length": 0,
            "source": "HOT_SNAPSHOT_NODE_ONLY",
        }
    byte_offset = edge_index * HOT_EDGE_STRUCT.size
    return {
        "record_id": f"hotedge:{edge_index}",
        "page_id": byte_offset // loaded.page_size,
        "offset": byte_offset,
        "length": HOT_EDGE_STRUCT.size,
        "source": "HOT_EDGE_FILE",
    }


def export_wave_rows_as_floating_subgraph(
    loaded: LoadedHotWaveGraph,
    rows: Sequence[SeedWaveRow],
    *,
    export_params: Mapping[str, object],
    wave_stats: Mapping[str, int | float],
) -> bytes:
    if not rows:
        raise ValueError("wave rows cannot be empty")

    best_by_node: Dict[int, SeedWaveRow] = {}
    seeds_by_node: Dict[int, set[int]] = {}
    for row in rows:
        node_id = int(row.result.node_id)
        seeds_by_node.setdefault(node_id, set()).add(int(row.seed_node))
        previous = best_by_node.get(node_id)
        candidate_key = (
            float(row.result.energy_score),
            -int(row.result.best_path_len),
            -int(row.seed_node),
        )
        if previous is None:
            best_by_node[node_id] = row
        else:
            previous_key = (
                float(previous.result.energy_score),
                -int(previous.result.best_path_len),
                -int(previous.seed_node),
            )
            if candidate_key > previous_key:
                best_by_node[node_id] = row

    selected_nodes = set(best_by_node)
    nodes_out: List[Mapping[str, object]] = []
    for node_id in sorted(selected_nodes):
        row = best_by_node[node_id]
        nodes_out.append({
            "node_id": node_id,
            "node_type": "TYPED_GRAPH_NODE",
            "best_energy": round(float(row.result.energy_score), 12),
            "best_depth": int(row.result.best_path_len),
            "path_edge_types": [edge_type.name for edge_type in row.result.path_edge_types],
            "seed_nodes": sorted(seeds_by_node[node_id]),
            "record_pointer": dict(_node_pointer(loaded, node_id)),
        })

    edges_out: List[Mapping[str, object]] = []
    provenance_refs: List[str] = []
    for record in loaded.edges:
        if record.src not in selected_nodes or record.dst not in selected_nodes:
            continue
        provenance_id = f"hot:{loaded.snapshot_sha256}:{record.edge_index}"
        provenance_refs.append(provenance_id)
        edges_out.append({
            "src": record.src,
            "dst": record.dst,
            "edge_type": record.edge_type.name,
            "weight": round(record.weight, 12),
            "relation_id": record.relation_id,
            "hot_edge_index": record.edge_index,
            "provenance_id": provenance_id,
        })

    content = {
        "format": "floating_subgraph",
        "format_version": VERSION,
        "source_hot_snapshot_hash": loaded.snapshot_sha256,
        "export_params": dict(export_params),
        "wave_stats": dict(wave_stats),
        "nodes": nodes_out,
        "edges": edges_out,
        "provenance_refs": sorted(provenance_refs),
        "blocked_path_count": int(wave_stats.get("blocked_path_count", 0)),
        "payload_policy": "POINTERS_ONLY_NO_PAYLOAD_BYTES",
        "agent_policy": "NO_AGENT_POLICY_NO_LLM_NO_SEMANTIC_INTERPRETATION",
        "core_binding": {
            "L1_exact_index": True,
            "L2_typed_edge_graph": True,
            "L3_wave_activation": True,
            "L4_hot_snapshot": True,
            "L7_floating_subgraph": True,
            "compression_replaces_graph_or_wave": False,
        },
    }
    return encode_stream(content)


def stream_sha256(stream: bytes) -> str:
    return sha256_hex(stream)
