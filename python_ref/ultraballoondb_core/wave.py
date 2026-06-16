#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deterministic typed topological wave activation core for UltraBalloonDB V00B.

The implementation is a compact Python reference layer. It operates only on
node IDs, typed edges, numeric attenuation, masks, thresholds and top_k.
"""
from __future__ import annotations

import heapq
from collections import defaultdict
from typing import Dict, Iterable, List, Sequence, Set, Tuple

from .types import DEFAULT_ATTENUATION, EdgeType, WaveConfig, WaveResult

EdgeTuple = Tuple[int, EdgeType, float]


class TypedGraph:
    """In-memory typed adjacency for the V00B reference core."""

    def __init__(self) -> None:
        self.adj: Dict[int, List[EdgeTuple]] = defaultdict(list)
        self.blocked_targets: Dict[int, Set[int]] = defaultdict(set)
        self.node_count = 0
        self.edge_count = 0

    def add_edge(self, src: int, dst: int, edge_type: EdgeType, weight: float = 1.0) -> None:
        if src < 0 or dst < 0:
            raise ValueError("node IDs must be non-negative")
        if not 0.0 <= weight <= 1.0:
            raise ValueError("edge weight must be in [0.0, 1.0]")
        self.node_count = max(self.node_count, src + 1, dst + 1)
        self.edge_count += 1
        self.adj[src].append((dst, edge_type, weight))
        if edge_type == EdgeType.IS_NOT_EDGE:
            self.blocked_targets[src].add(dst)

    def neighbors(self, node_id: int) -> Sequence[EdgeTuple]:
        return self.adj.get(node_id, ())


def _normalize_mask(edge_mask: Iterable[EdgeType]) -> Set[EdgeType]:
    normalized: Set[EdgeType] = set()
    for item in edge_mask:
        normalized.add(item if isinstance(item, EdgeType) else EdgeType(int(item)))
    return normalized


def wave_activation(
    graph: TypedGraph,
    config: WaveConfig,
    attenuation: Dict[EdgeType, float] | None = None,
) -> Tuple[List[WaveResult], Dict[str, int | float]]:
    """Propagate numeric energy through typed edges and return deterministic top_k.

    Blocking edges are applied before propagation to a target. Edge masks are
    applied before expansion. The function does not fetch payloads and does not
    interpret node meaning.
    """
    if config.top_k <= 0:
        raise ValueError("top_k must be positive")
    if config.max_steps < 0:
        raise ValueError("max_steps must be non-negative")
    if config.energy_threshold < 0.0:
        raise ValueError("energy_threshold must be non-negative")
    if config.rigor_multiplier <= 0.0:
        raise ValueError("rigor_multiplier must be positive")

    atten = attenuation or DEFAULT_ATTENUATION
    allowed = _normalize_mask(config.edge_mask)

    best_energy: Dict[int, float] = {config.seed_node: 1.0}
    best_path: Dict[int, Tuple[EdgeType, ...]] = {config.seed_node: tuple()}
    best_len: Dict[int, int] = {config.seed_node: 0}
    queue: List[Tuple[float, int, int, Tuple[EdgeType, ...]]] = [(-1.0, config.seed_node, 0, tuple())]

    expanded = 0
    filtered_by_mask = 0
    filtered_by_threshold = 0
    blocked_path_count = 0

    while queue:
        neg_energy, node, steps, path = heapq.heappop(queue)
        current_energy = -neg_energy
        if current_energy + 1e-15 < best_energy.get(node, 0.0):
            continue
        if steps >= config.max_steps:
            continue
        expanded += 1
        blocked_from_node = graph.blocked_targets.get(node, set())
        for dst, edge_type, weight in graph.neighbors(node):
            if edge_type == EdgeType.IS_NOT_EDGE:
                blocked_path_count += 1
                continue
            if edge_type not in allowed:
                filtered_by_mask += 1
                continue
            if dst in blocked_from_node:
                blocked_path_count += 1
                continue
            edge_attenuation = atten.get(edge_type, 0.0)
            next_energy = current_energy * edge_attenuation * weight * config.rigor_multiplier
            if next_energy < config.energy_threshold:
                filtered_by_threshold += 1
                continue
            if next_energy > best_energy.get(dst, -1.0) + 1e-15:
                next_path = path + (edge_type,)
                best_energy[dst] = next_energy
                best_path[dst] = next_path
                best_len[dst] = steps + 1
                heapq.heappush(queue, (-next_energy, dst, steps + 1, next_path))

    rows = [
        WaveResult(
            node_id=node,
            energy_score=round(energy, 12),
            best_path_len=best_len[node],
            path_edge_types=best_path[node],
            record_id=node,
        )
        for node, energy in best_energy.items()
        if energy >= config.energy_threshold
    ]
    rows.sort(key=lambda r: (-r.energy_score, r.best_path_len, r.node_id))
    limited = rows[: config.top_k]
    stats = {
        "expanded_nodes": expanded,
        "filtered_by_mask": filtered_by_mask,
        "filtered_by_threshold": filtered_by_threshold,
        "blocked_path_count": blocked_path_count,
        "result_count_before_top_k": len(rows),
        "result_count_after_top_k": len(limited),
    }
    return limited, stats


def build_synthetic_typed_graph(logical_edges_target: int) -> TypedGraph:
    """Build deterministic typed graph with approximately the requested edge count."""
    if logical_edges_target < 100:
        raise ValueError("logical_edges_target must be >= 100")
    graph = TypedGraph()
    # Keep out-degree bounded. Node count is chosen so that the workload is edge-led.
    node_count = max(64, logical_edges_target // 4)
    i = 0
    while graph.edge_count < logical_edges_target:
        src = i % node_count
        graph.add_edge(src, (src + 1) % node_count, EdgeType.PROJECT_CONTEXT, 1.0)
        if graph.edge_count >= logical_edges_target:
            break
        graph.add_edge(src, (src * 17 + 13) % node_count, EdgeType.CODE_PATTERN, 0.97)
        if graph.edge_count >= logical_edges_target:
            break
        parent = src // 4
        if src != parent:
            graph.add_edge(src, parent, EdgeType.UP_RULE, 0.92)
        else:
            graph.add_edge(src, (src + 7) % node_count, EdgeType.LATERAL_SIMILAR_CASE, 0.88)
        if graph.edge_count >= logical_edges_target:
            break
        graph.add_edge(parent, src, EdgeType.DOWN_EVIDENCE, 0.70)
        if graph.edge_count >= logical_edges_target:
            break
        if src % 97 == 0:
            blocked = (src * 17 + 13) % node_count
            graph.add_edge(src, blocked, EdgeType.IS_NOT_EDGE, 1.0)
        i += 1
    return graph
