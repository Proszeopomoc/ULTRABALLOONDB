#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Typed IDs and immutable result records for UltraBalloonDB V00B.

This file intentionally contains database-side numeric structures only.
No agent policy, no text meaning, no model calls.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Tuple


class EdgeType(IntEnum):
    UP_RULE = 1
    DOWN_EVIDENCE = 2
    LATERAL_SIMILAR_CASE = 3
    PROJECT_CONTEXT = 4
    CODE_PATTERN = 5
    RULE_TO_EVIDENCE = 6
    RULE_TO_CODE_PATTERN = 7
    PROJECT_TO_RECENT_SEED = 8
    CODE_TO_RECENT_RULE = 9
    IS_NOT_EDGE = 10


DEFAULT_ATTENUATION = {
    EdgeType.UP_RULE: 0.70,
    EdgeType.DOWN_EVIDENCE: 0.25,
    EdgeType.LATERAL_SIMILAR_CASE: 0.40,
    EdgeType.PROJECT_CONTEXT: 0.75,
    EdgeType.CODE_PATTERN: 0.90,
    EdgeType.RULE_TO_EVIDENCE: 0.55,
    EdgeType.RULE_TO_CODE_PATTERN: 0.65,
    EdgeType.PROJECT_TO_RECENT_SEED: 0.80,
    EdgeType.CODE_TO_RECENT_RULE: 0.85,
    EdgeType.IS_NOT_EDGE: 0.0,
}


@dataclass(frozen=True)
class WaveConfig:
    seed_node: int
    edge_mask: Tuple[EdgeType, ...]
    energy_threshold: float
    top_k: int
    max_steps: int
    rigor_multiplier: float = 1.0


@dataclass(frozen=True)
class WaveResult:
    node_id: int
    energy_score: float
    best_path_len: int
    path_edge_types: Tuple[EdgeType, ...]
    record_id: int | None = None
