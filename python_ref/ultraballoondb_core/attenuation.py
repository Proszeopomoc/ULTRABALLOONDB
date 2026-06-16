#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UltraBalloonDB V00C edge attenuation table.

This module keeps numeric edge attenuation outside the wave traversal code.
It is intentionally small and deterministic: no payload fetching, no network,
no semantic interpretation.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Dict, Iterable, Mapping, Tuple, Union
import hashlib
import json

EDGE_TYPE_NAMES: Tuple[str, ...] = (
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
EDGE_TYPE_IDS: Mapping[str, int] = MappingProxyType({name: idx for idx, name in enumerate(EDGE_TYPE_NAMES)})
EDGE_ID_TO_NAME: Mapping[int, str] = MappingProxyType({idx: name for idx, name in enumerate(EDGE_TYPE_NAMES)})
BLOCKING_EDGE_TYPE = "IS_NOT_EDGE"

DEFAULT_ATTENUATION_PROFILES: Mapping[str, Mapping[str, float]] = MappingProxyType({
    "STRICT_V00C": MappingProxyType({
        "UP_RULE": 0.66,
        "DOWN_EVIDENCE": 0.16,
        "LATERAL_SIMILAR_CASE": 0.18,
        "PROJECT_CONTEXT": 0.58,
        "CODE_PATTERN": 0.88,
        "RULE_TO_EVIDENCE": 0.28,
        "RULE_TO_CODE_PATTERN": 0.82,
        "PROJECT_TO_RECENT_SEED": 0.36,
        "CODE_TO_RECENT_RULE": 0.72,
        "IS_NOT_EDGE": 0.0,
    }),
    "BALANCED_V00C": MappingProxyType({
        "UP_RULE": 0.70,
        "DOWN_EVIDENCE": 0.25,
        "LATERAL_SIMILAR_CASE": 0.40,
        "PROJECT_CONTEXT": 0.75,
        "CODE_PATTERN": 0.90,
        "RULE_TO_EVIDENCE": 0.42,
        "RULE_TO_CODE_PATTERN": 0.86,
        "PROJECT_TO_RECENT_SEED": 0.55,
        "CODE_TO_RECENT_RULE": 0.80,
        "IS_NOT_EDGE": 0.0,
    }),
    "EXPLORATIVE_V00C": MappingProxyType({
        "UP_RULE": 0.76,
        "DOWN_EVIDENCE": 0.38,
        "LATERAL_SIMILAR_CASE": 0.62,
        "PROJECT_CONTEXT": 0.82,
        "CODE_PATTERN": 0.92,
        "RULE_TO_EVIDENCE": 0.55,
        "RULE_TO_CODE_PATTERN": 0.88,
        "PROJECT_TO_RECENT_SEED": 0.72,
        "CODE_TO_RECENT_RULE": 0.86,
        "IS_NOT_EDGE": 0.0,
    }),
})

EdgeType = Union[str, int]


def normalize_edge_type(edge_type: EdgeType) -> str:
    if isinstance(edge_type, str):
        if edge_type not in EDGE_TYPE_IDS:
            raise KeyError(f"Unknown edge type name: {edge_type}")
        return edge_type
    if isinstance(edge_type, int):
        if edge_type not in EDGE_ID_TO_NAME:
            raise KeyError(f"Unknown edge type id: {edge_type}")
        return EDGE_ID_TO_NAME[edge_type]
    raise TypeError(f"edge_type must be str or int, got {type(edge_type).__name__}")


@dataclass(frozen=True)
class EdgeAttenuationTable:
    """Immutable numeric attenuation table for typed-edge wave traversal."""

    profile_name: str
    values: Mapping[str, float]
    version: str = "V00C_EDGE_ATTENUATION_TABLE"

    def __post_init__(self) -> None:
        normalized = {normalize_edge_type(k): float(v) for k, v in dict(self.values).items()}
        object.__setattr__(self, "values", MappingProxyType(normalized))
        self.validate()

    def attenuation(self, edge_type: EdgeType) -> float:
        return self.values[normalize_edge_type(edge_type)]

    def validate(self) -> None:
        missing = [name for name in EDGE_TYPE_NAMES if name not in self.values]
        extra = [name for name in self.values if name not in EDGE_TYPE_IDS]
        if missing:
            raise ValueError(f"Missing attenuation values: {missing}")
        if extra:
            raise ValueError(f"Unknown attenuation values: {extra}")
        for name, value in self.values.items():
            if not (0.0 <= float(value) <= 1.0):
                raise ValueError(f"Attenuation for {name} out of range: {value}")
        if self.values[BLOCKING_EDGE_TYPE] != 0.0:
            raise ValueError("IS_NOT_EDGE attenuation must be exactly 0.0")

    def to_ordered_dict(self) -> Dict[str, object]:
        return {
            "version": self.version,
            "profile_name": self.profile_name,
            "edge_type_count": len(EDGE_TYPE_NAMES),
            "values": {name: self.values[name] for name in EDGE_TYPE_NAMES},
        }

    def stable_hash(self) -> str:
        payload = json.dumps(self.to_ordered_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(payload).hexdigest().upper()

    @classmethod
    def from_profile(cls, profile_name: str) -> "EdgeAttenuationTable":
        if profile_name not in DEFAULT_ATTENUATION_PROFILES:
            raise KeyError(f"Unknown attenuation profile: {profile_name}")
        return cls(profile_name=profile_name, values=dict(DEFAULT_ATTENUATION_PROFILES[profile_name]))

    @classmethod
    def from_json_text(cls, text: str) -> "EdgeAttenuationTable":
        data = json.loads(text)
        return cls(profile_name=str(data["profile_name"]), values=dict(data["values"]), version=str(data.get("version", "V00C_EDGE_ATTENUATION_TABLE")))

    def to_json_text(self) -> str:
        return json.dumps(self.to_ordered_dict(), indent=2, sort_keys=True) + "\n"


def make_default_table(profile_name: str = "BALANCED_V00C") -> EdgeAttenuationTable:
    return EdgeAttenuationTable.from_profile(profile_name)


def all_default_tables() -> Tuple[EdgeAttenuationTable, ...]:
    return tuple(EdgeAttenuationTable.from_profile(name) for name in sorted(DEFAULT_ATTENUATION_PROFILES))


def compile_edge_mask(edge_type_names: Iterable[EdgeType]) -> frozenset[str]:
    return frozenset(normalize_edge_type(edge_type) for edge_type in edge_type_names)
