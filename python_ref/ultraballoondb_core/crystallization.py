#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UltraBalloonDB V00F: deterministic crystallization paths.

This module is DB-side and semantics-blind. It observes repeated topological
path signatures and emits compact structural crystal nodes that point back to
original evidence records. It never deletes archive evidence, never calls a
model, never interprets payload text, and never performs agent policy logic.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

ACTIVE = "ACTIVE"
REVOKED = "REVOKED"
SKIPPED_BLOCKED = "SKIPPED_BLOCKED"
SKIPPED_LOW_SUPPORT = "SKIPPED_LOW_SUPPORT"
IS_NOT_EDGE = "IS_NOT_EDGE"


@dataclass(frozen=True)
class PathObservation:
    """One observed typed path, plus links to full external evidence.

    path_id and record_ids are opaque DB identifiers. They are not interpreted.
    edge_types are symbolic edge-type IDs already known to the DB core.
    """

    path_id: str
    edge_types: Tuple[str, ...]
    record_ids: Tuple[str, ...]
    weight: float = 1.0
    blocked: bool = False

    def normalized_signature(self) -> Tuple[str, ...]:
        return tuple(str(x) for x in self.edge_types)


@dataclass(frozen=True)
class CrystalNode:
    """Compact structural node representing repeated topological evidence."""

    crystal_id: str
    signature: Tuple[str, ...]
    support_count: int
    weighted_support: float
    provenance_path_ids: Tuple[str, ...]
    provenance_record_ids: Tuple[str, ...]
    status: str = ACTIVE
    revocation_reason: str = ""
    revocation_evidence_ids: Tuple[str, ...] = tuple()

    def to_dict(self) -> Dict[str, object]:
        return {
            "crystal_id": self.crystal_id,
            "signature": list(self.signature),
            "support_count": int(self.support_count),
            "weighted_support": float(round(self.weighted_support, 6)),
            "provenance_path_ids": list(self.provenance_path_ids),
            "provenance_record_ids": list(self.provenance_record_ids),
            "status": self.status,
            "revocation_reason": self.revocation_reason,
            "revocation_evidence_ids": list(self.revocation_evidence_ids),
        }


@dataclass(frozen=True)
class CrystallizationConfig:
    min_support: int = 8
    min_weighted_support: float = 8.0
    max_crystals: int = 256
    max_provenance_links_per_crystal: int = 64
    blocked_edge_types: Tuple[str, ...] = (IS_NOT_EDGE,)
    crystal_id_prefix: str = "CRYSTAL_V00F"

    def validate(self) -> None:
        if self.min_support <= 0:
            raise ValueError("min_support must be positive")
        if self.min_weighted_support <= 0:
            raise ValueError("min_weighted_support must be positive")
        if self.max_crystals <= 0:
            raise ValueError("max_crystals must be positive")
        if self.max_provenance_links_per_crystal <= 0:
            raise ValueError("max_provenance_links_per_crystal must be positive")


@dataclass(frozen=True)
class CrystallizationResult:
    crystals: Tuple[CrystalNode, ...]
    skipped_low_support_count: int
    skipped_blocked_count: int
    input_observation_count: int
    archive_delete_operation_count: int = 0

    def active_crystals(self) -> Tuple[CrystalNode, ...]:
        return tuple(c for c in self.crystals if c.status == ACTIVE)

    def to_dict(self) -> Dict[str, object]:
        return {
            "crystals": [c.to_dict() for c in self.crystals],
            "crystal_count": len(self.crystals),
            "active_crystal_count": len(self.active_crystals()),
            "skipped_low_support_count": int(self.skipped_low_support_count),
            "skipped_blocked_count": int(self.skipped_blocked_count),
            "input_observation_count": int(self.input_observation_count),
            "archive_delete_operation_count": int(self.archive_delete_operation_count),
        }


@dataclass
class _Accumulator:
    signature: Tuple[str, ...]
    support_count: int = 0
    weighted_support: float = 0.0
    provenance_path_ids: List[str] = None  # type: ignore[assignment]
    provenance_record_ids: List[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.provenance_path_ids is None:
            self.provenance_path_ids = []
        if self.provenance_record_ids is None:
            self.provenance_record_ids = []


class CrystallizationPathBuilder:
    """Build compact crystal nodes from repeated typed path observations."""

    def __init__(self, config: Optional[CrystallizationConfig] = None) -> None:
        self.config = config or CrystallizationConfig()
        self.config.validate()
        self.blocked_edge_types = frozenset(str(x) for x in self.config.blocked_edge_types)

    def _is_blocked(self, observation: PathObservation) -> bool:
        return bool(observation.blocked) or any(edge_type in self.blocked_edge_types for edge_type in observation.edge_types)

    def _crystal_id(self, signature: Sequence[str]) -> str:
        h = hashlib.sha256()
        h.update(self.config.crystal_id_prefix.encode("utf-8"))
        h.update(b"|")
        h.update("|".join(str(x) for x in signature).encode("utf-8"))
        return self.config.crystal_id_prefix + "_" + h.hexdigest()[:24].upper()

    def crystallize(self, observations: Iterable[PathObservation]) -> CrystallizationResult:
        acc: Dict[Tuple[str, ...], _Accumulator] = {}
        skipped_blocked = 0
        input_count = 0
        max_links = self.config.max_provenance_links_per_crystal

        for obs in observations:
            input_count += 1
            signature = obs.normalized_signature()
            if not signature or self._is_blocked(obs):
                skipped_blocked += 1
                continue
            item = acc.get(signature)
            if item is None:
                item = _Accumulator(signature=signature)
                acc[signature] = item
            item.support_count += 1
            item.weighted_support += float(obs.weight)
            if len(item.provenance_path_ids) < max_links:
                item.provenance_path_ids.append(str(obs.path_id))
            if len(item.provenance_record_ids) < max_links:
                for record_id in obs.record_ids:
                    if len(item.provenance_record_ids) >= max_links:
                        break
                    item.provenance_record_ids.append(str(record_id))

        candidates: List[_Accumulator] = []
        skipped_low_support = 0
        for item in acc.values():
            if item.support_count >= self.config.min_support and item.weighted_support >= self.config.min_weighted_support:
                candidates.append(item)
            else:
                skipped_low_support += item.support_count

        candidates.sort(
            key=lambda item: (
                -item.support_count,
                -round(item.weighted_support, 9),
                item.signature,
            )
        )

        crystals: List[CrystalNode] = []
        for item in candidates[: self.config.max_crystals]:
            crystals.append(
                CrystalNode(
                    crystal_id=self._crystal_id(item.signature),
                    signature=item.signature,
                    support_count=item.support_count,
                    weighted_support=item.weighted_support,
                    provenance_path_ids=tuple(item.provenance_path_ids),
                    provenance_record_ids=tuple(item.provenance_record_ids),
                    status=ACTIVE,
                )
            )

        # Stable final order by deterministic ID after selecting top support candidates.
        crystals = sorted(crystals, key=lambda c: c.crystal_id)
        return CrystallizationResult(
            crystals=tuple(crystals),
            skipped_low_support_count=skipped_low_support,
            skipped_blocked_count=skipped_blocked,
            input_observation_count=input_count,
            archive_delete_operation_count=0,
        )

    def revoke_crystal(self, crystal: CrystalNode, *, reason: str, evidence_ids: Iterable[str]) -> CrystalNode:
        reason = str(reason)
        ids = tuple(str(x) for x in evidence_ids)
        if not reason:
            raise ValueError("revocation reason is required")
        if not ids:
            raise ValueError("at least one revocation evidence id is required")
        return replace(
            crystal,
            status=REVOKED,
            revocation_reason=reason,
            revocation_evidence_ids=ids,
        )

    def result_digest(self, result: CrystallizationResult) -> str:
        return crystallization_digest(result.crystals)


def crystallization_digest(crystals: Iterable[CrystalNode]) -> str:
    h = hashlib.sha256()
    for crystal in sorted(crystals, key=lambda c: c.crystal_id):
        payload = json.dumps(crystal.to_dict(), sort_keys=True, separators=(",", ":"))
        h.update(payload.encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest().upper()


def build_crystal_manifest(result: CrystallizationResult, config: CrystallizationConfig) -> Dict[str, object]:
    return {
        "version": "V00F_CRYSTALLIZATION_PATHS",
        "db_side_only": True,
        "semantic_interpretation": False,
        "llm_calls": False,
        "agent_policy_logic": False,
        "archive_delete_operation_count": int(result.archive_delete_operation_count),
        "config": {
            "min_support": int(config.min_support),
            "min_weighted_support": float(config.min_weighted_support),
            "max_crystals": int(config.max_crystals),
            "max_provenance_links_per_crystal": int(config.max_provenance_links_per_crystal),
            "blocked_edge_types": list(config.blocked_edge_types),
        },
        "result": result.to_dict(),
        "digest": crystallization_digest(result.crystals),
    }
