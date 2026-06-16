#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UltraBalloonDB V00E: deterministic edge-type relation algebra.

This module is intentionally DB-side and semantics-blind. It combines edge type
IDs into derived relation type IDs using a fixed transition table. It does not
interpret text, call a model, perform planning, or fetch payloads.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


UNKNOWN_PATH = "UNKNOWN_PATH"
BLOCKED_PATH = "BLOCKED_PATH"
EMPTY_PATH = "EMPTY_PATH"
IS_NOT_EDGE = "IS_NOT_EDGE"


DEFAULT_EDGE_TYPES: Tuple[str, ...] = (
    "UP_RULE",
    "DOWN_EVIDENCE",
    "LATERAL_SIMILAR_CASE",
    "PROJECT_CONTEXT",
    "CODE_PATTERN",
    "RULE_TO_EVIDENCE",
    "RULE_TO_CODE_PATTERN",
    "PROJECT_TO_RECENT_SEED",
    "CODE_TO_RECENT_RULE",
    IS_NOT_EDGE,
)


@dataclass(frozen=True)
class RelationRule:
    """One deterministic transition from two relation IDs to one relation ID."""

    left: str
    right: str
    result: str
    commutative: bool = False

    def normalized_items(self) -> Tuple[Tuple[str, str, str], ...]:
        first = (self.left, self.right, self.result)
        if self.commutative and self.left != self.right:
            return (first, (self.right, self.left, self.result))
        return (first,)


@dataclass(frozen=True)
class PathDerivationStep:
    left: str
    right: str
    result: str
    blocked: bool = False


@dataclass(frozen=True)
class PathDerivation:
    input_edge_types: Tuple[str, ...]
    result_relation: str
    blocked: bool
    unknown_count: int
    step_count: int
    steps: Tuple[PathDerivationStep, ...]


class EdgeTypeRelationAlgebra:
    """Fixed table for deterministic edge-type relation composition."""

    def __init__(self, rules: Iterable[RelationRule], *, blocked_types: Iterable[str] = (IS_NOT_EDGE,)) -> None:
        self.blocked_types = frozenset(str(x) for x in blocked_types)
        table: Dict[Tuple[str, str], str] = {}
        for rule in rules:
            for left, right, result in rule.normalized_items():
                key = (str(left), str(right))
                existing = table.get(key)
                if existing is not None and existing != result:
                    raise ValueError(f"conflicting relation rule for {key}: {existing!r} vs {result!r}")
                table[key] = str(result)
        self._table = dict(sorted(table.items()))

    @property
    def table(self) -> Mapping[Tuple[str, str], str]:
        return self._table

    def combine(self, left: str, right: str) -> PathDerivationStep:
        left = str(left)
        right = str(right)
        if left in self.blocked_types or right in self.blocked_types:
            return PathDerivationStep(left=left, right=right, result=BLOCKED_PATH, blocked=True)
        result = self._table.get((left, right), UNKNOWN_PATH)
        return PathDerivationStep(left=left, right=right, result=result, blocked=False)

    def derive_path(self, edge_types: Sequence[str]) -> PathDerivation:
        normalized = tuple(str(x) for x in edge_types)
        if not normalized:
            return PathDerivation(
                input_edge_types=normalized,
                result_relation=EMPTY_PATH,
                blocked=False,
                unknown_count=0,
                step_count=0,
                steps=tuple(),
            )
        if len(normalized) == 1:
            only = normalized[0]
            blocked = only in self.blocked_types
            return PathDerivation(
                input_edge_types=normalized,
                result_relation=BLOCKED_PATH if blocked else only,
                blocked=blocked,
                unknown_count=0,
                step_count=0,
                steps=tuple(),
            )

        current = normalized[0]
        steps: List[PathDerivationStep] = []
        unknown_count = 0
        for nxt in normalized[1:]:
            step = self.combine(current, nxt)
            steps.append(step)
            if step.blocked:
                return PathDerivation(
                    input_edge_types=normalized,
                    result_relation=BLOCKED_PATH,
                    blocked=True,
                    unknown_count=unknown_count,
                    step_count=len(steps),
                    steps=tuple(steps),
                )
            if step.result == UNKNOWN_PATH:
                unknown_count += 1
            current = step.result
        return PathDerivation(
            input_edge_types=normalized,
            result_relation=current,
            blocked=False,
            unknown_count=unknown_count,
            step_count=len(steps),
            steps=tuple(steps),
        )

    def derive_many(self, paths: Iterable[Sequence[str]]) -> List[PathDerivation]:
        derived = [self.derive_path(path) for path in paths]
        # Stable deterministic order for equal inputs/outputs.
        return sorted(
            derived,
            key=lambda d: (d.blocked, d.result_relation, d.input_edge_types, d.unknown_count, d.step_count),
        )

    def derive_with_edge_mask(self, edge_types: Sequence[str], allowed_edge_types: Iterable[str]) -> PathDerivation:
        allowed = frozenset(str(x) for x in allowed_edge_types)
        masked: List[str] = []
        for edge_type in edge_types:
            edge_type = str(edge_type)
            if edge_type in allowed or edge_type in self.blocked_types:
                masked.append(edge_type)
            else:
                masked.append("MASKED_OUT_EDGE")
        return self.derive_path(masked)

    def to_manifest(self) -> Dict[str, object]:
        rules = [
            {"left": left, "right": right, "result": result}
            for (left, right), result in sorted(self._table.items())
        ]
        return {
            "version": "V00E_EDGE_TYPE_RELATION_ALGEBRA",
            "blocked_types": sorted(self.blocked_types),
            "rule_count": len(rules),
            "rules": rules,
        }


DEFAULT_RELATION_RULES: Tuple[RelationRule, ...] = (
    RelationRule("PROJECT_CONTEXT", "DOWN_EVIDENCE", "PROJECT_SUPPORT_PATH"),
    RelationRule("PROJECT_CONTEXT", "RULE_TO_EVIDENCE", "PROJECT_SUPPORT_PATH"),
    RelationRule("PROJECT_CONTEXT", "PROJECT_TO_RECENT_SEED", "PROJECT_RECENT_ACTIVITY_PATH"),
    RelationRule("UP_RULE", "CODE_PATTERN", "RULE_CODE_CANDIDATE"),
    RelationRule("UP_RULE", "RULE_TO_CODE_PATTERN", "RULE_CODE_CANDIDATE"),
    RelationRule("CODE_TO_RECENT_RULE", "RULE_TO_CODE_PATTERN", "RECENT_CODE_RULE_PATH"),
    RelationRule("CODE_PATTERN", "CODE_TO_RECENT_RULE", "CODE_RULE_BACKLINK_PATH"),
    RelationRule("RULE_CODE_CANDIDATE", "DOWN_EVIDENCE", "RULE_CODE_EVIDENCE_PATH"),
    RelationRule("RULE_CODE_CANDIDATE", "RULE_TO_EVIDENCE", "RULE_CODE_EVIDENCE_PATH"),
    RelationRule("PROJECT_SUPPORT_PATH", "LATERAL_SIMILAR_CASE", "PROJECT_SUPPORT_SIMILAR_CASE_PATH"),
    RelationRule("PROJECT_RECENT_ACTIVITY_PATH", "LATERAL_SIMILAR_CASE", "PROJECT_RECENT_SIMILAR_CASE_PATH"),
    RelationRule("RECENT_CODE_RULE_PATH", "DOWN_EVIDENCE", "RECENT_CODE_RULE_EVIDENCE_PATH"),
    RelationRule("CODE_RULE_BACKLINK_PATH", "DOWN_EVIDENCE", "CODE_RULE_BACKLINK_EVIDENCE_PATH"),
    RelationRule("LATERAL_SIMILAR_CASE", "DOWN_EVIDENCE", "SIMILAR_CASE_EVIDENCE_PATH"),
    RelationRule("LATERAL_SIMILAR_CASE", "PROJECT_CONTEXT", "SIMILAR_PROJECT_CONTEXT_PATH"),
    RelationRule("SIMILAR_PROJECT_CONTEXT_PATH", "DOWN_EVIDENCE", "SIMILAR_PROJECT_EVIDENCE_PATH"),
    RelationRule("MASKED_OUT_EDGE", "DOWN_EVIDENCE", UNKNOWN_PATH),
    RelationRule("MASKED_OUT_EDGE", "CODE_PATTERN", UNKNOWN_PATH),
    RelationRule("MASKED_OUT_EDGE", "PROJECT_CONTEXT", UNKNOWN_PATH),
)


def default_relation_algebra() -> EdgeTypeRelationAlgebra:
    return EdgeTypeRelationAlgebra(DEFAULT_RELATION_RULES, blocked_types=(IS_NOT_EDGE,))


def relation_digest(derivations: Iterable[PathDerivation]) -> str:
    import hashlib

    h = hashlib.sha256()
    for d in derivations:
        h.update("|".join(d.input_edge_types).encode("utf-8"))
        h.update(b"=>")
        h.update(d.result_relation.encode("utf-8"))
        h.update(b"#")
        h.update(str(int(d.blocked)).encode("ascii"))
        h.update(b"#")
        h.update(str(d.unknown_count).encode("ascii"))
        h.update(b"\n")
    return h.hexdigest().upper()
