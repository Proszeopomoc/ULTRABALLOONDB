#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Tuple

from ultraballoondb_core.g1g2_delta_patch import (
    MatrixG1G2DeltaModel,
    PrefixFamilyG1G2DeltaModel,
    bit_set,
    canon,
    sha256_bytes,
)


@dataclass
class MatrixPatchChain:
    """Append-only G4 event chain over a G1/G2 matrix state.

    The hot logical view uses the latest overlay value. Offline compaction folds the
    final logical state into a new G2 exception map and clears the active G4 chain.
    """

    base: MatrixG1G2DeltaModel
    patch_log: List[Dict[str, int]] = field(default_factory=list)
    overlay: Dict[int, int] = field(default_factory=dict)
    query_count: int = 0
    rebuild_count: int = 0

    def query(self, row: int, col: int) -> Dict[str, object]:
        self.query_count += 1
        key = self.base.key(row, col)
        if key in self.overlay:
            return {"value": self.overlay[key], "source_layer": "G4_PATCH", "key": key}
        if key in self.base.exceptions:
            return {"value": self.base.exceptions[key], "source_layer": "G2_EXCEPTION", "key": key}
        return {"value": self.base.rule_value(row, col), "source_layer": "G1_RULE", "key": key}

    def append_patch(self, row: int, col: int, value: int) -> Dict[str, int]:
        key = self.base.key(row, col)
        before = int(self.query(row, col)["value"])
        event = {
            "seq": len(self.patch_log),
            "key": key,
            "row": int(row),
            "col": int(col),
            "before": before,
            "after": int(value) & 1,
        }
        self.patch_log.append(event)
        self.overlay[key] = event["after"]
        return event

    def rebuild_bytes(self) -> bytes:
        self.rebuild_count += 1
        total_bits = self.base.n * self.base.n
        out = bytearray((total_bits + 7) // 8)
        for row in range(self.base.n):
            base_key = row * self.base.n
            for col in range(self.base.n):
                key = base_key + col
                if key in self.overlay:
                    value = self.overlay[key]
                elif key in self.base.exceptions:
                    value = self.base.exceptions[key]
                else:
                    value = self.base.rule_value(row, col)
                if value:
                    bit_set(out, key, 1)
        return bytes(out)

    def rollback_bundle(self) -> bytes:
        return canon({
            "format": "UBDB_MATRIX_PATCH_CHAIN_ROLLBACK_V00J6",
            "n": self.base.n,
            "base_exceptions": sorted((int(k), int(v)) for k, v in self.base.exceptions.items()),
            "patch_log": self.patch_log,
        })

    @classmethod
    def from_rollback_bundle(cls, data: bytes) -> "MatrixPatchChain":
        payload = json.loads(data.decode("utf-8"))
        if payload.get("format") != "UBDB_MATRIX_PATCH_CHAIN_ROLLBACK_V00J6":
            raise ValueError("invalid matrix rollback bundle format")
        base = MatrixG1G2DeltaModel(
            n=int(payload["n"]),
            exceptions={int(k): int(v) for k, v in payload["base_exceptions"]},
        )
        chain = cls(base=base)
        for raw in payload["patch_log"]:
            event = {name: int(raw[name]) for name in ("seq", "key", "row", "col", "before", "after")}
            if event["seq"] != len(chain.patch_log):
                raise ValueError("non-contiguous matrix patch sequence")
            chain.patch_log.append(event)
            chain.overlay[event["key"]] = event["after"]
        return chain

    def compact(self) -> Tuple[MatrixG1G2DeltaModel, Dict[str, object]]:
        candidate_keys = sorted(set(self.base.exceptions) | set(self.overlay))
        exceptions_after: Dict[int, int] = {}
        reverted_to_g1 = 0
        for key in candidate_keys:
            row, col = divmod(key, self.base.n)
            final_value = self.overlay.get(key, self.base.exceptions.get(key, self.base.rule_value(row, col)))
            rule_value = self.base.rule_value(row, col)
            if final_value != rule_value:
                exceptions_after[key] = int(final_value)
            else:
                reverted_to_g1 += 1

        compacted = MatrixG1G2DeltaModel(n=self.base.n, exceptions=exceptions_after)
        rollback = self.rollback_bundle()
        receipt = {
            "patch_events_before": len(self.patch_log),
            "active_overlay_before": len(self.overlay),
            "base_exceptions_before": len(self.base.exceptions),
            "exceptions_after": len(exceptions_after),
            "patch_events_after": 0,
            "reverted_to_g1_count": reverted_to_g1,
            "rollback_bundle_bytes": len(rollback),
            "rollback_bundle_sha256": sha256_bytes(rollback),
            "rollback_is_external_to_hot_state": True,
        }
        return compacted, receipt


@dataclass
class PrefixPatchChain:
    """Append-only G4 event chain over a G1/G2 prefix-record family."""

    base: PrefixFamilyG1G2DeltaModel
    patch_log: List[Dict[str, object]] = field(default_factory=list)
    overlay: Dict[int, str] = field(default_factory=dict)
    query_count: int = 0
    rebuild_count: int = 0

    def query(self, idx: int) -> Dict[str, object]:
        self.query_count += 1
        idx = int(idx)
        if idx in self.overlay:
            return {"value": self.overlay[idx], "source_layer": "G4_PATCH", "idx": idx}
        if idx in self.base.exceptions:
            return {"value": self.base.exceptions[idx], "source_layer": "G2_EXCEPTION", "idx": idx}
        return {"value": self.base.rule_record(idx), "source_layer": "G1_RULE", "idx": idx}

    def append_patch(self, idx: int, record: str) -> Dict[str, object]:
        idx = int(idx)
        before = str(self.query(idx)["value"])
        event: Dict[str, object] = {
            "seq": len(self.patch_log),
            "idx": idx,
            "before_sha256": sha256_bytes(before.encode("utf-8")),
            "after": str(record),
        }
        self.patch_log.append(event)
        self.overlay[idx] = str(record)
        return event

    def rebuild_bytes(self) -> bytes:
        self.rebuild_count += 1
        parts: List[str] = []
        for idx in range(self.base.count):
            if idx in self.overlay:
                parts.append(self.overlay[idx])
            elif idx in self.base.exceptions:
                parts.append(self.base.exceptions[idx])
            else:
                parts.append(self.base.rule_record(idx))
        return "".join(parts).encode("utf-8")

    def rollback_bundle(self) -> bytes:
        return canon({
            "format": "UBDB_PREFIX_PATCH_CHAIN_ROLLBACK_V00J6",
            "count": self.base.count,
            "prefix": self.base.prefix,
            "base_exceptions": sorted((int(k), str(v)) for k, v in self.base.exceptions.items()),
            "patch_log": self.patch_log,
        })

    @classmethod
    def from_rollback_bundle(cls, data: bytes) -> "PrefixPatchChain":
        payload = json.loads(data.decode("utf-8"))
        if payload.get("format") != "UBDB_PREFIX_PATCH_CHAIN_ROLLBACK_V00J6":
            raise ValueError("invalid prefix rollback bundle format")
        base = PrefixFamilyG1G2DeltaModel(
            count=int(payload["count"]),
            prefix=str(payload["prefix"]),
            exceptions={int(k): str(v) for k, v in payload["base_exceptions"]},
        )
        chain = cls(base=base)
        for raw in payload["patch_log"]:
            seq = int(raw["seq"])
            idx = int(raw["idx"])
            after = str(raw["after"])
            if seq != len(chain.patch_log):
                raise ValueError("non-contiguous prefix patch sequence")
            event = {
                "seq": seq,
                "idx": idx,
                "before_sha256": str(raw["before_sha256"]),
                "after": after,
            }
            chain.patch_log.append(event)
            chain.overlay[idx] = after
        return chain

    def compact(self) -> Tuple[PrefixFamilyG1G2DeltaModel, Dict[str, object]]:
        candidate_indices = sorted(set(self.base.exceptions) | set(self.overlay))
        exceptions_after: Dict[int, str] = {}
        reverted_to_g1 = 0
        for idx in candidate_indices:
            final_value = self.overlay.get(idx, self.base.exceptions.get(idx, self.base.rule_record(idx)))
            rule_value = self.base.rule_record(idx)
            if final_value != rule_value:
                exceptions_after[idx] = final_value
            else:
                reverted_to_g1 += 1

        compacted = PrefixFamilyG1G2DeltaModel(
            count=self.base.count,
            prefix=self.base.prefix,
            exceptions=exceptions_after,
        )
        rollback = self.rollback_bundle()
        receipt = {
            "patch_events_before": len(self.patch_log),
            "active_overlay_before": len(self.overlay),
            "base_exceptions_before": len(self.base.exceptions),
            "exceptions_after": len(exceptions_after),
            "patch_events_after": 0,
            "reverted_to_g1_count": reverted_to_g1,
            "rollback_bundle_bytes": len(rollback),
            "rollback_bundle_sha256": sha256_bytes(rollback),
            "rollback_is_external_to_hot_state": True,
        }
        return compacted, receipt


def deterministic_matrix_targets(base: MatrixG1G2DeltaModel, working_set: int) -> List[int]:
    targets: List[int] = []
    seen = set()
    for key in sorted(base.exceptions):
        if key not in seen:
            targets.append(key)
            seen.add(key)
            if len(targets) >= working_set:
                return targets
    t = 0
    while len(targets) < working_set:
        row = (t * 211 + 43) % base.n
        col = (t * 307 + 71) % base.n
        key = base.key(row, col)
        if key not in seen:
            targets.append(key)
            seen.add(key)
        t += 1
    return targets


def deterministic_prefix_targets(base: PrefixFamilyG1G2DeltaModel, working_set: int) -> List[int]:
    targets: List[int] = []
    seen = set()
    for idx in sorted(base.exceptions):
        if idx not in seen:
            targets.append(idx)
            seen.add(idx)
            if len(targets) >= working_set:
                return targets
    t = 0
    while len(targets) < working_set:
        idx = (t * 1237 + 89) % base.count
        if idx not in seen:
            targets.append(idx)
            seen.add(idx)
        t += 1
    return targets


def populate_matrix_chain(chain: MatrixPatchChain, patch_events: int, working_set: int) -> List[int]:
    if patch_events < working_set:
        raise ValueError("patch_events must be >= working_set")
    targets = deterministic_matrix_targets(chain.base, working_set)
    prelude = patch_events - working_set
    for seq in range(prelude):
        key = targets[seq % working_set]
        row, col = divmod(key, chain.base.n)
        value = (chain.base.rule_value(row, col) + 1 + (seq // working_set)) & 1
        chain.append_patch(row, col, value)
    for target_i, key in enumerate(targets):
        row, col = divmod(key, chain.base.n)
        rule = chain.base.rule_value(row, col)
        final_value = 1 - rule if target_i % 2 == 0 else rule
        chain.append_patch(row, col, final_value)
    return targets


def populate_prefix_chain(chain: PrefixPatchChain, patch_events: int, working_set: int) -> List[int]:
    if patch_events < working_set:
        raise ValueError("patch_events must be >= working_set")
    targets = deterministic_prefix_targets(chain.base, working_set)
    prelude = patch_events - working_set
    for seq in range(prelude):
        idx = targets[seq % working_set]
        record = (
            f"{chain.base.prefix}{idx:010d}|TYPE=P|STATUS=CHAIN|"
            f"VALUE={(idx + seq) % 997:03d}|SEQ={seq:06d}\n"
        )
        chain.append_patch(idx, record)
    for target_i, idx in enumerate(targets):
        if target_i % 2 == 0:
            final_record = (
                f"{chain.base.prefix}{idx:010d}|TYPE=C|STATUS=COMPACTABLE|"
                f"VALUE={idx % 251:03d}|FINAL=1\n"
            )
        else:
            final_record = chain.base.rule_record(idx)
        chain.append_patch(idx, final_record)
    return targets


def count_sources(rows: Iterable[Dict[str, object]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for row in rows:
        source = str(row.get("source_layer"))
        counts[source] = counts.get(source, 0) + 1
    return counts
