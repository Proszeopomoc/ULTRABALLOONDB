#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Tuple


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


# --------------------------- bit helpers ---------------------------

def bit_get(buf: bytes | bytearray, bit_index: int) -> int:
    byte_i = bit_index >> 3
    bit_i = bit_index & 7
    return (buf[byte_i] >> bit_i) & 1


def bit_set(buf: bytearray, bit_index: int, value: int) -> None:
    byte_i = bit_index >> 3
    bit_i = bit_index & 7
    if int(value) & 1:
        buf[byte_i] |= (1 << bit_i)
    else:
        buf[byte_i] &= ~(1 << bit_i)


# --------------------------- matrix G1/G2/G4 ---------------------------

@dataclass
class MatrixG1G2DeltaModel:
    n: int
    exceptions: Dict[int, int]
    patches: Dict[int, int] = field(default_factory=dict)
    rebuild_count: int = 0
    query_count: int = 0

    def rule_value(self, row: int, col: int) -> int:
        # Deterministic low-entropy rule: compactly computable, no table required.
        return 1 if (((row * 1315423911) ^ (col * 2654435761) ^ (row + col)) & 7) in (0, 3) else 0

    def key(self, row: int, col: int) -> int:
        return int(row) * int(self.n) + int(col)

    def query(self, row: int, col: int) -> Dict[str, object]:
        self.query_count += 1
        k = self.key(row, col)
        if k in self.patches:
            return {"value": self.patches[k], "source_layer": "G4_PATCH", "key": k}
        if k in self.exceptions:
            return {"value": self.exceptions[k], "source_layer": "G2_EXCEPTION", "key": k}
        return {"value": self.rule_value(row, col), "source_layer": "G1_RULE", "key": k}

    def apply_patch(self, row: int, col: int, value: int) -> Dict[str, object]:
        k = self.key(row, col)
        before = self.query(row, col)
        self.patches[k] = int(value) & 1
        return {"key": k, "row": row, "col": col, "before": before["value"], "after": self.patches[k]}

    def rebuild_bytes(self) -> bytes:
        self.rebuild_count += 1
        total_bits = self.n * self.n
        out = bytearray((total_bits + 7) // 8)
        for row in range(self.n):
            base = row * self.n
            for col in range(self.n):
                k = base + col
                if k in self.patches:
                    v = self.patches[k]
                elif k in self.exceptions:
                    v = self.exceptions[k]
                else:
                    v = self.rule_value(row, col)
                if v:
                    bit_set(out, k, 1)
        return bytes(out)

    def compact_bytes(self, include_patches: bool = True) -> bytes:
        return canon({
            "model": "MATRIX_RULE_EXCEPTION_DELTA_V00J3",
            "n": self.n,
            "rule_id": "xor_mix_mod8_in_0_3",
            "exceptions": sorted((int(k), int(v)) for k, v in self.exceptions.items()),
            "patches": sorted((int(k), int(v)) for k, v in self.patches.items()) if include_patches else [],
        })

    def direct_apply_to_original(self, original: bytes, patch_records: List[Dict[str, object]]) -> bytes:
        out = bytearray(original)
        for p in patch_records:
            bit_set(out, int(p["key"]), int(p["after"]))
        return bytes(out)


# --------------------------- prefix family G1/G2/G4 ---------------------------

@dataclass
class PrefixFamilyG1G2DeltaModel:
    count: int
    prefix: str = "9606.ENSP"
    exceptions: Dict[int, str] = field(default_factory=dict)
    patches: Dict[int, str] = field(default_factory=dict)
    rebuild_count: int = 0
    query_count: int = 0

    def rule_record(self, idx: int) -> str:
        return f"{self.prefix}{idx:010d}|TYPE=A|STATUS=OK|VALUE={idx % 97:02d}\n"

    def query(self, idx: int) -> Dict[str, object]:
        self.query_count += 1
        idx = int(idx)
        if idx in self.patches:
            return {"value": self.patches[idx], "source_layer": "G4_PATCH", "idx": idx}
        if idx in self.exceptions:
            return {"value": self.exceptions[idx], "source_layer": "G2_EXCEPTION", "idx": idx}
        return {"value": self.rule_record(idx), "source_layer": "G1_RULE", "idx": idx}

    def apply_patch(self, idx: int, record: str) -> Dict[str, object]:
        before = self.query(idx)
        self.patches[int(idx)] = str(record)
        return {"idx": int(idx), "before_source": before["source_layer"], "after_len": len(record)}

    def rebuild_bytes(self) -> bytes:
        self.rebuild_count += 1
        parts = []
        for idx in range(self.count):
            if idx in self.patches:
                parts.append(self.patches[idx])
            elif idx in self.exceptions:
                parts.append(self.exceptions[idx])
            else:
                parts.append(self.rule_record(idx))
        return ''.join(parts).encode('utf-8')

    def compact_bytes(self, include_patches: bool = True) -> bytes:
        return canon({
            "model": "PREFIX_FAMILY_RULE_EXCEPTION_DELTA_V00J3",
            "count": self.count,
            "prefix": self.prefix,
            "template": "{prefix}{idx:010d}|TYPE=A|STATUS=OK|VALUE={idx%97:02d}\\n",
            "exceptions": sorted((int(k), str(v)) for k, v in self.exceptions.items()),
            "patches": sorted((int(k), str(v)) for k, v in self.patches.items()) if include_patches else [],
        })

    def direct_apply_to_original(self, original: bytes, patch_records: List[Dict[str, object]]) -> bytes:
        records = original.decode('utf-8').splitlines(keepends=True)
        for p in patch_records:
            idx = int(p["idx"])
            records[idx] = self.patches[idx]
        return ''.join(records).encode('utf-8')


# --------------------------- deterministic builders ---------------------------

def build_matrix_model(n: int, exception_count: int) -> MatrixG1G2DeltaModel:
    exceptions: Dict[int, int] = {}
    used = set()
    for t in range(exception_count):
        row = (t * 97 + 17) % n
        col = (t * 193 + 29) % n
        k = row * n + col
        while k in used:
            col = (col + 1) % n
            k = row * n + col
        used.add(k)
        base = 1 if (((row * 1315423911) ^ (col * 2654435761) ^ (row + col)) & 7) in (0, 3) else 0
        exceptions[k] = 1 - base
    return MatrixG1G2DeltaModel(n=n, exceptions=exceptions)


def matrix_patch_plan(model: MatrixG1G2DeltaModel, patch_count: int) -> List[Tuple[int, int, int]]:
    n = model.n
    plan: List[Tuple[int, int, int]] = []
    # patch some G2 positions first
    for k in sorted(model.exceptions.keys())[: max(1, patch_count // 2)]:
        row, col = divmod(k, n)
        plan.append((row, col, 1 - model.exceptions[k]))
    # patch G1 positions
    t = 0
    while len(plan) < patch_count:
        row = (t * 211 + 43) % n
        col = (t * 307 + 71) % n
        k = row * n + col
        if k not in model.exceptions and k not in model.patches:
            plan.append((row, col, 1 - model.rule_value(row, col)))
        t += 1
    return plan


def build_prefix_model(count: int, exception_count: int) -> PrefixFamilyG1G2DeltaModel:
    model = PrefixFamilyG1G2DeltaModel(count=count)
    for t in range(exception_count):
        idx = (t * 997 + 31) % count
        model.exceptions[idx] = f"{model.prefix}{idx:010d}|TYPE=B|STATUS=RARE|VALUE={idx % 193:03d}|EX={t}\n"
    return model


def prefix_patch_plan(model: PrefixFamilyG1G2DeltaModel, patch_count: int) -> List[Tuple[int, str]]:
    plan: List[Tuple[int, str]] = []
    for idx in sorted(model.exceptions.keys())[: max(1, patch_count // 2)]:
        plan.append((idx, f"{model.prefix}{idx:010d}|TYPE=C|STATUS=PATCHED|VALUE={idx % 251:03d}|PATCH=E\n"))
    t = 0
    while len(plan) < patch_count:
        idx = (t * 1237 + 89) % model.count
        if idx not in model.exceptions and idx not in model.patches:
            plan.append((idx, f"{model.prefix}{idx:010d}|TYPE=C|STATUS=PATCHED|VALUE={idx % 251:03d}|PATCH=G\n"))
        t += 1
    return plan


def count_sources(rows: Iterable[Dict[str, object]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for r in rows:
        s = str(r.get("source_layer"))
        out[s] = out.get(s, 0) + 1
    return out
