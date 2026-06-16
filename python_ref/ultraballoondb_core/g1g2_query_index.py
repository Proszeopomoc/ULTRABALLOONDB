#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import json
import struct
import zlib
from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple


VERSION = "V00J2_G1G2_QUERYABLE_RECONSTRUCTION_INDEX"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def _stable_json_bytes(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _mix64(x: int) -> int:
    x &= 0xFFFFFFFFFFFFFFFF
    x ^= (x >> 30)
    x = (x * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    x ^= (x >> 27)
    x = (x * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    x ^= (x >> 31)
    return x & 0xFFFFFFFFFFFFFFFF


def matrix_rule_bit(row: int, col: int) -> int:
    # A deterministic high-entropy-looking rule. Byte compressors should not
    # see repeated text, but G1 can regenerate it from the rule id and params.
    return _mix64((row << 32) ^ col ^ 0xA7C15EED1234ABCD) & 1


def _bitpack(bits: Iterable[int]) -> bytes:
    out = bytearray()
    cur = 0
    pos = 0
    for bit in bits:
        if bit:
            cur |= 1 << pos
        pos += 1
        if pos == 8:
            out.append(cur)
            cur = 0
            pos = 0
    if pos:
        out.append(cur)
    return bytes(out)


@dataclass(frozen=True)
class QueryProof:
    status: str
    source_layer: str
    key: object
    value: object
    g1_rule_id: str
    g2_exception_id: str | None
    rebuild_used: bool

    def to_dict(self) -> Dict[str, object]:
        return {
            "status": self.status,
            "source_layer": self.source_layer,
            "key": self.key,
            "value": self.value,
            "g1_rule_id": self.g1_rule_id,
            "g2_exception_id": self.g2_exception_id,
            "rebuild_used": self.rebuild_used,
        }


class LowExceptionMatrixIndex:
    """G1/G2 queryable matrix model.

    G1 is a deterministic rule over coordinates.
    G2 is a sparse override map for exceptions.
    Query returns a value and proof without rebuilding the full matrix.
    """

    g1_rule_id = "G1_MATRIX_MIX64_BIT_RULE_V00J2"

    def __init__(self, n: int, exceptions: Dict[int, int]):
        if n <= 0:
            raise ValueError("n must be positive")
        self.n = int(n)
        self.exceptions = dict(sorted((int(k), int(v) & 1) for k, v in exceptions.items()))
        self.rebuild_count = 0

    def _index(self, row: int, col: int) -> int:
        row = int(row)
        col = int(col)
        if row < 0 or row >= self.n or col < 0 or col >= self.n:
            raise IndexError("matrix coordinate outside bounds")
        return row * self.n + col

    def query(self, row: int, col: int) -> QueryProof:
        idx = self._index(row, col)
        if idx in self.exceptions:
            value = self.exceptions[idx]
            eid = sha256_bytes(struct.pack("<QI", idx, value))[:16]
            return QueryProof("OK", "G2_EXCEPTION", [row, col], value, self.g1_rule_id, eid, False)
        value = matrix_rule_bit(row, col)
        return QueryProof("OK", "G1_RULE", [row, col], value, self.g1_rule_id, None, False)

    def rebuild_bytes(self) -> bytes:
        self.rebuild_count += 1
        def bits():
            for row in range(self.n):
                base = row * self.n
                for col in range(self.n):
                    idx = base + col
                    if idx in self.exceptions:
                        yield self.exceptions[idx]
                    else:
                        yield matrix_rule_bit(row, col)
        return _bitpack(bits())

    def compact_bytes(self) -> bytes:
        # Fixed compact representation: rule params plus sparse exceptions.
        out = bytearray()
        out += b"G1G2MAT2"
        out += struct.pack("<II", self.n, len(self.exceptions))
        for idx, value in self.exceptions.items():
            out += struct.pack("<QB", idx, value & 1)
        return bytes(out)

    def proof_manifest(self) -> Dict[str, object]:
        return {
            "model": "low_exception_rule_matrix",
            "g1_rule_id": self.g1_rule_id,
            "n": self.n,
            "exception_count": len(self.exceptions),
            "compact_sha256": sha256_bytes(self.compact_bytes()),
        }


class PrefixIdFamilyIndex:
    """G1/G2 queryable prefix-record family.

    G1 generates the common family record.
    G2 stores full records only for sparse exceptions.
    """

    g1_rule_id = "G1_PREFIX_ID_RECORD_TEMPLATE_V00J2"

    def __init__(self, count: int, exceptions: Dict[int, bytes]):
        if count <= 0:
            raise ValueError("count must be positive")
        self.count = int(count)
        self.exceptions = dict(sorted((int(k), bytes(v)) for k, v in exceptions.items()))
        self.rebuild_count = 0

    def _base_record(self, idx: int) -> bytes:
        if idx < 0 or idx >= self.count:
            raise IndexError("record index outside bounds")
        return f"9606.ENSP{idx:011d}|STATUS=OK|SOURCE=G1|VALUE={idx % 97:02d}\n".encode("ascii")

    def query(self, idx: int) -> QueryProof:
        idx = int(idx)
        if idx < 0 or idx >= self.count:
            raise IndexError("record index outside bounds")
        if idx in self.exceptions:
            value = self.exceptions[idx]
            eid = sha256_bytes(struct.pack("<I", idx) + value)[:16]
            return QueryProof("OK", "G2_EXCEPTION", idx, value.decode("ascii"), self.g1_rule_id, eid, False)
        value = self._base_record(idx)
        return QueryProof("OK", "G1_RULE", idx, value.decode("ascii"), self.g1_rule_id, None, False)

    def rebuild_bytes(self) -> bytes:
        self.rebuild_count += 1
        out = bytearray()
        for idx in range(self.count):
            out += self.exceptions.get(idx, self._base_record(idx))
        return bytes(out)

    def compact_bytes(self) -> bytes:
        out = bytearray()
        out += b"G1G2PFX2"
        out += struct.pack("<II", self.count, len(self.exceptions))
        for idx, payload in self.exceptions.items():
            out += struct.pack("<II", idx, len(payload))
            out += payload
        return bytes(out)

    def proof_manifest(self) -> Dict[str, object]:
        return {
            "model": "prefix_id_family",
            "g1_rule_id": self.g1_rule_id,
            "count": self.count,
            "exception_count": len(self.exceptions),
            "compact_sha256": sha256_bytes(self.compact_bytes()),
        }


def build_matrix_index(n: int, exception_count: int) -> LowExceptionMatrixIndex:
    total = n * n
    exceptions: Dict[int, int] = {}
    for k in range(exception_count):
        idx = _mix64(0xBADC0DE00000000 ^ k) % total
        row, col = divmod(idx, n)
        exceptions[idx] = 1 - matrix_rule_bit(row, col)
    return LowExceptionMatrixIndex(n, exceptions)


def build_prefix_index(count: int) -> PrefixIdFamilyIndex:
    raw = {
        17: b"9606.ENSP00000000017|STATUS=PATCHED|SOURCE=G2|VALUE=EXC17\n",
        max(0, count // 3): f"9606.ENSP{count // 3:011d}|STATUS=PATCHED|SOURCE=G2|VALUE=EXC_A\n".encode("ascii"),
        max(0, count - 3): f"9606.ENSP{count - 3:011d}|STATUS=PATCHED|SOURCE=G2|VALUE=EXC_Z\n".encode("ascii"),
    }
    exceptions = {k: v for k, v in raw.items() if 0 <= k < count}
    return PrefixIdFamilyIndex(count, exceptions)


def query_batch_without_rebuild(index, queries: List[Tuple[int, ...] | int]) -> Dict[str, object]:
    before = index.rebuild_count
    proofs = []
    for q in queries:
        if isinstance(q, tuple):
            proofs.append(index.query(*q).to_dict())
        else:
            proofs.append(index.query(q).to_dict())
    after = index.rebuild_count
    return {
        "query_count": len(queries),
        "rebuild_count_before": before,
        "rebuild_count_after": after,
        "no_full_rebuild_during_query": before == after,
        "proofs": proofs,
        "source_layer_counts": {
            "G1_RULE": sum(1 for p in proofs if p["source_layer"] == "G1_RULE"),
            "G2_EXCEPTION": sum(1 for p in proofs if p["source_layer"] == "G2_EXCEPTION"),
        },
    }


def compression_summary(name: str, original: bytes, compact: bytes) -> Dict[str, object]:
    z = zlib.compress(original, 9)
    return {
        "name": name,
        "original_bytes": len(original),
        "g1g2_bytes": len(compact),
        "g1g2_ratio": len(original) / max(1, len(compact)),
        "zlib_bytes": len(z),
        "zlib_ratio": len(original) / max(1, len(z)),
        "original_sha256": sha256_bytes(original),
        "compact_sha256": sha256_bytes(compact),
    }
