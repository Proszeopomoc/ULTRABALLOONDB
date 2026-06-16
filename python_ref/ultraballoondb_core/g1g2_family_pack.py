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


def _key(file_index: int, record_index: int) -> str:
    return f"{int(file_index)}:{int(record_index)}"


def _split_key(key: str) -> Tuple[int, int]:
    a, b = key.split(":", 1)
    return int(a), int(b)


@dataclass
class FamilyG1G2Pack:
    """Shared family model: one G1_family rule + small G2_file residuals.

    The hot/queryable point is that a record can be resolved by (file_index, record_index)
    without materializing the whole family. Rebuild remains available for byte-exact SHA.
    """

    family_name: str
    file_count: int
    records_per_file: int
    base_prefix: str = "UBDBFAM"
    exceptions: Dict[str, str] = field(default_factory=dict)
    rebuild_count: int = 0
    query_count: int = 0

    def rule_value(self, file_index: int, record_index: int) -> str:
        # Compact computable family rule. No per-record payload is stored in G1.
        # File-local variation is generated from file_index; record-local value from record_index.
        value = (int(record_index) * 17 + int(file_index) * 31) % 1000
        group = (int(record_index) // 128) % 64
        return (
            f"{self.base_prefix}|F={int(file_index):03d}|R={int(record_index):08d}"
            f"|TYPE=A|STATUS=OK|GROUP={group:02d}|VALUE={value:03d}\n"
        )

    def query(self, file_index: int, record_index: int) -> Dict[str, object]:
        self.query_count += 1
        k = _key(file_index, record_index)
        if k in self.exceptions:
            return {
                "value": self.exceptions[k],
                "source_layer": "G2_FILE_RESIDUAL",
                "file_index": int(file_index),
                "record_index": int(record_index),
            }
        return {
            "value": self.rule_value(file_index, record_index),
            "source_layer": "G1_FAMILY_RULE",
            "file_index": int(file_index),
            "record_index": int(record_index),
        }

    def rebuild_file_bytes(self, file_index: int) -> bytes:
        self.rebuild_count += 1
        out = bytearray()
        for record_index in range(self.records_per_file):
            out.extend(str(self.query(file_index, record_index)["value"]).encode("utf-8"))
        return bytes(out)

    def rebuild_pack_bytes(self) -> bytes:
        self.rebuild_count += 1
        out = bytearray()
        for file_index in range(self.file_count):
            payload = self.rebuild_file_bytes(file_index)
            out.extend(f"--FILE {file_index:03d} {len(payload)}--\n".encode("utf-8"))
            out.extend(payload)
        return bytes(out)

    def compact_obj(self) -> Dict[str, object]:
        return {
            "magic": "UBG1G2FAMILY00",
            "version": 1,
            "family_name": self.family_name,
            "g1_family_rule": {
                "base_prefix": self.base_prefix,
                "file_count": self.file_count,
                "records_per_file": self.records_per_file,
                "record_rule": "prefix|F=file|R=record|TYPE=A|STATUS=OK|GROUP=floor(record/128)%64|VALUE=(record*17+file*31)%1000",
            },
            "g2_file_residual": dict(sorted(self.exceptions.items(), key=lambda kv: _split_key(kv[0]))),
        }

    def compact_bytes(self) -> bytes:
        return canon(self.compact_obj())

    @classmethod
    def from_compact_bytes(cls, data: bytes) -> "FamilyG1G2Pack":
        obj = json.loads(data.decode("utf-8"))
        if obj.get("magic") != "UBG1G2FAMILY00":
            raise ValueError("bad family model magic")
        g1 = obj["g1_family_rule"]
        return cls(
            family_name=str(obj["family_name"]),
            file_count=int(g1["file_count"]),
            records_per_file=int(g1["records_per_file"]),
            base_prefix=str(g1["base_prefix"]),
            exceptions={str(k): str(v) for k, v in obj.get("g2_file_residual", {}).items()},
        )


def build_family_model(file_count: int, records_per_file: int, exceptions_per_file: int) -> FamilyG1G2Pack:
    model = FamilyG1G2Pack(
        family_name="synthetic_family_pack_low_residual",
        file_count=int(file_count),
        records_per_file=int(records_per_file),
    )
    for f in range(file_count):
        used = set()
        for t in range(exceptions_per_file):
            # Deterministic sparse residual positions, spread across each file.
            r = (f * 1009 + t * 811 + 97) % records_per_file
            while r in used:
                r = (r + 257) % records_per_file
            used.add(r)
            model.exceptions[_key(f, r)] = (
                f"{model.base_prefix}|F={f:03d}|R={r:08d}"
                f"|TYPE=B|STATUS=RARE|GROUP=EX|VALUE={(f * 37 + t * 19) % 1000:03d}|RESIDUAL={t:02d}\n"
            )
    return model


def count_sources(rows: Iterable[Dict[str, object]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for row in rows:
        src = str(row.get("source_layer", "UNKNOWN"))
        out[src] = out.get(src, 0) + 1
    return out
