#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UltraBalloonDB V00O stable database API.

This module exposes one semantics-blind public facade over the V00M unified
L0-L7 runtime and the V00N durable single-writer overlay.

The facade does not replace L2 typed edges or L3 wave activation. It only
stabilizes create/open/write/read/query/checkpoint/verify/export/import calls
for CLI and transport use.
"""
from __future__ import annotations

import base64
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from ultraballoondb_core.durable_runtime import DurableDatabaseRuntime
from ultraballoondb_core.types import EdgeType

VERSION = "V00O_STABLE_DATABASE_API_CLI_TRANSPORT"


def parse_edge_type(value: EdgeType | int | str) -> EdgeType:
    if isinstance(value, EdgeType):
        return value
    if isinstance(value, int):
        return EdgeType(value)
    text = str(value).strip()
    if not text:
        raise ValueError("edge type cannot be empty")
    if text.lstrip("+-").isdigit():
        return EdgeType(int(text))
    return EdgeType[text.upper()]


def parse_edge_mask(values: Sequence[EdgeType | int | str] | None) -> tuple[EdgeType, ...]:
    if not values:
        return (
            EdgeType.PROJECT_CONTEXT,
            EdgeType.CODE_PATTERN,
            EdgeType.RULE_TO_CODE_PATTERN,
        )
    return tuple(parse_edge_type(v) for v in values)


class UltraBalloonDatabase:
    """Stable V00O facade over the durable runtime."""

    def __init__(self, database_root: str | Path) -> None:
        self.database_root = Path(database_root).resolve()
        self.runtime = DurableDatabaseRuntime(self.database_root)

    @property
    def opened(self) -> bool:
        return self.runtime.opened

    def create(self, event_count: int, *, overwrite: bool = False) -> Mapping[str, object]:
        manifest = self.runtime.create(int(event_count), overwrite=bool(overwrite))
        return {
            "api_version": VERSION,
            "database_root": str(self.database_root),
            "created": True,
            "event_count": int(event_count),
            "durable_manifest": dict(manifest),
        }

    def open(self, *, repair_wal_tail: bool = True) -> Mapping[str, object]:
        status = self.runtime.open(repair_wal_tail=bool(repair_wal_tail))
        return {"api_version": VERSION, **dict(status)}

    def close(self) -> None:
        self.runtime.close()

    def __enter__(self) -> "UltraBalloonDatabase":
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _require_open(self) -> None:
        if not self.runtime.opened:
            raise RuntimeError("database is not open")

    def status(self) -> Mapping[str, object]:
        return {"api_version": VERSION, **dict(self.runtime.status())}

    def put_record(self, record_id: str, node_id: int, payload: bytes | bytearray | memoryview) -> Mapping[str, object]:
        self._require_open()
        tx = self.runtime.begin()
        tx.put_record(str(record_id), int(node_id), bytes(payload))
        receipt = tx.commit()
        return {"api_version": VERSION, "operation": "put_record", **receipt.__dict__}

    def get_record(self, record_id: str) -> Mapping[str, object]:
        self._require_open()
        rec = self.runtime.get_record(str(record_id))
        return {
            "api_version": VERSION,
            "record_id": rec.record_id,
            "node_id": rec.node_id,
            "payload_b64": base64.b64encode(rec.payload).decode("ascii"),
            "payload_bytes": len(rec.payload),
            "payload_sha256": rec.payload_sha256,
        }

    def put_edge(
        self,
        src: int,
        dst: int,
        edge_type: EdgeType | int | str,
        weight: float = 1.0,
    ) -> Mapping[str, object]:
        self._require_open()
        et = parse_edge_type(edge_type)
        tx = self.runtime.begin()
        tx.put_edge(int(src), int(dst), et, float(weight))
        receipt = tx.commit()
        return {
            "api_version": VERSION,
            "operation": "put_edge",
            "edge_type": et.name,
            "edge_type_id": int(et),
            **receipt.__dict__,
        }

    def put_record_and_edge(
        self,
        record_id: str,
        node_id: int,
        payload: bytes,
        src: int,
        edge_type: EdgeType | int | str,
        weight: float = 1.0,
    ) -> Mapping[str, object]:
        self._require_open()
        et = parse_edge_type(edge_type)
        tx = self.runtime.begin()
        tx.put_record(str(record_id), int(node_id), bytes(payload))
        tx.put_edge(int(src), int(node_id), et, float(weight))
        receipt = tx.commit()
        return {
            "api_version": VERSION,
            "operation": "put_record_and_edge",
            "edge_type": et.name,
            "edge_type_id": int(et),
            **receipt.__dict__,
        }

    def get_edges(
        self,
        node_id: int,
        *,
        direction: str = "out",
        edge_types: Sequence[EdgeType | int | str] | None = None,
        limit: int = 1000,
    ) -> Mapping[str, object]:
        self._require_open()
        direction = str(direction).lower()
        if direction not in {"out", "in", "both"}:
            raise ValueError("direction must be out, in, or both")
        if int(limit) <= 0:
            raise ValueError("limit must be positive")
        allowed = set(parse_edge_mask(edge_types)) if edge_types else None
        rows: list[dict[str, object]] = []
        seen: set[tuple[int, int, int, int]] = set()

        def consider(src: int, dst: int, edge_type: EdgeType, weight: float, source_layer: str) -> None:
            if allowed is not None and edge_type not in allowed:
                return
            if direction == "out" and src != int(node_id):
                return
            if direction == "in" and dst != int(node_id):
                return
            if direction == "both" and src != int(node_id) and dst != int(node_id):
                return
            key = (src, dst, int(edge_type), int(round(weight * 1_000_000)))
            if key in seen:
                return
            seen.add(key)
            rows.append({
                "src": src,
                "dst": dst,
                "edge_type": edge_type.name,
                "edge_type_id": int(edge_type),
                "weight": weight,
                "source_layer": source_layer,
            })

        for edge in self.runtime.base.hot_graph.edges:
            consider(int(edge.src), int(edge.dst), EdgeType(int(edge.edge_type)), float(edge.weight), "L2_BASE")
        for edge in self.runtime._edges:  # V00N durable overlay, wrapped here as V00O public API.
            consider(int(edge.src), int(edge.dst), EdgeType(int(edge.edge_type)), float(edge.weight), "L2_DURABLE")
        rows.sort(key=lambda r: (int(r["src"]), int(r["dst"]), int(r["edge_type_id"]), int(round(float(r["weight"]) * 1_000_000))))
        rows = rows[: int(limit)]
        return {
            "api_version": VERSION,
            "node_id": int(node_id),
            "direction": direction,
            "edge_count": len(rows),
            "edges": rows,
        }

    def wave_activation(
        self,
        seed_nodes: Iterable[int],
        *,
        edge_mask: Sequence[EdgeType | int | str] | None = None,
        energy_threshold: float = 0.10,
        top_k: int = 64,
        max_steps: int = 2,
        rigor_multiplier: float = 1.0,
    ) -> Mapping[str, object]:
        self._require_open()
        mask = parse_edge_mask(edge_mask)
        receipt = self.runtime.wave_query_nodes(
            seed_nodes,
            edge_mask=mask,
            energy_threshold=float(energy_threshold),
            top_k=int(top_k),
            max_steps=int(max_steps),
            rigor_multiplier=float(rigor_multiplier),
        )
        results = [
            {
                "node_id": int(row.node_id),
                "energy_score": float(row.energy_score),
                "best_path_len": int(row.best_path_len),
                "path_edge_types": [et.name for et in row.path_edge_types],
                "path_edge_type_ids": [int(et) for et in row.path_edge_types],
                "record_id": row.record_id,
            }
            for row in receipt.results
        ]
        return {
            "api_version": VERSION,
            "seed_nodes": list(receipt.seed_nodes),
            "edge_mask": [et.name for et in mask],
            "result_count": len(results),
            "results": results,
            "stats": dict(receipt.stats),
        }

    def checkpoint(self) -> Mapping[str, object]:
        self._require_open()
        return {"api_version": VERSION, **dict(self.runtime.checkpoint())}

    def verify(self) -> Mapping[str, object]:
        self._require_open()
        return {"api_version": VERSION, **dict(self.runtime.verify_integrity())}

    def get_base_event(self, event_id: int, *, include_payload: bool = False) -> Mapping[str, object]:
        self._require_open()
        rec = self.runtime.base.get_event_record(int(event_id))
        result: dict[str, object] = {
            "api_version": VERSION,
            "event_id": int(rec.event_id),
            "seed_node": int(rec.seed_node),
            "project_node": int(rec.project_node),
            "code_node": int(rec.code_node),
            "rule_node": int(rec.rule_node),
            "payload_offset": int(rec.payload_offset),
            "payload_len": int(rec.payload_len),
        }
        if include_payload:
            query = self.runtime.base.wave_query([int(event_id)], top_k_per_seed=1, max_steps=1)
            fetched = self.runtime.base.fetch_payloads_for_wave(query, max_records=1)
            payload = fetched.result.payloads.get(int(event_id), b"")
            result["payload_b64"] = base64.b64encode(payload).decode("ascii")
            result["payload_sha_verified"] = self.runtime.base.verify_event_payload(int(event_id))
        return result

    def export_base_wave_subgraph(
        self,
        seed_event_ids: Iterable[int],
        *,
        energy_threshold: float = 0.10,
        top_k_per_seed: int = 8,
        max_steps: int = 2,
    ) -> bytes:
        self._require_open()
        query = self.runtime.base.wave_query(
            seed_event_ids,
            energy_threshold=float(energy_threshold),
            top_k_per_seed=int(top_k_per_seed),
            max_steps=int(max_steps),
        )
        return self.runtime.base.export_wave_subgraph(query)

    def import_floating_subgraph(self, stream: bytes) -> Mapping[str, object]:
        self._require_open()
        return {"api_version": VERSION, **dict(self.runtime.base.import_wave_subgraph(bytes(stream)))}
