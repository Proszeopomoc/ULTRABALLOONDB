#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UltraBalloonDB V00N durable writes, WAL, and crash recovery.

This reference core extends the V00M unified L0-L7 runtime with a single-writer,
append-only write-ahead log and an atomically replaceable checkpoint for mutable
records and typed edges.

Durability contract:
- a transaction becomes committed only after its COMMIT frame is appended and
  fsync completes;
- recovery applies only complete committed transactions;
- a truncated trailing WAL frame is removed back to the last valid boundary;
- checksum damage inside an otherwise complete frame is a hard error;
- checkpoint writes use temp-file + fsync + atomic replace;
- the V00M canonical archive and hot snapshot remain unchanged.

This module remains semantics-blind. It stores byte payloads, numeric node IDs,
typed edges, weights, transaction IDs, hashes, and exact indexes only.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Sequence, Tuple

from ultraballoondb_core.types import EdgeType, WaveConfig, WaveResult
from ultraballoondb_core.unified_runtime import DEFAULT_EDGE_MASK, UnifiedDatabaseRuntime
from ultraballoondb_core.wave import TypedGraph, wave_activation

VERSION = "V00N_DURABLE_WRITES_WAL_CRASH_RECOVERY"
WAL_MAGIC = b"UBWL"
WAL_HEADER = struct.Struct("<4sI32s")
MAX_WAL_FRAME_BYTES = 64 * 1024 * 1024


def _canonical_json_bytes(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def _fsync_directory(path: Path) -> None:
    """Best-effort directory fsync; unsupported on some Windows configurations."""
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except (AttributeError, OSError):
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


@dataclass(frozen=True)
class DurablePaths:
    root: Path
    durable_dir: Path
    wal_path: Path
    checkpoint_path: Path
    manifest_path: Path


@dataclass(frozen=True)
class DurableRecord:
    record_id: str
    node_id: int
    payload: bytes
    payload_sha256: str


@dataclass(frozen=True)
class DurableEdge:
    src: int
    dst: int
    edge_type: EdgeType
    weight: float

    def key(self) -> Tuple[int, int, int, int]:
        return (
            int(self.src),
            int(self.dst),
            int(self.edge_type),
            int(round(float(self.weight) * 1_000_000)),
        )


@dataclass(frozen=True)
class WalScan:
    entries: Tuple[Mapping[str, object], ...]
    valid_frame_count: int
    last_good_offset: int
    tail_repaired_bytes: int
    max_lsn: int
    wal_sha256: str


@dataclass(frozen=True)
class RecoveryReport:
    checkpoint_lsn: int
    committed_transactions_seen: int
    replayed_transactions: int
    ignored_uncommitted_transactions: int
    tail_repaired_bytes: int
    valid_wal_frames: int
    last_applied_lsn: int
    wal_sha256: str


@dataclass(frozen=True)
class CommitReceipt:
    txid: str
    commit_lsn: int
    operation_count: int
    record_count: int
    edge_count: int
    state_sha256: str


@dataclass(frozen=True)
class DurableWaveReceipt:
    seed_nodes: Tuple[int, ...]
    results: Tuple[WaveResult, ...]
    stats: Mapping[str, int | float]


class WriteAheadLog:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_bytes(b"")

    @staticmethod
    def _frame(entry: Mapping[str, object]) -> bytes:
        payload = _canonical_json_bytes(entry)
        if len(payload) > MAX_WAL_FRAME_BYTES:
            raise ValueError("WAL frame too large")
        digest = hashlib.sha256(payload).digest()
        return WAL_HEADER.pack(WAL_MAGIC, len(payload), digest) + payload

    def append_entries(self, entries: Sequence[Mapping[str, object]], *, sync: bool = True) -> int:
        if not entries:
            return self.path.stat().st_size
        with self.path.open("ab") as f:
            for entry in entries:
                f.write(self._frame(entry))
            f.flush()
            if sync:
                os.fsync(f.fileno())
            return f.tell()

    def append_raw_tail_for_test(self, data: bytes) -> None:
        with self.path.open("ab") as f:
            f.write(bytes(data))
            f.flush()
            os.fsync(f.fileno())

    def scan(self, *, repair_tail: bool) -> WalScan:
        entries: List[Mapping[str, object]] = []
        last_good = 0
        tail_repaired = 0
        max_lsn = 0
        previous_lsn = 0
        file_size = self.path.stat().st_size

        with self.path.open("rb") as f:
            while True:
                frame_start = f.tell()
                header = f.read(WAL_HEADER.size)
                if not header:
                    last_good = frame_start
                    break
                if len(header) < WAL_HEADER.size:
                    last_good = frame_start
                    tail_repaired = file_size - frame_start
                    break
                magic, payload_len, expected_digest = WAL_HEADER.unpack(header)
                if magic != WAL_MAGIC:
                    raise ValueError(f"WAL magic mismatch at offset {frame_start}")
                if payload_len <= 0 or payload_len > MAX_WAL_FRAME_BYTES:
                    raise ValueError(f"WAL payload length invalid at offset {frame_start}")
                payload = f.read(payload_len)
                if len(payload) < payload_len:
                    last_good = frame_start
                    tail_repaired = file_size - frame_start
                    break
                if hashlib.sha256(payload).digest() != expected_digest:
                    raise ValueError(f"WAL checksum mismatch at offset {frame_start}")
                try:
                    entry = json.loads(payload.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ValueError(f"WAL JSON invalid at offset {frame_start}") from exc
                if not isinstance(entry, dict):
                    raise ValueError("WAL entry must be an object")
                lsn = int(entry.get("lsn", 0))
                if lsn <= previous_lsn:
                    raise ValueError("WAL LSN order violation")
                previous_lsn = lsn
                max_lsn = max(max_lsn, lsn)
                entries.append(entry)
                last_good = f.tell()

        if tail_repaired:
            if not repair_tail:
                raise ValueError(f"WAL has truncated tail of {tail_repaired} bytes")
            with self.path.open("r+b") as f:
                f.truncate(last_good)
                f.flush()
                os.fsync(f.fileno())

        return WalScan(
            entries=tuple(entries),
            valid_frame_count=len(entries),
            last_good_offset=last_good,
            tail_repaired_bytes=tail_repaired,
            max_lsn=max_lsn,
            wal_sha256=_sha256_file(self.path),
        )


class DurableTransaction:
    def __init__(self, runtime: "DurableDatabaseRuntime") -> None:
        self._runtime = runtime
        self._ops: List[Mapping[str, object]] = []
        self._closed = False

    def put_record(self, record_id: str, node_id: int, payload: bytes) -> "DurableTransaction":
        if self._closed:
            raise RuntimeError("transaction is closed")
        payload_bytes = bytes(payload)
        if not record_id:
            raise ValueError("record_id cannot be empty")
        if int(node_id) < 0:
            raise ValueError("node_id must be non-negative")
        self._ops.append({
            "kind": "PUT_RECORD",
            "record_id": str(record_id),
            "node_id": int(node_id),
            "payload_b64": base64.b64encode(payload_bytes).decode("ascii"),
            "payload_sha256": _sha256_bytes(payload_bytes),
        })
        return self

    def put_edge(
        self,
        src: int,
        dst: int,
        edge_type: EdgeType,
        weight: float = 1.0,
    ) -> "DurableTransaction":
        if self._closed:
            raise RuntimeError("transaction is closed")
        edge_type = edge_type if isinstance(edge_type, EdgeType) else EdgeType(int(edge_type))
        if int(src) < 0 or int(dst) < 0:
            raise ValueError("node IDs must be non-negative")
        if not 0.0 <= float(weight) <= 1.0:
            raise ValueError("edge weight must be in [0,1]")
        self._ops.append({
            "kind": "PUT_EDGE",
            "src": int(src),
            "dst": int(dst),
            "edge_type": int(edge_type),
            "weight_million": int(round(float(weight) * 1_000_000)),
        })
        return self

    @property
    def operations(self) -> Tuple[Mapping[str, object], ...]:
        return tuple(self._ops)

    def commit(self) -> CommitReceipt:
        if self._closed:
            raise RuntimeError("transaction is closed")
        self._closed = True
        return self._runtime._commit_operations(self._ops)

    def abort(self) -> None:
        self._closed = True
        self._ops.clear()


class DurableDatabaseRuntime:
    """V00M unified runtime plus durable mutable record/edge overlay."""

    def __init__(self, database_root: Path) -> None:
        root = Path(database_root).resolve()
        self.paths = DurablePaths(
            root=root,
            durable_dir=root / "durable",
            wal_path=root / "durable" / "wal.ubwl",
            checkpoint_path=root / "durable" / "checkpoint.json",
            manifest_path=root / "durable" / "durable_manifest.json",
        )
        self.base = UnifiedDatabaseRuntime(root)
        self._wal: WriteAheadLog | None = None
        self._records: Dict[str, DurableRecord] = {}
        self._node_to_record_ids: Dict[int, Tuple[str, ...]] = {}
        self._edges: List[DurableEdge] = []
        self._edge_keys: set[Tuple[int, int, int, int]] = set()
        self._committed_txids: set[str] = set()
        self._last_applied_lsn = 0
        self._next_lsn = 1
        self._opened = False
        self._merged_graph: TypedGraph | None = None
        self._recovery_report: RecoveryReport | None = None

    @property
    def opened(self) -> bool:
        return self._opened

    @property
    def recovery_report(self) -> RecoveryReport:
        if self._recovery_report is None:
            raise RuntimeError("database is not open")
        return self._recovery_report

    @property
    def wal(self) -> WriteAheadLog:
        if self._wal is None:
            raise RuntimeError("WAL is not initialized")
        return self._wal

    def create(self, event_count: int, *, overwrite: bool = False) -> Mapping[str, object]:
        base_manifest = self.base.create(int(event_count), overwrite=overwrite)
        self.paths.durable_dir.mkdir(parents=True, exist_ok=True)
        self.paths.wal_path.write_bytes(b"")
        self._wal = WriteAheadLog(self.paths.wal_path)
        durable_manifest = {
            "version": VERSION,
            "role": "CORE_DURABLE_MUTATION_REFERENCE",
            "single_writer": True,
            "wal_frame_checksum": "SHA256",
            "checkpoint_atomic_replace": True,
            "canonical_base_files_mutated": False,
            "layers": ["L0", "L1", "L2", "L3", "L4"],
            "preserves": ["L2_TYPED_EDGE_GRAPH", "L3_WAVE_ACTIVATION"],
            "base_runtime_version": base_manifest["version"],
        }
        self.paths.manifest_path.write_text(
            json.dumps(durable_manifest, indent=2, sort_keys=True),
            encoding="utf-8",
            newline="\n",
        )
        self._write_checkpoint(last_applied_lsn=0)
        return durable_manifest

    def _empty_state(self) -> None:
        self._records = {}
        self._node_to_record_ids = {}
        self._edges = []
        self._edge_keys = set()
        self._committed_txids = set()
        self._last_applied_lsn = 0

    def _state_payload(self) -> Mapping[str, object]:
        records = [
            {
                "record_id": rec.record_id,
                "node_id": rec.node_id,
                "payload_b64": base64.b64encode(rec.payload).decode("ascii"),
                "payload_sha256": rec.payload_sha256,
            }
            for rec in sorted(self._records.values(), key=lambda r: r.record_id)
        ]
        edges = [
            {
                "src": edge.src,
                "dst": edge.dst,
                "edge_type": int(edge.edge_type),
                "weight_million": int(round(edge.weight * 1_000_000)),
            }
            for edge in sorted(self._edges, key=lambda e: e.key())
        ]
        return {
            "records": records,
            "edges": edges,
            "committed_txids": sorted(self._committed_txids),
        }

    def state_sha256(self) -> str:
        return _sha256_bytes(_canonical_json_bytes(self._state_payload()))

    def _write_checkpoint(self, *, last_applied_lsn: int | None = None) -> Mapping[str, object]:
        self.paths.durable_dir.mkdir(parents=True, exist_ok=True)
        lsn = self._last_applied_lsn if last_applied_lsn is None else int(last_applied_lsn)
        state = self._state_payload()
        document: Dict[str, object] = {
            "version": VERSION,
            "last_applied_lsn": lsn,
            "state": state,
            "state_sha256": _sha256_bytes(_canonical_json_bytes(state)),
        }
        temp = self.paths.checkpoint_path.with_suffix(".json.tmp")
        with temp.open("wb") as f:
            f.write(json.dumps(document, indent=2, sort_keys=True).encode("utf-8"))
            f.write(b"\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, self.paths.checkpoint_path)
        _fsync_directory(self.paths.durable_dir)
        return document

    def checkpoint(self) -> Mapping[str, object]:
        if not self._opened:
            raise RuntimeError("database is not open")
        return self._write_checkpoint()

    def _load_checkpoint(self) -> int:
        self._empty_state()
        if not self.paths.checkpoint_path.exists():
            return 0
        document = json.loads(self.paths.checkpoint_path.read_text(encoding="utf-8"))
        state = document.get("state")
        if not isinstance(state, dict):
            raise ValueError("checkpoint state missing")
        expected = str(document.get("state_sha256", ""))
        actual = _sha256_bytes(_canonical_json_bytes(state))
        if actual != expected:
            raise ValueError("checkpoint state SHA mismatch")
        for item in state.get("records", []):
            self._apply_put_record(item)
        for item in state.get("edges", []):
            self._apply_put_edge(item)
        self._committed_txids = {str(x) for x in state.get("committed_txids", [])}
        self._last_applied_lsn = int(document.get("last_applied_lsn", 0))
        return self._last_applied_lsn

    def _rebuild_node_index(self) -> None:
        tmp: MutableMapping[int, List[str]] = {}
        for rec in self._records.values():
            tmp.setdefault(int(rec.node_id), []).append(rec.record_id)
        self._node_to_record_ids = {
            node: tuple(sorted(record_ids))
            for node, record_ids in sorted(tmp.items())
        }

    def _apply_put_record(self, op: Mapping[str, object]) -> None:
        record_id = str(op["record_id"])
        node_id = int(op["node_id"])
        payload = base64.b64decode(str(op["payload_b64"]).encode("ascii"), validate=True)
        payload_sha = str(op["payload_sha256"]).upper()
        if _sha256_bytes(payload) != payload_sha:
            raise ValueError("record payload SHA mismatch")
        candidate = DurableRecord(record_id, node_id, payload, payload_sha)
        previous = self._records.get(record_id)
        if previous is not None and previous != candidate:
            raise ValueError(f"record conflict for {record_id}")
        self._records[record_id] = candidate

    def _apply_put_edge(self, op: Mapping[str, object]) -> None:
        edge = DurableEdge(
            src=int(op["src"]),
            dst=int(op["dst"]),
            edge_type=EdgeType(int(op["edge_type"])),
            weight=float(int(op["weight_million"])) / 1_000_000.0,
        )
        key = edge.key()
        if key not in self._edge_keys:
            self._edge_keys.add(key)
            self._edges.append(edge)

    def _apply_operation(self, op: Mapping[str, object]) -> None:
        kind = str(op.get("kind", ""))
        if kind == "PUT_RECORD":
            self._apply_put_record(op)
        elif kind == "PUT_EDGE":
            self._apply_put_edge(op)
        else:
            raise ValueError(f"unsupported operation kind: {kind}")

    def _recover_from_wal(self, scan: WalScan, checkpoint_lsn: int) -> RecoveryReport:
        pending: Dict[str, List[Mapping[str, object]]] = {}
        seen_begin: set[str] = set()
        committed_seen = 0
        replayed = 0
        last_applied = checkpoint_lsn

        for entry in scan.entries:
            kind = str(entry.get("kind", ""))
            txid = str(entry.get("txid", ""))
            lsn = int(entry["lsn"])
            if not txid:
                raise ValueError("WAL transaction ID missing")
            if kind == "BEGIN":
                if txid in seen_begin or txid in pending:
                    raise ValueError("duplicate WAL BEGIN")
                seen_begin.add(txid)
                pending[txid] = []
            elif kind in ("PUT_RECORD", "PUT_EDGE"):
                if txid not in pending:
                    raise ValueError("WAL operation without BEGIN")
                pending[txid].append(entry)
            elif kind == "COMMIT":
                if txid not in pending:
                    raise ValueError("WAL COMMIT without BEGIN")
                ops = pending.pop(txid)
                if int(entry.get("op_count", -1)) != len(ops):
                    raise ValueError("WAL COMMIT operation count mismatch")
                committed_seen += 1
                if lsn > checkpoint_lsn and txid not in self._committed_txids:
                    for op in ops:
                        self._apply_operation(op)
                    self._committed_txids.add(txid)
                    self._last_applied_lsn = lsn
                    last_applied = max(last_applied, lsn)
                    replayed += 1
            else:
                raise ValueError(f"unknown WAL entry kind: {kind}")

        self._last_applied_lsn = max(self._last_applied_lsn, last_applied)
        self._rebuild_node_index()
        return RecoveryReport(
            checkpoint_lsn=checkpoint_lsn,
            committed_transactions_seen=committed_seen,
            replayed_transactions=replayed,
            ignored_uncommitted_transactions=len(pending),
            tail_repaired_bytes=scan.tail_repaired_bytes,
            valid_wal_frames=scan.valid_frame_count,
            last_applied_lsn=self._last_applied_lsn,
            wal_sha256=scan.wal_sha256,
        )

    def _rebuild_merged_graph(self) -> None:
        graph = TypedGraph()
        for edge in self.base.hot_graph.edges:
            graph.add_edge(edge.src, edge.dst, edge.edge_type, edge.weight)
        for edge in sorted(self._edges, key=lambda e: e.key()):
            graph.add_edge(edge.src, edge.dst, edge.edge_type, edge.weight)
        self._merged_graph = graph

    def open(self, *, repair_wal_tail: bool = True) -> Mapping[str, object]:
        if self._opened:
            return self.status()
        if not self.paths.manifest_path.exists():
            raise FileNotFoundError("durable manifest missing")
        self.base.open()
        checkpoint_lsn = self._load_checkpoint()
        self._wal = WriteAheadLog(self.paths.wal_path)
        scan = self._wal.scan(repair_tail=repair_wal_tail)
        self._next_lsn = scan.max_lsn + 1
        self._recovery_report = self._recover_from_wal(scan, checkpoint_lsn)
        self._rebuild_merged_graph()
        self._opened = True
        return self.status()

    def close(self) -> None:
        self.base.close()
        self._opened = False
        self._merged_graph = None

    def begin(self) -> DurableTransaction:
        if not self._opened:
            raise RuntimeError("database is not open")
        return DurableTransaction(self)

    def _wal_entry(self, txid: str, kind: str, body: Mapping[str, object] | None = None) -> Mapping[str, object]:
        entry: Dict[str, object] = {
            "version": VERSION,
            "lsn": self._next_lsn,
            "txid": txid,
            "kind": kind,
        }
        self._next_lsn += 1
        if body:
            entry.update(body)
        return entry

    def _validate_operations_against_state(self, ops: Sequence[Mapping[str, object]]) -> None:
        shadow_records = dict(self._records)
        shadow_edges = set(self._edge_keys)
        for op in ops:
            kind = str(op.get("kind", ""))
            if kind == "PUT_RECORD":
                record_id = str(op["record_id"])
                payload = base64.b64decode(str(op["payload_b64"]).encode("ascii"), validate=True)
                candidate = DurableRecord(
                    record_id=record_id,
                    node_id=int(op["node_id"]),
                    payload=payload,
                    payload_sha256=str(op["payload_sha256"]).upper(),
                )
                if _sha256_bytes(payload) != candidate.payload_sha256:
                    raise ValueError("record payload SHA mismatch")
                previous = shadow_records.get(record_id)
                if previous is not None and previous != candidate:
                    raise ValueError(f"record conflict for {record_id}")
                shadow_records[record_id] = candidate
            elif kind == "PUT_EDGE":
                edge = DurableEdge(
                    src=int(op["src"]),
                    dst=int(op["dst"]),
                    edge_type=EdgeType(int(op["edge_type"])),
                    weight=float(int(op["weight_million"])) / 1_000_000.0,
                )
                shadow_edges.add(edge.key())
            else:
                raise ValueError(f"unsupported operation kind: {kind}")

    def _commit_operations(self, operations: Sequence[Mapping[str, object]]) -> CommitReceipt:
        if not self._opened:
            raise RuntimeError("database is not open")
        if not operations:
            raise ValueError("transaction cannot be empty")
        self._validate_operations_against_state(operations)
        txid = uuid.uuid4().hex
        entries: List[Mapping[str, object]] = [self._wal_entry(txid, "BEGIN")]
        for op in operations:
            entries.append(self._wal_entry(txid, str(op["kind"]), op))
        commit_entry = self._wal_entry(txid, "COMMIT", {"op_count": len(operations)})
        entries.append(commit_entry)

        self.wal.append_entries(entries, sync=True)
        for op in operations:
            self._apply_operation(op)
        self._committed_txids.add(txid)
        self._last_applied_lsn = int(commit_entry["lsn"])
        self._rebuild_node_index()
        self._rebuild_merged_graph()
        return CommitReceipt(
            txid=txid,
            commit_lsn=self._last_applied_lsn,
            operation_count=len(operations),
            record_count=len(self._records),
            edge_count=len(self._edges),
            state_sha256=self.state_sha256(),
        )

    def append_uncommitted_transaction_for_test(self, operations: Sequence[Mapping[str, object]]) -> str:
        """Test-only helper: append BEGIN+operations without COMMIT."""
        if not self._opened:
            raise RuntimeError("database is not open")
        self._validate_operations_against_state(operations)
        txid = "TEST_UNCOMMITTED_" + uuid.uuid4().hex
        entries: List[Mapping[str, object]] = [self._wal_entry(txid, "BEGIN")]
        for op in operations:
            entries.append(self._wal_entry(txid, str(op["kind"]), op))
        self.wal.append_entries(entries, sync=True)
        return txid

    def append_partial_wal_tail_for_test(self, data: bytes = b"UBWL\x10\x00") -> None:
        """Test-only helper for a power-loss style truncated trailing frame."""
        self.wal.append_raw_tail_for_test(data)

    def get_record(self, record_id: str) -> DurableRecord:
        if not self._opened:
            raise RuntimeError("database is not open")
        try:
            return self._records[str(record_id)]
        except KeyError as exc:
            raise KeyError(f"record not found: {record_id}") from exc

    def record_ids_for_node(self, node_id: int) -> Tuple[str, ...]:
        if not self._opened:
            raise RuntimeError("database is not open")
        return self._node_to_record_ids.get(int(node_id), tuple())

    def wave_query_nodes(
        self,
        seed_nodes: Iterable[int],
        *,
        edge_mask: Sequence[EdgeType] = DEFAULT_EDGE_MASK,
        energy_threshold: float = 0.10,
        top_k: int = 64,
        max_steps: int = 2,
        rigor_multiplier: float = 1.0,
    ) -> DurableWaveReceipt:
        if not self._opened or self._merged_graph is None:
            raise RuntimeError("database is not open")
        seeds = tuple(sorted(set(int(x) for x in seed_nodes)))
        if not seeds:
            raise ValueError("at least one seed node is required")
        all_results: Dict[int, WaveResult] = {}
        aggregate: Dict[str, int | float] = {
            "seed_query_count": len(seeds),
            "expanded_nodes": 0,
            "filtered_by_mask": 0,
            "filtered_by_threshold": 0,
            "blocked_path_count": 0,
            "result_count_before_top_k": 0,
            "result_count_after_top_k": 0,
        }
        for seed in seeds:
            results, stats = wave_activation(
                self._merged_graph,
                WaveConfig(
                    seed_node=seed,
                    edge_mask=tuple(edge_mask),
                    energy_threshold=float(energy_threshold),
                    top_k=int(top_k),
                    max_steps=int(max_steps),
                    rigor_multiplier=float(rigor_multiplier),
                ),
            )
            for result in results:
                previous = all_results.get(result.node_id)
                if previous is None or (
                    result.energy_score,
                    -result.best_path_len,
                    -result.node_id,
                ) > (
                    previous.energy_score,
                    -previous.best_path_len,
                    -previous.node_id,
                ):
                    all_results[result.node_id] = result
            for key, value in stats.items():
                aggregate[key] = int(aggregate.get(key, 0)) + int(value)
        ordered = sorted(all_results.values(), key=lambda r: (-r.energy_score, r.best_path_len, r.node_id))[:top_k]
        return DurableWaveReceipt(seeds, tuple(ordered), aggregate)

    def verify_integrity(self) -> Mapping[str, object]:
        if not self._opened:
            raise RuntimeError("database is not open")
        scan = self.wal.scan(repair_tail=False)
        checkpoint_doc = json.loads(self.paths.checkpoint_path.read_text(encoding="utf-8"))
        state = checkpoint_doc["state"]
        checkpoint_valid = _sha256_bytes(_canonical_json_bytes(state)) == str(checkpoint_doc["state_sha256"])
        return {
            "checkpoint_valid": checkpoint_valid,
            "wal_valid": True,
            "wal_frames": scan.valid_frame_count,
            "wal_sha256": scan.wal_sha256,
            "state_sha256": self.state_sha256(),
            "base_opened": self.base.opened,
        }

    def status(self) -> Mapping[str, object]:
        if not self._opened:
            return {"version": VERSION, "opened": False, "database_root": str(self.paths.root)}
        return {
            "version": VERSION,
            "opened": True,
            "database_root": str(self.paths.root),
            "base_layers_ready": self.base.status().get("layers_ready", []),
            "durable_record_count": len(self._records),
            "durable_edge_count": len(self._edges),
            "committed_transaction_count": len(self._committed_txids),
            "last_applied_lsn": self._last_applied_lsn,
            "next_lsn": self._next_lsn,
            "state_sha256": self.state_sha256(),
            "recovery": {
                "checkpoint_lsn": self.recovery_report.checkpoint_lsn,
                "replayed_transactions": self.recovery_report.replayed_transactions,
                "ignored_uncommitted_transactions": self.recovery_report.ignored_uncommitted_transactions,
                "tail_repaired_bytes": self.recovery_report.tail_repaired_bytes,
                "wal_sha256": self.recovery_report.wal_sha256,
            },
        }
