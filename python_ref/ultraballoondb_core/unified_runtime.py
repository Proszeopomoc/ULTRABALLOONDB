#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UltraBalloonDB V00M unified L0-L7 reference database runtime.

This module binds the established UltraBalloonDB layers into one stateful
runtime object and one process:

L0 lossless archive / payload store
L1 exact event and node indexes
L2 typed edge graph
L3 deterministic wave activation and path evidence
L4 compact hot snapshot
L5 bounded coalesced payload fetch
L6 snapshot crystallization inventory
L7 deterministic floating-subgraph export/import

The runtime is semantics-blind. It does not call models, interpret payloads,
or replace the L2 graph or L3 wave with an auxiliary compression mechanism.
Durable mutation/WAL/crash recovery is intentionally reserved for V00N.
"""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Sequence, Tuple

from ultraballoondb_core.floating_subgraph import (
    SyntheticHotSnapshot,
    decode_stream,
    hot_patch_subgraph,
    verify_stream,
)
from ultraballoondb_core.hot_snapshot import (
    ARCHIVE_RECORD_STRUCT,
    ArchiveRecord,
    archive_paths,
    build_hot_snapshot_from_archive,
    load_hot_snapshot,
    pack_archive_record,
    sha256_file,
    snapshot_paths,
    unpack_archive_record,
    verify_payload_from_archive,
    write_lossless_archive,
)
from ultraballoondb_core.hot_wave_subgraph_binding import (
    LoadedHotWaveGraph,
    SeedWaveRow,
    export_wave_rows_as_floating_subgraph,
    load_real_hot_wave_graph,
    run_seed_waves,
)
from ultraballoondb_core.payload_fetch import (
    FetchResult,
    RecordPointer,
    build_coalesced_fetch_plan,
    coalesced_fetch_payloads,
    payload_digest,
)
from ultraballoondb_core.relation_algebra import PathDerivation, default_relation_algebra
from ultraballoondb_core.types import EdgeType

VERSION = "V00M_UNIFIED_L0_L7_DATABASE_RUNTIME"
DEFAULT_EDGE_MASK = (
    EdgeType.PROJECT_CONTEXT,
    EdgeType.CODE_PATTERN,
    EdgeType.RULE_TO_CODE_PATTERN,
)


@dataclass(frozen=True)
class RuntimePaths:
    database_root: Path
    archive_dir: Path
    snapshot_dir: Path
    runtime_manifest_path: Path


@dataclass(frozen=True)
class WaveQueryReceipt:
    seed_event_ids: Tuple[int, ...]
    seed_nodes: Tuple[int, ...]
    rows: Tuple[SeedWaveRow, ...]
    wave_stats: Mapping[str, int | float]
    relation_derivations: Tuple[PathDerivation, ...]


@dataclass(frozen=True)
class PayloadFetchReceipt:
    event_ids: Tuple[int, ...]
    result: FetchResult
    digest: str
    planned_span_count: int


class UnifiedDatabaseRuntime:
    """One reference runtime exposing the existing L0-L7 mechanisms."""

    def __init__(self, database_root: Path) -> None:
        root = Path(database_root).resolve()
        self.paths = RuntimePaths(
            database_root=root,
            archive_dir=root / "archive",
            snapshot_dir=root / "hot_snapshot",
            runtime_manifest_path=root / "runtime_manifest.json",
        )
        self._archive_manifest: Mapping[str, object] | None = None
        self._snapshot_manifest: Mapping[str, object] | None = None
        self._hot_graph: LoadedHotWaveGraph | None = None
        self._node_to_events: Dict[int, Tuple[int, ...]] = {}
        self._opened = False
        self._last_query: WaveQueryReceipt | None = None
        self._import_target: SyntheticHotSnapshot | None = None

    @property
    def opened(self) -> bool:
        return self._opened

    @property
    def hot_graph(self) -> LoadedHotWaveGraph:
        if not self._opened or self._hot_graph is None:
            raise RuntimeError("database is not open")
        return self._hot_graph

    @property
    def archive_manifest(self) -> Mapping[str, object]:
        if not self._opened or self._archive_manifest is None:
            raise RuntimeError("database is not open")
        return self._archive_manifest

    @property
    def snapshot_manifest(self) -> Mapping[str, object]:
        if not self._opened or self._snapshot_manifest is None:
            raise RuntimeError("database is not open")
        return self._snapshot_manifest

    def create(self, event_count: int, *, overwrite: bool = False) -> Mapping[str, object]:
        """Create a reference database from the established lossless archive format."""
        if event_count <= 0:
            raise ValueError("event_count must be positive")
        root = self.paths.database_root
        if root.exists():
            if not overwrite:
                raise FileExistsError(f"database root already exists: {root}")
            shutil.rmtree(root)
        root.mkdir(parents=True, exist_ok=False)
        archive_manifest = write_lossless_archive(int(event_count), self.paths.archive_dir)
        snapshot_manifest = build_hot_snapshot_from_archive(self.paths.archive_dir, self.paths.snapshot_dir)
        runtime_manifest = {
            "version": VERSION,
            "database_role": "UNIFIED_REFERENCE_RUNTIME",
            "event_count": int(event_count),
            "archive_records_sha256": archive_manifest["records_sha256"],
            "archive_payloads_sha256": archive_manifest["payloads_sha256"],
            "hot_snapshot_sha256": snapshot_manifest["snapshot_sha256"],
            "layers": ["L0", "L1", "L2", "L3", "L4", "L5", "L6", "L7"],
            "durable_mutation_wal_included": False,
            "db_core_only": True,
            "agent_policy": False,
            "compression_replaces_l2_l3": False,
        }
        self.paths.runtime_manifest_path.write_text(
            json.dumps(runtime_manifest, indent=2, sort_keys=True),
            encoding="utf-8",
            newline="\n",
        )
        return runtime_manifest

    def _read_archive_record(self, event_id: int) -> ArchiveRecord:
        if event_id < 0:
            raise IndexError("event_id must be non-negative")
        ap = archive_paths(self.paths.archive_dir)
        offset = int(event_id) * ARCHIVE_RECORD_STRUCT.size
        with ap.records_path.open("rb") as f:
            f.seek(offset)
            chunk = f.read(ARCHIVE_RECORD_STRUCT.size)
        if len(chunk) != ARCHIVE_RECORD_STRUCT.size:
            raise IndexError(f"event_id out of range: {event_id}")
        record = unpack_archive_record(chunk)
        if int(record.event_id) != int(event_id):
            raise ValueError("exact event index mismatch")
        return record

    def get_event_record(self, event_id: int) -> ArchiveRecord:
        if not self._opened:
            raise RuntimeError("database is not open")
        return self._read_archive_record(int(event_id))

    def _build_node_event_index(self) -> Dict[int, Tuple[int, ...]]:
        event_count = int(self._archive_manifest["event_count"])  # type: ignore[index]
        tmp: MutableMapping[int, List[int]] = {}
        for event_id in range(event_count):
            rec = self._read_archive_record(event_id)
            for node_id in (rec.seed_node, rec.project_node, rec.code_node, rec.rule_node):
                tmp.setdefault(int(node_id), []).append(int(event_id))
        return {node: tuple(values) for node, values in sorted(tmp.items())}

    def _verify_static_files(self) -> None:
        ap = archive_paths(self.paths.archive_dir)
        sp = snapshot_paths(self.paths.snapshot_dir)
        if sha256_file(ap.records_path) != str(self._archive_manifest["records_sha256"]):  # type: ignore[index]
            raise ValueError("archive record SHA mismatch")
        if sha256_file(ap.payloads_path) != str(self._archive_manifest["payloads_sha256"]):  # type: ignore[index]
            raise ValueError("archive payload SHA mismatch")
        actual_snapshot_hash = str(self._hot_graph.snapshot_sha256) if self._hot_graph else ""
        expected_snapshot_hash = str(self._snapshot_manifest["snapshot_sha256"])  # type: ignore[index]
        if actual_snapshot_hash != expected_snapshot_hash:
            raise ValueError("hot snapshot SHA mismatch")
        if not sp.edges_path.exists() or not sp.crystals_path.exists():
            raise FileNotFoundError("hot snapshot files missing")

    def open(self) -> Mapping[str, object]:
        """Open all existing layers and build the reference exact node index."""
        if self._opened:
            return self.status()
        if not self.paths.runtime_manifest_path.exists():
            raise FileNotFoundError("runtime manifest missing")
        ap = archive_paths(self.paths.archive_dir)
        sp = snapshot_paths(self.paths.snapshot_dir)
        self._archive_manifest = json.loads(ap.manifest_path.read_text(encoding="utf-8"))
        self._snapshot_manifest = json.loads(sp.manifest_path.read_text(encoding="utf-8"))
        self._hot_graph = load_real_hot_wave_graph(self.paths.snapshot_dir)
        self._verify_static_files()
        self._node_to_events = self._build_node_event_index()
        event_count = int(self._archive_manifest["event_count"])
        self._import_target = SyntheticHotSnapshot(logical_event_count=max(10_000_000_000, event_count * 10))
        self._opened = True
        return self.status()

    def close(self) -> None:
        self._archive_manifest = None
        self._snapshot_manifest = None
        self._hot_graph = None
        self._node_to_events = {}
        self._last_query = None
        self._import_target = None
        self._opened = False

    def status(self) -> Mapping[str, object]:
        if not self._opened or self._archive_manifest is None or self._snapshot_manifest is None or self._hot_graph is None:
            return {"version": VERSION, "opened": False, "database_root": str(self.paths.database_root)}
        return {
            "version": VERSION,
            "opened": True,
            "database_root": str(self.paths.database_root),
            "event_count": int(self._archive_manifest["event_count"]),
            "typed_edge_count": int(self._hot_graph.graph.edge_count),
            "hot_edge_count": len(self._hot_graph.edges),
            "crystal_count": int(self._snapshot_manifest.get("crystal_count", 0)),
            "exact_index_node_count": len(self._node_to_events),
            "hot_snapshot_sha256": self._hot_graph.snapshot_sha256,
            "layers_ready": ["L0", "L1", "L2", "L3", "L4", "L5", "L6", "L7"],
        }

    def wave_query(
        self,
        seed_event_ids: Iterable[int],
        *,
        edge_mask: Sequence[EdgeType] = DEFAULT_EDGE_MASK,
        energy_threshold: float = 0.10,
        top_k_per_seed: int = 8,
        max_steps: int = 2,
        rigor_multiplier: float = 1.0,
    ) -> WaveQueryReceipt:
        if not self._opened:
            raise RuntimeError("database is not open")
        event_ids = tuple(sorted(set(int(x) for x in seed_event_ids)))
        if not event_ids:
            raise ValueError("at least one seed event is required")
        seed_nodes = tuple(int(self._read_archive_record(event_id).seed_node) for event_id in event_ids)
        rows, stats = run_seed_waves(
            self.hot_graph,
            seed_nodes,
            edge_mask=tuple(edge_mask),
            energy_threshold=float(energy_threshold),
            top_k_per_seed=int(top_k_per_seed),
            max_steps=int(max_steps),
            rigor_multiplier=float(rigor_multiplier),
        )
        algebra = default_relation_algebra()
        derivations = tuple(
            algebra.derive_path(tuple(edge.name for edge in row.result.path_edge_types))
            for row in rows
        )
        receipt = WaveQueryReceipt(
            seed_event_ids=event_ids,
            seed_nodes=seed_nodes,
            rows=rows,
            wave_stats=stats,
            relation_derivations=derivations,
        )
        self._last_query = receipt
        return receipt

    def _event_ids_for_wave_rows(self, rows: Sequence[SeedWaveRow], max_records: int) -> Tuple[int, ...]:
        if max_records <= 0:
            return tuple()
        ranked = sorted(
            rows,
            key=lambda row: (
                -float(row.result.energy_score),
                int(row.result.best_path_len),
                int(row.result.node_id),
                int(row.seed_node),
            ),
        )
        chosen: List[int] = []
        seen: set[int] = set()
        for row in ranked:
            for event_id in self._node_to_events.get(int(row.result.node_id), ()):  # L1 exact node -> event refs
                if event_id in seen:
                    continue
                seen.add(event_id)
                chosen.append(event_id)
                if len(chosen) >= max_records:
                    return tuple(chosen)
        return tuple(chosen)

    def fetch_payloads_for_wave(
        self,
        query: WaveQueryReceipt | None = None,
        *,
        max_records: int = 16,
        max_gap_bytes: int = 256,
        max_span_bytes: int = 65536,
    ) -> PayloadFetchReceipt:
        if not self._opened:
            raise RuntimeError("database is not open")
        receipt = query or self._last_query
        if receipt is None:
            raise RuntimeError("no wave query available")
        event_ids = self._event_ids_for_wave_rows(receipt.rows, int(max_records))
        if not event_ids:
            event_ids = receipt.seed_event_ids[: int(max_records)]
        pointers = []
        for event_id in event_ids:
            rec = self._read_archive_record(event_id)
            pointers.append(RecordPointer(record_id=event_id, offset=int(rec.payload_offset), length=int(rec.payload_len)))
        spans = build_coalesced_fetch_plan(
            pointers,
            max_gap_bytes=int(max_gap_bytes),
            max_span_bytes=int(max_span_bytes),
        )
        result = coalesced_fetch_payloads(archive_paths(self.paths.archive_dir).payloads_path, spans)
        return PayloadFetchReceipt(
            event_ids=event_ids,
            result=result,
            digest=payload_digest(result.payloads),
            planned_span_count=len(spans),
        )

    def export_wave_subgraph(self, query: WaveQueryReceipt | None = None) -> bytes:
        if not self._opened:
            raise RuntimeError("database is not open")
        receipt = query or self._last_query
        if receipt is None:
            raise RuntimeError("no wave query available")
        params = {
            "seed_event_ids": list(receipt.seed_event_ids),
            "seed_nodes": list(receipt.seed_nodes),
            "top_k_source": "WAVE_QUERY_RECEIPT",
            "runtime_version": VERSION,
        }
        stream = export_wave_rows_as_floating_subgraph(
            self.hot_graph,
            receipt.rows,
            export_params=params,
            wave_stats=receipt.wave_stats,
        )
        verify_stream(stream)
        return stream

    def import_wave_subgraph(self, stream: bytes) -> Mapping[str, object]:
        if not self._opened or self._import_target is None:
            raise RuntimeError("database is not open")
        decode_stream(stream)
        return hot_patch_subgraph(self._import_target, stream)

    def verify_event_payload(self, event_id: int) -> bool:
        if not self._opened:
            raise RuntimeError("database is not open")
        return bool(verify_payload_from_archive(self.paths.archive_dir, int(event_id)))
