#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UltraBalloonDB V00R2 opt-in native Rust query runtime binding.

The canonical L0/WAL/database state remains owned by the established Python
runtime. A rebuildable CSR layout is opened once by a persistent Rust process.
Successful L2/L3/L7 reads use Rust; mutations mark the derived layout stale and
force a safe Python fallback until an explicit rebuild.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
import threading
from typing import Iterable, Mapping, Sequence

from ultraballoondb_core.csr_mmap_hotpath import CsrMmapHotGraph
from ultraballoondb_core.database_api import UltraBalloonDatabase, parse_edge_mask
from ultraballoondb_core.types import EdgeType

VERSION = "V00R2_RUST_NATIVE_RUNTIME_BINDING"


@dataclass(frozen=True)
class BindingCounters:
    rust_requests: int
    rust_wave_requests: int
    rust_get_edges_requests: int
    python_fallback_requests: int
    rust_failures: int


class RustCoreProcess:
    """Persistent line-protocol client for the standalone Rust binary."""

    def __init__(self, binary: Path, layout_dir: Path) -> None:
        self.binary = Path(binary).resolve()
        self.layout_dir = Path(layout_dir).resolve()
        self._lock = threading.Lock()
        self._next_id = 1
        self._stderr_path = self.layout_dir / "rust_runtime_stderr.log"
        self._stderr_handle = None
        self.process: subprocess.Popen[str] | None = None
        self.ready: Mapping[str, object] = {}
        self.start()

    @property
    def alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def start(self) -> None:
        if self.alive:
            return
        self.layout_dir.mkdir(parents=True, exist_ok=True)
        self._stderr_handle = self._stderr_path.open("a", encoding="utf-8")
        self.process = subprocess.Popen(
            [str(self.binary), "serve", "--layout-dir", str(self.layout_dir)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._stderr_handle,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        assert self.process.stdout is not None
        line = self.process.stdout.readline()
        if not line:
            code = self.process.poll()
            raise RuntimeError(f"Rust runtime failed before READY, exit={code}")
        value = json.loads(line)
        if not bool(value.get("ready")):
            raise RuntimeError(f"invalid Rust READY response: {value}")
        self.ready = value

    def request(self, fields: Sequence[object]) -> Mapping[str, object]:
        with self._lock:
            if not self.alive or self.process is None:
                raise RuntimeError("Rust runtime process is not alive")
            request_id = str(self._next_id)
            self._next_id += 1
            text = "\t".join([str(fields[0]), request_id, *(str(v) for v in fields[1:])]) + "\n"
            assert self.process.stdin is not None and self.process.stdout is not None
            try:
                self.process.stdin.write(text)
                self.process.stdin.flush()
                line = self.process.stdout.readline()
            except (BrokenPipeError, OSError) as exc:
                raise RuntimeError("Rust runtime pipe failed") from exc
            if not line:
                raise RuntimeError(f"Rust runtime returned EOF, exit={self.process.poll()}")
            value = json.loads(line)
            if str(value.get("request_id")) != request_id:
                raise RuntimeError("Rust runtime request/response id mismatch")
            if not bool(value.get("pass")):
                raise ValueError(str(value.get("error", "Rust request failed")))
            return value

    def ping(self) -> bool:
        return bool(self.request(("PING",)).get("pong"))

    def get_edges(self, node_id: int) -> Mapping[str, object]:
        return self.request(("GET", int(node_id)))

    def wave(
        self,
        seed: int,
        *,
        max_steps: int,
        top_k: int,
        energy_threshold: float,
        edge_mask_bits: int,
        rigor_multiplier: float,
        export_limit: int = 128,
    ) -> Mapping[str, object]:
        return self.request((
            "WAVE",
            int(seed),
            int(max_steps),
            int(top_k),
            format(float(energy_threshold), ".17g"),
            int(edge_mask_bits),
            format(float(rigor_multiplier), ".17g"),
            int(export_limit),
            "L3",
        ))

    def raw_invalid_for_test(self) -> Mapping[str, object]:
        with self._lock:
            if not self.alive or self.process is None:
                raise RuntimeError("Rust runtime process is not alive")
            request_id = str(self._next_id)
            self._next_id += 1
            assert self.process.stdin is not None and self.process.stdout is not None
            self.process.stdin.write(f"INVALID\t{request_id}\n")
            self.process.stdin.flush()
            value = json.loads(self.process.stdout.readline())
            return value

    def kill_for_test(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=10)

    def close(self) -> None:
        process = self.process
        self.process = None
        if process is not None and process.poll() is None:
            try:
                assert process.stdin is not None and process.stdout is not None
                process.stdin.write("EXIT\t0\n")
                process.stdin.flush()
                process.stdout.readline()
                process.wait(timeout=10)
            except Exception:
                process.kill()
                process.wait(timeout=10)
        if self._stderr_handle is not None:
            self._stderr_handle.close()
            self._stderr_handle = None


def edge_mask_bits(values: Sequence[EdgeType | int | str] | None) -> tuple[tuple[EdgeType, ...], int]:
    mask = parse_edge_mask(values)
    bits = 0
    for edge_type in mask:
        bits |= 1 << int(edge_type)
    return mask, bits


def build_csr_layout_from_database(database: UltraBalloonDatabase, layout_dir: Path) -> Mapping[str, object]:
    """Rebuild the derived CSR layout from canonical base + committed overlay."""
    if not database.opened:
        raise RuntimeError("database must be open")
    rows: list[tuple[int, int, int, int, float]] = []
    for edge in database.runtime.base.hot_graph.edges:
        rows.append((
            int(edge.src),
            int(edge.dst),
            int(edge.edge_type),
            int(edge.relation_id),
            float(edge.weight),
        ))
    for edge in database.runtime._edges:
        rows.append((int(edge.src), int(edge.dst), int(edge.edge_type), 0, float(edge.weight)))
    rows.sort(key=lambda row: (row[0], row[2], row[1], row[3], row[4]))
    graph = CsrMmapHotGraph.build_from_sorted_edges(Path(layout_dir), rows)
    result = {
        "node_count": graph.node_count,
        "edge_count": graph.edge_count,
        "layout_sha256": graph.layout_sha256(),
        "mmap_active": graph.mmap_active,
        "full_scan_counter": graph.full_scan_counter,
    }
    graph.close()
    return result


class RustBoundUltraBalloonDatabase:
    """Opt-in API facade: canonical writes stay Python, query hot path uses Rust."""

    def __init__(self, database_root: str | Path, rust_binary: str | Path, layout_dir: str | Path | None = None) -> None:
        self.database_root = Path(database_root).resolve()
        self.rust_binary = Path(rust_binary).resolve()
        self.layout_dir = Path(layout_dir).resolve() if layout_dir else self.database_root / "derived" / "rust_csr"
        self.base = UltraBalloonDatabase(self.database_root)
        self.rust: RustCoreProcess | None = None
        self.layout_stale = True
        self._rust_requests = 0
        self._rust_wave_requests = 0
        self._rust_get_edges_requests = 0
        self._python_fallback_requests = 0
        self._rust_failures = 0

    @property
    def opened(self) -> bool:
        return self.base.opened

    @property
    def counters(self) -> BindingCounters:
        return BindingCounters(
            self._rust_requests,
            self._rust_wave_requests,
            self._rust_get_edges_requests,
            self._python_fallback_requests,
            self._rust_failures,
        )

    def create(self, event_count: int, *, overwrite: bool = False) -> Mapping[str, object]:
        result = self.base.create(int(event_count), overwrite=bool(overwrite))
        self.layout_stale = True
        return result

    def open(self, *, repair_wal_tail: bool = True, rebuild_rust_layout: bool = True) -> Mapping[str, object]:
        result = self.base.open(repair_wal_tail=bool(repair_wal_tail))
        if rebuild_rust_layout:
            self.rebuild_rust_layout()
        return {**dict(result), "rust_binding": dict(self.binding_status())}

    def close(self) -> None:
        if self.rust is not None:
            self.rust.close()
            self.rust = None
        self.base.close()

    def rebuild_rust_layout(self) -> Mapping[str, object]:
        if not self.base.opened:
            raise RuntimeError("database is not open")
        if self.rust is not None:
            self.rust.close()
            self.rust = None
        result = build_csr_layout_from_database(self.base, self.layout_dir)
        self.rust = RustCoreProcess(self.rust_binary, self.layout_dir)
        if not self.rust.ping():
            raise RuntimeError("Rust runtime ping failed")
        self.layout_stale = False
        return result

    def binding_status(self) -> Mapping[str, object]:
        counters = self.counters
        return {
            "version": VERSION,
            "active_backend": "RUST_NATIVE" if self.rust is not None and self.rust.alive and not self.layout_stale else "PYTHON_FALLBACK",
            "rust_process_alive": bool(self.rust is not None and self.rust.alive),
            "layout_stale": self.layout_stale,
            "layout_dir": str(self.layout_dir),
            "rust_requests": counters.rust_requests,
            "rust_wave_requests": counters.rust_wave_requests,
            "rust_get_edges_requests": counters.rust_get_edges_requests,
            "python_fallback_requests": counters.python_fallback_requests,
            "rust_failures": counters.rust_failures,
            "canonical_writes_owned_by_python": True,
            "python_required_by_rust_binary": False,
        }

    def status(self) -> Mapping[str, object]:
        return {**dict(self.base.status()), "rust_binding": dict(self.binding_status())}

    def verify(self) -> Mapping[str, object]:
        return {**dict(self.base.verify()), "rust_binding": dict(self.binding_status())}

    def checkpoint(self) -> Mapping[str, object]:
        return self.base.checkpoint()

    def put_record(self, record_id: str, node_id: int, payload: bytes) -> Mapping[str, object]:
        return self.base.put_record(record_id, node_id, payload)

    def get_record(self, record_id: str) -> Mapping[str, object]:
        return self.base.get_record(record_id)

    def put_edge(self, src: int, dst: int, edge_type: EdgeType | int | str, weight: float = 1.0) -> Mapping[str, object]:
        result = self.base.put_edge(src, dst, edge_type, weight)
        self.layout_stale = True
        return result

    def _fallback_wave(self, *args, **kwargs) -> Mapping[str, object]:
        self._python_fallback_requests += 1
        return self.base.wave_activation(*args, **kwargs)

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
        seeds = tuple(sorted(set(int(v) for v in seed_nodes)))
        if not seeds:
            raise ValueError("at least one seed node is required")
        mask, bits = edge_mask_bits(edge_mask)
        if self.layout_stale or self.rust is None or not self.rust.alive:
            return self._fallback_wave(
                seeds,
                edge_mask=mask,
                energy_threshold=energy_threshold,
                top_k=top_k,
                max_steps=max_steps,
                rigor_multiplier=rigor_multiplier,
            )
        try:
            best_by_node: dict[int, Mapping[str, object]] = {}
            aggregate = {
                "seed_query_count": len(seeds),
                "expanded_nodes": 0,
                "filtered_by_mask": 0,
                "filtered_by_threshold": 0,
                "blocked_path_count": 0,
                "result_count_before_top_k": 0,
                "result_count_after_top_k": 0,
            }
            for seed in seeds:
                reply = self.rust.wave(
                    seed,
                    max_steps=max_steps,
                    top_k=top_k,
                    energy_threshold=energy_threshold,
                    edge_mask_bits=bits,
                    rigor_multiplier=rigor_multiplier,
                )
                self._rust_requests += 1
                self._rust_wave_requests += 1
                if int(reply.get("full_scan_counter", -1)) != 0:
                    raise RuntimeError("Rust full scan counter is non-zero")
                for key, value in dict(reply.get("stats", {})).items():
                    aggregate[key] = int(aggregate.get(key, 0)) + int(value)
                for row in reply.get("wave", []):
                    node_id = int(row["node_id"])
                    candidate = {
                        "node_id": node_id,
                        "energy_score": float(row["energy_score"]),
                        "best_path_len": int(row["best_path_len"]),
                        "path_edge_type_ids": [int(v) for v in row["path_edge_type_ids"]],
                        "record_id": int(row["record_id"]),
                    }
                    previous = best_by_node.get(node_id)
                    if previous is None or (
                        candidate["energy_score"],
                        -candidate["best_path_len"],
                        -candidate["node_id"],
                    ) > (
                        previous["energy_score"],
                        -previous["best_path_len"],
                        -previous["node_id"],
                    ):
                        best_by_node[node_id] = candidate
            ordered = sorted(
                best_by_node.values(),
                key=lambda row: (-float(row["energy_score"]), int(row["best_path_len"]), int(row["node_id"])),
            )[: int(top_k)]
            results = []
            for row in ordered:
                path_ids = list(row["path_edge_type_ids"])
                results.append({
                    **dict(row),
                    "path_edge_types": [EdgeType(v).name for v in path_ids],
                })
            return {
                "api_version": VERSION,
                "backend": "RUST_NATIVE",
                "seed_nodes": list(seeds),
                "edge_mask": [v.name for v in mask],
                "result_count": len(results),
                "results": results,
                "stats": aggregate,
            }
        except Exception:
            self._rust_failures += 1
            return self._fallback_wave(
                seeds,
                edge_mask=mask,
                energy_threshold=energy_threshold,
                top_k=top_k,
                max_steps=max_steps,
                rigor_multiplier=rigor_multiplier,
            )

    def get_edges(
        self,
        node_id: int,
        *,
        direction: str = "out",
        edge_types: Sequence[EdgeType | int | str] | None = None,
        limit: int = 1000,
    ) -> Mapping[str, object]:
        if direction != "out" or self.layout_stale or self.rust is None or not self.rust.alive:
            self._python_fallback_requests += 1
            return self.base.get_edges(node_id, direction=direction, edge_types=edge_types, limit=limit)
        allowed = set(parse_edge_mask(edge_types)) if edge_types else None
        try:
            reply = self.rust.get_edges(int(node_id))
            self._rust_requests += 1
            self._rust_get_edges_requests += 1
            if int(reply.get("full_scan_counter", -1)) != 0:
                raise RuntimeError("Rust full scan counter is non-zero")
            rows = []
            for edge in reply.get("edges", []):
                edge_type = EdgeType(int(edge["edge_type"]))
                if allowed is not None and edge_type not in allowed:
                    continue
                rows.append({
                    "src": int(edge["src"]),
                    "dst": int(edge["dst"]),
                    "edge_type": edge_type.name,
                    "edge_type_id": int(edge_type),
                    "weight": float(edge["weight"]),
                    "source_layer": "L2_RUST_CSR_DERIVED",
                })
            rows.sort(key=lambda row: (row["src"], row["dst"], row["edge_type_id"], row["weight"]))
            rows = rows[: int(limit)]
            return {
                "api_version": VERSION,
                "backend": "RUST_NATIVE",
                "node_id": int(node_id),
                "direction": "out",
                "edge_count": len(rows),
                "edges": rows,
            }
        except Exception:
            self._rust_failures += 1
            self._python_fallback_requests += 1
            return self.base.get_edges(node_id, direction=direction, edge_types=edge_types, limit=limit)
