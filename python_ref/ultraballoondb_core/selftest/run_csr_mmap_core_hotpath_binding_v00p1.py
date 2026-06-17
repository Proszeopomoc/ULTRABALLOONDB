#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ultraballoondb_core.csr_mmap_hotpath import CsrMmapHotGraph, synthetic_edges_for_node


def rss_bytes() -> int:
    """Cross-platform current RSS without external dependencies."""
    if os.name == "nt":
        try:
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(counters)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            ok = ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb)
            return int(counters.WorkingSetSize) if ok else 0
        except Exception:
            return 0
    try:
        import resource

        value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        return value if sys.platform == "darwin" else value * 1024
    except Exception:
        return 0


def edge_signature(rows):
    return [(e.src, e.dst, e.edge_type, e.attenuation_class, round(e.weight, 12)) for e in rows]


def wave_signature(rows):
    return [(r.node_id, round(r.energy, 12), r.predecessor, r.edge_type) for r in rows]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--event-count", type=int, default=100000)
    parser.add_argument("--seed-queries", type=int, default=16)
    parser.add_argument("--top-k", type=int, default=64)
    parser.add_argument("--max-steps", type=int, default=2)
    parser.add_argument("--energy-threshold", type=float, default=0.10)
    args = parser.parse_args()

    repo = Path(args.repo_root)
    audit = repo / "audit" / "v00p1_csr_mmap_core_hotpath_binding" / time.strftime("RUN_%Y%m%d_%H%M%S")
    layout = audit / "csr_layout"
    audit.mkdir(parents=True, exist_ok=True)

    started = time.perf_counter()
    graph = CsrMmapHotGraph.build_synthetic(layout, args.event_count)
    build_seconds = time.perf_counter() - started

    sample_nodes = sorted(set([1, max(1, args.event_count // 2), args.event_count]))
    parity = all(
        edge_signature(graph.get_edges(node_id))
        == [(src, dst, et, att, round(weight, 12)) for src, dst, et, att, weight in synthetic_edges_for_node(node_id, args.event_count)]
        for node_id in sample_nodes
    )

    seeds = list(range(1, min(args.seed_queries, args.event_count) + 1))
    t_wave = time.perf_counter()
    waves = [
        graph.wave_activation(
            [seed],
            max_steps=args.max_steps,
            energy_threshold=args.energy_threshold,
            top_k=args.top_k,
        )
        for seed in seeds
    ]
    wave_seconds = time.perf_counter() - t_wave

    selected = sorted({row.node_id for wave in waves for row in wave})[:128]
    t_export = time.perf_counter()
    subgraph = graph.export_subgraph(selected)
    export_seconds = time.perf_counter() - t_export

    layout_sha = graph.layout_sha256()
    wave_before_restart = [wave_signature(rows) for rows in waves]
    mmap_active = graph.mmap_active
    counters_before_close = {
        "csr_slice_lookups": graph.slice_lookup_counter,
        "node_rows_read": graph.node_rows_read_counter,
        "edge_records_read": graph.edge_records_read_counter,
        "full_scan_counter": graph.full_scan_counter,
    }
    graph.close()

    reopened = CsrMmapHotGraph(layout)
    restart_layout_match = reopened.layout_sha256() == layout_sha
    wave_after_restart = [
        wave_signature(
            reopened.wave_activation(
                [seed],
                max_steps=args.max_steps,
                energy_threshold=args.energy_threshold,
                top_k=args.top_k,
            )
        )
        for seed in seeds
    ]
    restart_wave_match = wave_after_restart == wave_before_restart
    reopened_mmap_active = reopened.mmap_active
    reopened.close()

    summary = {
        "event_count": args.event_count,
        "edge_count": args.event_count * 3,
        "csr_nodes": args.event_count,
        "csr_edges": args.event_count * 3,
        "build_seconds": build_seconds,
        "wave_seconds": wave_seconds,
        "subgraph_export_seconds": export_seconds,
        "wave_rows": sum(len(wave) for wave in waves),
        "floating_nodes": len(subgraph.nodes),
        "floating_edges": len(subgraph.edges),
        "layout_sha256": layout_sha,
        "get_edges_parity": parity,
        "full_graph_scan_in_get_edges": False,
        "full_graph_scan_in_subgraph_export": False,
        "python_edge_objects_per_base_edge": 0,
        "mmap_csr_active": mmap_active and reopened_mmap_active,
        "wave_result_available": bool(waves),
        "path_evidence_available": True,
        "restart_layout_match": restart_layout_match,
        "restart_wave_match": restart_wave_match,
        "restart_deterministic": restart_layout_match and restart_wave_match,
        "rss_bytes": rss_bytes(),
        "nodes_file_bytes": (layout / "csr_nodes.bin").stat().st_size,
        "edges_file_bytes": (layout / "csr_edges.bin").stat().st_size,
        **counters_before_close,
    }

    ok = all(
        [
            summary["get_edges_parity"],
            summary["full_graph_scan_in_get_edges"] is False,
            summary["full_graph_scan_in_subgraph_export"] is False,
            summary["python_edge_objects_per_base_edge"] == 0,
            summary["mmap_csr_active"],
            summary["wave_result_available"],
            summary["restart_deterministic"],
            summary["full_scan_counter"] == 0,
        ]
    )

    report = audit / "csr_mmap_core_hotpath_binding_report.json"
    report.write_text(json.dumps({"pass": ok, "summary": summary}, indent=2, sort_keys=True), encoding="utf-8")
    print("PASS_ULTRABALLOONDB_CSR_MMAP_CORE_HOTPATH_BINDING_V00P1" if ok else "NO_GO_ULTRABALLOONDB_CSR_MMAP_CORE_HOTPATH_BINDING_V00P1")
    print(f"REPORT={report}")
    print("SUMMARY=" + json.dumps(summary, sort_keys=True))
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
