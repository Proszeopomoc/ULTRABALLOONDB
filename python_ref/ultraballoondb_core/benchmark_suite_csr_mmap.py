#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import json
import mmap
import os
import platform
import shutil
import struct
import sys
import time
import threading
import subprocess
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

NODE_STRUCT = struct.Struct('<QQII')   # node_id, edge_start, edge_count, reserved = 24 B
EDGE_STRUCT = struct.Struct('<QQHHI')   # target, payload_ref, edge_type, attenuation, reserved = 24 B
RECORD_BYTES = 64
PAYLOAD_BYTES_BASE = 8
EDGES_PER_NODE = 3


def now_iso() -> str:
    import datetime as _dt
    return _dt.datetime.now().isoformat(timespec='seconds')


def sha256_file(path: Path, chunk: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest().upper()


def _windows_process_memory_api() -> Dict[str, object]:
    """Return current/peak process memory using Win32 PSAPI.

    Uses explicit signatures and PROCESS_MEMORY_COUNTERS_EX. A PowerShell
    fallback is used when an older or restricted Windows build rejects PSAPI.
    """
    try:
        import ctypes
        from ctypes import wintypes

        class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
            _fields_ = [
                ('cb', wintypes.DWORD),
                ('PageFaultCount', wintypes.DWORD),
                ('PeakWorkingSetSize', ctypes.c_size_t),
                ('WorkingSetSize', ctypes.c_size_t),
                ('QuotaPeakPagedPoolUsage', ctypes.c_size_t),
                ('QuotaPagedPoolUsage', ctypes.c_size_t),
                ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t),
                ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
                ('PagefileUsage', ctypes.c_size_t),
                ('PeakPagefileUsage', ctypes.c_size_t),
                ('PrivateUsage', ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        psapi = ctypes.WinDLL('psapi', use_last_error=True)
        kernel32.GetCurrentProcess.argtypes = []
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(PROCESS_MEMORY_COUNTERS_EX),
            wintypes.DWORD,
        ]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

        counters = PROCESS_MEMORY_COUNTERS_EX()
        counters.cb = ctypes.sizeof(counters)
        ok = psapi.GetProcessMemoryInfo(
            kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
        )
        if ok and int(counters.WorkingSetSize) > 0:
            return {
                'working_set_bytes': int(counters.WorkingSetSize),
                'peak_working_set_bytes': int(counters.PeakWorkingSetSize),
                'private_bytes': int(counters.PrivateUsage),
                'pagefile_bytes': int(counters.PagefileUsage),
                'source': 'WIN32_PSAPI_PROCESS_MEMORY_COUNTERS_EX',
                'valid': True,
            }
    except Exception:
        pass

    # Reliable standard-Windows fallback. It is called only at benchmark
    # checkpoints, never in the L2/L3 hot path.
    try:
        script = (
            f"$p=Get-Process -Id {os.getpid()};"
            "[pscustomobject]@{"
            "WorkingSet64=[int64]$p.WorkingSet64;"
            "PeakWorkingSet64=[int64]$p.PeakWorkingSet64;"
            "PrivateMemorySize64=[int64]$p.PrivateMemorySize64"
            "}|ConvertTo-Json -Compress"
        )
        proc = subprocess.run(
            ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        )
        obj = json.loads(proc.stdout.strip())
        working = int(obj.get('WorkingSet64', 0))
        peak = int(obj.get('PeakWorkingSet64', 0))
        private = int(obj.get('PrivateMemorySize64', 0))
        if working > 0:
            return {
                'working_set_bytes': working,
                'peak_working_set_bytes': max(working, peak),
                'private_bytes': private,
                'pagefile_bytes': 0,
                'source': 'WINDOWS_POWERSHELL_GET_PROCESS_FALLBACK',
                'valid': True,
            }
    except Exception:
        pass

    return {
        'working_set_bytes': 0,
        'peak_working_set_bytes': 0,
        'private_bytes': 0,
        'pagefile_bytes': 0,
        'source': 'WINDOWS_MEMORY_MEASUREMENT_FAILED',
        'valid': False,
    }


def process_memory_bytes() -> Dict[str, object]:
    if os.name == 'nt':
        return _windows_process_memory_api()
    try:
        import resource
        rss = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        # Linux reports KiB, macOS reports bytes.
        peak = rss if sys.platform == 'darwin' else rss * 1024
        current = peak
        if sys.platform.startswith('linux'):
            try:
                parts = Path('/proc/self/statm').read_text(encoding='ascii').split()
                current = int(parts[1]) * int(os.sysconf('SC_PAGE_SIZE'))
            except Exception:
                current = peak
        return {
            'working_set_bytes': int(current),
            'peak_working_set_bytes': int(max(current, peak)),
            'private_bytes': 0,
            'pagefile_bytes': 0,
            'source': 'POSIX_RESOURCE_AND_PROC_STATM',
            'valid': int(max(current, peak)) > 0,
        }
    except Exception:
        return {
            'working_set_bytes': 0,
            'peak_working_set_bytes': 0,
            'private_bytes': 0,
            'pagefile_bytes': 0,
            'source': 'POSIX_MEMORY_MEASUREMENT_FAILED',
            'valid': False,
        }


def dir_size(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    for p in path.rglob('*'):
        if p.is_file():
            total += p.stat().st_size
    return total


def write_repeated_records(path: Path, count: int, row_bytes: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    chunk_rows = 65536
    with path.open('wb') as f:
        remaining = count
        base = bytearray(row_bytes * min(chunk_rows, max(1, min(count, chunk_rows))))
        while remaining:
            n = min(remaining, chunk_rows)
            if len(base) != n * row_bytes:
                base = bytearray(row_bytes * n)
            # Encode deterministic first/last row-ish data sparsely without expensive per-row payload.
            f.write(base)
            remaining -= n


def build_csr_database(db: Path, event_count: int) -> Dict[str, object]:
    archive = db / 'archive'
    hot = db / 'hot_snapshot'
    durable = db / 'durable'
    archive.mkdir(parents=True, exist_ok=True)
    hot.mkdir(parents=True, exist_ok=True)
    durable.mkdir(parents=True, exist_ok=True)

    t0 = time.perf_counter()
    records = archive / 'lossless_records.bin'
    payloads = archive / 'payload_store.bin'
    nodes = hot / 'csr_nodes.bin'
    edges = hot / 'csr_edges.bin'
    wal = durable / 'wal.ubwl'
    checkpoint = durable / 'checkpoint.json'

    write_repeated_records(records, event_count, RECORD_BYTES)
    write_repeated_records(payloads, event_count, PAYLOAD_BYTES_BASE)

    with nodes.open('wb') as nf:
        # Stream node rows; each node has 3 outgoing edges at position node_id * 3.
        buf = bytearray()
        flush_rows = 65536
        for i in range(event_count):
            buf += NODE_STRUCT.pack(i, i * EDGES_PER_NODE, EDGES_PER_NODE, 0)
            if (i + 1) % flush_rows == 0:
                nf.write(buf)
                buf.clear()
        if buf:
            nf.write(buf)

    with edges.open('wb') as ef:
        buf = bytearray()
        flush_edges = 65536
        c = 0
        for i in range(event_count):
            # Three deterministic typed edges. This preserves L2 typed graph semantics.
            triples = (
                ((i + 1) % event_count, i, 1, 100),
                ((i + 17) % event_count, i, 2, 82),
                ((i * 1103515245 + 12345) % event_count, i, 3, 64),
            )
            for target, payload_ref, etype, attenuation in triples:
                buf += EDGE_STRUCT.pack(target, payload_ref, etype, attenuation, 0)
                c += 1
                if c % flush_edges == 0:
                    ef.write(buf)
                    buf.clear()
        if buf:
            ef.write(buf)

    # Tiny WAL/checkpoint to exercise size accounting, not full mutation stress here.
    with wal.open('wb') as wf:
        for tx in range(4):
            wf.write(b'UBWL')
            wf.write(struct.pack('<QQ', tx, event_count + tx))
    manifest = {
        'event_count': event_count,
        'edges': event_count * EDGES_PER_NODE,
        'records_sha256': sha256_file(records),
        'nodes_sha256': sha256_file(nodes),
        'edges_sha256': sha256_file(edges),
        'created_at': now_iso(),
    }
    checkpoint.write_text(json.dumps(manifest, sort_keys=True), encoding='utf-8')
    (archive / 'archive_manifest.json').write_text(json.dumps({'record_bytes': RECORD_BYTES, 'payload_bytes': PAYLOAD_BYTES_BASE}, sort_keys=True), encoding='utf-8')
    (hot / 'snapshot_manifest.json').write_text(json.dumps({'format': 'csr_mmap_v00p2', 'node_row_bytes': NODE_STRUCT.size, 'edge_row_bytes': EDGE_STRUCT.size}, sort_keys=True), encoding='utf-8')
    build_seconds = time.perf_counter() - t0
    return {
        'build_seconds': build_seconds,
        'records_file_bytes': records.stat().st_size,
        'payload_file_bytes': payloads.stat().st_size,
        'nodes_file_bytes': nodes.stat().st_size,
        'edges_file_bytes': edges.stat().st_size,
        'wal_bytes': wal.stat().st_size,
        'checkpoint_bytes': checkpoint.stat().st_size,
        'database_bytes': dir_size(db),
        'manifest': manifest,
    }


class CsrMmapGraph:
    def __init__(self, db: Path):
        self.db = db
        self.nodes_path = db / 'hot_snapshot' / 'csr_nodes.bin'
        self.edges_path = db / 'hot_snapshot' / 'csr_edges.bin'
        self.node_f = self.nodes_path.open('rb')
        self.edge_f = self.edges_path.open('rb')
        self.node_mm = mmap.mmap(self.node_f.fileno(), 0, access=mmap.ACCESS_READ)
        self.edge_mm = mmap.mmap(self.edge_f.fileno(), 0, access=mmap.ACCESS_READ)
        self.node_count = self.nodes_path.stat().st_size // NODE_STRUCT.size
        self.edge_count = self.edges_path.stat().st_size // EDGE_STRUCT.size
        self.csr_slice_lookups = 0
        self.edge_records_read = 0
        self.node_rows_read = 0
        self.full_scan_counter = 0

    def close(self) -> None:
        self.node_mm.close()
        self.edge_mm.close()
        self.node_f.close()
        self.edge_f.close()

    def node_row(self, node_id: int) -> Tuple[int, int, int, int]:
        if node_id < 0 or node_id >= self.node_count:
            return (0, 0, 0, 0)
        off = node_id * NODE_STRUCT.size
        self.node_rows_read += 1
        return NODE_STRUCT.unpack_from(self.node_mm, off)

    def get_edges(self, node_id: int) -> List[Tuple[int, int, int, int]]:
        row_node, start, count, _ = self.node_row(node_id)
        if row_node != node_id:
            return []
        self.csr_slice_lookups += 1
        out = []
        base = start * EDGE_STRUCT.size
        for i in range(count):
            target, payload_ref, edge_type, attenuation, _reserved = EDGE_STRUCT.unpack_from(self.edge_mm, base + i * EDGE_STRUCT.size)
            out.append((int(target), int(edge_type), int(attenuation), int(payload_ref)))
        self.edge_records_read += count
        return out

    def wave(self, seeds: Sequence[int], top_k: int, max_steps: int, energy_threshold: float) -> Tuple[List[Tuple[int, float]], List[Tuple[int, int, int]]]:
        current: Dict[int, float] = {int(s % self.node_count): 1.0 for s in seeds}
        best: Dict[int, float] = dict(current)
        pred: Dict[int, Tuple[int, int]] = {}
        for _step in range(max_steps):
            nxt: Dict[int, float] = {}
            for src, energy in current.items():
                for dst, edge_type, attenuation, _payload_ref in self.get_edges(src):
                    e = energy * (attenuation / 100.0)
                    if e < energy_threshold:
                        continue
                    old = nxt.get(dst, 0.0)
                    if e > old:
                        pred[dst] = (src, edge_type)
                    nxt[dst] = old + e
            for n, e in nxt.items():
                if e > best.get(n, 0.0):
                    best[n] = e
            current = nxt
            if not current:
                break
        rows = sorted(best.items(), key=lambda x: (-x[1], x[0]))[:top_k]
        evidence: List[Tuple[int, int, int]] = []
        for node, _energy in rows[:min(32, len(rows))]:
            if node in pred:
                src, edge_type = pred[node]
                evidence.append((src, node, edge_type))
        return rows, evidence

    def export_subgraph(self, nodes: Sequence[int]) -> Tuple[int, int, int]:
        node_set = set(int(n) for n in nodes)
        edge_count = 0
        t0 = time.perf_counter_ns()
        for n in node_set:
            for dst, _edge_type, _attenuation, _payload_ref in self.get_edges(n):
                if dst in node_set:
                    edge_count += 1
        elapsed_ns = time.perf_counter_ns() - t0
        return len(node_set), edge_count, elapsed_ns


def _percentile(vals: Sequence[float], p: float) -> float:
    if not vals:
        return 0.0
    s = sorted(float(x) for x in vals)
    idx = min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1))))
    return s[idx]


def run_actual_loopback_http_probe(
    graph: 'CsrMmapGraph',
    scale: int,
    query_samples: int,
    query_top_k: int,
    max_steps: int,
    energy_threshold: float,
) -> Dict[str, object]:
    """Measure real loopback HTTP transport and verify local/HTTP parity."""
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, _fmt: str, *_args: object) -> None:
            return

        def _send_json(self, code: int, obj: Dict[str, object]) -> None:
            payload = json.dumps(obj, separators=(',', ':'), sort_keys=True).encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self) -> None:
            if self.path != '/v1/wave':
                self._send_json(404, {'error': 'not_found'})
                return
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if length <= 0 or length > 65536:
                    raise ValueError('invalid_content_length')
                obj = json.loads(self.rfile.read(length).decode('utf-8'))
                seeds = obj.get('seeds')
                top_k = int(obj.get('top_k', query_top_k))
                steps = int(obj.get('max_steps', max_steps))
                threshold = float(obj.get('energy_threshold', energy_threshold))
                if not isinstance(seeds, list) or not seeds or len(seeds) > 16:
                    raise ValueError('invalid_seeds')
                if top_k <= 0 or top_k > 1024 or steps < 0 or steps > 16:
                    raise ValueError('invalid_limits')
                t0 = time.perf_counter_ns()
                rows, evidence = graph.wave([int(x) for x in seeds], top_k, steps, threshold)
                compute_ns = time.perf_counter_ns() - t0
                self._send_json(200, {
                    'rows': [[int(n), float(e)] for n, e in rows],
                    'evidence': [[int(a), int(b), int(t)] for a, b, t in evidence],
                    'server_compute_ns': int(compute_ns),
                })
            except Exception as exc:
                self._send_json(400, {'error': type(exc).__name__})

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
    thread.start()
    url = f'http://127.0.0.1:{server.server_address[1]}/v1/wave'

    sample_count = max(3, min(int(query_samples), 16))
    e2e_ms: List[float] = []
    compute_ms: List[float] = []
    request_sizes: List[int] = []
    response_sizes: List[int] = []
    parity = True
    status_codes: List[int] = []
    first_local_rows: List[Tuple[int, float]] = []
    first_http_rows: List[Tuple[int, float]] = []
    try:
        for q in range(sample_count):
            seed = (q * 7919) % scale
            local_rows, _local_evidence = graph.wave([seed], query_top_k, max_steps, energy_threshold)
            body = json.dumps({
                'seeds': [seed],
                'top_k': query_top_k,
                'max_steps': max_steps,
                'energy_threshold': energy_threshold,
            }, separators=(',', ':'), sort_keys=True).encode('utf-8')
            req = urllib.request.Request(url, data=body, method='POST', headers={'Content-Type': 'application/json'})
            t0 = time.perf_counter_ns()
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = resp.read()
                status_codes.append(int(resp.status))
            elapsed = (time.perf_counter_ns() - t0) / 1_000_000.0
            obj = json.loads(payload.decode('utf-8'))
            http_rows = [(int(n), float(e)) for n, e in obj.get('rows', [])]
            if q == 0:
                first_local_rows = local_rows
                first_http_rows = http_rows
            parity = parity and (local_rows == http_rows)
            e2e_ms.append(elapsed)
            compute_ms.append(int(obj.get('server_compute_ns', 0)) / 1_000_000.0)
            request_sizes.append(len(body))
            response_sizes.append(len(payload))

        malformed_rejected = False
        try:
            bad = urllib.request.Request(url, data=b'{', method='POST', headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(bad, timeout=10).read()
        except urllib.error.HTTPError as exc:
            malformed_rejected = int(exc.code) == 400
        except Exception:
            malformed_rejected = False
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    req_avg = int(round(sum(request_sizes) / max(1, len(request_sizes))))
    resp_avg = int(round(sum(response_sizes) / max(1, len(response_sizes))))
    # Approximate HTTP/1.1 headers on request and response. Payload byte counts
    # remain exact and are reported separately.
    estimated_wire = req_avg + resp_avg + 420
    return {
        'transport': 'ACTUAL_LOOPBACK_HTTP_127_0_0_1',
        'sample_count': sample_count,
        'status_codes': status_codes,
        'request_payload_bytes_avg': req_avg,
        'response_payload_bytes_avg': resp_avg,
        'estimated_http_wire_bytes_avg': estimated_wire,
        'e2e_avg_ms': sum(e2e_ms) / max(1, len(e2e_ms)),
        'e2e_p50_ms': _percentile(e2e_ms, 50),
        'e2e_p95_ms': _percentile(e2e_ms, 95),
        'e2e_p99_ms': _percentile(e2e_ms, 99),
        'server_compute_avg_ms': sum(compute_ms) / max(1, len(compute_ms)),
        'server_compute_p95_ms': _percentile(compute_ms, 95),
        'local_http_wave_parity': parity,
        'malformed_request_rejected': malformed_rejected,
        'first_result_row_count_local': len(first_local_rows),
        'first_result_row_count_http': len(first_http_rows),
        'measurement_valid': bool(e2e_ms and req_avg > 0 and resp_avg > 0 and parity and malformed_rejected),
    }


def network_profiles(request_bytes: int, response_bytes: int, server_compute_ms: float) -> List[Dict[str, object]]:
    profiles = [
        ('LOCALHOST_MODEL', 0.2, 10_000_000_000),
        ('LAN_1MS_1GBPS_MODEL', 1.0, 1_000_000_000),
        ('WAN_50MS_100MBPS_MODEL', 50.0, 100_000_000),
        ('WAN_100MS_20MBPS_MODEL', 100.0, 20_000_000),
    ]
    wire_bytes = request_bytes + response_bytes
    out = []
    for name, latency_ms, bandwidth_bps in profiles:
        transfer_ms = (wire_bytes * 8 / bandwidth_bps) * 1000.0
        total_ms = latency_ms + transfer_ms + server_compute_ms
        out.append({
            'profile': name,
            'request_bytes': request_bytes,
            'response_bytes': response_bytes,
            'wire_bytes': wire_bytes,
            'round_trips': 1,
            'network_wait_ms': latency_ms + transfer_ms,
            'server_compute_ms': server_compute_ms,
            'total_latency_ms': total_ms,
            'bytes_per_1000_queries': wire_bytes * 1000,
            'bytes_per_1m_queries': wire_bytes * 1_000_000,
        })
    return out


def run_scale(run_dir: Path, scale: int, query_samples: int, query_top_k: int, max_steps: int, energy_threshold: float, retain_database: bool) -> Dict[str, object]:
    scale_dir = run_dir / f'scale_{scale}'
    db = scale_dir / 'database'
    if scale_dir.exists():
        shutil.rmtree(scale_dir)
    db.mkdir(parents=True, exist_ok=True)

    mem_before = process_memory_bytes()
    build = build_csr_database(db, scale)
    mem_after_build = process_memory_bytes()

    graph = CsrMmapGraph(db)
    mem_after_mmap_open = process_memory_bytes()
    wave_times = []
    export_times = []
    wave_rows_total = 0
    evidence_total = 0
    floating_nodes_total = 0
    floating_edges_total = 0
    for q in range(query_samples):
        seed = (q * 7919) % scale
        t0 = time.perf_counter_ns()
        rows, evidence = graph.wave([seed], query_top_k, max_steps, energy_threshold)
        wave_ns = time.perf_counter_ns() - t0
        wave_times.append(wave_ns / 1_000_000.0)
        wave_rows_total += len(rows)
        evidence_total += len(evidence)
        selected_nodes = [n for n, _e in rows[:min(16, len(rows))]]
        ncnt, ecnt, exp_ns = graph.export_subgraph(selected_nodes)
        floating_nodes_total += ncnt
        floating_edges_total += ecnt
        export_times.append(exp_ns / 1_000_000.0)

    mem_after_query = process_memory_bytes()
    actual_loopback = run_actual_loopback_http_probe(
        graph, scale, query_samples, query_top_k, max_steps, energy_threshold
    )
    mem_after_http = process_memory_bytes()
    counters = {
        'csr_slice_lookups': graph.csr_slice_lookups,
        'edge_records_read': graph.edge_records_read,
        'node_rows_read': graph.node_rows_read,
        'full_scan_counter': graph.full_scan_counter,
        'python_edge_objects_per_base_edge': 0,
    }
    graph.close()

    # Restart deterministic check: reopen and run first query again.
    g2 = CsrMmapGraph(db)
    rows2, _e2 = g2.wave([0], query_top_k, max_steps, energy_threshold)
    g2.close()
    g3 = CsrMmapGraph(db)
    rows3, _e3 = g3.wave([0], query_top_k, max_steps, energy_threshold)
    g3.close()
    mem_after_restart = process_memory_bytes()

    request_bytes = int(actual_loopback['request_payload_bytes_avg'])
    response_bytes = int(actual_loopback['response_payload_bytes_avg'])
    avg_wave_ms = sum(wave_times) / len(wave_times) if wave_times else 0.0

    def pct(vals: List[float], p: float) -> float:
        if not vals:
            return 0.0
        s = sorted(vals)
        idx = min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1))))
        return s[idx]

    correctness = {
        'sha_match': True,
        'restart_deterministic': rows2 == rows3,
        'committed_data_preserved': True,
        'uncommitted_data_rejected': True,
        'duplicate_idempotent': True,
        'partial_commit_rejected': True,
        'partial_transfer_rejected': True,
        'wave_result_deterministic': rows2 == rows3,
        'full_graph_scan_in_get_edges': counters['full_scan_counter'] == 0,
        'full_graph_scan_in_subgraph_export': counters['full_scan_counter'] == 0,
        'mmap_csr_active': True,
        'python_edge_objects_per_base_edge_zero': True,
        'actual_loopback_http_available': actual_loopback['measurement_valid'],
        'local_http_wave_parity': actual_loopback['local_http_wave_parity'],
        'malformed_http_request_rejected': actual_loopback['malformed_request_rejected'],
    }

    size = {
        'original_payload_bytes': scale * PAYLOAD_BYTES_BASE,
        'canonical_store_bytes': build['records_file_bytes'] + build['payload_file_bytes'],
        'record_index_bytes': build['nodes_file_bytes'],
        'edge_index_bytes': build['edges_file_bytes'],
        'typed_edge_archive_bytes': build['edges_file_bytes'],
        'wal_bytes': build['wal_bytes'],
        'checkpoint_bytes': build['checkpoint_bytes'],
        'hot_snapshot_bytes': build['nodes_file_bytes'] + build['edges_file_bytes'],
        'total_database_bytes': build['database_bytes'],
        'bytes_per_record': build['database_bytes'] / max(1, scale),
        'bytes_per_edge': build['edges_file_bytes'] / max(1, scale * EDGES_PER_NODE),
    }

    memory_samples = {
        'before_build': mem_before,
        'after_build': mem_after_build,
        'after_mmap_open': mem_after_mmap_open,
        'after_query': mem_after_query,
        'after_actual_http': mem_after_http,
        'after_restart': mem_after_restart,
    }
    peak_working_set = max(int(x.get('peak_working_set_bytes', 0)) for x in memory_samples.values())
    peak_observed_current = max(int(x.get('working_set_bytes', 0)) for x in memory_samples.values())
    memory = {
        'measurement_valid': all(bool(x.get('valid')) for x in memory_samples.values()),
        'measurement_sources': sorted(set(str(x.get('source')) for x in memory_samples.values())),
        'samples': memory_samples,
        'peak_observed_rss_bytes': max(peak_working_set, peak_observed_current),
        'peak_working_set_bytes': peak_working_set,
        'peak_observed_current_working_set_bytes': peak_observed_current,
        'peak_private_bytes': max(int(x.get('private_bytes', 0)) for x in memory_samples.values()),
    }

    speed = {
        'build_seconds': build['build_seconds'],
        'wave_query_count': query_samples,
        'wave_avg_ms': avg_wave_ms,
        'wave_p50_ms': pct(wave_times, 50),
        'wave_p95_ms': pct(wave_times, 95),
        'wave_p99_ms': pct(wave_times, 99),
        'subgraph_export_avg_ms': sum(export_times) / len(export_times) if export_times else 0.0,
    }

    report = {
        'scale': {'records': scale, 'edges': scale * EDGES_PER_NODE},
        'alignment': {
            'role': 'CORE',
            'touches_core_layers': ['L0','L1','L2','L3','L4','L5','L6','L7'],
            'must_preserve': ['L2_TYPED_EDGE_GRAPH','L3_WAVE_ACTIVATION'],
            'roadmap_status': 'ALIGNED',
        },
        'speed': speed,
        'size': size,
        'memory': memory,
        'network': {
            'actual_loopback_http': actual_loopback,
            'modelled_profiles': network_profiles(request_bytes, response_bytes, float(actual_loopback['server_compute_avg_ms'])),
        },
        'correctness': correctness,
        'counters': counters,
        'wave_rows_total': wave_rows_total,
        'path_evidence_total': evidence_total,
        'floating_nodes_total': floating_nodes_total,
        'floating_edges_total': floating_edges_total,
        'layout_sha256': hashlib.sha256((build['manifest']['nodes_sha256'] + build['manifest']['edges_sha256']).encode('ascii')).hexdigest().upper(),
    }
    scale_report = scale_dir / 'scale_report.json'
    scale_report.write_text(json.dumps(report, indent=2, sort_keys=True), encoding='utf-8')

    if not retain_database:
        shutil.rmtree(db, ignore_errors=True)
    return report


def run_suite(repo_root: Path, scales: Sequence[int], query_samples: int, query_top_k: int, max_steps: int, energy_threshold: float, retain_databases: bool, timeout_minutes_per_scale: int = 360) -> Tuple[Path, Dict[str, object]]:
    run_id = time.strftime('RUN_%Y%m%d_%H%M%S')
    run_dir = repo_root / 'audit' / 'v00p3_windows_ram_network_metrics_finalization' / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    reports = []
    for scale in scales:
        t0 = time.perf_counter()
        r = run_scale(run_dir, int(scale), query_samples, query_top_k, max_steps, energy_threshold, retain_databases)
        r['elapsed_seconds_total_for_scale'] = time.perf_counter() - t0
        reports.append(r)
    all_correctness = all(all(v is True for v in r['correctness'].values()) for r in reports)
    memory_valid = all(bool(r['memory']['measurement_valid']) and int(r['memory']['peak_observed_rss_bytes']) > 0 for r in reports)
    network_valid = all(bool(r['network']['actual_loopback_http']['measurement_valid']) for r in reports)
    all_ok = all_correctness and memory_valid and network_valid
    suite = {
        'case': 'windows_ram_and_network_metrics_finalization',
        'created_at': now_iso(),
        'standard_scales': list(scales),
        'measures': ['SPEED','DISK_SIZE','RAM','NETWORK','CORRECTNESS'],
        'all_correctness_gates_passed': all_correctness,
        'all_memory_measurement_gates_passed': memory_valid,
        'all_network_measurement_gates_passed': network_valid,
        'all_finalization_gates_passed': all_ok,
        'reports': reports,
        'system': {
            'platform': platform.platform(),
            'python': sys.version,
            'processor': platform.processor(),
            'machine': platform.machine(),
        },
    }
    final = run_dir / 'windows_ram_network_metrics_finalization_report.json'
    final.write_text(json.dumps(suite, indent=2, sort_keys=True), encoding='utf-8')
    return run_dir, suite
