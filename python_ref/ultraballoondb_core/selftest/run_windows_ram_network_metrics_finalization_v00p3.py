#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from python_ref.ultraballoondb_core.benchmark_suite_csr_mmap import run_suite


def parse_scales(text: str):
    out = []
    for part in text.split(','):
        part = part.strip()
        if part:
            out.append(int(part))
    if not out:
        raise ValueError('at least one scale is required')
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo-root', required=True)
    ap.add_argument('--scales', default='10000,100000,1000000,10000000')
    ap.add_argument('--query-samples', type=int, default=32)
    ap.add_argument('--query-top-k', type=int, default=64)
    ap.add_argument('--max-steps', type=int, default=2)
    ap.add_argument('--energy-threshold', type=float, default=0.10)
    ap.add_argument('--retain-databases', action='store_true')
    ap.add_argument('--timeout-minutes-per-scale', type=int, default=360)
    args = ap.parse_args()

    scales = parse_scales(args.scales)
    print('ALIGNMENT_CHECK')
    print('MILESTONE=V00P3_WINDOWS_RAM_AND_NETWORK_METRICS_FINALIZATION')
    print('ROLE=CORE')
    print('TOUCHES_CORE_LAYERS=L0,L1,L2,L3,L4,L5,L6,L7')
    print('USES_AUXILIARY_LAYERS=NONE')
    print('MUST_PRESERVE=L2_TYPED_EDGE_GRAPH,L3_WAVE_ACTIVATION')
    print('RUNTIME_IMPACT=BENCHMARK_METRICS_FINALIZATION_ONLY')
    print('ROADMAP_STATUS=ALIGNED')
    print('STANDARD_SCALES=' + ','.join(str(x) for x in scales))
    print('MEASURES=WINDOWS_WORKING_SET,PEAK_WORKING_SET,PRIVATE_BYTES,ACTUAL_LOOPBACK_HTTP,MODELLED_LAN_WAN,CORRECTNESS')

    run_dir, suite = run_suite(
        repo_root=Path(args.repo_root),
        scales=scales,
        query_samples=args.query_samples,
        query_top_k=args.query_top_k,
        max_steps=args.max_steps,
        energy_threshold=args.energy_threshold,
        retain_databases=args.retain_databases,
        timeout_minutes_per_scale=args.timeout_minutes_per_scale,
    )
    report_path = run_dir / 'windows_ram_network_metrics_finalization_report.json'
    summary = []
    for report in suite['reports']:
        actual = report['network']['actual_loopback_http']
        summary.append({
            'records': report['scale']['records'],
            'edges': report['scale']['edges'],
            'build_seconds': report['speed']['build_seconds'],
            'wave_p95_ms': report['speed']['wave_p95_ms'],
            'peak_rss_bytes': report['memory']['peak_observed_rss_bytes'],
            'peak_private_bytes': report['memory']['peak_private_bytes'],
            'memory_sources': report['memory']['measurement_sources'],
            'http_loopback_p95_ms': actual['e2e_p95_ms'],
            'http_server_compute_p95_ms': actual['server_compute_p95_ms'],
            'http_request_payload_bytes': actual['request_payload_bytes_avg'],
            'http_response_payload_bytes': actual['response_payload_bytes_avg'],
            'http_wire_bytes_estimated': actual['estimated_http_wire_bytes_avg'],
            'local_http_wave_parity': actual['local_http_wave_parity'],
            'malformed_request_rejected': actual['malformed_request_rejected'],
            'full_scan_counter': report['counters']['full_scan_counter'],
        })

    if not suite.get('all_finalization_gates_passed'):
        print('NO_GO_ULTRABALLOONDB_WINDOWS_RAM_NETWORK_METRICS_FINALIZATION_V00P3')
        print('REPORT=' + str(report_path))
        print('SUMMARY=' + json.dumps(summary, sort_keys=True))
        return 2

    print('PASS_ULTRABALLOONDB_WINDOWS_RAM_NETWORK_METRICS_FINALIZATION_V00P3')
    print('REPORT=' + str(report_path))
    print('SUMMARY=' + json.dumps(summary, sort_keys=True))
    print('PASS_ULTRABALLOONDB_V00P3_ALIGNMENT_CHECK')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
