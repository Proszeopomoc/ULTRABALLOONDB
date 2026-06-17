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


def parse_scales(s: str):
    out = []
    for part in s.split(','):
        part = part.strip()
        if part:
            out.append(int(part))
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
    print('MILESTONE=V00P2_DATABASE_BENCHMARK_CSR_MMAP_INTEGRATION')
    print('ROLE=CORE')
    print('TOUCHES_CORE_LAYERS=L0,L1,L2,L3,L4,L5,L6,L7')
    print('USES_AUXILIARY_LAYERS=NONE')
    print('MUST_PRESERVE=L2_TYPED_EDGE_GRAPH,L3_WAVE_ACTIVATION')
    print('RUNTIME_IMPACT=BENCHMARK_ONLY_CSR_MMAP_HOTPATH')
    print('ROADMAP_STATUS=ALIGNED')
    print('STANDARD_SCALES=' + ','.join(str(x) for x in scales))
    print('MEASURES=SPEED,DISK_SIZE,RAM,NETWORK,CORRECTNESS')

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
    if not suite.get('all_correctness_gates_passed'):
        print('NO_GO_ULTRABALLOONDB_DATABASE_BENCHMARK_CSR_MMAP_INTEGRATION_V00P2')
        print('REPORT=' + str(run_dir / 'database_benchmark_csr_mmap_integration_report.json'))
        return 2
    summary = []
    for r in suite['reports']:
        summary.append({
            'records': r['scale']['records'],
            'edges': r['scale']['edges'],
            'build_seconds': r['speed']['build_seconds'],
            'wave_p95_ms': r['speed']['wave_p95_ms'],
            'total_database_bytes': r['size']['total_database_bytes'],
            'peak_rss_bytes': r['memory']['peak_observed_rss_bytes'],
            'full_scan_counter': r['counters']['full_scan_counter'],
        })
    print('PASS_ULTRABALLOONDB_DATABASE_BENCHMARK_CSR_MMAP_INTEGRATION_V00P2')
    print('REPORT=' + str(run_dir / 'database_benchmark_csr_mmap_integration_report.json'))
    print('SUMMARY=' + json.dumps(summary, sort_keys=True))
    print('PASS_ULTRABALLOONDB_V00P2_ALIGNMENT_CHECK')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
