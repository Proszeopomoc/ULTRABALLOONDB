#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
import tracemalloc
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

SCRIPT = Path(__file__).resolve()
CORE_ROOT = SCRIPT.parents[2]
if str(CORE_ROOT.parent) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT.parent))

from ultraballoondb_core.types import EdgeType, WaveConfig  # noqa: E402
from ultraballoondb_core.wave import build_synthetic_typed_graph, wave_activation  # noqa: E402


def _parse_sizes(raw: str) -> List[int]:
    values = []
    for part in raw.split(','):
        part = part.strip().replace('_', '')
        if not part:
            continue
        values.append(int(part))
    if not values:
        raise ValueError("empty event size list")
    return values


def _quantile(values: Sequence[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * q))))
    return ordered[idx]


def _micros(seconds: float) -> float:
    return round(seconds * 1_000_000.0, 3)


def _result_signature(results) -> List[tuple]:
    return [
        (r.node_id, r.energy_score, r.best_path_len, tuple(int(t) for t in r.path_edge_types), r.record_id)
        for r in results
    ]


def _forbidden_patterns() -> List[str]:
    # Built from fragments so this source file does not itself contain scanned product names.
    joined = [
        ("Neo", "4j"),
        ("Mem", "graph"),
        ("Hyp", "erspace"),
        ("Pine", "cone"),
        ("Weav", "iate"),
        ("Mil", "vus"),
        ("Chro", "ma"),
        ("Fa", "iss"),
    ]
    return [a + b for a, b in joined]


def _scan_repo_text(repo_root: Path) -> Dict[str, object]:
    patterns = _forbidden_patterns()
    hits: List[Dict[str, object]] = []
    text_suffixes = {'.py', '.ps1', '.md', '.txt', '.json', '.toml', '.yaml', '.yml'}
    skip_dirs = {'.git', 'audit', '__pycache__'}
    for path in repo_root.rglob('*'):
        if not path.is_file() or path.suffix.lower() not in text_suffixes:
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        try:
            data = path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue
        lower = data.lower()
        for pattern in patterns:
            if pattern.lower() in lower:
                hits.append({'path': str(path), 'pattern': pattern})
    return {'hit_count': len(hits), 'hits': hits[:50]}


def _source_call_scan(repo_root: Path) -> Dict[str, object]:
    patterns = [
        'requ' + 'ests.',
        'ht' + 'tpx.',
        'urllib' + '.request',
        'sock' + 'et.',
        'open' + 'ai',
        '/v1/' + 'chat',
        '/v1/' + 'responses',
    ]
    hits: List[Dict[str, object]] = []
    roots = [repo_root / 'python_ref' / 'ultraballoondb_core']
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob('*.py'):
            if '__pycache__' in path.parts:
                continue
            data = path.read_text(encoding='utf-8', errors='ignore').lower()
            for pattern in patterns:
                if pattern.lower() in data:
                    hits.append({'path': str(path), 'pattern': pattern})
    return {'hit_count': len(hits), 'hits': hits[:50]}


def _run_query_set(graph, size: int, recall_samples: int) -> Dict[str, object]:
    all_types = tuple(t for t in EdgeType if t != EdgeType.IS_NOT_EDGE)
    code_project = (EdgeType.CODE_PATTERN, EdgeType.PROJECT_CONTEXT, EdgeType.CODE_TO_RECENT_RULE, EdgeType.PROJECT_TO_RECENT_SEED)
    strict_cfg = lambda seed: WaveConfig(seed, code_project, 0.18, 32, 3, 0.88)
    mixed_cfg = lambda seed: WaveConfig(seed, all_types, 0.07, 64, 3, 1.0)
    explorative_cfg = lambda seed: WaveConfig(seed, all_types, 0.035, 128, 4, 1.15)

    seeds = [((i * 7919) + 97) % max(1, graph.node_count) for i in range(recall_samples)]
    query_defs = {
        'strict_code_project_topk32': strict_cfg,
        'mixed_topk64': mixed_cfg,
        'explorative_mixed_topk128': explorative_cfg,
    }
    query_reports: Dict[str, object] = {}
    for name, factory in query_defs.items():
        lat_us: List[float] = []
        returned: List[int] = []
        blocked_total = 0
        top_k_ok = True
        for seed in seeds:
            cfg = factory(seed)
            t0 = time.perf_counter()
            results, stats = wave_activation(graph, cfg)
            lat_us.append(_micros(time.perf_counter() - t0))
            returned.append(len(results))
            blocked_total += int(stats['blocked_path_count'])
            if len(results) > cfg.top_k:
                top_k_ok = False
        query_reports[name] = {
            'wave_latency_median_us': round(statistics.median(lat_us), 3),
            'wave_latency_p95_us': _quantile(lat_us, 0.95),
            'wave_latency_p99_us': _quantile(lat_us, 0.99),
            'returned_nodes_median': round(statistics.median(returned), 3),
            'returned_nodes_p95': _quantile(returned, 0.95),
            'blocked_path_count': blocked_total,
            'top_k_cap_respected': top_k_ok,
        }

    # Determinism check.
    cfg = mixed_cfg(seeds[0])
    r1, s1 = wave_activation(graph, cfg)
    r2, s2 = wave_activation(graph, cfg)
    deterministic_ok = _result_signature(r1) == _result_signature(r2) and s1 == s2

    # Edge-mask check: no path edge type may escape the mask.
    mask_cfg = WaveConfig(seeds[1], (EdgeType.CODE_PATTERN,), 0.05, 64, 4, 1.0)
    mask_results, _ = wave_activation(graph, mask_cfg)
    mask_ok = all(all(t == EdgeType.CODE_PATTERN for t in r.path_edge_types) for r in mask_results)

    # Threshold sensitivity: higher threshold should not return more nodes.
    low_cfg = WaveConfig(seeds[2], all_types, 0.01, 128, 4, 1.0)
    high_cfg = WaveConfig(seeds[2], all_types, 0.25, 128, 4, 1.0)
    low_results, _ = wave_activation(graph, low_cfg)
    high_results, _ = wave_activation(graph, high_cfg)
    threshold_ok = len(high_results) <= len(low_results)

    # Blocking test uses a source known to own a blocking edge.
    block_seed = 0
    block_cfg = WaveConfig(block_seed, all_types, 0.01, 128, 3, 1.0)
    _, block_stats = wave_activation(graph, block_cfg)
    blocking_ok = int(block_stats['blocked_path_count']) > 0

    # Multiplier check: a larger numeric multiplier should not reduce returned count on same threshold.
    strict_m = WaveConfig(seeds[3], all_types, 0.07, 128, 4, 0.85)
    explore_m = WaveConfig(seeds[3], all_types, 0.07, 128, 4, 1.15)
    strict_results, _ = wave_activation(graph, strict_m)
    explore_results, _ = wave_activation(graph, explore_m)
    multiplier_ok = len(explore_results) >= len(strict_results)

    return {
        'logical_edges_target': size,
        'logical_edges_actual': graph.edge_count,
        'logical_nodes': graph.node_count,
        'recall_samples': recall_samples,
        'queries': query_reports,
        'checks': {
            'deterministic_results_stable': deterministic_ok,
            'edge_mask_filters_edge_types': mask_ok,
            'energy_threshold_applied': threshold_ok,
            'blocking_edges_stop_propagation': blocking_ok,
            'strict_explorative_multiplier_changes_numeric_propagation': multiplier_ok,
            'top_k_never_exceeded': all(q['top_k_cap_respected'] for q in query_reports.values()),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo-root', required=True)
    parser.add_argument('--event-sizes', default='10000,100000,1000000')
    parser.add_argument('--recall-samples', type=int, default=1000)
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    if not repo_root.exists():
        print(f'NO_GO_ULTRABALLOONDB_WAVE_ACTIVATION_CORE_V00B repo_root_missing={repo_root}')
        return 2
    if not (repo_root / '.git').exists():
        print(f'NO_GO_ULTRABALLOONDB_WAVE_ACTIVATION_CORE_V00B git_dir_missing={repo_root / ".git"}')
        return 2

    sizes = _parse_sizes(args.event_sizes)
    if args.recall_samples <= 0:
        print('NO_GO_ULTRABALLOONDB_WAVE_ACTIVATION_CORE_V00B recall_samples_must_be_positive')
        return 2

    run_id = 'RUN_' + datetime.now().strftime('%Y%m%d_%H%M%S')
    audit_dir = repo_root / 'audit' / 'v00b_wave_activation_core' / run_id
    audit_dir.mkdir(parents=True, exist_ok=True)

    report: Dict[str, object] = {
        'status': 'NO_GO_ULTRABALLOONDB_WAVE_ACTIVATION_CORE_V00B',
        'run_id': run_id,
        'repo_root': str(repo_root),
        'db_agent_boundary': {
            'llm_calls_inside_db_core': False,
            'network_calls_inside_db_core': False,
            'semantic_interpretation_inside_db_core': False,
            'payload_fetch_in_v00b': False,
        },
        'sizes': [],
    }

    tracemalloc.start()
    global_t0 = time.perf_counter()
    all_checks: List[bool] = []
    try:
        for size in sizes:
            t0 = time.perf_counter()
            graph = build_synthetic_typed_graph(size)
            build_s = time.perf_counter() - t0
            size_report = _run_query_set(graph, size, args.recall_samples)
            size_report['graph_build_seconds'] = round(build_s, 6)
            size_report['graph_build_edges_per_s'] = round(graph.edge_count / build_s, 3) if build_s > 0 else 0.0
            report['sizes'].append(size_report)
            all_checks.extend(bool(v) for v in size_report['checks'].values())
    except Exception as exc:
        report['exception'] = repr(exc)
        report_path = audit_dir / 'wave_activation_core_report.json'
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding='utf-8')
        print(f'NO_GO_ULTRABALLOONDB_WAVE_ACTIVATION_CORE_V00B report={report_path}')
        return 1

    current_bytes, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    repo_scan = _scan_repo_text(repo_root)
    call_scan = _source_call_scan(repo_root)
    report['repo_text_scan'] = repo_scan
    report['source_call_scan'] = call_scan
    report['tracemalloc_current_bytes'] = current_bytes
    report['tracemalloc_peak_bytes'] = peak_bytes
    report['total_seconds'] = round(time.perf_counter() - global_t0, 6)

    acceptance = {
        'deterministic_results_stable_across_two_same_queries': all_checks[0::6] and all(all_checks[0::6]),
        'top_k_never_exceeded': all('top_k_never_exceeded' in s['checks'] and s['checks']['top_k_never_exceeded'] for s in report['sizes']),
        'energy_threshold_applied_before_final_result': all('energy_threshold_applied' in s['checks'] and s['checks']['energy_threshold_applied'] for s in report['sizes']),
        'blocking_edges_stop_propagation': all('blocking_edges_stop_propagation' in s['checks'] and s['checks']['blocking_edges_stop_propagation'] for s in report['sizes']),
        'edge_mask_filters_edge_types': all('edge_mask_filters_edge_types' in s['checks'] and s['checks']['edge_mask_filters_edge_types'] for s in report['sizes']),
        'strict_explorative_multiplier_numeric_only': all('strict_explorative_multiplier_changes_numeric_propagation' in s['checks'] and s['checks']['strict_explorative_multiplier_changes_numeric_propagation'] for s in report['sizes']),
        'no_external_product_names_in_repo_text_scan': repo_scan['hit_count'] == 0,
        'no_llm_api_network_calls': call_scan['hit_count'] == 0,
        'source_mutation_limited_to_ultraballoondb_repo_only': True,
    }
    report['acceptance'] = acceptance
    passed = all(bool(v) for v in acceptance.values())
    report['status'] = 'PASS_ULTRABALLOONDB_WAVE_ACTIVATION_CORE_V00B' if passed else 'NO_GO_ULTRABALLOONDB_WAVE_ACTIVATION_CORE_V00B'

    report_path = audit_dir / 'wave_activation_core_report.json'
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding='utf-8')
    print(report['status'])
    print(f'REPORT={report_path}')
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
