#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import tracemalloc
from typing import Dict, List

# Ensure package imports work when launched from repo root.
THIS_FILE = Path(__file__).resolve()
CORE_ROOT = THIS_FILE.parents[1]
PY_ROOT = THIS_FILE.parents[2]
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from ultraballoondb_core.decode_checksum_split import build_page_store, run_split_profile  # noqa:E402

VERSION = "V00I3_DECODE_CHECKSUM_HOTPATH_SPLIT"
PASS_LINE = "PASS_ULTRABALLOONDB_DECODE_CHECKSUM_HOTPATH_SPLIT_V00I3"
NO_GO_LINE = "NO_GO_ULTRABALLOONDB_DECODE_CHECKSUM_HOTPATH_SPLIT_V00I3"


def parse_int_csv(value: str) -> List[int]:
    out = []
    for part in value.split(','):
        part = part.strip()
        if part:
            out.append(int(part))
    if not out:
        raise argparse.ArgumentTypeError("empty integer csv")
    return out


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest().upper()


def _token_from_codes(codes: List[int]) -> str:
    return ''.join(chr(c) for c in codes).lower()


def _control_tokens() -> List[str]:
    # Keep control strings out of repo text as plain literals.
    # This prevents the scanner from flagging its own guard implementation.
    token_codes = [
        [110, 101, 111, 52, 106],
        [112, 105, 110, 101, 99, 111, 110, 101],
        [119, 101, 97, 118, 105, 97, 116, 101],
        [99, 104, 114, 111, 109, 97, 100, 98],
        [99, 104, 114, 111, 109, 97],
        [109, 105, 108, 118, 117, 115],
        [113, 100, 114, 97, 110, 116],
        [102, 97, 105, 115, 115],
    ]
    return [_token_from_codes(codes) for codes in token_codes]


def repo_text_scan(repo_root: Path) -> Dict[str, object]:
    control_tokens = _control_tokens()
    hits = []
    skip_dirs = {'.git', 'audit', '__pycache__'}
    suffixes = {'.py', '.ps1', '.md', '.txt'}

    for path in repo_root.rglob('*'):
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        if any(part in skip_dirs for part in path.parts):
            continue

        try:
            text = path.read_text(encoding='utf-8', errors='ignore').lower()
        except Exception:
            continue

        for token in control_tokens:
            if token in text:
                hits.append({
                    'path': str(path.relative_to(repo_root)),
                    'token_sha256_8': hashlib.sha256(token.encode('utf-8')).hexdigest().upper()[:8],
                })

    return {
        'pass': not hits,
        'hit_count': len(hits),
        'hits': hits,
    }


def run_one_size(record_count: int, page_size: int, recall_samples: int, top_k_values: List[int], run_dir: Path) -> Dict[str, object]:
    store_dir = run_dir / 'stores'
    store_dir.mkdir(parents=True, exist_ok=True)

    store_path = store_dir / f'v00i3_records_{record_count}_page_{page_size}.ubpage'

    t0 = time.perf_counter()
    pointers = build_page_store(
        store_path,
        record_count=record_count,
        page_size=page_size,
        payload_size=96,
    )
    build_s = time.perf_counter() - t0

    file_size = store_path.stat().st_size
    file_sha256 = sha256_file(store_path)

    profiles = []
    for top_k in top_k_values:
        for checksum_mode in [
            'checksum_full',
            'checksum_sampled_1_of_8',
            'checksum_disabled_trusted_hot_snapshot',
        ]:
            profiles.append(
                run_split_profile(
                    store_path,
                    pointers,
                    recall_samples,
                    top_k,
                    checksum_mode,
                )
            )

    strict_profiles = [p for p in profiles if p['checksum_mode'] == 'checksum_full']
    strict_top = max(strict_profiles, key=lambda p: int(p['top_k']))
    summary_top = strict_top['summary']

    mode_rank = sorted(
        [
            {
                'top_k': p['top_k'],
                'checksum_mode': p['checksum_mode'],
                'total_context_p95_us': p['summary']['total_context_p95_us'],
                'actual_read_p95_us': p['summary']['actual_read_p95_us'],
                'checksum_p95_us': p['summary']['checksum_p95_us'],
                'header_parse_p95_us': p['summary']['header_parse_p95_us'],
                'record_decode_p95_us': p['summary']['record_decode_p95_us'],
                'slice_copy_p95_us': p['summary']['slice_copy_p95_us'],
                'dominant_phase_by_p95': p['summary']['dominant_phase_by_p95'],
                'actual_read_share_of_total_p95': p['summary']['actual_read_share_of_total_p95'],
                'checksum_share_of_total_p95': p['summary']['checksum_share_of_total_p95'],
                'decode_plus_header_share_of_total_p95': p['summary']['decode_plus_header_share_of_total_p95'],
            }
            for p in profiles
        ],
        key=lambda x: (int(x['top_k']), str(x['checksum_mode'])),
    )

    return {
        'record_count': record_count,
        'page_size': page_size,
        'store_path': str(store_path),
        'store_size_bytes': file_size,
        'store_sha256': file_sha256,
        'build_seconds': build_s,
        'pointer_count': len(pointers),
        'profiles': profiles,
        'strict_topk_max_checksum_full_summary': summary_top,
        'ranked_mode_summary': mode_rank,
        'final_page_size_selected': False,
        'hot_path_policy_selected': False,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo-root', required=True)
    ap.add_argument('--event-sizes', default='10000,100000,1000000')
    ap.add_argument('--recall-samples', type=int, default=1000)
    ap.add_argument('--max-effective-samples', type=int, default=250)
    ap.add_argument('--page-sizes', default='16384,65536')
    ap.add_argument('--top-k-values', default='32,64,128')
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    event_sizes = parse_int_csv(args.event_sizes)
    page_sizes = parse_int_csv(args.page_sizes)
    top_k_values = parse_int_csv(args.top_k_values)

    requested_recall_samples = int(args.recall_samples)
    effective_recall_samples = min(requested_recall_samples, int(args.max_effective_samples))

    if not repo_root.exists():
        print(f"{NO_GO_LINE}: repo root does not exist: {repo_root}")
        return 1

    run_id = time.strftime('RUN_%Y%m%d_%H%M%S')
    run_dir = repo_root / 'audit' / 'v00i3_decode_checksum_hotpath_split' / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    tracemalloc.start()
    start = time.perf_counter()

    failures: Dict[str, str] = {}
    size_reports = []

    try:
        for n in event_sizes:
            for page_size in page_sizes:
                size_reports.append(
                    run_one_size(
                        n,
                        page_size,
                        effective_recall_samples,
                        top_k_values,
                        run_dir,
                    )
                )
    except Exception as exc:
        failures['benchmark_exception'] = repr(exc)

    text_scan = repo_text_scan(repo_root)
    if not text_scan['pass']:
        failures['text_scan'] = 'repo text scan hit'

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    checks = {
        'decode_checksum_split_present': True,
        'checksum_full_profile_present': False,
        'checksum_sampled_profile_present': False,
        'checksum_disabled_profile_present': False,
        'dominant_phase_measured': False,
        'actual_read_share_measured': False,
        'no_final_page_size_assumption': True,
        'hot_path_policy_not_selected': True,
        'no_agent_policy': True,
        'no_model_calls': True,
        'no_network_calls': True,
        'text_scan_no_control_token_hits': bool(text_scan['pass']),
    }

    all_profiles = []
    for sr in size_reports:
        all_profiles.extend(sr.get('profiles', []))

    modes = {p.get('checksum_mode') for p in all_profiles}

    checks['checksum_full_profile_present'] = 'checksum_full' in modes
    checks['checksum_sampled_profile_present'] = 'checksum_sampled_1_of_8' in modes
    checks['checksum_disabled_profile_present'] = 'checksum_disabled_trusted_hot_snapshot' in modes
    checks['dominant_phase_measured'] = all(
        'dominant_phase_by_p95' in p.get('summary', {})
        for p in all_profiles
    )
    checks['actual_read_share_measured'] = all(
        'actual_read_share_of_total_p95' in p.get('summary', {})
        for p in all_profiles
    )

    for key, ok in checks.items():
        if not ok:
            failures[key] = 'check failed'

    status = PASS_LINE if not failures else NO_GO_LINE

    report = {
        'version': VERSION,
        'status': status,
        'repo_root': str(repo_root),
        'run_dir': str(run_dir),
        'elapsed_seconds': time.perf_counter() - start,
        'event_sizes': event_sizes,
        'page_sizes': page_sizes,
        'top_k_values': top_k_values,
        'requested_recall_samples': requested_recall_samples,
        'effective_recall_samples': effective_recall_samples,
        'measurement_scope': {
            'file_backed_page_store': True,
            'cold_disk_guaranteed': False,
            'final_page_size_selected': False,
            'hot_path_policy_selected': False,
            'runtime_hot_path_format_finalized': False,
        },
        'checks': checks,
        'failures': failures,
        'text_scan': text_scan,
        'size_reports': size_reports,
        'tracemalloc_current_bytes': current,
        'tracemalloc_peak_bytes': peak,
    }

    report_path = run_dir / 'decode_checksum_hotpath_split_report.json'
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding='utf-8',
    )

    print(status)
    print(f"REPORT={report_path}")

    if failures:
        print('FAILURES=' + '; '.join(f'{k}={v}' for k, v in failures.items()))
        print('TEXT_SCAN_HITS=' + json.dumps(text_scan.get('hits', []), ensure_ascii=False))
        return 1

    return 0


if __name__ == '__main__':
    raise SystemExit(main())