#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Dict, List, Mapping

HERE = Path(__file__).resolve()
CORE_ROOT = HERE.parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from ultraballoondb_core.durable_runtime import DurableDatabaseRuntime
from ultraballoondb_core.hot_snapshot import archive_paths, sha256_file, snapshot_paths
from ultraballoondb_core.types import EdgeType

VERSION = "V00N_DURABLE_WRITES_WAL_CRASH_RECOVERY"
PASS_LINE = "PASS_ULTRABALLOONDB_DURABLE_WRITES_WAL_CRASH_RECOVERY_V00N"
NO_GO_LINE = "NO_GO_ULTRABALLOONDB_DURABLE_WRITES_WAL_CRASH_RECOVERY_V00N"


def record_op(record_id: str, node_id: int, payload: bytes) -> Mapping[str, object]:
    import hashlib
    return {
        "kind": "PUT_RECORD",
        "record_id": record_id,
        "node_id": node_id,
        "payload_b64": base64.b64encode(payload).decode("ascii"),
        "payload_sha256": hashlib.sha256(payload).hexdigest().upper(),
    }


def edge_op(src: int, dst: int) -> Mapping[str, object]:
    return {
        "kind": "PUT_EDGE",
        "src": src,
        "dst": dst,
        "edge_type": int(EdgeType.PROJECT_CONTEXT),
        "weight_million": 1_000_000,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--event-count", type=int, default=10000)
    ap.add_argument("--checkpoint-records", type=int, default=4)
    ap.add_argument("--replay-records", type=int, default=4)
    ap.add_argument("--query-top-k", type=int, default=64)
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    if not repo_root.exists():
        print(f"{NO_GO_LINE}: repo root missing")
        return 1
    if args.event_count < 64 or args.checkpoint_records < 1 or args.replay_records < 1:
        print(f"{NO_GO_LINE}: invalid parameters")
        return 1

    run_id = time.strftime("RUN_%Y%m%d_%H%M%S")
    run_dir = repo_root / "audit" / "v00n_durable_writes_wal_crash_recovery" / run_id
    database_root = run_dir / "database"
    run_dir.mkdir(parents=True, exist_ok=True)

    tracemalloc.start()
    started = time.perf_counter()

    runtime = DurableDatabaseRuntime(database_root)
    create_manifest = runtime.create(args.event_count)
    runtime.open()

    apaths = archive_paths(database_root / "archive")
    spaths = snapshot_paths(database_root / "hot_snapshot")
    base_hashes_before = {
        "records": sha256_file(apaths.records_path),
        "payloads": sha256_file(apaths.payloads_path),
        "edges": sha256_file(spaths.edges_path),
        "crystals": sha256_file(spaths.crystals_path),
    }

    base_seed = int(runtime.base.get_event_record(0).seed_node)
    checkpoint_ids: List[str] = []
    checkpoint_nodes: List[int] = []
    tx1 = runtime.begin()
    for i in range(args.checkpoint_records):
        record_id = f"durable:checkpoint:{i}"
        node_id = 10_000_000 + i
        payload = f"CHECKPOINT_PAYLOAD_{i:04d}".encode("ascii")
        checkpoint_ids.append(record_id)
        checkpoint_nodes.append(node_id)
        tx1.put_record(record_id, node_id, payload)
        tx1.put_edge(base_seed, node_id, EdgeType.PROJECT_CONTEXT, 1.0)
    receipt1 = tx1.commit()
    checkpoint_doc = runtime.checkpoint()

    replay_ids: List[str] = []
    replay_nodes: List[int] = []
    tx2 = runtime.begin()
    for i in range(args.replay_records):
        record_id = f"durable:replay:{i}"
        node_id = 10_100_000 + i
        payload = f"REPLAY_PAYLOAD_{i:04d}".encode("ascii")
        replay_ids.append(record_id)
        replay_nodes.append(node_id)
        tx2.put_record(record_id, node_id, payload)
        tx2.put_edge(base_seed, node_id, EdgeType.PROJECT_CONTEXT, 1.0)
    receipt2 = tx2.commit()
    state_before_crash = runtime.state_sha256()

    uncommitted_record_id = "durable:must_not_exist"
    uncommitted_node = 10_900_000
    runtime.append_uncommitted_transaction_for_test([
        record_op(uncommitted_record_id, uncommitted_node, b"UNCOMMITTED_PAYLOAD"),
        edge_op(base_seed, uncommitted_node),
    ])
    runtime.append_partial_wal_tail_for_test()
    runtime.close()  # no checkpoint after tx2: recovery must use WAL

    recovered = DurableDatabaseRuntime(database_root)
    status_recovered = recovered.open(repair_wal_tail=True)
    recovery = recovered.recovery_report

    all_expected_ids = checkpoint_ids + replay_ids
    exact_records_ok = all(
        recovered.get_record(record_id).record_id == record_id
        for record_id in all_expected_ids
    )
    uncommitted_absent = False
    try:
        recovered.get_record(uncommitted_record_id)
    except KeyError:
        uncommitted_absent = True

    wave_a = recovered.wave_query_nodes(
        [base_seed],
        edge_mask=(EdgeType.PROJECT_CONTEXT,),
        energy_threshold=0.10,
        top_k=args.query_top_k,
        max_steps=1,
    )
    result_nodes = {int(result.node_id) for result in wave_a.results}
    durable_nodes_recalled = set(checkpoint_nodes + replay_nodes).issubset(result_nodes)
    uncommitted_node_absent_from_wave = uncommitted_node not in result_nodes

    integrity_a = recovered.verify_integrity()
    state_after_recovery = recovered.state_sha256()
    base_hashes_after_recovery = {
        "records": sha256_file(apaths.records_path),
        "payloads": sha256_file(apaths.payloads_path),
        "edges": sha256_file(spaths.edges_path),
        "crystals": sha256_file(spaths.crystals_path),
    }

    checkpoint_after_recovery = recovered.checkpoint()
    recovered.close()

    reopened = DurableDatabaseRuntime(database_root)
    status_reopened = reopened.open(repair_wal_tail=False)
    wave_b = reopened.wave_query_nodes(
        [base_seed],
        edge_mask=(EdgeType.PROJECT_CONTEXT,),
        energy_threshold=0.10,
        top_k=args.query_top_k,
        max_steps=1,
    )
    integrity_b = reopened.verify_integrity()
    final_state_sha = reopened.state_sha256()
    base_hashes_final = {
        "records": sha256_file(apaths.records_path),
        "payloads": sha256_file(apaths.payloads_path),
        "edges": sha256_file(spaths.edges_path),
        "crystals": sha256_file(spaths.crystals_path),
    }

    checks = {
        "v00m_base_runtime_opened": reopened.base.opened,
        "durable_manifest_declares_single_writer": bool(create_manifest["single_writer"]),
        "first_commit_fsynced_and_visible": receipt1.record_count == args.checkpoint_records,
        "second_commit_fsynced_and_visible": receipt2.record_count == args.checkpoint_records + args.replay_records,
        "checkpoint_lsn_matches_first_commit": int(checkpoint_doc["last_applied_lsn"]) == receipt1.commit_lsn,
        "wal_replayed_post_checkpoint_commit": recovery.replayed_transactions >= 1,
        "uncommitted_transaction_ignored": recovery.ignored_uncommitted_transactions >= 1 and uncommitted_absent,
        "truncated_wal_tail_repaired": recovery.tail_repaired_bytes > 0,
        "all_committed_records_exactly_indexed": exact_records_ok,
        "durable_edge_count_recovered": int(status_recovered["durable_edge_count"]) == args.checkpoint_records + args.replay_records,
        "durable_edges_visible_to_wave": durable_nodes_recalled,
        "uncommitted_edge_not_visible_to_wave": uncommitted_node_absent_from_wave,
        "state_sha_recovered": state_before_crash == state_after_recovery,
        "checkpoint_checksum_valid": bool(integrity_a["checkpoint_valid"]) and bool(integrity_b["checkpoint_valid"]),
        "wal_checksum_valid": bool(integrity_a["wal_valid"]) and bool(integrity_b["wal_valid"]),
        "canonical_base_files_unchanged": base_hashes_before == base_hashes_after_recovery == base_hashes_final,
        "restart_state_deterministic": final_state_sha == state_after_recovery,
        "restart_wave_deterministic": wave_a.results == wave_b.results,
        "checkpoint_after_recovery_covers_latest_commit": int(checkpoint_after_recovery["last_applied_lsn"]) == receipt2.commit_lsn,
        "no_replay_needed_after_latest_checkpoint": reopened.recovery_report.replayed_transactions == 0,
    }

    failures = {name: "check failed" for name, ok in checks.items() if not ok}
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    status = PASS_LINE if not failures else NO_GO_LINE

    report: Dict[str, object] = {
        "version": VERSION,
        "status": status,
        "repo_root": str(repo_root),
        "run_dir": str(run_dir),
        "database_root": str(database_root),
        "elapsed_seconds": time.perf_counter() - started,
        "memory_current_bytes": current,
        "memory_peak_bytes": peak,
        "params": vars(args),
        "alignment": {
            "role": "CORE",
            "touches_core_layers": ["L0", "L1", "L2", "L3", "L4"],
            "uses_auxiliary_layers": [],
            "must_preserve": ["L2_TYPED_EDGE_GRAPH", "L3_WAVE_ACTIVATION"],
            "runtime_impact": "DURABLE_SINGLE_WRITER_WAL_RECOVERY_REFERENCE",
            "roadmap_status": "ALIGNED",
        },
        "create_manifest": create_manifest,
        "receipt_checkpointed": receipt1.__dict__,
        "receipt_replayed": receipt2.__dict__,
        "recovery": recovery.__dict__,
        "status_recovered": status_recovered,
        "status_reopened": status_reopened,
        "integrity_recovered": integrity_a,
        "integrity_reopened": integrity_b,
        "checks": checks,
        "failures": failures,
    }
    report_path = run_dir / "durable_writes_wal_crash_recovery_report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    summary = {
        "committed_transactions": int(status_recovered["committed_transaction_count"]),
        "durable_records": int(status_recovered["durable_record_count"]),
        "durable_edges": int(status_recovered["durable_edge_count"]),
        "checkpoint_lsn": recovery.checkpoint_lsn,
        "last_applied_lsn": recovery.last_applied_lsn,
        "replayed_transactions": recovery.replayed_transactions,
        "ignored_uncommitted_transactions": recovery.ignored_uncommitted_transactions,
        "tail_repaired_bytes": recovery.tail_repaired_bytes,
        "wal_frames": recovery.valid_wal_frames,
        "wal_sha256": recovery.wal_sha256,
        "state_sha256": state_after_recovery,
        "wave_recalled_durable_nodes": durable_nodes_recalled,
        "canonical_base_unchanged": base_hashes_before == base_hashes_final,
        "restart_deterministic": final_state_sha == state_after_recovery and wave_a.results == wave_b.results,
    }
    print(status)
    print(f"REPORT={report_path}")
    print("SUMMARY=" + json.dumps(summary, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
