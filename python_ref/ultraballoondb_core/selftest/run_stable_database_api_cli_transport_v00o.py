#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import time
import tracemalloc
from pathlib import Path

HERE = Path(__file__).resolve()
CORE_ROOT = HERE.parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from ultraballoondb_core.database_api import UltraBalloonDatabase
from ultraballoondb_core.http_transport import HttpDatabaseClient, start_server_in_thread
from ultraballoondb_core.types import EdgeType

VERSION = "V00O_STABLE_DATABASE_API_CLI_TRANSPORT"
PASS_LINE = "PASS_ULTRABALLOONDB_STABLE_DATABASE_API_CLI_TRANSPORT_V00O"
NO_GO_LINE = "NO_GO_ULTRABALLOONDB_STABLE_DATABASE_API_CLI_TRANSPORT_V00O"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--event-count", type=int, default=10000)
    ap.add_argument("--query-top-k", type=int, default=64)
    args = ap.parse_args()
    repo_root = Path(args.repo_root).resolve()
    if args.event_count < 64:
        print(f"{NO_GO_LINE}: event-count must be >= 64")
        return 1

    run_id = time.strftime("RUN_%Y%m%d_%H%M%S")
    run_dir = repo_root / "audit" / "v00o_stable_database_api_cli_transport" / run_id
    db_root = run_dir / "database"
    run_dir.mkdir(parents=True, exist_ok=True)
    tracemalloc.start()
    started = time.perf_counter()

    db = UltraBalloonDatabase(db_root)
    create_result = db.create(args.event_count, overwrite=False)
    open_result = db.open()
    base_event = db.get_base_event(0)
    base_seed = int(base_event["seed_node"])
    api_node = 20_000_001
    api_payload = b"V00O_API_DURABLE_PAYLOAD"
    receipt = db.put_record_and_edge(
        "v00o:api:record", api_node, api_payload, base_seed,
        EdgeType.PROJECT_CONTEXT, 1.0,
    )
    get_record = db.get_record("v00o:api:record")
    get_edges = db.get_edges(base_seed, direction="out", edge_types=["PROJECT_CONTEXT"], limit=10000)
    wave_local = db.wave_activation(
        [base_seed], edge_mask=["PROJECT_CONTEXT"],
        energy_threshold=0.10, top_k=args.query_top_k, max_steps=1,
    )
    checkpoint = db.checkpoint()
    verify_local = db.verify()
    state_before = str(db.status()["state_sha256"])

    server, thread = start_server_in_thread(db, "127.0.0.1", 0)
    base_url = f"http://127.0.0.1:{server.server_port}"
    client = HttpDatabaseClient(base_url)
    http_status = client.status()
    http_record = client.get_record("v00o:api:record")
    http_wave = client.wave(
        [base_seed], edge_mask=["PROJECT_CONTEXT"],
        energy_threshold=0.10, top_k=args.query_top_k, max_steps=1,
    )
    http_receipt = client.last_receipt
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)
    db.close()

    reopened = UltraBalloonDatabase(db_root)
    reopened.open()
    state_after = str(reopened.status()["state_sha256"])
    reopened_record = reopened.get_record("v00o:api:record")
    verify_reopened = reopened.verify()
    reopened.close()

    env = dict(os.environ)
    env["PYTHONPATH"] = str(repo_root / "python_ref") + os.pathsep + env.get("PYTHONPATH", "")
    cli_cmd = [
        sys.executable, "-m", "ultraballoondb_core.cli", "status",
        "--db-root", str(db_root),
    ]
    cli_proc = subprocess.run(cli_cmd, capture_output=True, text=True, env=env, timeout=60)
    cli_doc = json.loads(cli_proc.stdout) if cli_proc.stdout.strip() else {}

    wave_nodes_local = [int(x["node_id"]) for x in wave_local["results"]]
    wave_nodes_http = [int(x["node_id"]) for x in http_wave["results"]]
    durable_edge_rows = [e for e in get_edges["edges"] if e["source_layer"] == "L2_DURABLE" and int(e["dst"]) == api_node]

    checks = {
        "create_open_api": bool(create_result["created"]) and bool(open_result["opened"]),
        "stable_put_record_and_edge": int(receipt["operation_count"]) == 2,
        "stable_get_record_exact": base64.b64decode(get_record["payload_b64"]) == api_payload,
        "stable_get_edges_includes_durable_edge": len(durable_edge_rows) == 1,
        "stable_wave_includes_durable_node": api_node in wave_nodes_local,
        "checkpoint_and_verify": bool(verify_local["checkpoint_valid"]) and bool(verify_local["wal_valid"]),
        "restart_state_deterministic": state_before == state_after,
        "restart_record_exact": reopened_record["payload_sha256"] == get_record["payload_sha256"],
        "restart_verify": bool(verify_reopened["checkpoint_valid"]) and bool(verify_reopened["wal_valid"]),
        "cli_status_works": cli_proc.returncode == 0 and bool(cli_doc.get("opened")),
        "http_status_works": bool(http_status.get("opened")),
        "http_get_record_exact": http_record["payload_sha256"] == get_record["payload_sha256"],
        "http_wave_matches_local": wave_nodes_http == wave_nodes_local,
        "http_transport_measures_bytes": http_receipt is not None and http_receipt.response_bytes > 0,
        "l2_l3_preserved": api_node in wave_nodes_local and durable_edge_rows[0]["edge_type"] == "PROJECT_CONTEXT",
    }
    failures = {name: "check failed" for name, ok in checks.items() if not ok}
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    status = PASS_LINE if not failures else NO_GO_LINE
    report = {
        "version": VERSION,
        "status": status,
        "repo_root": str(repo_root),
        "run_dir": str(run_dir),
        "database_root": str(db_root),
        "elapsed_seconds": time.perf_counter() - started,
        "memory_current_bytes": current,
        "memory_peak_bytes": peak,
        "params": vars(args),
        "alignment": {
            "role": "CORE",
            "touches_core_layers": ["L0", "L1", "L2", "L3", "L4", "L5", "L6", "L7"],
            "uses_auxiliary_layers": [],
            "must_preserve": ["L2_TYPED_EDGE_GRAPH", "L3_WAVE_ACTIVATION"],
            "runtime_impact": "STABLE_API_CLI_HTTP_REFERENCE",
            "roadmap_status": "ALIGNED",
        },
        "checks": checks,
        "failures": failures,
        "create_result": create_result,
        "open_result": open_result,
        "commit_receipt": receipt,
        "checkpoint": checkpoint,
        "verify_local": verify_local,
        "verify_reopened": verify_reopened,
        "http_transport": None if http_receipt is None else http_receipt.__dict__,
        "cli_returncode": cli_proc.returncode,
    }
    report_path = run_dir / "stable_database_api_cli_transport_report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    summary = {
        "event_count": args.event_count,
        "api_put_get": checks["stable_get_record_exact"],
        "api_edge_query": checks["stable_get_edges_includes_durable_edge"],
        "api_wave": checks["stable_wave_includes_durable_node"],
        "cli_status": checks["cli_status_works"],
        "http_status": checks["http_status_works"],
        "http_wave_matches_local": checks["http_wave_matches_local"],
        "restart_deterministic": checks["restart_state_deterministic"],
        "request_bytes": 0 if http_receipt is None else http_receipt.request_bytes,
        "response_bytes": 0 if http_receipt is None else http_receipt.response_bytes,
    }
    print(status)
    print(f"REPORT={report_path}")
    print("SUMMARY=" + json.dumps(summary, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
