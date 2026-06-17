#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UltraBalloonDB V00O command-line interface."""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

from ultraballoondb_core.database_api import UltraBalloonDatabase
from ultraballoondb_core.http_transport import DatabaseHttpServer


def _print(value) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


def _csv_ints(value: str) -> list[int]:
    return [int(x.strip()) for x in value.split(",") if x.strip()]


def _csv_text(value: str | None):
    if not value:
        return None
    return [x.strip() for x in value.split(",") if x.strip()]


def _payload(args) -> bytes:
    options = [args.payload_text is not None, args.payload_file is not None, args.payload_b64 is not None]
    if sum(options) != 1:
        raise ValueError("provide exactly one of --payload-text, --payload-file, --payload-b64")
    if args.payload_text is not None:
        return args.payload_text.encode("utf-8")
    if args.payload_file is not None:
        return Path(args.payload_file).read_bytes()
    return base64.b64decode(args.payload_b64.encode("ascii"), validate=True)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ultraballoondb", description="UltraBalloonDB V00O stable API/CLI")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("create")
    c.add_argument("--db-root", required=True)
    c.add_argument("--event-count", type=int, required=True)
    c.add_argument("--overwrite", action="store_true")

    for name in ("status", "checkpoint", "verify"):
        q = sub.add_parser(name)
        q.add_argument("--db-root", required=True)

    pr = sub.add_parser("put-record")
    pr.add_argument("--db-root", required=True)
    pr.add_argument("--record-id", required=True)
    pr.add_argument("--node-id", type=int, required=True)
    pr.add_argument("--payload-text")
    pr.add_argument("--payload-file")
    pr.add_argument("--payload-b64")

    gr = sub.add_parser("get-record")
    gr.add_argument("--db-root", required=True)
    gr.add_argument("--record-id", required=True)

    pe = sub.add_parser("put-edge")
    pe.add_argument("--db-root", required=True)
    pe.add_argument("--src", type=int, required=True)
    pe.add_argument("--dst", type=int, required=True)
    pe.add_argument("--edge-type", required=True)
    pe.add_argument("--weight", type=float, default=1.0)

    ge = sub.add_parser("get-edges")
    ge.add_argument("--db-root", required=True)
    ge.add_argument("--node-id", type=int, required=True)
    ge.add_argument("--direction", choices=("out", "in", "both"), default="out")
    ge.add_argument("--edge-types")
    ge.add_argument("--limit", type=int, default=1000)

    w = sub.add_parser("wave")
    w.add_argument("--db-root", required=True)
    w.add_argument("--seed-nodes", required=True)
    w.add_argument("--edge-mask")
    w.add_argument("--energy-threshold", type=float, default=0.10)
    w.add_argument("--top-k", type=int, default=64)
    w.add_argument("--max-steps", type=int, default=2)
    w.add_argument("--rigor-multiplier", type=float, default=1.0)

    ex = sub.add_parser("export-subgraph")
    ex.add_argument("--db-root", required=True)
    ex.add_argument("--seed-event-ids", required=True)
    ex.add_argument("--output", required=True)
    ex.add_argument("--energy-threshold", type=float, default=0.10)
    ex.add_argument("--top-k-per-seed", type=int, default=8)
    ex.add_argument("--max-steps", type=int, default=2)

    im = sub.add_parser("import-subgraph")
    im.add_argument("--db-root", required=True)
    im.add_argument("--input", required=True)

    s = sub.add_parser("serve")
    s.add_argument("--db-root", required=True)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8765)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    db = UltraBalloonDatabase(args.db_root)
    try:
        if args.command == "create":
            _print(db.create(args.event_count, overwrite=args.overwrite))
            return 0
        db.open()
        if args.command == "status": result = db.status()
        elif args.command == "put-record": result = db.put_record(args.record_id, args.node_id, _payload(args))
        elif args.command == "get-record": result = db.get_record(args.record_id)
        elif args.command == "put-edge": result = db.put_edge(args.src, args.dst, args.edge_type, args.weight)
        elif args.command == "get-edges": result = db.get_edges(args.node_id, direction=args.direction, edge_types=_csv_text(args.edge_types), limit=args.limit)
        elif args.command == "wave": result = db.wave_activation(
            _csv_ints(args.seed_nodes), edge_mask=_csv_text(args.edge_mask),
            energy_threshold=args.energy_threshold, top_k=args.top_k,
            max_steps=args.max_steps, rigor_multiplier=args.rigor_multiplier)
        elif args.command == "checkpoint": result = db.checkpoint()
        elif args.command == "verify": result = db.verify()
        elif args.command == "export-subgraph":
            stream = db.export_base_wave_subgraph(_csv_ints(args.seed_event_ids), energy_threshold=args.energy_threshold, top_k_per_seed=args.top_k_per_seed, max_steps=args.max_steps)
            Path(args.output).write_bytes(stream)
            result = {"output": str(Path(args.output).resolve()), "stream_bytes": len(stream)}
        elif args.command == "import-subgraph": result = db.import_floating_subgraph(Path(args.input).read_bytes())
        elif args.command == "serve":
            server = DatabaseHttpServer((args.host, args.port), db)
            print(f"ULTRABALLOONDB_V00O_LISTENING=http://{args.host}:{server.server_port}", flush=True)
            try: server.serve_forever()
            except KeyboardInterrupt: pass
            finally: server.server_close()
            return 0
        else:
            raise RuntimeError("unsupported command")
        _print(result)
        return 0
    except Exception as exc:
        _print({"error": type(exc).__name__, "message": str(exc)})
        return 1
    finally:
        if db.opened:
            db.close()


if __name__ == "__main__":
    raise SystemExit(main())
