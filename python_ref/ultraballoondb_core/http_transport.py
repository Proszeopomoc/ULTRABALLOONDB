#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Minimal single-writer JSON/HTTP transport for UltraBalloonDB V00O.

The transport is deliberately small and standard-library-only. It is intended
for local/LAN/WAN benchmarking and early integration, not as a final security
boundary. TLS, authentication, authorization, quotas, and production hardening
remain release tasks.
"""
from __future__ import annotations

import base64
import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Mapping

from ultraballoondb_core.database_api import UltraBalloonDatabase

VERSION = "V00O_STABLE_DATABASE_API_CLI_TRANSPORT"
MAX_REQUEST_BYTES = 64 * 1024 * 1024


def _json_bytes(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class TransportReceipt:
    request_bytes: int
    response_bytes: int
    status_code: int


class DatabaseHttpServer(HTTPServer):
    allow_reuse_address = True

    def __init__(self, server_address, database: UltraBalloonDatabase):
        self.database = database
        super().__init__(server_address, DatabaseRequestHandler)


class DatabaseRequestHandler(BaseHTTPRequestHandler):
    server: DatabaseHttpServer

    def log_message(self, format, *args):
        return

    def _send(self, status: int, value: Mapping[str, object]) -> None:
        body = _json_bytes(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Mapping[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise ValueError("request body too large")
        raw = self.rfile.read(length)
        if not raw:
            return {}
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON request must be an object")
        return value

    def do_GET(self) -> None:
        try:
            if self.path == "/v1/status":
                self._send(200, dict(self.server.database.status()))
                return
            if self.path == "/v1/verify":
                self._send(200, dict(self.server.database.verify()))
                return
            self._send(404, {"error": "not_found", "path": self.path})
        except Exception as exc:
            self._send(400, {"error": type(exc).__name__, "message": str(exc)})

    def do_POST(self) -> None:
        try:
            req = self._read_json()
            db = self.server.database
            if self.path == "/v1/put-record":
                payload = base64.b64decode(str(req["payload_b64"]).encode("ascii"), validate=True)
                result = db.put_record(str(req["record_id"]), int(req["node_id"]), payload)
            elif self.path == "/v1/get-record":
                result = db.get_record(str(req["record_id"]))
            elif self.path == "/v1/put-edge":
                result = db.put_edge(int(req["src"]), int(req["dst"]), req["edge_type"], float(req.get("weight", 1.0)))
            elif self.path == "/v1/get-edges":
                result = db.get_edges(
                    int(req["node_id"]),
                    direction=str(req.get("direction", "out")),
                    edge_types=req.get("edge_types"),
                    limit=int(req.get("limit", 1000)),
                )
            elif self.path == "/v1/wave":
                result = db.wave_activation(
                    req["seed_nodes"],
                    edge_mask=req.get("edge_mask"),
                    energy_threshold=float(req.get("energy_threshold", 0.10)),
                    top_k=int(req.get("top_k", 64)),
                    max_steps=int(req.get("max_steps", 2)),
                    rigor_multiplier=float(req.get("rigor_multiplier", 1.0)),
                )
            elif self.path == "/v1/checkpoint":
                result = db.checkpoint()
            else:
                self._send(404, {"error": "not_found", "path": self.path})
                return
            self._send(200, dict(result))
        except Exception as exc:
            self._send(400, {"error": type(exc).__name__, "message": str(exc)})


def start_server_in_thread(database: UltraBalloonDatabase, host: str = "127.0.0.1", port: int = 0):
    server = DatabaseHttpServer((host, int(port)), database)
    thread = threading.Thread(target=server.serve_forever, name="UltraBalloonDB-V00O-HTTP", daemon=True)
    thread.start()
    return server, thread


class HttpDatabaseClient:
    def __init__(self, base_url: str, timeout_seconds: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = float(timeout_seconds)
        self.last_receipt: TransportReceipt | None = None

    def request(self, method: str, path: str, payload: Mapping[str, object] | None = None) -> Mapping[str, object]:
        body = b"" if payload is None else _json_bytes(payload)
        request = urllib.request.Request(
            self.base_url + path,
            data=body if method.upper() != "GET" else None,
            method=method.upper(),
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read()
                status = int(response.status)
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            status = int(exc.code)
        self.last_receipt = TransportReceipt(len(body), len(raw), status)
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("HTTP response must be a JSON object")
        if status >= 400:
            raise RuntimeError(f"HTTP {status}: {value}")
        return value

    def status(self) -> Mapping[str, object]:
        return self.request("GET", "/v1/status")

    def verify(self) -> Mapping[str, object]:
        return self.request("GET", "/v1/verify")

    def put_record(self, record_id: str, node_id: int, payload: bytes) -> Mapping[str, object]:
        return self.request("POST", "/v1/put-record", {
            "record_id": record_id,
            "node_id": int(node_id),
            "payload_b64": base64.b64encode(payload).decode("ascii"),
        })

    def get_record(self, record_id: str) -> Mapping[str, object]:
        return self.request("POST", "/v1/get-record", {"record_id": record_id})

    def put_edge(self, src: int, dst: int, edge_type: str | int, weight: float = 1.0) -> Mapping[str, object]:
        return self.request("POST", "/v1/put-edge", {
            "src": int(src), "dst": int(dst), "edge_type": edge_type, "weight": float(weight)
        })

    def wave(self, seed_nodes, **kwargs) -> Mapping[str, object]:
        payload = {"seed_nodes": list(seed_nodes), **kwargs}
        return self.request("POST", "/v1/wave", payload)
