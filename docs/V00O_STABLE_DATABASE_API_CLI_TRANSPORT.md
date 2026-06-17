# UltraBalloonDB V00O — Stable Database API, CLI, and Basic Transport

## Alignment

- role: CORE
- touches: L0-L7
- auxiliary compression layers: none
- preserves: L2 typed edge graph and L3 wave activation
- runtime impact: stable API/CLI/HTTP reference

## Purpose

V00O converts the V00M unified runtime and V00N durable overlay into one stable,
semantics-blind product interface.

Public operations:

- create/open/close/status
- put/get durable record
- put/get typed edge
- durable wave activation
- checkpoint and integrity verification
- base floating-subgraph export/import
- JSON CLI
- single-writer JSON/HTTP transport

## Boundaries

The HTTP transport is a benchmark/integration reference. It is single-writer and
standard-library-only. TLS, authentication, authorization, quotas, distributed
consensus, and production hardening are not claimed in V00O.

The API never promotes trust and does not interpret payload semantics. L2 remains
the typed graph; L3 remains deterministic wave activation.

## CLI examples

```powershell
$env:PYTHONPATH="C:\UltraBalloonDB\python_ref"
python -m ultraballoondb_core.cli status --db-root C:\data\mydb
python -m ultraballoondb_core.cli put-record --db-root C:\data\mydb --record-id r1 --node-id 1001 --payload-text "abc"
python -m ultraballoondb_core.cli wave --db-root C:\data\mydb --seed-nodes 10 --edge-mask PROJECT_CONTEXT --top-k 64
python -m ultraballoondb_core.cli serve --db-root C:\data\mydb --host 127.0.0.1 --port 8765
```
