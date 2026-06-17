# UltraBalloonDB V00N — Durable writes, WAL, and crash recovery

## Alignment

- Role: **CORE**
- Core layers touched: **L0, L1, L2, L3, L4**
- Auxiliary compression layers: **none**
- Must preserve: **L2 typed edge graph, L3 wave activation**
- Runtime impact: **durable single-writer WAL/recovery reference**

## Purpose

V00N adds a durable mutable overlay to the V00M unified L0–L7 runtime.
It supports byte records, exact record lookup, typed edges, explicit transactions,
WAL commit, checkpoint, restart replay, truncated-tail repair, and wave queries over
base plus committed mutable edges.

## Commit contract

A transaction is durable only after its `COMMIT` WAL frame is written, flushed,
and `fsync` completes. Recovery applies only transactions with a complete BEGIN,
operation sequence, and COMMIT. Transactions without COMMIT are ignored.

## WAL framing

Each WAL frame contains:

- fixed magic,
- payload length,
- SHA-256 of canonical JSON payload,
- canonical JSON payload with monotonic LSN and transaction ID.

A partial trailing frame is treated as interrupted I/O and truncated to the last
valid frame boundary. A checksum mismatch in a complete frame is a hard error.

## Checkpoint

Mutable records, exact indexes, typed edges, committed transaction IDs, and the
last applied LSN are written through a temporary file, `fsync`, and atomic replace.
The checkpoint state has its own SHA-256.

## Canonical boundary

V00N does not rewrite the V00M canonical archive or hot snapshot. The durable
record/edge overlay is merged into an in-memory typed graph for L3 wave queries.
The original L2 graph and L3 wave implementation remain the core mechanisms.

## Current scope

Included:

- single writer,
- explicit transaction object,
- `put_record`,
- `put_edge`,
- commit with WAL fsync,
- exact mutable record index,
- checkpoint,
- restart replay,
- ignored uncommitted transaction,
- truncated tail repair,
- entry and checkpoint SHA verification,
- wave query over committed durable edges.

Deferred:

- multi-process writers,
- distributed consensus,
- network server,
- advanced isolation levels,
- WAL segment rotation and retention policy,
- schema/query language.
