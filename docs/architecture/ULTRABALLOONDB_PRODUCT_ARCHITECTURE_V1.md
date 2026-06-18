# UltraBalloonDB Product Architecture V1

Status: public target architecture. This document does not migrate runtime code.

## One database engine, multiple editions

UltraBalloonDB has one canonical database engine assembled from internal modules.
The product is delivered through several hosts:

- Edition A: native Rust binary;
- Edition B: PyO3 extension;
- Edition C: daemon/server;
- Edition D: stable C ABI.

The editions are adapters. They must not implement independent storage, WAL,
recovery, Wave, Trust or routing semantics.

## Internal product layers

### Durable Database Store

Owns canonical formats, integrity checks, page storage, transactions, WAL,
checkpoint, recovery, backup and restore.

### Evidence and Trust Core

Owns provenance references, trust states, append-only transition history,
revocation/expiry semantics and the public trust invariants.

### Typed Topological and Wave Engine

Owns typed edges, bounded Wave queries, masks, energy propagation, TopK,
predecessor evidence and subgraph results.

### Execution Engine

Owns CPU execution, optional accelerator backends, parity validation, hardware
calibration, snapshot lifecycle and unconditional CPU fallback.

### Protocol and Editions

Expose the same canonical engine through native CLI, Python, daemon and C ABI.

## Target workspace

```text
crates/
  ultraballoondb-core/
  ultraballoondb-storage/
  ultraballoondb-wal/
  ultraballoondb-wave/
  ultraballoondb-gpu/
  ultraballoondb-router/
  ultraballoondb-trust/
  ultraballoondb-provenance/
  ultraballoondb-protocol/

editions/
  ultraballoondb-exe/
  ultraballoondbd/
  ultraballoondb-pyo3/
  ultraballoondb-c-abi/
```

This target is implemented additively. Existing compatibility paths remain until
their replacements pass full regression.

## Innovation Kernel and Enterprise Shell

The Innovation Kernel contains typed topology, deterministic Wave semantics,
evidence/trust guarantees and safe accelerated execution.

The Enterprise Shell contains operational capabilities such as transactions,
recovery, access control, observability, deployment and support tooling.

Enterprise capabilities may wrap, authorize, schedule and observe the kernel.
They may not redefine canonical storage, Trust or Wave semantics.
