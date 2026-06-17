# UltraBalloonDB V00R3A1 — Shared Rust Workspace Extraction

## Role

```text
ROLE=CORE
RUNTIME_IMPACT=STRUCTURAL_REFACTOR_WITHOUT_SEMANTIC_CHANGE
ACTIVE_FULL_RUNTIME_REPLACEMENT=FALSE
```

## Purpose

Extract the verified V00R2 monolithic Rust source into:

```text
rust_native/
  Cargo.toml
  Cargo.lock
  rust-toolchain.toml
  .cargo/config.toml

  ultraballoondb-core/
    Cargo.toml
    src/lib.rs

  ultraballoondb_rust_core/
    Cargo.toml
    src/main.rs
```

`ultraballoondb-core` becomes the one canonical reusable Rust implementation.
`ultraballoondb_rust_core` remains a thin compatibility executable so V00R1 and
V00R2 bindings keep the same binary name and location.

## Preserved contracts

- fixed 24-byte CSR node rows,
- fixed 24-byte CSR edge rows,
- little-endian binary format,
- Windows and Unix mmap,
- L2 typed-edge lookup,
- direct wave semantics,
- L3 path-evidence semantics,
- L7 floating-subgraph export,
- V00R2 line protocol,
- zero full-graph scans,
- no third-party Rust crates,
- active V00R2 Rust query binding with safe fallback.

## Explicitly not included

- canonical writes in Rust,
- Rust WAL ownership,
- Rust checkpoint/recovery ownership,
- PyO3,
- C ABI,
- daemon protocol redesign,
- complete Python removal.

Those belong to later gates.

## Next gate

```text
V00R3B_PURE_RUST_STORAGE_WAL_CHECKPOINT_RECOVERY
```
