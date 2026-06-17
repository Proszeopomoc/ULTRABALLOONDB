# UltraBalloonDB V00R1 — Rust Native CSR/MMAP Wave Core Candidate

## Purpose

Build and benchmark a standalone Rust binary for the current fixed-width CSR/mmap graph format. The candidate performs the complete L2/L3 query and L7 bounded subgraph export inside Rust. It does not call Rust once per edge and does not use PyO3.

## Scope

- L1 CSR range lookup
- L2 typed edge records
- L3 wave activation and predecessor evidence
- L7 bounded floating-subgraph extraction
- Windows and Unix read-only mmap
- identical little-endian node and edge files
- batch benchmark with one native process

## Non-goals

V00R1 does not replace the active Python runtime. It does not yet implement the complete L0-L7 database, WAL, checkpoint, HTTP server, CLI, compaction, or active production binding.

## Dependency policy

The Rust crate uses only the Rust standard library. `Cargo.toml` has no external crates. Platform mmap calls are bound directly to the operating system.

## Gates

Technical PASS requires:

- exact node-file byte parity with Python
- exact edge-file byte parity with Python
- wave-result parity
- floating-subgraph parity
- mmap active
- full-scan counter equal to zero
- no third-party Rust crates

Active promotion additionally requires native batch-query speedup of at least the configured threshold, default `1.25x`.

A technical PASS with `ACTIVE_PROMOTION_READY=FALSE` keeps Python active and triggers profiling instead of replacement.

## Why build speed is diagnostic only

The Python V00P1 builder computes SHA-256 of the full generated files during its build method. V00R1 Rust does not yet include native SHA-256 because external crates are intentionally excluded. Therefore build-time speedup is reported but is not used as the promotion gate in this milestone.
