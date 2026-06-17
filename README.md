# UltraBalloonDB

UltraBalloonDB is an original deterministic database and memory engine for agent infrastructure.

It is built from BalloonDB benchmark evidence and extends the foundation toward typed topological wave memory.

## Core Position

UltraBalloonDB is not an AI agent and does not contain agent reasoning.

The database layer is responsible for:

- typed nodes and typed edges
- deterministic topological wave activation
- edge attenuation and edge blocking
- relation algebra over edge types
- compact hot snapshots
- generic lossless edge archive
- page-store and payload storage
- batch/coalesced payload fetch
- crystallization of repeated graph structures
- deterministic floating subgraph export/import

The agent layer is responsible for:

- meaning
- user intent
- policy
- query parameter selection
- semantic summaries
- LLM/VLM/ASR/TTS calls
- business decisions
- communication strategy between agents

## Main Primitive

```text
wave_activation(seed_node, edge_mask, energy_threshold, top_k, rigor_multiplier)
```

The database injects energy into a seed node and propagates it through typed edges. Every edge type has a deterministic attenuation factor. Blocking edges stop propagation. The result is a bounded ranked set of node IDs and path evidence.

## Hot Path

```text
seed -> wave_activation -> top_k node IDs -> batch payload fetch -> agent context
```

The database must not fetch hundreds of payloads by default. Payload fetch is bounded by `top_k` and executed through batch/coalesced reads.

## Cold Path

```text
full page-store + generic lossless edge archive -> offline rebuild -> hot snapshot
```

The full archive remains the source of truth. The hot snapshot is the fast working memory artifact.

## First Milestones

```text
V00A repo bootstrap
V00B wave_activation benchmark
V00C edge attenuation table
V00D top_k batch/coalesced payload fetch
V00E edge-type relation algebra
V00F crystallization paths
V00G hot snapshot + archive split
V00H floating subgraph export/import
V00I page-size benchmark: 4 KB / 16 KB / 64 KB / 256 KB
```

<!-- ULTRABALLOONDB:RUST-DELIVERY-ARCHITECTURE:START -->

## Rust core and product delivery architecture

UltraBalloonDB uses **one canonical Rust core** with multiple delivery modes:

1. Pure Rust binary
2. PyO3 native Python extension
3. Isolated Rust daemon/service
4. Stable C ABI embedded library

The database format, WAL contract, typed-edge semantics, wave activation, path evidence, and correctness gates remain shared across all editions.

See: [V00R3A Shared Rust Core and Delivery Modes Architecture](docs/V00R3A_SHARED_RUST_CORE_AND_DELIVERY_MODES_ARCHITECTURE.md)

<!-- ULTRABALLOONDB:RUST-DELIVERY-ARCHITECTURE:END -->

