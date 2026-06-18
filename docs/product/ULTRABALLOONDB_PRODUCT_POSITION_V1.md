# UltraBalloonDB Product Position V1

Status: public architecture contract.

UltraBalloonDB is a deterministic, evidence-native, typed topological database.
It combines a durable database store, evidence lineage, auditable trust states,
a native Wave Query Engine and safe adaptive CPU/GPU execution.

## Product boundary

UltraBalloonDB is:

- a full database product with its own formats and lifecycle;
- a canonical Rust engine with multiple delivery editions;
- usable locally, embedded, through Python, through a daemon or through C ABI;
- correct without a GPU and faster where a validated accelerator is available.

UltraBalloonDB is not:

- an agent framework;
- a GraphRAG-only library;
- a wrapper around another database;
- a CUDA-only execution engine;
- a benchmark harness presented as a product.

## Market-facing differentiators

Public positioning may state that UltraBalloonDB provides:

- evidence-native records and provenance;
- strict separation of relevance from trust;
- deterministic typed-topological recall;
- exact-parity CPU/GPU execution gates;
- safe fallback and hardware-local calibration;
- one database engine across multiple delivery modes.

Public positioning must not claim universal superiority or disclose private
validation rules, hidden fingerprint challenges or customer-specific markers.

## Product rule

Every edition must preserve the same storage, trust, Wave and recovery contracts.
Different editions may change transport and hosting, not database semantics.
