# UltraBalloonDB V00R4 — Recovery and Completion Plan

This file is the single execution plan for V00R4.

## 0. Bound state

```text
historical baseline = 118bdde3d6e6b2e8eaeee6a2bb8ad73cf16b4d11
adjudicated repository HEAD = bed67dc7c03da57fded36f29f7cdc66ab958f0a2
branch = main
HEAD == origin/main = true
commits after baseline = 25
changed paths after baseline = 281
current Rust crates = 20
```

The previous V00R3Z9 result closed an engineering pre-release. It did not close
the original UltraBalloonDB concept because native semantic L8 and active CPU/GPU
routing were not implemented.

No history reset is allowed. Later work is preserved and classified below.

## 1. Current repository map

### Canonical core candidates — KEEP_CORE

```text
ultraballoondb-core
ultraballoondb-lifecycle
ultraballoondb-storage
ultraballoondb-wal
```

Interpretation:

- `ultraballoondb-core` owns typed graph, Wave and query semantics.
- `ultraballoondb-storage`, `ultraballoondb-wal` and
  `ultraballoondb-lifecycle` are existing Rust durability candidates.
- They are not to be rewritten from zero.
- Their actual coverage must be freshly re-derived against the Python reference
  and format/recovery contracts.

### Support and delivery — KEEP_SUPPORT

```text
ultraballoondb-backup
ultraballoondb-cabi
ultraballoondb-cli
ultraballoondb-compat
ultraballoondb-daemon
ultraballoondb-migrate
ultraballoondb-observability-security
ultraballoondb-pyo3
```

These components already exist. They are preserved and later run through one
canonical-core conformance suite. They must not contain independent storage,
WAL, Wave, semantic or router ownership.

### Governance perimeter — FREEZE_PERIMETER

```text
ultraballoondb-provenance
ultraballoondb-trust
ultraballoondb-trust-asymmetric
ultraballoondb-trust-auth
ultraballoondb-trust-commit
ultraballoondb-trust-enterprise
ultraballoondb-trust-federation
```

Code is preserved. No new features are added until R4.1–R4.4 pass.
Relevance, semantic similarity, Wave and CPU/GPU routing remain unable to promote trust.

### Compatibility shim — CONTROLLED RETIREMENT

```text
ultraballoondb_rust_core
```

`ultraballoondb_rust_core` is a three-line historical executable shim.
`ultraballoondb-cli` already exists. Do not create a second CLI. Retain the old
shim only for compatibility until the native command conformance gate proves
that it can be retired or converted into an alias.

## 2. Proven completed work that is not to be repeated

The following milestones are present as committed Rust code/evidence and are
not listed as missing implementation stages:

```text
T6C  provider abstraction and enterprise federation
P0   provenance core
C1   backup / restore / upgrade dry-run
D2   daemon and protocol
D3   C ABI
D4   PyO3
E1   observability and security
G1   release packaging
Z9   engineering pre-release closure audit
```

Their code is preserved. Their claims must later be re-derived against the
completed V00R4 core.

## 3. Actual missing product pillars

### A. Native semantic L8 — ABSENT

No Rust semantic crate/module, semantic index or `find_similar` API exists.

Target:

```text
L8 = derived semantic relevance over hash-stable records
```

V1 features must be derived from UltraBalloonDB-native structure:

- typed-edge distributions;
- bounded Wave reachability, energy and path evidence;
- G-family/co-occurrence structure.

Hard rules:

- record identity remains the canonical hash;
- rebuild/reprojection/re-layout changes no record ID;
- similarity never changes trust;
- exact scan is the correctness baseline before optimized indexing;
- no external embedding model is required in V1.

### B. Active CPU/GPU execution — SHADOW/EVIDENCE ONLY

B1–B5 evidence exists, but no GPU crate/backend or active router exists.

Target:

- canonical CPU implementation remains owner and unconditional fallback;
- GPU uses a read-only derived snapshot;
- crossover is measured on current hardware;
- exact result parity is mandatory;
- stale snapshot, VRAM and GPU failure force CPU;
- routing is deterministic from declared workload properties.

### C. One store, three query modes — ABSENT

```text
TOPOLOGICAL
SEMANTIC
HYBRID
```

HYBRID:

```text
semantic candidate recall
-> typed Wave/path verification
-> evidence/trust filtering
-> deterministic ranking
```

## 4. Ordered execution gates

### R4.0A — plan installation and scope freeze

Install this plan, crate ownership V2 and freeze manifest without modifying Rust code.

Gate:

```text
PASS_V00R4_0A_SINGLE_SOURCE_PLAN_INSTALLED
```

### R4.1A — canonical Rust core conformance and gap audit

Read-only/fresh execution first:

- `cargo check --workspace --all-targets --locked --offline`;
- `cargo test --workspace --all-targets --locked --offline`;
- inventory public storage/lifecycle/WAL/query APIs;
- rerun storage, transaction, recovery, migration and compatibility probes;
- compare Rust outputs with Python reference corpus;
- map L0–L7 capability coverage;
- find duplicate or conflicting ownership;
- list only real missing gaps.

No implementation is allowed before this report.

Gate:

```text
PASS_R4_1A_CANONICAL_RUST_CORE_CONFORMANCE_AND_GAP_AUDIT
```


### R4.1B — targeted canonical-core gap closure

R4.1A passed by fresh execution at HEAD
`6db91fc8f2903bd90691356d3a33c4073789cead`.

Proven gaps:

```text
L4 = no unambiguous versioned Rust read snapshot
L6 = no Rust derived-artifact crystallization/inventory
```

R4.1B implements only:

- immutable borrow-scoped `ReadSnapshot`;
- deterministic snapshot descriptor bound to the current state;
- persistent derived-artifact inventory;
- artifact SHA and source-snapshot binding;
- restart recovery of interrupted inventory replacement;
- stale-artifact invalidation after canonical state changes;
- corruption and path-traversal rejection.

It does not implement vectors, semantic ranking, ANN, GPU routing or trust
promotion.

Gate:

```text
PASS_R4_1B_CANONICAL_RUST_L0_L7_DURABILITY_PARITY
```

### R4.2 — model-agnostic Vector Store foundation

Implement VS1 and VS2 over the completed L4/L6 contracts.

VS1:

- `VectorSpaceDescriptor` and deterministic `space_id`;
- external and UltraBalloon-native origins share one storage contract;
- durable vector attachments outside the payload hash;
- bulk idempotent import;
- WAL/checkpoint/recovery/backup coverage;
- record identity and trust invariance.

VS2:

- canonical exact CPU cosine scan;
- deterministic top-k and tie-breaking;
- independent exact-cosine verifier;
- migration-faithfulness report;
- no ANN in the canonical path.

Gate:

```text
PASS_R4_2_VECTOR_STORE_EXACT_MIGRATION_FOUNDATION
```

### R4.3 — graph, trust and native structural semantics

VS3:

- anchor/scope/typed-edge filters;
- Wave candidate narrowing;
- relation and path evidence;
- trust filtering without trust mutation.

VS4:

- native UltraBalloon structural vector space derived from typed graph,
  bounded Wave evidence and G-family/co-occurrence structure;
- same vector column/query contracts as external model spaces;
- deterministic rebuild and record-ID invariance.

VS5:

- TOPOLOGICAL, SEMANTIC and HYBRID modes;
- content similarity and structural similarity remain separately reported;
- trust remains a filter/result property, never a similarity component;
- honest quality and migration benchmark.

Gate:

```text
PASS_R4_3_NATIVE_AND_EXTERNAL_SEMANTIC_HYBRID_QUERY
```

### R4.4 — CPU/GPU productionization

Reuse B1–B5 evidence, but rederive separate crossover models for:

```text
Wave workload   = frontier, edges, depth, seed_count
Vector workload = candidate_count, dimension, query_batch
```

Required:

- canonical CPU result remains the source of truth;
- read-only GPU snapshots are registered in L6;
- snapshot compatibility is checked against L4;
- deterministic router;
- exact CPU/GPU parity;
- stale snapshot, VRAM and GPU failure fallback;
- ANN remains optional, explicit and approximate.

Gate:

```text
PASS_R4_4_ACTIVE_CPU_GPU_ROUTER_WITH_EXACT_PARITY
```

### R4.5 — existing component conformance and perimeter reintegration

- test KEEP_SUPPORT components against the canonical query/storage contract;
- test frozen provenance/trust components for compatibility and trust leakage;
- preserve compatible code;
- quarantine only proven conflicts;
- do not expand perimeter scope.

Gate:

```text
PASS_R4_5_EXISTING_COMPONENT_CONFORMANCE_AND_REINTEGRATION
```

### R4.6 — re-derived release closure

The final audit must freshly execute:

- Cargo check/test;
- storage/WAL/recovery fault matrix;
- Python↔Rust parity;
- CPU/GPU exact parity and fallbacks;
- L8 identity/trust invariance;
- topological/semantic/hybrid conformance;
- CLI/daemon/C ABI/PyO3 conformance;
- backup/restore/upgrade;
- release reproducibility.

Archived booleans are evidence pointers, not proof of their own claims.

Gate:

```text
PASS_V00R4_FINAL_REDERIVED_PRODUCT_CLOSURE
```

## 5. Definition of done

V00R4 is complete only when:

1. one Rust ownership chain controls storage, WAL, recovery and queries;
2. Python is an independent reference, not a second production database;
3. CPU/GPU routing is active with exact parity and CPU fallback;
4. semantic L8 is real, deterministic, hash-stable and trust-neutral;
5. TOPOLOGICAL, SEMANTIC and HYBRID use the same records;
6. existing delivery and governance components pass current conformance;
7. final PASS is freshly executed.

## 6. Immediate next gate

```text
V00R4_1A_CANONICAL_RUST_CORE_CONFORMANCE_AND_GAP_AUDIT_READ_ONLY
```


## 7. Current execution state

```text
R4.0A = PASS, commit 6db91fc8f2903bd90691356d3a33c4073789cead
R4.1A = PASS, evidence SHA256
          76693824A34E20A4756EE5F74185C6F1178CCDB19E3F9E1A350F0E03BDD7B1B0
R4.1A workspace crates = 20
R4.1A duplicate ownership conflicts = 0
R4.1A exact gaps = L4 and L6
R4.1B = PASS when this commit is installed after full local validation
R4.2 = next gate
```

The build order is therefore:

```text
R4.1B core snapshot/inventory
-> R4.2 exact model-agnostic Vector Store
-> R4.3 graph/trust/native semantic HYBRID
-> R4.4 CPU/GPU acceleration
-> R4.5 existing component conformance
-> R4.6 final re-derived closure
```
