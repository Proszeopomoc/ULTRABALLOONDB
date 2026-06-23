# UltraBalloonDB R4.9E9 — ogbn-arxiv validation semantic exact baseline result

## Status

`PASS_ULTRABALLOONDB_V00R4_9E9_OGBN_ARXIV_VALIDATION_SEMANTIC_EXACT_BASELINE_EXECUTION`

Authoritative execution revision: **R04**
Source repository HEAD: `173008034ba7f8994e15e426420fcfa99d8c3d58`

This document publishes the first full validation semantic-only exact baseline for the frozen
`ogbn-arxiv` retrieval profile. It is a baseline gate result, not a claim that the complete
UltraBalloonDB product or the future hybrid ranking path is finished.

## Execution identity

- Backend: `CPU_EXACT`
- Kernel: `RUST_CPU_EXACT_PRODUCT_BIT_PARITY_CERTIFIED_R04_BUILD_ID_LOCKED`
- Queries: `29,799` official validation nodes
- Candidates: `90,941` official train nodes
- Dimension: `128`
- `top_k`: `10`
- Shards: `30`
- Threads: `6`
- Product parity probes: `30 / 30` exact
- ANN: disabled
- Hybrid fusion: disabled
- Native structural space: disabled
- Test set: not executed

## Numeric source-of-truth contract

The committed machine-readable source of truth is the exact frozen artifact:

`specs/benchmarks/r4_9e9_ogbn_arxiv_validation_semantic_exact_baseline_metrics.json`

It is copied byte-for-byte from the benchmark output and must retain SHA256:

`CBB457AD96D162281086B2769B4E5456D96F4B534C19EC32DB6EB5B63762D189`

No rounded metric value in this document may be used for replay, hashing, comparison, or further calculation.

Human-readable presentation is derived deterministically from raw JSON decimal tokens using
decimal `ROUND_HALF_EVEN`:

- quality metrics: 12 decimal places,
- operational metrics: 6 decimal places.

## Quality metrics

| Metric | Result |
|---|---:|
| Precision@10 | `0.397030101681` |
| Top-1 accuracy | `0.455518641565` |
| MRR | `0.578248843974` |
| NDCG@10 | `0.408140289474` |

## Operational metrics

| Metric | Result |
|---|---:|
| Latency p50 | `18.726500 ms` |
| Latency p95 | `34.357710 ms` |
| Latency p99 | `43.201442 ms` |
| Throughput | `285.576277 queries/s` |

## Leakage and evaluation boundaries

The executor did not receive labels or ground truth. Evaluation occurred only after all shard
results were frozen. The candidate universe remained train-only. Canonical database output,
benchmark definition, preflight data, staging data, repository files, and Git history were not
changed during benchmark execution.

## R04 build identity closure

R04 closed stale Cargo executable reuse by binding compilation to a unique crate identity and a
source-hash-derived target directory.

- Build ID: `R4_9E9_R04`
- Crate: `ultraballoondb-r4-9e9-executor-r04-0.0.4`
- Executable SHA256: `1ED439D07BF19BA94F260B5DA6631936E2E7ADC6F2CCF4EDEC29B9F006A6C15D`
- Executor source SHA256: `A559D439FDA9F3759B74DD5A2008AA236F6C60FC935D4C3C0BDE97541156FC4E`
- Pre-execution file smoke: PASS

## Evidence digests

- Execution report: `437D35261BFF52808A9A01E4BBB20ABA121CBFA2B57A11F35BEF8CA795EC3F18`
- Evidence ZIP: `52BB4620E41684379AB6E831D20EABA4DBA9F0D2A5C2A9D4612B394B87842DFA`
- Final manifest: `5230A3178D72D9AFE306C0C500AA001F702F039CDBADFB73481F0146C59C7E11`
- Results freeze manifest: `CA03053CB1711FFEE07798ABEB8EC5F4A4D720E1D0F05DB91369FC28C5E97824`
- Metrics: `CBB457AD96D162281086B2769B4E5456D96F4B534C19EC32DB6EB5B63762D189`

Large shard results and the evidence ZIP remain outside the Git repository. Their immutable
digests are published here and in the benchmark result specification.

## Claim boundary

This result supports only the frozen **validation semantic-only exact CPU baseline**. It does not
support a hybrid superiority claim, a test-set quality claim, an ANN claim, a whole-database
superiority claim, or final product-readiness language.

## Next gate

`R4_9E10_OGBN_ARXIV_VALIDATION_SEMANTIC_BASELINE_POST_EXECUTION_CONFORMANCE_READ_ONLY`
