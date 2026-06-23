# R4.9D Engine Purpose and Benchmark Fit Freeze

## Status

This document freezes product meaning before any further quality benchmark is
executed.

Exact product base:

- HEAD/origin/main:
  `9a91e120cbe3df6110915c443aa569cdbf76f20a`
- product engine:
  `ultraballoondb-hybrid-engine`
- public entry point:
  `execute_product_hybrid_query`

R4.9D does not execute a benchmark and does not claim superiority.

## 1. Product boundaries

UltraBalloonDB is a database product with multiple distinct execution
components. A benchmark result belongs only to the component and use case that
the benchmark actually exercises.

The database core, semantic retrieval, hybrid retrieval, Trust, deterministic
execution, code generation, broad-knowledge retrieval, and creative generation
must not be collapsed into one score.

## 2. Current product engine

### 2.1 Frozen identity

The current product-bound engine is:

`ULTRABALLOONDB_PRODUCT_HYBRID_ENGINE_V1`

Its frozen purpose is:

> Deterministic retrieval and ranking of database records by combining external
> semantic similarity, native structural similarity, and Wave/topological
> evidence over one bound database snapshot, while keeping Trust outside the
> numeric ranking score and returning an auditable receipt.

### 2.2 Input contract

The engine consumes:

- a durable database read snapshot;
- an anchor record;
- an external semantic query vector;
- an external semantic vector space;
- a native structural vector space;
- a graph snapshot bound to the same database snapshot;
- a graph-scope configuration;
- frozen fusion weights;
- a Trust eligibility filter;
- a requested top-k.

### 2.3 Output contract

The engine returns:

- a deterministic ranked list of database records;
- component scores for external semantic, native structural, and Wave evidence;
- a product hybrid receipt;
- exact CPU or parity-certified OpenCL backend evidence;
- graph/database snapshot binding;
- Trust-filter and Trust-ledger evidence;
- deterministic tie-break evidence;
- explicit `trust_in_numeric_score=false`;
- explicit `ann_used=false`.

### 2.4 What the current engine does not own

The current engine does not own:

- embedding-model training;
- query text-to-vector generation;
- approximate nearest-neighbour indexing;
- natural-language answer generation;
- code generation;
- autonomous patch generation or test repair;
- creative generation;
- model factual knowledge;
- cross-database policy learning.

Those capabilities require separate engines or profiles and separate
benchmarks.

## 3. Engine and component portfolio

### 3.1 Canonical database core

Purpose:

- durable records and typed graph edges;
- transactions;
- WAL, checkpoint, recovery, and restart determinism;
- snapshot binding;
- lifecycle and migration guarantees.

Benchmark class:

- database correctness, durability, recovery, concurrency, throughput, latency,
  restart determinism, and storage efficiency.

Retrieval-quality scores must not be used as a substitute for database-core
conformance.

### 3.2 Exact semantic retrieval component

Purpose:

- exact retrieval over vectors already stored in the database;
- deterministic CPU/OpenCL routing;
- exact CPU/GPU parity where OpenCL is selected.

Benchmark class:

- exactness against brute force;
- top-k identity;
- deterministic repeatability;
- p50/p95 latency and throughput;
- memory and transfer cost;
- CPU/OpenCL crossover.

Embedding quality belongs to the embedding model, not to the database.

### 3.3 Product hybrid retrieval engine

Purpose:

- improve record retrieval when useful evidence exists in both semantic content
  and database structure;
- combine semantic, native structural, and Wave/topological evidence;
- remain deterministic and receipt-producing;
- keep Trust outside numeric score.

Primary benchmark class:

- paired hybrid retrieval on real records with a real imperfect graph;
- semantic-only versus hybrid comparison on the same query set;
- graph-only, native-only, Wave-only, and fusion ablations;
- frozen validation-only weight selection;
- locked test set;
- deterministic repeated runs.

### 3.4 Wave/topological component

Wave/topological execution is an active internal scoring component, not a
separate public generative engine.

It may be tested through ablations and propagation-specific fixtures, including:

- multi-hop evidence;
- typed-edge masks;
- missing edges;
- noisy edges;
- disconnected components;
- candidate-limit behavior;
- propagation termination.

Its component result must not be presented as a whole-product benchmark.

### 3.5 Trust control plane

Trust is a control plane, not a relevance-ranking engine.

Allowed Trust benchmarks:

- authorization correctness;
- key rotation and revocation;
- ledger integrity;
- provenance;
- receipt verification;
- fail-closed behavior.

Forbidden attribution:

- increasing nDCG, Recall, MRR, or hybrid numeric score through Trust weights,
  boosts, penalties, or multipliers.

### 3.6 Deterministic execution contract

Determinism is a cross-cutting product invariant.

Allowed measurements:

- byte-stable receipts after normalization of runtime paths;
- identical top-k and component scores;
- stable tie-break behavior;
- CPU/OpenCL exact parity;
- restart-stable database state;
- exact release and snapshot identity.

Determinism is not a separate retrieval-quality engine.

## 4. Future or domain-specific engines and profiles

### 4.1 Code bug-localization profile

Bench4BL is allowed only as a domain-specific profile of the hybrid retrieval
engine:

`CODE_BUG_LOCALIZATION_SEMANTIC_AND_GRAPH_RETRIEVAL_PROFILE`

It measures whether a query describing a defect ranks relevant source files or
entities.

It does not measure:

- code writing;
- patch generation;
- repository repair;
- autonomous testing;
- full database quality;
- general broad-knowledge retrieval;
- creative generation.

Execution remains blocked until the temporal mapping and ground-truth semantics
are resolved without weakening leakage protection.

### 4.2 Code-writing and repair agent

No code-writing or autonomous repair engine is currently product-bound.

Therefore agentic software-repair benchmarks are forbidden for the current
hybrid engine.

Such a benchmark becomes valid only after a separate engine can:

- read a repository and issue;
- generate a patch;
- execute tests;
- revise the patch;
- return a final change and evidence.

### 4.3 Broad-knowledge retrieval profile

A broad-knowledge profile is not yet frozen.

It would require:

- a heterogeneous multi-domain corpus;
- long-document and short-document cases;
- paraphrases and specialist terminology;
- ambiguous queries and distractors;
- multilingual cases where applicable;
- explicit separation of embedding-model quality from database execution.

It must be frozen as its own profile before execution.

### 4.4 Creative generation engine

No creative generation engine is currently product-bound.

Creativity, novelty, useful recombination, and generated-output quality cannot
be attributed to the current retrieval engine.

A future creative engine must have its own generator, memory interface,
evaluation protocol, and baselines.

## 5. Frozen benchmark fit for the current hybrid engine

### 5.1 Primary claim under test

The first product-level quality claim may test only:

> On a fixed corpus, fixed external embeddings, fixed graph, fixed queries,
> fixed Trust eligibility, and frozen fusion configuration, the product-bound
> hybrid engine improves retrieval ranking over semantic-only exact retrieval
> without sacrificing determinism, snapshot integrity, Trust separation, or
> declared latency bounds.

### 5.2 Required baselines

Every primary hybrid benchmark must include:

1. semantic-only exact retrieval;
2. native-structural-only retrieval;
3. Wave/topological-only retrieval;
4. graph-only evidence where separately representable;
5. full product hybrid retrieval;
6. at least one fusion ablation;
7. exact repeated-run verification.

The same records, query set, Trust eligibility, and test split must be used for
all comparable paths.

### 5.3 Required quality metrics

Primary quality metrics:

- nDCG@k;
- Recall@k;
- MRR;
- Top-k hit rate where a single relevant target exists.

Required operational metrics:

- p50 and p95 end-to-end latency;
- throughput;
- CPU/OpenCL backend selection;
- host packing and transfer cost where OpenCL is used;
- exact parity;
- repeatability;
- error and fail-closed counts.

### 5.4 Required graph conditions

The benchmark must include an imperfect graph, not only an oracle graph.

Required profiles:

- natural observed graph;
- deterministic edge dropout;
- deterministic irrelevant-edge noise;
- disconnected or sparse cases.

The exact profile construction must be frozen before test execution.

### 5.5 Required statistical discipline

- corpus and query eligibility frozen before execution;
- train/validation/test boundaries frozen;
- fusion parameters selected only on validation;
- test set locked;
- paired comparisons on identical queries;
- confidence intervals or paired bootstrap for quality deltas;
- leakage verification;
- no test-driven threshold changes.

## 6. Prohibited claims

A result from the current hybrid benchmark must not be presented as proof that:

- UltraBalloonDB is the fastest database in general;
- the embedding model is better than other embedding models;
- the product writes or repairs code;
- the product has broad factual knowledge;
- the product is creative;
- Trust improves relevance;
- ANN quality has been achieved;
- one code dataset proves all-domain retrieval quality;
- one benchmark completes the whole product.

## 7. Reclassification of prior benchmark work

The earlier Bench4BL-oriented R4.9A/B work is reclassified as preparation for a
secondary code bug-localization profile.

It is not the primary benchmark of the whole database and is not a benchmark of
a code-writing engine.

Its valid future name is:

`CODE_BUG_LOCALIZATION_SEMANTIC_AND_GRAPH_RETRIEVAL_BENCHMARK`

Its execution remains blocked until ground-truth and temporal mapping semantics
are closed.

## 8. Next gate

The next gate is:

`R4_9E_PRIMARY_HYBRID_RETRIEVAL_BENCHMARK_DATASET_BINDING`

That gate must select and bind the primary corpus, query ground truth, real
graph, licenses, splits, leakage rules, and exact baselines without executing
the locked test.
