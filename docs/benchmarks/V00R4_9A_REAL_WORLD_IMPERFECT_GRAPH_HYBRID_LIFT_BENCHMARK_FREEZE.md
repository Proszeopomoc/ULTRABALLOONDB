# UltraBalloonDB V00R4.9A
## Real-world imperfect-graph hybrid-lift benchmark freeze

Status: **benchmark protocol frozen; execution not yet performed**

This milestone defines the first benchmark intended to measure UltraBalloonDB's
distinctive value over semantic retrieval alone:

> How much does the native graph/Wave path improve file localization over the
> same real embeddings and the same candidate universe?

A PASS of this milestone does not claim hybrid superiority. It only freezes an
auditable protocol before any benchmark result is known.

## 1. Research question

Primary question:

`HYBRID_SEMANTIC_WAVE` versus `SEMANTIC_ONLY`

Secondary controls:

- `GRAPH_ONLY`
- `SEMANTIC_PLUS_STATIC_GRAPH`
- `SEMANTIC_PLUS_COCHANGE`
- `SEMANTIC_PLUS_WAVE`
- `SEMANTIC_PLUS_STRUCTURAL`
- `FULL_HYBRID`

The benchmark must report absolute and relative lift for MRR, MAP, nDCG@10,
Recall@1, Recall@5, and Recall@10.

## 2. External corpus

Primary source:

- Bench4BL
- upstream repository: `https://github.com/exatoa/Bench4BL`
- frozen upstream branch: `master`
- expected upstream commit prefix at protocol freeze: `5480cb0`
- the intake gate must resolve and record the full 40-character commit hash
- archives must be downloaded from the links declared by that exact upstream
  snapshot
- every archive must be recorded with URL, byte size, and SHA256 before use

Frozen first cohort:

1. Commons CODEC
2. Commons COLLECTIONS
3. Commons COMPRESS
4. Commons CONFIGURATION
5. Commons CSV
6. Commons IO
7. Commons LANG
8. Commons MATH

No report may be manually added or removed after seeing retrieval results.

## 3. Unit of evaluation

One query is one real bug report.

Candidate units are production Java source files from the source snapshot mapped
to the bug report by Bench4BL.

Ground truth is the set of production source files identified by the benchmark
as files modified to fix that report.

Test files, documentation-only files, generated sources, vendored sources, and
build artifacts are not candidates and cannot be ground truth.

## 4. Eligibility gates

A report is eligible only when all conditions hold:

- non-empty bug summary or description;
- a mapped source-code version exists;
- at least one production Java ground-truth file exists;
- every ground-truth path exists in the mapped candidate snapshot;
- the candidate universe contains at least 20 production Java files;
- the report is not marked duplicate, invalid, or non-bug;
- the report and answer metadata parse without lossy encoding replacement;
- the report does not explicitly contain a full ground-truth file path;
- no answer file is injected into a query, graph seed, embedding document, or
  graph edge.

All exclusions must be reported by project and reason before scoring.

## 5. Temporal and leakage contract

For each query, the observable world ends at its mapped buggy source snapshot.

Allowed:

- source text present in that snapshot;
- package declarations, imports, type names, method signatures, comments, and
  Javadocs present in that snapshot;
- repository history strictly older than or equal to the snapshot cutoff;
- previous bug-fix history whose fixing commit precedes the cutoff.

Forbidden:

- the fixing commit for the current query;
- files changed by the current fix as graph seeds or special metadata;
- future commits or future issue comments;
- post-fix source;
- labels derived from the answer set;
- duplicate-report links that reveal the current answer;
- fitting fusion weights on the test partition.

The execution gate must generate an independent leakage report and fail closed
when any forbidden relation is observed.

## 6. Chronological partition

Partition separately inside each project:

- earliest 60% eligible reports: calibration/train;
- next 20%: validation;
- latest 20%: locked test.

Ordering key:

1. report creation timestamp;
2. mapped source snapshot timestamp;
3. stable report identifier as final tie-break.

Projects with fewer than 30 eligible reports after filtering are excluded from
the first cohort and reported, not replaced manually.

The test partition remains untouched until document construction, graph
construction, fusion configuration, and validation selection are complete.

## 7. Semantic representation

Embedding runtime:

- FastEmbed `0.8.0`;
- model `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2`;
- dimension `384`;
- normalized float32 vectors;
- exact UltraBalloonDB semantic router;
- ANN disabled;
- Trust excluded from score.

Bug query text:

`summary + "\n" + description`

File document, in deterministic order:

1. relative path;
2. package declaration;
3. imported package/type names;
4. declared class, interface, enum, and annotation names;
5. method and constructor signatures;
6. comments and Javadocs;
7. remaining source text.

Deterministic chunking:

- normalize line endings to LF;
- UTF-8;
- 1,800 Unicode characters per chunk;
- 200-character overlap;
- no semantic truncation;
- embed every chunk;
- file vector is the L2-normalized arithmetic mean of its normalized chunk
  vectors.

The semantic baseline performs exact file-level ranking over the complete
candidate universe for that query.

## 8. Natural imperfect graph

The graph is built independently for every mapped source snapshot.

Node types:

- FILE
- PACKAGE
- DECLARED_SYMBOL

Allowed edge types:

- `FILE_IN_PACKAGE`
- `FILE_IMPORTS_FILE`
- `FILE_IMPORTS_PACKAGE`
- `FILE_DECLARES_SYMBOL`
- `FILE_REFERENCES_SYMBOL`
- `HISTORICAL_COCHANGE`

Graph construction uses static parsing plus history available before the cutoff.
No build, test execution, answer metadata, or fixing commit is required.

The natural graph is expected to be incomplete:

- unresolved imports remain unresolved;
- reflection and dynamic dispatch are not guessed;
- generated code is excluded;
- ambiguous symbol references may be omitted;
- co-change is evidence, not proof of dependency.

Historical co-change rules:

- only commits at or before the cutoff;
- ignore merge commits;
- ignore commits touching more than 50 production files;
- minimum two independent co-change observations;
- edge weight is normalized pointwise mutual information, clipped to `[0,1]`;
- current query fixing commit is forbidden.

## 9. Query modes

### SEMANTIC_ONLY

Exact semantic ranking over all candidate files.

### GRAPH_ONLY

Seeds are created only from literal report tokens matching package, file, type,
or method identifiers. No embedding score is used.

### SEMANTIC_PLUS_STATIC_GRAPH

Semantic top-200 files seed propagation over static graph edges only.

### SEMANTIC_PLUS_COCHANGE

Semantic top-200 files are re-ranked using only historical co-change evidence.

### SEMANTIC_PLUS_WAVE

Semantic top-200 files seed the native Wave engine over all allowed natural
graph edges.

### SEMANTIC_PLUS_STRUCTURAL

Semantic score is fused with the existing native structural-vector score.

### FULL_HYBRID

Semantic exact + native Wave + structural vectors + deterministic fusion.

All modes use the same candidate universe and the same ground truth.

## 10. Fusion policy

No per-query learning is allowed.

A finite global validation grid is frozen:

- semantic weight: `0.50, 0.65, 0.80`
- Wave weight: `0.10, 0.20, 0.30`
- structural weight: `0.00, 0.10, 0.20`
- path-length decay: `0.50, 0.70, 0.85`
- maximum Wave steps: `2, 3, 4`
- semantic seed count: `100, 200, 500`

Only configurations whose weights sum to `1.0` are eligible.

Selection metric:

1. highest macro validation nDCG@10;
2. then highest macro validation MRR;
3. then lower p95 latency;
4. then higher semantic weight;
5. then fewer Wave steps.

The selected single configuration is frozen before opening the test partition.

## 11. Imperfect-graph stress profiles

Every locked-test query runs under:

- `NATURAL`
- `EDGE_DROPOUT_10`
- `EDGE_DROPOUT_25`
- `DEGREE_MATCHED_NOISE_10`

Deterministic edge dropout:

`SHA256(project_id || query_id || edge_type || source || target)`

Noise edges:

- same project and source root;
- absent from the natural graph;
- degree-matched by edge type;
- deterministic SHA256 selection;
- no use of ground truth.

## 12. Metrics

Quality:

- Recall@1
- Recall@5
- Recall@10
- MRR
- MAP
- nDCG@10
- mean first-relevant rank
- median first-relevant rank

Lift:

- absolute hybrid-minus-semantic lift;
- relative hybrid-over-semantic lift;
- per-project lift;
- macro-project lift;
- micro-query lift;
- percentage of queries improved;
- percentage unchanged;
- percentage harmed.

Runtime:

- p50, p95, p99 latency;
- candidate count;
- semantic backend and receipt;
- CPU policy selection count;
- true GPU fallback count;
- Wave nodes visited;
- Wave edges traversed;
- graph build time and size;
- peak resident memory where available.

Statistics:

- 10,000 deterministic paired bootstrap samples;
- 95% confidence interval for MRR and nDCG@10 lift;
- paired randomization test;
- project is the primary aggregation unit.

## 13. Outcome classification

`HYBRID_ADVANTAGE_STRONG`

- test macro nDCG@10 absolute lift at least `+0.05`;
- relative macro nDCG@10 lift at least `+10%`;
- macro MRR lift positive;
- at least 6 of 8 projects positive, or all eligible projects when fewer remain;
- paired 95% CI lower bound above zero;
- NATURAL and EDGE_DROPOUT_10 both positive;
- p95 latency no more than 3x semantic baseline.

`HYBRID_ADVANTAGE_MEASURED`

- macro nDCG@10 and MRR lift positive;
- majority of eligible projects positive;
- no leakage;
- EDGE_DROPOUT_10 not materially negative.

`NO_PROVEN_HYBRID_ADVANTAGE`

- quality lift is indistinguishable from zero.

`HYBRID_REGRESSION`

- macro nDCG@10 or MRR is materially negative;
- or most projects regress.

No outcome may be renamed after results are observed.

## 14. Required receipts

Each query result must retain:

- dataset archive SHA256;
- project and report identifier;
- mapped source snapshot;
- temporal cutoff;
- candidate-set SHA256;
- query-text SHA256;
- embedding model and dimension;
- graph SHA256 by stress profile;
- selected fusion configuration SHA256;
- engine scores before fusion;
- semantic, graph, Wave, structural, and final rank;
- all graph paths used for the top-10 hybrid results;
- ground-truth paths only in the scoring receipt, never in execution inputs.

## 15. Required execution stages

1. `R4.9B1_DATASET_INTAKE_AND_LICENSE_PROVENANCE_READ_ONLY`
2. `R4.9B2_TEMPORAL_SNAPSHOT_AND_GROUND_TRUTH_AUDIT_READ_ONLY`
3. `R4.9B3_REAL_EMBEDDING_AND_IMPERFECT_GRAPH_BUILD_READ_ONLY`
4. `R4.9B4_VALIDATION_FUSION_SELECTION_READ_ONLY`
5. `R4.9B5_LOCKED_TEST_HYBRID_LIFT_EXECUTION_READ_ONLY`
6. `R4.9B6_INDEPENDENT_RESULT_AND_LEAKAGE_VERIFIER_READ_ONLY`

No stage may commit generated datasets, source archives, embeddings, project
repositories, or benchmark answers into the UltraBalloonDB repository.

## 16. Interpretation boundary

This benchmark can show that UltraBalloonDB's native hybrid path improves
real-world bug-file localization over its own real-embedding semantic baseline.

It does not by itself prove superiority over every external database, embedding
model, graph system, or commercial product. Cross-product comparison requires a
separate benchmark with equivalent inputs, tuning budgets, and hardware.
