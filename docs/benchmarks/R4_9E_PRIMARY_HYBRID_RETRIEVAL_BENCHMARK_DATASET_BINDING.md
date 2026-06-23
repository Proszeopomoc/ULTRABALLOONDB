# R4.9E Primary Hybrid Retrieval Benchmark Dataset Binding

## Status

This milestone binds the first primary product-level retrieval benchmark for the
post-commit verified engine:

- engine: `ULTRABALLOONDB_PRODUCT_HYBRID_ENGINE_V1`;
- crate: `ultraballoondb-hybrid-engine`;
- entry point: `execute_product_hybrid_query`;
- exact base HEAD/origin/main:
  `eb6bf130073ed8ab18b4c4bef78b4bbc346a429f`.

R4.9E is a protocol and provenance freeze. It does **not** download the
dataset, build a database, generate embeddings, execute validation or test
queries, or make a quality claim.

## 1. Bound dataset

The primary dataset is Open Graph Benchmark `ogbn-arxiv`, upstream dataset
version 1.

The official OGB description defines:

- 169,343 Computer Science arXiv papers;
- 1,166,243 directed citation edges;
- a 128-dimensional feature vector derived from paper titles and abstracts;
- 40 author/moderator-assigned primary subject categories;
- a temporal split: training through 2017, validation in 2018, and test from
  2019 onward;
- dataset license: ODC-BY.

Official sources:

- `https://ogb.stanford.edu/docs/nodeprop/`
- official registry URL: `http://snap.stanford.edu/ogb/data/nodeproppred/arxiv.zip`
- required TLS download URL: `https://snap.stanford.edu/ogb/data/nodeproppred/arxiv.zip`
- `https://raw.githubusercontent.com/snap-stanford/ogb/master/ogb/nodeproppred/master.csv`

The registry snapshot observed while freezing this protocol has SHA-256:

`E2AE8CDBC995E8E07EF801711D6EDA01316FED1EBBE68BCF0A522686E20AAA3D`

The archive digest is deliberately not guessed. R4.9E1 must download the
official artifact read-only, record exact bytes, verify its internal structure
and bind its SHA-256 before any materialization.

## 2. UltraBalloonDB derived task

OGB's official task is node subject classification. UltraBalloonDB does not
rename that task as an official OGB retrieval benchmark.

The bound derived task is:

`GRAPH_SCOPED_PRIOR_PAPER_SAME_PRIMARY_CATEGORY_RETRIEVAL`

For each query paper, the engine ranks prior corpus papers inside an identical
Wave-generated candidate universe. A candidate is evaluation-relevant when its
official primary subject category equals the query paper's category. Labels are
kept in an evaluation-only ledger and may not enter semantic vectors, native
structural vectors, the natural graph, Trust, or numeric ranking.

The claim is restricted to this scientific-paper retrieval profile. It cannot
be used as evidence of broad factual knowledge, code writing, code repair,
creativity, ANN quality, embedding-model superiority, or general database
superiority.

## 3. Temporal snapshots and leakage protection

Validation snapshot:

- corpus: official train nodes only;
- anchors: official validation nodes only;
- allowed edges: corpus-to-corpus and validation-anchor-to-corpus;
- forbidden edges: corpus-to-validation-anchor and validation-to-validation.

Test snapshot:

- corpus: official train plus validation nodes;
- anchors: official test nodes only;
- allowed edges: corpus-to-corpus and test-anchor-to-corpus;
- forbidden edges: corpus-to-test-anchor and test-to-test.

This deliberately removes future inbound information. Query anchors are never
eligible as returned candidates.

The validation configuration is selected once. The locked test configuration
must be written to a receipt before the first test query. Test-driven
reselection, threshold changes, or query replacement are forbidden.

## 4. Comparable ranking paths

All comparable paths use the same records, query anchors, graph-scoped
candidate universe, Trust eligibility, top-k, and snapshot.

Required paths:

1. semantic-only exact: `(external=1, native=0, wave=0)`;
2. native-structural-only: `(0,1,0)`;
3. Wave/topological-only: `(0,0,1)`;
4. external plus Wave ablation: `(1,0,1)`;
5. external plus native ablation: `(1,1,0)`;
6. full hybrid selected only from the frozen seven-point validation grid.

A second graph-only score is not separately representable in the current
public engine because Wave is its sole graph-derived numeric signal. It is
therefore recorded as not separable rather than fabricated.

## 5. Query selection

Queries are selected deterministically before engine results exist:

- 256 validation anchors;
- 512 test anchors;
- at least 64 graph-scoped candidates;
- at least 5 relevant candidates;
- ascending SHA-256 of
  `R49E_QUERY\0 + split + \0 + record_id`.

Failure to meet a target count is fail-closed. No easier replacement query may
be substituted after results are seen.

## 6. Graph profiles

The primary claim uses the natural temporal citation graph.

Robustness-only profiles are:

- deterministic 10% edge dropout;
- deterministic 10% adversarial cross-label non-edge noise;
- deterministic disconnection of 10% of query anchors.

The adversarial noise profile may use labels only while constructing corrupted
edges. Labels are then removed before engine execution. This profile is never
used for parameter selection and cannot support the primary natural-graph
claim.

## 7. Metrics and pass condition

Quality metrics include nDCG@10/50, Recall@10/50/100, MRR and top-10 hit rate.
Operational metrics include p50/p95 end-to-end latency, throughput, backend
selection, packing and transfer cost, exact parity, repeatability and
fail-closed counts.

The primary natural-graph claim passes only when:

- mean full-hybrid minus semantic-only nDCG@10 is positive;
- the lower bound of a deterministic 10,000-resample paired 95% bootstrap is
  positive;
- MRR does not regress;
- full-hybrid p95 latency is at most 3x semantic-only p95;
- there are zero determinism, snapshot-binding, Trust-separation or exactness
  violations.

A failed lift is a valid benchmark result and must not trigger protocol changes.

## 8. Licensing and redistribution

The bound dataset is marked ODC-By-1.0 by OGB and requires attribution.
R4.9E authorizes no redistribution of raw title/abstract text. The optional
title/abstract mapping is not required for locked execution. The official
128-dimensional features are the frozen external semantic space; their quality
is not attributed to UltraBalloonDB.

## 9. Bench4BL

Bench4BL remains a secondary code bug-localization retrieval profile. Its
temporal ground-truth semantics remain unresolved, so this milestone does not
execute or weaken that protocol.

## 10. Next gate

`R4_9E1_OGBN_ARXIV_DATASET_INTAKE_LICENSE_AND_DIGEST_READ_ONLY`

That gate must download only the official artifacts, bind exact digests and
sizes, verify license/provenance and archive structure, and leave the repository,
database, embeddings, graph and Git history unchanged.
