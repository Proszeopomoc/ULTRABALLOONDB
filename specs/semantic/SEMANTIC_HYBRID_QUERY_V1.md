# SEMANTIC_HYBRID_QUERY_V1

## Dependency boundary

Required base:

```text
R4.2 PASS
HEAD = 66eb526aad7b1394269d0c66a1a37f5ce0672884
workspace crates = 21
```

R4.3 extends the existing `ultraballoondb-semantic` crate. It does not create
a second graph, Wave, trust, storage, WAL or vector engine.

Canonical owners:

```text
records / edges / ReadSnapshot = ultraballoondb-lifecycle
typed Wave / path semantics    = ultraballoondb-core
vector columns / exact cosine  = ultraballoondb-semantic
trust state                    = ultraballoondb-trust
```

## 1. Graph snapshot binding

A deterministic CSR graph snapshot is materialized from one L4
`ReadSnapshot`:

```text
derived/semantic_graph/<snapshot_sha256>/
  csr_nodes.bin
  csr_edges.bin
  GRAPH_SNAPSHOT.ubgsm
```

The binary manifest binds:

```text
database_snapshot_sha256
record_count
edge_count
nodes_sha256
edges_sha256
```

The manifest is registered as `HOT_SNAPSHOT` in L6. A graph snapshot from a
different canonical database snapshot cannot be used.

The CSR layout is only a derived read accelerator. It does not replace typed
edges in the canonical database.

## 2. Trust boundary

Queries receive an immutable `&TrustLedger`.

Supported filters:

```text
ANY
ACTIVE_ONLY
MATURITY_AT_LEAST
VERIFIED_ACTIVE_ONLY
```

A record without an explicit trust transition is represented as implicit
`RAW + ACTIVE`, unless the caller chooses `EXCLUDE_UNKNOWN`.

Trust is:

- never part of cosine;
- never part of hybrid score;
- never modified by Wave, similarity or ranking;
- returned as a separate result property;
- bound to the ledger head digest used by the query.

## 3. External semantic query

R4.2 external spaces remain unchanged.

```text
semantic_query_exact(
    snapshot,
    vector_store,
    external_space_id,
    query_vector,
    k,
    optional_wave_scope,
    trust_ledger,
    trust_filter
)
```

Without scope this is exact global vector retrieval.

With scope, Wave first creates the allowed record set and exact cosine is
calculated only for those records.

## 4. Native UltraBalloon structural space

R4.3 introduces:

```text
origin = ULTRABALLOON_NATIVE
model_id = ultraballoon-native-structural
model_revision = v1
dim = 48
```

The 48 deterministic features are derived only from:

- typed incoming/outgoing edge distributions;
- degree, weight and reciprocal-link statistics;
- two-hop typed motif/co-occurrence bins;
- canonical L3 Wave energy by path depth;
- canonical L3 Wave path-edge-type bins;
- reachable-count bins.

The full feature vector is L2-normalized and written through the same
R4.2 vector-column API. It is therefore searchable by the same exact cosine
engine.

The native vector column is registered as a `VECTOR_COLUMN` derived artifact
in L6 and bound to the source L4 snapshot.

## 5. Query modes

### TOPOLOGICAL

```text
anchor
-> canonical L3 Wave
-> typed path evidence
-> optional trust filter
```

Ranking:

```text
wave energy descending
record_id ascending for ties
```

### SEMANTIC

```text
query vector
-> exact cosine in one declared space
-> optional Wave candidate scope
-> optional trust filter
```

Ranking remains exact cosine ranking.

### HYBRID

```text
anchor
-> Wave scope
query vector
-> external exact cosine inside scope
anchor native vector
-> native structural exact cosine inside scope
-> deterministic component merge
-> trust filter
```

Components are returned independently:

```text
external_similarity
native_similarity
wave_energy
```

Hybrid score:

```text
cosine_component = clamp((cosine + 1) / 2, 0, 1)
wave_component   = clamp(wave_energy, 0, 1)

score =
  sum(component * declared_weight for available components)
  / sum(declared_weight for available components)
```

Trust is not included in this score.

Ties:

```text
hybrid_score descending
record_id ascending
```

## 6. Evidence returned

A result can include:

```text
record_id
node_id
external cosine
native cosine
wave energy
hybrid score
best path edge-type sequence
direct outgoing edge types
direct incoming edge types
trust maturity
trust validity
explicit / implicit trust source
trust last sequence
trust ledger head digest
database snapshot SHA256
exact vector retrieval flag
```

## 7. Required proofs

- graph snapshot is deterministic and source-snapshot-bound;
- canonical `ultraballoondb-core::Graph::wave_activation_l3` is used;
- no duplicated Wave implementation exists;
- global external semantic retrieval still matches R4.2 exact reference;
- Wave-scoped exact retrieval contains no out-of-scope records;
- native structural space is deterministic across rebuild/restart;
- native vector attachment does not change canonical record identity/state;
- TOPOLOGICAL, SEMANTIC and HYBRID return distinct, deterministic results;
- trust filters work;
- query execution leaves trust transition count and head digest unchanged;
- revoked/disputed/expired records can be excluded without deleting data;
- external similarity, native similarity and Wave energy remain separately
  observable;
- ANN and GPU remain disabled.

Pass marker:

```text
PASS_R4_3_NATIVE_AND_EXTERNAL_SEMANTIC_HYBRID_QUERY
```

Next gate:

```text
V00R4_4_ACTIVE_CPU_GPU_ROUTER_WITH_EXACT_PARITY
```
