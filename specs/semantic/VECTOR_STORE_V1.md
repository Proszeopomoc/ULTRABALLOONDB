# VECTOR_STORE_V1 — model-agnostic exact vector foundation

## Status and dependency

This specification is the first production element of semantic Pillar A.

Required base:

```text
R4.1B PASS
L4 ReadSnapshot implemented
L6 DerivedArtifactInventory implemented
HEAD = 572386fda8774aae3cec527bfc214162996427d9
```

R4.2 implements external/model-provided vector spaces and exact CPU search.
Native structural semantics, graph narrowing, HYBRID query, GPU and ANN remain
outside this gate.

## 1. Identity boundary

Canonical identity remains:

```text
record_id = sha256(canonical payload)
```

Vectors are durable attachments outside the canonical payload hash.

Vector writes:

- do not modify records or typed edges;
- do not modify the canonical database state hash;
- do not change trust;
- do not create a replacement identity.

## 2. Vector-space identity

`model_id + dim` is insufficient because model revisions, preprocessing and
normalization can create incompatible coordinate spaces.

```text
VectorSpaceDescriptor {
    schema_version
    origin               // EXTERNAL_MODEL | ULTRABALLOON_NATIVE
    provider_id
    model_id
    model_revision
    preprocessing_id
    dim
    dtype                // F32 in V1
    metric               // COSINE in V1
    normalization        // NONE | UNIT_L2
}
```

```text
space_id = sha256(canonical descriptor encoding)
```

Only vectors with the same exact `space_id` are compared.

`ULTRABALLOON_NATIVE` is reserved by this format but is not generated in R4.2.

## 3. Physical layout

```text
vectors/
  REGISTRY.ubvs
  COLUMNS/
    <SPACE_ID>.ubvc
```

The registry stores complete descriptors.

Each column stores:

```text
space_id
column_generation
dim
idempotent import receipts
sorted record_id metadata
contiguous float32 matrix
SHA256 footer
```

Record metadata and vector coordinates are separated in the file. Coordinates
are contiguous and suitable for a later mmap/SIMD/GPU scan.

Customer vectors are durable auxiliary data, not rebuildable derived cache.
ANN indexes and GPU snapshots, when introduced later, are derived artifacts
registered through L6.

## 4. Durability

Every registry or column replacement uses a full-image journal:

```text
<target>.journal
<target>.tmp
<target>.bak
```

Sequence:

1. encode and validate the new complete image;
2. write and fsync the journal;
3. write and fsync the temporary target;
4. replace the target through a backup;
5. remove backup and journal only after success.

On open:

- a valid journal is replayed deterministically;
- a completed target matching the journal is accepted and cleanup finishes;
- an interrupted backup replacement is recovered;
- corrupted journal, registry or column fails closed;
- unknown/orphan column files fail closed.

This is a correctness-first foundation. It does not replace the canonical
record/WAL formats.

## 5. API

```text
VectorStore::create(database_root)
VectorStore::open(database_root)
VectorStore::open_or_create(database_root)

create_space(descriptor) -> (space_id, outcome)

put_vector(
    read_snapshot,
    space_id,
    record_id,
    vector
) -> PutVectorOutcome

import_vectors(
    read_snapshot,
    space_id,
    idempotency_key,
    batch
) -> ImportOutcome

find_exact(
    read_snapshot,
    space_id,
    query_vector,
    k
) -> [VectorHit]

verify()
backup_file_set()
```

A vector can only be attached when the record exists in the supplied L4
`ReadSnapshot`.

Bulk import is atomic at the column-file boundary and idempotent:

- same key + same batch digest: duplicate ignored;
- same key + different batch digest: conflict;
- duplicate record IDs in one batch: rejected.

## 6. Exact cosine contract

V1 canonical search is scalar exact CPU search.

Validation:

- exact dimension match;
- all values finite;
- zero-norm vectors rejected;
- `k > 0`.

Calculation:

```text
dot and squared norms accumulate in f64
fixed coordinate order 0..dim
score = dot / (sqrt(query_norm) * sqrt(vector_norm))
```

Ranking:

```text
score descending
record_id ascending for exact ties
```

The same snapshot, space, column generation, query and `k` produce the same
ordered result.

Deleted canonical records are filtered at query time through the supplied
`ReadSnapshot`.

## 7. Migration fidelity

R4.2 proves:

```text
same imported f32 values
+ same cosine definition
+ same candidate set
= same result as an independent exact reference
```

It does not claim identical output to an old ANN database. For an ANN source,
future migration reporting must measure recall/overlap against the exact result.

## 8. Result contract

```text
VectorHit {
    record_id
    cosine_score
    rank
    exact = true
    space_id
    column_generation
    database_snapshot_sha256
}
```

Retrieval exactness and knowledge trust remain separate concepts.

R4.2 has no dependency on any trust crate and performs no trust transition.

## 9. Backup boundary

`backup_file_set()` returns all durable vector registry/column files with
relative paths, byte counts and SHA256 values.

R4.2 proves that copying this complete set to a new root produces an identical,
strictly verifiable vector store. Integration into the existing product backup
surface is performed during component conformance, not by creating a second
backup engine here.

## 10. Gates

### VS1 — layout and ingest

- descriptor/space ID determinism;
- incompatible revisions create different spaces;
- durable put/import;
- import idempotency;
- unknown records rejected;
- record identity and canonical state hash unchanged;
- journal recovery;
- corruption and orphan rejection;
- backup file-set round trip.

### VS2 — exact drop-in search

- full-column exact cosine;
- deterministic top-k and tie-breaking;
- strict space isolation;
- independent Python exact-cosine parity;
- restart determinism;
- no ANN;
- no GPU;
- no trust mutation.

Pass marker:

```text
PASS_R4_2_VECTOR_STORE_EXACT_MIGRATION_FOUNDATION
```

Next gate:

```text
V00R4_3_NATIVE_AND_EXTERNAL_SEMANTIC_HYBRID_QUERY
```
