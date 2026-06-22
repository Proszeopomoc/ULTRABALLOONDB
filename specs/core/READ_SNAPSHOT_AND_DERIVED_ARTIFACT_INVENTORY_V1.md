# Read Snapshot and Derived Artifact Inventory V1

## Scope

Closes the two R4.1A gaps without implementing semantic or GPU behavior:

```text
L4 versioned hot/read snapshot
L6 crystallization / derived-artifact inventory
```

## L4 — ReadSnapshot

`DurableDatabase::read_snapshot()` returns an immutable borrow-scoped view.
While the snapshot exists, Rust prevents a mutable commit through the same
database handle.

The descriptor contains:

```text
format_version
checkpoint_generation
committed_transaction_count
record_count
edge_count
state_sha256
snapshot_sha256
```

`snapshot_sha256` is derived from the logical state and counts. It deliberately
does not include checkpoint generation, so checkpointing an unchanged state
does not invalidate derived artifacts.

The snapshot delegates record and edge reads to the canonical recovered state.

## L6 — DerivedArtifactInventory

The inventory is stored under:

```text
derived/INVENTORY.ubdai
```

Supported artifact kinds:

```text
HOT_SNAPSHOT
CRYSTALLIZATION
FLOATING_SUBGRAPH
VECTOR_COLUMN
VECTOR_INDEX
GPU_SNAPSHOT
```

Each complete record binds:

```text
artifact_id
kind
generation
source_snapshot_sha256
artifact_sha256
relative_path
item_count
byte_count
state = COMPLETE | INVALIDATED
```

Rules:

- artifact paths are relative, UTF-8 and contain only normal components;
- symlinks are rejected;
- complete files are verified by length and SHA256;
- the same artifact record is idempotent;
- conflicting metadata for the same ID is rejected;
- a canonical-state change makes prior artifacts incompatible;
- stale records are explicitly invalidated;
- corrupted inventory files fail closed;
- interrupted replacement recovers from backup or completed temporary file.

Derived artifacts are not canonical database truth. Losing an artifact does
not change records, edges, WAL or trust, but a missing/corrupt inventory is not
silently accepted.

## Required proof

```text
snapshot changes after canonical commit
snapshot is deterministic after checkpoint/restart
artifact registration survives restart
file SHA verification passes
old artifact becomes stale after state change
stale invalidation is persisted
corruption is rejected
path traversal is rejected
record identity is unchanged
trust is unchanged
semantic is not implemented
GPU is not promoted
```
