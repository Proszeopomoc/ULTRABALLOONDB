# V00J7 G1/G2 Hot Patch Export/Import

## Alignment

- role: `SUPPORT`
- touches core layers: `L0`, `L4`, `L7`
- uses auxiliary layers: `C1`, `C2`, `C3`, `C4`, `C5`
- runtime impact: `BOUNDED_IN_MEMORY_HOT_PATCH_ONLY`
- must not replace: `L2_TYPED_EDGE_GRAPH`, `L3_WAVE_ACTIVATION`
- roadmap status: `ALIGNED`

## Purpose

V00J7 adds a deterministic export/import primitive for compact G4 changes:

```text
compact state + ordered changes -> hashed patch bundle -> bounded in-memory hot apply
```

The receiving hot state validates the bundle hash, model identity, base-state manifest hash,
and every optimistic before-value before accepting the update.

## Required invariants

- The same content produces identical canonical bundle bytes.
- Provenance is carried outside the content hash and cannot promote trust.
- A wrong base-state hash is rejected before mutation.
- Tampered content is rejected.
- Hot import performs no full logical rebuild.
- Queries after import perform no full rebuild.
- Explicit post-import verification reproduces the expected target SHA.
- An inverse bundle restores the original logical SHA.
- The source/canonical model is not mutated by hot import.
- L2 typed edges and L3 wave activation remain unchanged.

## Scope limit

This is a compact in-process export/import primitive for L4/L7. It is not a network protocol,
replication engine, WAL transaction, distributed consensus mechanism, or agent state policy.
Persistence to the canonical archive remains a separate explicit operation.
