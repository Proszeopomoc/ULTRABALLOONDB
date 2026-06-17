# V00J6 G1/G2 Patch Chain Compaction

## Alignment

- role: `SUPPORT`
- touches core layers: `L0`, `L4`, `L6`
- uses auxiliary layers: `C1`, `C2`, `C3`, `C4`, `C5`
- runtime impact: `OFFLINE_COMPACTION_ONLY`
- must not replace: `L2_TYPED_EDGE_GRAPH`, `L3_WAVE_ACTIVATION`
- roadmap status: `ALIGNED`

## Purpose

V00J6 prevents an append-only G4 patch chain from growing without bound.
It compacts the current logical state into a new G1/G2 snapshot:

```text
G1 + G2 + G4 event chain -> new G1/G2 snapshot + external rollback bundle
```

The operation is offline and does not alter the typed-edge graph or wave-activation engine.

## Required invariants

- The logical state SHA before and after compaction is identical.
- Queries after compaction do not require a full rebuild.
- The active G4 event count becomes zero.
- Values that return to the G1 rule are removed from G2.
- The pre-compaction event chain can be serialized as an external rollback bundle.
- The rollback bundle is not part of the hot compact state.
- No trust promotion, agent policy, model call, or network call is performed.

## Scope limit

This milestone validates compaction primitives on the existing V00J3 matrix and prefix-family models. It is not yet WAL compaction, transactional recovery, or a complete storage-engine checkpoint protocol.
