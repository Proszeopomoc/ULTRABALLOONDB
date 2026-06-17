# UltraBalloonDB V00M — Unified L0-L7 Database Runtime

## Status

CORE milestone. Reference runtime binding the already validated UltraBalloonDB layers into one process and one stateful database object.

## Alignment

- role: `CORE`
- touches: `L0,L1,L2,L3,L4,L5,L6,L7`
- auxiliary compression layers: `NONE`
- must preserve: `L2_TYPED_EDGE_GRAPH`, `L3_WAVE_ACTIVATION`
- runtime impact: `UNIFIED_REFERENCE_RUNTIME`
- roadmap status: `ALIGNED`

## Purpose

V00M is the transition from separate validated primitives to one database runtime. The runtime can:

1. create a lossless archive and payload store,
2. build and open the hot snapshot,
3. perform exact event/node lookup,
4. load the typed edge graph,
5. execute deterministic wave queries with path evidence,
6. derive relation-algebra evidence from returned paths,
7. fetch selected payloads through a bounded coalesced read plan,
8. expose crystallization inventory,
9. export/import a deterministic floating subgraph,
10. close, reopen, and reproduce the same query result.

## Explicit boundary

V00M does **not** yet claim durable online mutation, WAL replay, transactions, or crash recovery. Those belong to V00N. V00M uses the existing canonical archive and hot snapshot formats and verifies that unified reads do not mutate them.

## Core invariant

```text
canonical archive -> exact indexes -> typed graph -> wave -> payload fetch
                  -> crystallization -> floating subgraph
```

Compression/support layers do not replace L2 or L3.
