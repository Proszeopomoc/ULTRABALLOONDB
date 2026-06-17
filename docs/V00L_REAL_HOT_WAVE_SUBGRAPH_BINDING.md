# UltraBalloonDB V00L — Real Hot Snapshot / Wave / Floating Subgraph Binding

## Role

CORE integration milestone.

V00L binds the previously implemented product layers without replacing them:

- L1 exact byte references into the hot edge file,
- L2 typed edge graph,
- L3 deterministic wave activation,
- L4 real hot snapshot,
- L7 deterministic floating subgraph export/import.

## What V00L adds

1. Reads the real V00G `hot_edges.bin` format.
2. Reconstructs the existing typed graph in memory without payload decoding.
3. Runs the existing V00B wave activation over that graph.
4. Converts selected wave results and path evidence into the existing floating-subgraph stream.
5. Imports the stream idempotently into a separate in-memory hot target.
6. Preserves archive and source hot-snapshot hashes.

## Boundaries

- No G1/G2 compression replaces the graph or wave.
- No embeddings or model calls are introduced.
- No payload bytes are embedded in the floating subgraph; only exact references are exported.
- No canonical archive mutation occurs during export/import.
- This is a Python reference binding, not yet a production concurrency engine.

## Pass conditions

- real hot edge count matches the snapshot manifest,
- typed edge graph loads correctly,
- wave results and path evidence are produced,
- floating export is deterministic and hash-verified,
- import succeeds and duplicate import is idempotent,
- tampering is rejected,
- archive and source snapshot remain unchanged,
- L2 and L3 remain the active graph/query mechanisms.
