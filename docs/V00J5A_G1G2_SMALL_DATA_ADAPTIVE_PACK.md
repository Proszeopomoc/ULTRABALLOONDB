# V00J5A_G1G2_SMALL_DATA_ADAPTIVE_PACK

Status: additive small-data intake layer.
Scope: cold/intake packing only; hot query reads the selected ready plan.

## Purpose

V00J5 showed that small, mixed documentation files should not be forced through a G1/G2 family model when the model overhead is larger than the data.
V00J5A adds a deterministic adaptive selector:

- `RAW_SMALL_INDEX`: keep canonical bytes and add a small query index.
- `G1G2_LINE_FAMILY`: repeated exact lines become rules; unique lines remain residuals.
- `DICT_SMALL_TOKEN_PACK`: repeated byte tokens/phrases become dictionary rules; unique bytes remain literals.

The selector does not make a compression claim unless the selected self-contained pack is smaller than the original bytes and SHA reconstruction passes.

## Non-goals

- no model calls
- no network calls
- no semantic interpretation
- no hot-path compression decision during query
- no fake compression claim on weak small data

## Guarantees checked

- all files rebuild to the original SHA256
- query sample works without full file-family rebuild
- candidate modes are measured
- weak small data can safely fall back to `RAW_SMALL_INDEX`

## Interpretation

This layer protects the database from small-data overhead while preserving queryability.
It is not a replacement for G1/G2 family compression on large regular data; it is a safe intake selector.

## Core alignment

```text
role: SUPPORT
touches: L0, L4, L6
uses: C1, C2, C3, C5
runtime impact: BUILD_ONLY
must not replace: L2 typed edge graph, L3 wave activation
roadmap status: ALIGNED
```

The adaptive pack is a storage/intake optimization. It does not redefine the UltraBalloonDB graph model or wave-activation query engine.
