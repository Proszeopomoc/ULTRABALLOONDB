# UltraBalloonDB V00J Compact Computable Hot Layout

V00J changes the direction from "decode faster" to "do not decode on the hot path".
The hot snapshot is written in the same layout used by recall.

## Purpose

Create a compact, directly-computable hot snapshot:

- fixed-width node rows
- fixed-width edge rows
- CSR-style edge ranges (`first_edge`, `edge_count`)
- integer/fixed-point edge type and attenuation codes
- manifest hash verification
- payload references only; payload bytes are resolved after `top_k`

## Layer boundary

V00J does not remove the lossless archive. The archive remains the source of truth.
The hot snapshot is a rebuildable compute layout.

## Why this matters

The V00I/V00I2/V00I3 evidence showed that tuning page size does not remove the hot-path cost.
V00J therefore removes per-record decode from recall instead of micro-optimizing decoding.

## Compression meaning

V00J is not a universal lossless compressor. It is a hot-working-set reduction:
full payload/evidence stays in the canonical archive, while recall uses compact typed arrays.
Large ratios are possible when the archive contains large payloads and the hot path needs only ids,
edge types, attenuation, relation codes, flags and payload references.

## Non-negotiables

- canonical archive remains source of truth
- hot snapshot is rebuildable
- folds/crystals are derived indexes, not canonical truth
- activation/firing never promotes trust
- no model calls
- no network calls
- no agent policy inside DB core

## PASS line

```text
PASS_ULTRABALLOONDB_COMPACT_COMPUTABLE_HOT_LAYOUT_V00J
```
