# V00J2 G1/G2 Queryable Reconstruction Index

Status: additive milestone after V00J1.

## Purpose

V00J1 proved that `G1 + G2 -> REBUILD -> SHA256 match` can compress rule/exception data while preserving exact reconstruction. V00J2 adds the database property: selected values must be queryable without rebuilding the full original.

## Layer roles

- G1: deterministic rule/model/generator.
- G2: sparse exceptions/residual patches.
- G3: query/navigation proof path.
- G5: rebuild validation and SHA audit.

Query returns whether a value came from G1 or G2 plus a small proof. Query must not call full rebuild.

## Non-goals

- No final compression format lock.
- No agent policy.
- No LLM/model calls.
- No network calls.
- No claim that all data compresses.

## Acceptance

PASS requires:

- G1-rule query is present.
- G2-exception query is present.
- Query does not use full rebuild.
- Full rebuild remains available and SHA matches.
- Compression claim is allowed only when SHA reconstruction matches.
