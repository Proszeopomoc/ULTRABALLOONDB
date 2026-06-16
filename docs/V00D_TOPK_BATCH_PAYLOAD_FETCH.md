# UltraBalloonDB V00D — Top-K Batch Payload Fetch

## Status

Additive gate after V00B wave activation and V00C edge attenuation table.

## Purpose

V00D separates graph candidate selection from payload retrieval:

1. The graph/wave stage returns numeric `top_k` candidate records.
2. The DB creates physical `RecordPointer` values: `record_id`, `offset`, `length`.
3. The DB sorts pointers by physical offset.
4. The DB groups nearby records into bounded `FetchSpan` reads.
5. The DB fetches payload bytes and verifies byte-equivalence with naive per-record fetch.

## Boundary

The database core does:

- top_k bound enforcement,
- offset/length pointer handling,
- coalesced fetch-plan construction,
- byte reads from a local payload store,
- deterministic payload digests,
- benchmark reporting.

The database core does not:

- call an LLM,
- call network APIs,
- interpret text meaning,
- decide agent policy,
- summarize payloads semantically.

## Files

- `python_ref/ultraballoondb_core/payload_fetch.py`
- `python_ref/ultraballoondb_core/selftest/run_topk_batch_payload_fetch_v00d.py`
- `scripts/windows/RUN_TOPK_BATCH_PAYLOAD_FETCH_V00D.ps1`
- `docs/V00D_TOPK_BATCH_PAYLOAD_FETCH.md`

## Acceptance

Expected status line:

```text
PASS_ULTRABALLOONDB_TOPK_BATCH_PAYLOAD_FETCH_V00D
```

Required checks:

- naive and coalesced fetch return identical payload bytes,
- `top_k` cap is never exceeded,
- payload fetch happens only after candidate selection,
- coalesced plan is sorted by physical offset,
- coalesced span count does not exceed selected record count,
- repo scan finds no LLM/API/network markers,
- report JSON is written under `audit/v00d_topk_batch_payload_fetch/`.

## Report

The selftest writes:

```text
audit/v00d_topk_batch_payload_fetch/<RUN_ID>/topk_batch_payload_fetch_report.json
```

Metrics include:

- store build records/s,
- balloon-only median/p95 us,
- fetch-plan median/p95 us,
- naive payload fetch median/p95 us,
- coalesced payload fetch median/p95 us,
- total context median/p95 us,
- requested payload bytes,
- physical bytes read,
- coalesced span count.

Note: V00D records both requested recall samples and effective fetch samples. The default effective cap keeps the IO benchmark bounded; pass `-MaxEffectiveSamples 1000` for a full 1000-fetch run.


## V00D1 Windows positional read fix

This package replaces direct `os.pread` calls with `_portable_pread`. On platforms without `os.pread`, including Windows Python, the DB-core benchmark uses a deterministic `lseek/read` fallback. No agent, LLM, network, or semantic layer is added.
