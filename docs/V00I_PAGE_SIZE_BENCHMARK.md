# UltraBalloonDB V00I — Page Size Benchmark 4K/16K/64K/256K

## Status

Additive benchmark gate.

## Goal

Measure physical page sizes for payload storage after wave/top_k selection:

- 4096 bytes
- 16384 bytes
- 65536 bytes
- 262144 bytes

The benchmark does not select a permanent default. It reports the tradeoff between coalesced context-read performance and physical slack/fragmentation.

## DB/agent boundary

V00I is database-side and semantic-blind. It measures offsets, page counts, byte ranges, checksums, read ranges, and latency. It does not call LLMs, interpret payload meaning, or make agent policy decisions.

## What is measured

For each event size and page size:

- store file size
- payload bytes
- stored record bytes
- page count
- slack bytes
- slack ratio
- records per page
- write throughput
- naive payload fetch latency
- coalesced payload fetch latency
- coalesced range count
- coalescing ratio
- checksum correctness

## Acceptance

The gate passes only when:

- all four page sizes are tested
- headers match page size and record count
- coalesced reads return exactly the same payloads as naive reads
- coalesced range count is never worse than naive read count in median
- no external service, LLM call, network call, or agent policy is used
- generated report is written to `audit/v00i_page_size_benchmark/<RUN_ID>/page_size_benchmark_report.json`

## Public positioning

This benchmark is part of the original deterministic typed topological wave memory storage design. It is not an agent and not a semantic layer.
