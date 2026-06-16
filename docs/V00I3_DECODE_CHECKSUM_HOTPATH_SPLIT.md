# UltraBalloonDB V00I3 Decode/Checksum Hot-Path Split

V00I3 is a measurement gate after V00I2. It does not select a final page size and does not finalize the runtime binary format.

## Purpose

Split the post-fetch hot path into measurable phases:

- query/top-k generation
- coalesced plan build
- actual file-backed read
- slice/copy extraction
- Python loop overhead
- header parse
- fixed binary record decode
- checksum verification

## Profiles

V00I3 measures three validation profiles:

- `checksum_full`
- `checksum_sampled_1_of_8`
- `checksum_disabled_trusted_hot_snapshot`

These profiles are audit modes only. V00I3 does not promote a runtime policy.

## Scope

The benchmark uses a file-backed page store. It does not guarantee true cold-disk conditions because operating-system cache may still participate.

## Non-goals

- no final page-size selection
- no semantic interpretation
- no agent policy
- no model calls
- no network calls
- no runtime format lock

## PASS line

```text
PASS_ULTRABALLOONDB_DECODE_CHECKSUM_HOTPATH_SPLIT_V00I3
```
