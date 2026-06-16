# UltraBalloonDB V00I2 cold-ish I/O and traversal split audit

## Status

Additive benchmark gate after V00I.

## Purpose

V00I showed that page size did not create a clean final winner under the current warm file-backed benchmark. V00I2 splits the measured path into separate phases:

1. query / top_k id generation,
2. coalesced read-plan build,
3. actual file-backed read,
4. decode / checksum verification.

It also records two modes:

- `warm_file_backed`,
- `coldish_cache_disturbed`.

The cold-ish mode reads a side disturbance file before the profile. This is not a true operating-system cache flush and must not be described as guaranteed cold disk I/O.

## Non-goals

V00I2 does not select a final page size.
V00I2 does not define product policy.
V00I2 does not call LLMs.
V00I2 does not use network calls.
V00I2 does not interpret payload meaning.
V00I2 does not move agent logic into the database.

## Required checks

The report must confirm:

- phase split fields are present,
- warm and cold-ish modes both ran,
- cold-ish mode declares `cold_disk_guaranteed=false`,
- checksum verification passed,
- final page-size assumption remains false,
- no agent policy, LLM calls, or network calls,
- repository text scan passes.

## Report path

`audit/v00i2_cold_io_and_traversal_split_audit/<RUN_ID>/cold_io_and_traversal_split_audit_report.json`

## Interpretation rule

If actual read is not the dominant phase, page size tuning must not be promoted as the main optimization direction. If actual read dominates only in cold-ish mode, a separate lower-level storage benchmark is required before locking page-size policy.
