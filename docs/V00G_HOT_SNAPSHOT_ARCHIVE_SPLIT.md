# UltraBalloonDB V00G Hot Snapshot / Archive Split

## Status gate

`PASS_ULTRABALLOONDB_HOT_SNAPSHOT_ARCHIVE_SPLIT_V00G`

## Purpose

V00G separates the database into two deterministic storage paths:

1. **Lossless archive** — source of truth.
2. **Hot snapshot** — compact working-memory representation for startup and recall.

The hot snapshot is not allowed to replace the archive. It is a rebuildable derived artifact.

## Lossless archive role

The lossless archive stores:

- numeric record identifiers,
- node identifiers,
- typed edge source data,
- payload offsets and payload hashes,
- payload bytes,
- revocation records.

The archive is used for:

- offline rebuild,
- audit,
- payload verification,
- provenance verification,
- crystal revocation and snapshot rebuild.

## Hot snapshot role

The hot snapshot stores:

- compact typed edges,
- compact crystal nodes,
- structural metadata,
- source archive hashes.

The hot snapshot does **not** store full payload bytes.

## Revocation

A crystal node can be revoked by appending a revocation record to the archive-side revocation log. Rebuilding the hot snapshot excludes revoked crystal nodes while preserving the archive records and payloads.

## DB/agent boundary

The database layer does not interpret payload meaning. V00G only handles IDs, edge types, offsets, hashes, compact edge files, crystal records and deterministic rebuild.

## Files added

- `python_ref/ultraballoondb_core/hot_snapshot.py`
- `python_ref/ultraballoondb_core/selftest/run_hot_snapshot_archive_split_v00g.py`
- `scripts/windows/RUN_HOT_SNAPSHOT_ARCHIVE_SPLIT_V00G.ps1`
- `docs/V00G_HOT_SNAPSHOT_ARCHIVE_SPLIT.md`

## Report

The local run writes:

`audit/v00g_hot_snapshot_archive_split/<RUN_ID>/hot_snapshot_archive_split_report.json`
