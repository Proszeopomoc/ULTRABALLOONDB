# UltraBalloonDB V00H — Floating Subgraph Export/Import

## Purpose

V00H adds deterministic floating subgraph export/import.

A floating subgraph is a compact topology fragment exported from a hot snapshot and imported into another UltraBalloonDB instance. It is a DB-level byte stream containing node ids, edge types, numeric path energy, record pointers, provenance ids, and hashes.

## Boundary

The database does:

- export a compact subgraph from a hot snapshot,
- preserve root, edge mask, top-k, threshold, and source snapshot hash,
- encode a deterministic canonical byte stream,
- verify SHA-256 hashes,
- import/hot-patch the fragment into another instance,
- preserve provenance and record pointers.

The database does not:

- export semantic summaries,
- call any model,
- decide policy,
- interpret payload meaning,
- remove the lossless archive,
- treat a subgraph as globally true without provenance.

## V00H invariants

- Same source + same query => identical byte stream.
- Stream hash verifies canonical content.
- Tampered stream is rejected.
- Export respects top_k.
- Export stores pointers only, not payload bytes.
- Import is idempotent for the same stream hash.
- Provenance references remain attached.
- Source hot snapshot hash is included.

## Test gate

Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\windows\RUN_FLOATING_SUBGRAPH_EXPORT_IMPORT_V00H.ps1 `
  -RepoRoot C:\UltraBalloonDB `
  -EventSizes "10000,100000,1000000" `
  -RecallSamples 1000
```

Expected:

```text
PASS_ULTRABALLOONDB_FLOATING_SUBGRAPH_EXPORT_IMPORT_V00H
PASS_RUN_FLOATING_SUBGRAPH_EXPORT_IMPORT_V00H_SCRIPT
```

Report:

```text
C:\UltraBalloonDB\audit\v00h_floating_subgraph_export_import\<RUN_ID>\floating_subgraph_export_import_report.json
```
