# V00J5_G1G2_REAL_FILE_FAMILY_INTAKE

Status: additive core gate.

Purpose: ingest a real folder of text-like files and build a first G1/G2 family pack without full rebuild during query.

This is not a universal compression claim. It is a real-file intake bridge:

- G1 family dictionary stores repeated byte-lines across the file family.
- G2 file residual stores non-repeated byte-lines.
- Query resolves a file/line directly from G1 or G2 without rebuilding the file.
- Full rebuild remains available and must match each original file SHA256.

PASS does not require compression. A weak or unique folder may pass intake and correctly report that no compression claim is allowed.

## Boundary

In scope:

- deterministic file collection
- exact byte-line reconstruction
- G1/G2 source-layer reporting
- query without full rebuild
- zlib baseline for reference
- SHA verification per file

Out of scope:

- binary media files
- lossy compression
- semantic interpretation
- model calls
- network calls
- agent policy

## Why this exists

V00J1-V00J4 proved synthetic rule/exception/family compression. V00J5 starts the bridge to real folders while keeping the test small and non-blocking.
