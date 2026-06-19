# UltraBalloonDB Backup Restore Upgrade Dry Run V1

## Scope

C1 introduces a separate offline backup core. It copies an explicit, bounded file set from a stable source directory into a new backup directory, records exact sizes and SHA-256 digests, binds the snapshot to a database ID, schema version and P0 provenance head digest, and verifies the complete payload before returning success.

C1 is not attached to the active database runtime. It does not pause writers, rotate WAL, modify database pages, overwrite a live database, execute an upgrade, or expose a production command surface.

## Backup layout

A backup directory contains:

- `backup-manifest.ubbackup` — deterministic binary manifest;
- `payload/` — the exact relative file tree copied from the source.

The manifest stores:

- backup ID and source database ID;
- logical timestamp and source schema version;
- exact P0 provenance head digest;
- sorted unique relative paths;
- exact file sizes and SHA-256 digests;
- a final manifest digest over all preceding bytes.

Absolute paths, drive prefixes, empty components, `.`/`..`, backslashes, symlinks, duplicate paths and files outside the source root are rejected.

## Stable source rule

Each source file is streamed to the backup payload and hashed. The source is then read and hashed again. A changed size or digest fails the backup. The source tree is never written by C1.

## Strict replay

Opening a backup verifies the manifest structure, digest, sorted unique paths, every payload file size and digest, and the exact payload file set. Missing, modified, truncated or extra files fail closed.

## Restore dry-run

Restore dry-run verifies the entire backup, examines destination conflicts, computes total bytes and a deterministic plan digest, and returns without creating or modifying the destination.

## Upgrade dry-run

Upgrade dry-run permits only the same schema version or a bounded forward sequence. Downgrades, version zero and gaps larger than the bounded maximum are rejected. It produces a deterministic plan digest but performs no transformation and writes no database data.

## Staged restore

C1 may restore an unmodified snapshot only into a destination path that does not exist. Files are first copied and verified in a sibling temporary directory. A receipt is written and the completed directory is atomically renamed into place. Existing destinations are never overwritten.

## Boundaries

Online backup coordination, active WAL checkpointing, in-place restore, upgrade execution, daemon transport, C ABI and PyO3 remain later gates.
