# UltraBalloonDB Provenance Core V1

## Scope

P0 adds a separate append-only provenance ledger. It records where an immutable object snapshot came from, which operation produced it, which earlier provenance records are its parents, which T6B authorization signed the exact subject, and which accepted T6C enterprise policy bundle governed the operation.

## File

`provenance-core.ubprov` is an independent SHA-256 frame chain. It does not alter database records, storage pages, WAL, lifecycle, database CLI, or active runtime.

## Event kinds

1. `SOURCE` — locally observed source with a hashed locator and no parents.
2. `IMPORTED` — externally imported source with a hashed locator and no parents.
3. `DERIVED` — output derived from one or more earlier provenance IDs and a nonzero transformation digest.

## Required bindings

Every event binds:

- namespace, object ID, object kind and exact object version;
- content, operation and optional transformation digests;
- no raw source URI or credential, only a source-locator digest;
- exact T6B asymmetric authorization sequence, event ID and frame digest;
- provenance authorization domain `9` and the namespace authority role;
- exact T6C policy version/digest and accepted bundle version/digest;
- sorted unique parent provenance IDs that must already exist;
- previous ledger frame digest, event subject digest and provenance ID.

An authorization sequence may be consumed by only one provenance event. Object versions advance by exactly one per namespace/object pair. Strict replay rejects unknown parents, duplicate authorization use, signature/policy/bundle mismatch, frame tampering and truncation.

## Boundaries

P0 is a core evidence layer only. Runtime attachment, query surfaces, backup/restore transport, upgrade execution, daemon, C ABI and PyO3 remain later gates.
