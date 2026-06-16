# ADR 0003: Crystallization Paths

## Status

Proposed for V00F.

## Decision

UltraBalloonDB should support structural memory reconsolidation through crystallization paths.

## Definition

A crystallization path is a repeated, high-confidence topological pattern that can be condensed into a synthetic node or shortcut bridge while preserving provenance in the lossless archive.

## Database Role

The database may detect repeated structures such as:

```text
seed -> project -> code -> evidence -> rule
seed -> error -> patch -> test -> pass
seed -> user_intent -> artifact -> result
```

The database may create compact structural nodes or shortcut edges.

## Agent Role

The agent may later attach a human-readable semantic summary as payload, but the database itself does not write semantic meaning.

## Required Properties

- deterministic
- auditable
- reversible to source evidence
- never destructive to the lossless archive
- no hidden deletion
- no policy promotion by the database
