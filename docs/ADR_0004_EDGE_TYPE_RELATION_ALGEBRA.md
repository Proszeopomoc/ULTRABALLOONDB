# ADR 0004: Edge-Type Relation Algebra

## Status

Proposed for V00E.

## Decision

UltraBalloonDB should support read-time relation algebra over typed edges.

## Purpose

Some relations should be inferred during recall without physically writing every possible shortcut edge.

Example:

```text
A --UP_RULE--> B
B --CODE_PATTERN--> C
```

The engine may derive a temporary relation class between A and C during read-time expansion.

## Database Role

The database performs table-based transformations over edge type IDs:

```text
transition_table[type_a][type_b] -> derived_type
```

This is not semantic reasoning. It is deterministic relation algebra.

## Agent Role

The agent interprets the returned derived path.
