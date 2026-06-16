# ADR 0005: Floating Subgraphs

## Status

Proposed for V00H.

## Decision

UltraBalloonDB should support deterministic export/import of compact subgraphs.

## Export

```text
export_subgraph(root_node, radius, edge_mask, top_k)
```

The database returns a binary stream containing:

- node IDs or remapped local IDs
- typed edges
- optional payload references
- provenance hash
- format version
- integrity checksum

## Import

```text
hot_patch_subgraph(byte_stream)
```

The database inserts the subgraph into a transient or persistent graph layer according to explicit mode.

## Constraints

- deterministic binary format
- no semantic interpretation
- no automatic trust escalation
- no hidden overwrite
- provenance must be retained
