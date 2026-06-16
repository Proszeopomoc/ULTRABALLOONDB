# UltraBalloonDB V00A Architecture

## Layers

```text
L0 Physical storage
  page files, WAL segments, edge archive, checksums

L1 Exact indexes
  record_id -> page/offset/length
  node_id -> adjacency reference

L2 Typed edge graph
  edge_type, source, target, mask, attenuation class

L3 Wave activation
  energy propagation, thresholds, top_k, path evidence

L4 Hot snapshot
  compact reload artifact for daily agent memory

L5 Batch/coalesced payload fetch
  sorted page/offset reads for selected node IDs

L6 Crystallization
  offline structural reconsolidation into compact patterns

L7 Floating subgraphs
  deterministic export/import of compact topology
```

## Forbidden Coupling

UltraBalloonDB must not include:

- LLM prompts
- natural-language interpretation
- business rules
- user intent logic
- voice logic
- UI policy
- autonomous agent decisions

## API Sketch

```text
open_db(path)
append_node(node_type, payload_ref)
append_edge(src, dst, edge_type)
create_blocking_edge(src, dst)
wave_activation(seed, edge_mask, energy_threshold, top_k, rigor_multiplier)
batch_fetch_payloads(record_ids)
build_hot_snapshot()
reload_hot_snapshot()
export_subgraph(root, radius, edge_mask, top_k)
hot_patch_subgraph(stream, mode)
```
