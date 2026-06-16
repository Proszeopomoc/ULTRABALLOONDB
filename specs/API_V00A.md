# UltraBalloonDB API V00A Draft

## Core Types

```text
NodeId: u64
EdgeType: u16
EdgeMask: u64
Energy: f32 or fixed-point u32
RecordId: u64
PageId: u64
Offset: u32
Length: u32
```

## Core Functions

```text
open(path) -> DbHandle
close(handle)

append_node(node_type, payload_ref) -> NodeId
append_edge(src, dst, edge_type) -> EdgeId
append_blocking_edge(src, dst) -> EdgeId

wave_activation(
  seed_node: NodeId,
  edge_mask: EdgeMask,
  energy_threshold: Energy,
  top_k: u32,
  rigor_multiplier: f32
) -> WaveResult

batch_fetch_payloads(record_ids: &[RecordId]) -> PayloadBatch

build_hot_snapshot() -> SnapshotId
reload_hot_snapshot(snapshot_id) -> ReloadStats

export_subgraph(root_node, radius, edge_mask, top_k) -> ByteStream
hot_patch_subgraph(byte_stream, mode) -> PatchStats
```

## Non-Goals

The API does not expose LLM behavior.  
The API does not interpret payload text.  
The API does not decide policy.
