# V00P1 CSR/MMAP CORE HOTPATH BINDING

Role: CORE performance repair after V00P R01 10M Python-object baseline.

## Purpose

V00P R01 proved that 10M records and 30M edges fit on disk, but the Python reference runtime became too costly after build. V00P1 binds the L1/L2/L3/L4/L7 hot path to a CSR-style compact layout so lookup and wave traversal do not scan the full graph.

## Alignment

- role: CORE
- touches: L1, L2, L3, L4, L7
- auxiliary layers: NONE
- must preserve: L2_TYPED_EDGE_GRAPH and L3_WAVE_ACTIVATION
- runtime impact: CORE_HOTPATH_LAYOUT_BINDING
- roadmap status: ALIGNED

## Required gates

- `full_graph_scan_in_get_edges = FALSE`
- `full_graph_scan_in_subgraph_export = FALSE`
- `python_edge_objects_per_base_edge = 0`
- `mmap_CSR_active = TRUE`
- `wave_result_available = TRUE`
- `path_evidence_available = TRUE`
- `restart_deterministic = TRUE`

## Design

The immutable hot graph is represented as CSR columns:

- `node_ids`
- `node_offsets`
- `edge_targets`
- `edge_types`
- `attenuation_classes`
- `weights`

`get_edges(node_id)` resolves the node position and reads only the slice `[offset[node], offset[node+1])`. Floating subgraph export iterates selected nodes and their CSR slices, not all edges.

## Boundary

V00P1 does not add embeddings, similarity search, agent logic, or compression claims. It is a core runtime repair to keep the original L2/L3 graph+wave architecture viable at 10M scale.
