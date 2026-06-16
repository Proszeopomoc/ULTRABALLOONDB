# UltraBalloonDB CORE_ALIGNMENT_GUARD V00K

Status: active project guard.
Runtime impact: none.
Purpose: prevent roadmap drift while allowing auxiliary discoveries, compression work, optimizations, and future research notes.

## Main product contract

UltraBalloonDB primary architecture is L0-L7:

- **L0 Physical storage**: page files, WAL segments, edge archive, checksums.
- **L1 Exact indexes**: record_id -> page/offset/length, node_id -> adjacency reference.
- **L2 Typed edge graph**: edge_type, source, target, mask, attenuation class.
- **L3 Wave activation**: energy propagation, thresholds, top_k, path evidence.
- **L4 Hot snapshot**: compact reload artifact for daily agent memory.
- **L5 Batch/coalesced payload fetch**: sorted page/offset reads for selected node IDs.
- **L6 Crystallization**: offline structural reconsolidation into compact patterns.
- **L7 Floating subgraphs**: deterministic export/import of compact topology.

L2 and L3 are central. They must not be silently replaced by compression, embeddings, hyperbolic vectors, KV-cache logic, agent policy, or any other side mechanism.

## Auxiliary compact/crystallization contract

The compact rule/exception work is an auxiliary mechanism named C1-C5:

- **C1_RULE_MODEL**: rule, model, template, generator, family structure.
- **C2_RESIDUAL_EXCEPTION**: exceptions, file residuals, local repairs.
- **C3_QUERY_RECONSTRUCTION_INDEX**: query over compact state without full rebuild.
- **C4_DELTA_PATCH**: mutation, patch, override, correction layer.
- **C5_REBUILD_VERIFY**: SHA/audit/rebuild validation.

C1-C5 may support L4, L6, and L7. C1-C5 may also improve physical storage formats under L0 when explicitly declared. C1-C5 must not replace L2 typed edge graph or L3 wave activation.

## Work classes

Every milestone must be classified as exactly one of:

- **CORE**: directly implements or improves L0-L7.
- **SUPPORT**: supports L0-L7 without replacing the core model.
- **EXPERIMENT**: isolated side test; no roadmap authority.
- **FUTURE**: strategic note for later; no implementation pressure now.

## Required alignment manifest

Every new milestone must declare:

```json
{
  "milestone": "V00K_EXAMPLE",
  "role": "CORE|SUPPORT|EXPERIMENT|FUTURE",
  "touches_core_layers": ["L0", "L1", "L2", "L3", "L4", "L5", "L6", "L7"],
  "uses_auxiliary_layers": ["C1_RULE_MODEL", "C2_RESIDUAL_EXCEPTION", "C3_QUERY_RECONSTRUCTION_INDEX", "C4_DELTA_PATCH", "C5_REBUILD_VERIFY"],
  "must_not_replace": ["L2_TYPED_EDGE_GRAPH", "L3_WAVE_ACTIVATION"],
  "runtime_impact": "NONE|BUILD_ONLY|HOT_PATH_DECLARED|RUNTIME_DECLARED",
  "roadmap_status": "ALIGNED|EXPERIMENT_ONLY|FUTURE_ONLY|NO_GO",
  "reason": "one sentence explaining why this milestone belongs here"
}
```

## Hard rules

1. If a milestone changes the meaning of UltraBalloonDB from typed graph + wave activation into another product, it is **NO_GO**.
2. If a milestone uses C1-C5, it must state which L-layer it supports.
3. If a milestone discusses agent memory, KV-cache, hyperbolic vectors, RAG, or swarm state, it is **FUTURE** unless explicitly isolated as EXPERIMENT.
4. If a milestone improves compression but does not improve or support L0-L7, it is **EXPERIMENT**, not CORE.
5. Compression claims require byte-for-byte rebuild verification or must be labeled as non-claim.
6. Hot-path impact must be declared before implementation.
7. The DB core remains semantically blind: no LLM policy, no agent policy, no interpretation logic inside core storage.

## Standard pre-build check

Before a new package is created, answer:

```text
ALIGNMENT CHECK
milestone: ...
role: CORE/SUPPORT/EXPERIMENT/FUTURE
main L-layer: ...
auxiliary C-layer: ...
does not replace: L2 typed edge graph, L3 wave activation
runtime impact: ...
roadmap status: ALIGNED/EXPERIMENT_ONLY/FUTURE_ONLY/NO_GO
```

Only ALIGNED milestones should enter the core roadmap.
