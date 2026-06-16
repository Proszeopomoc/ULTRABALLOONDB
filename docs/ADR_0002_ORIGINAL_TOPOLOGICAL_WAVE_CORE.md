# ADR 0002: Original Topological Wave Core

## Status

Accepted.

## Decision

UltraBalloonDB uses typed topological wave activation as its core recall mechanism.

The primary recall primitive is not a fixed-radius BFS. It is a deterministic spreading-energy operation over typed edges.

## Primitive

```text
wave_activation(seed_node, edge_mask, energy_threshold, top_k, rigor_multiplier)
```

## Edge Attenuation

Each edge type has a deterministic attenuation value.

Example class of table:

```text
CODE edge      -> strong conduction
PROJECT edge   -> strong contextual conduction
UP_RULE edge   -> abstract/rule conduction
LATERAL edge   -> weaker associative conduction
DOWN edge      -> evidence/downstream conduction
IS_NOT edge    -> hard block
```

The exact values are implementation parameters and should be benchmarked.

## Output

The function returns:

```text
node_id
energy_score
path_summary
edge_type_trace
record_id pointer
```

## Principle

The database does not decide what the result means. It only returns a deterministic ranked subgraph.

The agent decides how to use the returned context.
