# UltraBalloonDB ROADMAP_ALIGNMENT_TABLE V00K

Status: active alignment table.
Purpose: keep completed and future milestones attached to the original L0-L7 database architecture.

## Product layers

| Layer | Name | Role |
|---|---|---|
| L0 | Physical storage | Page files, WAL, archive, checksums |
| L1 | Exact indexes | record_id/page/offset/length and adjacency refs |
| L2 | Typed edge graph | edge_type/source/target/mask/attenuation |
| L3 | Wave activation | energy propagation/top_k/path evidence |
| L4 | Hot snapshot | compact reload artifact |
| L5 | Batch payload fetch | sorted coalesced reads |
| L6 | Crystallization | offline structural reconsolidation |
| L7 | Floating subgraphs | deterministic export/import |

## Auxiliary compact layers

| Layer | Name | Use |
|---|---|---|
| C1 | Rule model | Structure/rule/family/template |
| C2 | Residual exception | Exceptions and file residuals |
| C3 | Query reconstruction index | Query compact state without full rebuild |
| C4 | Delta patch | Mutations and corrections |
| C5 | Rebuild verify | SHA/rebuild/audit |

## Completed milestone alignment

| Milestone | Role | Main L-layer | Auxiliary C-layer | Status |
|---|---|---|---|---|
| V00A Repository bootstrap | CORE | L0-L7 boundary | none | PASS |
| V00B Wave activation core | CORE | L3 | none | PASS |
| V00C Edge attenuation table | CORE | L2, L3 | none | PASS |
| V00D Batch payload fetch | CORE | L5 | none | PASS |
| V00E Relation algebra | CORE | L2 | none | PASS |
| V00F Crystallization paths | CORE | L6 | C1-C5 support later | PASS |
| V00G Hot snapshot/archive split | CORE | L4, L0 | C1-C5 support later | PASS |
| V00H Floating subgraph export/import | CORE | L7 | C1-C5 support later | PASS |
| V00I Page/cold IO audits | SUPPORT | L0, L5 | none | PASS |
| V00J Compact computable hot layout | SUPPORT | L4 | C1, C3, C5 | PASS |
| V00J1 G1/G2 reconstruction core | SUPPORT | L6 | C1, C2, C5 | PASS |
| V00J2 Queryable reconstruction index | SUPPORT | L1, L6 | C1, C2, C3, C5 | PASS |
| V00J3 Mutation delta patch | SUPPORT | L6, L7 | C1, C2, C3, C4, C5 | PASS |
| V00J4 Family model pack | SUPPORT | L6, L7 | C1, C2, C3, C5 | PASS |
| V00J5 Real file family intake | SUPPORT | L6 | C1, C2, C3, C5 | PASS, no compression claim |
| V00J5A Small data adaptive pack | SUPPORT | L0, L6 | C1, C2, C3, C5 | pending/pass after run |
| V00K Core alignment guard | CORE | L0-L7 governance | C1-C5 boundary | this document |

## Future application boundary

The following areas are FUTURE until the database core is stable:

- compressed agent context / KV-like layer
- multi-agent state patch exchange
- neuro-symbolic exception handling / guardrails
- mutable compressed DB productization beyond prototype
- hyperbolic / embedding index layer

They must not redirect the core roadmap until explicitly promoted by a future alignment manifest.
