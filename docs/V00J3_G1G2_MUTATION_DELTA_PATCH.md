# V00J3_G1G2_MUTATION_DELTA_PATCH

Status: additive gate. Scope: UltraBalloonDB G1/G2 layer.

## Purpose

V00J1 proved lossless rule+exception reconstruction. V00J2 proved queries can be answered from the compact G1/G2 index without full rebuild. V00J3 adds a minimal mutation layer:

- G1 remains the rule/model.
- G2 remains exception/residual.
- G4 is a small delta patch layer for local mutations.
- Queries resolve in order: G4 patch -> G2 exception -> G1 rule.
- Full rebuild remains available for SHA validation, but normal query does not require it.

## Non-goals

This is not a full storage engine and not a transaction system. It is a compact deterministic proof that local mutations can be represented as small patches without rebuilding the whole model.

## Trust boundary

Delta patches do not promote trust. They are storage/reconstruction facts only. Any source/trust semantics remain outside this core.

## Acceptance

PASS requires:

- direct patched original SHA equals G1/G2/G4 rebuild SHA,
- query does not trigger full rebuild,
- G4_PATCH is visible in query source tracing,
- compact representation remains smaller than original in the synthetic regular cases.
