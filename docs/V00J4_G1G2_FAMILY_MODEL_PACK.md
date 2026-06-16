# V00J4_G1G2_FAMILY_MODEL_PACK

Status: additive gate. Scope: UltraBalloonDB G1/G2 layer.

## Purpose

V00J1 proved rule+exception reconstruction for one dataset. V00J2 proved query without full rebuild. V00J3 proved local patching. V00J4 adds a shared family model:

- `G1_family` = one common rule/model for a family of similar files or record sets.
- `G2_file` = small per-file residuals/exceptions.
- Query resolves a record by `(file_index, record_index)` without rebuilding the whole family.
- Full byte-exact rebuild remains available for SHA validation.

## Why this matters

Family modeling is where high compression ratios can appear: one model can explain many similar files. The compact model is not only smaller; it remains queryable.

## Non-goals

This is not a full transaction engine, not a general-purpose compressor, and not a semantic/agent layer. It is a deterministic proof of shared-family G1 plus file-local G2 residuals.

## Acceptance

PASS requires:

- all rebuilt file SHA values match original file SHA values,
- rebuilt pack SHA matches original pack SHA,
- queries do not trigger full rebuild,
- query tracing includes both `G1_FAMILY_RULE` and `G2_FILE_RESIDUAL`,
- compact family model is smaller than original in the synthetic low-residual case.
