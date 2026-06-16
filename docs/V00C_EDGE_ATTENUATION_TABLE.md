# UltraBalloonDB V00C Edge Attenuation Table

Status: additive gate after V00B.

## Purpose

V00C moves numeric attenuation for typed-edge wave traversal into a separate database-side table. The wave core should receive attenuation as numeric configuration instead of hardcoding every edge-type weight in traversal logic.

## Scope

V00C adds:

- immutable `EdgeAttenuationTable`,
- deterministic default profiles: `STRICT_V00C`, `BALANCED_V00C`, `EXPLORATIVE_V00C`,
- stable table hashing,
- JSON roundtrip validation,
- generated benchmark for table-driven wave propagation,
- hard checks for `IS_NOT_EDGE`, `edge_mask`, `energy_threshold`, `top_k`, `max_steps`, and numeric `rigor_multiplier`.

V00C does not add payload fetching, semantic interpretation, planning, policy, or external calls.

## Edge types

- `UP_RULE`
- `DOWN_EVIDENCE`
- `LATERAL_SIMILAR_CASE`
- `PROJECT_CONTEXT`
- `CODE_PATTERN`
- `RULE_TO_EVIDENCE`
- `RULE_TO_CODE_PATTERN`
- `PROJECT_TO_RECENT_SEED`
- `CODE_TO_RECENT_RULE`
- `IS_NOT_EDGE`

`IS_NOT_EDGE` must always have attenuation `0.0` and must block propagation before result selection.

## Acceptance

The run must print:

```text
PASS_ULTRABALLOONDB_EDGE_ATTENUATION_TABLE_V00C
PASS_RUN_EDGE_ATTENUATION_TABLE_V00C_SCRIPT
```

The report is written to:

```text
audit/v00c_edge_attenuation_table/<RUN_ID>/edge_attenuation_table_report.json
```

Do not commit `audit/` unless an evidence publishing decision is made separately.
