# UltraBalloonDB V00E Edge Type Relation Algebra

## Status

V00E adds a deterministic DB-side edge-type relation algebra.

The database still remains semantics-blind. It combines relation/type IDs only. It does not call a model, interpret text, plan agent behavior, summarize payloads, or make policy decisions.

## Purpose

Earlier gates added:

- V00B: wave activation core
- V00C: edge attenuation table
- V00D: top-k batch payload fetch

V00E adds a read-time transition table for path typing:

```text
EDGE_TYPE_A + EDGE_TYPE_B -> DERIVED_RELATION_TYPE
```

The result is a relation/path type ID, not a semantic judgment.

## Examples

```text
PROJECT_CONTEXT + DOWN_EVIDENCE -> PROJECT_SUPPORT_PATH
UP_RULE + RULE_TO_CODE_PATTERN -> RULE_CODE_CANDIDATE
RULE_CODE_CANDIDATE + DOWN_EVIDENCE -> RULE_CODE_EVIDENCE_PATH
... + IS_NOT_EDGE -> BLOCKED_PATH
```

## Contract

The database may:

- combine edge type IDs through a fixed transition table
- stop traversal when a blocking edge type is present
- return deterministic path relation IDs
- return unknown path IDs when no transition exists
- emit a manifest of the transition table
- benchmark derivation latency

The database must not:

- interpret natural language
- call an agent or model
- fetch payloads in this gate
- make business or agent policy decisions
- convert relation IDs into human meaning

## Report

The runner writes:

```text
audit/v00e_edge_type_relation_algebra/<RUN_ID>/edge_type_relation_algebra_report.json
```

Required PASS line:

```text
PASS_ULTRABALLOONDB_EDGE_TYPE_RELATION_ALGEBRA_V00E
```
