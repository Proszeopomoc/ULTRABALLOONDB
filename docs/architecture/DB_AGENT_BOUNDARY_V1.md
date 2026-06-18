# UltraBalloonDB Database / Agent Boundary V1

Status: public repository boundary.

## Database repository

`ULTRABALLOONDB` contains:

- database storage and formats;
- WAL, checkpoint and recovery;
- evidence lineage and Trust Core;
- typed relations and Wave Engine;
- CPU/GPU execution and routing;
- protocol, CLI, daemon and language bindings;
- compatibility, tests, benchmarks and operations.

## Agent repository

`ULTRABALLOONDB-AGENT` is a separate future repository containing:

- model and LLM integrations;
- GraphRAG orchestration;
- prompting and planning;
- agent tools;
- conversation-memory policies;
- ingestion workflows;
- answer evaluation.

## Hard boundary

The agent is a client of UltraBalloonDB. It may use the public protocol, SDK,
PyO3, C ABI or CLI. It must not import private storage, WAL, Wave, Trust or
router internals.

Agent, model or LLM output may propose records and evidence references. It
cannot bypass database validation or directly promote a trust state.
