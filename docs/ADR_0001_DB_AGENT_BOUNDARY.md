# ADR 0001: Database / Agent Boundary

## Status

Accepted.

## Decision

UltraBalloonDB must remain a deterministic low-level database and memory engine. It must not contain agent logic.

## Database Responsibilities

UltraBalloonDB may implement:

- node IDs
- typed edge IDs
- edge masks
- edge attenuation
- blocking edges
- wave activation
- top-k limiting
- physical page layout
- offset indexes
- hot snapshots
- lossless edge archives
- batch payload fetch
- structural compaction
- deterministic subgraph export/import

## Agent Responsibilities

The agent layer must own:

- interpretation
- semantic meaning
- query intent
- policy choices
- LLM calls
- speech/text interfaces
- summaries
- decisions about what should be remembered or blocked
- setting database parameters such as `top_k`, `energy_threshold`, and `rigor_multiplier`

## Reason

Mixing database logic with agent logic destroys low-level optimizability. The database must be semantically blind. It operates on IDs, bytes, edge types, offsets, masks, energies and scores.

The agent provides meaning.  
The database provides deterministic cognitive infrastructure.
