# UltraBalloonDB Trust Model V1

Status: public semantic contract.

## Core rule

Relevance is not trust. Retrieval score, activation, similarity, frequency,
ranking, clustering, an agent assertion or an LLM assertion cannot independently
promote trust.

A trust change requires an auditable transition associated with evidence and
provenance under a versioned policy.

## Two public axes

### Maturity

- RAW
- HYPOTHESIS
- CANDIDATE
- VERIFIED

### Validity

- ACTIVE
- DISPUTED
- EXPIRED
- REVOKED
- SUPERSEDED

`VERIFIED` means verified under an identified policy, scope and evidence set. It
does not mean eternal or absolute truth.

## History

Trust transition history is append-only. The current state may be revoked,
expired, disputed or superseded without deleting the previous decision.

## Imports

Imported records preserve source provenance. An imported source assertion does
not automatically become a local VERIFIED state.

## Separation

Wave and similarity components may read trust for filtering or presentation.
They do not own trust mutation.
