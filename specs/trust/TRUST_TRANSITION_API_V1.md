# UltraBalloonDB Trust Transition API V1

Status: public API-level contract, not an internal validation algorithm.

## Conceptual operations

- propose
- promote
- dispute
- revoke
- expire
- supersede

## Public transition envelope

A transition records, at minimum:

- transition identifier;
- record or claim identifier;
- previous and next state;
- evidence references;
- policy identifier and version;
- verifier identifier;
- content/decision digests;
- logical timestamp;
- reason code.

## Mutation boundary

The canonical Trust component is the only owner of trust-state mutation.
Other modules receive read-only trust views and relevance-only result types.

## Private implementation boundary

This specification does not publish private acceptance thresholds, hidden
adversarial cases, secret fingerprints or customer-specific policy material.
