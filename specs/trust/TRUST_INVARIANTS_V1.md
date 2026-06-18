# UltraBalloonDB Trust Invariants V1

Status: public regression contract.

1. New locally ingested records do not enter as VERIFIED.
2. Trust promotion is unavailable through ranking, Wave, similarity or frequency APIs.
3. A numeric score is not evidence.
4. Agent or LLM output cannot directly mutate trust.
5. Imported provenance does not automatically create local verification.
6. Evidence must be bound to the affected record or claim.
7. Every trust transition is auditable and append-only.
8. Revocation, expiry, dispute and supersession preserve history.
9. `rigor_multiplier` and query parameters may filter results but cannot mutate trust.
10. Trust semantics are identical across native binary, PyO3, daemon and C ABI editions.
