# UltraBalloonDB Trust Model and Transition Ledger V1

Status: **T1 IMPLEMENTATION PROFILE**

## 1. Separation invariant

Trust is not relevance. The following signals are trust-neutral:

- rank/score;
- wave activation;
- similarity;
- frequency;
- import volume;
- LLM or agent output;
- rigor multiplier.

Only an evidence-backed transition accepted by the trust gate may mutate trust.

## 2. State axes

Maturity:

```text
RAW -> HYPOTHESIS -> CANDIDATE -> VERIFIED
```

Promotion may advance exactly one maturity step. Skipping is forbidden.

Validity:

```text
ACTIVE | DISPUTED | EXPIRED | REVOKED | SUPERSEDED
```

Validity transitions preserve maturity. `REVOKED` and `SUPERSEDED` are terminal.
Promotion is allowed only while validity is `ACTIVE`.

## 3. Operations

- `PROPOSE`: untracked -> RAW/ACTIVE;
- `PROMOTE`: one maturity step, validity remains ACTIVE;
- `DISPUTE`: ACTIVE -> DISPUTED;
- `REVOKE`: ACTIVE/DISPUTED/EXPIRED -> REVOKED;
- `EXPIRE`: ACTIVE/DISPUTED -> EXPIRED;
- `SUPERSEDE`: ACTIVE/DISPUTED/EXPIRED -> SUPERSEDED and requires another
  existing, non-terminal record.

Import authority may only `PROPOSE`. Every other transition requires
`EVIDENCE_POLICY` authority.

## 4. Required evidence contract

Every accepted transition contains at least one unique evidence reference:

```text
evidence_id
provenance_id
evidence_digest
```

Empty IDs, empty provenance, duplicate evidence IDs and zero digests are
rejected. `policy_id`, `policy_version`, `verifier_id`, `reason_code` and
`record_digest` are mandatory. Later transitions must use the record digest
bound by `PROPOSE`.

## 5. Transition fields

```text
transition_id
record_id
previous_state
next_state
evidence_refs
policy_id
policy_version
verifier_id
record_digest
input_digest
decision_digest
logical_timestamp
reason_code
operation
authority
superseding_record_id
```

`input_digest`, `decision_digest` and `transition_id` are calculated by the
Rust trust core from canonical binary preimages.

## 6. Ledger V1

Each frame contains:

```text
magic
format version
sequence
logical timestamp
payload length
previous transition digest
payload digest
transition digest
reserved bytes
canonical transition payload
```

Invariants:

- sequence starts at 1 and is contiguous;
- logical timestamp is strictly increasing;
- frame points to the previous transition digest;
- payload and transition digests use SHA-256;
- accepted frames are appended, flushed and fsynced;
- strict open rejects invalid magic, version, sequence, chain, digest,
  semantic transition, corruption and truncated tail;
- no automatic repair in T1;
- history is never rewritten when a record is disputed, expired, revoked or
  superseded.

## 7. Single mutator

Only `TrustLedger::apply` may append a transition and update the replayed state.
Callers cannot directly set `VERIFIED`, `REVOKED` or any other trust state.

## 8. T1 boundaries

The ledger is a standalone Rust trust primitive. Canonical database binding,
transactional co-commit, policy registry, signatures, authorization and CLI
commands are later gates.
