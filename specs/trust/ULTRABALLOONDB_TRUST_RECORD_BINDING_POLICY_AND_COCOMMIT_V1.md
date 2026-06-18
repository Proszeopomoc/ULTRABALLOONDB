# UltraBalloonDB Trust Record Binding, Policy Registry and Co-Commit V1

Status: **T2 IMPLEMENTATION PROFILE**

## 1. Canonical record digest

```text
SHA256(
  "UBTRREC1"
  || logical_id
  || record_id_length || record_id
  || node_id
  || payload_length
  || payload_sha256
  || payload
)
```

Caller nie może ustawić `record_digest`.

## 2. Policy definition

```text
policy_id
policy_version
allowed_authority
allowed_operation_mask
min_evidence_refs
max_evidence_refs
required_verifier_id
require_unique_provenance
policy_digest
```

Allowed authorities in T2 registry:

```text
IMPORT
EVIDENCE_POLICY
```

Inne authorities są trust-neutral i nie mogą zostać zarejestrowane jako
mutator trust.

## 3. Immutable registry

Policy key może zostać zapisany tylko raz. Nowa wersja używa nowego
`policy_version`. Brak update-in-place i delete.

Każda frame zawiera hash poprzedniej frame, payload SHA i frame digest.
Append, flush i fsync są obowiązkowe.

## 4. Commit request

Request nie zawiera record digest:

```text
record_id
operation
authority
evidence_refs
policy_id
policy_version
verifier_id
logical_timestamp
reason_code
superseding_record_id
```

## 5. Database binding record

Immutable binding record zapisuje:

```text
transaction_id
target_record_id
canonical_record_digest
policy_digest
request_digest
trust_pre_head
expected_trust_sequence
logical_timestamp
```

Binding record jest durable przed append trust transition.

## 6. Commit journal

Stages:

```text
PREPARED
DATABASE_COMMITTED
TRUST_COMMITTED
FINALIZED
ABORTED
```

Journal frame zawiera pełny request i wystarczające dane do deterministycznego
recovery bez zewnętrznego caller state.

## 7. Exactly-once recovery

Recovery rozpoznaje już wykonany trust transition przez pełne porównanie pól:

- record ID;
- operation;
- authority;
- evidence refs;
- policy ID/version;
- verifier ID;
- record digest;
- logical timestamp;
- reason code;
- superseding record ID.

Niezgodny transition jest hard failure.

## 8. T2 boundaries

Brak signatures, user authorization, policy revocation, policy effective-time
windows i CLI trust commands. Są to kolejne gate'y.
