# UltraBalloonDB Enterprise Approval and Audit Profile V1

Status: **T5 implementation profile**

## Profile

```text
profile_id = ENTERPRISE_STRICT_V1
approval_threshold = 2
approver_role = AUDITOR
requester_excluded = true
distinct_approvers = true
max_logical_ttl = 1000
one_time_finalization = true
```

## Protected subject domains

```text
4 = POLICY_REGISTER
5 = TRUST_COMMIT
6 = KEY_ROTATE
7 = POLICY_REVOKE
```

## Request ID

```text
request_id = SHA256(
  "UBAPRQ01"
  || profile_digest
  || domain
  || subject_digest
  || requester_fingerprint
  || created_at
  || expires_at
  || key_registry_head
  || requester_id
  || nonce
)
```

## Approval signature

```text
HMAC-SHA256(
  approver_secret,
  "UBAPSG01"
  || event_kind
  || request_id
  || profile_digest
  || subject_digest
  || operation_reference
  || logical_timestamp
  || expires_at
  || actor_fingerprint
  || key_registry_head
  || requester_id
  || actor_id
  || nonce
)
```

## Enterprise operation coverage

Every post-activation authorization record in domains 4, 5 and 7 must be
referenced by exactly one valid `FINALIZE` event.

Every post-activation `KEY_ROTATE` event must be referenced by exactly one
valid `FINALIZE` event.

The enterprise audit status is PASS only when:

```text
uncovered_protected_operation_count = 0
invalid_finalization_count = 0
expired_finalization_count = 0
```
