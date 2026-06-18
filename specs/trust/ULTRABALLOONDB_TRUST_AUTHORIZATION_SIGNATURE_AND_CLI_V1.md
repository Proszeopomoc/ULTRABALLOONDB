# UltraBalloonDB Trust Authorization Signature and CLI V1

Status: **T3 IMPLEMENTATION PROFILE**

## 1. Signature algorithm

```text
algorithm = HMAC-SHA256
minimum_secret_bytes = 32
maximum_secret_bytes = 4096
```

Canonical signature message:

```text
"UBAUTSG1"
|| domain_code
|| required_role_mask
|| logical_timestamp
|| subject_digest
|| key_fingerprint
|| key_registry_head
|| key_id_length || key_id
|| nonce_length || nonce
```

Signature:

```text
HMAC-SHA256(secret, canonical_signature_message)
```

## 2. Key fingerprint

```text
SHA256(secret_bytes)
```

Raw secret bytes are never persisted.

## 3. Key event subject

REGISTER/BOOTSTRAP:

```text
SHA256(
  "UBKEYSUB"
  || target_key_id
  || target_key_fingerprint
  || target_role_mask
)
```

REVOKE:

```text
SHA256(
  "UBKEYREV"
  || target_key_id
  || target_key_fingerprint
)
```

## 4. Roles

```text
KEY_ADMIN      0x0001
POLICY_ADMIN   0x0002
TRUST_OPERATOR 0x0004
AUDITOR        0x0008
```

Unknown bits are rejected.

## 5. Policy subject

```text
subject_digest = PolicyDefinition::digest()
required_role = POLICY_ADMIN
domain = POLICY_REGISTER
```

## 6. Trust request subject

Canonical digest includes all public T2 request fields and ordered evidence
references. Caller-supplied record digest is absent.

```text
required_role = TRUST_OPERATOR
domain = TRUST_COMMIT
```

## 7. Files

Default trust root:

```text
keys.ubkey
authorizations.ubauth
policies.ubpolicy
trust.ubtrust
commit.ubcommit
```

## 8. Evidence file

UTF-8 TSV without header:

```text
evidence_id<TAB>provenance_id<TAB>64_HEX_SHA256
```

Blank lines and duplicate evidence IDs are rejected.

## 9. Security boundaries

- HMAC is symmetric authorization, not public-key nonrepudiation.
- Secret material is supplied per invocation and never written.
- Key fingerprint, signature and nonce are durable.
- Every mutating file uses append, flush and fsync.
- Replay is strict; corruption and truncated tails are rejected.
- `repair=false` remains mandatory for canonical database access.

## 10. Key registry head binding

Każdy POLICY_REGISTER i TRUST_COMMIT zapisuje i podpisuje dokładny hash head Key Registry z chwili autoryzacji. Audyt odtwarza stan aktywności i role signera na tym head, niezależnie od późniejszego revoke.
