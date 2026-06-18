# UltraBalloonDB Trust Governance V1

Status: **T4 IMPLEMENTATION PROFILE**

## Key rotation subject

```text
SHA256(
  "UBKROT01"
  || role_mask
  || key_id_length || key_id
  || old_fingerprint
  || new_fingerprint
)
```

Administrator signature:

```text
HMAC-SHA256(
  active_admin_secret,
  canonical_authorization_message(
    domain=KEY_ROTATE,
    required_role=KEY_ADMIN,
    subject=rotation_subject,
    key_registry_head=pre_rotation_head
  )
)
```

New-key proof:

```text
HMAC-SHA256(
  new_secret,
  canonical_authorization_message(
    domain=KEY_ROTATE,
    required_role=0,
    subject=rotation_subject,
    key_registry_head=pre_rotation_head,
    key_id=rotated_key_id
  )
)
```

## Policy revocation subject

```text
SHA256(
  "UBPOLRV1"
  || policy_digest
  || policy_id_length || policy_id
  || version_length || policy_version
  || reason_length || reason_code
)
```

Required role:

```text
POLICY_ADMIN
```

Authorization domain:

```text
POLICY_REVOKE
```

## Policy status ledger

```text
magic = "UBPST01\0"
payload_magic = "UBPSP01\0"
frame_domain = "UBPSTFR1"
```

Append-only, flush+fsync, strict replay, no repair.

## Audit export

The export root contains:

```text
database/
trust/
audit-summary.json
audit-manifest.json
audit-receipt.json
```

`audit-manifest.json` excludes itself and the receipt. It covers every copied
source file plus `audit-summary.json`.

```text
manifest_sha256 = SHA256(audit-manifest.json)
root_digest = SHA256(
  "UBAUDR01"
  || manifest_sha256
  || SHA256(audit-summary.json)
)
```

The source is hashed before and after export. Any difference causes failure
and removal of the incomplete export.
