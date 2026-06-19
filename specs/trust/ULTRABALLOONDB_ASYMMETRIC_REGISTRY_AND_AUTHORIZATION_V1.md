# UltraBalloonDB Asymmetric Registry and Authorization V1

## Algorithm

```text
provider = Microsoft Software Key Storage Provider
algorithm = ECDSA_P256
hash = SHA256
public_blob = BCRYPT_ECCPUBLIC_BLOB
signature = IEEE-P1363 r||s, 64 bytes
```

## Registry proof rules

### ENROLL
The new private key signs the enrollment subject.

### ROTATE
The active old key and new key both sign the same exact rotation subject.

### REVOKE
The active current key signs the revocation subject.

## Authorization proof

```text
authorization_message_digest = SHA256(
  "UBASAU01"
  || domain_code
  || required_role_mask
  || subject_digest
  || registry_head
  || public_key_digest
  || logical_timestamp
  || key_id
  || nonce
)
```

The authorization event ID is bound to the authorization digest and signature.

## Provider boundary

Private key bytes are owned by Windows CNG. Registry records contain no
private-key blob. `PKCS8_PRIVATEKEY` export must be rejected by the provider.
