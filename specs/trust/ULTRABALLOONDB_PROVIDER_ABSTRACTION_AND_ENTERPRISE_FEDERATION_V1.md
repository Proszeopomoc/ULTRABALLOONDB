# UltraBalloonDB Provider Abstraction and Enterprise Federation V1

## Scope

T6C adds a provider-neutral signing interface above the T6B asymmetric registry and authorization ledger, plus a separate append-only enterprise federation ledger.

## Provider contract

A provider advertises availability, persistent-key support, private-export rejection, provider class, hardware binding, TPM usage, and an evidence digest. Admission is explicit:

- `SOFTWARE_ALLOWED` admits a verified software provider.
- `HARDWARE_REQUIRED` rejects software and unavailable hardware providers.
- `TPM_REQUIRED` rejects software and unavailable TPM providers.

No fallback from a hardware/TPM requirement to software is permitted.

## Federation file

`enterprise-federation.ubfed` is an append-only SHA-256 frame chain. It does not modify database storage, WAL, lifecycle, active runtime, or existing trust ledgers.

Event types:

1. `NAMESPACE_POLICY_SET`
2. `AUTHORITY_ENROLL`
3. `AUTHORITY_REVOKE`
4. `BUNDLE_ACCEPT`

## Policy and quorum

Each namespace has one immutable V1 policy containing a controller key, controller role, authority role, weighted quorum threshold, and provider requirement. Controller operations reference exact T6B authorization events. Bundle acceptance requires:

- exact namespace and policy digest binding;
- monotonic bundle version;
- the previous accepted bundle digest after version 1;
- strictly increasing authorization sequences;
- one approval per authority key;
- no authorization-event reuse;
- active namespace authorities whose total weight reaches quorum;
- provider class satisfying the namespace policy.

Replay resolves signer state at the historical T6B key-registry head. Later key revocation does not invalidate previously verified evidence.

## Security boundaries

- No private key bytes are written by UltraBalloonDB.
- T6C does not claim hardware binding or TPM use when T6A reports them unavailable.
- No network, automatic repair, policy activation, active routing, database runtime mutation, storage-format mutation, or WAL mutation is introduced.
