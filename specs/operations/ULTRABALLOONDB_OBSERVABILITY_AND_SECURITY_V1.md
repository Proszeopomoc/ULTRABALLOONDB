# UltraBalloonDB Observability and Security V1

Status: additive Enterprise Shell contract.
Milestone: `V00R3E1_OBSERVABILITY_AND_SECURITY_R01`.

## Position in the product

This layer wraps the committed `DaemonBackend` contract. It does not implement a
second database lifecycle, storage format, WAL, Trust state machine, protocol or
Wave engine. The canonical database remains semantically blind.

## Observability contract

The layer exposes fixed, low-cardinality counters only:

- total operations;
- accepted operations;
- policy rejections;
- backend errors;
- health, read and write operation counts;
- request and response byte totals;
- audit event count;
- audit availability state.

Metric names are fixed and contain no request IDs, paths, user values, payloads,
keys, URIs or error strings. Dynamic labels are not part of V1.

## Security contract

- Request and response bodies are never written to audit or metrics.
- Only domain-separated SHA-256 digests and byte counts are recorded.
- Backend error text is replaced by stable generic error codes at the wrapper
  boundary.
- Request, response and audit-event limits are bounded and validated.
- Remote-network enablement is rejected by E1; remote transport requires a
  later explicit authentication/TLS gate.
- Write operations may be disabled by policy.
- Any audit append failure permanently marks the wrapper unavailable and future
  operations fail closed.

## Audit format

`observability-security.ube1audit` is append-only and contains:

1. a fixed 64-byte V1 file header;
2. fixed 180-byte event records;
3. contiguous sequence numbers starting at one;
4. explicit monotonic logical times supplied by the wrapper;
5. operation, outcome and stable reason code;
6. byte counts and request/response digests;
7. previous-record digest and current-record digest.

Strict replay rejects unsupported versions, non-zero reserved fields, sequence
or time regression, broken digest chains, tampering, truncation and trailing
bytes.

## Backend wrapper

`ObservedBackend<B>` implements the existing D2 `DaemonBackend` trait. It can be
used by future hosts without modifying D2. E1 itself does not install a service,
open a listener or activate production routing.

## Explicit exclusions

E1 does not provide TLS, remote authentication, secret storage, OS service
installation, SIEM delivery, external telemetry export, active runtime wiring,
or changes to storage/WAL/lifecycle/Trust/Wave semantics.
