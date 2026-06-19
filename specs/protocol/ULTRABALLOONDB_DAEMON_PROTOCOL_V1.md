# UltraBalloonDB Daemon Protocol V1

## Scope

D2 defines a deterministic bounded binary protocol and a loopback-first daemon core. It does not install or start a production service and does not replace the active database runtime.

## Transport

Each TCP message is a little-endian `u32` length followed by one complete protocol frame. The default binding policy accepts loopback addresses only. Remote binding requires a later explicit security gate.

## Frame

The fixed 64-byte header contains magic, protocol version, frame kind, flags, request ID, payload length, reserved fields, and a SHA-256 frame digest. Reserved fields must be zero. Unknown kinds, versions, digest mismatches, truncation, trailing bytes, zero request IDs, and frames above the configured bound are rejected.

## Session

The first request must be `HELLO`. A non-`HELLO` first request returns an error and fail-closes that session; a later request cannot revive it. After a successful handshake, request IDs are non-zero, unique, and strictly increasing. A duplicate or non-increasing ID is rejected without silently advancing the accepted sequence. Each connection has a bounded request budget and bounded read/write payload limits. Supported core requests are `PING`, `HEALTH`, `CAPABILITIES`, `READ`, `WRITE`, and `CLOSE`.

## Backend boundary

The daemon core depends on an explicit `DaemonBackend` trait. D2 validates protocol and transport behavior with a probe backend only. Binding the production UltraBalloonDB runtime is a separate promotion decision.

## Security boundary

The frame digest detects corruption and deterministic tampering; it is not authentication or encryption. D2 binds to loopback by default. Authentication, TLS, authorization mapping, rate-limit policy, and production service hardening remain gated for E1.
