# UltraBalloonDB C ABI V1

## Scope

D3 exposes the already-committed D2 bounded protocol session through a stable versioned C ABI. D3 does not bind the production database runtime, install a service, alter storage/WAL/lifecycle formats, or expose network listening through the ABI.

## Stability boundary

All exported symbols carry the `_v1` suffix. Public structures are `repr(C)` and begin with `struct_size` and `abi_version`. Unknown structure sizes or versions are rejected. The public header is committed at `rust_native/ultraballoondb-cabi/include/ultraballoondb.h`.

## Ownership

The session handle is opaque and must be destroyed exactly once. Request and response memory is caller-owned. Backend callbacks return borrowed byte views; the Rust boundary validates and copies them before callback return. No Rust allocation is transferred to C.

## Buffer rule

`ubdb_session_process_frame_v1` requires a response buffer at least as large as the configured `max_frame_bytes`. If it is smaller, the function returns `UBDB_STATUS_BUFFER_TOO_SMALL`, writes the required capacity, and does not process or mutate the protocol session.

## Configuration consistency

`max_read_payload_bytes` and `max_write_payload_bytes` must each fit within `max_frame_bytes - 64`. Reducing `max_frame_bytes` without reducing the payload limits is invalid and returns `UBDB_STATUS_INVALID_ARGUMENT` without creating a session handle.

## Backend boundary

The C caller provides health, read, and write callbacks. D3 adapts them to the D2 `DaemonBackend` trait. Callback failure is fail-closed. A failed or malformed health callback is represented as unhealthy and read-only.

## Panic and validation boundary

Exported functions reject null pointers, wrong structure versions/sizes, non-zero reserved fields, invalid protocol frames, and invalid configuration. Every exported entry point contains a panic guard. The workspace release profile remains `panic = abort`; the ABI is designed so ordinary invalid input returns status codes rather than panicking.

## Concurrency

A session handle is not thread-safe. External synchronization is required. D3 does not provide background threads, autonomous retry, remote binding, TLS, authentication, or service registration.
