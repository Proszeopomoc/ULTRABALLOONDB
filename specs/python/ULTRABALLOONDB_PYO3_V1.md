# UltraBalloonDB PyO3 V1

## Scope

D4 exposes the committed D3 C ABI through a CPython extension built with PyO3 `0.24.2` and the stable `abi3-py38` interface. D4 does not bypass D3, install a service, bind a production database, open a listener, or alter storage, WAL, lifecycle or active runtime behavior.

## Module

The extension module is `ultraballoondb_native`. It exposes ABI/protocol versions, frame encode/decode helpers, HELLO payload encoding, protocol-kind constants, and an unsendable `Session` class.

## Backend contract

The Python backend object must implement:

- `health() -> (healthy: bool, read_only: bool, generation: int)`
- `execute_read(request: bytes) -> bytes`
- `execute_write(request: bytes) -> bytes`

Python callback failures are converted to the existing D3 backend status and fail closed. Returned bytes are copied by D3 before callback return. Recursive callback entry is rejected.

## Ownership and lifetime

The Python `Session` owns the D3 opaque handle and the callback context. `destroy()` is idempotent. `Drop` destroys any remaining handle before the Python callback context is released. No Rust allocation is transferred to Python or C.

## GIL and concurrency

Python callbacks execute while holding the GIL. `Session` is explicitly unsendable and not thread-safe. D4 creates no background thread and performs no autonomous retry.

## Dependency policy

PyO3 is pinned exactly to `0.24.2`. The installer commits the generated Cargo lock, verifies the resolved version, fetches once if the exact dependency is not cached, and then runs check, test and release build with `--locked --offline`.
