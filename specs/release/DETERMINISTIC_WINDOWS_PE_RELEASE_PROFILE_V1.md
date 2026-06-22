# UltraBalloonDB Deterministic Windows PE Release Profile V1

## Scope

This profile applies only to the `x86_64-pc-windows-msvc` target.

## Integrated rule

```toml
[target.x86_64-pc-windows-msvc]
rustflags = ["-C", "link-arg=/Brepro"]
```

## Evidence basis

R4.6A classified the prior release mismatch as PE metadata or debug-path
nondeterminism and found no product-logic difference.

R4.6B demonstrated that the minimal `BREPRO_ONLY` profile produced ten out of
ten byte-identical top-level UltraBalloonDB `.exe`, `.dll`, and `.lib`
artifacts across two clean release builds in the same stable target path.

## Invariants

- no storage, WAL, record, vector-column, Trust, provenance, semantic, Wave, or
  CPU/GPU execution format is changed;
- no ANN path is introduced;
- canonical CPU behavior and unconditional CPU fallback remain unchanged;
- the flag is target-scoped and does not alter non-MSVC targets;
- release reproducibility is verified by two clean builds and byte-for-byte
  SHA-256 equality of the complete ten-artifact delivery set.
