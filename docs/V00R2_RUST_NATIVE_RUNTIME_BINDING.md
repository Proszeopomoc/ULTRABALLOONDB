# UltraBalloonDB V00R2 Rust Native Runtime Binding

V00R2 binds the V00R1 standalone Rust CSR/mmap engine to the stable database
API as an opt-in active query backend.

## Scope

- Persistent Rust process opens the derived CSR layout once.
- L2 outgoing-edge queries use Rust CSR slices.
- L3 wave activation uses the established typed attenuation and blocking rules.
- L7 selected subgraph data is returned by the same native request.
- V00O HTTP transport can call the Rust-bound facade unchanged.
- Canonical L0 data, WAL, checkpointing and mutations remain owned by the
  established Python runtime.

## Safety contract

A committed edge mutation marks the derived Rust layout stale. Queries then
fall back to the canonical Python path until an explicit CSR rebuild. A dead or
malformed Rust process also triggers safe Python fallback. No fallback silently
changes canonical data.

## Promotion boundary

V00R2 is an active query binding, not a full L0-L7 runtime replacement. Full
promotion requires V00R3 with native storage/WAL/API lifecycle and equivalent
Windows/Linux gates.
