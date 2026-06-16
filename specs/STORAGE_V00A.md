# UltraBalloonDB Storage V00A Draft

## Physical Files

```text
*.upage   page-store payload pages
*.uedge   generic lossless edge archive
*.uhot    compact hot snapshot
*.uoff    record offset index
*.umeta   metadata and checksums
```

## Page Size Direction

Benchmark candidates:

```text
4 KB
16 KB
64 KB
256 KB
```

64 KB is a serious candidate for coalesced context fetch, but it must be tested against fragmentation and small-record overhead.

## Hot Snapshot

The hot snapshot contains only the working topology required for fast recall:

```text
bounded adjacency
edge type masks
attenuation table ID
project/code/rule tails
topological shortcut hints
blocking masks
```

## Lossless Archive

The lossless archive contains the full edge truth and is used for:

```text
audit
offline rebuild
crystallization
recovery
full provenance
```

It is not the startup hot path.
