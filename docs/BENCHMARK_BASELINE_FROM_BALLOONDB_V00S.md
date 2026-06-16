# Benchmark Baseline from BalloonDB V00S Sequence

## Purpose

This file records why UltraBalloonDB starts from typed topological memory and not from a generic storage-only design.

## Evidence Summary

The BalloonDB V00S sequence showed:

```text
V00S:
typed topological balloon recall in RAM works at microsecond/millisecond scale.

V00S1:
compact typed graph artifacts can reload quickly.

V00S2:
full payload fetch after balloon recall works, but payload fetching dominates latency when many nodes are fetched.

V00S3:
generic lossless edge archive and benchmark page-store work, but full edge-store reload is too heavy for the hot path.
```

## Architectural Consequence

UltraBalloonDB must separate:

```text
hot working memory:
  compact snapshot + wave activation + top_k + batch fetch

cold source of truth:
  page-store + generic lossless edge archive + offline rebuild
```

## First Optimization Target

The first optimization is not semantic search.  
The first optimization is:

```text
wave_activation + top_k + batch/coalesced payload fetch
```
