# UltraBalloonDB V00A Test Plan

## V00A

Repository bootstrap and boundary validation.

Pass condition:

```text
repo created
docs installed
no agent logic in core docs
original topological wave direction documented
```

## V00B

Wave activation benchmark.

Measure:

```text
events: 10k / 100k / 1M
edges: typed
query: wave_activation
filters: edge_mask, top_k, energy_threshold
latency: p50 / p95 / p99
returned nodes
energy path traces
```

## V00C

Edge attenuation table benchmark.

Measure:

```text
different attenuation tables
strict vs explorative multiplier
blocked edges
latency and returned node quality proxy
```

## V00D

Batch/coalesced payload fetch.

Measure:

```text
top_k: 10 / 25 / 50 / 100 / 250
page size: 4 KB / 16 KB / 64 KB / 256 KB
payload fetch latency
context assembly latency
read amplification
```

## V00E

Relation algebra.

Measure:

```text
read-time derived relations
no physical edge creation
latency overhead
correctness against deterministic transition table
```

## V00F

Crystallization paths.

Measure:

```text
repeated path detection
snapshot size reduction
reload speed
query speed before/after crystallization
provenance preservation
```

## V00G

Hot snapshot + archive split.

Measure:

```text
startup time
RAM usage
cold fetch
warm recall
rebuild time
```

## V00H

Floating subgraphs.

Measure:

```text
export size
import latency
integrity checks
duplicate handling
provenance
```
