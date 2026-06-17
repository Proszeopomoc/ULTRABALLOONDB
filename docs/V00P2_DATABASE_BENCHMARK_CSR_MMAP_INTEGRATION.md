# UltraBalloonDB V00P2 Database Benchmark CSR/MMAP Integration

Role: CORE  
Runtime impact: BENCHMARK_ONLY_CSR_MMAP_HOTPATH  
Alignment: ALIGNED

V00P2 replaces the abandoned V00P R01 Python-object benchmark with a benchmark path that uses persistent CSR files and `mmap` for L2/L3 hot-path operations.

Standard scales:

- 10,000
- 100,000
- 1,000,000
- 10,000,000

Measured axes:

- speed
- disk size
- RAM / working set
- network transfer and latency models
- correctness gates

Core gates:

- no full graph scan in `get_edges`
- no full graph scan in subgraph export
- `mmap` CSR active
- zero Python edge objects per base edge
- restart deterministic
- wave result deterministic
- committed data preserved
- uncommitted/partial data rejected

V00P2 preserves L2 typed edge graph and L3 wave activation. It does not introduce auxiliary C/G compression layers.
