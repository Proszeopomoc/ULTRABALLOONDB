# UltraBalloonDB — Shared Rust Core and Delivery Modes Architecture

**Milestone:** `V00R3A_SHARED_RUST_CORE_AND_DELIVERY_MODES_ARCHITECTURE`  
**Role:** `SUPPORT`  
**Runtime impact:** `DOCUMENTATION_AND_ARCHITECTURE_CONTRACT_ONLY`  
**Roadmap status:** `ALIGNED`

## 1. Architectural decision

UltraBalloonDB will not be maintained as several separate database implementations.

The project will use:

```text
ONE_CANONICAL_RUST_CORE = TRUE
MULTIPLE_DELIVERY_MODES = TRUE
SEPARATE_DATABASE_IMPLEMENTATIONS = FALSE
```

All product variants must share the same:

- binary storage format,
- exact-index semantics,
- typed-edge graph semantics,
- wave-activation semantics,
- path-evidence semantics,
- WAL and recovery contract,
- checkpoint contract,
- floating-subgraph format,
- compatibility tests,
- correctness gates.

A product variant may change the deployment boundary, API surface, process model, packaging, and security envelope. It must not silently change database meaning.

## 2. Current verified state

### V00R1 — native Rust CSR/mmap/wave candidate

Verified on Windows with:

```text
1,000,000 events
3,000,000 edges
5,000 batch queries
TopK = 64
MaxSteps = 2
EnergyThreshold = 0.10
```

Confirmed:

- node bytes identical to Python,
- edge bytes identical to Python,
- wave parity,
- floating-subgraph parity,
- mmap active,
- zero full-graph scans,
- no third-party Rust crates,
- Python not required by the Rust binary.

Measured result:

```text
Python batch: approximately 10,202 queries/s
Rust batch:   approximately 284,309 queries/s
Query speedup: approximately 27.87x

Python p95: approximately 104.6 microseconds
Rust p95:   approximately 5.2 microseconds
```

The synthetic CSR build comparison measured approximately `61.74x` diagnostic speedup. This is not yet a claim for the complete database lifecycle.

### V00R2 — active Rust query binding

Verified on the real UltraBalloonDB runtime:

- active query backend: `RUST_NATIVE`,
- persistent Rust process,
- Python query hot path bypassed on successful requests,
- safe Python fallback on controlled Rust-process failure,
- layout marked stale after graph mutation,
- Python fallback while stale,
- Rust reactivated after CSR rebuild,
- WAL and checkpoint remained valid,
- HTTP and protocol parity passed,
- zero full-graph scans.

Current ownership boundary:

```text
Rust:
- L2 get_edges
- L3 wave activation
- L7 floating-subgraph query path

Python:
- canonical writes
- WAL ownership
- checkpoint ownership
- database creation
- lifecycle orchestration
```

Therefore:

```text
ACTIVE_RUST_QUERY_BINDING = TRUE
ACTIVE_FULL_RUNTIME_REPLACEMENT = FALSE
```

## 3. Product delivery modes

## 3.1 Edition A — Pure Rust Binary

**Form**

```text
ultraballoondb.exe
ultraballoondb
```

**Purpose**

- production servers,
- edge computing,
- industrial systems,
- IoT devices,
- low-power deployments,
- official native benchmarks.

**Target ownership**

Rust owns the entire database lifecycle:

- L0 physical storage,
- L1 exact indexes,
- L2 typed-edge graph,
- L3 wave activation,
- L4 hot snapshot,
- L5 batch payload fetch,
- L6 crystallization,
- L7 floating subgraphs,
- canonical writes,
- WAL append and commit,
- checkpoint,
- crash recovery,
- CSR rebuild,
- CLI,
- native server interfaces.

**Expected benefit**

- no Python runtime,
- no process-boundary query overhead,
- lowest normal-runtime latency,
- highest batch throughput,
- predictable memory use,
- simple deployment as one compiled executable.

The measured `284,309 queries/s` result belongs to the native L2/L3 batch core. It is not yet a verified throughput claim for the complete server with concurrent writes, WAL, HTTP, and recovery.

## 3.2 Edition B — Native Python Extension through PyO3

**Form**

```python
import ultraballoondb
```

**Purpose**

- AI agents,
- local research,
- notebooks,
- Python automation,
- integration with Ollama, PyTorch, NumPy, Arrow, and data pipelines.

**Design**

The shared Rust core is compiled as:

```text
Windows: .pyd
Linux:   .so
macOS:   .dylib / Python extension bundle
```

Python remains the application and orchestration layer. The database engine remains Rust.

**Important contract**

PyO3 is not automatically zero-copy. Zero-copy or bounded-copy operation must use explicit buffer-compatible interfaces such as:

- `memoryview`,
- `bytes`/byte buffers,
- NumPy arrays,
- Arrow buffers,
- mmap-backed views.

Python dictionaries, lists, objects, and JSON may require conversion and allocation.

**Goal**

Remove the process and protocol overhead measured in V00R2 while preserving Python usability. Throughput targets must be measured; no unverified `150k–200k queries/s` claim is part of the contract.

## 3.3 Edition C — Isolated Rust Daemon / Service

**Form**

```text
ultraballoondbd
```

**Purpose**

- commercial customer deployment,
- polyglot environments,
- multiple client processes,
- process isolation,
- controlled upgrades,
- central authorization and observability.

**Supported transport directions**

- Unix Domain Sockets,
- Windows Named Pipes,
- TCP,
- HTTP,
- optional shared-memory ring buffer,
- optional binary batch protocol.

**Benefits**

- clients can be written in C#, Java, Go, JavaScript, Python, Rust, or other languages,
- Rust engine failure is isolated from client processes,
- one database process can serve multiple clients,
- access control and deployment policy can be centralized.

The current V00R2 result of approximately `10,636 queries/s` includes process/protocol overhead and is not a permanent ceiling. Binary batching, persistent connections, reduced serialization, and shared memory may improve it.

A compiled black-box process increases deployment isolation but does not make reverse engineering impossible.

Hardware binding is a separate optional layer and may use:

- TPM-backed keys,
- signed license tokens,
- machine identity,
- encrypted key storage,
- remote attestation.

## 3.4 Edition D — Embedded Native Library with Stable C ABI

**Form**

```text
Windows: ultraballoondb.dll
Linux:   libultraballoondb.so
macOS:   libultraballoondb.dylib
```

**Purpose**

- C and C++ applications,
- C# through P/Invoke,
- Java through JNI,
- Go through cgo,
- Swift,
- Unity,
- Unreal Engine,
- desktop software,
- industrial and embedded applications.

**Example ABI direction**

```c
ubdb_handle* ubdb_open(const char* path, const ubdb_options* options);
int ubdb_put(ubdb_handle* db, const ubdb_record* record);
int ubdb_get_edges(ubdb_handle* db, uint64_t node_id, ubdb_edge_buffer* out);
int ubdb_wave(ubdb_handle* db, const ubdb_wave_request* request, ubdb_wave_result* out);
int ubdb_checkpoint(ubdb_handle* db);
void ubdb_close(ubdb_handle* db);
```

**Benefits**

- same-process native performance,
- no Python dependency,
- no IPC requirement,
- stable integration surface for many languages.

C ABI belongs to the embedded-library edition, not to the isolated-daemon edition.

## 3.5 Future Edition E — Distributed Cluster

This edition is explicitly future work.

Potential scope:

- replication,
- high availability,
- failover,
- sharding,
- multi-node storage,
- distributed query routing,
- distributed wave activation,
- consensus and recovery contracts.

It must not be started before the single-node Rust core and all four primary delivery modes share a stable format and test contract.

## 4. Shared Rust workspace

Target workspace:

```text
rust_native/
  Cargo.toml

  ultraballoondb-core/
    binary format
    CSR/mmap
    typed edges
    wave activation
    path evidence
    floating subgraphs

  ultraballoondb-storage/
    archive
    indexes
    canonical writes
    WAL
    checkpoint
    recovery
    compaction

  ultraballoondb-server/
    daemon
    HTTP
    IPC
    authorization
    observability

  ultraballoondb-cli/
    pure Rust executable

  ultraballoondb-py/
    PyO3 extension

  ultraballoondb-ffi/
    stable C ABI
```

No delivery mode may fork and independently reimplement the database semantics.

## 5. Migration roadmap

### V00R3A — Shared Rust core contract

- convert the current single Rust binary into a workspace,
- extract reusable core and storage crates,
- freeze public internal contracts,
- preserve V00R1 and V00R2 parity.

### V00R3B — Pure Rust full runtime

- move canonical writes to Rust,
- move WAL, checkpoint, and recovery to Rust,
- move database open/restart lifecycle to Rust,
- provide native CLI and server,
- remove Python from normal production runtime.

### V00R4 — PyO3 native extension

- bind the shared Rust core,
- use batch and buffer-oriented APIs,
- test zero-copy paths where technically valid,
- benchmark against V00R2 process binding.

### V00R5 — Optimized daemon and binary protocol

- replace text-heavy protocol paths,
- add persistent binary sessions,
- add batching,
- evaluate shared memory,
- preserve safe process isolation.

### V00R6 — Stable C ABI embedded library

- define versioned ABI,
- define ownership and buffer rules,
- provide C header,
- add C/C++ and C# integration tests,
- produce DLL/SO/DYLIB artifacts.

## 6. Non-negotiable gates

Every edition must pass:

```text
binary format parity = TRUE
typed-edge semantics parity = TRUE
wave-result parity = TRUE
path-evidence parity = TRUE
WAL recovery parity = TRUE
restart determinism = TRUE
full_scan_counter = 0
Windows compatibility = TRUE
Linux compatibility = TRUE
```

macOS compatibility may only be claimed after a real native macOS test.

Additional rules:

- no hidden change to canonical meaning,
- no separate incompatible database formats,
- no benchmark claim without a reproducible report,
- no removal of safe rollback before replacement is verified,
- no automatic claim that PyO3 is zero-copy,
- no claim that compiled binaries prevent reverse engineering,
- no claim that WAN latency is improved by a faster local engine.

## 7. Platform status

Current verified status:

```text
Windows native runtime: PASS
Linux under WSL2, native Linux Python/filesystem: PASS
Windows ↔ Linux binary compatibility: PASS
macOS native: NOT TESTED
Linux ARM64: NOT TESTED
macOS ARM64: NOT TESTED
```

## 8. Licensing and repository status

At the time of this architecture decision:

```text
repository visibility: PRIVATE
local provenance audit: PASS
detected packages: 0
ScanCode license/copyright findings: 0
manual provenance findings: 0
external snippet-corpus scan: DEFERRED UNTIL FINAL CODE FREEZE
final license decision: DEFERRED
```

The final external snippet scan, license selection, and release freeze must be repeated against the final release-candidate commit.

## 9. Product principle

UltraBalloonDB is one database engine with several deployment modes.

```text
ONE ENGINE
ONE FORMAT
ONE WAL CONTRACT
ONE QUERY SEMANTICS
ONE CORRECTNESS SUITE
MULTIPLE DELIVERY MODES
```
