# UltraBalloonDB CPU/GPU Exact Router V1

## Scope

R4.4 adds an active exhaustive cosine router to `ultraballoondb-semantic`.
The canonical Rust CPU implementation remains the source of truth. The GPU path is an optional read-only accelerator over an immutable query batch.

## Invariants

- Exact exhaustive scoring only. No ANN, approximate pruning or graph narrowing.
- OpenCL FP64 performs dot product and vector norm in the same dimension order as the CPU reference.
- Parallelism is across candidate vectors. Each work-item accumulates one vector sequentially by dimension; V1 does not use a parallel reduction tree across dimensions.
- `#pragma OPENCL FP_CONTRACT OFF` prevents contraction in the kernel. Because the CPU and GPU execute the same ordered FP64 accumulation and final cosine division remains on CPU, raw bitwise parity is a valid hardware certification gate for this V1 kernel.
- Score quantization and tolerance-based ranking are intentionally not used: they could alter exact ordering for near-ties and would weaken the exact-cosine contract.
- Final cosine division, deterministic sort and record-ID tie-break remain on CPU.
- GPU activation requires an FP64 device, kernel build success, exact-parity certification and a measured runtime crossover.
- Crossover is semantic-vector-specific and is never inherited from Wave. It is calibrated separately per vector dimension and candidate-count frontier.
- Crossover timing includes host packing of selected vectors, OpenCL buffer allocation, host-to-device writes, kernel execution, synchronization and device-to-host reads. Common CPU ranking, record-ID tie-break and Trust filtering remain outside the differential timing because both routes execute them on CPU.
- Calibration uses the median of three measurements and requires at least a 5% end-to-end GPU advantage before automatic GPU promotion.
- Every query samples first/middle/last GPU rows against the CPU reference.
- Any loader, device, allocation, kernel, parity or calibration failure causes unconditional CPU fallback.
- Trust is read-only filtering outside semantic score and is never a score component.
- The GPU does not write canonical records, vector columns, WAL, Trust, graph snapshots or inventory.
- The GPU batch is bound to the caller's `ReadSnapshot`; returned hits carry the same snapshot digest.
- Storage format, vector column format, canonical record format and WAL format do not change.

## Platform boundary

V1 activates the OpenCL backend on Windows through dynamic `OpenCL.dll` loading and keeps a compile-time CPU fallback on other platforms. A later additive backend may extend OpenCL loading to Linux/macOS without changing the router contract.

## Runtime configuration

- `ULTRABALLOONDB_GPU_ROUTER=auto|cpu|gpu`
- `ULTRABALLOONDB_GPU_BOOTSTRAP_CANDIDATES=<positive integer>`
- `ULTRABALLOONDB_GPU_MAX_BATCH_BYTES=<positive integer>`

`gpu` is a diagnostic force mode. It does not bypass FP64, parity or error gates.
