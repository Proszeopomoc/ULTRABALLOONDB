# R4.9C2 Product-Bound Hybrid Engine

## Product path

The canonical product query path is:

`DurableDatabase ReadSnapshot`
→ `external semantic vector space`
→ `exact CPU/GPU router`
→ `native structural vector space`
→ `exact CPU/GPU router`
→ `Wave/topological scope`
→ `deterministic weighted fusion`
→ `Trust eligibility filter`
→ `ProductHybridReceipt`.

## Invariants

- The existing semantic, native structural, Wave and fusion implementations are reused.
- No duplicate Wave implementation is introduced.
- Trust may include or exclude a candidate, but it never changes the numeric hybrid score.
- Both external and native semantic searches use the exact routed backend.
- CPU is accepted as the canonical exact backend; OpenCL is accepted only when exact parity is certified.
- ANN is forbidden from the canonical product path.
- Ranking is descending `f64::total_cmp`, then ascending `record_id`.
- The graph snapshot and database snapshot must be identical.
- Query execution cannot modify the database or Trust ledger.
- The public product entry point is
  `ultraballoondb_hybrid_engine::execute_product_hybrid_query`.

## Scope

R4.9C2 completes product binding. It does not claim benchmark superiority.
Real benchmark execution remains a later gate.
