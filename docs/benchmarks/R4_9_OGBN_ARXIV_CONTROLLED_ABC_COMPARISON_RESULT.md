# OGBN-Arxiv controlled A/B/C comparison

## Result

The controlled validation comparison completed on the same frozen OGBN-Arxiv-derived database, query set, candidate universe, graph profile G4, and `top_k=10`.

| Variant | Precision@10 | Top-1 | MRR | NDCG@10 | p50 ms | p95 ms | p99 ms | QPS |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| A semantic | 0.446578744253 | 0.537870398336 | 0.624084381227 | 0.464683672274 | 7.116100 | 13.437840 | 16.107764 | 143.125665 |
| B structural | 0.428994261552 | 0.497063659854 | 0.590612473946 | 0.442671633115 | 8.788900 | 15.676470 | 18.529926 | 118.947352 |
| C hybrid H111 | **0.474680358401** | **0.579650323836** | **0.655987230849** | **0.496103104717** | 14.273600 | 24.625020 | 28.458174 | 74.847257 |

Quality winner: **C hybrid H111**.

Compared with A semantic, C improved Precision@10 by 0.028101614148, Top-1 by 0.041779925501, MRR by 0.031902849622, and NDCG@10 by 0.031419432443. The quality gain costs higher latency and lower throughput: p50 is approximately twice A and QPS is 47.7% lower.

B structural-only did not outperform A semantic. Its structural signal became useful when fused with semantic and Wave/topological evidence in C.

## Integrity

- Queries: 29,799 validation records.
- Candidates: 90,941 train records.
- Test split executed: no.
- Labels and ground truth available to ranking executors: no.
- Results frozen before evaluation: yes.
- Recovery R09 reran benchmark queries: no.
- ANN used: no.
- Trust included in numeric score: no.

## Evidence

- Frozen R08 run: `RUN_R08_20260624_135210_290`
- Results freeze manifest SHA256: `47580B7190E1C28A8F61AA4EB6FB91613D06B0F9396172F49A9C9AB6401DC7A4`
- R09 comparison report SHA256: `08C663906547542CBCE9F53ADE5EFDF6E31EC442F674179C7BE21E0D40A75D95`
- R09 recovery receipt SHA256: `8D9010345FE7DCC3A644BA349842A760C4921431ADA6F5CB3A4C721EBA9FF4B4`
- Ground-truth binding receipt SHA256: `F75BE02DAAEB41DED551A0DA6F2737FCBC4AB8888B91EDD38C1F23CD5343AC2E`

## Claim boundary

This result applies only to the frozen OGBN-Arxiv-derived validation retrieval profile. It is not a claim of superiority on the official OGB node-classification task, the test split, arbitrary databases, ANN retrieval, or overall product readiness.

Next fixed roadmap step: `R4_9F2_CURRENT_PRODUCT_10M_SEMANTIC_SCALE_EXECUTION`.
