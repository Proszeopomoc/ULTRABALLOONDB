# UltraBalloonDB Python V00N -> Canonical Rust Migration Plan V1

Status: **OFFLINE MIGRATION PARITY**

## Header

Little-endian, 160 bytes:

```text
magic[8]                 = "UBMIG01\0"
major:u16                = 1
minor:u16                = 0
header_bytes:u32         = 160
record_count:u64
edge_count:u64
source_committed_tx:u64
source_checkpoint_lsn:u64
source_last_valid_lsn:u64
payload_bytes:u64
source_python_state_sha[32]
semantic_state_sha[32]
payload_sha[32]
```

## Payload

Deterministyczna sekwencja entries:

```text
kind:u16
flags:u16 = 0
logical_id:u64
payload_bytes:u64
payload_sha256[32]
payload[payload_bytes]
```

Najpierw rekordy sortowane po `record_id`, następnie krawędzie sortowane po:

```text
(src, dst, edge_type, weight_million)
```

Record payload zachowuje canonical B2 encoding:

```text
record_id_bytes:u32
reserved:u32 = 0
node_id:u64
user_payload_bytes:u64
user_payload_sha256[32]
record_id_utf8
user_payload
```

Edge payload zachowuje canonical B2 encoding:

```text
src:u64
dst:u64
edge_type:u32
reserved:u32 = 0
weight:f64
```

## Cross-format semantic SHA

Preimage:

```text
"UBMIGS1\0"
record_count:u64
edge_count:u64
sorted semantic record entries
sorted semantic edge entries
```

Rekord:

```text
record_id_bytes:u32
record_id_utf8
node_id:u64
payload_bytes:u64
payload_sha256[32]
payload
```

Krawędź:

```text
src:u64
dst:u64
edge_type:u32
weight_million:i64
```

SHA jest niezależne od wewnętrznego Python JSON i Rust checkpoint encoding.

## Warunki fail-closed

Migracja jest zatrzymywana przy:

- złym checkpoint SHA V00N;
- złej ramce lub SHA WAL;
- niepoprawnym LSN;
- operacji bez BEGIN;
- COMMIT bez BEGIN;
- złym `op_count`;
- konflikcie record ID;
- nieznanym rodzaju operacji;
- niezgodnym plan payload SHA;
- niezgodnym semantic SHA;
- istniejącym docelowym katalogu;
- nieudanym durable commit/checkpoint/restart;
- niezgodności niezależnego verifiera.
