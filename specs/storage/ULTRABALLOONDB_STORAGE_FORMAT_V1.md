# UltraBalloonDB Storage Format V1

Status: **FROZEN TARGET FORMAT**

## 1. Zasady ogólne

- little-endian;
- wszystkie długości w bajtach;
- wszystkie rekordy wyrównane do 8 bajtów;
- nieznany major version: fail closed;
- minor version może dodawać wyłącznie pola pomijalne przez starszy reader;
- payload hash: SHA-256;
- canonical data jest append-only w V1;
- CSR jest indexem derived/rebuildable.

## 2. Układ katalogów

```text
<database-root>/
  CURRENT.ubhead
  manifests/
    MANIFEST-<generation>.ubmeta
  segments/
    SEGMENT-<generation>-<sequence>.ubseg
  wal/
    WAL-<generation>-<sequence>.ubwal
  checkpoints/
    CHECKPOINT-<generation>.ubchk
  indexes/
    CSR-<generation>/
      csr_nodes.bin
      csr_edges.bin
      csr_manifest.json
  legacy_v00n/
    import_manifest.json
```

`legacy_v00n` jest opcjonalnym, read-only evidence rootem migracji.

## 3. Wspólny nagłówek pliku — 80 bajtów

| Offset | Typ | Pole |
|---:|---|---|
| 0 | `[u8;8]` | magic |
| 8 | `u16` | major |
| 10 | `u16` | minor |
| 12 | `u32` | header_bytes = 80 |
| 16 | `u64` | generation |
| 24 | `u64` | payload_bytes |
| 32 | `u64` | item_count |
| 40 | `u64` | flags |
| 48 | `[u8;32]` | SHA-256 payload |

Magic:

- `UBHEAD1\0`
- `UBMETA1\0`
- `UBSEG01\0`
- `UBCHK01\0`

## 4. Atomic head

`CURRENT.ubhead` wskazuje dokładnie jedną generację manifestu i zawiera:

- generation `u64`;
- manifest filename length `u32`;
- reserved `u32`;
- manifest SHA-256 `[u8;32]`;
- UTF-8 filename;
- padding do 8 bajtów.

Head jest aktualizowany wyłącznie przez temp + fsync + atomic replace +
directory fsync.

## 5. Segment

Segment jest immutable po publikacji.

Każdy record ma nagłówek 56 bajtów:

| Offset | Typ | Pole |
|---:|---|---|
| 0 | `u16` | kind |
| 2 | `u16` | flags |
| 4 | `u32` | header_bytes = 56 |
| 8 | `u64` | logical_id |
| 16 | `u64` | payload_bytes |
| 24 | `[u8;32]` | SHA-256 payload |

Kind V1:

- 1 — RECORD;
- 2 — TYPED_EDGE;
- 3 — RECORD_TOMBSTONE;
- 4 — EDGE_TOMBSTONE;
- 5 — METADATA.

Payload jest zakończony paddingiem zerowym do 8 bajtów. Padding nie wchodzi do
payload hash.

## 6. Record payload

```text
record_id_len:u32
reserved:u32
node_id:u64
user_payload_len:u64
user_payload_sha256:[u8;32]
record_id_utf8:[u8;record_id_len]
user_payload:[u8;user_payload_len]
padding_to_8
```

`record_id` nie może być pusty. Ta sama para `record_id + canonical content`
jest idempotentna. Konflikt tego samego `record_id` z inną treścią jest hard
error w V1.

## 7. Typed edge payload — 32 bajty

```text
src:u64
dst:u64
edge_type:u32
reserved:u32
weight:f64
```

Klucz deduplikacji:

`(src, dst, edge_type, canonical_f64_bits(weight))`

Na etapie kompatybilności Python V00N `weight_million` jest konwertowany
deterministycznie i sprawdzany przez parity test.

## 8. CSR V00P1 — zamrożony index zgodności

Node row, 24 bajty:

`<QQQ> = node_id, first_edge, edge_count`

Edge row, 24 bajty:

`<QIId> = dst, edge_type, attenuation_class, weight`

CSR:

- jest read-only w query path;
- może zostać odbudowany z canonical segments;
- nie może być jedyną kopią danych;
- musi zachować `full_scan_counter=0`.
