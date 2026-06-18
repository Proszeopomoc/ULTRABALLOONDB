# UltraBalloonDB B3 WAL, Checkpoint and Recovery

Status: **OFFLINE TARGET-STATE IMPLEMENTATION**

## Durable commit

B3 potwierdza commit dopiero po:

1. materializacji immutable segmentu B1;
2. append ramki BEGIN;
3. append wszystkich ramek operacji;
4. append ramki COMMIT;
5. flush;
6. `fsync` WAL.

Segment zapisany bez zatwierdzonego WAL jest orphanem i nie jest częścią
odzyskanego stanu.

## WAL V1

Ramka:

- magic `UBWFR01\0`;
- major = 1;
- frame type;
- header bytes = 96;
- LSN;
- transaction ID 16 B;
- payload bytes;
- flags = 0;
- SHA-256 payload;
- reserved = 0.

Typy:

1. BEGIN
2. PUT_RECORD
3. PUT_EDGE
4. DELETE_RECORD
5. DELETE_EDGE
6. COMMIT
7. ABORT
8. CHECKPOINT

## Recovery

Recovery:

- weryfikuje head i manifest;
- ładuje checkpoint;
- skanuje cały WAL pod kątem integralności;
- replayuje wyłącznie kompletne transakcje po checkpoint LSN;
- ignoruje transakcje bez COMMIT;
- przycina wyłącznie niekompletny finalny header/payload;
- odrzuca zły magic, hash, flags, reserved, LSN i semantykę transakcji;
- porównuje state hash zapisany w COMMIT;
- zwraca deterministyczny recovery receipt.

## Checkpoint

Checkpoint zawiera:

- last applied LSN;
- state SHA-256;
- aktualne records i typed edges;
- zbiór zatwierdzonych transaction IDs.

Publikacja:

1. append i fsync CHECKPOINT frame;
2. checkpoint temp + fsync + atomic move;
3. immutable manifest;
4. atomic `CURRENT.ubhead`.

## State hash

Preimage:

```text
"UBSTA01\0"
record_count:u64
edge_count:u64
sorted current record entries
sorted current edge entries
```

Każdy entry:

```text
kind:u16
flags:u16 = 0
logical_id:u64
payload_bytes:u64
payload_sha256:[u8;32]
payload
```

## Poza zakresem

- aktywne podłączenie CLI/daemon/Python;
- fault injection procesu/OS;
- backup/restore;
- migracja Python V00N;
- compaction;
- multi-writer;
- GPU i Trust.
