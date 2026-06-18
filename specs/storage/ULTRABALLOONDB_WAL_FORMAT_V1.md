# UltraBalloonDB WAL Format V1

Status: **FROZEN TARGET FORMAT**

## 1. Rola

WAL jest append-only redo logiem i jedyną podstawą potwierdzenia durable commit
przed checkpointem.

## 2. Frame header — 96 bajtów

| Offset | Typ | Pole |
|---:|---|---|
| 0 | `[u8;8]` | `UBWFR01\0` |
| 8 | `u16` | major = 1 |
| 10 | `u16` | frame_type |
| 12 | `u32` | header_bytes = 96 |
| 16 | `u64` | LSN |
| 24 | `[u8;16]` | transaction ID |
| 40 | `u64` | payload_bytes |
| 48 | `u64` | flags |
| 56 | `[u8;32]` | SHA-256 payload |
| 88 | `[u8;8]` | reserved = zero |

LSN jest ściśle rosnący w obrębie database lineage.

## 3. Frame types

- 1 — BEGIN
- 2 — PUT_RECORD
- 3 — PUT_EDGE
- 4 — DELETE_RECORD
- 5 — DELETE_EDGE
- 6 — COMMIT
- 7 — ABORT
- 8 — CHECKPOINT

## 4. COMMIT payload

```text
operation_count:u64
state_sha256:[u8;32]
```

Commit frame kończy dokładnie jedną transakcję. Liczba operacji musi odpowiadać
frame’om operacyjnym pomiędzy BEGIN i COMMIT.

## 5. Durability ordering

1. append BEGIN + operations + COMMIT;
2. flush;
3. fsync WAL;
4. dopiero teraz commit może zostać potwierdzony;
5. materializacja segmentu może nastąpić asynchronicznie lub podczas checkpoint;
6. recovery musi odtworzyć każdy commit potwierdzony w WAL.

## 6. Scan rules

- incomplete final header lub payload wskutek EOF:
  - może zostać przycięty do ostatniej prawidłowej granicy;
- complete frame z:
  - złym magic,
  - nieobsługiwaną wersją,
  - złym payload hash,
  - niezerowym reserved,
  - niemonotonicznym LSN,
  - nieprawidłowym transaction state
  kończy open jako hard failure;
- operacje bez BEGIN są błędem;
- COMMIT bez BEGIN jest błędem;
- podwójny BEGIN/COMMIT jest błędem;
- transakcja bez COMMIT nie wpływa na stan.

## 7. Python V00N compatibility

Legacy V00N:

- magic `UBWL`;
- header `<4sI32s>`;
- canonical JSON payload;
- SHA-256 payload;
- frame kinds BEGIN, PUT_RECORD, PUT_EDGE, COMMIT.

Rust migrator musi:

1. zweryfikować V00N bez modyfikowania źródła;
2. odtworzyć stan zgodny z Python oracle;
3. porównać state SHA;
4. zapisać nowy V1 lineage do osobnego katalogu;
5. nigdy nie dopisywać frame’ów V1 do pliku V00N.
