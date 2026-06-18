# UltraBalloonDB Checkpoint and Recovery V1

Status: **FROZEN TARGET CONTRACT**

## Checkpoint content

Checkpoint zawiera:

- format major/minor;
- generation;
- last applied LSN;
- manifest SHA-256;
- state SHA-256;
- index najnowszych record/edge locations;
- committed transaction dedupe state potrzebny do idempotentnego replay;
- opcjonalny CSR generation pointer.

Checkpoint nie zawiera aktywnej polityki, trust promotion ani GPU state.

## Publication protocol

1. zbuduj checkpoint w pamięci;
2. zapisz `CHECKPOINT-<generation>.ubchk.tmp`;
3. flush + fsync pliku;
4. rename do finalnej nazwy;
5. fsync katalogu;
6. zapisz nowy manifest temp;
7. flush + fsync;
8. rename manifestu;
9. fsync katalogu;
10. zapisz `CURRENT.ubhead.tmp`;
11. flush + fsync;
12. atomic replace `CURRENT.ubhead`;
13. fsync database root.

Przerwanie w dowolnym punkcie przed krokiem 12 pozostawia poprzedni head
kanonicznym.

## Open and recovery

1. weryfikuj head;
2. weryfikuj wskazany manifest;
3. weryfikuj segmenty i checkpoint;
4. odczytaj WAL od `checkpoint_lsn + 1`;
5. odtwórz wyłącznie kompletne committed transactions;
6. zbuduj deterministic state hash;
7. opcjonalnie odbuduj derived CSR;
8. zwróć recovery receipt.

## Required receipts

- opened generation;
- checkpoint LSN;
- maximum valid WAL LSN;
- replayed transaction count;
- ignored uncommitted count;
- repaired trailing bytes;
- state SHA-256;
- manifest SHA-256;
- segment hashes;
- full_scan_counter for any verification query.

## Fail closed

Open nie może automatycznie „naprawiać”:

- kompletnej ramki ze złym hashem;
- błędnego manifestu;
- brakującego segmentu;
- rozbieżnego generation;
- nieznanej major version;
- niezgodnego state hash.

Takie przypadki wymagają jawnego narzędzia `verify/repair` pracującego na kopii.
