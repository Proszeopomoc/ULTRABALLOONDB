# UltraBalloonDB Storage Format V1 — B1 implementation profile

Status: **IMPLEMENTED OFFLINE / NOT ACTIVE RUNTIME**

## Zakres

B1 implementuje trwałe, immutable pliki:

- `SEGMENT-<generation>-<sequence>.ubseg`
- `MANIFEST-<generation>.ubmeta`
- `CURRENT.ubhead`

oraz katalogi przyszłych `wal`, `checkpoints` i `indexes`.

## Rekord segmentu

Każdy wpis składa się z 56-bajtowego nagłówka, payloadu i zerowego paddingu
do granicy 8 bajtów.

B1 semantycznie waliduje:

- `RECORD`:
  - niepusty UTF-8 record ID;
  - reserved = 0;
  - dokładna długość;
  - SHA-256 user payload.
- `TYPED_EDGE`:
  - 32 bajty;
  - reserved = 0;
  - finite f64;
  - `-0.0` normalizowane do `+0.0`.

Pozostałe kind V1 mogą być przechowane jako raw payload, ale lifecycle B2/B3
musi zdefiniować ich semantykę przed aktywnym użyciem.

## Atomic publication

- immutable segment i manifest:
  temp file → file sync → atomic move → parent durability barrier;
- head:
  temp file → file sync → atomic replace → parent durability barrier.

Na Windows atomic replace korzysta z `MoveFileExW` z
`MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`.
Na Unix po `rename` wykonywany jest `sync_all` katalogu nadrzędnego.

## Integralność

Open/verify odrzuca:

- zły magic;
- major version != 1;
- header size inny niż kontrakt;
- niezerowe flagi/reserved;
- niezgodny payload length;
- niezgodny SHA-256 pliku lub wpisu;
- niezerowy padding;
- trailing bytes;
- nieprawidłowy payload record/edge;
- head z path traversal;
- head wskazujący brakujący lub zmieniony manifest.

## Granice

- CSR pozostaje derived indexem.
- Nie ma zapisu WAL.
- Nie ma transakcji.
- Nie ma automatycznego importu BalloonDB.
- Crate nie jest połączony z aktywnym binary adapterem.
