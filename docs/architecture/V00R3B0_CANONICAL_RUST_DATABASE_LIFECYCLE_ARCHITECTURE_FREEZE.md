# UltraBalloonDB canonical Rust database lifecycle — architecture freeze V1

Status: **FROZEN BY V00R3B0**

## 1. Granica produktu

Ten kontrakt dotyczy wyłącznie **UltraBalloonDB**, nowej bazy falowej.
Starsza płaska **BalloonDB** jest osobnym produktem i nie może być
automatycznie importowana, linkowana ani traktowana jako implementacja
referencyjna.

## 2. Jeden kanoniczny silnik

Docelowo jedna implementacja Rust posiada:

- create/open/close;
- durable records i typed edges;
- transakcje;
- WAL;
- checkpoint;
- recovery;
- integrity verification;
- backup/restore/upgrade;
- Wave nad zatwierdzonym stanem.

CLI, daemon, C ABI i PyO3 są hostami jednego silnika, a nie osobnymi
implementacjami lifecycle.

## 3. Stan obecny i migracja odpowiedzialności

### Obecnie potwierdzone

- Python V00N: durable overlay, transakcje, WAL, checkpoint i recovery.
- Rust: read-only CSR mmap, typed-edge lookup, Wave i subgraph.
- GPU: parity/crossover/snapshot/router shadow evidence, bez promocji.

### Stan docelowy

- Rust jest kanonicznym właścicielem lifecycle.
- Python V00N staje się oracle zgodności i kontrolowanym formatem importu.
- CSR V00P1 pozostaje derived/rebuildable indexem, nigdy canonical store.
- GPU pozostaje opcjonalnym backendem obliczeniowym; CPU fallback jest
  bezwarunkowy.

## 4. Crate ownership

- `ultraballoondb-core`
  - typy grafu, CSR read path, Wave, L2/L3/L7;
  - bez WAL i bez lifecycle side effects.
- `ultraballoondb-storage`
  - Storage Format V1, segmenty, rekordy, integralność, atomic head.
- `ultraballoondb-wal`
  - WAL Format V1, frame codec, append, fsync, scan i tail rules.
- `ultraballoondb-lifecycle`
  - Database, Transaction, commit, checkpoint, recovery i migrator V00N.
- `ultraballoondb-gpu`
  - opcjonalny backend obliczeniowy, bez własności stanu.
- `ultraballoondb-router`
  - wybór backendu z fail-closed CPU fallback.
- `ultraballoondb-trust`
  - osobna warstwa trust transitions; Wave nie promuje trust.
- `ultraballoondb-provenance`
  - manifesty pochodzenia i weryfikacja bez telemetrii.

Kierunek zależności:

`storage <- wal <- lifecycle -> core`

`gpu/router/trust/provenance` nie mogą tworzyć alternatywnego lifecycle.

## 5. Commit durability

Commit jest potwierdzony użytkownikowi dopiero po:

1. zapisaniu wszystkich frame’ów transakcji, włącznie z `COMMIT`;
2. flush;
3. `fsync` aktywnego WAL.

Zmiany data segment mogą zostać utrwalone później, ponieważ WAL jest redo logiem.
Po restarcie każdy zatwierdzony commit musi zostać deterministycznie odtworzony.

## 6. Recovery

Recovery:

1. otwiera i weryfikuje atomic head;
2. otwiera ostatni prawidłowy checkpoint;
3. skanuje WAL przy ściśle rosnącym LSN;
4. odtwarza tylko kompletne transakcje zakończone `COMMIT`;
5. ignoruje transakcje bez `COMMIT`;
6. może przyciąć wyłącznie niekompletną końcową ramkę powstałą przez EOF;
7. traktuje zły magic/version/hash/order w kompletnej ramce jako hard failure;
8. produkuje ten sam state hash przy każdym ponownym otwarciu.

## 7. Checkpoint

Checkpoint jest publikowany przez:

1. zapis pliku tymczasowego;
2. flush i fsync;
3. rename do versioned checkpoint;
4. fsync katalogu;
5. zapis tymczasowego `CURRENT.ubhead`;
6. flush, fsync i atomic replace;
7. fsync katalogu.

Stary checkpoint i WAL nie są usuwane przed opublikowaniem nowego head.

## 8. Kompatybilność

- Python V00N WAL/checkpoint: **MUST_VERIFY_AND_IMPORT**, bez dalszego zapisu po
  zakończonej migracji.
- CSR V00P1:
  - nodes: little-endian `<QQQ>`, 24 bajty;
  - edges: little-endian `<QIId>`, 24 bajty;
  - **MUST_READ_NATIVE** i zachować `full_scan_counter=0`.
- B2 Wave results: **MUST_MATCH_EXACT**.
- BalloonDB legacy: **FORBIDDEN_AUTOMATIC_IMPORT**.

## 9. Kolejność implementacji

1. B1 — storage/page store/integrity, offline.
2. B2 — Rust write batch i transaction state machine.
3. B3 — WAL/checkpoint/recovery.
4. B4 — crash consistency i compatibility matrix.
5. Dopiero potem promocja Edition A na kanoniczny lifecycle.

## 10. Zakazy

- brak ukrytego fallbacku do Python dla operacji deklarowanych jako Rust;
- brak dwóch niezależnych formatów kanonicznych;
- brak aktywacji GPU przez ten gate;
- brak zmiany Wave semantics;
- brak automatycznego importu BalloonDB;
- brak promocji przed fault-injection i parity PASS.
