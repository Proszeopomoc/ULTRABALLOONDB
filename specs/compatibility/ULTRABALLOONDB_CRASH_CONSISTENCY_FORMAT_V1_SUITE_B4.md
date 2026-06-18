# UltraBalloonDB Crash Consistency and Format V1 Suite B4

Status: **OFFLINE TEST SUITE**

## Scenariusze hard-exit

1. `UNCOMMITTED`
   - BEGIN + operacje;
   - brak COMMIT;
   - twarde wyjście;
   - recovery musi zwrócić pusty stan i `ignored_uncommitted_count=1`.

2. `COMMITTED_NO_CHECKPOINT`
   - segment;
   - BEGIN + operacje + COMMIT;
   - WAL `fsync`;
   - twarde wyjście;
   - recovery musi odtworzyć transakcję z WAL.

3. `CHECKPOINTED`
   - durable COMMIT;
   - checkpoint;
   - manifest;
   - atomiczny head;
   - twarde wyjście;
   - recovery musi rozpocząć od checkpointu.

4. `PARTIAL_WAL_TAIL`
   - durable COMMIT;
   - dopisany niekompletny ogon;
   - twarde wyjście;
   - pierwszy restart naprawia dokładną liczbę bajtów;
   - drugi restart nie wykonuje kolejnej naprawy.

## Scenariusze hard failure

- kompletna ramka WAL z błędnym SHA;
- WAL major version większa od obsługiwanej;
- uszkodzony `CURRENT.ubhead`;
- uszkodzony manifest;
- uszkodzony checkpoint.

Każdy przypadek musi zostać odrzucony. Repair mode nie może ukryć kompletnej
korupcji.

## Golden vectors V1

Zestaw zapisuje rzeczywiste pliki B3 i publikuje ich SHA-256 jako golden
vectors. Niezależny verifier Python:

- parsuje nagłówki bez użycia kodu Rust;
- sprawdza magic, major/minor, header size i flags;
- sprawdza SHA payloadu;
- sprawdza head -> manifest;
- sprawdza manifest -> checkpoint;
- rekonstruuje checkpoint;
- replayuje committed WAL;
- pomija transakcję bez COMMIT;
- porównuje deterministyczny state hash.

## Warunek promocji

B4 nie promuje aktywnego runtime. Po PASS kolejnym gate jest test migracji
historycznego Python V00N do canonical Rust storage.
