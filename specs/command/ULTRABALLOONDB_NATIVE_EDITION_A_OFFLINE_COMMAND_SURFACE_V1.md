# UltraBalloonDB Native Edition A Offline Command Surface V1

Status: **B6 IMPLEMENTATION PROFILE**

## Wspólny kontrakt

Każdy wynik zawiera:

```json
{
  "schema": "ultraballoondb.command.v1",
  "ok": true,
  "command": "status"
}
```

Błąd:

```json
{
  "schema": "ultraballoondb.command.v1",
  "ok": false,
  "error": {
    "code": "INVALID_ARGUMENT",
    "message": "..."
  }
}
```

## Create

```text
ultraballoondb create --db PATH
```

Tworzy nowy katalog canonical database i publikuje pusty checkpoint generation
`1`. Istniejąca ścieżka jest błędem semantycznym.

## Status

```text
ultraballoondb status --db PATH
```

Zwraca:

- record count;
- edge count;
- state SHA-256;
- checkpoint generation/LSN;
- maximum valid WAL LSN;
- replayed committed transaction count;
- ignored uncommitted transaction count;
- repaired trailing bytes.

Otwiera bazę z `repair_trailing=false`.

## Verify

```text
ultraballoondb verify --db PATH
```

Wykonuje dwa niezależne otwarcia i potwierdza:

- identyczny state SHA;
- identyczne liczniki;
- brak automatycznej naprawy;
- restart determinism.

## Record commands

```text
put-record --db PATH --record-id ID --node-id N --payload-file FILE
put-record --db PATH --record-id ID --node-id N --payload-utf8 TEXT
get-record --db PATH --record-id ID
list-records --db PATH
delete-record --db PATH --record-id ID
```

`list-records` nie emituje payload bytes; zwraca rozmiar i SHA.
`get-record` zwraca payload jako hexadecimal.

## Edge commands

```text
put-edge --db PATH --src N --dst N --edge-type N --weight-million N
list-edges --db PATH
delete-edge --db PATH --src N --dst N --edge-type N --weight-million N
```

Klucz krawędzi jest dokładny:

```text
(src, dst, edge_type, canonical f64 bits)
```

## Checkpoint

```text
checkpoint --db PATH
```

Publikuje nowy checkpoint bez zmiany stanu semantycznego.

## Write lifecycle

Dla każdej realnej zmiany:

```text
OPEN(no repair)
-> BEGIN
-> ADD OPERATION
-> PREPARE
-> SEGMENT
-> WAL BEGIN/OP/COMMIT
-> FLUSH + FSYNC
-> CHECKPOINT WAL FRAME
-> CHECKPOINT FILE
-> MANIFEST
-> ATOMIC HEAD
-> RECEIPT
```

Segment sequence jest wyprowadzany z aktualnego maximum valid WAL LSN, aby
ograniczyć kolizję po przerwanym procesie przed checkpointem.

## Bezpieczeństwo

- brak sieci;
- brak env secrets;
- brak automatycznego repair;
- brak overwrite przy create;
- brak panic jako przewidzianego wyniku użytkownika;
- nieznane i powtórzone flagi są odrzucane;
- wszystkie liczby są parsowane fail-closed;
- payload file jest czytany jako surowe bytes.
