# UltraBalloonDB WriteBatch and Transaction Core V1

Status: **B2 OFFLINE IMPLEMENTATION**

## 1. Model

B2 implementuje jeden aktywny writer w `TransactionCore`.

Nowa transakcja nie może zostać rozpoczęta, dopóki poprzednia nie została:

- zmaterializowana w shadow i jawnie zwolniona; albo
- abortowana i jawnie zwolniona.

## 2. Stany

- `ACTIVE`
  - dozwolone dodawanie operacji;
- `PREPARED`
  - batch jest zamrożony;
  - digest i kolejność operacji są deterministyczne;
- `SHADOW_MATERIALIZED`
  - immutable segment B1 został zapisany i zweryfikowany;
  - nie oznacza durable commit;
- `ABORTED`
  - operacje nie mogą zostać zmaterializowane.

Mutacja po `PREPARED` jest błędem.

## 3. Operacje

- `PUT_RECORD`
- `PUT_EDGE`
- `DELETE_RECORD`
- `DELETE_EDGE`

Kolejność dodawania jest kolejnością materializacji.

## 4. Idempotencja i konflikty

Dokładnie identyczna operacja powtórzona w tym samym batchu jest ignorowana.

Błąd konfliktu występuje, gdy:

- ten sam `logical_id` wskazuje inną operację;
- ten sam record ID ma inną akcję lub treść;
- ta sama tożsamość typed edge ma inną akcję lub logical ID.

## 5. Batch digest

SHA-256 preimage:

```text
"UBTXB01\0"
transaction_id:[u8;16]
operation_count:u64
total_payload_bytes:u64
repeat operation_count:
  kind:u16
  flags:u16 = 0
  logical_id:u64
  payload_bytes:u64
  payload_sha256:[u8;32]
  payload:[u8;payload_bytes]
```

Wszystkie liczby są little-endian.

Padding segmentu B1 nie wchodzi do batch digest.

## 6. Materializacja shadow

`materialize_shadow`:

1. wymaga stanu `PREPARED`;
2. zapisuje jeden immutable segment B1;
3. wykonuje pełną weryfikację segmentu;
4. porównuje `item_count` z operation count;
5. zwraca receipt:
   - transaction ID,
   - batch digest,
   - segment path/hash,
   - generation/sequence,
   - `durable_commit=false`,
   - `wal_recorded=false`,
   - `head_published=false`.

## 7. Granice

B2 nie publikuje manifestu ani head jako commit transakcji.
B2 nie posiada WAL i nie potwierdza trwałości użytkownikowi.
B3 musi połączyć transaction core z WAL V1 przed promocją lifecycle.
