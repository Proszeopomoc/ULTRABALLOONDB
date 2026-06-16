# UltraBalloonDB V00B Wave Activation Core

## Cel

V00B dodaje pierwszy realny rdzeń deterministycznego falowania energii po typowanych krawędziach.
Baza pozostaje semantycznie ślepa: operuje na node_id, edge_type, energii, maskach, progach i top_k.

## Zakres

Dodane elementy:

- `python_ref/ultraballoondb_core/types.py`
- `python_ref/ultraballoondb_core/wave.py`
- `python_ref/ultraballoondb_core/selftest/run_wave_activation_core_v00b.py`
- `scripts/windows/RUN_WAVE_ACTIVATION_CORE_V00B.ps1`

V00B nie pobiera payloadów. To jest tylko rdzeń falowania.

## Edge types

- `UP_RULE`
- `DOWN_EVIDENCE`
- `LATERAL_SIMILAR_CASE`
- `PROJECT_CONTEXT`
- `CODE_PATTERN`
- `RULE_TO_EVIDENCE`
- `RULE_TO_CODE_PATTERN`
- `PROJECT_TO_RECENT_SEED`
- `CODE_TO_RECENT_RULE`
- `IS_NOT_EDGE`

## Mechanika

`wave_activation(seed_node, edge_mask, energy_threshold, top_k, max_steps, rigor_multiplier)`:

1. Startuje z energią `1.0` na `seed_node`.
2. Rozszerza tylko krawędzie dopuszczone przez `edge_mask`.
3. Mnoży energię przez tłumienie typu krawędzi, wagę krawędzi i `rigor_multiplier`.
4. Odrzuca ścieżki poniżej `energy_threshold`.
5. Blokuje propagację przez relacje `IS_NOT_EDGE`.
6. Zwraca deterministycznie sortowany wynik ograniczony do `top_k`.

## Granica DB / agent

DB robi:

- propagację numericzną,
- filtrowanie maską krawędzi,
- próg energii,
- blokady,
- ranking numeric energy,
- top_k.

DB nie robi:

- interpretacji tekstu,
- streszczania,
- planowania agenta,
- decyzji polityki,
- wywołań modeli,
- wywołań sieciowych.

## Komenda testowa

```powershell
cd $env:USERPROFILE\Downloads
Expand-Archive .\ULTRABALLOONDB_V00B_WAVE_ACTIVATION_CORE_PACKAGE.zip -DestinationPath . -Force
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ultraballoondb_v00b_wave_activation_core_package\scripts\windows\RUN_WAVE_ACTIVATION_CORE_V00B.ps1 -RepoRoot C:\UltraBalloonDB -EventSizes "10000,100000,1000000" -RecallSamples 1000
```

## PASS

Oczekiwany status:

`PASS_ULTRABALLOONDB_WAVE_ACTIVATION_CORE_V00B`

Raport:

`C:\UltraBalloonDB\audit\v00b_wave_activation_core\<RUN_ID>\wave_activation_core_report.json`
