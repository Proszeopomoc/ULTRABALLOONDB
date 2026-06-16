# UltraBalloonDB V00F Crystallization Paths

## Status target

`PASS_ULTRABALLOONDB_CRYSTALLIZATION_PATHS_V00F`

## Purpose

V00F adds deterministic crystallization paths to the DB core. Repeated typed topological paths can be compacted into synthetic structural crystal nodes while keeping provenance links to the original evidence records.

## Boundary

The database does:

- count repeated typed path signatures,
- create compact structural crystal nodes,
- preserve path and record provenance identifiers,
- support revocation by explicit negative evidence identifiers,
- keep the lossless archive untouched.

The database does not:

- call a model,
- interpret text or payload meaning,
- summarize semantically,
- perform agent policy logic,
- delete archive evidence.

## Core objects

- `PathObservation`: observed edge-type sequence plus opaque path/record IDs.
- `CrystallizationConfig`: thresholds and bounded crystal/provenance limits.
- `CrystalNode`: compact structural node with support count, weighted support, provenance and status.
- `CrystallizationResult`: deterministic output with skipped blocked/low-support counts.

## Acceptance checks

- Repeated path creates a crystal.
- Provenance path IDs are preserved.
- Provenance record IDs are preserved.
- Blocked paths do not crystallize.
- Low-support paths do not crystallize.
- Digest is deterministic across equal input.
- Revocation is supported.
- Active/revoked status is explicit.
- Archive delete operation count remains zero.
- `max_crystals` is respected.
- Repo text scan has no forbidden network/model markers.

## Report

Local runs write:

`audit/v00f_crystallization_paths/<RUN_ID>/crystallization_paths_report.json`

`audit/` is generated local evidence and should remain ignored unless evidence publication is intentionally requested.
