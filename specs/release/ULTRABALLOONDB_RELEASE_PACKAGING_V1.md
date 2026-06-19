# UltraBalloonDB Release Packaging V1

Status: additive delivery and verification contract.
Milestone: `V00R3G1_RELEASE_PACKAGING_R01`.

## Source of truth

A release is bound to one clean, pushed Git commit and its exact tree. The
release builder may package only artifacts built from that commit with
`--locked`. G1 does not redefine storage, WAL, Trust, Wave, protocol or edition
semantics.

## Product status

The G1 bundle is an unsigned Windows x86_64 pre-release for evaluation. It is
not production-ready, carries no SLA, installs no service, opens no remote
listener and grants no software license beyond the repository COPYRIGHT and
applicable law.

## Included delivery surfaces

- Edition A native offline CLI;
- Edition B CPython `abi3-py38` PyO3 module and type stub;
- Edition D stable C ABI DLL, optional link libraries and public header;
- offline Trust administration command-line tools;
- selected canonical specifications, product architecture and legal status;
- deterministic release manifest, component inventory, SHA-256 checksums and
  independent verification tools.

Edition C production daemon/service is explicitly not included. D2 remains a
bounded protocol core. Service installation, remote binding, authentication and
TLS require later explicit gates.

## Deterministic package

The bundle uses sorted paths, normalized timestamps and fixed permissions. Two
packages generated from the same built artifacts must have identical SHA-256.
`RELEASE_MANIFEST.json` binds source commit/tree, toolchain, target and every
artifact digest/size. `SHA256SUMS.txt` covers every file except itself.

## Fail-closed rules

Packaging fails on:

- dirty or unpushed repository;
- source commit/tree mismatch;
- failed workspace check or tests;
- missing required executable, DLL, header, Python module, type stub or spec;
- non-PE Windows deliverables;
- unsafe paths, symlinks, duplicate entries or secret-like tracked paths;
- inclusion of build intermediates such as PDB, RLIB or RMETA;
- checksum, manifest or exact-file-set mismatch;
- native CLI, C ABI or fresh-process PyO3 smoke-test failure;
- non-deterministic repeat packaging;
- any attempt to claim signing, production readiness, service installation,
  remote listener activation or a license grant.

## Repository impact

G1 adds release tooling, this specification, alignment evidence and a verified
release bundle. It does not add a database engine, crate, runtime route or
background service, and does not modify storage/WAL/lifecycle/Trust/Wave
semantics.
