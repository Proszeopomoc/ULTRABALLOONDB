# Public / Private Disclosure Boundary V1

Status: public disclosure policy.

## Public repository may contain

- product definition and high-level architecture;
- public API and compatibility contracts;
- public storage/protocol specifications where approved;
- Trust invariants and externally observable guarantees;
- reproducible benchmark methodology and verified results;
- security, support and data-safety policies;
- licensing notices.

## Public repository must not contain

- signing private keys;
- secret semantic fingerprint challenges;
- customer fingerprint maps;
- hidden adversarial corpora;
- private evidence-validation thresholds;
- non-public policy exceptions;
- unreleased patent-sensitive implementation notes;
- private commercial contracts.

## Documentation principle

Public documentation explains what the database guarantees and how clients use
it. It does not need to publish every internal heuristic, optimization threshold
or IP-protection mechanism.

## Trust principle

The public contract states that only auditable evidence-backed transitions may
change trust. Exact private evidence-adjudication policies may remain private,
provided public behavior remains deterministic, testable and non-deceptive.
