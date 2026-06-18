#!/usr/bin/env python3
"""Public reference guard for UltraBalloonDB Trust invariants.

This is a contract model, not the production Trust implementation and not a
publication of private evidence-adjudication policy.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import sys
from enum import Enum
from typing import Any


class Maturity(str, Enum):
    RAW = "RAW"
    HYPOTHESIS = "HYPOTHESIS"
    CANDIDATE = "CANDIDATE"
    VERIFIED = "VERIFIED"


class Validity(str, Enum):
    ACTIVE = "ACTIVE"
    DISPUTED = "DISPUTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    SUPERSEDED = "SUPERSEDED"


@dataclasses.dataclass(frozen=True)
class TrustState:
    maturity: Maturity
    validity: Validity


@dataclasses.dataclass(frozen=True)
class EvidenceRef:
    record_id: str
    record_digest: str
    policy_id: str
    policy_version: str
    verifier_id: str
    decision_digest: str
    passed: bool


@dataclasses.dataclass(frozen=True)
class Transition:
    record_id: str
    previous: TrustState
    next: TrustState
    reason_code: str
    evidence_refs: tuple[EvidenceRef, ...]


class Record:
    def __init__(self, payload: Any):
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.payload = payload
        self.record_digest = hashlib.sha256(encoded).hexdigest()
        self.record_id = self.record_digest[:24]
        self._state = TrustState(Maturity.RAW, Validity.ACTIVE)
        self.provenance: list[dict[str, str]] = []

    @property
    def trust(self) -> TrustState:
        return self._state


class TrustLedger:
    def __init__(self) -> None:
        self._transitions: list[Transition] = []

    @property
    def transitions(self) -> tuple[Transition, ...]:
        return tuple(self._transitions)

    def _append(self, transition: Transition) -> None:
        self._transitions.append(transition)


class TrustGate:
    """The only contract-model owner of trust mutation."""

    _PROMOTION_ORDER = {
        Maturity.RAW: Maturity.HYPOTHESIS,
        Maturity.HYPOTHESIS: Maturity.CANDIDATE,
        Maturity.CANDIDATE: Maturity.VERIFIED,
    }

    def __init__(self, ledger: TrustLedger):
        self._ledger = ledger

    @staticmethod
    def _valid_evidence(record: Record, evidence: EvidenceRef) -> bool:
        return (
            isinstance(evidence, EvidenceRef)
            and evidence.passed is True
            and evidence.record_id == record.record_id
            and evidence.record_digest == record.record_digest
            and bool(evidence.policy_id)
            and bool(evidence.policy_version)
            and bool(evidence.verifier_id)
            and bool(evidence.decision_digest)
        )

    def promote_one_step(self, record: Record, evidence: EvidenceRef) -> bool:
        if not self._valid_evidence(record, evidence):
            return False
        next_maturity = self._PROMOTION_ORDER.get(record.trust.maturity)
        if next_maturity is None or record.trust.validity is not Validity.ACTIVE:
            return False
        previous = record.trust
        record._state = TrustState(next_maturity, Validity.ACTIVE)
        self._ledger._append(
            Transition(record.record_id, previous, record.trust, "EVIDENCE_PROMOTION", (evidence,))
        )
        return True

    def revoke(self, record: Record, reason_code: str) -> bool:
        if not reason_code:
            return False
        previous = record.trust
        record._state = TrustState(previous.maturity, Validity.REVOKED)
        self._ledger._append(Transition(record.record_id, previous, record.trust, reason_code, ()))
        return True


def wave_rank(records: list[Record]) -> list[tuple[str, float]]:
    return sorted(
        ((r.record_id, float(len(json.dumps(r.payload)))) for r in records),
        key=lambda item: (-item[1], item[0]),
    )


def similarity_layout(records: list[Record]) -> dict[int, list[str]]:
    result: dict[int, list[str]] = {}
    for record in records:
        result.setdefault(len(record.record_id) % 3, []).append(record.record_id)
    return result


def fold_layout(records: list[Record]) -> tuple[str, ...]:
    return tuple(r.record_id for r in records[:2])


def import_record(record: Record, source: str) -> None:
    record.provenance.append({"imported_from": source})


def evidence_for(record: Record, passed: bool = True) -> EvidenceRef:
    return EvidenceRef(
        record_id=record.record_id,
        record_digest=record.record_digest,
        policy_id="PUBLIC_CONTRACT_TEST",
        policy_version="1",
        verifier_id="REFERENCE_GUARD",
        decision_digest=hashlib.sha256((record.record_id + str(passed)).encode()).hexdigest(),
        passed=passed,
    )


def snapshot(records: list[Record]) -> dict[str, TrustState]:
    return {r.record_id: r.trust for r in records}


def main() -> int:
    checks: dict[str, bool] = {}
    records = [Record({"index": i, "value": "x" * i}) for i in range(1, 6)]
    ledger = TrustLedger()
    gate = TrustGate(ledger)

    before = snapshot(records)
    wave_rank(records)
    similarity_layout(records)
    fold_layout(records)
    checks["recall_components_are_trust_neutral"] = before == snapshot(records)

    imported = Record({"external": True})
    import_record(imported, "external-instance@example")
    checks["import_preserves_raw_and_adds_provenance"] = (
        imported.trust == TrustState(Maturity.RAW, Validity.ACTIVE)
        and len(imported.provenance) == 1
    )

    checks["score_is_not_evidence"] = gate.promote_one_step(records[0], 0.99) is False  # type: ignore[arg-type]
    checks["wrong_record_evidence_rejected"] = (
        gate.promote_one_step(records[0], evidence_for(records[1])) is False
    )
    checks["failed_evidence_rejected"] = (
        gate.promote_one_step(records[0], evidence_for(records[0], passed=False)) is False
    )

    steps = [
        gate.promote_one_step(records[0], evidence_for(records[0])),
        gate.promote_one_step(records[0], evidence_for(records[0])),
        gate.promote_one_step(records[0], evidence_for(records[0])),
    ]
    checks["evidence_promotes_only_one_step_at_a_time"] = (
        all(steps) and records[0].trust.maturity is Maturity.VERIFIED
    )

    count_before_revoke = len(ledger.transitions)
    checks["revocation_supported"] = gate.revoke(records[0], "SOURCE_REVOKED")
    checks["revocation_preserves_history"] = (
        records[0].trust.validity is Validity.REVOKED
        and len(ledger.transitions) == count_before_revoke + 1
        and any(t.next.maturity is Maturity.VERIFIED for t in ledger.transitions)
    )

    checks["ledger_is_append_only_view"] = isinstance(ledger.transitions, tuple)

    failures = sorted(name for name, passed in checks.items() if not passed)
    marker = "PASS_TRUST_PUBLIC_CONTRACT_GUARD" if not failures else "NO_GO_TRUST_PUBLIC_CONTRACT_GUARD"
    print(json.dumps({"status": marker, "checks": checks, "failures": failures}, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
