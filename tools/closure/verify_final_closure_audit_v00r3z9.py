#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


PASS = "PASS_ULTRABALLOONDB_V00R3Z9_FINAL_CLOSURE_AUDIT"
VERIFY_PASS = "PASS_V00R3Z9_INDEPENDENT_FINAL_CLOSURE_VERIFIER"
EXPECTED_HEAD = "448ffc93face12d8be26d7fe1272c649c733bf42"
EXPECTED_TREE = "1099b72a1d4fbc3cffe35140152b6ecc9975ab0b"
EXPECTED_RELEASE_SHA256 = "5C35081C44AD24219F640FF4B0BBA054711E28CF71B4FB9BD16CBB69D1514821"
NEXT_GATE = "NONE_V00R3_PRE_RELEASE_CLOSED"


class VerificationFailure(RuntimeError):
    pass


def ensure(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationFailure(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        raise VerificationFailure(f"invalid JSON {path}: {exc}") from exc


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest().upper()


def verify(repo: Path, report_path: Path, summary_path: Path, evidence_path: Path, output_path: Path) -> dict[str, Any]:
    report = load_json(report_path)
    summary = load_json(summary_path)
    evidence = load_json(evidence_path)

    ensure(report.get("status") == PASS, "closure report status mismatch")
    ensure(report.get("closure_class") == "ENGINEERING_PRE_RELEASE_CLOSED", "closure class mismatch")
    ensure(report.get("source_head") == EXPECTED_HEAD, "source head mismatch")
    ensure(report.get("source_origin_main") == EXPECTED_HEAD, "origin main mismatch")
    ensure(report.get("source_tree") == EXPECTED_TREE, "source tree mismatch")
    ensure(report.get("release_sha256") == EXPECTED_RELEASE_SHA256, "release SHA mismatch")
    ensure(report.get("critical_milestone_count") == 22, "critical milestone count mismatch")
    ensure(report.get("critical_milestones_passed") == 22, "critical milestone pass count mismatch")
    ensure(report.get("release_artifact_count") == 28, "release artifact count mismatch")
    ensure(report.get("release_static_verification") is True, "release static verification missing")
    ensure(report.get("recent_commit_chain_verified") is True, "commit chain verification missing")
    ensure(report.get("next_gate") == NEXT_GATE, "next gate mismatch")

    false_fields = (
        "signed",
        "production_ready",
        "production_service_installed",
        "remote_network_enabled",
        "hardware_bound",
        "license_grant",
        "active_runtime_changed",
        "storage_format_changed",
        "wal_changed",
        "trust_semantics_changed",
        "wave_semantics_changed",
    )
    for key in false_fields:
        ensure(report.get(key) is False, f"required false boundary changed: {key}")

    true_fields = (
        "v00r3_pre_release_closed",
        "g1_cargo_check_evidence",
        "g1_cargo_test_evidence",
        "g1_release_repeat_determinism",
        "g1_native_cli_probe",
        "g1_cabi_dynamic_load_probe",
        "g1_pyo3_fresh_process_import_probe",
        "software_cng_preserved",
        "provider_abstraction_implemented",
        "future_changes_require_new_milestone",
    )
    for key in true_fields:
        ensure(report.get(key) is True, f"required true evidence missing: {key}")

    ensure(report.get("license_status") == "DRAFT_PENDING_LEGAL_REVIEW", "license status mismatch")
    ensure(summary.get("status") == PASS, "summary status mismatch")
    ensure(summary.get("source_head") == EXPECTED_HEAD, "summary head mismatch")
    ensure(summary.get("release_sha256") == EXPECTED_RELEASE_SHA256, "summary release SHA mismatch")
    ensure(summary.get("critical_milestones_passed") == 22, "summary milestone count mismatch")
    ensure(summary.get("next_gate") == NEXT_GATE, "summary next gate mismatch")

    ensure(evidence.get("source_head") == EXPECTED_HEAD, "evidence head mismatch")
    ensure(evidence.get("source_tree") == EXPECTED_TREE, "evidence tree mismatch")
    ensure(evidence.get("release_sha256") == EXPECTED_RELEASE_SHA256, "evidence release SHA mismatch")
    entries = evidence.get("entries")
    ensure(isinstance(entries, list) and len(entries) == 22, "evidence entries mismatch")
    ensure(len({entry.get("id") for entry in entries}) == 22, "duplicate milestone IDs")

    expected_manifest_hash = report.get("critical_evidence_manifest_sha256")
    actual_manifest_hash = sha256_file(evidence_path)
    ensure(expected_manifest_hash == actual_manifest_hash, "evidence manifest hash mismatch")

    for entry in entries:
        alignment = repo / str(entry["alignment_path"])
        milestone_report = repo / str(entry["report_path"])
        ensure(alignment.is_file(), f"alignment disappeared: {alignment}")
        ensure(milestone_report.is_file(), f"report disappeared: {milestone_report}")
        ensure(sha256_file(alignment) == entry["alignment_sha256"], f"alignment hash mismatch: {entry['id']}")
        ensure(sha256_file(milestone_report) == entry["report_sha256"], f"report hash mismatch: {entry['id']}")
        actual_report = load_json(milestone_report)
        ensure(actual_report.get("status") == entry["status"], f"status drift: {entry['id']}")

    release = repo / "docs/releases/v00r3g1/RUN_20260619_150326/UltraBalloonDB-0.0.3-windows-x86_64-pre1.zip"
    ensure(release.is_file(), "committed release disappeared")
    ensure(sha256_file(release) == EXPECTED_RELEASE_SHA256, "committed release SHA mismatch")

    verification = {
        "version": "V00R3Z9_INDEPENDENT_FINAL_CLOSURE_VERIFIER_V1",
        "status": VERIFY_PASS,
        "closure_report_sha256": sha256_file(report_path),
        "closure_summary_sha256": sha256_file(summary_path),
        "closure_evidence_manifest_sha256": actual_manifest_hash,
        "source_head": EXPECTED_HEAD,
        "source_tree": EXPECTED_TREE,
        "release_sha256": EXPECTED_RELEASE_SHA256,
        "critical_milestones_verified": 22,
        "pre_release_boundaries_preserved": True,
        "next_gate": NEXT_GATE,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(verification, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return verification


def selftest() -> int:
    ensure(len(EXPECTED_HEAD) == 40, "bad head constant")
    ensure(len(EXPECTED_RELEASE_SHA256) == 64, "bad release constant")
    print("PASS_V00R3Z9_INDEPENDENT_FINAL_CLOSURE_VERIFIER_SELFTEST")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root")
    ap.add_argument("--report")
    ap.add_argument("--summary")
    ap.add_argument("--evidence-manifest")
    ap.add_argument("--output-json")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    for name in ("repo_root", "report", "summary", "evidence_manifest", "output_json"):
        if not getattr(args, name):
            ap.error(f"--{name.replace('_', '-')} is required")
    result = verify(
        Path(args.repo_root).resolve(),
        Path(args.report).resolve(),
        Path(args.summary).resolve(),
        Path(args.evidence_manifest).resolve(),
        Path(args.output_json).resolve(),
    )
    print(VERIFY_PASS)
    print(f"CRITICAL_MILESTONES_VERIFIED={result['critical_milestones_verified']}")
    print(f"RELEASE_SHA256={result['release_sha256']}")
    print(f"NEXT_GATE={result['next_gate']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationFailure as exc:
        print(f"NO_GO_V00R3Z9_INDEPENDENT_FINAL_CLOSURE_VERIFIER\nERROR={exc}", file=sys.stderr)
        raise SystemExit(1)
