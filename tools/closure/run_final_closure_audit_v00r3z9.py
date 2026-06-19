#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


PASS = "PASS_ULTRABALLOONDB_V00R3Z9_FINAL_CLOSURE_AUDIT"
VERSION = "V00R3Z9_FINAL_CLOSURE_AUDIT_R01"
EXPECTED_HEAD = "448ffc93face12d8be26d7fe1272c649c733bf42"
EXPECTED_TREE = "1099b72a1d4fbc3cffe35140152b6ecc9975ab0b"
EXPECTED_RELEASE_SHA256 = "5C35081C44AD24219F640FF4B0BBA054711E28CF71B4FB9BD16CBB69D1514821"
NEXT_GATE = "NONE_V00R3_PRE_RELEASE_CLOSED"
CLOSURE_CLASS = "ENGINEERING_PRE_RELEASE_CLOSED"

SECRET_PATH_PATTERNS = (
    re.compile(r"(^|/)\.env($|\.)", re.IGNORECASE),
    re.compile(r"(^|/)(secrets?|credentials?)(/|$)", re.IGNORECASE),
    re.compile(r"(^|/)(id_rsa|id_ed25519)(\.pub)?$", re.IGNORECASE),
    re.compile(r"\.(pem|pfx|p12|key)$", re.IGNORECASE),
)


class AuditFailure(RuntimeError):
    pass


def run(cmd: list[str], cwd: Path, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    cp = subprocess.run(
        cmd,
        cwd=str(cwd),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
        errors="replace",
    )
    if check and cp.returncode != 0:
        raise AuditFailure(
            f"command failed rc={cp.returncode}: {' '.join(cmd)}\n"
            f"stdout={cp.stdout}\nstderr={cp.stderr}"
        )
    return cp


def git(repo: Path, *args: str) -> str:
    return run(["git", "-C", str(repo), *args], repo).stdout.strip()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest().upper()


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        raise AuditFailure(f"invalid JSON {path}: {exc}") from exc


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def ensure(condition: bool, message: str) -> None:
    if not condition:
        raise AuditFailure(message)


def tracked_secret_paths(repo: Path) -> list[str]:
    paths = [line.strip().replace("\\", "/") for line in git(repo, "ls-files").splitlines() if line.strip()]
    return [p for p in paths if any(rx.search(p) for rx in SECRET_PATH_PATTERNS)]


def verify_recent_commit_chain(repo: Path) -> list[dict[str, str]]:
    expected = [
        ("448ffc93face12d8be26d7fe1272c649c733bf42", "UltraBalloonDB V00R3G1 release packaging"),
        ("a67ff484589bed2736c5ad18744be02588c42c16", "UltraBalloonDB V00R3E1 observability and security"),
        ("0f890d7a854b5d36454a6b6ec13d0a9a03a465de", "UltraBalloonDB V00R3D4 PyO3"),
        ("cc06461cf3b25d40b42ed37823482fc02c38e9e6", "UltraBalloonDB V00R3D3 C ABI"),
        ("7753d2b8223b6d25c41d14c2d7f303e25cf923e5", "UltraBalloonDB V00R3D2 daemon and protocol core"),
        ("1fba5c70891fbcb2065ad27c0f799968b74a711d", "UltraBalloonDB V00R3C1 backup restore upgrade dry run"),
        ("1ad23b2ee4ba7145ba1102cbbbf0c5c76c358d54", "UltraBalloonDB V00R3P0 provenance core"),
        ("d866ed023ff5af5b13001391997d312e3bb7289b", "UltraBalloonDB V00R3T6C provider abstraction and enterprise federation"),
        ("6ce6dd25e7605a3fd941f3e2d55173f6a6fde678", "UltraBalloonDB V00R3T6B asymmetric software CNG core"),
        ("34fcf2db409cc8111ffab8fa62f6b0af3db89368", "UltraBalloonDB V00R3T5 enterprise approvals audit profile"),
        ("5cbaacf8c9f9f27553848db3da2fe00f0e9fcbf2", "UltraBalloonDB V00R3T4 trust governance audit export"),
        ("378cd5858f31bd842d274e2daf08a3044d9721ee", "UltraBalloonDB V00R3T3 trust authorization signatures CLI"),
        ("88304e097144dd0ecbc83eb6554d8b07230e3b72", "UltraBalloonDB V00R3T2 trust record binding policy co-commit"),
        ("c3122db99b82e08592cef51d00c36fa72db7abc9", "UltraBalloonDB V00R3T1 Rust trust core transition ledger"),
        ("ecff7d4705fae5a51f6943d8cc8eb390ee242ed5", "UltraBalloonDB V00R3B6 native Edition A offline command surface"),
        ("1544dd41ce6d2a29c953d38feb30390f39f755c7", "UltraBalloonDB V00R3B5 Python V00N to Rust migration parity"),
        ("692e4240af1a361e20a8a98ec775c49aaa6940f0", "UltraBalloonDB V00R3B4 crash consistency and Format V1 suite"),
        ("4c469aad7ac86889ca689f526228a339ad2fa021", "UltraBalloonDB V00R3B3 Rust WAL checkpoint recovery"),
        ("5c912f28a9f315ceb96b2a4a84da6283dd988e0d", "UltraBalloonDB V00R3B2 Rust write batch and transaction core"),
    ]
    resolved: list[dict[str, str]] = []
    for commit, subject in expected:
        actual_subject = git(repo, "show", "-s", "--format=%s", commit)
        ensure(actual_subject == subject, f"commit subject mismatch for {commit}: {actual_subject!r}")
        ancestor = run(["git", "-C", str(repo), "merge-base", "--is-ancestor", commit, EXPECTED_HEAD], repo, check=False)
        ensure(ancestor.returncode == 0, f"required commit is not ancestor of G1: {commit}")
        resolved.append({"commit": commit, "subject": subject})
    return resolved


def verify_release(repo: Path, release_zip: Path, output_dir: Path) -> dict[str, Any]:
    ensure(release_zip.is_file(), f"release missing: {release_zip}")
    release_sha = sha256_file(release_zip)
    ensure(release_sha == EXPECTED_RELEASE_SHA256, f"release SHA mismatch: {release_sha}")

    verifier = repo / "tools/release/verify_release_bundle_v00r3g1.py"
    ensure(verifier.is_file(), f"G1 verifier missing: {verifier}")
    verifier_output = output_dir / "g1_release_static_verification.json"
    cp = run(
        [
            sys.executable,
            str(verifier),
            "--release-zip",
            str(release_zip),
            "--output-json",
            str(verifier_output),
        ],
        repo,
    )
    verify_data = load_json(verifier_output)
    verifier_pass = verify_data.get("pass") is True
    marker = str(verify_data.get("status") or ("PASS_V00R3G1_RELEASE_VERIFIER" if verifier_pass else "NO_GO_V00R3G1_RELEASE_VERIFIER"))
    ensure(verifier_pass, f"G1 release verifier did not pass: {verify_data}")
    ensure(verify_data.get("release_sha256") == EXPECTED_RELEASE_SHA256, "G1 verifier release SHA mismatch")
    ensure(verify_data.get("artifact_count") == 28, "G1 verifier artifact count mismatch")
    return {
        "release_path": str(release_zip),
        "release_sha256": release_sha,
        "release_size_bytes": release_zip.stat().st_size,
        "static_verifier_status": marker,
        "static_verifier_stdout": cp.stdout.strip(),
        "static_verification_report": str(verifier_output),
    }


def perform_audit(repo: Path, output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)

    branch = git(repo, "branch", "--show-current")
    head = git(repo, "rev-parse", "HEAD")
    origin = git(repo, "rev-parse", "origin/main")
    tree = git(repo, "rev-parse", "HEAD^{tree}")
    ensure(branch == "main", f"branch must be main: {branch}")
    ensure(head == EXPECTED_HEAD, f"HEAD mismatch: {head}")
    ensure(origin == EXPECTED_HEAD, f"origin/main mismatch: {origin}")
    ensure(tree == EXPECTED_TREE, f"tree mismatch: {tree}")

    status_lines = [x for x in git(repo, "status", "--short", "--untracked-files=all").splitlines() if x]
    allowed_prefixes = (
        "docs/alignment/V00R3Z9_FINAL_CLOSURE_AUDIT_R01.json",
        "specs/closure/ULTRABALLOONDB_FINAL_CLOSURE_AUDIT_V1.md",
        "specs/closure/ULTRABALLOONDB_FINAL_CLOSURE_CATALOG_V1.json",
        "tools/closure/run_final_closure_audit_v00r3z9.py",
        "tools/closure/verify_final_closure_audit_v00r3z9.py",
        "scripts/windows/VERIFY_ULTRABALLOONDB_FINAL_CLOSURE_V00R3Z9.ps1",
    )
    unexpected = []
    for line in status_lines:
        path = line[3:].replace("\\", "/")
        if not any(path == p for p in allowed_prefixes):
            unexpected.append(line)
    ensure(not unexpected, f"unexpected repository changes during Z9: {unexpected}")

    catalog_path = repo / "specs/closure/ULTRABALLOONDB_FINAL_CLOSURE_CATALOG_V1.json"
    catalog = load_json(catalog_path)
    ensure(catalog.get("required_exact_head") == EXPECTED_HEAD, "catalog head mismatch")
    ensure(catalog.get("required_exact_tree") == EXPECTED_TREE, "catalog tree mismatch")
    entries = catalog.get("entries")
    ensure(isinstance(entries, list) and len(entries) == 22, "closure catalog must contain 22 entries")

    evidence: list[dict[str, Any]] = []
    for entry in entries:
        milestone = str(entry["id"])
        alignment_path = repo / str(entry["alignment"])
        report_path = repo / str(entry["report"])
        ensure(alignment_path.is_file(), f"{milestone} alignment missing: {alignment_path}")
        ensure(report_path.is_file(), f"{milestone} report missing: {report_path}")
        alignment = load_json(alignment_path)
        report = load_json(report_path)
        status = str(report.get("status", ""))
        ensure(status == entry["expected_status"], f"{milestone} status mismatch: {status}")
        evidence.append(
            {
                "id": milestone,
                "dimension": entry["dimension"],
                "alignment_path": entry["alignment"],
                "alignment_sha256": sha256_file(alignment_path),
                "report_path": entry["report"],
                "report_sha256": sha256_file(report_path),
                "status": status,
                "version": report.get("version"),
                "alignment_milestone": alignment.get("milestone") or alignment.get("version"),
            }
        )

    ensure(not tracked_secret_paths(repo), "secret-like tracked paths detected")

    recent_chain = verify_recent_commit_chain(repo)

    g1 = load_json(repo / "docs/releases/v00r3g1/RUN_20260619_150326/v00r3g1_release_packaging_report.json")
    required_g1_true = (
        "cargo_check",
        "cargo_test",
        "release_build_locked_offline",
        "release_repeat_determinism",
        "manifest_verified",
        "checksums_verified",
        "exact_file_set_verified",
        "native_cli_probe",
        "cabi_dynamic_load_probe",
        "pyo3_fresh_process_import_probe",
    )
    for key in required_g1_true:
        ensure(g1.get(key) is True, f"G1 required evidence is not true: {key}")
    ensure(g1.get("artifact_count") == 28, "G1 artifact count mismatch")
    ensure(g1.get("release_sha256") == EXPECTED_RELEASE_SHA256, "G1 release SHA mismatch")
    ensure(g1.get("signed") is False, "G1 signed boundary changed")
    ensure(g1.get("production_ready") is False, "G1 production_ready boundary changed")
    ensure(g1.get("production_service_installed") is False, "G1 service boundary changed")
    ensure(g1.get("remote_network_enabled") is False, "G1 network boundary changed")

    release_rel = str(g1["release_zip"]).replace("\\", "/")
    marker = "/docs/releases/"
    idx = release_rel.lower().find(marker)
    ensure(idx >= 0, f"cannot derive committed release path from G1 report: {release_rel}")
    repo_release = repo / release_rel[idx + 1 :]
    release_result = verify_release(repo, repo_release, output_dir)

    t6b = load_json(repo / "docs/benchmarks/v00r3t6b_asymmetric_software_cng/RUN_20260619_091907/v00r3t6b_asymmetric_software_cng_report.json")
    t6c = load_json(repo / "docs/benchmarks/v00r3t6c_provider_federation/RUN_20260619_114740/v00r3t6c_provider_federation_report.json")
    x0 = load_json(repo / "docs/benchmarks/v00r3x0_product_identity_trust_architecture_freeze/RUN_20260618_123223/v00r3x0_product_identity_trust_architecture_freeze_report.json")

    ensure(t6b.get("hardware_bound") is False, "hardware binding unexpectedly true")
    ensure(t6c.get("hardware_bound") is False, "T6C hardware binding unexpectedly true")
    ensure(t6c.get("provider_abstraction_implemented") is True, "provider abstraction missing")
    ensure(x0.get("license_files_changed") is False, "license boundary changed")

    evidence_manifest = {
        "version": "V00R3Z9_CLOSURE_EVIDENCE_MANIFEST_V1",
        "source_head": head,
        "source_tree": tree,
        "release_sha256": EXPECTED_RELEASE_SHA256,
        "critical_milestone_count": len(evidence),
        "entries": evidence,
        "recent_commit_chain": recent_chain,
    }
    evidence_manifest_path = output_dir / "v00r3z9_closure_evidence_manifest.json"
    write_json(evidence_manifest_path, evidence_manifest)
    evidence_manifest_sha = sha256_file(evidence_manifest_path)

    report = {
        "version": VERSION,
        "status": PASS,
        "closure_class": CLOSURE_CLASS,
        "v00r3_pre_release_closed": True,
        "source_head": head,
        "source_origin_main": origin,
        "source_tree": tree,
        "critical_milestone_count": len(evidence),
        "critical_milestones_passed": len(evidence),
        "critical_evidence_manifest": str(evidence_manifest_path),
        "critical_evidence_manifest_sha256": evidence_manifest_sha,
        "recent_commit_chain_verified": True,
        "release_sha256": release_result["release_sha256"],
        "release_size_bytes": release_result["release_size_bytes"],
        "release_artifact_count": 28,
        "release_static_verification": True,
        "release_static_verifier_status": release_result["static_verifier_status"],
        "g1_cargo_check_evidence": True,
        "g1_cargo_test_evidence": True,
        "g1_release_repeat_determinism": True,
        "g1_native_cli_probe": True,
        "g1_cabi_dynamic_load_probe": True,
        "g1_pyo3_fresh_process_import_probe": True,
        "signed": False,
        "production_ready": False,
        "production_service_installed": False,
        "remote_network_enabled": False,
        "hardware_bound": False,
        "software_cng_preserved": True,
        "provider_abstraction_implemented": True,
        "license_status": "DRAFT_PENDING_LEGAL_REVIEW",
        "license_grant": False,
        "active_runtime_changed": False,
        "storage_format_changed": False,
        "wal_changed": False,
        "trust_semantics_changed": False,
        "wave_semantics_changed": False,
        "new_crate": None,
        "future_changes_require_new_milestone": True,
        "next_gate": NEXT_GATE,
    }
    report_path = output_dir / "v00r3z9_final_closure_audit_report.json"
    summary_path = output_dir / "v00r3z9_final_closure_audit_summary.json"
    markdown_path = output_dir / "V00R3Z9_FINAL_CLOSURE_AUDIT.md"
    write_json(report_path, report)
    write_json(
        summary_path,
        {
            "status": PASS,
            "closure_class": CLOSURE_CLASS,
            "source_head": head,
            "release_sha256": EXPECTED_RELEASE_SHA256,
            "critical_milestones_passed": len(evidence),
            "signed": False,
            "production_ready": False,
            "hardware_bound": False,
            "next_gate": NEXT_GATE,
        },
    )
    markdown_path.write_text(
        "\n".join(
            [
                "# UltraBalloonDB V00R3 Final Closure Audit",
                "",
                f"- Status: `{PASS}`",
                f"- Closure class: `{CLOSURE_CLASS}`",
                f"- Source commit: `{head}`",
                f"- Source tree: `{tree}`",
                f"- Release SHA-256: `{EXPECTED_RELEASE_SHA256}`",
                f"- Critical milestones passed: `{len(evidence)}/{len(evidence)}`",
                "- Signed: `false`",
                "- Production ready: `false`",
                "- Production service installed: `false`",
                "- Remote network enabled: `false`",
                "- Hardware bound: `false`",
                "- Licensing: `DRAFT_PENDING_LEGAL_REVIEW`",
                f"- Next gate: `{NEXT_GATE}`",
                "",
                "This closes the V00R3 engineering pre-release chain only. It is not a production, legal, security-accreditation, or hardware-binding certification.",
                "",
            ]
        ),
        encoding="utf-8",
    )

    return {
        "report": report,
        "report_path": report_path,
        "summary_path": summary_path,
        "evidence_manifest_path": evidence_manifest_path,
        "markdown_path": markdown_path,
    }


def selftest() -> int:
    ensure(len(EXPECTED_HEAD) == 40, "bad head constant")
    ensure(len(EXPECTED_TREE) == 40, "bad tree constant")
    ensure(len(EXPECTED_RELEASE_SHA256) == 64, "bad release hash")
    ensure(CLOSURE_CLASS == "ENGINEERING_PRE_RELEASE_CLOSED", "bad closure class")
    print("PASS_V00R3Z9_FINAL_CLOSURE_AUDITOR_SELFTEST")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root")
    ap.add_argument("--output-dir")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.repo_root or not args.output_dir:
        ap.error("--repo-root and --output-dir are required")
    result = perform_audit(Path(args.repo_root).resolve(), Path(args.output_dir).resolve())
    report = result["report"]
    print(PASS)
    print(f"CLOSURE_CLASS={report['closure_class']}")
    print(f"SOURCE_HEAD={report['source_head']}")
    print(f"RELEASE_SHA256={report['release_sha256']}")
    print(f"CRITICAL_MILESTONES_PASSED={report['critical_milestones_passed']}")
    print("SIGNED=False")
    print("PRODUCTION_READY=False")
    print("PRODUCTION_SERVICE_INSTALLED=False")
    print("REMOTE_NETWORK_ENABLED=False")
    print("HARDWARE_BOUND=False")
    print(f"NEXT_GATE={NEXT_GATE}")
    print(f"REPORT={result['report_path']}")
    print(f"SUMMARY={result['summary_path']}")
    print(f"EVIDENCE_MANIFEST={result['evidence_manifest_path']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AuditFailure as exc:
        print(f"NO_GO_ULTRABALLOONDB_V00R3Z9_FINAL_CLOSURE_AUDIT\nERROR={exc}", file=sys.stderr)
        raise SystemExit(1)
