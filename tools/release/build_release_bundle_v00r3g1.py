#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

MILESTONE = "V00R3G1_RELEASE_PACKAGING_R01"
BUNDLE_FORMAT = "ultraballoondb.release.v1"
FIXED_ZIP_TIME = (2026, 1, 1, 0, 0, 0)
RELEASE_ROOT_NAME = "UltraBalloonDB-0.0.3-windows-x86_64-pre1"

REQUIRED_SPEC_PATHS = [
    "specs/storage/ULTRABALLOONDB_STORAGE_FORMAT_V1.md",
    "specs/storage/ULTRABALLOONDB_WAL_FORMAT_V1.md",
    "specs/protocol/ULTRABALLOONDB_DAEMON_PROTOCOL_V1.md",
    "specs/ffi/ULTRABALLOONDB_C_ABI_V1.md",
    "specs/python/ULTRABALLOONDB_PYO3_V1.md",
    "specs/provenance/ULTRABALLOONDB_PROVENANCE_CORE_V1.md",
    "specs/trust/TRUST_INVARIANTS_V1.md",
    "specs/operations/ULTRABALLOONDB_OBSERVABILITY_AND_SECURITY_V1.md",
]

FORBIDDEN_SUFFIXES = {
    ".pdb", ".d", ".rlib", ".rmeta", ".exp", ".ilk", ".obj", ".o", ".a",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def normalized_rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def safe_copy(src: Path, dst: Path) -> None:
    if not src.is_file() or src.is_symlink():
        raise RuntimeError(f"release input must be a regular non-symlink file: {src}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)


def deterministic_zip(source_dir: Path, output_zip: Path) -> None:
    files = sorted(p for p in source_dir.rglob("*") if p.is_file())
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    temp = output_zip.with_suffix(output_zip.suffix + ".tmp")
    if temp.exists():
        temp.unlink()
    with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in files:
            rel = normalized_rel(path, source_dir)
            info = zipfile.ZipInfo(rel, FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (0o100644 & 0xFFFF) << 16
            data = path.read_bytes()
            zf.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    os.replace(temp, output_zip)


def artifact_record(root: Path, path: Path, role: str, edition: str, executable: bool = False) -> dict:
    return {
        "path": normalized_rel(path, root),
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
        "role": role,
        "edition": edition,
        "executable": executable,
    }


def validate_pe(path: Path) -> None:
    if path.read_bytes()[:2] != b"MZ":
        raise RuntimeError(f"expected Windows PE artifact (MZ): {path}")


def build_release(args: argparse.Namespace) -> dict:
    repo = Path(args.repo_root).resolve()
    out = Path(args.output_zip).resolve()
    metadata = json.loads(Path(args.build_metadata).read_text(encoding="utf-8-sig"))

    required_meta = ["source_commit", "source_tree", "cargo_version", "rustc_version", "target_triple"]
    for key in required_meta:
        if not str(metadata.get(key, "")).strip():
            raise RuntimeError(f"missing build metadata field: {key}")

    inputs = {
        "native_cli": Path(args.native_cli).resolve(),
        "trust_cli": Path(args.trust_cli).resolve(),
        "trust_enterprise_cli": Path(args.trust_enterprise_cli).resolve(),
        "trust_asymmetric_cli": Path(args.trust_asymmetric_cli).resolve(),
        "cabi_dll": Path(args.cabi_dll).resolve(),
        "pyo3_module": Path(args.pyo3_module).resolve(),
        "c_header": (repo / "rust_native/ultraballoondb-cabi/include/ultraballoondb.h").resolve(),
        "python_stub": (repo / "python/ultraballoondb_native.pyi").resolve(),
        "copyright": (repo / "COPYRIGHT").resolve(),
        "readme": (repo / "README.md").resolve(),
        "product_position": (repo / "docs/product/ULTRABALLOONDB_PRODUCT_POSITION_V1.md").resolve(),
        "product_architecture": (repo / "docs/architecture/ULTRABALLOONDB_PRODUCT_ARCHITECTURE_V1.md").resolve(),
        "provenance_license": (repo / "docs/PROVENANCE_AND_LICENSE_STATUS.md").resolve(),
        "license_draft": (repo / "docs/legal/LICENSING_STRATEGY_DRAFT_V1.md").resolve(),
        "verifier": (repo / "tools/release/verify_release_bundle_v00r3g1.py").resolve(),
        "verify_ps1": (repo / "scripts/windows/VERIFY_ULTRABALLOONDB_RELEASE_V00R3G1.ps1").resolve(),
    }
    for key, path in inputs.items():
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"required release input missing or unsafe: {key}={path}")

    for key in ("native_cli", "trust_cli", "trust_enterprise_cli", "trust_asymmetric_cli", "cabi_dll", "pyo3_module"):
        validate_pe(inputs[key])

    with tempfile.TemporaryDirectory(prefix="ubdb_g1_release_") as tmp:
        stage = Path(tmp) / RELEASE_ROOT_NAME
        stage.mkdir(parents=True)

        copy_map = [
            (inputs["native_cli"], stage / "bin/ultraballoondb.exe"),
            (inputs["trust_cli"], stage / "bin/ultraballoondb-trust.exe"),
            (inputs["trust_enterprise_cli"], stage / "bin/ultraballoondb-trust-enterprise.exe"),
            (inputs["trust_asymmetric_cli"], stage / "bin/ultraballoondb-trust-asymmetric.exe"),
            (inputs["cabi_dll"], stage / "lib/ultraballoondb_cabi.dll"),
            (inputs["pyo3_module"], stage / "python/ultraballoondb_native.pyd"),
            (inputs["c_header"], stage / "include/ultraballoondb.h"),
            (inputs["python_stub"], stage / "python/ultraballoondb_native.pyi"),
            (inputs["copyright"], stage / "legal/COPYRIGHT"),
            (inputs["license_draft"], stage / "legal/LICENSING_STRATEGY_DRAFT_V1.md"),
            (inputs["provenance_license"], stage / "legal/PROVENANCE_AND_LICENSE_STATUS.md"),
            (inputs["readme"], stage / "docs/README.md"),
            (inputs["product_position"], stage / "docs/ULTRABALLOONDB_PRODUCT_POSITION_V1.md"),
            (inputs["product_architecture"], stage / "docs/ULTRABALLOONDB_PRODUCT_ARCHITECTURE_V1.md"),
            (inputs["verifier"], stage / "verification/verify_release_bundle_v00r3g1.py"),
            (inputs["verify_ps1"], stage / "verification/VERIFY_RELEASE.ps1"),
        ]
        for src, dst in copy_map:
            safe_copy(src, dst)

        optional_libs = []
        for raw in args.cabi_library:
            path = Path(raw).resolve()
            if path.is_file() and not path.is_symlink():
                name = path.name
                if name.lower().endswith(".lib"):
                    dst = stage / "lib" / name
                    safe_copy(path, dst)
                    optional_libs.append(dst)

        for rel in REQUIRED_SPEC_PATHS:
            src = (repo / rel).resolve()
            if not src.is_file() or src.is_symlink():
                raise RuntimeError(f"required release specification missing: {rel}")
            safe_copy(src, stage / rel)

        pre_release = """UltraBalloonDB 0.0.3 Windows x86_64 pre-release\n\nThis bundle is experimental evaluation software. It is unsigned, carries no SLA,\ninstalls no Windows service, exposes no remote listener, and grants no license\nbeyond the repository COPYRIGHT and applicable law. Verify SHA256SUMS and\nRELEASE_MANIFEST.json before use.\n\nIncluded delivery surfaces:\n- Edition A native offline CLI\n- Edition B CPython abi3 extension\n- Edition D stable C ABI DLL and header\n- offline Trust administration tools\n\nEdition C production daemon/service is not included. D2 remains a bounded local\nprotocol core and requires a later explicit service deployment gate.\n"""
        (stage / "README_RELEASE.txt").write_text(pre_release, encoding="utf-8", newline="\n")

        components = {
            "schema": "ultraballoondb.components.v1",
            "product": "UltraBalloonDB",
            "version": "0.0.3",
            "source_commit": metadata["source_commit"],
            "components": [
                {"name": "Edition A native CLI", "included": True, "path": "bin/ultraballoondb.exe"},
                {"name": "Edition B PyO3 abi3 module", "included": True, "path": "python/ultraballoondb_native.pyd"},
                {"name": "Edition C daemon/service", "included": False, "reason": "production service installation is outside G1"},
                {"name": "Edition D C ABI", "included": True, "path": "lib/ultraballoondb_cabi.dll"},
                {"name": "Observability/security wrapper", "included": False, "reason": "build-only library; no active runtime wiring in E1/G1"},
            ],
        }
        (stage / "COMPONENTS.json").write_text(json.dumps(components, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")

        roles = {
            "bin/ultraballoondb.exe": ("native offline database CLI", "A", True),
            "bin/ultraballoondb-trust.exe": ("offline trust administration CLI", "support", True),
            "bin/ultraballoondb-trust-enterprise.exe": ("offline enterprise trust CLI", "support", True),
            "bin/ultraballoondb-trust-asymmetric.exe": ("offline asymmetric trust CLI", "support", True),
            "lib/ultraballoondb_cabi.dll": ("stable C ABI dynamic library", "D", True),
            "python/ultraballoondb_native.pyd": ("CPython abi3 extension", "B", True),
            "include/ultraballoondb.h": ("public C ABI header", "D", False),
            "python/ultraballoondb_native.pyi": ("Python type stub", "B", False),
        }

        records = []
        for path in sorted(p for p in stage.rglob("*") if p.is_file()):
            rel = normalized_rel(path, stage)
            if rel in {"RELEASE_MANIFEST.json", "SHA256SUMS.txt"}:
                continue
            role, edition, executable = roles.get(rel, ("documentation or verification material", "shared", False))
            records.append(artifact_record(stage, path, role, edition, executable))

        manifest = {
            "schema": BUNDLE_FORMAT,
            "milestone": MILESTONE,
            "product": "UltraBalloonDB",
            "version": "0.0.3",
            "release_channel": "pre-release-evaluation",
            "platform": "windows-x86_64",
            "source_commit": metadata["source_commit"],
            "source_tree": metadata["source_tree"],
            "source_subject": metadata.get("source_subject", ""),
            "cargo_version": metadata["cargo_version"],
            "rustc_version": metadata["rustc_version"],
            "target_triple": metadata["target_triple"],
            "python_version": metadata.get("python_version", ""),
            "build_profile": "release",
            "deterministic_zip": True,
            "signed": False,
            "production_ready": False,
            "license_grant_in_bundle": False,
            "service_installed": False,
            "remote_listener_enabled": False,
            "active_runtime_changed": False,
            "storage_format_changed": False,
            "wal_changed": False,
            "daemon_binary_included": False,
            "artifacts": records,
        }
        manifest_path = stage / "RELEASE_MANIFEST.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")

        checksum_paths = sorted(p for p in stage.rglob("*") if p.is_file() and p.name != "SHA256SUMS.txt")
        checksum_lines = [f"{sha256_file(p)}  {normalized_rel(p, stage)}" for p in checksum_paths]
        (stage / "SHA256SUMS.txt").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8", newline="\n")

        # No build internals or secret-like paths may enter the bundle.
        for path in stage.rglob("*"):
            if not path.is_file():
                continue
            rel = normalized_rel(path, stage)
            suffix = path.suffix.lower()
            if suffix in FORBIDDEN_SUFFIXES:
                raise RuntimeError(f"forbidden build intermediate in release: {rel}")
            lower = rel.lower()
            if any(token in lower for token in ("/.env", "secret", "credential", "id_rsa", "id_ed25519")):
                raise RuntimeError(f"forbidden secret-like path in release: {rel}")

        deterministic_zip(stage, out)
        first_hash = sha256_file(out)

        if args.repeat_output:
            repeat = Path(args.repeat_output).resolve()
            deterministic_zip(stage, repeat)
            second_hash = sha256_file(repeat)
            if first_hash != second_hash:
                raise RuntimeError(f"deterministic package mismatch: {first_hash} != {second_hash}")

        return {
            "pass": True,
            "version": MILESTONE,
            "release_zip": str(out),
            "release_sha256": first_hash,
            "release_size_bytes": out.stat().st_size,
            "artifact_count": len(records),
            "source_commit": metadata["source_commit"],
            "source_tree": metadata["source_tree"],
            "deterministic_repeat_match": bool(args.repeat_output),
            "signed": False,
            "production_ready": False,
            "service_installed": False,
            "remote_listener_enabled": False,
            "active_runtime_changed": False,
        }


def selftest() -> int:
    with tempfile.TemporaryDirectory(prefix="ubdb_g1_builder_selftest_") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        out = root / "one.zip"
        repeat = root / "two.zip"
        # minimal fixture repository
        required = [
            "rust_native/ultraballoondb-cabi/include/ultraballoondb.h",
            "python/ultraballoondb_native.pyi",
            "COPYRIGHT", "README.md",
            "docs/product/ULTRABALLOONDB_PRODUCT_POSITION_V1.md",
            "docs/architecture/ULTRABALLOONDB_PRODUCT_ARCHITECTURE_V1.md",
            "docs/PROVENANCE_AND_LICENSE_STATUS.md",
            "docs/legal/LICENSING_STRATEGY_DRAFT_V1.md",
            "tools/release/verify_release_bundle_v00r3g1.py",
            "scripts/windows/VERIFY_ULTRABALLOONDB_RELEASE_V00R3G1.ps1",
            *REQUIRED_SPEC_PATHS,
        ]
        for rel in required:
            p = repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(rel + "\n", encoding="utf-8")
        artifacts = {}
        for name in ("native", "trust", "enterprise", "asymmetric", "cabi", "pyo3"):
            p = root / f"{name}.bin"
            p.write_bytes(b"MZ" + name.encode("ascii") * 8)
            artifacts[name] = p
        meta = root / "meta.json"
        meta.write_text(json.dumps({
            "source_commit": "A" * 40,
            "source_tree": "B" * 40,
            "source_subject": "selftest",
            "cargo_version": "cargo selftest",
            "rustc_version": "rustc selftest",
            "target_triple": "x86_64-pc-windows-msvc",
            "python_version": "Python selftest",
        }), encoding="utf-8")
        args = argparse.Namespace(
            repo_root=str(repo), output_zip=str(out), repeat_output=str(repeat),
            build_metadata=str(meta), native_cli=str(artifacts["native"]),
            trust_cli=str(artifacts["trust"]), trust_enterprise_cli=str(artifacts["enterprise"]),
            trust_asymmetric_cli=str(artifacts["asymmetric"]), cabi_dll=str(artifacts["cabi"]),
            pyo3_module=str(artifacts["pyo3"]), cabi_library=[]
        )
        result = build_release(args)
        if not result["pass"] or sha256_file(out) != sha256_file(repeat):
            raise RuntimeError("release builder selftest failed")
        with zipfile.ZipFile(out) as zf:
            names = set(zf.namelist())
            if "RELEASE_MANIFEST.json" not in names or "SHA256SUMS.txt" not in names:
                raise RuntimeError("release metadata missing")
    print("PASS_V00R3G1_RELEASE_BUILDER_SELFTEST")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--repo-root")
    parser.add_argument("--output-zip")
    parser.add_argument("--repeat-output", default="")
    parser.add_argument("--build-metadata")
    parser.add_argument("--native-cli")
    parser.add_argument("--trust-cli")
    parser.add_argument("--trust-enterprise-cli")
    parser.add_argument("--trust-asymmetric-cli")
    parser.add_argument("--cabi-dll")
    parser.add_argument("--pyo3-module")
    parser.add_argument("--cabi-library", action="append", default=[])
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    required = ["repo_root", "output_zip", "build_metadata", "native_cli", "trust_cli", "trust_enterprise_cli", "trust_asymmetric_cli", "cabi_dll", "pyo3_module"]
    for key in required:
        if not getattr(args, key):
            parser.error(f"--{key.replace('_', '-')} is required")
    result = build_release(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
