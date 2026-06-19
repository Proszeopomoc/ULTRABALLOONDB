#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

EXPECTED_SCHEMA = "ultraballoondb.release.v1"
EXPECTED_MILESTONE = "V00R3G1_RELEASE_PACKAGING_R01"
REQUIRED = {
    "RELEASE_MANIFEST.json",
    "SHA256SUMS.txt",
    "README_RELEASE.txt",
    "COMPONENTS.json",
    "bin/ultraballoondb.exe",
    "bin/ultraballoondb-trust.exe",
    "bin/ultraballoondb-trust-enterprise.exe",
    "bin/ultraballoondb-trust-asymmetric.exe",
    "lib/ultraballoondb_cabi.dll",
    "include/ultraballoondb.h",
    "python/ultraballoondb_native.pyd",
    "python/ultraballoondb_native.pyi",
    "legal/COPYRIGHT",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def safe_name(name: str) -> bool:
    p = PurePosixPath(name)
    return bool(name) and not p.is_absolute() and ".." not in p.parts and "\\" not in name


def verify_static(zip_path: Path) -> dict:
    if not zip_path.is_file():
        raise RuntimeError(f"release zip missing: {zip_path}")
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        names = [i.filename for i in infos]
        if len(names) != len(set(names)):
            raise RuntimeError("duplicate zip entry")
        for info in infos:
            if not safe_name(info.filename):
                raise RuntimeError(f"unsafe zip path: {info.filename}")
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise RuntimeError(f"symlink entry rejected: {info.filename}")
        name_set = set(names)
        missing = sorted(REQUIRED - name_set)
        if missing:
            raise RuntimeError(f"required release entries missing: {missing}")
        manifest = json.loads(zf.read("RELEASE_MANIFEST.json").decode("utf-8"))
        if manifest.get("schema") != EXPECTED_SCHEMA or manifest.get("milestone") != EXPECTED_MILESTONE:
            raise RuntimeError("release manifest identity mismatch")
        hard_false = ["signed", "production_ready", "license_grant_in_bundle", "service_installed", "remote_listener_enabled", "active_runtime_changed", "storage_format_changed", "wal_changed", "daemon_binary_included"]
        for key in hard_false:
            if manifest.get(key) is not False:
                raise RuntimeError(f"manifest flag must be false: {key}")
        records = manifest.get("artifacts")
        if not isinstance(records, list) or not records:
            raise RuntimeError("artifact records missing")
        manifest_paths = set()
        for rec in records:
            path = rec.get("path")
            if not safe_name(path):
                raise RuntimeError(f"unsafe manifest path: {path}")
            if path in manifest_paths:
                raise RuntimeError(f"duplicate manifest path: {path}")
            manifest_paths.add(path)
            if path not in name_set:
                raise RuntimeError(f"manifest path missing from zip: {path}")
            data = zf.read(path)
            if len(data) != rec.get("size_bytes") or sha256_bytes(data) != rec.get("sha256"):
                raise RuntimeError(f"artifact digest mismatch: {path}")
        expected_set = manifest_paths | {"RELEASE_MANIFEST.json", "SHA256SUMS.txt"}
        if name_set != expected_set:
            extra = sorted(name_set - expected_set)
            absent = sorted(expected_set - name_set)
            raise RuntimeError(f"release exact-set mismatch extra={extra} missing={absent}")
        sums = zf.read("SHA256SUMS.txt").decode("utf-8").splitlines()
        parsed = {}
        for line in sums:
            if not line.strip():
                continue
            digest, sep, path = line.partition("  ")
            if not sep or path in parsed:
                raise RuntimeError("invalid SHA256SUMS format")
            parsed[path] = digest
        if set(parsed) != (name_set - {"SHA256SUMS.txt"}):
            raise RuntimeError("SHA256SUMS exact set mismatch")
        for path, digest in parsed.items():
            if sha256_bytes(zf.read(path)) != digest:
                raise RuntimeError(f"SHA256SUMS mismatch: {path}")
        for pe in ("bin/ultraballoondb.exe", "lib/ultraballoondb_cabi.dll", "python/ultraballoondb_native.pyd"):
            if zf.read(pe)[:2] != b"MZ":
                raise RuntimeError(f"not a PE artifact: {pe}")
    return {
        "pass": True,
        "version": EXPECTED_MILESTONE,
        "release_zip": str(zip_path),
        "release_sha256": sha256_file(zip_path),
        "release_size_bytes": zip_path.stat().st_size,
        "artifact_count": len(records),
        "manifest_verified": True,
        "checksums_verified": True,
        "exact_file_set_verified": True,
        "unsafe_paths_absent": True,
        "symlinks_absent": True,
        "signed": False,
        "production_ready": False,
    }


def verify_dynamic(zip_path: Path) -> dict:
    if os.name != "nt":
        raise RuntimeError("dynamic verification requires Windows")
    with tempfile.TemporaryDirectory(prefix="ubdb_g1_verify_") as tmp:
        root = Path(tmp)
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(root)
        cli = root / "bin/ultraballoondb.exe"
        cli_run = subprocess.run([str(cli), "version"], text=True, capture_output=True, timeout=30)
        if cli_run.returncode != 0:
            raise RuntimeError(f"native CLI version failed: {cli_run.stderr}")
        cli_json = json.loads(cli_run.stdout)
        if not cli_json.get("ok") or cli_json.get("command") != "version":
            raise RuntimeError("native CLI version response invalid")
        cabi_module = root / "lib/ultraballoondb_cabi.dll"
        cabi_code = (
            "import ctypes,json,sys;"
            "dll=ctypes.CDLL(sys.argv[1]);"
            "abi=dll.ubdb_abi_version_v1;abi.argtypes=[];abi.restype=ctypes.c_uint32;"
            "protocol=dll.ubdb_protocol_version_v1;protocol.argtypes=[];protocol.restype=ctypes.c_uint16;"
            "print(json.dumps({'abi':int(abi()),'protocol':int(protocol())}))"
        )
        cabi_run = subprocess.run(
            [sys.executable, "-c", cabi_code, str(cabi_module)],
            text=True,
            capture_output=True,
            timeout=60,
        )
        if cabi_run.returncode != 0:
            raise RuntimeError(f"C ABI dynamic load failed: {cabi_run.stderr}")
        cabi_result = json.loads(cabi_run.stdout)
        if cabi_result != {"abi": 1, "protocol": 1}:
            raise RuntimeError(f"C ABI dynamic version mismatch: {cabi_result}")
        module = root / "python/ultraballoondb_native.pyd"
        code = "import importlib.util,sys,json; p=sys.argv[1]; s=importlib.util.spec_from_file_location('ultraballoondb_native',p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); print(json.dumps({'abi':m.abi_version(),'protocol':m.protocol_version()}))"
        run = subprocess.run([sys.executable, "-c", code, str(module)], text=True, capture_output=True, timeout=60)
        if run.returncode != 0:
            raise RuntimeError(f"PyO3 import failed: {run.stderr}")
        imported = json.loads(run.stdout)
        if imported != {"abi": 1, "protocol": 1}:
            raise RuntimeError(f"PyO3 version mismatch: {imported}")
    return {
        "native_cli_version_probe": True,
        "cabi_dynamic_load_probe": True,
        "pyo3_fresh_process_import_probe": True,
        "abi_version": 1,
        "protocol_version": 1,
    }


def selftest() -> int:
    # The release builder owns the full synthetic archive selftest. This verifier
    # selftest covers path validation and digest primitives without fabricating a
    # second manifest implementation.
    if safe_name("../bad") or safe_name("/bad") or safe_name("bad\\path"):
        raise RuntimeError("unsafe path selftest failed")
    if not safe_name("bin/ultraballoondb.exe"):
        raise RuntimeError("safe path selftest failed")
    if sha256_bytes(b"abc") != "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD":
        raise RuntimeError("sha256 selftest failed")
    print("PASS_V00R3G1_RELEASE_VERIFIER_SELFTEST")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--release-zip")
    parser.add_argument("--dynamic", action="store_true")
    parser.add_argument("--output-json", default="")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    if not args.release_zip:
        parser.error("--release-zip is required")
    result = verify_static(Path(args.release_zip).resolve())
    if args.dynamic:
        result.update(verify_dynamic(Path(args.release_zip).resolve()))
    if args.output_json:
        Path(args.output_json).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
