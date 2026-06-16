#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import json
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

MAGIC = b"UBJ5G1G2"
VERSION = 1

ALLOWED_SUFFIXES = {
    ".txt", ".md", ".py", ".ps1", ".json", ".csv", ".tsv", ".log",
    ".toml", ".yaml", ".yml", ".ini", ".cfg",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def _u32(n: int) -> bytes:
    return struct.pack("<I", int(n))


def _u64(n: int) -> bytes:
    return struct.pack("<Q", int(n))


def _put_bytes(data: bytes) -> bytes:
    return _u32(len(data)) + data


@dataclass(frozen=True)
class SourceFile:
    relpath: str
    data: bytes


@dataclass(frozen=True)
class EncodedLine:
    source_layer: str
    value: int | bytes


@dataclass
class FamilyModel:
    source_root: str
    files: List[SourceFile]
    dictionary: List[bytes]
    encoded_files: List[List[EncodedLine]]
    original_sha_by_file: Dict[str, str]


def collect_input_files(input_folder: Path, max_files: int, max_bytes_per_file: int) -> List[SourceFile]:
    root = input_folder.resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"input folder does not exist: {root}")

    files: List[SourceFile] = []
    for path in sorted(root.rglob("*"), key=lambda p: str(p).lower()):
        if not path.is_file():
            continue
        if path.suffix.lower() not in ALLOWED_SUFFIXES:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > max_bytes_per_file:
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        # Skip likely binary blobs but keep UTF-8/text-like files. NUL is enough for this first intake gate.
        if b"\x00" in data:
            continue
        rel = path.relative_to(root).as_posix()
        files.append(SourceFile(rel, data))
        if len(files) >= max_files:
            break
    return files


def split_lines_exact(data: bytes) -> List[bytes]:
    if data == b"":
        return [b""]
    return data.splitlines(keepends=True)


def build_family_model(input_folder: Path, max_files: int = 64, max_bytes_per_file: int = 1_048_576) -> FamilyModel:
    files = collect_input_files(input_folder, max_files=max_files, max_bytes_per_file=max_bytes_per_file)
    if not files:
        raise ValueError("no eligible input files found")

    counts: Dict[bytes, int] = {}
    file_lines: List[List[bytes]] = []
    for sf in files:
        lines = split_lines_exact(sf.data)
        file_lines.append(lines)
        for line in lines:
            counts[line] = counts.get(line, 0) + 1

    # G1 family rule dictionary: lines repeated across the family. Stable order by frequency desc, then hash, then bytes.
    repeated = [line for line, count in counts.items() if count >= 2]
    repeated.sort(key=lambda b: (-counts[b], sha256_bytes(b), b))
    dictionary = repeated
    dict_index = {line: idx for idx, line in enumerate(dictionary)}

    encoded_files: List[List[EncodedLine]] = []
    for lines in file_lines:
        enc: List[EncodedLine] = []
        for line in lines:
            if line in dict_index:
                enc.append(EncodedLine("G1_FAMILY_RULE", dict_index[line]))
            else:
                enc.append(EncodedLine("G2_FILE_RESIDUAL", line))
        encoded_files.append(enc)

    return FamilyModel(
        source_root=str(input_folder.resolve()),
        files=files,
        dictionary=dictionary,
        encoded_files=encoded_files,
        original_sha_by_file={sf.relpath: sha256_bytes(sf.data) for sf in files},
    )


def serialize_family_model(model: FamilyModel) -> bytes:
    header = {
        "magic": "ULTRABALLOONDB_V00J5_G1G2_REAL_FILE_FAMILY_INTAKE",
        "version": VERSION,
        "source_root_hash": sha256_bytes(model.source_root.encode("utf-8")),
        "file_count": len(model.files),
        "dictionary_count": len(model.dictionary),
        "files": [
            {
                "relpath": sf.relpath,
                "sha256": model.original_sha_by_file[sf.relpath],
                "line_count": len(model.encoded_files[idx]),
            }
            for idx, sf in enumerate(model.files)
        ],
    }
    out = bytearray()
    out += MAGIC
    hb = json.dumps(header, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    out += _put_bytes(hb)

    out += _u32(len(model.dictionary))
    for line in model.dictionary:
        out += _put_bytes(line)

    out += _u32(len(model.files))
    for sf, enc_lines in zip(model.files, model.encoded_files):
        out += _put_bytes(sf.relpath.encode("utf-8"))
        out += _u32(len(enc_lines))
        for item in enc_lines:
            if item.source_layer == "G1_FAMILY_RULE":
                out += b"R" + _u32(int(item.value))
            elif item.source_layer == "G2_FILE_RESIDUAL":
                out += b"L" + _put_bytes(item.value if isinstance(item.value, bytes) else bytes(item.value))
            else:
                raise ValueError(f"unknown source layer: {item.source_layer}")
    return bytes(out)


def original_pack_stream(files: List[SourceFile]) -> bytes:
    out = bytearray()
    out += b"UBJ5ORIG"
    out += _u32(len(files))
    for sf in files:
        out += _put_bytes(sf.relpath.encode("utf-8"))
        out += _u64(len(sf.data))
        out += sf.data
    return bytes(out)


def rebuild_file(model: FamilyModel, file_index: int) -> bytes:
    out = bytearray()
    for item in model.encoded_files[file_index]:
        if item.source_layer == "G1_FAMILY_RULE":
            out += model.dictionary[int(item.value)]
        elif item.source_layer == "G2_FILE_RESIDUAL":
            out += item.value if isinstance(item.value, bytes) else bytes(item.value)
        else:
            raise ValueError(f"unknown source layer: {item.source_layer}")
    return bytes(out)


def query_line(model: FamilyModel, file_index: int, line_index: int) -> Dict[str, object]:
    item = model.encoded_files[file_index][line_index]
    if item.source_layer == "G1_FAMILY_RULE":
        value = model.dictionary[int(item.value)]
        return {
            "file_index": file_index,
            "line_index": line_index,
            "source_layer": "G1_FAMILY_RULE",
            "rule_id": int(item.value),
            "value_sha256_8": sha256_bytes(value)[:8],
            "value_preview": value[:160].decode("utf-8", errors="replace"),
            "no_full_rebuild": True,
        }
    value = item.value if isinstance(item.value, bytes) else bytes(item.value)
    return {
        "file_index": file_index,
        "line_index": line_index,
        "source_layer": "G2_FILE_RESIDUAL",
        "value_sha256_8": sha256_bytes(value)[:8],
        "value_preview": value[:160].decode("utf-8", errors="replace"),
        "no_full_rebuild": True,
    }


def run_real_file_family_intake(input_folder: Path, max_files: int, max_bytes_per_file: int, query_samples: int) -> Dict[str, object]:
    model = build_family_model(input_folder, max_files=max_files, max_bytes_per_file=max_bytes_per_file)
    pack = serialize_family_model(model)
    pack2 = serialize_family_model(model)
    original_stream = original_pack_stream(model.files)
    zlib_bytes = zlib.compress(original_stream, level=9)

    rebuilt_sha_by_file: Dict[str, str] = {}
    for idx, sf in enumerate(model.files):
        rebuilt_sha_by_file[sf.relpath] = sha256_bytes(rebuild_file(model, idx))

    file_sha_match_all = all(
        model.original_sha_by_file[path] == rebuilt_sha_by_file[path]
        for path in model.original_sha_by_file
    )

    source_layer_counts: Dict[str, int] = {}
    for enc in model.encoded_files:
        for item in enc:
            source_layer_counts[item.source_layer] = source_layer_counts.get(item.source_layer, 0) + 1

    samples: List[Dict[str, object]] = []
    # Deterministic sample: first line, middle line, last line across files until limit.
    for file_index, enc in enumerate(model.encoded_files):
        if not enc:
            continue
        candidate_indices = sorted(set([0, len(enc) // 2, len(enc) - 1]))
        for line_index in candidate_indices:
            samples.append(query_line(model, file_index, line_index))
            if len(samples) >= query_samples:
                break
        if len(samples) >= query_samples:
            break

    original_bytes = sum(len(sf.data) for sf in model.files)
    g1g2_bytes = len(pack)
    zlib_len = len(zlib_bytes)

    return {
        "case": "real_file_family_intake",
        "input_folder": str(input_folder.resolve()),
        "file_count": len(model.files),
        "dictionary_count": len(model.dictionary),
        "original_bytes": original_bytes,
        "original_pack_bytes": len(original_stream),
        "g1g2_family_bytes": g1g2_bytes,
        "g1g2_family_ratio": (original_bytes / g1g2_bytes) if g1g2_bytes else 0.0,
        "zlib_bytes": zlib_len,
        "zlib_ratio": (original_bytes / zlib_len) if zlib_len else 0.0,
        "g1g2_beats_zlib": g1g2_bytes < zlib_len,
        "deterministic_pack_bytes": pack == pack2,
        "pack_sha256": sha256_bytes(pack),
        "original_pack_sha256": sha256_bytes(original_stream),
        "file_sha_match_all": file_sha_match_all,
        "no_full_rebuild_during_query": all(q.get("no_full_rebuild") for q in samples),
        "source_layer_counts": source_layer_counts,
        "compression_claim_allowed": bool(file_sha_match_all and original_bytes > g1g2_bytes),
        "query_sample": samples,
        "files": [
            {
                "index": idx,
                "relpath": sf.relpath,
                "bytes": len(sf.data),
                "sha256": model.original_sha_by_file[sf.relpath],
                "line_count": len(model.encoded_files[idx]),
            }
            for idx, sf in enumerate(model.files)
        ],
    }
