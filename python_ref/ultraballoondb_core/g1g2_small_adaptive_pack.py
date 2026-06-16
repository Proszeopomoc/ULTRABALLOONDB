#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import json
import re
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple, Union

MAGIC = b"UBJ5ASM0"
VERSION = 1

ALLOWED_SUFFIXES = {
    ".txt", ".md", ".py", ".ps1", ".json", ".csv", ".tsv", ".log",
    ".toml", ".yaml", ".yml", ".ini", ".cfg",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def _u16(n: int) -> bytes:
    return struct.pack("<H", int(n))


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
class Piece:
    source_layer: str
    value: Union[int, bytes]


@dataclass(frozen=True)
class EncodedLine:
    source_layer: str
    pieces: Tuple[Piece, ...]


@dataclass
class AdaptiveCandidate:
    mode: str
    source_root: str
    files: List[SourceFile]
    dictionary: List[bytes]
    encoded_files: List[List[EncodedLine]]
    original_sha_by_file: Dict[str, str]
    pack_bytes: bytes
    selected_total_bytes: int
    payload_external: bool
    index_overhead_bytes: int


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


def original_pack_stream(files: List[SourceFile]) -> bytes:
    out = bytearray()
    out += b"UBJ5AOR0"
    out += _u32(len(files))
    for sf in files:
        out += _put_bytes(sf.relpath.encode("utf-8"))
        out += _u64(len(sf.data))
        out += sf.data
    return bytes(out)


def _vint(n: int) -> bytes:
    n = int(n)
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _serialize_candidate(mode: str, source_root: str, files: List[SourceFile], dictionary: List[bytes], encoded_files: List[List[EncodedLine]], include_payload: bool) -> bytes:
    header = {
        "magic": "ULTRABALLOONDB_V00J5A_SMALL_DATA_ADAPTIVE_PACK",
        "version": VERSION,
        "mode": mode,
        "source_root_hash": sha256_bytes(source_root.encode("utf-8")),
        "file_count": len(files),
        "dictionary_count": len(dictionary),
        "include_payload": include_payload,
        "files": [
            {
                "relpath": sf.relpath,
                "sha256": sha256_bytes(sf.data),
                "bytes": len(sf.data),
                "line_count": len(encoded_files[idx]),
            }
            for idx, sf in enumerate(files)
        ],
    }
    out = bytearray()
    out += MAGIC
    hb = json.dumps(header, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    out += _put_bytes(hb)

    out += _u32(len(dictionary))
    for item in dictionary:
        out += _put_bytes(item)

    out += _u32(len(files))
    for sf, enc_lines in zip(files, encoded_files):
        out += _put_bytes(sf.relpath.encode("utf-8"))
        out += _u32(len(enc_lines))
        for line in enc_lines:
            out += _vint(len(line.pieces))
            for piece in line.pieces:
                if piece.source_layer.startswith("G1_"):
                    out += b"R" + _vint(int(piece.value))
                else:
                    data = piece.value if isinstance(piece.value, bytes) else bytes(piece.value)
                    out += b"L" + _vint(len(data)) + data
        if include_payload:
            out += _put_bytes(sf.data)
    return bytes(out)


def build_line_family_candidate(input_folder: Path, files: List[SourceFile]) -> AdaptiveCandidate:
    counts: Dict[bytes, int] = {}
    file_lines: List[List[bytes]] = []
    for sf in files:
        lines = split_lines_exact(sf.data)
        file_lines.append(lines)
        for line in lines:
            counts[line] = counts.get(line, 0) + 1

    repeated = [line for line, count in counts.items() if count >= 2 and len(line) >= 4]
    repeated.sort(key=lambda b: (-counts[b], sha256_bytes(b), b))
    dictionary = repeated
    dict_index = {line: idx for idx, line in enumerate(dictionary)}

    encoded_files: List[List[EncodedLine]] = []
    for lines in file_lines:
        enc: List[EncodedLine] = []
        for line in lines:
            if line in dict_index:
                enc.append(EncodedLine("G1_LINE_RULE", (Piece("G1_LINE_RULE", dict_index[line]),)))
            else:
                enc.append(EncodedLine("G2_LINE_RESIDUAL", (Piece("G2_LINE_RESIDUAL", line),)))
        encoded_files.append(enc)

    pack = _serialize_candidate("G1G2_LINE_FAMILY", str(input_folder.resolve()), files, dictionary, encoded_files, include_payload=False)
    return AdaptiveCandidate(
        mode="G1G2_LINE_FAMILY",
        source_root=str(input_folder.resolve()),
        files=files,
        dictionary=dictionary,
        encoded_files=encoded_files,
        original_sha_by_file={sf.relpath: sha256_bytes(sf.data) for sf in files},
        pack_bytes=pack,
        selected_total_bytes=len(pack),
        payload_external=False,
        index_overhead_bytes=0,
    )


def _candidate_tokens_from_files(files: List[SourceFile], max_tokens: int = 512) -> List[bytes]:
    counts: Dict[bytes, int] = {}

    # Whole repeated lines can be very profitable for small documentation packs.
    for sf in files:
        for line in split_lines_exact(sf.data):
            stripped = line.strip()
            if len(stripped) >= 8:
                counts[line] = counts.get(line, 0) + 1

    word_re = re.compile(rb"[A-Za-z0-9_./\\:\-]{4,}")
    for sf in files:
        toks = word_re.findall(sf.data)
        for tok in toks:
            if len(tok) >= 4:
                counts[tok] = counts.get(tok, 0) + 1
        # Common short phrases: 2..5 neighboring tokens with one space between them.
        # These are not semantic claims; they are byte patterns only.
        for n in (2, 3, 4, 5):
            if len(toks) < n:
                continue
            for i in range(0, len(toks) - n + 1):
                phrase = b" ".join(toks[i:i+n])
                if 8 <= len(phrase) <= 160:
                    counts[phrase] = counts.get(phrase, 0) + 1

    scored: List[Tuple[int, bytes]] = []
    for tok, count in counts.items():
        if count < 2:
            continue
        # Conservative estimated net gain. Reference overhead is approx 2 bytes, dictionary entry overhead approx 4 bytes.
        gain = count * max(0, len(tok) - 2) - (len(tok) + 4)
        if gain > 0:
            scored.append((gain, tok))

    scored.sort(key=lambda x: (-x[0], -len(x[1]), sha256_bytes(x[1]), x[1]))
    out: List[bytes] = []
    seen = set()
    for _, tok in scored:
        if tok in seen:
            continue
        seen.add(tok)
        out.append(tok)
        if len(out) >= max_tokens:
            break
    # Greedy matching should prefer longest patterns first.
    out.sort(key=lambda b: (-len(b), sha256_bytes(b), b))
    return out


def _encode_line_with_dictionary(line: bytes, dictionary: List[bytes], dict_index: Dict[bytes, int]) -> EncodedLine:
    if not line:
        return EncodedLine("G2_BYTE_LITERAL", (Piece("G2_BYTE_LITERAL", b""),))

    pieces: List[Piece] = []
    i = 0
    literal = bytearray()
    while i < len(line):
        matched = None
        # dictionary size is intentionally bounded; linear scan is acceptable for this small-data intake gate.
        for tok in dictionary:
            if line.startswith(tok, i):
                matched = tok
                break
        if matched is not None:
            if literal:
                pieces.append(Piece("G2_BYTE_LITERAL", bytes(literal)))
                literal.clear()
            pieces.append(Piece("G1_TOKEN_RULE", dict_index[matched]))
            i += len(matched)
        else:
            literal.append(line[i])
            i += 1
    if literal:
        pieces.append(Piece("G2_BYTE_LITERAL", bytes(literal)))
    return EncodedLine("G1G2_TOKEN_MIX", tuple(pieces))


def build_token_dictionary_candidate(input_folder: Path, files: List[SourceFile], max_dictionary_tokens: int = 512) -> AdaptiveCandidate:
    dictionary = _candidate_tokens_from_files(files, max_tokens=max_dictionary_tokens)
    dict_index = {tok: idx for idx, tok in enumerate(dictionary)}
    encoded_files: List[List[EncodedLine]] = []
    for sf in files:
        enc_lines: List[EncodedLine] = []
        for line in split_lines_exact(sf.data):
            enc_lines.append(_encode_line_with_dictionary(line, dictionary, dict_index))
        encoded_files.append(enc_lines)
    pack = _serialize_candidate("DICT_SMALL_TOKEN_PACK", str(input_folder.resolve()), files, dictionary, encoded_files, include_payload=False)
    return AdaptiveCandidate(
        mode="DICT_SMALL_TOKEN_PACK",
        source_root=str(input_folder.resolve()),
        files=files,
        dictionary=dictionary,
        encoded_files=encoded_files,
        original_sha_by_file={sf.relpath: sha256_bytes(sf.data) for sf in files},
        pack_bytes=pack,
        selected_total_bytes=len(pack),
        payload_external=False,
        index_overhead_bytes=0,
    )


def build_raw_small_candidate(input_folder: Path, files: List[SourceFile]) -> AdaptiveCandidate:
    # RAW_SMALL is a pass-through archive mode: do not force G1/G2 overhead on small mixed data.
    # It keeps canonical file bytes externally and stores only a small deterministic line/query index.
    encoded_files: List[List[EncodedLine]] = []
    for sf in files:
        
        lines = split_lines_exact(sf.data)
        enc_lines: List[EncodedLine] = []
        offset = 0
        for line in lines:
            ref = _u64(offset) + _u32(len(line))
            enc_lines.append(EncodedLine("RAW_SMALL_EXTERNAL", (Piece("RAW_SMALL_EXTERNAL_REF", ref),)))
            offset += len(line)
        encoded_files.append(enc_lines)
    pack = _serialize_candidate("RAW_SMALL_INDEX", str(input_folder.resolve()), files, [], encoded_files, include_payload=False)
    original_bytes = sum(len(sf.data) for sf in files)
    return AdaptiveCandidate(
        mode="RAW_SMALL_INDEX",
        source_root=str(input_folder.resolve()),
        files=files,
        dictionary=[],
        encoded_files=encoded_files,
        original_sha_by_file={sf.relpath: sha256_bytes(sf.data) for sf in files},
        pack_bytes=pack,
        selected_total_bytes=original_bytes + len(pack),
        payload_external=True,
        index_overhead_bytes=len(pack),
    )


def rebuild_file(candidate: AdaptiveCandidate, file_index: int) -> bytes:
    if candidate.mode == "RAW_SMALL_INDEX":
        return candidate.files[file_index].data
    out = bytearray()
    for line in candidate.encoded_files[file_index]:
        for piece in line.pieces:
            if piece.source_layer.startswith("G1_"):
                out += candidate.dictionary[int(piece.value)]
            else:
                out += piece.value if isinstance(piece.value, bytes) else bytes(piece.value)
    return bytes(out)


def query_line(candidate: AdaptiveCandidate, file_index: int, line_index: int) -> Dict[str, object]:
    line = candidate.encoded_files[file_index][line_index]
    if candidate.mode == "RAW_SMALL_INDEX":
        value = candidate.files[file_index].data.splitlines(keepends=True)[line_index]
        return {
            "mode": candidate.mode,
            "file_index": file_index,
            "line_index": line_index,
            "source_layer": "RAW_SMALL_EXTERNAL_REF",
            "value_sha256_8": sha256_bytes(value)[:8],
            "value_preview": value[:160].decode("utf-8", errors="replace"),
            "no_full_rebuild": True,
        }

    source_layers: Dict[str, int] = {}
    out = bytearray()
    rule_ids: List[int] = []
    for piece in line.pieces:
        source_layers[piece.source_layer] = source_layers.get(piece.source_layer, 0) + 1
        if piece.source_layer.startswith("G1_"):
            rule_ids.append(int(piece.value))
            out += candidate.dictionary[int(piece.value)]
        else:
            out += piece.value if isinstance(piece.value, bytes) else bytes(piece.value)
    value = bytes(out)
    return {
        "mode": candidate.mode,
        "file_index": file_index,
        "line_index": line_index,
        "source_layers": source_layers,
        "rule_ids_sample": rule_ids[:8],
        "value_sha256_8": sha256_bytes(value)[:8],
        "value_preview": value[:160].decode("utf-8", errors="replace"),
        "no_full_rebuild": True,
    }


def source_layer_counts(candidate: AdaptiveCandidate) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for enc in candidate.encoded_files:
        for line in enc:
            for piece in line.pieces:
                counts[piece.source_layer] = counts.get(piece.source_layer, 0) + 1
    return counts


def candidate_summary(candidate: AdaptiveCandidate, original_bytes: int) -> Dict[str, object]:
    rebuilt_sha_by_file: Dict[str, str] = {}
    for idx, sf in enumerate(candidate.files):
        rebuilt_sha_by_file[sf.relpath] = sha256_bytes(rebuild_file(candidate, idx))
    file_sha_match_all = all(candidate.original_sha_by_file[p] == rebuilt_sha_by_file[p] for p in candidate.original_sha_by_file)

    if candidate.mode == "RAW_SMALL_INDEX":
        effective_ratio = (original_bytes / candidate.selected_total_bytes) if candidate.selected_total_bytes else 0.0
        payload_ratio = 1.0
    else:
        effective_ratio = (original_bytes / len(candidate.pack_bytes)) if candidate.pack_bytes else 0.0
        payload_ratio = effective_ratio
    return {
        "mode": candidate.mode,
        "pack_bytes": len(candidate.pack_bytes),
        "selected_total_bytes": candidate.selected_total_bytes,
        "payload_external": candidate.payload_external,
        "index_overhead_bytes": candidate.index_overhead_bytes,
        "dictionary_count": len(candidate.dictionary),
        "effective_ratio": effective_ratio,
        "payload_ratio": payload_ratio,
        "file_sha_match_all": file_sha_match_all,
        "deterministic_pack_bytes": candidate.pack_bytes == _serialize_candidate(candidate.mode, candidate.source_root, candidate.files, candidate.dictionary, candidate.encoded_files, include_payload=False),
        "source_layer_counts": source_layer_counts(candidate),
    }


def select_candidate(candidates: List[AdaptiveCandidate], original_bytes: int) -> AdaptiveCandidate:
    # Do not let a structural mode expand small mixed data. If no self-contained candidate beats raw bytes,
    # choose RAW_SMALL_INDEX as safe pass-through mode.
    self_contained = [c for c in candidates if not c.payload_external]
    beating = [c for c in self_contained if len(c.pack_bytes) < original_bytes]
    if beating:
        return min(beating, key=lambda c: (len(c.pack_bytes), c.mode))
    raw = [c for c in candidates if c.mode == "RAW_SMALL_INDEX"]
    if raw:
        return raw[0]
    return min(candidates, key=lambda c: (c.selected_total_bytes, c.mode))


def run_small_data_adaptive_pack(input_folder: Path, max_files: int, max_bytes_per_file: int, query_samples: int, max_dictionary_tokens: int = 512) -> Dict[str, object]:
    files = collect_input_files(input_folder, max_files=max_files, max_bytes_per_file=max_bytes_per_file)
    if not files:
        raise ValueError("no eligible input files found")

    original_bytes = sum(len(sf.data) for sf in files)
    original_stream = original_pack_stream(files)
    zlib_bytes = zlib.compress(original_stream, level=9)

    candidates = [
        build_raw_small_candidate(input_folder, files),
        build_line_family_candidate(input_folder, files),
        build_token_dictionary_candidate(input_folder, files, max_dictionary_tokens=max_dictionary_tokens),
    ]
    selected = select_candidate(candidates, original_bytes)

    selected_summary = candidate_summary(selected, original_bytes)
    candidate_summaries = [candidate_summary(c, original_bytes) for c in candidates]

    samples: List[Dict[str, object]] = []
    for file_index, enc in enumerate(selected.encoded_files):
        if not enc:
            continue
        candidate_indices = sorted(set([0, len(enc) // 2, len(enc) - 1]))
        for line_index in candidate_indices:
            samples.append(query_line(selected, file_index, line_index))
            if len(samples) >= query_samples:
                break
        if len(samples) >= query_samples:
            break

    no_full_rebuild_during_query = all(q.get("no_full_rebuild") for q in samples)
    compression_claim_allowed = bool(
        selected_summary["file_sha_match_all"]
        and not selected.payload_external
        and len(selected.pack_bytes) < original_bytes
    )

    return {
        "case": "small_data_adaptive_pack",
        "input_folder": str(input_folder.resolve()),
        "file_count": len(files),
        "original_bytes": original_bytes,
        "original_pack_bytes": len(original_stream),
        "zlib_bytes": len(zlib_bytes),
        "zlib_ratio": (original_bytes / len(zlib_bytes)) if zlib_bytes else 0.0,
        "selected_mode": selected.mode,
        "selected_pack_bytes": len(selected.pack_bytes),
        "selected_total_bytes": selected.selected_total_bytes,
        "selected_effective_ratio": selected_summary["effective_ratio"],
        "selected_payload_external": selected.payload_external,
        "selected_index_overhead_bytes": selected.index_overhead_bytes,
        "file_sha_match_all": bool(selected_summary["file_sha_match_all"]),
        "no_full_rebuild_during_query": no_full_rebuild_during_query,
        "compression_claim_allowed": compression_claim_allowed,
        "candidate_summaries": candidate_summaries,
        "source_layer_counts": selected_summary["source_layer_counts"],
        "query_sample": samples,
        "files": [
            {
                "index": idx,
                "relpath": sf.relpath,
                "bytes": len(sf.data),
                "sha256": sha256_bytes(sf.data),
                "line_count": len(split_lines_exact(sf.data)),
            }
            for idx, sf in enumerate(files)
        ],
    }
