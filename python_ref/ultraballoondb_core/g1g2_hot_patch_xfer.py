#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple

from ultraballoondb_core.g1g2_delta_patch import (
    MatrixG1G2DeltaModel,
    PrefixFamilyG1G2DeltaModel,
    canon,
    sha256_bytes,
)

FORMAT = "UBDB_G1G2_HOT_PATCH_XFER_V00J7"


class HotPatchError(ValueError):
    """Raised when a hot patch bundle fails deterministic validation."""


@dataclass(frozen=True)
class HotPatchReceipt:
    kind: str
    operation_count: int
    content_sha256: str
    base_state_sha256: str
    target_state_sha256_expected: str
    hot_apply_full_rebuild_count: int
    verification_deferred_to_explicit_gate: bool

    def as_dict(self) -> Dict[str, object]:
        return {
            "kind": self.kind,
            "operation_count": self.operation_count,
            "content_sha256": self.content_sha256,
            "base_state_sha256": self.base_state_sha256,
            "target_state_sha256_expected": self.target_state_sha256_expected,
            "hot_apply_full_rebuild_count": self.hot_apply_full_rebuild_count,
            "verification_deferred_to_explicit_gate": self.verification_deferred_to_explicit_gate,
        }


def _clone_matrix(model: MatrixG1G2DeltaModel) -> MatrixG1G2DeltaModel:
    return MatrixG1G2DeltaModel(
        n=int(model.n),
        exceptions={int(k): int(v) for k, v in model.exceptions.items()},
        patches={int(k): int(v) for k, v in model.patches.items()},
    )


def _clone_prefix(model: PrefixFamilyG1G2DeltaModel) -> PrefixFamilyG1G2DeltaModel:
    return PrefixFamilyG1G2DeltaModel(
        count=int(model.count),
        prefix=str(model.prefix),
        exceptions={int(k): str(v) for k, v in model.exceptions.items()},
        patches={int(k): str(v) for k, v in model.patches.items()},
    )


def _build_envelope(content: Mapping[str, object], provenance: Mapping[str, object] | None) -> bytes:
    content_obj = dict(content)
    content_bytes = canon(content_obj)
    envelope = {
        "format": FORMAT,
        "content": content_obj,
        "content_sha256": sha256_bytes(content_bytes),
        # Provenance is carried for audit but deliberately excluded from content_sha256.
        "provenance": dict(provenance or {}),
    }
    return canon(envelope)


def parse_bundle(bundle: bytes) -> Dict[str, object]:
    try:
        envelope = json.loads(bundle.decode("utf-8"))
    except Exception as exc:  # pragma: no cover - explicit validation path
        raise HotPatchError("bundle is not canonical UTF-8 JSON") from exc
    if envelope.get("format") != FORMAT:
        raise HotPatchError("invalid hot patch format")
    content = envelope.get("content")
    if not isinstance(content, dict):
        raise HotPatchError("missing content object")
    expected = str(envelope.get("content_sha256", ""))
    actual = sha256_bytes(canon(content))
    if expected != actual:
        raise HotPatchError("content hash mismatch")
    if content.get("kind") not in {"MATRIX", "PREFIX"}:
        raise HotPatchError("unsupported hot patch kind")
    operations = content.get("operations")
    if not isinstance(operations, list) or not operations:
        raise HotPatchError("operations must be a non-empty list")
    for seq, op in enumerate(operations):
        if not isinstance(op, dict) or int(op.get("seq", -1)) != seq:
            raise HotPatchError("non-contiguous operation sequence")
    return envelope


def export_matrix_bundle(
    model: MatrixG1G2DeltaModel,
    plan: Sequence[Tuple[int, int, int]],
    provenance: Mapping[str, object] | None = None,
) -> bytes:
    base = _clone_matrix(model)
    base_state_sha = sha256_bytes(base.rebuild_bytes())
    target = _clone_matrix(model)
    operations: List[Dict[str, int]] = []
    for seq, raw in enumerate(plan):
        row, col, after = (int(raw[0]), int(raw[1]), int(raw[2]) & 1)
        if row < 0 or col < 0 or row >= target.n or col >= target.n:
            raise HotPatchError("matrix operation outside model bounds")
        before = int(target.query(row, col)["value"])
        target.apply_patch(row, col, after)
        operations.append({
            "seq": seq,
            "row": row,
            "col": col,
            "key": target.key(row, col),
            "before": before,
            "after": after,
        })
    target_state_sha = sha256_bytes(target.rebuild_bytes())
    content = {
        "schema": 1,
        "kind": "MATRIX",
        "model": {"n": int(model.n)},
        "base_state_sha256": base_state_sha,
        "target_state_sha256": target_state_sha,
        "operations": operations,
    }
    return _build_envelope(content, provenance)


def export_prefix_bundle(
    model: PrefixFamilyG1G2DeltaModel,
    plan: Sequence[Tuple[int, str]],
    provenance: Mapping[str, object] | None = None,
) -> bytes:
    base = _clone_prefix(model)
    base_state_sha = sha256_bytes(base.rebuild_bytes())
    target = _clone_prefix(model)
    operations: List[Dict[str, object]] = []
    for seq, raw in enumerate(plan):
        idx, after = int(raw[0]), str(raw[1])
        if idx < 0 or idx >= target.count:
            raise HotPatchError("prefix operation outside model bounds")
        before = str(target.query(idx)["value"])
        target.apply_patch(idx, after)
        operations.append({
            "seq": seq,
            "idx": idx,
            "before_sha256": sha256_bytes(before.encode("utf-8")),
            "before": before,
            "after": after,
        })
    target_state_sha = sha256_bytes(target.rebuild_bytes())
    content = {
        "schema": 1,
        "kind": "PREFIX",
        "model": {"count": int(model.count), "prefix": str(model.prefix)},
        "base_state_sha256": base_state_sha,
        "target_state_sha256": target_state_sha,
        "operations": operations,
    }
    return _build_envelope(content, provenance)


def apply_matrix_bundle_hot(
    model: MatrixG1G2DeltaModel,
    bundle: bytes,
    current_state_sha256: str,
) -> Tuple[MatrixG1G2DeltaModel, HotPatchReceipt]:
    envelope = parse_bundle(bundle)
    content = envelope["content"]
    if content["kind"] != "MATRIX":
        raise HotPatchError("matrix importer received non-matrix bundle")
    if int(content["model"]["n"]) != int(model.n):
        raise HotPatchError("matrix model identity mismatch")
    if str(content["base_state_sha256"]) != str(current_state_sha256):
        raise HotPatchError("base state hash mismatch")

    target = _clone_matrix(model)
    rebuild_before = target.rebuild_count
    for raw in content["operations"]:
        row, col = int(raw["row"]), int(raw["col"])
        if row < 0 or col < 0 or row >= target.n or col >= target.n:
            raise HotPatchError("matrix operation outside model bounds")
        if int(raw["key"]) != target.key(row, col):
            raise HotPatchError("matrix key mismatch")
        current = int(target.query(row, col)["value"])
        if current != int(raw["before"]):
            raise HotPatchError("matrix optimistic before-value mismatch")
        target.apply_patch(row, col, int(raw["after"]))
    rebuild_after = target.rebuild_count

    receipt = HotPatchReceipt(
        kind="MATRIX",
        operation_count=len(content["operations"]),
        content_sha256=str(envelope["content_sha256"]),
        base_state_sha256=str(content["base_state_sha256"]),
        target_state_sha256_expected=str(content["target_state_sha256"]),
        hot_apply_full_rebuild_count=rebuild_after - rebuild_before,
        verification_deferred_to_explicit_gate=True,
    )
    return target, receipt


def apply_prefix_bundle_hot(
    model: PrefixFamilyG1G2DeltaModel,
    bundle: bytes,
    current_state_sha256: str,
) -> Tuple[PrefixFamilyG1G2DeltaModel, HotPatchReceipt]:
    envelope = parse_bundle(bundle)
    content = envelope["content"]
    if content["kind"] != "PREFIX":
        raise HotPatchError("prefix importer received non-prefix bundle")
    identity = content["model"]
    if int(identity["count"]) != int(model.count) or str(identity["prefix"]) != str(model.prefix):
        raise HotPatchError("prefix model identity mismatch")
    if str(content["base_state_sha256"]) != str(current_state_sha256):
        raise HotPatchError("base state hash mismatch")

    target = _clone_prefix(model)
    rebuild_before = target.rebuild_count
    for raw in content["operations"]:
        idx = int(raw["idx"])
        if idx < 0 or idx >= target.count:
            raise HotPatchError("prefix operation outside model bounds")
        current = str(target.query(idx)["value"])
        if sha256_bytes(current.encode("utf-8")) != str(raw["before_sha256"]):
            raise HotPatchError("prefix optimistic before-value mismatch")
        if current != str(raw["before"]):
            raise HotPatchError("prefix canonical before-value mismatch")
        target.apply_patch(idx, str(raw["after"]))
    rebuild_after = target.rebuild_count

    receipt = HotPatchReceipt(
        kind="PREFIX",
        operation_count=len(content["operations"]),
        content_sha256=str(envelope["content_sha256"]),
        base_state_sha256=str(content["base_state_sha256"]),
        target_state_sha256_expected=str(content["target_state_sha256"]),
        hot_apply_full_rebuild_count=rebuild_after - rebuild_before,
        verification_deferred_to_explicit_gate=True,
    )
    return target, receipt


def build_inverse_bundle(bundle: bytes, provenance: Mapping[str, object] | None = None) -> bytes:
    envelope = parse_bundle(bundle)
    content = envelope["content"]
    inverse_ops: List[Dict[str, object]] = []
    for seq, raw in enumerate(reversed(content["operations"])):
        if content["kind"] == "MATRIX":
            inverse_ops.append({
                "seq": seq,
                "row": int(raw["row"]),
                "col": int(raw["col"]),
                "key": int(raw["key"]),
                "before": int(raw["after"]),
                "after": int(raw["before"]),
            })
        else:
            inverse_ops.append({
                "seq": seq,
                "idx": int(raw["idx"]),
                "before_sha256": sha256_bytes(str(raw["after"]).encode("utf-8")),
                "before": str(raw["after"]),
                "after": str(raw["before"]),
            })
    inverse_content = {
        "schema": 1,
        "kind": content["kind"],
        "model": content["model"],
        "base_state_sha256": content["target_state_sha256"],
        "target_state_sha256": content["base_state_sha256"],
        "operations": inverse_ops,
    }
    return _build_envelope(inverse_content, provenance)


def tamper_bundle_after_value(bundle: bytes) -> bytes:
    """Test helper: changes content without updating content_sha256."""
    envelope = json.loads(bundle.decode("utf-8"))
    op = envelope["content"]["operations"][0]
    if envelope["content"]["kind"] == "MATRIX":
        op["after"] = 1 - int(op["after"])
    else:
        op["after"] = str(op["after"]) + "TAMPER"
    return canon(envelope)
