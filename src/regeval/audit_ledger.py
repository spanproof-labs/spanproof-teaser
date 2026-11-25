# SPDX-FileCopyrightText: 2026 SpanProof Labs
# SPDX-License-Identifier: MIT
"""SpanProof (regeval) — Tamper-Evident WORM Forensic Audit Receipt Ledger.

Pure Python stdlib implementation of an append-only, SHA-256 hash-chained
JSONL receipt ledger with deterministic canonical JSON hashing and optional
keyed HMAC-SHA-256 authentication.

Each line records one deterministic regulatory verification event chained to the
previous entry via ``prev_receipt_sha256`` (genesis ``"0" * 64``):

- ``prev_receipt_sha256``: 64-char hex hash of the preceding entry (or genesis)
- ``timestamp_utc``: ISO 8601 UTC timestamp
- ``input_claim_sha256``: SHA-256 digest of the candidate claim text
- ``item_id``: Regulatory item identifier
- ``cfr_citation``: Pinned CFR citation string
- ``corpus_item_sha256``: SHA-256 digest of the canonical corpus item record
- ``verdict``: Evaluation verdict (e.g. ``"PASS"`` / ``"FAIL"`` or bool)
- ``failure_reasons``: List of deterministic failure reason strings
- ``latency_ms``: Verification latency in milliseconds
- ``receipt_sha256``: Canonical SHA-256 digest over the entry payload
- ``hmac_key_id`` / ``hmac_sha256``: Optional keyed HMAC-SHA-256 fields

Zero external dependencies; zero network calls.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator, Mapping, Sequence

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX fallback
    fcntl = None  # type: ignore[assignment]

GENESIS_PREV_HASH: str = "0" * 64
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

REQUIRED_ENTRY_FIELDS: tuple[str, ...] = (
    "prev_receipt_sha256",
    "timestamp_utc",
    "input_claim_sha256",
    "item_id",
    "cfr_citation",
    "corpus_item_sha256",
    "verdict",
    "failure_reasons",
    "latency_ms",
    "receipt_sha256",
)


def canonical_json(obj: Any) -> str:
    """Serialize ``obj`` deterministically with sorted keys and compact separators."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(data: str | bytes) -> str:
    """Return the 64-character lowercase SHA-256 hex digest of ``data``."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def corpus_item_digest(item: Mapping[str, Any]) -> str:
    """Return the canonical SHA-256 hex digest for a corpus item dictionary."""
    return sha256_hex(canonical_json(dict(item)))


def _coerce_hmac_key(hmac_key: bytes | str) -> bytes:
    key_bytes = hmac_key.encode("utf-8") if isinstance(hmac_key, str) else bytes(hmac_key)
    if not key_bytes:
        raise ValueError("hmac_key must not be empty")
    return key_bytes


def compute_receipt_sha256(entry: Mapping[str, Any]) -> str:
    """Compute canonical SHA-256 over all receipt fields except hash/HMAC outputs."""
    payload = {
        k: v
        for k, v in entry.items()
        if k not in ("receipt_sha256", "hmac_sha256")
    }
    return sha256_hex(canonical_json(payload))


def compute_hmac_sha256(entry: Mapping[str, Any], hmac_key: bytes | str) -> str:
    """Compute keyed HMAC-SHA-256 over the full entry (including ``receipt_sha256``)."""
    key_bytes = _coerce_hmac_key(hmac_key)
    payload = {k: v for k, v in entry.items() if k != "hmac_sha256"}
    return hmac.new(key_bytes, canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()


@contextmanager
def _exclusive_file_lock(fh: Any) -> Iterator[None]:
    if fcntl is not None:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
    try:
        yield
    finally:
        if fcntl is not None:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def _validate_hex64(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not HEX64_RE.match(value):
        raise ValueError(f"{field_name} must be a 64-character lowercase hex SHA-256 string")
    return value


def _read_prev_hash_locked(raw_bytes: bytes) -> tuple[str, bool]:
    """Extract ``receipt_sha256`` from the final entry of an open ledger file.

    Returns ``(prev_receipt_sha256, needs_leading_newline)``.
    """
    if not raw_bytes:
        return GENESIS_PREV_HASH, False

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Existing ledger contains invalid UTF-8 bytes: {exc}") from exc

    lines = text.splitlines()
    if not lines:
        return GENESIS_PREV_HASH, False

    last_line = lines[-1]
    if not last_line.strip():
        raise ValueError("Existing ledger ends with a blank line; refusing to append onto corrupted chain")

    try:
        last_entry = json.loads(last_line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Existing ledger last line is malformed JSON: {exc}") from exc

    if not isinstance(last_entry, dict):
        raise ValueError("Existing ledger last line must be a JSON object")

    prev_hash = _validate_hex64(last_entry.get("receipt_sha256"), "last entry receipt_sha256")
    needs_leading_newline = not raw_bytes.endswith(b"\n")
    return prev_hash, needs_leading_newline


def append_receipt(
    ledger_path: str | os.PathLike[str],
    item_id: str,
    cfr_citation: str,
    verdict: Any,
    failure_reasons: Sequence[str] | None = None,
    latency_ms: float = 0.0,
    input_claim: str | None = None,
    input_claim_sha256: str | None = None,
    corpus_item: Mapping[str, Any] | None = None,
    corpus_item_sha256: str | None = None,
    timestamp_utc: str | None = None,
    hmac_key: bytes | str | None = None,
    hmac_key_id: str | None = None,
) -> dict[str, Any]:
    """Append one hash-chained audit receipt to ``ledger_path`` and return the entry."""
    if not isinstance(item_id, str) or not item_id.strip():
        raise ValueError("item_id must be a non-empty string")
    if not isinstance(cfr_citation, str):
        raise ValueError("cfr_citation must be a string")
    if verdict is None:
        raise ValueError("verdict must not be None")
    if isinstance(latency_ms, bool) or not isinstance(latency_ms, (int, float)):
        raise ValueError("latency_ms must be a numeric value")

    if input_claim_sha256 is not None:
        claim_hash = _validate_hex64(input_claim_sha256, "input_claim_sha256")
    elif isinstance(input_claim, str):
        claim_hash = sha256_hex(input_claim)
    else:
        raise ValueError("Either input_claim or input_claim_sha256 must be provided")

    if corpus_item_sha256 is not None:
        item_hash = _validate_hex64(corpus_item_sha256, "corpus_item_sha256")
    elif isinstance(corpus_item, Mapping):
        item_hash = corpus_item_digest(corpus_item)
    else:
        raise ValueError("Either corpus_item or corpus_item_sha256 must be provided")

    if timestamp_utc is None:
        ts = datetime.now(timezone.utc).isoformat()
    elif isinstance(timestamp_utc, str) and timestamp_utc.strip():
        ts = timestamp_utc
    else:
        raise ValueError("timestamp_utc must be a non-empty ISO 8601 string")

    reasons_list = [str(r) for r in (failure_reasons or ())]
    if hmac_key is not None:
        _coerce_hmac_key(hmac_key)

    path_str = os.fspath(ledger_path)
    parent = os.path.dirname(os.path.abspath(path_str))
    if parent:
        os.makedirs(parent, exist_ok=True)

    with open(path_str, "a+b") as fh:
        with _exclusive_file_lock(fh):
            fh.seek(0)
            raw_bytes = fh.read()
            prev_hash, needs_newline = _read_prev_hash_locked(raw_bytes)

            entry: dict[str, Any] = {
                "prev_receipt_sha256": prev_hash,
                "timestamp_utc": ts,
                "input_claim_sha256": claim_hash,
                "item_id": item_id,
                "cfr_citation": cfr_citation,
                "corpus_item_sha256": item_hash,
                "verdict": verdict,
                "failure_reasons": reasons_list,
                "latency_ms": round(float(latency_ms), 6),
            }
            if hmac_key is not None:
                entry["hmac_key_id"] = str(hmac_key_id) if hmac_key_id else "default"

            entry["receipt_sha256"] = compute_receipt_sha256(entry)
            if hmac_key is not None:
                entry["hmac_sha256"] = compute_hmac_sha256(entry, hmac_key)

            line_bytes = canonical_json(entry).encode("utf-8") + b"\n"
            fh.seek(0, os.SEEK_END)
            if needs_newline:
                fh.write(b"\n")
            fh.write(line_bytes)
            fh.flush()
            os.fsync(fh.fileno())

    return entry


def _failure_result(
    entries_checked: int,
    broken_at_index: int | None,
    head_receipt_sha256: str | None,
    reason: str,
) -> dict[str, Any]:
    return {
        "valid": False,
        "entries_checked": entries_checked,
        "broken_at_index": broken_at_index,
        "head_receipt_sha256": head_receipt_sha256,
        "hmac_verified": False,
        "reason": reason,
    }


def verify_ledger_integrity(
    ledger_path: str | os.PathLike[str],
    hmac_key: bytes | str | None = None,
) -> dict[str, Any]:
    """Verify hash-chain, canonical digests, and optional HMAC across a JSONL ledger."""
    path_str = os.fspath(ledger_path)
    if not os.path.exists(path_str):
        return _failure_result(0, None, None, "ledger file does not exist")

    if hmac_key is not None:
        _coerce_hmac_key(hmac_key)

    with open(path_str, "rb") as fh:
        raw_bytes = fh.read()

    if not raw_bytes:
        return {
            "valid": True,
            "entries_checked": 0,
            "broken_at_index": None,
            "head_receipt_sha256": GENESIS_PREV_HASH,
            "hmac_verified": hmac_key is not None,
            "reason": None,
        }

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        approx_idx = raw_bytes[: exc.start].count(b"\n")
        return _failure_result(
            approx_idx + 1,
            approx_idx,
            None,
            f"invalid UTF-8 bytes at index {approx_idx}: {exc}",
        )

    lines = text.splitlines()
    expected_prev = GENESIS_PREV_HASH
    last_valid_head: str | None = None

    for idx, line in enumerate(lines):
        checked = idx + 1
        if not line.strip():
            return _failure_result(
                checked, idx, last_valid_head, f"empty or blank JSONL line at index {idx}"
            )

        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            return _failure_result(
                checked, idx, last_valid_head, f"malformed JSON at index {idx}: {exc}"
            )

        if not isinstance(entry, dict):
            return _failure_result(
                checked, idx, last_valid_head, f"entry at index {idx} is not a JSON object"
            )

        missing = [field for field in REQUIRED_ENTRY_FIELDS if field not in entry]
        if missing:
            return _failure_result(
                checked,
                idx,
                last_valid_head,
                f"missing required fields at index {idx}: {', '.join(missing)}",
            )

        for hex_field in (
            "prev_receipt_sha256",
            "input_claim_sha256",
            "corpus_item_sha256",
            "receipt_sha256",
        ):
            val = entry.get(hex_field)
            if not isinstance(val, str) or not HEX64_RE.match(val):
                return _failure_result(
                    checked,
                    idx,
                    last_valid_head,
                    f"invalid SHA-256 hex in '{hex_field}' at index {idx}",
                )

        if (
            not isinstance(entry["timestamp_utc"], str)
            or not entry["timestamp_utc"].strip()
            or not isinstance(entry["item_id"], str)
            or not entry["item_id"].strip()
            or not isinstance(entry["cfr_citation"], str)
            or not isinstance(entry["failure_reasons"], list)
            or isinstance(entry["latency_ms"], bool)
            or not isinstance(entry["latency_ms"], (int, float))
        ):
            return _failure_result(
                checked, idx, last_valid_head, f"invalid field types at index {idx}"
            )

        if entry["prev_receipt_sha256"] != expected_prev:
            return _failure_result(
                checked,
                idx,
                last_valid_head,
                (
                    f"prev_receipt_sha256 mismatch at index {idx}: "
                    f"expected {expected_prev}, got {entry['prev_receipt_sha256']}"
                ),
            )

        expected_receipt_hash = compute_receipt_sha256(entry)
        if not hmac.compare_digest(expected_receipt_hash, entry["receipt_sha256"]):
            return _failure_result(
                checked,
                idx,
                last_valid_head,
                f"receipt_sha256 mismatch at index {idx}",
            )

        if hmac_key is not None:
            sig = entry.get("hmac_sha256")
            if not isinstance(sig, str) or not HEX64_RE.match(sig):
                return _failure_result(
                    checked,
                    idx,
                    last_valid_head,
                    f"missing or malformed hmac_sha256 at index {idx}",
                )
            expected_hmac = compute_hmac_sha256(entry, hmac_key)
            if not hmac.compare_digest(expected_hmac, sig):
                return _failure_result(
                    checked,
                    idx,
                    last_valid_head,
                    f"hmac_sha256 mismatch at index {idx}",
                )

        expected_prev = entry["receipt_sha256"]
        last_valid_head = expected_prev

    return {
        "valid": True,
        "entries_checked": len(lines),
        "broken_at_index": None,
        "head_receipt_sha256": expected_prev,
        "hmac_verified": hmac_key is not None,
        "reason": None,
    }
