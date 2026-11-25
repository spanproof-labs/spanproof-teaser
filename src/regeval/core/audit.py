# SPDX-FileCopyrightText: 2026 SpanProof Labs
# SPDX-License-Identifier: MIT
"""
SpanProof RegEval — Enterprise Audit Vault

Generates cryptographic receipts for every evaluation. Each receipt carries an
HMAC-SHA-256 signature over the deterministic JSON serialisation of the
evaluation data, providing a verifiable audit trail.

A receipt records that a specific AI output was evaluated against a specific
regulation at a specific time with a specific result.

WHY HMAC AND NOT A BARE SHA-256 DIGEST. An earlier version of this module
published a plain `sha256_signature` and called the receipt tamper-evident. It
was not. Every input to that digest travels inside the receipt, so anyone
holding a receipt could edit the verdict, recompute the digest and produce a
document that verifies perfectly. A bare hash over public data detects
corruption, never forgery. The keyed construction is what makes the claim true.

WHAT "TAMPER-EVIDENT" REQUIRES, STATED HONESTLY. The guarantee holds only when
SPANPROOF_RECEIPT_KEY is set to a secret the verifier controls. Absent it this
module falls back to a published development key, which restores the original
weakness in full — anyone reading this source can forge a receipt. So the
receipt now RECORDS WHICH MODE IT WAS SIGNED UNDER, inside the signed payload,
and `receipt_is_tamper_evident()` reports it. A receipt signed under the
development key is a useful record; it is not evidence, and it must never be
presented as evidence. The instrument does not overstate its own guarantee.

CRITICAL: Uses ONLY Python standard library. Zero external dependencies.
"""
# SPDX-License-Identifier: MIT
import hashlib
import hmac
import json
import uuid
import os
from datetime import datetime, timezone


SIGNATURE_FIELD = "hmac_sha256_signature"
SIGNATURE_ALGORITHM = "HMAC-SHA256"

# The published fallback. Named so that nothing about it reads as a secret, and
# so that a receipt signed under it is self-evidently not evidence.
_INSECURE_DEFAULT_KEY = "dev_default_key"
KEY_PROVENANCE_ENV = "environment"
KEY_PROVENANCE_INSECURE = "insecure_default"


def _signing_key() -> tuple[bytes, str]:
    """Return (key material, provenance label).

    Provenance is reported rather than inferred at verify time, because a
    verifier holding only the receipt cannot otherwise tell whether the
    signature means anything.
    """
    env_key = os.environ.get("SPANPROOF_RECEIPT_KEY")
    if env_key:
        return env_key.encode("utf-8"), KEY_PROVENANCE_ENV
    return _INSECURE_DEFAULT_KEY.encode("utf-8"), KEY_PROVENANCE_INSECURE


def receipt_is_tamper_evident(receipt: dict) -> bool:
    """True only if this receipt's signature is worth anything as evidence.

    A receipt signed under the published development key verifies perfectly and
    proves nothing, because the key is in this file. Callers presenting receipts
    to an auditor, a regulator or a court must gate on THIS, not on
    verify_receipt() alone.
    """
    return (isinstance(receipt, dict)
            and receipt.get("key_provenance") == KEY_PROVENANCE_ENV
            and verify_receipt(receipt))


def generate_cryptographic_receipt(
    expected: str,
    got: str,
    rule_type: str,
    config_name: str,
    passed: bool,
    explanation: str,
    latency_ms: float,
) -> dict:
    """
    Generate a tamper-evident cryptographic receipt for an evaluation.

    The receipt contains all evaluation inputs and outputs, a UUID-4
    receipt ID, an ISO 8601 UTC timestamp, and a SHA-256 signature
    computed over the sorted, deterministic JSON serialization of the
    evaluation data.

    Args:
        expected: The ground-truth regulatory value.
        got: The LLM's raw generation that was evaluated.
        rule_type: The evaluation rule type (numeric, boolean, etc.).
        config_name: The regulatory domain config used.
        passed: Whether the evaluation passed.
        explanation: Human-readable explanation from the adjudicator.
        latency_ms: Wall-clock evaluation time in milliseconds.

    Returns:
        A dictionary containing the full receipt with SHA-256 signature.
    """
    receipt_id = str(uuid.uuid4())
    timestamp_utc = datetime.now(timezone.utc).isoformat()
    key_material, key_provenance = _signing_key()

    # Build the evaluation data payload (keys sorted for determinism).
    #
    # signature_algorithm and key_provenance live INSIDE the signed payload on
    # purpose. If they sat outside it, an attacker could downgrade a receipt by
    # relabelling it — claiming an environment-keyed signature over a payload
    # actually signed with the published development key. Signing them binds
    # the receipt to the strength of its own guarantee.
    eval_data = {
        "config_name": config_name,
        "engine_version": "regeval-1.0",
        "evaluation": {
            "expected": expected,
            "explanation": explanation,
            "got": got,
            "passed": passed,
            "rule_type": rule_type,
        },
        "key_provenance": key_provenance,
        "latency_ms": round(latency_ms, 4),
        "receipt_id": receipt_id,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "timestamp_utc": timestamp_utc,
    }

    # Compute HMAC-SHA-256 over the deterministic JSON serialization
    canonical_json = json.dumps(eval_data, sort_keys=True, separators=(",", ":"))
    hmac_signature = hmac.new(key_material, canonical_json.encode("utf-8"), hashlib.sha256).hexdigest()

    # Append the signature to the receipt (this field is NOT included
    # in the hash input — it is the hash output)
    eval_data[SIGNATURE_FIELD] = hmac_signature

    return eval_data


def verify_receipt(receipt: dict) -> bool:
    """
    Verify the integrity of a cryptographic receipt.

    Recomputes the SHA-256 signature from the receipt data and compares
    it to the stored signature. Returns True if the receipt has not been
    tampered with.

    Args:
        receipt: A receipt dictionary previously generated by
                 generate_cryptographic_receipt().

    Returns:
        True if the receipt is valid and untampered, False otherwise.
    """
    if not isinstance(receipt, dict) or SIGNATURE_FIELD not in receipt:
        return False

    stored_sig = receipt[SIGNATURE_FIELD]
    if not isinstance(stored_sig, str):
        return False

    # Reconstruct the eval_data without the signature
    eval_data = {k: v for k, v in receipt.items() if k != SIGNATURE_FIELD}

    # Verify under the key the RECEIPT declares, not under whatever this process
    # happens to have configured. A receipt signed on a machine with a real key
    # must not silently "verify" on a machine without one — that would let the
    # development key validate production receipts.
    if eval_data.get("key_provenance") == KEY_PROVENANCE_INSECURE:
        key_material = _INSECURE_DEFAULT_KEY.encode("utf-8")
    else:
        env_key = os.environ.get("SPANPROOF_RECEIPT_KEY")
        if not env_key:
            return False
        key_material = env_key.encode("utf-8")

    canonical_json = json.dumps(eval_data, sort_keys=True, separators=(",", ":"))
    recomputed_sig = hmac.new(key_material, canonical_json.encode("utf-8"), hashlib.sha256).hexdigest()

    return hmac.compare_digest(recomputed_sig, stored_sig)
