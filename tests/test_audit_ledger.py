#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SpanProof Labs
# SPDX-License-Identifier: MIT
"""Unit tests for regeval.audit_ledger (Tamper-Evident WORM JSONL Ledger)."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from regeval.audit_ledger import (  # noqa: E402
    GENESIS_PREV_HASH,
    REQUIRED_ENTRY_FIELDS,
    append_receipt,
    compute_receipt_sha256,
    corpus_item_digest,
    sha256_hex,
    verify_ledger_integrity,
)


SAMPLE_ITEM_1 = {
    "item_id": "GT-K-DFARS-000010",
    "citation_canonical": "48 CFR 25.402",
    "answer_canonical": {"value": 174000, "unit": "USD"},
}
SAMPLE_ITEM_2 = {
    "item_id": "SP-17CFR-206-4-1",
    "citation_canonical": "17 CFR 275.206(4)-1",
    "answer_canonical": {"determination": "no"},
}
SAMPLE_ITEM_3 = {
    "item_id": "SP-47CFR-64-1200-A10",
    "citation_canonical": "47 CFR 64.1200(a)(10)",
    "answer_canonical": {"value": 10, "unit": "business days"},
}


class TestAuditLedger(unittest.TestCase):
    """Verify hash chaining, canonical digests, HMAC, and tamper detection."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.ledger_path = os.path.join(self._tmpdir.name, "audit_ledger.jsonl")

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _populate_three_entries(self, hmac_key: str | None = None) -> list[dict]:
        r0 = append_receipt(
            self.ledger_path,
            item_id=SAMPLE_ITEM_1["item_id"],
            cfr_citation=SAMPLE_ITEM_1["citation_canonical"],
            verdict="PASS",
            failure_reasons=[],
            latency_ms=1.12,
            input_claim="$174,000.",
            corpus_item=SAMPLE_ITEM_1,
            timestamp_utc="2026-11-24T19:00:00+00:00",
            hmac_key=hmac_key,
            hmac_key_id="k1" if hmac_key else None,
        )
        r1 = append_receipt(
            self.ledger_path,
            item_id=SAMPLE_ITEM_2["item_id"],
            cfr_citation=SAMPLE_ITEM_2["citation_canonical"],
            verdict="FAIL",
            failure_reasons=["Gross-only 5-yr ad prohibited under 17 CFR 275.206(4)-1"],
            latency_ms=1.45,
            input_claim="Yes, gross performance alone is allowed.",
            corpus_item=SAMPLE_ITEM_2,
            timestamp_utc="2026-11-24T19:00:01+00:00",
            hmac_key=hmac_key,
            hmac_key_id="k1" if hmac_key else None,
        )
        r2 = append_receipt(
            self.ledger_path,
            item_id=SAMPLE_ITEM_3["item_id"],
            cfr_citation=SAMPLE_ITEM_3["citation_canonical"],
            verdict="PASS",
            failure_reasons=[],
            latency_ms=0.98,
            input_claim="10 business days",
            corpus_item=SAMPLE_ITEM_3,
            timestamp_utc="2026-11-24T19:00:02+00:00",
            hmac_key=hmac_key,
            hmac_key_id="k1" if hmac_key else None,
        )
        return [r0, r1, r2]

    def test_missing_and_empty_ledger(self) -> None:
        missing = verify_ledger_integrity(self.ledger_path)
        self.assertIs(missing["valid"], False)
        self.assertEqual(missing["entries_checked"], 0)
        self.assertIsNone(missing["broken_at_index"])

        with open(self.ledger_path, "wb"):
            pass
        empty = verify_ledger_integrity(self.ledger_path)
        self.assertIs(empty["valid"], True)
        self.assertEqual(empty["entries_checked"], 0)
        self.assertIsNone(empty["broken_at_index"])
        self.assertEqual(empty["head_receipt_sha256"], GENESIS_PREV_HASH)

    def test_multi_entry_chain_and_required_fields(self) -> None:
        receipts = self._populate_three_entries()
        self.assertEqual(receipts[0]["prev_receipt_sha256"], GENESIS_PREV_HASH)
        self.assertEqual(receipts[1]["prev_receipt_sha256"], receipts[0]["receipt_sha256"])
        self.assertEqual(receipts[2]["prev_receipt_sha256"], receipts[1]["receipt_sha256"])

        for idx, rec in enumerate(receipts):
            missing = [f for f in REQUIRED_ENTRY_FIELDS if f not in rec]
            self.assertEqual(missing, [], f"Entry {idx} missing fields: {missing}")
            self.assertEqual(rec["receipt_sha256"], compute_receipt_sha256(rec))

        self.assertEqual(receipts[0]["input_claim_sha256"], sha256_hex("$174,000."))
        self.assertEqual(receipts[0]["corpus_item_sha256"], corpus_item_digest(SAMPLE_ITEM_1))

        status = verify_ledger_integrity(self.ledger_path)
        self.assertIs(status["valid"], True)
        self.assertEqual(status["entries_checked"], 3)
        self.assertIsNone(status["broken_at_index"])
        self.assertEqual(status["head_receipt_sha256"], receipts[2]["receipt_sha256"])
        self.assertIs(status["hmac_verified"], False)

    def test_single_byte_tampering_detected_at_exact_index(self) -> None:
        self._populate_three_entries()
        with open(self.ledger_path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()

        # Flip 1 byte in entry 1 ("FAIL" -> "FAIl")
        tampered_lines = list(lines)
        self.assertIn('"verdict":"FAIL"', tampered_lines[1])
        tampered_lines[1] = tampered_lines[1].replace('"verdict":"FAIL"', '"verdict":"FAIl"', 1)
        with open(self.ledger_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(tampered_lines) + "\n")

        res = verify_ledger_integrity(self.ledger_path)
        self.assertIs(res["valid"], False)
        self.assertEqual(res["broken_at_index"], 1)
        self.assertIn("receipt_sha256 mismatch", res["reason"])

        # Flip 1 byte in entry 0 receipt_sha256 without updating entry 1 prev_receipt_sha256
        lines0 = list(lines)
        parsed0 = json.loads(lines0[0])
        h = parsed0["receipt_sha256"]
        flipped = ("0" if h[0] != "0" else "1") + h[1:]
        lines0[0] = lines0[0].replace(h, flipped, 1)
        with open(self.ledger_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines0) + "\n")

        res0 = verify_ledger_integrity(self.ledger_path)
        self.assertIs(res0["valid"], False)
        self.assertEqual(res0["broken_at_index"], 0)

    def test_intermediate_and_genesis_line_deletion_and_reorder(self) -> None:
        self._populate_three_entries()
        with open(self.ledger_path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()

        # Delete intermediate line (index 1) -> remaining index 1 has broken prev_receipt_sha256
        del_mid = os.path.join(self._tmpdir.name, "del_mid.jsonl")
        with open(del_mid, "w", encoding="utf-8") as fh:
            fh.write("\n".join([lines[0], lines[2]]) + "\n")
        res_mid = verify_ledger_integrity(del_mid)
        self.assertIs(res_mid["valid"], False)
        self.assertEqual(res_mid["broken_at_index"], 1)
        self.assertIn("prev_receipt_sha256 mismatch", res_mid["reason"])

        # Delete first line -> new index 0 has non-genesis prev_receipt_sha256
        del_first = os.path.join(self._tmpdir.name, "del_first.jsonl")
        with open(del_first, "w", encoding="utf-8") as fh:
            fh.write("\n".join([lines[1], lines[2]]) + "\n")
        res_first = verify_ledger_integrity(del_first)
        self.assertIs(res_first["valid"], False)
        self.assertEqual(res_first["broken_at_index"], 0)

        # Reorder lines 1 and 2
        reordered = os.path.join(self._tmpdir.name, "reordered.jsonl")
        with open(reordered, "w", encoding="utf-8") as fh:
            fh.write("\n".join([lines[0], lines[2], lines[1]]) + "\n")
        res_reord = verify_ledger_integrity(reordered)
        self.assertIs(res_reord["valid"], False)
        self.assertEqual(res_reord["broken_at_index"], 1)

    def test_malformed_json_blank_line_and_bad_utf8(self) -> None:
        self._populate_three_entries()
        with open(self.ledger_path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()

        # Truncate JSON on index 2
        malformed = os.path.join(self._tmpdir.name, "malformed.jsonl")
        with open(malformed, "w", encoding="utf-8") as fh:
            fh.write("\n".join([lines[0], lines[1], lines[2][:-5]]) + "\n")
        res_mal = verify_ledger_integrity(malformed)
        self.assertIs(res_mal["valid"], False)
        self.assertEqual(res_mal["broken_at_index"], 2)
        self.assertIn("malformed JSON", res_mal["reason"])

        # Blank line inserted at index 1
        blank = os.path.join(self._tmpdir.name, "blank.jsonl")
        with open(blank, "w", encoding="utf-8") as fh:
            fh.write("\n".join([lines[0], "", lines[1]]) + "\n")
        res_blank = verify_ledger_integrity(blank)
        self.assertIs(res_blank["valid"], False)
        self.assertEqual(res_blank["broken_at_index"], 1)

        # Invalid UTF-8 byte on index 1
        bad_utf8 = os.path.join(self._tmpdir.name, "bad_utf8.jsonl")
        with open(bad_utf8, "wb") as fh:
            fh.write(lines[0].encode("utf-8") + b"\n" + b"\xff\xfe" + b"\n")
        res_utf8 = verify_ledger_integrity(bad_utf8)
        self.assertIs(res_utf8["valid"], False)
        self.assertEqual(res_utf8["broken_at_index"], 1)

    def test_hmac_signing_and_tamper_detection(self) -> None:
        secret = "practice-audit-secret-key-2026"
        receipts = self._populate_three_entries(hmac_key=secret)
        self.assertEqual(receipts[0]["hmac_key_id"], "k1")
        self.assertEqual(len(receipts[0]["hmac_sha256"]), 64)

        ok = verify_ledger_integrity(self.ledger_path, hmac_key=secret)
        self.assertIs(ok["valid"], True)
        self.assertIs(ok["hmac_verified"], True)
        self.assertEqual(ok["entries_checked"], 3)

        wrong_key = verify_ledger_integrity(self.ledger_path, hmac_key="wrong-key")
        self.assertIs(wrong_key["valid"], False)
        self.assertEqual(wrong_key["broken_at_index"], 0)
        self.assertIn("hmac_sha256 mismatch", wrong_key["reason"])

        # Tamper HMAC on index 2 only
        with open(self.ledger_path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        e2 = json.loads(lines[2])
        sig = e2["hmac_sha256"]
        e2["hmac_sha256"] = ("a" if sig[0] != "a" else "b") + sig[1:]
        lines[2] = json.dumps(e2, sort_keys=True, separators=(",", ":"))
        with open(self.ledger_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")

        bad_sig = verify_ledger_integrity(self.ledger_path, hmac_key=secret)
        self.assertIs(bad_sig["valid"], False)
        self.assertEqual(bad_sig["broken_at_index"], 2)
        self.assertIn("hmac_sha256 mismatch", bad_sig["reason"])

    def test_verify_performance_millisecond_scale(self) -> None:
        for i in range(50):
            append_receipt(
                self.ledger_path,
                item_id=f"SP-BENCH-{i:04d}",
                cfr_citation="48 CFR 25.402",
                verdict="PASS",
                failure_reasons=[],
                latency_ms=1.0,
                input_claim="$174,000.",
                corpus_item=SAMPLE_ITEM_1,
            )
        t0 = time.perf_counter()
        res = verify_ledger_integrity(self.ledger_path)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        self.assertIs(res["valid"], True)
        self.assertEqual(res["entries_checked"], 50)
        self.assertLess(elapsed_ms, 250.0)


if __name__ == "__main__":
    unittest.main()
