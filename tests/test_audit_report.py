#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SpanProof Contributors
# SPDX-License-Identifier: MIT
"""Tests for regeval.audit_report and demo_guardrail_proof.py --sample-certificate."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from regeval.audit_ledger import GENESIS_PREV_HASH, append_receipt  # noqa: E402
from regeval.audit_report import (  # noqa: E402
    CERTIFICATE_HTML_FILENAME,
    CERTIFICATE_MD_FILENAME,
    generate_certificate_from_batch,
    generate_certificate_from_ledger,
)


class TestTeaserAuditReport(unittest.TestCase):
    """Verify COSO/ICFR/QMSR certificate generation against teaser_items.json."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.teaser_items_path = REPO_ROOT / "teaser_items.json"

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_mode_b_teaser_batch_to_ledger_and_certificates(self) -> None:
        batch_path = self.tmp / "teaser_pairs.jsonl"
        pairs = [
            {"item_id": "GT-K-DFARS-000010", "model_output": "$174,000."},
            {"item_id": "GT-K-DFARS-000010", "model_output": "$250,000."},
            {"item_id": "SP-21CFR-820-35-QMSR", "model_output": "Yes, per 21 CFR 820.35."},
            {
                "item_id": "SP-21CFR-820-35-QMSR",
                "model_output": "No, internal and supplier quality audit reports remain exempt under 21 CFR 820.180(c).",
            },
            {"item_id": "SP-17CFR-206-4-1", "model_output": "No, per 17 CFR 275.206(4)-1."},
            {"item_id": "SP-47CFR-64-1200-A10", "model_output": "30 calendar days"},
        ]
        batch_path.write_text("\n".join(json.dumps(p) for p in pairs) + "\n", encoding="utf-8")

        out_dir = self.tmp / "cert_out"
        ledger_out = self.tmp / "teaser_ledger.jsonl"
        result = generate_certificate_from_batch(
            batch_path=batch_path,
            items_path=self.teaser_items_path,
            out_dir=out_dir,
            ledger_out=ledger_out,
            hmac_key="teaser-test-hmac",
            hmac_key_id="teaser-k1",
        )
        rep = result["report"]
        self.assertEqual(rep["chain_of_custody"]["verdict"], "VALID")
        self.assertTrue(rep["chain_of_custody"]["valid"])
        self.assertEqual(rep["chain_of_custody"]["entries_checked"], 6)
        self.assertEqual(rep["chain_of_custody"]["root_prev_receipt_sha256"], GENESIS_PREV_HASH)
        self.assertEqual(rep["summary"]["total_entries"], 6)
        self.assertEqual(rep["summary"]["passed"], 3)
        self.assertEqual(rep["summary"]["caught"], 3)
        self.assertGreaterEqual(rep["latency_ms"]["p95_ms"], rep["latency_ms"]["avg_ms"])
        self.assertGreaterEqual(rep["latency_ms"]["max_ms"], rep["latency_ms"]["p95_ms"])

        html_text = Path(result["html_path"]).read_text(encoding="utf-8")
        md_text = Path(result["md_path"]).read_text(encoding="utf-8")
        self.assertIn("COSO ICIF", html_text)
        self.assertIn("QMSR", html_text)
        self.assertIn("SP-21CFR-820-35-QMSR", html_text)
        self.assertIn("SP-47CFR-64-1200-A10", md_text)
        self.assertNotIn("https://", html_text)
        self.assertNotIn("http://", html_text)

    def test_mode_a_valid_and_tampered_ledger(self) -> None:
        ledger_path = self.tmp / "ledger.jsonl"
        item = {"item_id": "SP-21CFR-820-35-QMSR", "citation_canonical": "21 CFR 820.35"}
        append_receipt(
            ledger_path,
            item_id="SP-21CFR-820-35-QMSR",
            cfr_citation="21 CFR 820.35",
            verdict="PASS",
            failure_reasons=[],
            latency_ms=1.1,
            input_claim="Yes, per 21 CFR 820.35.",
            corpus_item=item,
        )
        append_receipt(
            ledger_path,
            item_id="SP-21CFR-820-35-QMSR",
            cfr_citation="21 CFR 820.35",
            verdict="FAIL",
            failure_reasons=["QMSR trap caught"],
            latency_ms=1.3,
            input_claim="No, exempt under 820.180(c).",
            corpus_item=item,
        )

        valid_res = generate_certificate_from_ledger(ledger_path, out_dir=self.tmp / "ok")
        self.assertEqual(valid_res["report"]["chain_of_custody"]["verdict"], "VALID")

        lines = ledger_path.read_text(encoding="utf-8").splitlines()
        lines[0] = lines[0].replace('"verdict":"PASS"', '"verdict":"FAIL"', 1)
        tampered = self.tmp / "tampered.jsonl"
        tampered.write_text("\n".join(lines) + "\n", encoding="utf-8")

        tamper_res = generate_certificate_from_ledger(tampered, out_dir=self.tmp / "bad")
        self.assertEqual(tamper_res["report"]["chain_of_custody"]["verdict"], "TAMPER_DETECTED")
        self.assertEqual(tamper_res["report"]["chain_of_custody"]["broken_at_index"], 0)
        self.assertIn("TAMPER_DETECTED", Path(tamper_res["html_path"]).read_text(encoding="utf-8"))

    def test_html_xss_escaping(self) -> None:
        ledger_path = self.tmp / "xss.jsonl"
        append_receipt(
            ledger_path,
            item_id='<script>alert("id")</script>',
            cfr_citation='48 CFR 25.402"><img src=x onerror=alert(2)>',
            verdict="FAIL",
            failure_reasons=['<script>alert("reason")</script>'],
            latency_ms=0.5,
            input_claim="bad",
            corpus_item={"item_id": "x"},
        )
        res = generate_certificate_from_ledger(ledger_path, out_dir=self.tmp / "xss")
        html_text = Path(res["html_path"]).read_text(encoding="utf-8")
        self.assertNotIn("<script>", html_text)
        self.assertNotIn("<img ", html_text)
        self.assertIn("&lt;script&gt;", html_text)

    def test_demo_sample_certificate_flag_without_breaking_default(self) -> None:
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        default_proc = subprocess.run(
            [sys.executable, "demo_guardrail_proof.py"],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(default_proc.returncode, 0, msg=default_proc.stderr)
        self.assertIn("Valid Grounded Pass Rate : 11/11 (100.0%)", default_proc.stdout)
        self.assertIn("Corruption Catch Rate    : 11/11 (100.0%)", default_proc.stdout)

        cert_dir = self.tmp / "demo_certs"
        cert_proc = subprocess.run(
            [sys.executable, "demo_guardrail_proof.py", "--sample-certificate", str(cert_dir)],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(cert_proc.returncode, 0, msg=cert_proc.stderr)
        html_p = cert_dir / CERTIFICATE_HTML_FILENAME
        md_p = cert_dir / CERTIFICATE_MD_FILENAME
        self.assertTrue(html_p.is_file())
        self.assertTrue(md_p.is_file())
        html_text = html_p.read_text(encoding="utf-8")
        self.assertIn("VALID", html_text)
        self.assertIn("SP-21CFR-820-35-QMSR", html_text)


if __name__ == "__main__":
    unittest.main()
