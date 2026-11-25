#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SpanProof Labs
# SPDX-License-Identifier: MIT
"""Stdio end-to-end tests for SpanProof (regeval) MCP server.

Pure Python stdlib; runnable directly or via `python3 -m unittest`.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from typing import Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(REPO_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from regeval.audit_ledger import GENESIS_PREV_HASH, verify_ledger_integrity  # noqa: E402

SERVER_PATH = os.path.join(REPO_ROOT, "mcp_server.py")
EXPECTED_SHA256 = "08d2034074cc804ca11b9455ee58d8a176e7806d78f7a92bb6b6f4cb1655ba15"


class TestMCPStdioServer(unittest.TestCase):
    """Spawn mcp_server.py over stdio and verify JSON-RPC 2.0 MCP contracts."""

    proc: subprocess.Popen[str]

    @classmethod
    def setUpClass(cls) -> None:
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        cls.proc = subprocess.Popen(
            [sys.executable, SERVER_PATH],
            cwd=REPO_ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        proc = cls.proc
        if proc.stdin and not proc.stdin.closed:
            proc.stdin.close()
        try:
            rc = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                rc = proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                rc = proc.wait(timeout=3)
        stderr_out = proc.stderr.read() if proc.stderr else ""
        if proc.stdout and not proc.stdout.closed:
            proc.stdout.close()
        if proc.stderr and not proc.stderr.closed:
            proc.stderr.close()
        if rc != 0:
            raise AssertionError(f"mcp_server.py exited with {rc}; stderr={stderr_out!r}")

    def _send(self, payload: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()

    def _recv(self) -> dict[str, Any]:
        assert self.proc.stdout is not None
        line = self.proc.stdout.readline()
        self.assertTrue(line, "Expected JSON-RPC response line from mcp_server.py stdout")
        return json.loads(line)

    def _rpc(self, req_id: int, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        req: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            req["params"] = params
        self._send(req)
        resp = self._recv()
        self.assertEqual(resp.get("id"), req_id)
        return resp

    def test_01_initialize_and_ping(self) -> None:
        init_resp = self._rpc(
            1,
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "spanproof-stdio-test", "version": "1.0.0"},
            },
        )
        result = init_resp["result"]
        self.assertIn("protocolVersion", result)
        self.assertEqual(result["capabilities"], {"tools": {}})
        self.assertEqual(
            result["serverInfo"],
            {"name": "spanproof-regeval", "version": "1.0.0"},
        )

        # Notification must not emit a stdout response; next ping gets id=2 cleanly.
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        ping_resp = self._rpc(2, "ping")
        self.assertEqual(ping_resp.get("result"), {})

    def test_02_tools_list(self) -> None:
        resp = self._rpc(3, "tools/list")
        tools = resp["result"]["tools"]
        names = {t["name"] for t in tools}
        self.assertEqual(
            names,
            {"verify_cfr_claim", "list_supported_cfr_domains", "verify_and_record_receipt"},
        )
        for tool in tools:
            self.assertIn("inputSchema", tool)

    def test_03_list_supported_cfr_domains(self) -> None:
        resp = self._rpc(
            4,
            "tools/call",
            {"name": "list_supported_cfr_domains", "arguments": {}},
        )
        result = resp["result"]
        self.assertFalse(result.get("isError", False))
        sc = result["structuredContent"]
        self.assertEqual(sc, json.loads(result["content"][0]["text"]))
        self.assertEqual(sc["teaser_total_items"], 325)
        self.assertEqual(sc["teaser_domain_count"], 9)
        self.assertEqual(sc["teaser_sha256"], EXPECTED_SHA256)
        titles = [d["cfr_title_number"] for d in sc["domains"]]
        self.assertEqual(titles, [10, 14, 15, 17, 21, 22, 47, 48, 49])
        self.assertEqual(sum(d["item_count"] for d in sc["domains"]), 325)
        counts = {d["cfr_title_number"]: d["item_count"] for d in sc["domains"]}
        self.assertEqual(
            counts,
            {10: 55, 14: 55, 15: 60, 17: 15, 21: 15, 22: 6, 47: 15, 48: 48, 49: 56},
        )
        comm = sc["commercial_snapshot"]
        self.assertEqual(comm["total_items"], 26485)
        self.assertEqual(comm["non_cloze_items"], 15530)
        self.assertEqual(comm["cloze_items"], 10955)
        self.assertEqual(comm["cfr_titles_count"], 11)
        self.assertEqual(comm["claimtruth_statutory_modules"], 41)

    def test_04_verify_valid_dfars_000010(self) -> None:
        resp = self._rpc(
            5,
            "tools/call",
            {
                "name": "verify_cfr_claim",
                "arguments": {"item_id": "GT-K-DFARS-000010", "text": "$174,000."},
            },
        )
        result = resp["result"]
        self.assertFalse(result.get("isError", False))
        sc = result["structuredContent"]
        self.assertEqual(sc, json.loads(result["content"][0]["text"]))
        self.assertIs(sc["passed"], True)
        self.assertLess(sc["latency_ms"], 25.0)
        self.assertEqual(sc["failure_reasons"], [])
        self.assertEqual(sc["required_citation"], "48 CFR 25.402")
        self.assertEqual(sc["item_id"], "GT-K-DFARS-000010")
        self.assertEqual(sc["cfr_title"], "48 CFR")

    def test_05_verify_corrupt_dfars_000010(self) -> None:
        resp = self._rpc(
            6,
            "tools/call",
            {
                "name": "verify_cfr_claim",
                "arguments": {"item_id": "GT-K-DFARS-000010", "text": "$250,000."},
            },
        )
        result = resp["result"]
        self.assertFalse(result.get("isError", False))
        sc = result["structuredContent"]
        self.assertIs(sc["passed"], False)
        self.assertLess(sc["latency_ms"], 25.0)
        self.assertGreater(len(sc["failure_reasons"]), 0)
        self.assertEqual(sc["required_citation"], "48 CFR 25.402")

    def test_06_verify_think_leak_dfars_000050(self) -> None:
        resp = self._rpc(
            7,
            "tools/call",
            {
                "name": "verify_cfr_claim",
                "arguments": {
                    "item_id": "GT-K-DFARS-000050",
                    "text": "<think>Checking 48 CFR 252.228-7006: $300,000.</think> $150,000.",
                },
            },
        )
        result = resp["result"]
        self.assertFalse(result.get("isError", False))
        sc = result["structuredContent"]
        self.assertIs(sc["passed"], False)
        self.assertGreater(len(sc["failure_reasons"]), 0)
        self.assertEqual(sc["required_citation"], "48 CFR 252.228-7006")

    def test_07_verify_unknown_item_and_invalid_args(self) -> None:
        unknown_resp = self._rpc(
            8,
            "tools/call",
            {
                "name": "verify_cfr_claim",
                "arguments": {"item_id": "GT-K-UNKNOWN-999999", "text": "$174,000."},
            },
        )
        self.assertIs(unknown_resp["result"].get("isError"), True)

        empty_resp = self._rpc(
            9,
            "tools/call",
            {
                "name": "verify_cfr_claim",
                "arguments": {"item_id": "GT-K-DFARS-000010", "text": "   "},
            },
        )
        self.assertIs(empty_resp["result"].get("isError"), True)

    def test_08_verify_17_21_47_cfr_valid_and_corrupt(self) -> None:
        cases = [
            (
                "SP-17CFR-206-4-1",
                "17 CFR",
                "17 CFR 275.206(4)-1",
                "No, per 17 CFR 275.206(4)-1.",
                "Yes, gross performance alone is permitted for 5-year advertisements per 17 CFR 275.206(4)-1.",
            ),
            (
                "SP-21CFR-820-35-QMSR",
                "21 CFR",
                "21 CFR 820.35",
                "Yes, per 21 CFR 820.35.",
                "No, internal and supplier quality audit reports remain exempt under 21 CFR 820.180(c).",
            ),
            (
                "SP-47CFR-64-1200-A10",
                "47 CFR",
                "47 CFR 64.1200(a)(10)",
                "10 business days",
                "30 calendar days",
            ),
        ]
        req_id = 10
        for item_id, cfr_title, req_cit, valid_txt, corrupt_txt in cases:
            ok_resp = self._rpc(
                req_id,
                "tools/call",
                {"name": "verify_cfr_claim", "arguments": {"item_id": item_id, "text": valid_txt}},
            )
            req_id += 1
            self.assertFalse(ok_resp["result"].get("isError", False))
            sc_ok = ok_resp["result"]["structuredContent"]
            self.assertIs(sc_ok["passed"], True, f"Expected pass for {item_id}: {sc_ok}")
            self.assertEqual(sc_ok["cfr_title"], cfr_title)
            self.assertEqual(sc_ok["required_citation"], req_cit)
            self.assertEqual(sc_ok["failure_reasons"], [])

            bad_resp = self._rpc(
                req_id,
                "tools/call",
                {"name": "verify_cfr_claim", "arguments": {"item_id": item_id, "text": corrupt_txt}},
            )
            req_id += 1
            self.assertFalse(bad_resp["result"].get("isError", False))
            sc_bad = bad_resp["result"]["structuredContent"]
            self.assertIs(sc_bad["passed"], False, f"Expected catch for {item_id}: {sc_bad}")
            self.assertGreater(len(sc_bad["failure_reasons"]), 0)
            self.assertEqual(sc_bad["cfr_title"], cfr_title)
            self.assertEqual(sc_bad["required_citation"], req_cit)

    def test_09_verify_and_record_receipt_worm_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ledger_path = os.path.join(tmpdir, "mcp_worm_ledger.jsonl")
            hmac_key = "mcp-stdio-secret-2026"

            # Entry 0: PASS
            r0 = self._rpc(
                20,
                "tools/call",
                {
                    "name": "verify_and_record_receipt",
                    "arguments": {
                        "item_id": "GT-K-DFARS-000010",
                        "text": "$174,000.",
                        "ledger_path": ledger_path,
                        "hmac_key": hmac_key,
                        "hmac_key_id": "eng-01",
                    },
                },
            )
            self.assertFalse(r0["result"].get("isError", False))
            sc0 = r0["result"]["structuredContent"]
            self.assertIs(sc0["passed"], True)
            self.assertEqual(sc0["verdict"], "PASS")
            self.assertEqual(sc0["receipt"]["prev_receipt_sha256"], GENESIS_PREV_HASH)
            self.assertEqual(sc0["receipt"]["hmac_key_id"], "eng-01")
            self.assertIs(sc0["ledger_status"]["valid"], True)
            self.assertEqual(sc0["ledger_status"]["entries_checked"], 1)
            self.assertIs(sc0["ledger_status"]["hmac_verified"], True)

            # Entry 1: FAIL (corrupt claim chained to entry 0)
            r1 = self._rpc(
                21,
                "tools/call",
                {
                    "name": "verify_and_record_receipt",
                    "arguments": {
                        "item_id": "GT-K-DFARS-000010",
                        "text": "$250,000.",
                        "ledger_path": ledger_path,
                        "hmac_key": hmac_key,
                        "hmac_key_id": "eng-01",
                    },
                },
            )
            self.assertFalse(r1["result"].get("isError", False))
            sc1 = r1["result"]["structuredContent"]
            self.assertIs(sc1["passed"], False)
            self.assertEqual(sc1["verdict"], "FAIL")
            self.assertGreater(len(sc1["failure_reasons"]), 0)
            self.assertEqual(
                sc1["receipt"]["prev_receipt_sha256"],
                sc0["receipt"]["receipt_sha256"],
            )
            self.assertIs(sc1["ledger_status"]["valid"], True)
            self.assertEqual(sc1["ledger_status"]["entries_checked"], 2)

            # Entry 2: PASS (47 CFR chained to entry 1)
            r2 = self._rpc(
                22,
                "tools/call",
                {
                    "name": "verify_and_record_receipt",
                    "arguments": {
                        "item_id": "SP-47CFR-64-1200-A10",
                        "text": "10 business days",
                        "ledger_path": ledger_path,
                        "hmac_key": hmac_key,
                        "hmac_key_id": "eng-01",
                    },
                },
            )
            self.assertFalse(r2["result"].get("isError", False))
            sc2 = r2["result"]["structuredContent"]
            self.assertEqual(
                sc2["receipt"]["prev_receipt_sha256"],
                sc1["receipt"]["receipt_sha256"],
            )
            self.assertIs(sc2["ledger_status"]["valid"], True)
            self.assertEqual(sc2["ledger_status"]["entries_checked"], 3)

            # Verify full chain externally and test 1-byte tamper detection at index 1
            verified = verify_ledger_integrity(ledger_path, hmac_key=hmac_key)
            self.assertIs(verified["valid"], True)
            self.assertEqual(verified["entries_checked"], 3)

            with open(ledger_path, encoding="utf-8") as fh:
                lines = fh.read().splitlines()
            lines[1] = lines[1].replace('"verdict":"FAIL"', '"verdict":"PASS"', 1)
            with open(ledger_path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")

            tampered = verify_ledger_integrity(ledger_path, hmac_key=hmac_key)
            self.assertIs(tampered["valid"], False)
            self.assertEqual(tampered["broken_at_index"], 1)


def main() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestMCPStdioServer)
    runner = unittest.TextTestRunner(verbosity=2)
    res = runner.run(suite)
    print(
        f"MCP Stdio Test Summary: {res.testsRun} run, "
        f"{len(res.failures)} failed, {len(res.errors)} errors"
    )
    return 0 if res.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
