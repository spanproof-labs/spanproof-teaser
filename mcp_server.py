#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SpanProof Labs
# SPDX-License-Identifier: MIT
"""SpanProof (regeval) — Zero-Dependency Stdio MCP Server.

Pure Python stdlib implementation of the Model Context Protocol (JSON-RPC 2.0
over newline-delimited stdin/stdout). Zero network calls, zero third-party
dependencies. Pre-warms all MIT teaser CFR domain pipelines on startup so
deterministic symbolic verification executes in milliseconds.

Usage:
    python3 mcp_server.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import time
from collections import Counter
from typing import Any

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from regeval.audit_ledger import (  # noqa: E402
    append_receipt,
    verify_ledger_integrity,
)
from regeval.pipeline import (  # noqa: E402
    adapt_knowledge_item,
    get_pipeline,
    grade_one,
    resolve_config_path,
)

SERVER_NAME = "spanproof-regeval"
SERVER_VERSION = "1.0.0"
PROTOCOL_VERSION = "2024-11-05"
DEFAULT_LEDGER_FILENAME = "spanproof_audit_ledger.jsonl"

TOOLS_SPEC: list[dict[str, Any]] = [
    {
        "name": "verify_cfr_claim",
        "description": (
            "Verify a candidate regulatory answer or agent claim deterministically "
            "against a pinned CFR record in teaser_items.json."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Candidate agent response or regulatory claim text to verify.",
                },
                "item_id": {
                    "type": "string",
                    "description": "Teaser benchmark item identifier (e.g., GT-K-DFARS-000010).",
                },
            },
            "required": ["text", "item_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_supported_cfr_domains",
        "description": (
            "List the 9 MIT public teaser CFR domains (325 items) with dataset "
            "SHA-256 and commercial snapshot scope metadata."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "verify_and_record_receipt",
        "description": (
            "Verify a candidate regulatory claim against teaser_items.json and "
            "append a tamper-evident SHA-256 hash-chained JSONL audit receipt "
            "with ledger integrity status."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Candidate agent response or regulatory claim text to verify.",
                },
                "item_id": {
                    "type": "string",
                    "description": "Teaser benchmark item identifier (e.g., GT-K-DFARS-000010).",
                },
                "ledger_path": {
                    "type": "string",
                    "description": (
                        "Optional path to append-only JSONL audit ledger. Defaults to "
                        "SPANPROOF_AUDIT_LEDGER_PATH or system temp ledger file."
                    ),
                },
                "hmac_key": {
                    "type": "string",
                    "description": (
                        "Optional HMAC-SHA-256 signing key (defaults to "
                        "SPANPROOF_RECEIPT_KEY if set)."
                    ),
                },
                "hmac_key_id": {
                    "type": "string",
                    "description": "Optional key identifier recorded when HMAC signing is enabled.",
                },
            },
            "required": ["text", "item_id"],
            "additionalProperties": False,
        },
    },
]


def _log(msg: str) -> None:
    """Emit diagnostics strictly to stderr so stdout stays pure JSON-RPC."""
    sys.stderr.write(f"[{SERVER_NAME}] {msg}\n")
    sys.stderr.flush()


def _load_state() -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], dict[int, dict[str, Any]], str]:
    teaser_path = os.path.join(ROOT, "teaser_items.json")
    with open(teaser_path, "rb") as fh:
        raw_bytes = fh.read()
    dataset_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    doc = json.loads(raw_bytes.decode("utf-8"))
    items: list[dict[str, Any]] = doc if isinstance(doc, list) else doc.get("items", [])
    by_id: dict[str, dict[str, Any]] = {
        str(it["item_id"]): it for it in items if "item_id" in it
    }

    registry_path = os.path.join(ROOT, "configs", "registry.json")
    by_title_meta: dict[int, dict[str, Any]] = {}
    if os.path.exists(registry_path):
        with open(registry_path, encoding="utf-8") as fh:
            reg = json.load(fh)
        for key, entry in (reg.get("domains") or {}).items():
            if isinstance(entry, dict) and "cfr_title_number" in entry:
                meta = dict(entry)
                meta["config_key"] = key
                by_title_meta[int(entry["cfr_title_number"])] = meta

    return items, by_id, by_title_meta, dataset_sha256


def _warm_pipelines(items: list[dict[str, Any]]) -> int:
    """Pre-load all domain configs and exercise every gradability class at startup."""
    seen_configs: set[str | None] = set()
    for it in items:
        flat = adapt_knowledge_item(it)
        cfg = resolve_config_path(flat)
        if cfg not in seen_configs:
            seen_configs.add(cfg)
            get_pipeline(cfg)

    seen_classes: set[str | None] = set()
    for it in items:
        gc = it.get("gradability_class")
        if gc not in seen_classes:
            seen_classes.add(gc)
            ans = adapt_knowledge_item(it)["answer"]
            grade_one(it, ans)

    for it in items:
        if it.get("gradability_class") == "numeric_with_tolerance":
            grade_one(it, "<think>warmup check</think> 0")
            break

    return len(seen_configs)


class SpanProofMCPServer:
    """Stateless stdio JSON-RPC 2.0 server backed by pre-warmed SpanProof state."""

    def __init__(self) -> None:
        self.items, self.by_id, self.by_title_meta, self.dataset_sha256 = _load_state()
        warmed = _warm_pipelines(self.items)
        _log(f"warmed {warmed} domain pipelines across {len(self.items)} items")

    def _evaluate_claim(
        self, args: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]] | dict[str, Any]:
        text = args.get("text")
        item_id = args.get("item_id")
        if not isinstance(text, str) or not text.strip():
            err = {"error": "Argument 'text' must be a non-empty string."}
            return {"content": [{"type": "text", "text": json.dumps(err)}], "isError": True}
        if not isinstance(item_id, str) or not item_id.strip():
            err = {"error": "Argument 'item_id' must be a non-empty string."}
            return {"content": [{"type": "text", "text": json.dumps(err)}], "isError": True}

        item = self.by_id.get(item_id)
        if item is None:
            err = {"error": f"Unknown item_id: {item_id}", "item_id": item_id}
            return {"content": [{"type": "text", "text": json.dumps(err)}], "isError": True}

        t0 = time.perf_counter()
        res = grade_one(item, text)
        latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        passed = res.get("correct") is True
        detail = res.get("detail")
        failure_reasons: list[str] = (
            [] if passed else [str(detail) if detail else "verification failed"]
        )
        cfr_num = item.get("cfr_title")
        cfr_title = f"{cfr_num} CFR" if cfr_num is not None else "unknown"
        required_citation = str(item.get("citation_canonical") or "")

        structured: dict[str, Any] = {
            "passed": passed,
            "latency_ms": latency_ms,
            "failure_reasons": failure_reasons,
            "required_citation": required_citation,
            "item_id": str(item["item_id"]),
            "cfr_title": cfr_title,
        }
        return structured, item

    def _tool_verify_cfr_claim(self, args: dict[str, Any]) -> dict[str, Any]:
        evaluated = self._evaluate_claim(args)
        if isinstance(evaluated, dict):
            return evaluated
        structured, _ = evaluated
        return {
            "content": [{"type": "text", "text": json.dumps(structured)}],
            "structuredContent": structured,
        }

    def _tool_verify_and_record_receipt(self, args: dict[str, Any]) -> dict[str, Any]:
        evaluated = self._evaluate_claim(args)
        if isinstance(evaluated, dict):
            return evaluated
        structured, item = evaluated

        ledger_path = args.get("ledger_path")
        if ledger_path is None:
            ledger_path = os.environ.get("SPANPROOF_AUDIT_LEDGER_PATH") or os.path.join(
                tempfile.gettempdir(), DEFAULT_LEDGER_FILENAME
            )
        elif not isinstance(ledger_path, str) or not ledger_path.strip():
            err = {"error": "Argument 'ledger_path' must be a non-empty string when provided."}
            return {"content": [{"type": "text", "text": json.dumps(err)}], "isError": True}

        hmac_key = args.get("hmac_key")
        if hmac_key is None:
            hmac_key = os.environ.get("SPANPROOF_RECEIPT_KEY") or None
        elif not isinstance(hmac_key, str) or not hmac_key:
            err = {"error": "Argument 'hmac_key' must be a non-empty string when provided."}
            return {"content": [{"type": "text", "text": json.dumps(err)}], "isError": True}

        hmac_key_id = args.get("hmac_key_id")
        if hmac_key_id is not None and (not isinstance(hmac_key_id, str) or not hmac_key_id.strip()):
            err = {"error": "Argument 'hmac_key_id' must be a non-empty string when provided."}
            return {"content": [{"type": "text", "text": json.dumps(err)}], "isError": True}

        verdict = "PASS" if structured["passed"] else "FAIL"
        try:
            receipt = append_receipt(
                ledger_path=ledger_path,
                item_id=structured["item_id"],
                cfr_citation=structured["required_citation"],
                verdict=verdict,
                failure_reasons=structured["failure_reasons"],
                latency_ms=structured["latency_ms"],
                input_claim=str(args["text"]),
                corpus_item=item,
                hmac_key=hmac_key,
                hmac_key_id=hmac_key_id,
            )
            ledger_status = verify_ledger_integrity(ledger_path, hmac_key=hmac_key)
        except (OSError, ValueError) as exc:
            err = {"error": f"Audit ledger write/verify failed: {exc}"}
            return {"content": [{"type": "text", "text": json.dumps(err)}], "isError": True}

        combined: dict[str, Any] = {
            **structured,
            "verdict": verdict,
            "receipt": receipt,
            "ledger_status": {
                **ledger_status,
                "ledger_path": os.path.abspath(ledger_path),
            },
        }
        return {
            "content": [{"type": "text", "text": json.dumps(combined)}],
            "structuredContent": combined,
        }

    def _tool_list_supported_cfr_domains(self) -> dict[str, Any]:
        counts = Counter(int(it["cfr_title"]) for it in self.items if "cfr_title" in it)
        domains: list[dict[str, Any]] = []
        for title_num in sorted(counts):
            meta = self.by_title_meta.get(title_num, {})
            domains.append(
                {
                    "cfr_title_number": title_num,
                    "title": meta.get("title", f"{title_num} CFR"),
                    "agency": meta.get("agency", ""),
                    "agency_full": meta.get("agency_full", ""),
                    "config_key": meta.get("config_key", ""),
                    "description": meta.get("description", ""),
                    "item_count": counts[title_num],
                }
            )

        structured: dict[str, Any] = {
            "license": "MIT",
            "teaser_total_items": len(self.items),
            "teaser_domain_count": len(domains),
            "teaser_sha256": self.dataset_sha256,
            "domains": domains,
            "commercial_snapshot": {
                "total_items": 26485,
                "non_cloze_items": 15530,
                "cloze_items": 10955,
                "cfr_titles_count": 11,
                "cfr_titles": [10, 14, 15, 17, 21, 22, 29, 40, 47, 48, 49],
                "claimtruth_statutory_modules": 41,
                "claimtruth_cfr_titles": [38, 20],
                "note": (
                    "Commercial SpanProof & ClaimTruth snapshots include 26,485 total items "
                    "(15,530 non-cloze + 10,955 cloze) across 11 CFR titles plus ClaimTruth "
                    "(41 deterministic statutory math modules across 38 CFR and 20 CFR)."
                ),
            },
        }
        return {
            "content": [{"type": "text", "text": json.dumps(structured)}],
            "structuredContent": structured,
        }

    def handle_request(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        has_id = "id" in msg
        req_id = msg.get("id")

        if msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32600, "message": "Invalid Request"},
            }

        method: str = msg["method"]
        params = msg.get("params")
        if params is None:
            params = {}

        if method == "notifications/initialized" or method.startswith("notifications/"):
            if not has_id:
                return None
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "initialize":
            result = {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION,
                },
            }
            return {"jsonrpc": "2.0", "id": req_id, "result": result}

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS_SPEC}}

        if method == "tools/call":
            if not isinstance(params, dict):
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": "Invalid params: expected object"},
                }
            name = params.get("name")
            args = params.get("arguments")
            if args is None:
                args = {}
            if not isinstance(args, dict):
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": "Invalid params: arguments must be an object"},
                }
            if name == "verify_cfr_claim":
                return {"jsonrpc": "2.0", "id": req_id, "result": self._tool_verify_cfr_claim(args)}
            if name == "list_supported_cfr_domains":
                return {"jsonrpc": "2.0", "id": req_id, "result": self._tool_list_supported_cfr_domains()}
            if name == "verify_and_record_receipt":
                return {"jsonrpc": "2.0", "id": req_id, "result": self._tool_verify_and_record_receipt(args)}
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": f"Unknown tool: {name!r}"},
            }

        if not has_id:
            return None
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }


def _write_response(resp: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()


def main() -> int:
    server = SpanProofMCPServer()
    while True:
        raw_line = sys.stdin.readline()
        if raw_line == "":
            break
        line = raw_line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            _write_response(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {exc}"},
                }
            )
            continue

        if not isinstance(msg, dict):
            _write_response(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": "Invalid Request: expected JSON object"},
                }
            )
            continue

        resp = server.handle_request(msg)
        if resp is not None:
            _write_response(resp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
