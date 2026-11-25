#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SpanProof Contributors
# SPDX-License-Identifier: MIT
"""SpanProof (regeval) — COSO ICIF / ICFR / QMSR Substantiation Report CLI.

Pure Python 3.11+ standard-library module that converts deterministic
verification runs and WORM SHA-256 hash-chained JSONL audit ledgers into
auditor-ready, single-file HTML and Markdown substantiation certificates.

Two operational modes:
  - Mode A (Ledger Verification): validates an existing JSONL WORM ledger via
    ``audit_ledger.verify_ledger_integrity()`` and builds substantiation
    certificates directly from the verified receipt chain.
  - Mode B (Batch Grading + Ledger + Certificate): grades a JSONL batch of
    ``{"item_id": ..., "model_output": ...}`` pairs against regulatory corpus
    items via ``regeval.pipeline.grade_one()``, appends SHA-256 hash-chained
    receipts via ``audit_ledger.append_receipt()``, verifies chain integrity,
    and emits substantiation certificates.

Zero external dependencies; zero network calls; zero external CDN assets.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import math
import os
import re
import statistics
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .audit_ledger import (
    GENESIS_PREV_HASH,
    append_receipt,
    verify_ledger_integrity,
)
from .pipeline import (
    adapt_knowledge_item,
    get_pipeline,
    grade_one,
    resolve_config_path,
)

CERTIFICATE_HTML_FILENAME = "spanproof_substantiation_certificate.html"
CERTIFICATE_MD_FILENAME = "spanproof_substantiation_certificate.md"

_CFR_TITLE_RE = re.compile(r"^\s*(\d{1,3})\s+CFR\b", re.IGNORECASE)

_CFR_AGENCY_LABELS: dict[int, str] = {
    10: "NRC (Energy / Nuclear)",
    14: "FAA (Aeronautics & Space)",
    15: "BIS / EAR (Commerce & Foreign Trade)",
    17: "SEC / CFTC (Commodity & Securities)",
    21: "FDA (Food, Drugs & QMSR Devices)",
    22: "DDTC / ITAR (Foreign Relations)",
    29: "OSHA (Labor & Workplace Safety)",
    30: "BOEM / BSEE (Mineral Resources)",
    40: "EPA (Environment & RCRA)",
    47: "FCC (Telecommunications & TCPA)",
    48: "FAR / DFARS (Federal Acquisition)",
    49: "DOT / PHMSA (Transportation & HazMat)",
}


def _esc(value: Any) -> str:
    """HTML-escape any value safely with quote escaping enabled."""
    return html.escape("" if value is None else str(value), quote=True)


def _md_cell(value: Any) -> str:
    """Escape pipe characters and newlines for clean GitHub-Flavored Markdown tables."""
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_cfr_citation(item: Mapping[str, Any]) -> str:
    """Extract the canonical CFR citation string from any supported item shape."""
    for key in ("citation_canonical", "citation"):
        val = item.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()

    citations = item.get("citations")
    if isinstance(citations, Sequence) and not isinstance(citations, (str, bytes)):
        for pin in citations:
            if isinstance(pin, Mapping):
                cc = pin.get("citation_canonical")
                if isinstance(cc, str) and cc.strip():
                    return cc.strip()

    grader = item.get("grader")
    if isinstance(grader, Mapping):
        req = grader.get("required_citation")
        if isinstance(req, str) and req.strip():
            return req.strip()

    cfr_title = item.get("cfr_title")
    if isinstance(cfr_title, int) and not isinstance(cfr_title, bool):
        return f"{cfr_title} CFR"
    return ""


def extract_cfr_title(cfr_citation: str) -> tuple[int | None, str]:
    """Parse a CFR title number and normalized label from a citation string."""
    match = _CFR_TITLE_RE.match(cfr_citation or "")
    if not match:
        return None, "Other / Unspecified"
    title_num = int(match.group(1))
    return title_num, f"{title_num} CFR"


def compute_latency_stats(latencies_ms: Sequence[float]) -> dict[str, float]:
    """Compute deterministic latency summary telemetry in milliseconds."""
    clean = [float(x) for x in latencies_ms if not isinstance(x, bool) and isinstance(x, (int, float))]
    if not clean:
        return {
            "count": 0,
            "min_ms": 0.0,
            "avg_ms": 0.0,
            "p50_ms": 0.0,
            "p95_ms": 0.0,
            "max_ms": 0.0,
        }
    ordered = sorted(clean)
    n = len(ordered)
    p95_idx = max(0, min(n - 1, math.ceil(0.95 * n) - 1))
    return {
        "count": n,
        "min_ms": round(ordered[0], 3),
        "avg_ms": round(statistics.fmean(ordered), 3),
        "p50_ms": round(statistics.median(ordered), 3),
        "p95_ms": round(ordered[p95_idx], 3),
        "max_ms": round(ordered[-1], 3),
    }


def _extract_item_records(doc: Any) -> list[dict[str, Any]]:
    """Extract item dictionaries from list or {'items': [...]} JSON containers."""
    candidates: list[Any]
    if isinstance(doc, list):
        candidates = doc
    elif isinstance(doc, Mapping):
        items_field = doc.get("items")
        if isinstance(items_field, list):
            candidates = items_field
        elif any(k in doc for k in ("item_id", "eval_id", "candidate_id")):
            candidates = [doc]
        else:
            return []
    else:
        return []

    records: list[dict[str, Any]] = []
    for entry in candidates:
        if isinstance(entry, dict) and any(
            isinstance(entry.get(k), str) and entry.get(k)
            for k in ("item_id", "eval_id", "candidate_id")
        ):
            records.append(entry)
    return records


def load_items_index(
    items_path: str | os.PathLike[str],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    """Load regulatory items from a JSON file or directory into lookup indexes.

    Returns ``(items_by_id, bank_index)`` where ``items_by_id`` indexes records by
    ``item_id``, ``eval_id``, and ``candidate_id``.
    """
    path = Path(items_path)
    if not path.exists():
        raise FileNotFoundError(f"Items path does not exist: {path}")

    files = [path] if path.is_file() else sorted(p for p in path.rglob("*.json") if p.is_file())
    if not files:
        raise ValueError(f"No JSON item files found under: {path}")

    items_by_id: dict[str, dict[str, Any]] = {}
    bank_index: dict[str, dict[str, Any]] = {}

    for json_file in files:
        with json_file.open(encoding="utf-8") as fh:
            doc = json.load(fh)
        for rec in _extract_item_records(doc):
            for key_name in ("item_id", "eval_id", "candidate_id"):
                val = rec.get(key_name)
                if isinstance(val, str) and val.strip():
                    items_by_id.setdefault(val.strip(), rec)
            iid = rec.get("item_id")
            if isinstance(iid, str) and iid.strip() and "answer_canonical" in rec:
                bank_index.setdefault(iid.strip(), rec)

    if not items_by_id:
        raise ValueError(f"No valid regulatory items loaded from: {path}")
    return items_by_id, bank_index


def read_ledger_entries_tolerantly(
    ledger_path: str | os.PathLike[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Parse ledger JSONL entries without aborting when a line is tampered or corrupt."""
    path = Path(ledger_path)
    if not path.exists():
        return [], []

    raw_bytes = path.read_bytes()
    if not raw_bytes:
        return [], []

    text = raw_bytes.decode("utf-8", errors="replace")
    parsed: list[dict[str, Any]] = []
    parse_errors: list[dict[str, Any]] = []

    for idx, line in enumerate(text.splitlines()):
        if not line.strip():
            parse_errors.append({"index": idx, "reason": f"blank line at index {idx}"})
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            parse_errors.append({"index": idx, "reason": f"malformed JSON at index {idx}: {exc}"})
            continue
        if not isinstance(obj, dict):
            parse_errors.append({"index": idx, "reason": f"entry at index {idx} is not a JSON object"})
            continue
        entry = dict(obj)
        entry["_line_index"] = idx
        parsed.append(entry)

    return parsed, parse_errors


def _classify_verdict(verdict: Any) -> str:
    if verdict is True:
        return "PASS"
    if verdict is False:
        return "FAIL"
    if isinstance(verdict, str):
        norm = verdict.strip().upper()
        if norm == "PASS":
            return "PASS"
        if norm == "FAIL":
            return "FAIL"
        if norm in ("NOT_EVALUATED", "UNSCORED", "JUDGMENT"):
            return "NOT_EVALUATED"
        return norm or "FAIL"
    return "FAIL"


def summarize_ledger(
    ledger_path: str | os.PathLike[str],
    hmac_key: bytes | str | None = None,
    mode: str = "ledger_verify",
    source_label: str | None = None,
    generated_at_utc: str | None = None,
) -> dict[str, Any]:
    """Verify ledger chain integrity and aggregate COSO/ICFR/QMSR report metrics."""
    path = Path(ledger_path)
    integrity = verify_ledger_integrity(path, hmac_key=hmac_key)
    entries, parse_errors = read_ledger_entries_tolerantly(path)

    ts = generated_at_utc or datetime.now(timezone.utc).isoformat()
    ledger_sha256 = _sha256_file(path)

    first_entry = entries[0] if entries else None
    last_entry = entries[-1] if entries else None
    root_prev_hash = (
        str(first_entry.get("prev_receipt_sha256", ""))
        if first_entry is not None
        else GENESIS_PREV_HASH
    )
    first_receipt_sha256 = (
        str(first_entry.get("receipt_sha256", ""))
        if first_entry is not None
        else None
    )
    terminal_receipt_sha256 = (
        str(last_entry.get("receipt_sha256", ""))
        if last_entry is not None
        else integrity.get("head_receipt_sha256")
    )
    hmac_key_ids = sorted(
        {str(e["hmac_key_id"]) for e in entries if e.get("hmac_key_id")}
    )

    latencies: list[float] = []
    by_title_buckets: dict[tuple[int | None, str], dict[str, Any]] = {}
    discrepancies: list[dict[str, Any]] = []
    normalized_entries: list[dict[str, Any]] = []

    passed_total = 0
    caught_total = 0
    not_eval_total = 0

    for entry in entries:
        idx = int(entry.get("_line_index", len(normalized_entries)))
        verdict_raw = entry.get("verdict")
        verdict_norm = _classify_verdict(verdict_raw)
        cfr_citation = str(entry.get("cfr_citation") or "")
        title_num, title_label = extract_cfr_title(cfr_citation)

        raw_lat = entry.get("latency_ms", 0.0)
        lat_val = (
            float(raw_lat)
            if not isinstance(raw_lat, bool) and isinstance(raw_lat, (int, float))
            else 0.0
        )
        latencies.append(lat_val)

        reasons_raw = entry.get("failure_reasons")
        if isinstance(reasons_raw, list):
            reasons = [str(r) for r in reasons_raw]
        elif reasons_raw is None:
            reasons = []
        else:
            reasons = [str(reasons_raw)]

        bucket_key = (title_num, title_label)
        bucket = by_title_buckets.get(bucket_key)
        if bucket is None:
            bucket = {
                "title_number": title_num,
                "cfr_title": title_label,
                "agency": _CFR_AGENCY_LABELS.get(title_num, "Federal Regulation")
                if title_num is not None
                else "Unspecified CFR Title",
                "total": 0,
                "passed": 0,
                "caught": 0,
                "not_evaluated": 0,
                "latencies": [],
            }
            by_title_buckets[bucket_key] = bucket

        bucket["total"] += 1
        bucket["latencies"].append(lat_val)

        if verdict_norm == "PASS":
            passed_total += 1
            bucket["passed"] += 1
        elif verdict_norm == "NOT_EVALUATED":
            not_eval_total += 1
            bucket["not_evaluated"] += 1
        else:
            caught_total += 1
            bucket["caught"] += 1

        norm_row = {
            "index": idx,
            "timestamp_utc": str(entry.get("timestamp_utc") or ""),
            "item_id": str(entry.get("item_id") or ""),
            "cfr_citation": cfr_citation,
            "verdict": str(verdict_raw if verdict_raw is not None else verdict_norm),
            "verdict_normalized": verdict_norm,
            "failure_reasons": reasons,
            "latency_ms": round(lat_val, 3),
            "input_claim_sha256": str(entry.get("input_claim_sha256") or ""),
            "corpus_item_sha256": str(entry.get("corpus_item_sha256") or ""),
            "receipt_sha256": str(entry.get("receipt_sha256") or ""),
        }
        normalized_entries.append(norm_row)

        if verdict_norm != "PASS" or reasons:
            discrepancies.append(norm_row)

    for perr in parse_errors:
        discrepancies.append(
            {
                "index": perr["index"],
                "timestamp_utc": "",
                "item_id": "<CORRUPT_LEDGER_LINE>",
                "cfr_citation": "",
                "verdict": "CORRUPT_ENTRY",
                "verdict_normalized": "CORRUPT_ENTRY",
                "failure_reasons": [perr["reason"]],
                "latency_ms": 0.0,
                "input_claim_sha256": "",
                "corpus_item_sha256": "",
                "receipt_sha256": "",
            }
        )

    discrepancies.sort(key=lambda d: int(d["index"]))

    cfr_breakdown: list[dict[str, Any]] = []
    for (title_num, _), b in sorted(
        by_title_buckets.items(),
        key=lambda kv: (kv[0][0] is None, kv[0][0] or 0, kv[0][1]),
    ):
        total = b["total"]
        cfr_breakdown.append(
            {
                "title_number": title_num,
                "cfr_title": b["cfr_title"],
                "agency": b["agency"],
                "total": total,
                "passed": b["passed"],
                "caught": b["caught"],
                "not_evaluated": b["not_evaluated"],
                "pass_rate_pct": round((b["passed"] / total) * 100.0, 2) if total else 0.0,
                "catch_rate_pct": round((b["caught"] / total) * 100.0, 2) if total else 0.0,
                "avg_latency_ms": round(statistics.fmean(b["latencies"]), 3)
                if b["latencies"]
                else 0.0,
            }
        )

    total_parsed = len(entries)
    chain_valid = bool(integrity.get("valid"))
    tamper_verdict = "VALID" if chain_valid else "TAMPER_DETECTED"

    return {
        "schema": "spanproof.substantiation_certificate.v1",
        "report_metadata": {
            "generated_at_utc": ts,
            "mode": mode,
            "source_label": source_label or path.name,
            "ledger_path": str(path),
            "ledger_sha256": ledger_sha256,
            "frameworks": [
                "COSO ICIF (2013) — Control & Monitoring Activities",
                "SOX / ICFR Section 404 — Substantiation Evidence Trail",
                "FDA 21 CFR Part 820 QMSR — Audit-Ready Record Verification",
            ],
        },
        "chain_of_custody": {
            "verdict": tamper_verdict,
            "valid": chain_valid,
            "entries_checked": int(integrity.get("entries_checked") or 0),
            "broken_at_index": integrity.get("broken_at_index"),
            "reason": integrity.get("reason"),
            "hmac_verified": bool(integrity.get("hmac_verified")),
            "hmac_key_ids": hmac_key_ids,
            "genesis_anchor_sha256": GENESIS_PREV_HASH,
            "root_prev_receipt_sha256": root_prev_hash,
            "first_receipt_sha256": first_receipt_sha256,
            "terminal_receipt_sha256": terminal_receipt_sha256,
            "head_receipt_sha256": integrity.get("head_receipt_sha256"),
        },
        "summary": {
            "total_entries": total_parsed,
            "passed": passed_total,
            "caught": caught_total,
            "not_evaluated": not_eval_total,
            "parse_errors": len(parse_errors),
            "pass_rate_pct": round((passed_total / total_parsed) * 100.0, 2)
            if total_parsed
            else 0.0,
            "catch_rate_pct": round((caught_total / total_parsed) * 100.0, 2)
            if total_parsed
            else 0.0,
        },
        "latency_ms": compute_latency_stats(latencies),
        "by_cfr_title": cfr_breakdown,
        "discrepancies": discrepancies,
        "entries": normalized_entries,
    }


def _warm_batch_pipelines(items: Sequence[Mapping[str, Any]]) -> None:
    """Pre-load cached domain configs so per-item timing reflects verification cost."""
    seen: set[str | None] = set()
    for it in items:
        item_dict = dict(it)
        if "answer_canonical" in item_dict and "answer" not in item_dict:
            item_dict = adapt_knowledge_item(item_dict)
        cfg = resolve_config_path(item_dict)
        if cfg not in seen:
            seen.add(cfg)
            get_pipeline(cfg)


def grade_batch_to_ledger(
    batch_path: str | os.PathLike[str],
    items_path: str | os.PathLike[str],
    ledger_out: str | os.PathLike[str],
    hmac_key: bytes | str | None = None,
    hmac_key_id: str | None = None,
) -> list[dict[str, Any]]:
    """Grade JSONL ``{"item_id": ..., "model_output": ...}`` pairs and append WORM receipts."""
    batch_file = Path(batch_path)
    if not batch_file.is_file():
        raise FileNotFoundError(f"Batch file does not exist: {batch_file}")

    items_by_id, bank_index = load_items_index(items_path)

    pairs: list[tuple[int, str, str, dict[str, Any]]] = []
    with batch_file.open(encoding="utf-8") as fh:
        for line_no, raw_line in enumerate(fh, start=1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed JSON in batch line {line_no}: {exc}") from exc
            if not isinstance(obj, dict):
                raise ValueError(f"Batch line {line_no} must be a JSON object")

            item_id = obj.get("item_id") or obj.get("eval_id") or obj.get("candidate_id")
            if not isinstance(item_id, str) or not item_id.strip():
                raise ValueError(f"Batch line {line_no} missing non-empty 'item_id'")
            item_id = item_id.strip()

            if item_id not in items_by_id:
                raise KeyError(f"Batch line {line_no} references unknown item_id: {item_id!r}")

            if "model_output" in obj:
                model_output = obj["model_output"]
            elif "response" in obj:
                model_output = obj["response"]
            elif "text" in obj:
                model_output = obj["text"]
            else:
                raise ValueError(f"Batch line {line_no} missing 'model_output'")

            if not isinstance(model_output, str):
                model_output = "" if model_output is None else str(model_output)

            pairs.append((line_no, item_id, model_output, obj))

    _warm_batch_pipelines([items_by_id[iid] for _, iid, _, _ in pairs])

    receipts: list[dict[str, Any]] = []
    for _, item_id, model_output, obj in pairs:
        item = items_by_id[item_id]
        t0 = time.perf_counter()
        res = grade_one(item, model_output, bank_index=bank_index or None)
        latency_ms = (time.perf_counter() - t0) * 1000.0

        correct = res.get("correct")
        detail = res.get("detail")
        if correct is True:
            verdict = "PASS"
            failure_reasons: list[str] = []
        elif correct is False:
            verdict = "FAIL"
            failure_reasons = [str(detail) if detail else "deterministic verification failed"]
        else:
            verdict = "NOT_EVALUATED"
            failure_reasons = [str(detail) if detail else "item routed outside mechanical tier"]

        ts_override = obj.get("timestamp_utc")
        receipt = append_receipt(
            ledger_path=ledger_out,
            item_id=item_id,
            cfr_citation=extract_cfr_citation(item),
            verdict=verdict,
            failure_reasons=failure_reasons,
            latency_ms=latency_ms,
            input_claim=model_output,
            corpus_item=item,
            timestamp_utc=ts_override if isinstance(ts_override, str) and ts_override.strip() else None,
            hmac_key=hmac_key,
            hmac_key_id=hmac_key_id,
        )
        receipts.append(receipt)

    return receipts


def render_certificate_markdown(report: Mapping[str, Any]) -> str:
    """Render an auditor-ready Markdown substantiation certificate."""
    meta = report["report_metadata"]
    custody = report["chain_of_custody"]
    summary = report["summary"]
    latency = report["latency_ms"]
    cfr_rows = report["by_cfr_title"]
    discrepancies = report["discrepancies"]

    verdict = custody["verdict"]
    broken_str = (
        "None"
        if custody["broken_at_index"] is None
        else str(custody["broken_at_index"])
    )
    hmac_str = (
        f"VERIFIED ({', '.join(custody['hmac_key_ids']) or 'keyed'})"
        if custody["hmac_verified"]
        else "NOT_ENABLED"
    )

    lines: list[str] = [
        "# SpanProof Deterministic Substantiation Certificate",
        "",
        "**Control Scope:** COSO ICIF Continuous Control Monitoring | SOX / ICFR Substantiation | FDA 21 CFR Part 820 QMSR Audit Readiness",
        "",
        f"- **Generated (UTC):** `{meta['generated_at_utc']}`",
        f"- **Verification Mode:** `{meta['mode']}`",
        f"- **Source Artifact:** `{meta['source_label']}`",
        f"- **Ledger File SHA-256:** `{meta['ledger_sha256'] or 'N/A'}`",
        "",
        "## 1. Chain-of-Custody & Tamper-Check Verdict",
        "",
        "| Field | Value |",
        "| :--- | :--- |",
        f"| **Tamper-Check Verdict** | **{verdict}** |",
        f"| **Broken At Index** | `{broken_str}` |",
        f"| **Integrity Detail** | {_md_cell(custody['reason'] or 'All hash-chain links and canonical digests verified.')} |",
        f"| **Entries Checked** | `{custody['entries_checked']}` |",
        f"| **HMAC-SHA-256 Status** | `{hmac_str}` |",
        f"| **Genesis Anchor (`prev_receipt_sha256[0]`)** | `{custody['root_prev_receipt_sha256']}` |",
        f"| **First Entry (`receipt_sha256[0]`)** | `{custody['first_receipt_sha256'] or 'N/A'}` |",
        f"| **Terminal Entry (`receipt_sha256[-1]`)** | `{custody['terminal_receipt_sha256'] or 'N/A'}` |",
        "",
        "## 2. Verification Summary & Latency Telemetry",
        "",
        "| Metric | Value |",
        "| :--- | :--- |",
        f"| **Total Receipts Evaluated** | `{summary['total_entries']}` |",
        f"| **Verified Compliant (PASS)** | `{summary['passed']}` (`{summary['pass_rate_pct']:.2f}%`) |",
        f"| **Discrepancies Caught (FAIL)** | `{summary['caught']}` (`{summary['catch_rate_pct']:.2f}%`) |",
        f"| **Not Evaluated (Judgment / Unscored)** | `{summary['not_evaluated']}` |",
        f"| **Latency Avg / p95 / Max (ms)** | `{latency['avg_ms']:.3f} ms` / `{latency['p95_ms']:.3f} ms` / `{latency['max_ms']:.3f} ms` |",
        f"| **Latency Min / Median p50 (ms)** | `{latency['min_ms']:.3f} ms` / `{latency['p50_ms']:.3f} ms` |",
        "",
        "## 3. Pass / Catch Breakdown by CFR Title",
        "",
        "| CFR Title | Agency / Scope | Total | Pass | Caught (Fail) | Not Evaluated | Pass Rate | Catch Rate | Avg Latency (ms) |",
        "| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]

    if cfr_rows:
        for row in cfr_rows:
            lines.append(
                f"| {_md_cell(row['cfr_title'])} "
                f"| {_md_cell(row['agency'])} "
                f"| {row['total']} "
                f"| {row['passed']} "
                f"| {row['caught']} "
                f"| {row['not_evaluated']} "
                f"| {row['pass_rate_pct']:.2f}% "
                f"| {row['catch_rate_pct']:.2f}% "
                f"| {row['avg_latency_ms']:.3f} |"
            )
    else:
        lines.append("| None | No receipt rows found | 0 | 0 | 0 | 0 | 0.00% | 0.00% | 0.000 |")

    lines.extend(
        [
            "",
            "## 4. Exact Statutory Span Discrepancies & Failure Reasons",
            "",
        ]
    )

    if discrepancies:
        lines.extend(
            [
                "| Index | Item ID | CFR Citation | Verdict | Failure Reasons | Receipt SHA-256 |",
                "| ---: | :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for d in discrepancies:
            reasons_txt = "; ".join(d["failure_reasons"]) if d["failure_reasons"] else "No detail recorded"
            r_hash = d["receipt_sha256"] or "N/A"
            lines.append(
                f"| {d['index']} "
                f"| `{_md_cell(d['item_id'])}` "
                f"| `{_md_cell(d['cfr_citation'] or 'N/A')}` "
                f"| `{_md_cell(d['verdict'])}` "
                f"| {_md_cell(reasons_txt)} "
                f"| `{_md_cell(r_hash)}` |"
            )
    else:
        lines.append(
            f"0 statutory span discrepancies detected across {summary['total_entries']} verified assertions."
        )

    lines.extend(
        [
            "",
            "---",
            "*Generated deterministically offline by `regeval.audit_report` (zero external dependencies, zero network egress).*",
            "",
        ]
    )
    return "\n".join(lines)


def render_certificate_html(report: Mapping[str, Any]) -> str:
    """Render an offline, XSS-safe, single-file enterprise HTML substantiation certificate."""
    meta = report["report_metadata"]
    custody = report["chain_of_custody"]
    summary = report["summary"]
    latency = report["latency_ms"]
    cfr_rows = report["by_cfr_title"]
    discrepancies = report["discrepancies"]

    chain_valid = bool(custody["valid"])
    verdict_badge_cls = "badge-valid" if chain_valid else "badge-tamper"
    broken_str = (
        "None"
        if custody["broken_at_index"] is None
        else str(custody["broken_at_index"])
    )
    hmac_label = (
        f"VERIFIED ({', '.join(custody['hmac_key_ids']) or 'keyed'})"
        if custody["hmac_verified"]
        else "NOT_ENABLED"
    )

    cfr_table_rows: list[str] = []
    if cfr_rows:
        for row in cfr_rows:
            pass_pct_str = f"{row['pass_rate_pct']:.2f}%"
            catch_pct_str = f"{row['catch_rate_pct']:.2f}%"
            avg_lat_str = f"{row['avg_latency_ms']:.3f}"
            cfr_table_rows.append(
                "<tr>"
                f'<td class="mono strong">{_esc(row["cfr_title"])}</td>'
                f'<td>{_esc(row["agency"])}</td>'
                f'<td class="num">{_esc(row["total"])}</td>'
                f'<td class="num pass-txt">{_esc(row["passed"])}</td>'
                f'<td class="num fail-txt">{_esc(row["caught"])}</td>'
                f'<td class="num">{_esc(row["not_evaluated"])}</td>'
                f'<td class="num">{_esc(pass_pct_str)}</td>'
                f'<td class="num">{_esc(catch_pct_str)}</td>'
                f'<td class="num mono">{_esc(avg_lat_str)}</td>'
                "</tr>"
            )
    else:
        cfr_table_rows.append(
            '<tr><td colspan="9" class="muted">No receipt entries present in ledger.</td></tr>'
        )

    if discrepancies:
        disc_rows: list[str] = []
        for d in discrepancies:
            reasons_txt = "; ".join(d["failure_reasons"]) if d["failure_reasons"] else "No detail recorded"
            v_cls = "pill-fail" if d["verdict_normalized"] in ("FAIL", "CORRUPT_ENTRY") else "pill-neutral"
            disc_rows.append(
                "<tr>"
                f"<td class=\"num mono\">{_esc(d['index'])}</td>"
                f"<td class=\"mono\">{_esc(d['item_id'])}</td>"
                f"<td class=\"mono\">{_esc(d['cfr_citation'] or 'N/A')}</td>"
                f"<td><span class=\"pill {v_cls}\">{_esc(d['verdict'])}</span></td>"
                f"<td>{_esc(reasons_txt)}</td>"
                f"<td class=\"mono hash-cell\">{_esc(d['receipt_sha256'] or 'N/A')}</td>"
                "</tr>"
            )
        discrepancy_block = (
            "<div class=\"table-wrap\">"
            "<table>"
            "<thead><tr>"
            "<th class=\"num\">Idx</th>"
            "<th>Item ID</th>"
            "<th>CFR Citation</th>"
            "<th>Verdict</th>"
            "<th>Exact Statutory Span Discrepancy / Failure Reason</th>"
            "<th>Receipt SHA-256</th>"
            "</tr></thead>"
            f"<tbody>{''.join(disc_rows)}</tbody>"
            "</table>"
            "</div>"
        )
    else:
        discrepancy_block = (
            "<div class=\"empty-notice\">"
            f"0 statutory span discrepancies detected across {_esc(summary['total_entries'])} verified assertions."
            "</div>"
        )

    pass_rate_label = f"{summary['pass_rate_pct']:.2f}%"
    catch_rate_label = f"{summary['catch_rate_pct']:.2f}%"
    lat_avg_label = f"{latency['avg_ms']:.3f} ms"
    lat_avg_num = f"{latency['avg_ms']:.3f}"
    lat_min_num = f"{latency['min_ms']:.3f}"
    lat_p50_num = f"{latency['p50_ms']:.3f}"
    lat_p95_num = f"{latency['p95_ms']:.3f}"
    lat_max_num = f"{latency['max_ms']:.3f}"
    cfr_rows_html = "".join(cfr_table_rows)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SpanProof Substantiation Certificate — {_esc(meta['source_label'])}</title>
  <style>
    :root {{
      --bg: #f4f6f9;
      --surface: #ffffff;
      --ink: #0f172a;
      --muted: #475569;
      --border: #cbd5e1;
      --border-soft: #e2e8f0;
      --header-bg: #1e293b;
      --header-fg: #f8fafc;
      --accent: #1d4ed8;
      --valid-bg: #ecfdf5;
      --valid-fg: #065f46;
      --valid-bd: #a7f3d0;
      --tamper-bg: #fef2f2;
      --tamper-fg: #991b1b;
      --tamper-bd: #fecaca;
      --neutral-bg: #f1f5f9;
      --neutral-fg: #334155;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      padding: 24px 16px 40px;
      background: var(--bg);
      color: var(--ink);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      font-size: 14px;
      line-height: 1.5;
    }}
    .page {{
      max-width: 1120px;
      margin: 0 auto;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      overflow: hidden;
    }}
    .banner {{
      background: var(--header-bg);
      color: var(--header-fg);
      padding: 22px 28px;
      border-bottom: 3px solid var(--accent);
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: flex-start;
      gap: 16px;
    }}
    .banner-kicker {{
      font-size: 11px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: #cbd5e1;
      margin: 0 0 4px 0;
      font-weight: 600;
    }}
    .banner h1 {{
      margin: 0 0 6px 0;
      font-size: 21px;
      font-weight: 700;
      letter-spacing: -0.01em;
    }}
    .banner-sub {{
      margin: 0;
      font-size: 13px;
      color: #e2e8f0;
    }}
    .badge {{
      display: inline-block;
      padding: 6px 12px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      border: 1px solid transparent;
      white-space: nowrap;
    }}
    .badge-valid {{
      background: var(--valid-bg);
      color: var(--valid-fg);
      border-color: var(--valid-bd);
    }}
    .badge-tamper {{
      background: var(--tamper-bg);
      color: var(--tamper-fg);
      border-color: var(--tamper-bd);
    }}
    .content {{
      padding: 24px 28px 28px;
    }}
    .meta-bar {{
      display: grid;
      grid-template-columns: 1.2fr 1fr 1fr 2fr;
      gap: 12px;
      padding: 12px 14px;
      background: #f8fafc;
      border: 1px solid var(--border-soft);
      border-radius: 4px;
      margin-bottom: 20px;
      font-size: 12.5px;
    }}
    .meta-label {{
      color: var(--muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 10.5px;
      letter-spacing: 0.05em;
      display: block;
    }}
    .kpi-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr 1fr 1.35fr;
      gap: 12px;
      margin-bottom: 24px;
    }}
    @media (max-width: 760px) {{
      .meta-bar, .kpi-grid {{
        grid-template-columns: 1fr;
      }}
    }}
    .kpi {{
      border: 1px solid var(--border-soft);
      border-radius: 4px;
      padding: 12px 14px;
      background: #ffffff;
    }}
    .kpi-label {{
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--muted);
    }}
    .kpi-value {{
      font-size: 22px;
      font-weight: 700;
      margin-top: 4px;
      color: var(--ink);
    }}
    .kpi-sub {{
      font-size: 12px;
      color: var(--muted);
      margin-top: 2px;
    }}
    h2 {{
      font-size: 15px;
      font-weight: 700;
      color: var(--ink);
      margin: 24px 0 10px 0;
      padding-bottom: 6px;
      border-bottom: 1px solid var(--border-soft);
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }}
    .table-wrap {{
      overflow-x: auto;
      border: 1px solid var(--border-soft);
      border-radius: 4px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }}
    th, td {{
      padding: 8px 10px;
      text-align: left;
      border-bottom: 1px solid var(--border-soft);
      vertical-align: top;
    }}
    thead th {{
      background: #f8fafc;
      color: #334155;
      font-size: 11.5px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }}
    tbody tr:last-child td {{
      border-bottom: none;
    }}
    .num {{
      text-align: right;
      font-variant-numeric: tabular-nums;
    }}
    .mono {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
    }}
    .hash-cell {{
      word-break: break-all;
      max-width: 300px;
    }}
    .strong {{ font-weight: 600; }}
    .muted {{ color: var(--muted); }}
    .pass-txt {{ color: var(--valid-fg); font-weight: 600; }}
    .fail-txt {{ color: var(--tamper-fg); font-weight: 600; }}
    .pill {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 3px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
    }}
    .pill-fail {{
      background: var(--tamper-bg);
      color: var(--tamper-fg);
      border: 1px solid var(--tamper-bd);
    }}
    .pill-neutral {{
      background: var(--neutral-bg);
      color: var(--neutral-fg);
      border: 1px solid var(--border);
    }}
    .empty-notice {{
      padding: 14px 16px;
      background: var(--valid-bg);
      color: var(--valid-fg);
      border: 1px solid var(--valid-bd);
      border-radius: 4px;
      font-weight: 600;
    }}
    .footer {{
      padding: 12px 28px;
      background: #f8fafc;
      border-top: 1px solid var(--border-soft);
      font-size: 12px;
      color: var(--muted);
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: 8px;
    }}
    @media print {{
      body {{ background: #ffffff; padding: 0; }}
      .page {{ border: none; }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <div class="banner">
      <div>
        <p class="banner-kicker">COSO ICIF &middot; SOX / ICFR &middot; FDA 21 CFR Part 820 QMSR</p>
        <h1>SpanProof Deterministic Substantiation Certificate</h1>
        <p class="banner-sub">Cryptographically Chained WORM Verification &amp; Statutory Span Audit Report</p>
      </div>
      <div class="badge {verdict_badge_cls}">Chain Integrity: {_esc(custody['verdict'])}</div>
    </div>

    <div class="content">
      <div class="meta-bar">
        <div><span class="meta-label">Generated (UTC)</span><span class="mono">{_esc(meta['generated_at_utc'])}</span></div>
        <div><span class="meta-label">Execution Mode</span><span class="mono">{_esc(meta['mode'])}</span></div>
        <div><span class="meta-label">Source Artifact</span><span class="mono">{_esc(meta['source_label'])}</span></div>
        <div><span class="meta-label">Ledger File SHA-256</span><span class="mono hash-cell">{_esc(meta['ledger_sha256'] or 'N/A')}</span></div>
      </div>

      <div class="kpi-grid">
        <div class="kpi">
          <div class="kpi-label">Assertions Verified</div>
          <div class="kpi-value">{_esc(summary['total_entries'])}</div>
          <div class="kpi-sub">Entries checked: {_esc(custody['entries_checked'])}</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">Verified Compliant (PASS)</div>
          <div class="kpi-value pass-txt">{_esc(summary['passed'])}</div>
          <div class="kpi-sub">{_esc(pass_rate_label)} pass rate</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">Discrepancies Caught (FAIL)</div>
          <div class="kpi-value fail-txt">{_esc(summary['caught'])}</div>
          <div class="kpi-sub">{_esc(catch_rate_label)} catch rate</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">Latency Telemetry (ms)</div>
          <div class="kpi-value mono">{_esc(lat_avg_label)}</div>
          <div class="kpi-sub">p95 {_esc(lat_p95_num)} ms &middot; max {_esc(lat_max_num)} ms</div>
        </div>
      </div>

      <h2>1. Chain-of-Custody &amp; Tamper-Check Verdict</h2>
      <div class="table-wrap">
        <table>
          <tbody>
            <tr><th style="width:280px;">Tamper-Check Verdict</th><td><span class="badge {verdict_badge_cls}">{_esc(custody['verdict'])}</span></td></tr>
            <tr><th>Broken At Index</th><td class="mono">{_esc(broken_str)}</td></tr>
            <tr><th>Verification Detail</th><td>{_esc(custody['reason'] or 'All hash-chain links and canonical digests verified.')}</td></tr>
            <tr><th>HMAC-SHA-256 Authentication</th><td class="mono">{_esc(hmac_label)}</td></tr>
            <tr><th>Root Genesis Anchor (prev_receipt_sha256[0])</th><td class="mono hash-cell">{_esc(custody['root_prev_receipt_sha256'])}</td></tr>
            <tr><th>First Entry Hash (receipt_sha256[0])</th><td class="mono hash-cell">{_esc(custody['first_receipt_sha256'] or 'N/A')}</td></tr>
            <tr><th>Terminal Entry Hash (receipt_sha256[-1])</th><td class="mono hash-cell">{_esc(custody['terminal_receipt_sha256'] or 'N/A')}</td></tr>
          </tbody>
        </table>
      </div>

      <h2>2. Latency Telemetry (Deterministic Engine)</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th class="num">Evaluated Count</th>
              <th class="num">Min (ms)</th>
              <th class="num">Avg (ms)</th>
              <th class="num">Median p50 (ms)</th>
              <th class="num">p95 (ms)</th>
              <th class="num">Max (ms)</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td class="num mono">{_esc(latency['count'])}</td>
              <td class="num mono">{_esc(lat_min_num)}</td>
              <td class="num mono strong">{_esc(lat_avg_num)}</td>
              <td class="num mono">{_esc(lat_p50_num)}</td>
              <td class="num mono strong">{_esc(lat_p95_num)}</td>
              <td class="num mono strong">{_esc(lat_max_num)}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2>3. Pass / Catch Breakdown by CFR Title</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>CFR Title</th>
              <th>Agency / Scope</th>
              <th class="num">Total</th>
              <th class="num">Pass</th>
              <th class="num">Caught (Fail)</th>
              <th class="num">Not Evaluated</th>
              <th class="num">Pass Rate</th>
              <th class="num">Catch Rate</th>
              <th class="num">Avg Latency (ms)</th>
            </tr>
          </thead>
          <tbody>
            {cfr_rows_html}
          </tbody>
        </table>
      </div>

      <h2>4. Exact Statutory Span Discrepancies &amp; Failure Reasons</h2>
      {discrepancy_block}
    </div>

    <div class="footer">
      <span>SpanProof (regeval.audit_report) &mdash; Offline Deterministic Verification</span>
      <span>Zero external dependencies &middot; Zero network egress</span>
    </div>
  </div>
</body>
</html>
"""


def write_certificates(
    report: Mapping[str, Any],
    out_dir: str | os.PathLike[str] = ".",
    html_path: str | os.PathLike[str] | None = None,
    md_path: str | os.PathLike[str] | None = None,
) -> tuple[Path, Path]:
    """Render and write both HTML and Markdown substantiation certificates."""
    out_root = Path(out_dir)
    resolved_html = Path(html_path) if html_path is not None else out_root / CERTIFICATE_HTML_FILENAME
    resolved_md = Path(md_path) if md_path is not None else out_root / CERTIFICATE_MD_FILENAME

    resolved_html.parent.mkdir(parents=True, exist_ok=True)
    resolved_md.parent.mkdir(parents=True, exist_ok=True)

    resolved_html.write_text(render_certificate_html(report), encoding="utf-8")
    resolved_md.write_text(render_certificate_markdown(report), encoding="utf-8")
    return resolved_html, resolved_md


def generate_certificate_from_ledger(
    ledger_path: str | os.PathLike[str],
    out_dir: str | os.PathLike[str] = ".",
    hmac_key: bytes | str | None = None,
    html_path: str | os.PathLike[str] | None = None,
    md_path: str | os.PathLike[str] | None = None,
    generated_at_utc: str | None = None,
) -> dict[str, Any]:
    """Mode A Python API: verify an existing WORM ledger and emit HTML + MD certificates."""
    report = summarize_ledger(
        ledger_path=ledger_path,
        hmac_key=hmac_key,
        mode="ledger_verify",
        generated_at_utc=generated_at_utc,
    )
    hp, mp = write_certificates(report, out_dir=out_dir, html_path=html_path, md_path=md_path)
    return {"report": report, "html_path": str(hp), "md_path": str(mp)}


def generate_certificate_from_batch(
    batch_path: str | os.PathLike[str],
    items_path: str | os.PathLike[str],
    out_dir: str | os.PathLike[str] = ".",
    ledger_out: str | os.PathLike[str] | None = None,
    hmac_key: bytes | str | None = None,
    hmac_key_id: str | None = None,
    html_path: str | os.PathLike[str] | None = None,
    md_path: str | os.PathLike[str] | None = None,
    generated_at_utc: str | None = None,
) -> dict[str, Any]:
    """Mode B Python API: grade batch pairs, append WORM receipts, verify chain, emit certs."""
    resolved_ledger = (
        Path(ledger_out)
        if ledger_out is not None
        else Path(out_dir) / "spanproof_audit_ledger.jsonl"
    )
    grade_batch_to_ledger(
        batch_path=batch_path,
        items_path=items_path,
        ledger_out=resolved_ledger,
        hmac_key=hmac_key,
        hmac_key_id=hmac_key_id,
    )
    report = summarize_ledger(
        ledger_path=resolved_ledger,
        hmac_key=hmac_key,
        mode="batch_grade_and_verify",
        source_label=Path(batch_path).name,
        generated_at_utc=generated_at_utc,
    )
    hp, mp = write_certificates(report, out_dir=out_dir, html_path=html_path, md_path=md_path)
    return {
        "report": report,
        "ledger_path": str(resolved_ledger),
        "html_path": str(hp),
        "md_path": str(mp),
    }


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m regeval.audit_report",
        description="Generate COSO/ICFR/QMSR Substantiation Certificates (HTML + Markdown) from SpanProof WORM ledgers or batch pairs.",
    )
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--ledger",
        help="Mode A: Path to an existing WORM JSONL audit ledger to verify and certify.",
    )
    mode_group.add_argument(
        "--batch",
        help="Mode B: Path to a JSONL file of {'item_id': ..., 'model_output': ...} pairs to grade.",
    )
    parser.add_argument(
        "--items",
        help="Mode B: Path to regulatory items JSON file or directory (required with --batch).",
    )
    parser.add_argument(
        "--ledger-out",
        default=None,
        help="Mode B: Output path for appended WORM JSONL receipt ledger (defaults to <out-dir>/spanproof_audit_ledger.jsonl).",
    )
    parser.add_argument(
        "--out-dir",
        default=".",
        help="Directory where spanproof_substantiation_certificate.html and .md are written (default: '.').",
    )
    parser.add_argument(
        "--html-out",
        default=None,
        help="Optional explicit path for HTML certificate output.",
    )
    parser.add_argument(
        "--md-out",
        default=None,
        help="Optional explicit path for Markdown certificate output.",
    )
    parser.add_argument(
        "--hmac-key",
        default=None,
        help="Optional keyed HMAC-SHA-256 secret for ledger signing/verification.",
    )
    parser.add_argument(
        "--hmac-key-id",
        default=None,
        help="Optional HMAC key identifier recorded when signing Mode B receipts.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 2 if chain tamper check returns TAMPER_DETECTED.",
    )
    parser.add_argument(
        "--json-summary",
        action="store_true",
        help="Print structured JSON summary to stdout instead of human-readable status lines.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    if args.batch and not args.items:
        parser.error("--items is required when using --batch")

    if args.ledger:
        result = generate_certificate_from_ledger(
            ledger_path=args.ledger,
            out_dir=args.out_dir,
            hmac_key=args.hmac_key,
            html_path=args.html_out,
            md_path=args.md_out,
        )
    else:
        result = generate_certificate_from_batch(
            batch_path=args.batch,
            items_path=args.items,
            out_dir=args.out_dir,
            ledger_out=args.ledger_out,
            hmac_key=args.hmac_key,
            hmac_key_id=args.hmac_key_id,
            html_path=args.html_out,
            md_path=args.md_out,
        )

    report = result["report"]
    custody = report["chain_of_custody"]
    summary = report["summary"]

    if args.json_summary:
        payload = {
            "verdict": custody["verdict"],
            "valid": custody["valid"],
            "entries_checked": custody["entries_checked"],
            "broken_at_index": custody["broken_at_index"],
            "total_entries": summary["total_entries"],
            "passed": summary["passed"],
            "caught": summary["caught"],
            "html_path": result["html_path"],
            "md_path": result["md_path"],
        }
        if "ledger_path" in result:
            payload["ledger_path"] = result["ledger_path"]
        print(json.dumps(payload, indent=2))
    else:
        print(
            f"SpanProof Substantiation Certificate [{custody['verdict']}] "
            f"entries={summary['total_entries']} pass={summary['passed']} caught={summary['caught']}"
        )
        print(f"  HTML: {result['html_path']}")
        print(f"  MD  : {result['md_path']}")
        if "ledger_path" in result:
            print(f"  WORM: {result['ledger_path']}")

    if args.strict and not custody["valid"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
