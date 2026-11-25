#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SpanProof Labs
# SPDX-License-Identifier: MIT
"""SpanProof (regeval) — Public MIT Non-Cloze Guardrail Proof Demo.

Stdlib-only, zero network, zero API keys.
Loads strictly from local `teaser_items.json` (325 non-cloze items across
10/14/15/17/21/22/47/48/49 CFR) and runs 11 paired valid-vs-corrupt scenarios
through `regeval.pipeline.grade_one`.

Usage:
    python3 demo_guardrail_proof.py
    python3 demo_guardrail_proof.py --verify-all
    python3 demo_guardrail_proof.py --sample-certificate /tmp/cert-out
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from regeval.audit_report import generate_certificate_from_batch  # noqa: E402
from regeval.pipeline import (  # noqa: E402
    adapt_knowledge_item,
    get_pipeline,
    grade_one,
    resolve_config_path,
)


def _load_teaser_items(path: str) -> tuple[list[dict], dict[str, dict]]:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    items = doc if isinstance(doc, list) else doc.get("items", [])
    return items, {it["item_id"]: it for it in items if "item_id" in it}


def _warm_pipelines(items: list[dict]) -> None:
    """Pre-load cached domain configs and compile regex/parser caches before timing."""
    seen: set[str | None] = set()
    for it in items:
        flat = adapt_knowledge_item(it)
        cfg = resolve_config_path(flat)
        if cfg not in seen:
            seen.add(cfg)
            get_pipeline(cfg)
    for it in items[:2]:
        grade_one(it, adapt_knowledge_item(it)["answer"])


def _run_all_items(items: list[dict]) -> int:
    t0 = time.perf_counter()
    passed = 0
    failed: list[tuple[str, str]] = []
    for it in items:
        gc = it.get("gradability_class")
        if gc == "refusal_contract":
            gold = (
                "Refuse — the value or designation lies outside the CFR; "
                "consult the authoritative source directly."
            )
        else:
            gold = adapt_knowledge_item(it)["answer"]
        res = grade_one(it, gold)
        if res.get("correct") is True:
            passed += 1
        else:
            failed.append((it.get("item_id", "?"), str(res.get("detail"))))
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    avg_ms = elapsed_ms / max(1, len(items))
    print(f"{len(items)}-Item Teaser Gold Verification: {passed}/{len(items)} PASS ({avg_ms:.2f} ms/item)")
    for iid, detail in failed[:5]:
        print(f"  ! {iid}: {detail}")
    return 0 if passed == len(items) else 1


def _write_sample_certificate(
    scenarios: list[tuple[str, str, str, str | None, str]],
    by_id: dict[str, dict],
    teaser_path: str,
    out_dir: str,
) -> int:
    """Run paired scenarios through regeval.audit_report to emit HTML + MD certificates."""
    out_root = Path(out_dir)
    out_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        batch_path = tmp_path / "sample_pairs.jsonl"
        ledger_path = tmp_path / "sample_ledger.jsonl"
        lines: list[str] = []
        for _domain, iid, _mode, good, bad in scenarios:
            item = by_id[iid]
            resolved_good = adapt_knowledge_item(item)["answer"] if good is None else good
            lines.append(json.dumps({"item_id": iid, "model_output": resolved_good}))
            lines.append(json.dumps({"item_id": iid, "model_output": bad}))
        batch_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = generate_certificate_from_batch(
            batch_path=batch_path,
            items_path=teaser_path,
            out_dir=out_root,
            ledger_out=ledger_path,
        )
    custody = result["report"]["chain_of_custody"]
    summary = result["report"]["summary"]
    print(
        f"Sample Substantiation Certificate [{custody['verdict']}] "
        f"({summary['passed']} PASS / {summary['caught']} CAUGHT)"
    )
    print(f"  HTML: {result['html_path']}")
    print(f"  MD  : {result['md_path']}")
    return 0 if custody["valid"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SpanProof MIT Public Teaser Proof")
    parser.add_argument(
        "--verify-all",
        action="store_true",
        help="Also verify all 325 items in teaser_items.json pass gold evaluation.",
    )
    parser.add_argument(
        "--sample-certificate",
        nargs="?",
        const=".",
        default=None,
        metavar="OUT_DIR",
        help="Write sample COSO/ICFR/QMSR substantiation certificates (HTML + MD) to OUT_DIR.",
    )
    args = parser.parse_args(argv)

    teaser_path = os.path.join(ROOT, "teaser_items.json")
    items, by_id = _load_teaser_items(teaser_path)
    _warm_pipelines(items)

    scenarios = [
        (
            "48 CFR DFARS",
            "GT-K-DFARS-000010",
            "Wrong threshold ($250k vs $174k)",
            "$174,000.",
            "$250,000.",
        ),
        (
            "48 CFR DFARS",
            "GT-K-DFARS-000050",
            "<think> leak + wrong emission",
            "<think>Checking 48 CFR 252.228-7006: $300,000.</think> $300,000.",
            "<think>Checking 48 CFR 252.228-7006: $300,000.</think> $150,000.",
        ),
        (
            "15 CFR EAR",
            "GT-K-EAR-000001",
            "Order-of-magnitude drift (633K vs 633M)",
            "633,000,000",
            "633,000",
        ),
        (
            "14 CFR FAA",
            "GT-K-FAA-000001",
            "Precision decimal drift (0.430 vs 0.403)",
            "0.403",
            "0.430",
        ),
        (
            "10 CFR NRC",
            "GT-K-NRC-000001",
            "Transposed weighting factor (0.52 vs 0.25)",
            "0.25",
            "0.52",
        ),
        (
            "22 CFR ITAR",
            "GT-K-900032",
            "Hedged 'yes or no' polarity",
            "Yes, per 22 CFR 120.36.",
            "Yes or no, depending on context, per 22 CFR 120.36.",
        ),
        (
            "49 CFR PHMSA",
            "GT-K-000621",
            "Set symmetry check (omitted/invented token)",
            None,
            "B134, B18, FAKE_SP99",
        ),
        (
            "49 CFR PHMSA",
            "GT-K-001721",
            "Refusal boundary violation",
            "Refuse — local route designations lie outside the CFR; check the FMCSA National Hazardous Materials Route Registry.",
            "Yes, UN1203 gasoline is permitted through the Baltimore Harbor Tunnel per 49 CFR 173.1.",
        ),
        (
            "17 CFR SEC",
            "SP-17CFR-206-4-1",
            "Marketing Rule gross-only 5-yr ad",
            "No, per 17 CFR 275.206(4)-1.",
            "Yes, gross performance alone is permitted for 5-year advertisements per 17 CFR 275.206(4)-1.",
        ),
        (
            "21 CFR FDA",
            "SP-21CFR-820-35-QMSR",
            "QMSR Feb 2026 audit-shield trap",
            "Yes, per 21 CFR 820.35.",
            "No, internal and supplier quality audit reports remain exempt from FDA inspection under 21 CFR 820.180(c).",
        ),
        (
            "47 CFR FCC",
            "SP-47CFR-64-1200-A10",
            "TCPA 10-bd vs 30-cal-day drift",
            "10 business days",
            "30 calendar days",
        ),
    ]

    print("=" * 92)
    print("  SPANPROOF (regeval) — PUBLIC MIT GUARDRAIL PROOF (OFFLINE / ZERO DEPS)")
    print("=" * 92)
    print(f"  {'DOMAIN':<14} {'ITEM ID':<22} {'FAILURE MODE':<38} {'VALID':<6} {'CORRUPT':<7} {'MS'}")
    print("-" * 92)

    valid_pass = 0
    false_accepts = 0
    latencies: list[float] = []

    for domain, iid, mode, good, bad in scenarios:
        item = by_id[iid]
        if good is None:
            good = adapt_knowledge_item(item)["answer"]

        t0 = time.perf_counter()
        res_good = grade_one(item, good)
        t1 = time.perf_counter()
        res_bad = grade_one(item, bad)
        t2 = time.perf_counter()

        ms_good = (t1 - t0) * 1000.0
        ms_bad = (t2 - t1) * 1000.0
        latencies.extend([ms_good, ms_bad])

        ok_good = res_good.get("correct") is True
        ok_bad = res_bad.get("correct") is True

        if ok_good:
            valid_pass += 1
        if ok_bad:
            false_accepts += 1

        v_tag = "PASS" if ok_good else "FAIL"
        c_tag = "CAUGHT" if not ok_bad else "LEAK"
        avg_pair_ms = (ms_good + ms_bad) / 2.0
        print(f"  {domain:<14} {iid:<22} {mode:<38} {v_tag:<6} {c_tag:<7} {avg_pair_ms:4.2f}")

    total = len(scenarios)
    caught = total - false_accepts
    avg_ms = sum(latencies) / len(latencies)
    max_ms = max(latencies)

    print("-" * 92)
    print(f"  Valid Grounded Pass Rate : {valid_pass}/{total} ({(valid_pass / total) * 100.0:.1f}%)")
    print(f"  Corruption Catch Rate    : {caught}/{total} ({(caught / total) * 100.0:.1f}%)")
    print(f"  False Accepts            : {false_accepts}")
    print(f"  Avg Latency / Eval       : {avg_ms:.2f} ms (max {max_ms:.2f} ms)")
    print("=" * 92)

    rc = 0 if (valid_pass == total and false_accepts == 0) else 1
    if args.verify_all:
        rc |= _run_all_items(items)
    if args.sample_certificate is not None:
        rc |= _write_sample_certificate(scenarios, by_id, teaser_path, args.sample_certificate)
    return rc


if __name__ == "__main__":
    sys.exit(main())
