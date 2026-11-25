# SpanProof (`regeval`) — 325-Item MIT Public Non-Cloze Teaser

Deterministic, zero-dependency Python symbolic verifier (`dependencies = []`) and a **325-item MIT-licensed non-cloze CFR benchmark** curated from U.S. Federal regulations (`17 U.S.C. § 105` public-domain works) across nine titles: **10, 14, 15, 17, 21, 22, 47, 48, and 49 CFR**.

- **License:** MIT (`Copyright (c) 2026 SpanProof Labs`) — see [`LICENSE`](LICENSE)
- **Dataset:** [`teaser_items.json`](teaser_items.json) (`325` non-cloze items, `0` holdouts, `0` external guidebook content)
- **SHA-256 (`teaser_items.json`):** `08d2034074cc804ca11b9455ee58d8a176e7806d78f7a92bb6b6f4cb1655ba15`

---

## Quickstart (Offline, Pure Python Stdlib)

```bash
python3 demo_guardrail_proof.py
python3 demo_guardrail_proof.py --verify-all
```

Zero third-party dependencies, zero API keys, zero network calls.

---

## Plug Into Claude Code, Antigravity & MCP Agent Pipelines

Run SpanProof locally as a zero-dependency stdio MCP server (`mcp_server.py`) exposing `verify_cfr_claim` and `list_supported_cfr_domains` to **Claude Code**, **Antigravity**, and any MCP-compatible agent pipeline:

```json
{
  "mcpServers": {
    "spanproof-regeval": { "command": "python3", "args": ["/path/to/public-teaser-repo/mcp_server.py"] }
  }
}
```

Verify the stdio JSON-RPC server end-to-end offline:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 tests/test_mcp_stdio.py
```

---

## GitHub Action CI Gate

![SpanProof CI Gate](https://img.shields.io/badge/SpanProof%20CI%20Gate-100%25%20Deterministic-brightgreen)

Drop [`.github/workflows/spanproof-ci-gate.yml`](.github/workflows/spanproof-ci-gate.yml) into your repository to block pull requests on any `< 100%` regression across all `325` teaser gold checks and the stdio MCP suite:

```yaml
on: [pull_request, push]
jobs:
  spanproof-verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: PYTHONDONTWRITEBYTECODE=1 python3 demo_guardrail_proof.py --verify-all
      - run: PYTHONDONTWRITEBYTECODE=1 python3 tests/test_mcp_stdio.py
```

---

## Measured Guardrail Benchmark (Dual-Latency Reference)

LLM-as-a-judge loops take `1,000–3,000 ms` per check and miss subtle comparator flips, unit-scale errors, `<think>` leakage, hedged polarity, and hallucinated CFR pins. SpanProof executes deterministic AST and symbolic domain checks in milliseconds:

- **Standalone MIT Teaser Proof (`demo_guardrail_proof.py --verify-all`):** **`2.00 ms` avg** across the 11 paired scenarios (`11/11` valid grounded pass, `11/11` silent corruptions caught, `0` false accepts) and **`1.09 ms/item`** across all `325` MIT teaser items (`325/325 PASS`) on baseline single-core benchmark runs *(observed wall-clock per-run timings vary slightly with host CPU load)*.
- **Full Commercial Pipeline (`EvaluationPipeline.evaluate_e2e` 8-pair suite):** **`2.12–2.77 ms` avg** (`1.174 ms` avg / `851.5 EPS` core parser throughput) with full commercial pipeline stages enabled.

| # | Domain | Target Failure Mode | Valid Grounded | Corrupt Output | MIT Teaser Proof (`demo_guardrail_proof.py`) | Commercial `EvaluationPipeline.evaluate_e2e` |
|---:|---|---|---:|---:|---:|---:|
| 1 | `48 CFR DFARS` | Reversed comparator (`>=` vs `<=`) / threshold flip | **PASS** | **CAUGHT** | `2.00 ms` 11-case avg | `2.12–2.77 ms` 8-pair avg |
| 2 | `49 CFR PHMSA` | Inverted boundary comparator (`<=` vs `>=`) | **PASS** | **CAUGHT** | `2.00 ms` 11-case avg | `2.12–2.77 ms` 8-pair avg |
| 3 | `15 CFR EAR` | Unit-scale & magnitude drift (`mm` vs `in`, `633K` vs `633M`) | **PASS** | **CAUGHT** | `2.00 ms` 11-case avg | `2.12–2.77 ms` 8-pair avg |
| 4 | `49 CFR / 14 CFR` | Sub-tolerance scale & decimal drift (`cm`/`mm`, `0.430` vs `0.403`) | **PASS** | **CAUGHT** | `2.00 ms` 11-case avg | `2.12–2.77 ms` 8-pair avg |
| 5 | `10 CFR / 22 CFR` | Wrong / transposed regulatory constant (`0.52` vs `0.25`) | **PASS** | **CAUGHT** | `2.00 ms` 11-case avg | `2.12–2.77 ms` 8-pair avg |
| 6 | `48 CFR DFARS` | `<think>` reasoning-trace leakage + conflicting emission | **PASS** | **CAUGHT** | `2.00 ms` 11-case avg | `2.12–2.77 ms` 8-pair avg |
| 7 | `49 CFR PHMSA` | Symmetric special-provision set / wrong CFR pin mismatch | **PASS** | **CAUGHT** | `2.00 ms` 11-case avg | `2.12–2.77 ms` 8-pair avg |
| 8 | `22 CFR / 49 CFR` | Hedged `'yes or no'` polarity & out-of-scope refusal violation | **PASS** | **CAUGHT** | `2.00 ms` 11-case avg | `2.12–2.77 ms` 8-pair avg |
| 9 | `17 CFR SEC` | Marketing Rule (`§ 275.206(4)-1`) gross-only 5-yr ad polarity flip | **PASS** | **CAUGHT** | `2.00 ms` 11-case avg | Covered in `17 CFR` bank |
| 10 | `21 CFR FDA` | QMSR (`§ 820.35`, Feb 2, 2026) audit-inspection shield trap | **PASS** | **CAUGHT** | `2.00 ms` 11-case avg | Covered in `21 CFR` bank |
| 11 | `47 CFR FCC` | TCPA (`§ 64.1200(a)(10)`, `91 FR 67214`) 10-bd vs 30-cal drift | **PASS** | **CAUGHT** | `2.00 ms` 11-case avg | Covered in `47 CFR` bank |

---

## MIT Open-Core Demo vs. Paid Commercial Moat

This public repository is intentionally scoped as a zero-signup **MIT open-core evaluation slice** (`teaser_items.json` + `demo_guardrail_proof.py`) so engineering teams can verify deterministic guardrail mechanics offline before licensing a full production snapshot.

| Layer | MIT Open-Core Demo Runtime (This Repo) | Paid Commercial Moat (SpanProof & ClaimTruth Snapshots) |
|---|---|---|
| **Runtime & Engine** | Standalone `src/regeval/` public runtime + `demo_guardrail_proof.py` | Full `regeval` commercial `EvaluationPipeline.evaluate_e2e` + **Tamper-Evident SHA-256 WORM Audit Receipt Ledger** (`regeval.audit_ledger`) with keyed `HMAC-SHA-256` receipts + **COSO/ICFR/QMSR Substantiation Certificate CLI** (`regeval/audit_report.py`) + **Per-Vertical SKU Slicers (`V1`–`V9`)** |
| **Item Bank** | `teaser_items.json` (`325` strictly non-cloze items across `9` CFR titles) | **`26,485` active items (`1,424` core + `25,061` `bank-v2`; `15,530` non-cloze / `58.64%` + `10,955` cloze / `41.36%`) across `11` CFR titles** (`10, 14, 15, 17, 21, 22, 29, 40, 47, 48, 49 CFR`); **`100.000%` (`25,866 / 25,866`) mechanical gold pass** (`0` failing, `0` duplicate normalized prompts) and **`0 CRITICAL / 0 HIGH` RC3 clean-room verdict** |
| **eCFR Refresh & Drift** | Static MIT teaser snapshot only | Automated buyer-operated **`pull_ecfr.py`** XML refresh, currency monitoring, and drift-detection pipeline |
| **Evaluation Isolation** | `0` holdouts (`teaser_items.json` only) | **Private holdout splits** excluded from public release to prevent benchmark contamination |
| **Disability Math Engine** | Not included in MIT repo | **ClaimTruth:** `41` unified deterministic statutory math modules across **`38 CFR`** & **`20 CFR`** (`1,821` parsed eCFR sections, `693` VA diagnostic codes) |
| **Measured Latency** | **`2.00 ms` avg** (11-case proof) · **`1.09 ms/item`** (`325` MIT items) | **`2.12–2.77 ms` avg** (`EvaluationPipeline.evaluate_e2e` 8-pair suite) · **`1.174 ms` / `851.5 EPS`** core parser |

### Commercial Snapshot Licensing Overview (Optional Upgrade)
- **Tier 1 — Starter Slice (`$2,500–$3,500`):** Single regulatory vertical slice or blind evaluation run. **100% of any December 2026 Tier 1 Starter fee credits dollar-for-dollar toward Tier 2 or a Tier 3 single-vertical buyout if Escrow.com is funded on or before January 15, 2027.**
- **Tier 2 — Full Perpetual Snapshot (`$14,900` Federal/SBIR COTS sub-MPT · `$19,500–$24,500` Commercial B2B):** Frozen full codebase + `26,485`-item bank + `pull_ecfr.py` tooling, governed by a mandatory **7-calendar-day** Escrow.com substantive engineering inspection window (`pytest` / `verify.py`).
- **Tier 3 — Per-Vertical Pre-Seat-1 Exclusive Buyout (`$45,000–$65,000`):** Exclusive rights strictly over **one** named CFR vertical slice (`48 CFR GovCon`, `15/22 CFR Trade`, `10 CFR Nuclear`, `14 CFR Aviation`, `49/29/40 CFR HazMat`, or `ClaimTruth VA/SSDI`) via Escrow.com with the mandatory 7-calendar-day inspection window; Seller retains unrestricted rights to license `regeval` and all other CFR verticals independently.

---

## Teaser Coverage (`325` Items Across 9 CFR Titles)

| CFR Title | Domain | Items |
| :--- | :--- | ---: |
| `10 CFR` | Nuclear (NRC) | 55 |
| `14 CFR` | Aviation (FAA) | 55 |
| `15 CFR` | Commerce / Export Control (EAR) | 60 |
| `17 CFR` | Securities & Advisers (SEC) | 15 |
| `21 CFR` | Food, Drug & Medical Devices (FDA) | 15 |
| `22 CFR` | Defense Trade (ITAR) | 6 |
| `47 CFR` | Telecommunications & TCPA (FCC) | 15 |
| `48 CFR` | Federal Acquisition (FAR / DFARS) | 48 |
| `49 CFR` | Hazardous Materials & Transportation (PHMSA) | 56 |

### Why Non-Cloze + `question_citation_stripped`
1. **Zero Cloze Leakage:** Every `MASKED_CONSTANT`, `REGULATORY_STATEMENT`, and fill-in-the-blank prompt is excluded so models cannot game evaluations by predicting masked tokens.
2. **Citation-Stripped View:** Every record pairs `question` with `question_citation_stripped` so teams can measure whether a RAG or policy model retrieves the governing rule on its own vs. parroting a section citation supplied in the prompt.

---

## Scope & Disclaimer

- Covers public-domain U.S. federal regulations (`17 U.S.C. § 105`) only; external trilateral Emergency Response Guidebook tables are intentionally omitted.
- Symbolic verification checks answer faithfulness against pinned regulatory records, comparators, units, and refusal boundaries; it does not constitute legal advice.
