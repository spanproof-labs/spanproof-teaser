# SpanProof `regeval`: an open-source grader for CFR answers (prototype)

`regeval` is an MIT-licensed Python prototype from SpanProof Labs. It grades a model's answer to a question about U.S. federal regulations against a fixed answer key. This repo ships the grader and 325 questions drawn from nine titles of the Code of Federal Regulations (10, 14, 15, 17, 21, 22, 47, 48 and 49 CFR).

The runtime uses only the Python standard library. No API keys are needed.

- **License:** MIT. See [`LICENSE`](LICENSE).
- **Items:** [`teaser_items.json`](teaser_items.json), 325 items, no held-out split.
- **SHA-256 of `teaser_items.json`:** `08d2034074cc804ca11b9455ee58d8a176e7806d78f7a92bb6b6f4cb1655ba15`
- **Also on Hugging Face:** [`spanproof-labs/spanproof-cfr-bench`](https://huggingface.co/datasets/spanproof-labs/spanproof-cfr-bench)

---

## What it grades

Each item names a grading class. The grader compares the answer to that item's key.

| Class | Items | What is compared |
| :--- | ---: | :--- |
| `numeric_with_tolerance` | 141 | A number, its unit and the item's tolerance |
| `exact_match` | 105 | A short canonical value after declared normalization (case, whitespace, the § sign) |
| `boolean_with_citation` | 53 | A yes/no determination plus the cited section |
| `set_equality` | 13 | A set of codes; a missing member and an extra member both fail |
| `refusal_contract` | 11 | A refusal with a redirect, for questions the CFR cannot answer |
| `structured_match` | 2 | A multi-field answer |

222 of the 325 items are table lookups: they ask for a value exactly as a published CFR table prints it.

| CFR title | Domain | Items |
| :--- | :--- | ---: |
| `10 CFR` | Nuclear (NRC) | 55 |
| `14 CFR` | Aviation (FAA) | 55 |
| `15 CFR` | Export control (EAR) | 60 |
| `17 CFR` | Securities (SEC) | 15 |
| `21 CFR` | Food and drugs (FDA) | 15 |
| `22 CFR` | Defense trade (ITAR) | 6 |
| `47 CFR` | Telecommunications (FCC) | 15 |
| `48 CFR` | Federal acquisition (FAR / DFARS) | 48 |
| `49 CFR` | Hazardous materials (PHMSA) | 56 |

### Where the answer keys come from

Every item records the eCFR XML file it was written from. That record holds the eCFR versioner URL for a dated edition (2026-07-17, 2026-07-20 or 2026-07-23) and the retrieval time. For 308 of the 325 items, it also holds the SHA-256 of that file. The XML files are not in this repo, and no code here downloads them or checks those hashes. They are provenance records you can check yourself.

### Negative controls

- **`[Reserved]` sections.** 30 paired yes/no items ask whether a cited section "imposes any requirement". In 15 of them the section reads `[Reserved]` in the pinned edition, so the key is "no". The other 15 cite live sections, so the key is "yes".
- **Out-of-corpus questions.** The 11 `refusal_contract` items ask for facts the CFR does not contain, such as a state's designated hazmat routes. The key expects a refusal and a pointer to the right source.

Each item also carries `question_citation_stripped`, the same question with the section citation removed. Use it to test whether a system finds the governing rule itself.

---

## Run it

```bash
python3 demo_guardrail_proof.py
python3 demo_guardrail_proof.py --verify-all
```

The demo runs 11 paired cases. Each pairs a correct answer with a corrupted one: a flipped threshold, a decimal slip, an order-of-magnitude error, a hedged yes/no, a set with an invented member, or an answer where a refusal was required. `--verify-all` also grades the gold answer for all 325 items.

Output on one laptop on 2026-11-25: 11/11 correct answers passed, 11/11 corrupted answers were caught, and 325/325 gold answers passed. Grading averaged 1.87 ms per demo case and 0.96 ms per item. Timings vary by machine.

Tests:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 tests/test_mcp_stdio.py
PYTHONDONTWRITEBYTECODE=1 python3 tests/test_audit_ledger.py
PYTHONDONTWRITEBYTECODE=1 python3 tests/test_audit_report.py
python3 -m pytest tests/test_metrology_torture.py   # this one file needs pytest
```

[`.github/workflows/spanproof-ci-gate.yml`](.github/workflows/spanproof-ci-gate.yml) runs the demo and the MCP test on every push and pull request.

---

## What each module does

**`mcp_server.py`** is a stdio JSON-RPC server for MCP clients. It exposes three tools:

- `verify_cfr_claim(text, item_id)` grades `text` against the key for `item_id`.
- `list_supported_cfr_domains()` lists the nine titles and the dataset hash.
- `verify_and_record_receipt(...)` grades the answer, then appends the result to a local ledger file (see `audit_ledger.py`).

```json
{
  "mcpServers": {
    "spanproof-regeval": { "command": "python3", "args": ["/path/to/spanproof-teaser/mcp_server.py"] }
  }
}
```

**`src/regeval/metrology.py`** does unit arithmetic with `decimal.Decimal` and `fractions.Fraction` instead of `float`. It keeps point conversions separate from delta conversions: 60 °C converts to exactly 140 °F as a temperature, but a 10 K difference converts to 18 °F. Customary units are built from their exact legal definitions (for example 1 lb = 0.45359237 kg). The psi factor is derived from a published 14.6959488 psi/atm figure, so it is not an exact definition. The module also parses US, EU and ISO-style numerals. It raises a typed error on malformed digit grouping such as `1,00,50`. In its default mode it reads `1,234` as 1234.
**It is standalone in this release.** The grading pipeline, the lexer, the adjudicators and the MCP server do not import it. Only `tests/test_metrology_torture.py` uses it (14 tests). Wiring it into `EvaluationPipeline` is the next piece of work.

**`src/regeval/audit_ledger.py`** appends one JSON line per graded answer to a local file. Each line holds the SHA-256 of the previous line's receipt, SHA-256 digests of the answer text and the item record, the verdict, and an optional HMAC-SHA-256 under a key you supply. `verify_ledger_integrity()` re-walks the chain. It detects an edited, reordered or malformed entry. It does **not** detect entries removed from the end of the file. Without an HMAC key, anyone who can write the file can rewrite it and recompute every hash. It is an ordinary file on local disk, not immutable storage.

**`src/regeval/audit_report.py`** reads a ledger, or grades a batch and writes one, then renders a Markdown and HTML summary of the verdicts, failure reasons and latencies. The report summarizes grading results. It is not a compliance attestation.

---

## Known Limitations & Active Hardening

- **`verify_cfr_claim` grades against benchmark keys.** It needs an `item_id` and compares the text to that item's key. It does not check arbitrary free-text compliance claims.
- **Grader edge cases are being fixed.** A blind red-team pass on 2026-11-25 found inputs that get the wrong verdict. They involve citation parsing, negation, and aligning units between the answer and the key. Fixes are in progress, and each failing case is becoming a regression test.
- **`metrology.py` is not yet used by the grader** (see above).
- **Source hashes are recorded, not re-checked.** 17 items have no XML hash.
- **Some table-lookup prompts carry header text run together from the source table** (for example, a missing space). Cleanup is planned.
- **Some docstrings, demo labels and MCP tool descriptions use older wording that overstates what the code does.** That wording is being removed along with the fixes above.
- **Network access.** The demo and the MCP server make no network calls. `pipeline.load_domain_config()` fetches a config over HTTPS only when you pass it a URL. Those fetches are limited to an allowlist of hosts, and redirects are refused. `jsonschema` is used if it is installed; it is not required.
- **The timings above come from one machine.**
- **This is a research prototype, not legal advice.**

---

## License and sources

The code and item set are MIT-licensed, © 2026 SpanProof Labs. The regulation text the items quote is a U.S. government work in the public domain (17 U.S.C. § 105).
