# SPDX-FileCopyrightText: 2026 SpanProof Labs
# SPDX-License-Identifier: MIT
"""table_lookup — the adjudicator for the bank's largest lane (368 of 631 items).

A table_lookup key is ADDRESSED, not stored. Where an exact_match item carries
its answer inline, a table_lookup item carries a pin:

    {"artifact": "corpus/derived/hmt-172-101.json",
     "artifact_sha256": "20787b82...",
     "row_id": "HMT-01982",
     "column_key": "special_provisions"}

The answer is the cell that pin addresses. That is the whole point of the lane:
the key cannot drift from the corpus, because the key IS the corpus. Withholding
`expected` on a HOLDOUT item costs nothing, because the grader re-derives it.

Until this module existed the lane had no entry in the GRADERS dict, so all 368
items returned an unscored verdict and the published mechanical score was
computed over the other 42% of the bank.

WHAT THIS MODULE DOES AND DOES NOT DO
  * It RESOLVES. Pin -> artifact -> row -> cell -> expected value, plus the
    comparison semantics that cell's shape implies.
  * It DOES NOT COMPARE. Comparison is delegated, unchanged, to the existing
    exact_match / set_equality / boolean adjudicators, so a table_lookup item is
    graded by exactly the normalization the rest of the bank is graded by. No
    second, laxer matcher exists for the majority lane — that is precisely how a
    benchmark gets quietly gamed.

INTEGRITY IS ENFORCED, NOT ASSUMED
  The pin declares artifact_sha256. If the artifact on disk does not hash to it,
  the item is NOT_EVALUATED with the mismatch named. A grader that scores against
  a silently-swapped corpus is worse than one that refuses.

NOT_EVALUATED IS NOT FAILURE
  Every refusal path here returns ok=None with a reason. An unreadable artifact,
  a missing row, an empty cell — none of them may read as "the model got it
  wrong". That distinction is the product.

DETERMINISM AND COST
  Pure stdlib. Each artifact is read, hashed and indexed by row_id exactly once
  (O(N) in the artifact, amortized O(1) per item); grading 368 items touches the
  3,686-row table one time.
"""
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..core.context import PipelineContext
from .base import BaseAdjudicator

# A column whose cells hold a bare section NUMBER, with the part carried in the
# artifact's own column metadata: "Col 8B - Packaging: Non-bulk (173.xxx)".
# The cell reads "203"; the regulatory answer is "§173.203". The part number is
# read from the artifact, never hardcoded here — a second table with a different
# part resolves correctly with no change to this file.
_SECTION_REF_COLUMN = re.compile(r"\((\d{2,3})\.xxx\)")

# Cells that state a prohibition rather than a value. Column 9A of the §172.101
# table reads "Forbidden" where a quantity would otherwise stand; the question
# asked against such a cell is a yes/no determination, not a token match.
_DETERMINATION_CELLS: Dict[str, bool] = {"forbidden": False}


@dataclass
class ResolvedKey:
    """The outcome of resolving a pin. `ok` False always means NOT_EVALUATED —
    an infrastructure or provenance gap — and never a wrong answer."""
    ok: bool
    detail: str
    value: Any = None
    rule_type: str = ""
    citation: Optional[str] = None
    boolean_answer: Optional[bool] = None


@dataclass
class _Artifact:
    """A derived-corpus table, read and indexed once."""
    rows_by_id: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    column_meaning: Dict[str, str] = field(default_factory=dict)
    citation: str = ""
    sha256: str = ""


# Artifacts are few (one per derived table) and immutable for the life of a run,
# so this cache is bounded by the corpus, not by the item count.
_ARTIFACT_CACHE: Dict[str, _Artifact] = {}


def _load_artifact(abs_path: str) -> _Artifact:
    """Read, hash and index one derived-corpus table. Cached by absolute path."""
    cached = _ARTIFACT_CACHE.get(abs_path)
    if cached is not None:
        return cached
    with open(abs_path, "rb") as fh:
        raw = fh.read()
    doc = json.loads(raw.decode("utf-8"))
    art = _Artifact(
        sha256=hashlib.sha256(raw).hexdigest(),
        citation=str(doc.get("citation") or ""),
        column_meaning={c.get("key"): str(c.get("meaning") or "")
                        for c in (doc.get("columns") or []) if isinstance(c, dict)},
    )
    for row in doc.get("rows") or []:
        rid = row.get("row_id")
        if rid is not None:
            art.rows_by_id[str(rid)] = row
    _ARTIFACT_CACHE[abs_path] = art
    return art


def _split_cell(cell: str) -> List[str]:
    """A cell is a comma-separated enumeration or a single value. Splitting is
    the same operation either way; arity is what decides the grading semantics."""
    return [tok.strip() for tok in cell.split(",") if tok.strip()]


def resolve_table_key(expected_source: Optional[Dict[str, Any]],
                      root: str) -> ResolvedKey:
    """Resolve a table_lookup pin to (expected value, comparison rule).

    `root` is the repository root the pin's relative artifact path is taken from.
    Every failure mode returns ok=False with a stated reason — NOT_EVALUATED.
    """
    if not isinstance(expected_source, dict):
        return ResolvedKey(False, "table_lookup item carries no expected_source pin; "
                                  "not evaluated")
    artifact = expected_source.get("artifact")
    row_id = expected_source.get("row_id")
    column_key = expected_source.get("column_key")
    missing = [k for k, v in (("artifact", artifact), ("row_id", row_id),
                              ("column_key", column_key)) if not v]
    if missing:
        return ResolvedKey(False, f"table_lookup pin is incomplete (missing "
                                  f"{', '.join(missing)}); not evaluated")

    # Containment check: a pin is data, and data does not get to address files
    # outside the corpus root.
    abs_path = os.path.normpath(os.path.join(root, str(artifact)))
    if not abs_path.startswith(os.path.join(os.path.normpath(root), "")):
        return ResolvedKey(False, f"table_lookup pin addresses a path outside the "
                                  f"repository root ({artifact!r}); not evaluated")
    if not os.path.exists(abs_path):
        return ResolvedKey(False, f"pinned artifact {artifact!r} is not on disk; "
                                  f"not evaluated")
    try:
        art = _load_artifact(abs_path)
    except (OSError, ValueError) as exc:
        return ResolvedKey(False, f"pinned artifact {artifact!r} could not be read "
                                  f"({exc.__class__.__name__}); not evaluated")

    declared_sha = expected_source.get("artifact_sha256")
    if declared_sha and declared_sha != art.sha256:
        return ResolvedKey(False, f"pinned artifact {artifact!r} does not match its "
                                  f"declared digest (expected {declared_sha[:12]}…, "
                                  f"found {art.sha256[:12]}…); not evaluated")

    row = art.rows_by_id.get(str(row_id))
    if row is None:
        return ResolvedKey(False, f"row {row_id!r} is not present in {artifact!r}; "
                                  f"not evaluated")
    if column_key not in row:
        return ResolvedKey(False, f"column {column_key!r} is not present on row "
                                  f"{row_id!r} of {artifact!r}; not evaluated")

    cell = row.get(column_key)
    cell = "" if cell is None else str(cell).strip()
    if not cell:
        return ResolvedKey(False, f"pinned cell {row_id}/{column_key} is empty in "
                                  f"{artifact!r}; there is no answer to grade — "
                                  f"not evaluated")

    meaning = art.column_meaning.get(column_key, "")

    # 1. A determination cell states a prohibition, not a value.
    determination = _DETERMINATION_CELLS.get(cell.casefold())
    if determination is not None:
        return ResolvedKey(
            True,
            f"resolved {row_id}/{column_key} = {cell!r} -> determination "
            f"{determination} grounded in {art.citation}",
            value=str(determination), rule_type="boolean",
            citation=art.citation or None, boolean_answer=determination)

    # 2. A section-reference column holds a bare section number; the part comes
    #    from the artifact's column metadata.
    tokens = _split_cell(cell)
    sec_col = _SECTION_REF_COLUMN.search(meaning)
    if sec_col:
        part = sec_col.group(1)
        tokens = [f"§{part}.{tok}" for tok in tokens]

    # 3. Arity decides the semantics. A multi-token cell is an unordered set
    #    (omission and invention are both errors); a single token is an exact
    #    match. A one-element set IS an exact match, and routing it that way
    #    keeps it clear of the set grader's >=2-member prose guard.
    if len(tokens) > 1:
        return ResolvedKey(True,
                           f"resolved {row_id}/{column_key} = {cell!r} -> "
                           f"{len(tokens)}-member set",
                           value=tokens, rule_type="set_equality")
    value = tokens[0] if tokens else cell
    return ResolvedKey(True,
                       f"resolved {row_id}/{column_key} = {cell!r} -> {value!r}",
                       value=value, rule_type="exact_match")


class TableLookupAdjudicator(BaseAdjudicator):
    """Registered so the router can name this lane. Resolution must happen BEFORE
    Lex/Tag/Resolve/Align — the aligner needs the resolved expected value to align
    against — so the pipeline calls `resolve()` up front and then runs the item
    through the ordinary adjudicator for the resolved rule type. `grade()` exists
    for a caller that reaches the router with rule_type='table_lookup' anyway, and
    refuses rather than inventing a verdict."""

    def resolve(self, expected_source: Optional[Dict[str, Any]], root: str) -> ResolvedKey:
        return resolve_table_key(expected_source, root)

    def grade(self, ctx: PipelineContext, expected_val: Any,
              aligned_got: List[Dict[str, Any]]) -> Tuple[Optional[bool], str]:
        ctx.trace_log.append({"module": "ADJUDICATOR",
                              "action": "ADJUDICATOR [TABLE_LOOKUP]: key must be "
                                        "resolved before alignment; refusing to grade."})
        return None, ("table_lookup key was not resolved before adjudication; "
                      "not evaluated")
