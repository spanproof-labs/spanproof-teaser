# SPDX-License-Identifier: MIT
"""The refusal_contract lane: grading the answers that should not be given.

WHY THIS FILE DID NOT EXIST, AND WHAT THAT COST
------------------------------------------------
`refusal_contract` has been a declared gradability class since the bank was built.
Ninety-two items carry it. `tools/consistency_guard.py` cross-checks its contract,
`tools/build_eval_bank.py` renders its prompts, `tools/triangulate.py` has selftests
for it. Everything around it was built.

The adjudicator itself was not. `grade_one` classed those items MECHANICAL — so they
counted in the auto-gradable denominator — then found no grader and returned
`scored: False, correct: None`. Ninety-two items were being counted as machine-gradable
and never machine-graded.

Underneath that sat a worse one. `_sanitize_got` collapsed any response containing
"I cannot" into a single token before grading, so a model that answered a reserved-
section question CORRECTLY — "I cannot state a requirement for 49 CFR 171.11 because
that section is reserved" — had its answer destroyed and scored wrong. Three of four
correct phrasings failed that way. The published false-rejection rate did not catch it,
because it was measured on an eval bank containing zero refusal items: the headline
metric never touched the broken lane.

WHAT A REFUSAL CONTRACT ACTUALLY REQUIRES
------------------------------------------
Not "did it decline". Two things, and the second is the one nobody tests:

    1. Did it decline when it should have, and answer when it should have?
    2. Did it decline FOR THE RIGHT REASON?

The second matters because the degenerate strategy is free. A system that refuses
everything scores perfectly on a suite where refusal is always correct — and today
that describes this lane exactly: all 92 items expect a refusal and none is a decoy.
That is why grading here is symmetric in the same way `set_equality` is symmetric
about missing and extra members: an over-refusal is an error of the same rank as a
fabrication, and a suite that cannot express one is not measuring the capability.

So the contract has three outcomes, not two:

    GROUNDED_REFUSAL   declined and named the reason (reserved, out of scope,
                       not carried by this bank) -> correct where refusal is owed
    BARE_EVASION       declined with nothing behind it -> never correct. The
                       canonical answer for these items carries a `reason` field;
                       the reason IS part of the contract, not decoration.
    SUBSTANTIVE        answered. Correct on an in-scope decoy; on a reserved
                       section it is a fabrication, which is the failure this
                       whole lane exists to catch.
"""
from __future__ import annotations

from ..core.utils import (BARE_EVASION, GROUNDED_REFUSAL, SUBSTANTIVE,
                          refusal_shape)


def _expected_refusal(expected, item):
    """Does this item's contract owe a refusal? (bool, source-of-truth string)

    Read in preference order, because the same fact is recorded three ways depending
    on whether the record came through the eval-bank adapter or straight off the
    knowledge bank:

      1. answer_canonical / expected  {"refuse": bool, "reason": str}
      2. item['refusal_expected']
      3. item['over_refusal_decoy']   an in-scope decoy owes an ANSWER, not a refusal

    consistency_guard.py already enforces that (1) and (2) agree, so disagreement is
    a bank defect rather than something to resolve silently here.
    """
    for src in (expected, item.get("answer_canonical"), item.get("answer")):
        if isinstance(src, dict) and "refuse" in src:
            return bool(src["refuse"]), "answer_canonical.refuse"
    if item.get("over_refusal_decoy"):
        return False, "over_refusal_decoy"
    exp = item.get("refusal_expected")
    if exp is not None:
        return bool(exp), "refusal_expected"
    return None, "UNDECLARED"


def grade_refusal_contract(expected, got, item=None, config_path=None):
    """(ok, detail). ok is None only when the item declares no contract to grade."""
    item = item or {}
    owes_refusal, source = _expected_refusal(expected, item)
    if owes_refusal is None:
        return None, ("no refusal contract on this item — neither answer_canonical."
                      "refuse, refusal_expected nor over_refusal_decoy is set; not scored")

    shape = refusal_shape(got or "")

    if owes_refusal:
        if shape == GROUNDED_REFUSAL:
            return True, f"declined and gave regulatory grounds ({source})"
        if shape == BARE_EVASION:
            return False, ("declined, but supplied no regulatory grounds — the "
                           "contract's `reason` is part of the answer, and a "
                           "contentless refusal is indistinguishable from a system "
                           "that refuses everything")
        return False, ("answered a question whose correct response is a refusal — "
                       "this is the fabrication case the lane exists to catch")

    # In-scope decoy: refusing is the error. Whether the substantive answer is itself
    # correct is a different item's job; this lane scores the refuse/answer decision.
    if shape == SUBSTANTIVE:
        return True, f"answered an in-scope item rather than over-refusing ({source})"
    return False, (f"OVER-REFUSAL — the item is in scope and owes an answer, but the "
                   f"response declined ({shape})")
