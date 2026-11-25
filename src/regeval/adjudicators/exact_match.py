# SPDX-FileCopyrightText: 2026 SpanProof Labs
# SPDX-License-Identifier: MIT
import re
from typing import Any, List, Dict
from ..core.context import PipelineContext
from .base import BaseAdjudicator
from ..core.utils import norm_token

# A packing group ASSERTION: the group named as such, or standing alone as the
# whole answer. Roman numerals only, so an "I" inside a word can never match.
# ⚠ ARABIC FORMS ARE THE SAME ANSWER. The HMT is written in Roman numerals and
# real responses say "PG 3"; the bank has always treated III and 3 as equal, and
# tests/test_multi_domain.py locks that in. A Roman-only pattern silently made
# every Arabic answer wrong — a false NEGATIVE, the direction that inflates the
# caught-error rate.
_PG_ASSERTION = re.compile(
    r"(?:\b(?:packing\s+group|pack\s+group|pg|group)\b\s*(?:is|:|=)?\s*"
    r"(I{1,3}|[123])\b)"
    r"|(?:^\s*(?:answer\s*:\s*)?(I{1,3}|[123])\s*\.?\s*$)",
    re.IGNORECASE | re.MULTILINE)

_PG_ARABIC = {"1": "I", "2": "II", "3": "III"}

_BARE_NUM = re.compile(r"^\s*-?(?:\d[\d,]*(?:\.\d+)?|\.\d+)\s*$")


def _pg_groups(text):
    """Every packing group the response actually ASSERTS."""
    out = set()
    for m in _PG_ASSERTION.finditer(text or ""):
        v = (m.group(1) or m.group(2) or "").upper()
        out.add(_PG_ARABIC.get(v, v))
    return {x for x in out if x}


class ExactMatchAdjudicator(BaseAdjudicator):
    def grade(self, ctx: PipelineContext, expected_val: Any, aligned_got: List[Dict[str, Any]]) -> tuple[bool, str]:
        ctx.trace_log.append({"module": "ADJUDICATOR", "action": f"ADJUDICATOR [{ctx.rule_type.upper()}]: Executing deterministic logic."})
        got_text = ctx.got_text
        exp_str = str(expected_val)
        e_tok = norm_token(self.lex(exp_str))
        g_tok = norm_token(ctx.got_text_lexed)

        if e_tok == g_tok and e_tok:
            return True, "exact match (normalized token)"

        # ⛔ ADDED 2026-08-05 — NUMERIC EQUALITY WHEN BOTH SIDES ARE PURE NUMBERS.
        #
        # 362 items in the bank (12.3% of all bare-number golds) carry a numeric gold answer
        # with gradability_class=exact_match, so they were graded by STRING equality. The CFR
        # writes decimals in legal-drafting style with no leading zero, so a gold of ".01"
        # marked a response of "0.01" WRONG — the same value, rejected on punctuation. A live
        # frontier-model run then reported those as caught hallucinations, which inflated the
        # catch rate: the defect made the product look better than it was.
        #
        # Deliberately narrow. This fires ONLY when the gold AND the response are each a
        # single bare number — no units, no prose, no lists. It cannot loosen class codes
        # against prose, and it cannot rescue a wrong value: 0.1 against .01 still fails.
        # Trailing-zero forms ("6.10" vs "6.1") also become equal, which is correct for a
        # measurement and harmless for a hazard-class code.
        if _BARE_NUM.match(exp_str) and _BARE_NUM.match(str(got_text)):
            try:
                if float(exp_str.replace(",", "")) == float(str(got_text).replace(",", "")):
                    return True, "exact match (numerically equal; differs only in written form)"
            except (ValueError, OverflowError):
                pass

        NONE_SYNONYMS = {"none", "na", "nil", "notapplicable", "n/a", "not applicable"}
        clean_exp = "".join(c for c in exp_str if c.isalnum() or c == '_').lower()
        clean_got = "".join(c for c in got_text if c.isalnum() or c == '_').lower()
        if clean_exp in NONE_SYNONYMS and clean_got in NONE_SYNONYMS:
            return True, "exact match (none / N/A synonym)"

        if ctx.exact_negated:
            return False, f"canonical value mismatch: response explicitly negates target {exp_str!r}"

        # F23 — AN OVER-GENERATION GUARD MUST BE MEASURED AGAINST THE KEY.
        #
        # These three guards catch a model hedging: offering several candidate
        # values so that one of them happens to be right. Every one of them
        # counted values in the RESPONSE alone and never asked how many the
        # ANSWER KEY has. That works while every key is a single token, and this
        # bank's keys are not: the HMT's subsidiary-hazard column yields keys
        # like "2.3, 5.1, 8" and "8, 3, 6.1" — a list of hazard classes, which is
        # the correct and complete answer.
        #
        # A response reproducing that key exactly was rejected as an exploit.
        # Measured over a fresh 700-item build, feeding every item its own gold
        # answer: 22 of 25 perfect-oracle failures were this, all in the
        # table_lookup lane. The engine could not grade its own answer key.
        #
        # The fix is the same in all three places and it does not weaken any of
        # them: fire only on values the response offers that the KEY DOES NOT
        # CONTAIN. A hedge introduces a rival; mirroring the key introduces
        # nothing. Where the key holds one value, every one of these behaves
        # exactly as before — which is why the attack cases still fail.
        exp_dotted = set(re.findall(r"\b\d{1,4}\.\d+(?:[a-z]{1,2})?(?:-\d+)?\b",
                                    self.lex(exp_str)))
        cfr_sections = ctx.got_citations
        if cfr_sections is not None and e_tok in cfr_sections:
            rival = cfr_sections - exp_dotted
            if len(rival) > 0 and len(cfr_sections) > 1:
                return False, (f"canonical value mismatch: response provides multiple competing "
                               f"CFR section numbers {sorted(cfr_sections)}; "
                               f"{sorted(rival)} do not appear in the answer key")

        aligned_values = [item["aligned_value"] for item in aligned_got if item["type"] == "EXACT"]

        got_ids = [item["value"] for item in aligned_got if item["type"] == "IDENTIFIER"]
        exp_ids = set(re.findall(r"[A-Za-z0-9][A-Za-z0-9./-]*", self.lex(exp_str)))

        if e_tok.isdigit():
            got_digits = {i for i in got_ids if i.isdigit()}
            rival = got_digits - exp_ids
            if len(got_digits) > 1 and rival:
                return False, (f"over-generation exploit detected: response provides multiple "
                               f"competing numeric identifiers {sorted(got_digits)}; "
                               f"{sorted(rival)} are not in the answer key")
        elif len(e_tok) >= 6 and e_tok[:2].lower() in ("un", "na") and e_tok[2:].isdigit():
            got_uns = {i for i in got_ids if len(i) >= 6 and i[:2].lower() in ("un", "na") and i[2:].isdigit()}
            rival = {u for u in got_uns if u.lower() not in {x.lower() for x in exp_ids}}
            if len(got_uns) > 1 and rival:
                return False, (f"over-generation exploit detected: response provides multiple "
                               f"competing UN/NA identifiers {sorted(got_uns)}; "
                               f"{sorted(rival)} are not in the answer key")

        # F18 — a disjunction offering rival answers is a hedge, not an answer.
        # Checked BEFORE the extraction fallbacks below, because each of them
        # finds the gold answer as a substring and returns True without ever
        # asking what else the response offered. Measured at 223 of 326
        # table_lookup items, whose resolved values are packing groups,
        # quantities and provision codes.
        #
        # Compares the ALTERNATIVES either side of the disjunction rather than
        # extracted tokens: roman numerals ("II or III") produce no tokens at
        # all, and "60 L or 30 kg" tokenizes into pieces that never reassemble
        # into the expected compound. Splitting the response is what actually
        # sees the shape.
        #
        # Requires >=2 distinct alternatives AND the expected to BE one of them —
        # a single answer that merely contains the word "or" is untouched.
        if ctx.has_disjunction and e_tok:
            alts = [norm_token(a) for a in re.split(r"\bor\b", ctx.got_text_lexed)]
            alts = [a for a in alts if a]
            if len(set(alts)) > 1 and any(a == e_tok or e_tok in a for a in alts):
                return False, (f"hedged answer: response offers {len(set(alts))} rival "
                               f"alternatives in a disjunction rather than one determination")

        # F15 — DO NOT HUNT PRONOUNS. EXTRACT THE ASSERTION.
        #
        # Round 1 special-cased the sentence a review quoted. Round 2 reopened it
        # with a three-word prefix ("Per the HMT, I cannot determine this.") and
        # with other phrasings the rival check could not see ("PG III", "Group
        # III"), while simultaneously REJECTING three correct answers that happened
        # to contain the pronoun. Pattern-matching where "I" sits in a sentence was
        # always going to lose that race.
        #
        # The property is simpler than the patterns: a packing group answer is an
        # ASSERTION of a group. So find the assertions. If the response asserts one
        # or more, it is correct only if the gold is among them and no rival is. If
        # it asserts none, it is not an answer — a refusal, a hedge, or prose that
        # merely contains the letter I — and the only exception is a response that
        # IS the bare token.
        # Arabic gold ("3") is the same answer as Roman ("III") — the bank uses
        # both and the equivalence is locked in by tests/test_multi_domain.py.
        _pg_gold = {"i": "I", "ii": "II", "iii": "III",
                    "1": "I", "2": "II", "3": "III"}.get(e_tok)
        if _pg_gold and (e_tok in ("i", "ii", "iii") or e_tok in got_ids):
            raw = str(got_text or "")
            asserted = _pg_groups(raw)
            if asserted:
                if _pg_gold in asserted and len(asserted) == 1:
                    return True, f"exact match (asserted packing group {_pg_gold})"
                return False, (f"response asserts packing group "
                               f"{'/'.join(sorted(asserted))}, expected {_pg_gold}")
            # No assertion anywhere. Accept only a response that IS the bare token.
            bare = norm_token(raw)
            if bare == e_tok or {"1": "i", "2": "ii", "3": "iii"}.get(bare) == e_tok \
                    or {"i": "1", "ii": "2", "iii": "3"}.get(bare) == e_tok:
                return True, "exact match (response is the bare packing group token)"
            return False, ("response asserts no packing group — the expected token "
                           "appears only as ordinary prose")

        if e_tok in got_ids:
            return True, "exact match (extracted UN/NA identifier token)"

        exp_lexed = self.lex(exp_str)
        if e_tok:
            # Word-boundary aware substring check
            idx = ctx.got_text_lexed.find(exp_lexed)
            if idx != -1:
                before_ok = (idx == 0 or not ctx.got_text_lexed[idx - 1].isalnum())
                end_idx = idx + len(exp_lexed)
                after_char = ctx.got_text_lexed[end_idx] if end_idx < len(ctx.got_text_lexed) else ""
                if after_char.isalnum():
                    after_ok = False
                elif after_char == "." and end_idx + 1 < len(ctx.got_text_lexed) and ctx.got_text_lexed[end_idx + 1].isalnum():
                    after_ok = False  # e.g. "Class 3" inside "Class 3.1"
                else:
                    after_ok = True
                if before_ok and after_ok:
                    return True, "exact match (extracted from conversational wrapper)"

        return False, f"canonical value mismatch: got {got_text!r} (normalized: {g_tok!r})"
