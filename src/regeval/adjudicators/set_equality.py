# SPDX-FileCopyrightText: 2026 SpanProof Labs
# SPDX-License-Identifier: MIT
import re
from typing import Any, List, Dict
from ..core.context import PipelineContext
from .base import BaseAdjudicator
from ..core.utils import norm_token, safe_split_set
from ..parsing.lexer import _citation_spans

# A set ELEMENT that is itself a regulatory address — "173.185", "261.24(a)".
# Used only to detect that the EXPECTED set is a list of citations, in which case
# citation tokens must NOT be stripped from the response (see F11 below).
_CITATION_ELEM = re.compile(r"^\d{2,4}\.\d{1,4}(?:\([0-9a-z]+\))*$", re.IGNORECASE)

# F25 — the bracket a citation lived in must come out with the citation.
#
# F11 below excises the citation SPAN from clean_got, but the shell it sat in
# survives: "non-combustible (see 49 CFR 173.185)." becomes
# "non-combustible (see  )." and safe_split_set() PROTECTS parenthesised text
# from splitting, so "(see)" fuses onto the last member and the answer is
# rejected for citing its own authority — the same self-contradiction the
# boolean_with_citation fix removed one lane over.
#
# It can only delete a bracket whose remaining content is entirely reference
# cues and punctuation. "(see 8)" is NOT vestigial and is left alone, so a set
# member parked inside a parenthetical is still counted. The inner class is
# `[^)\]]` — no nested quantifier, no ambiguous alternation — so matching is
# linear and cannot backtrack.
_PAREN_SPAN = re.compile(r"[\(\[]([^)\]]{0,160})[\)\]]")
_REF_CUE = frozenset((
    "see", "also", "per", "under", "pursuant", "to", "ref", "refs", "cf",
    "citing", "cite", "cited", "cites", "source", "sources", "accord",
    "in", "accordance", "with", "and", "or", "eg", "ie", "e", "g", "i",
))


def _drop_vestigial_parens(text: str) -> str:
    def _sub(m):
        toks = [w for w in re.split(r"[\s,;:.\-\u2013\u2014]+", m.group(1).lower()) if w]
        return " " if all(w in _REF_CUE for w in toks) else m.group(0)
    return _PAREN_SPAN.sub(_sub, text)


class SetEqualityAdjudicator(BaseAdjudicator):
    def grade(self, ctx: PipelineContext, expected_val: Any, aligned_got: List[Dict[str, Any]]) -> tuple[bool, str]:
        ctx.trace_log.append({"module": "ADJUDICATOR", "action": f"ADJUDICATOR [{ctx.rule_type.upper()}]: Executing deterministic logic."})
        got_text = ctx.got_text
        def _norm_set_elem(val, do_lex=False):
            s = norm_token(self.lex(str(val)) if do_lex else str(val))
            if not s: return None
            try:
                f = float(s)
                return str(int(f)) if f == int(f) else str(f)
            except ValueError:
                return s

        if isinstance(expected_val, (list, tuple, set)):
            expected_set = {_norm_set_elem(x, True) for x in expected_val if _norm_set_elem(x, True)}
        else:
            raw_exp = safe_split_set(expected_val, r"[,;&\n]|\s+[-–—]\s+|\band\b")
            expected_set = {_norm_set_elem(x, True) for x in raw_exp if _norm_set_elem(x, True)}

        # F23 — the disjunction guard must be measured against the KEY too.
        #
        # ctx.has_disjunction is set by a bare `\bor\b` search over the response.
        # The guard then reads any "or" as the model hedging between rival
        # answers when the key requires several items together. That is right
        # when the key is a conjunction and wrong when the REGULATION ITSELF is
        # disjunctive — and several of these keys are, because they are quoted
        # from the authority:
        #
        #   "the potential of producing a dangerous evolution of heat, fire,
        #    or short circuit"
        #   "marked ... on a CLASS 9 placard, an orange panel, or a white
        #    square-on-point display configuration"
        #
        # A response reproducing the key verbatim was rejected as an exploit.
        # Measured on a fresh 700-item build: 2 of 25 perfect-oracle failures.
        #
        # Fire only when the response hedges and the KEY DOES NOT. If the key
        # contains its own "or", the response is entitled to.
        if len(expected_set) > 1 and ctx.has_disjunction:
            exp_has_or = bool(re.search(r"\bor\b", str(expected_val), re.IGNORECASE))
            if not exp_has_or:
                return False, ("disjunction exploit detected: model output 'or'/'either' when "
                               "multiple items are required")

        # F9 — open-set over-claim. Checked HERE, before any equality test, so
        # the verdict never depends on a token surviving the laundering retry
        # below. The old guard was an in-band sentinel that the retry's
        # ", ".join(got_set) rewrite destroyed ("all other" -> "allother"),
        # which turned a caught hallucination into a pass on the second lap.
        if ctx.has_open_set_claim:
            return False, ("open-set hallucination detected: response enumerates the set and then "
                           "claims membership beyond it ('all other', 'etc.')")

        # F11 — a set answer that cites its source was failing for the citation.
        #
        # "UN3091, UN3481 (173.185)" put 173.185 into the response set as an
        # extraneous member and the answer was scored WRONG. Same defect as F1,
        # one lane over: 6 of the 10 remaining citation-flips on the eval bank
        # were set_equality items, not numeric ones.
        #
        # Citation tokens are dropped ONLY when the expected set contains no
        # citation of its own. If the answer legitimately IS a list of sections
        # ("which paragraphs apply?"), both sides carry them and dropping from
        # the response alone would manufacture a mismatch — so in that case
        # nothing is dropped and the comparison stays symmetric.
        expected_is_citations = any(
            _CITATION_ELEM.match(str(x) or "") for x in expected_set if x)
        drop_citations = bool(expected_set) and not expected_is_citations

        def _keep(item):
            return not (drop_citations and item.get("in_citation"))

        got_ids = {_norm_set_elem(item["value"], False) for item in aligned_got
                   if item["type"] == "IDENTIFIER" and _keep(item)}
        got_nums = {str(int(item["value"])) if item["value"] == int(item["value"]) else str(item["value"])
                    for item in aligned_got if item["type"] == "NUM" and _keep(item)}
        got_extracted = (got_ids | got_nums) - {None}
        
        # If the expected set consists of numbers/identifiers, see if the extracted ones match exactly
        if expected_set and expected_set == got_extracted:
            return True, "set equal (extracted numeric/identifiers match exactly)"

        clean_got = ctx.set_cleaned_got
        # F11, second path: the fallback splits the RAW text, so the citation has
        # to come out of the string too or it reappears as an extra member here
        # after passing the token filter above.
        if drop_citations and clean_got:
            for cs, ce in reversed(_citation_spans(clean_got.lower())):
                clean_got = clean_got[:cs] + " " + clean_got[ce:]
            # F25 — and the now-empty bracket the citation lived in.
            clean_got = _drop_vestigial_parens(clean_got)
        raw_got_parts = [_norm_set_elem(p, False) for p in safe_split_set(clean_got, r"[,;&\n]|\s+[-–—]\s+|\band\b|\bas\s+well\s+as\b") if _norm_set_elem(p, False)]
        got_set = set(raw_got_parts)

        missing = sorted(expected_set - got_set)
        extra = sorted(got_set - expected_set)

        if expected_set in ({"none"}, {"nil"}, {"n/a"}) or norm_token(str(expected_val)) in ("none", "nil", "na"):
            if not got_set or "none" in got_set or "nil" in got_set or "no" in got_set or ctx.has_none_term:
                return True, "set equal (none/empty set match)"

        ok = not missing and not extra
        
        if not ok and ctx.ttl > 1:
            from ..core.context import YieldForLaundering
            ctx.trace_log.append({"module": "ADJUDICATOR", "action": f"ADJUDICATOR [SET_EQUALITY]: Mismatch detected. Yielding for laundering."})
            # Launder the messy response by replacing verbose conjugations and yielding to lexer
            laundered_payload = ", ".join(got_set) 
            raise YieldForLaundering("lexer", laundered_payload)
            
        detail = "set equal" if ok else "set element mismatch: response set incomplete or contains extraneous tokens"
        return ok, detail
