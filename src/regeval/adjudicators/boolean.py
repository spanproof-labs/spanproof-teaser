# SPDX-FileCopyrightText: 2026 SpanProof Labs
# SPDX-License-Identifier: MIT
import re
from typing import Any, List, Dict
from ..core.context import PipelineContext
from .base import BaseAdjudicator
from ..core.utils import cite_parts

# A docket / letter / interpretation reference: "00-0227", "05-0123", "PHMSA-2021-0109".
# cite_parts() only understands CFR SECTION ADDRESSES and returns nothing for these,
# which is how the grounding check came to be silently skipped for every one of them.
_REFERENCE_TOKEN = re.compile(r"\b[A-Z]{0,6}-?\d{2,4}-\d{3,5}\b", re.IGNORECASE)


def _authority_produced(required_cite, response):
    """Did the response actually name a NON-CFR authority? (bool, what_was_wanted)

    The grounding requirement is that a correct answer identify the authority it
    rests on. For a CFR section that is a parsed address comparison. For an agency
    letter it is the reference number, which is the only part a reader could look up
    — "PHMSA Interpretation 00-0227", "Ref. No. 00-0227" and "letter 00-0227" all
    satisfy it, while "PHMSA has interpreted this" does not.
    """
    refs = set(m.group(0).lower() for m in _REFERENCE_TOKEN.finditer(required_cite or ""))
    low = (response or "").lower()
    if refs:
        return (any(r in low for r in refs), sorted(refs))
    # No reference number to key on: fall back to the citation's own distinctive
    # words. Deliberately conservative — better to ask for the authority twice than
    # to assert a check that did not run.
    words = [w for w in re.findall(r"[A-Za-z0-9.]{4,}", required_cite or "")]
    if not words:
        return (True, [])            # nothing checkable was ever supplied
    return (all(w.lower() in low for w in words), words)

class BooleanAdjudicator(BaseAdjudicator):
    def grade(self, ctx: PipelineContext, expected_val: Any, aligned_got: List[Dict[str, Any]]) -> tuple[bool, str]:
        ctx.trace_log.append({"module": "ADJUDICATOR", "action": f"ADJUDICATOR [{ctx.rule_type.upper()}]: Executing deterministic logic."})
        got_text = ctx.got_text
        eb = ctx.boolean_answer
        if eb is None:
            eb = expected_val
        if isinstance(eb, str):
            eb_lower = eb.lower()
            expected_bool = True if ("yes" in eb_lower or "true" in eb_lower or "permitted" in eb_lower or "allowed" in eb_lower) else False
        elif isinstance(eb, bool):
            expected_bool = eb
        else:
            expected_bool = True if "yes" in str(expected_val).lower() or "true" in str(expected_val).lower() else False

        gb = None
        if ctx.got_boolean_polarity is not None:
            gb = ctx.got_boolean_polarity
        else:
            got_bool_items = [item for item in aligned_got if item["type"] == "BOOLEAN"]
            if got_bool_items:
                gb = got_bool_items[0]["value"]

        # F16 — a response offering both polarities is a hedge, not a
        # determination. Checked BEFORE polarity, because polarity reads the
        # first marker and would otherwise credit the leading half of a hedge.
        if ctx.boolean_hedged:
            return False, ("hedged determination: response asserts both polarities "
                           "(\"yes or no\") rather than answering")

        if gb is None:
            return False, f"response did not begin with a yes/no determination: {got_text[:80]!r}"
        if expected_bool != gb:
            return False, f"polarity wrong: got {'yes' if gb else 'no'}"

        required_cite = ctx.citation
        if required_cite:
            def_title = self.config.get("domain", {}).get("cfr_title", "49") if self.config else "49"
            req_parts = cite_parts(required_cite, default_title=def_title)
            # A BARE section number in the answer means the section under discussion,
            # not title 49.
            #
            # This default used to fall through to "49" for the answer text as well,
            # which is safe in a single-title world and wrong in an eleven-title one.
            # An answer about 10 CFR 26.155 that names it once in full and once bare —
            # "10 CFR 26.155 is [Reserved] ... the heading reads '§ 26.155 [Reserved]'"
            # — parsed as TWO sections, 10:26.155 and 49:26.155. The second is a title
            # the answer never mentioned, so the over-citation check below rejected a
            # correct answer for citing something it did not cite. Measured on the
            # reserved-section shard: 33 of 98 gold answers failed their own grader
            # this way, every one of them outside title 49.
            #
            # verify.py never caught it because its perfect responder emits the
            # citation exactly once, fully qualified. That is the same shape as the
            # refusal defect found alongside this one: the instrument was built to
            # avoid the case where the engine breaks.
            req_title = next((s.split(":", 1)[0] for s, _ in req_parts if ":" in s), def_title)
            got_parts = cite_parts(got_text, default_title=req_title)
            if req_parts:
                req_secs = {s for s, _ in req_parts}
                got_secs = {s for s, _ in got_parts}
                if not (req_secs & got_secs):
                    return False, "polarity correct but required citation was not produced — ungrounded correct answers do not count"

                if ctx.citation_inverted:
                    return False, "citation inversion exploit detected: response negates applicability of required citation"

                extraneous = got_secs - req_secs
                if len(extraneous) > 0:
                    return False, f"over-citation exploit detected: produced extraneous section citations {sorted(extraneous)}"

                for sec, para in req_parts:
                    if not para:
                        continue
                    got_paras = {p for s, p in got_parts if s == sec}
                    if para not in got_paras:
                        return False, f"polarity correct but operative paragraph citation was missing or incorrect for section {sec}"
                    req_paras_all = {p for s, p in req_parts if s == sec and p}
                    extraneous_paras = got_paras - req_paras_all
                    if len(extraneous_paras) > 0:
                        is_para_range = ctx.has_para_range
                        if not (is_para_range and len(extraneous_paras) <= 2):
                            return False, f"over-citation exploit detected: produced multiple extraneous paragraph citations {sorted(extraneous_paras)} for section {sec}"
            else:
                # THE REQUIRED CITATION IS NOT A CFR SECTION, AND THE CHECK USED TO
                # VANISH HERE.
                #
                # `if req_parts:` guarded the ENTIRE grounding block, and cite_parts()
                # returns nothing for an agency letter — "PHMSA Interpretation
                # 00-0227" and every other non-CFR authority. So for those items no
                # citation check ran at all, and control fell through to a terminal
                # `return True, "polarity correct with required citation present"`
                # that asserted a check which had not happened.
                #
                # Measured: all 90 required citations in the shipped eval bank are
                # PHMSA Interpretation references, i.e. the grounding requirement was
                # dead across the whole lane — 18.7% of the published catch-rate
                # denominator. A bare "Yes." scored correct, and so did "Yes. See 49
                # CFR 999.999." with a fabricated citation. For an asset whose claim
                # is that it only credits GROUNDED answers, that message was the most
                # damaging string in the codebase.
                ok, wanted = _authority_produced(required_cite, ctx.got_text)
                if ok:
                    return True, f"polarity correct; required authority {wanted} produced"

                # THE NAMED CITATION IS A SOURCE DOCUMENT, NOT THE GROUND OF THE
                # ANSWER — and demanding it was a false rejection of 247 correct
                # answers in the flagship bank.
                #
                # LOI-lane items name "PHMSA Interpretation 00-0362" as their
                # citation: that is where the QUESTION came from. The answer is true
                # because of 49 CFR 107.601, which the gold answer cites and which is
                # pinned on the item. Requiring the letter number would demand the
                # responder know which agency letter a question was derived from —
                # not a thing regulatory grounding means, and not something any
                # correct answer would contain.
                #
                # So grounding is satisfied by the named authority OR by any
                # authority the item itself pins. A bare "Yes." still fails: it
                # produces neither.
                for sup in (ctx.supporting_citations or []):
                    sup_parts = cite_parts(sup, default_title=def_title)
                    if sup_parts:
                        if {s for s, _ in sup_parts} & {s for s, _ in got_parts}:
                            return True, ("polarity correct; grounded in the pinned "
                                          f"authority {sup!r}")
                    elif _authority_produced(sup, ctx.got_text)[0]:
                        return True, ("polarity correct; grounded in the pinned "
                                      f"authority {sup!r}")

                return False, ("polarity correct but no pinned authority was produced "
                               f"(wanted {wanted} or one of "
                               f"{list(ctx.supporting_citations or [])[:3]}) — "
                               "ungrounded correct answers do not count")

        return True, ("polarity correct; no citation was required by this item"
                      if not required_cite else
                      "polarity correct with required citation present")
