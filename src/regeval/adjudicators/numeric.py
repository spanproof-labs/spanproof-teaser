# SPDX-FileCopyrightText: 2026 SpanProof Labs
# SPDX-License-Identifier: MIT
import re
from typing import Any, List, Dict
from ..core.context import PipelineContext
from ..core.utils import UNIT_SCALES, same_dimension, units_equivalent
from ..comparator import comparators, source_consistent
from .base import BaseAdjudicator


_UNIT_WORD = re.compile(r"\s*([a-zµ°%][a-zµ°%/.-]*)", re.IGNORECASE)
# SI-prefixed variants of the same stem are DIFFERENT magnitudes, never synonyms:
# kilowatts is not watts. Stripping a trailing "s" is the only folding done.
# ⛔ FIXED 2026-08-05 — this pattern USED TO BE r"-?\d+(?:\.(\d+))?", which REQUIRES a digit
# before the decimal point. The CFR routinely writes decimals in legal-drafting style with no
# leading zero (".01", ".001", ".354"). Against ".01" the old pattern could not match at
# position 0, so it matched the "01" AFTER the dot and parsed the value as 1 — a 100x error,
# silently, in the core scoring path.
#
# It surfaced in a live frontier-model run: the engine marked a model that answered "0.01"
# WRONG against a gold answer of ".01", and the demo then reported it as a caught
# hallucination. The defect therefore inflated the catch rate — it made the product look
# BETTER than it was, which is the direction that does the most damage in diligence.
# 127 gold answers in the bank begin with a bare decimal, concentrated in 10 CFR (NRC).
#
# Group 1 = fractional digits when an integer part is present; group 2 = fractional digits
# for a bare decimal. Callers must read `m.group(1) or m.group(2)`.
_NUM_IN_TEXT = re.compile(r"-?(?:\d+(?:\.(\d+))?|\.(\d+))")
# F22 — "8,200 kg" matched only the "8", the adjacent character was "," (not a
# unit word), so exp_word came back None and the F19 unit guard silently stood
# down: GT-K-FCC-006117 accepted "8200 g" against a kg gold — a live 1000x mass
# error. 380 comma-grouped unit-bearing golds were latently exposed. Thousands
# separators are erased before any number/unit adjacency is read.
_GROUP_COMMA = re.compile(r"(?<=\d),(?=\d{3}\b)")

# A genuine retraction of an earlier number. Every alternative below is a
# CORRECTIVE CONSTRUCTION — a speaker withdrawing what they just said — not a
# word that merely tends to appear near one. "standard" and "current" are
# deliberately absent: they are ordinary regulatory adjectives and their presence
# in the old word-list is what let a plain hedge through.
_CORRECTION_PHRASE = re.compile(
    r"\b(?:"
    r"wait[,\s]|hold on|scratch that|strike that|"
    r"actually,|i mean|my mistake|apolog|"
    r"correct(?:ion|ed to|ing that)|"
    r"revis(?:ed|ing) (?:to|that)|"
    r"supersed(?:es|ed)|"
    r"that (?:was|is) (?:wrong|incorrect)|"
    r"that was the old|"
    r"no[,\s]+(?:it|the|i|that|this|wait)\b|"
    r"i need to (?:check|verify|recheck)|let me (?:check|correct|recheck)|"
    r"on (?:second thoughts?|reflection)|"
    r"rather than"
    r")", re.IGNORECASE)

# ⚡ THE LIST CAN AFFORD TO BE GENEROUS NOW, BECAUSE POSITION DOES THE WORK.
#
# The earlier failure was never the vocabulary — it was that ANY match anywhere in
# the response disabled the guard, so an opening sentence switched it off. With
# F16b requiring the phrase to sit BETWEEN the retracted value and the replacing
# one, a prefix cannot qualify however it is worded. That frees this pattern to
# recognise real multi-step corrections ("0.05. Wait, that was the old standard.
# Actually, revised to 0.010. No, I need to check again. The level is 0.015.")
# without reopening the hole.


# ⛔ ADDED 2026-08-05 — ANGULAR DEGREES. "20 degrees from horizontal" (10 CFR 50.55a) folds
# to the unit word "degree"; a response of "20°" folds to "°". Same value, same dimension,
# graded WRONG — and then reported as a caught hallucination, which inflates the catch rate
# in the direction that flatters the seller. Found by grading a live frontier model.
# Temperature is NOT included here: "°c" and "°f" already fold correctly upstream, and
# collapsing a bare "degree" into them would make 20°C equal 20°F.
# Every entry below was found by a systematic equivalence sweep on 2026-08-05, not by
# guesswork: each pair is a form a real model actually emits, which the engine was scoring
# as a HALLUCINATION. Every one of them inflated the catch rate — the direction that
# flatters the seller and collapses in diligence. Percent was the worst: "50 percent" and
# "50%" are freely interchangeable in regulatory prose and graded as different answers.
#
# Note what is deliberately NOT here: no cross-unit conversion (hours->days, kg->lb,
# inch->mil). Those change the value's expressed dimension and the questions ask for the
# value "as published". Folding them would make the grader lenient in a way a buyer could
# attack, which is the opposite failure and the more expensive one.
_UNIT_ALIAS = {
    "degree": "°", "deg": "°", "arcdegree": "°",
    "percent": "%", "pct": "%", "percentage": "%",
    "yr": "year", "yrs": "year",
    "hr": "hour", "hrs": "hour",
    "min": "minute", "mins": "minute",
    "sec": "second", "secs": "second",
    "mo": "month", "mos": "month",
    "wk": "week", "wks": "week",
}


def _fold_unit_word(w):
    w = w.lower().rstrip(".,;:!?)")
    # Alias BEFORE de-pluralising so "yrs" and "degrees" resolve, then again after so a
    # plural of an alias target ("percentages") still lands. Two cheap lookups, no loop.
    w = _UNIT_ALIAS.get(w, w)
    w = w[:-1] if w.endswith("s") and len(w) > 2 else w
    return _UNIT_ALIAS.get(w, w)


def _adjacent_unit_word(text):
    """The unit-word bound to the FIRST number in `text`, or None."""
    if not text:
        return None
    text = _GROUP_COMMA.sub("", str(text))          # F22
    m = _NUM_IN_TEXT.search(str(text))
    if not m:
        return None
    m2 = _UNIT_WORD.match(str(text)[m.end():])
    return _fold_unit_word(m2.group(1)) if m2 else None


def _adjacent_unit_word_at(lexed, end):
    """The unit-word immediately after position `end` in the lexed text."""
    if not lexed or end >= len(lexed):
        return None
    m = _UNIT_WORD.match(lexed[end:])
    return _fold_unit_word(m.group(1)) if m else None


def _quantum_of(expected_text, expected_num):
    """The place value of the gold's least significant digit, as written.
    "1220" -> 1 · "0.015" -> 0.001 · falls back to 1 when unparseable."""
    m = _NUM_IN_TEXT.search(_GROUP_COMMA.sub("", str(expected_text or "")))
    if not m:
        return 1.0
    dec = m.group(1) or m.group(2)      # group 2 carries a bare decimal like ".015"
    return 10.0 ** -len(dec) if dec else 1.0


def _dimensionally_disjoint(m_items, nm_items, scales) -> bool:
    """True iff two numbers measure DIFFERENT kinds of thing.

    F7 — the multi-numeric guard's job is to catch a model making two
    conflicting claims about ONE quantity ("the limit is 5 L, but actually
    10 L"). It was instead counting distinct numbers, so every qualifying
    figure in ordinary regulatory prose read as a hallucination:

        "The speed limit below 10,000 feet MSL is 250 knots."   -> WRONG
        "A Form 8-K must be filed within 4 business days."      -> WRONG

    Two numbers only compete if they are commensurable. Two tests, in order:

    1. Both carry units -> compete only within the same dimension class.
       feet vs knots, feet vs minutes, days vs percent: not rivals.
    2. Exactly one carries a unit -> not rivals. This follows from the
       aligner's own list-distribution rule (F2b): a trailing unit already
       distributes backwards across a genuine alternation, so "5, 10 or 15 kg"
       arrives here with kg on ALL THREE. If one number has a unit and the
       other does not, the aligner has already determined they are not members
       of one list.

    Both dimensionless -> they DO compete. That is the conservative default and
    it is what keeps "The answer is 5 or 7" a rejection.

    Note this path is only reachable when the EXPECTED value declares no unit.
    When it does, numeric.py filters the response to that unit long before the
    conflict loop, which is why the unit-bearing lane never showed this defect.
    """
    m_units = {it.get("unit") for it in m_items if it.get("unit")}
    nm_units = {it.get("unit") for it in nm_items if it.get("unit")}

    if bool(m_units) != bool(nm_units):   # exactly one side is dimensionless
        return True
    if not m_units:                       # both dimensionless -> rivals
        return False
    return not any(same_dimension(mu, nu, scales)
                   for mu in m_units for nu in nm_units)


class NumericAdjudicator(BaseAdjudicator):
    def grade(self, ctx: PipelineContext, expected_val: Any, aligned_got: List[Dict[str, Any]]) -> tuple[bool, str]:
        ctx.trace_log.append({"module": "ADJUDICATOR", "action": f"ADJUDICATOR [{ctx.rule_type.upper()}]: Executing deterministic logic."})
        got_text = ctx.got_text
        if expected_val is None:
            # ⚠ CORRECTED 2026-08-05 — this branch tests the EXPECTED value and used to
            # report "could not parse ... from response". It named the wrong side, and it
            # cost an investigation: a grader that blames the answer for a defect in its
            # own key is worse than one that simply fails, because it sends the reader
            # looking in the wrong place. A buyer's engineer debugging a false catch would
            # have hit the same wall.
            #
            # ⚠ NOT the branch that fires on the word-unit xfails in
            # tests/test_unit_word_equivalence.py — those reach the `not aligned_values`
            # return further down, which is a RESPONSE-side alignment failure: the
            # response's unit did not fold to the expected one, so no candidate value was
            # aligned. Both branches previously printed the same sentence, which is what
            # made the two indistinguishable. They now say different things.
            return False, ("could not parse a numerical value from the EXPECTED answer "
                           "(the item's own key, not the response). Response was: "
                           f"{got_text[:60]!r}")
        expected_num = float(expected_val)
        tol = ctx.tolerance or 0.0
        # F20 — the implicit proportional floor (0.1% of the gold) exists to
        # absorb float noise, but on large integers it silently became an
        # off-by-one licence: gold 1220 carried tolerance 1.22, so 1221 passed.
        # Measured at 10.9% of expansion items (2,095 of 19,139) and corpus-wide.
        # For a reportable quantity or a CT value, 1221 is a WRONG ANSWER.
        #
        # The implicit floor is therefore capped at half the QUANTUM of the gold
        # as written: "1220" quantizes at 1 -> cap 0.5, so 1221 can never pass
        # implicitly; "0.015" quantizes at 0.001 -> cap 0.0005. An EXPLICIT
        # declared tolerance is untouched — if the item says ±5, ±5 governs.
        implicit = min(0.001 * abs(expected_num), 0.5 * _quantum_of(ctx.expected_text, expected_num))
        effective_tol = max(tol, implicit)

        expected_resolved = ctx.expected_resolved
        eu = next((r["value"] for r in expected_resolved if r["type"] == "UNIT"), None)
        
        if eu:
            # F13b — match on the FOLDED unit. This read `item.get("unit") == eu`,
            # a raw string compare, so a response saying "50%" against a gold of
            # "50 percent" produced expected='%' and aligned unit='percent',
            # matched nothing, and returned "no value aligned to the expected
            # unit (expected unit '%', response unit '%')" — a message that prints
            # the folded forms and so shows two identical units while rejecting
            # the answer. The engine was calling a correct answer a hallucination
            # and saying why in a way that read as a contradiction.
            #
            # units_equivalent() only collapses spellings of the SAME unit; a real
            # dimension mismatch ("50 watts" vs "50 kilowatts") still fails here,
            # which is the fail-OPEN case F19 below exists to prevent.
            aligned_values = [item["aligned_value"] for item in aligned_got
                              if item["type"] == "NUM"
                              and units_equivalent(item.get("unit"), eu)]
        else:
            # F19 — this branch used to accept EVERY number when the expected
            # unit did not resolve through the pack's unit map. That is fail-OPEN:
            # on the FCC pack (empty unit map) "50 watts" accepted "50 kilowatts"
            # — a 1,000x transmit-power error scored correct, measured on 41.2%
            # of FCC items and 17.9% of all unit-bearing expansion items. EPA at
            # 0.1% proved the mechanism: rich map -> filter works; empty map ->
            # filter silently OFF.
            #
            # When the maps cannot resolve a unit, fall back to the WORDS. If the
            # expected text binds a unit-word to its number, a response number
            # whose adjacent unit-word differs is not an answer to the same
            # question. Lexical, stdlib, deterministic — and fail-closed: an
            # unconvertible-but-correct unit ("240 minutes" for "4 hours" with no
            # scale in the pack) is now rejected, which is a FALSE NEGATIVE, the
            # direction this instrument deliberately errs in.
            exp_word = _adjacent_unit_word(ctx.expected_text)
            if exp_word:
                aligned_values = []
                for item in aligned_got:
                    if item["type"] != "NUM":
                        continue
                    got_word = _adjacent_unit_word_at(ctx.got_text_lexed, item.get("end", 0))
                    if got_word is None or got_word == exp_word:
                        aligned_values.append(item["aligned_value"])
            else:
                aligned_values = [item["aligned_value"] for item in aligned_got if item["type"] == "NUM"]

        try:
            e_str = str(int(expected_num)) if expected_num == int(expected_num) else str(expected_num)
        except (OverflowError, ValueError):
            e_str = str(expected_num)
        # Comparator consistency against the pinned source (regeval.comparator).
        # Regulations state most constants WITH a comparator, so "No more than 5 years."
        # is how a correct free-text answer reads. When a source span is pinned and the
        # response attaches ANY comparator to the target value:
        #   - it must be a comparator the source attaches to that value, or the response
        #     fails here — including the forms the lexer guard never saw ("5 years or
        #     more", "up to", "within"), which used to pass unchecked;
        #   - if it is, the inequality/negation guards below are waived. Waiving is not
        #     accepting: every check after this one still runs.
        # With no pinned source, behaviour is unchanged.
        #   - if the source is ambiguous about the value (several comparators on it), or a
        #     bare negation remains, nothing is decided here and the guards run unchanged.
        if ctx.source_text:
            resp_cmp, _ = comparators(got_text, expected_num)
            if resp_cmp:
                verdict, why = source_consistent(got_text, ctx.source_text, expected_num)
                ctx.trace_log.append({"module": "ADJUDICATOR", "action": "COMPARATOR CHECK "
                                      f"{ {True: 'passed', False: 'failed', None: 'undecided'}[verdict] }: {why}"})
                if verdict is False:
                    return False, f"comparator inconsistent with pinned source: {why}"
                if verdict is True:
                    ctx.comparator_waiver = why
        if ctx.numeric_inequality and not ctx.comparator_waiver:
            return False, f"mathematical inequality exploit detected: target value {e_str} is modified by inequality term in response"

        # Numeric negation detection: reject 'not 500 kg', 'never 500 kg', etc.
        if ctx.numeric_negated and not ctx.comparator_waiver:
            return False, f"numeric negation exploit detected: target value {e_str} is explicitly negated in response"

        if expected_num == 0.0:
            if aligned_values == [0.0] or ctx.has_zero_term:
                return True, "numeric evaluation complete (implicit zero / unlimited match)"

        if not aligned_values:
            # Distinguished from the expected-side failure above, which used to print this
            # same sentence. "No aligned value" almost always means the response DID carry
            # a number but its unit did not fold to the expected unit — the open word-unit
            # defect in tests/test_unit_word_equivalence.py lands here. Naming the unit
            # makes that visible instead of looking like the model answered nothing.
            exp_unit = _adjacent_unit_word(str(ctx.expected_text or "")) or "none"
            got_unit = _adjacent_unit_word(str(got_text or "")) or "none"
            return False, (f"no value in the response aligned to the expected unit "
                           f"(expected unit {exp_unit!r}, response unit {got_unit!r}): "
                           f"{got_text[:60]!r}")

        distinct_nums = set(aligned_values)
        matching_values = [val for val in distinct_nums if abs(expected_num - val) <= effective_tol]
        non_matching_values = [val for val in distinct_nums if abs(expected_num - val) > effective_tol]

        if len(distinct_nums) > 1:
            is_range = ctx.has_range_expression
            if is_range and matching_values:
                return True, "numeric evaluation complete (metrological range expression matched bound)"

            if matching_values:
                # Determine agency context for Jurisdiction Proximity
                config_name = getattr(ctx, "config_name", "") or ""
                if not config_name and self.config:
                    config_name = self.config.get("domain", {}).get("name", "")
                
                agency_map = {
                    "epa": ["epa", "rcra", "cercla", "40 cfr"],
                    "osha": ["osha", "29 cfr"],
                    "fda": ["fda", "21 cfr"],
                    "hazmat": ["hazmat", "dot", "phmsa", "49 cfr"],
                    # F14 — bare "sec" REMOVED from this list. It is three things
                    # at once: the Securities and Exchange Commission, the unit
                    # "seconds", and the abbreviation for "section". Matching it
                    # as an agency meant any response containing the word marked
                    # conflicting numbers as foreign-jurisdiction decoys and
                    # FORGAVE them — "The answer is 3, see sec. 40." graded
                    # CORRECT, and so would "done in 30 sec". A false positive
                    # reachable by an innocent word. SEC items still resolve via
                    # title_map["17"] and the config's own domain name, which are
                    # unambiguous; only the ambiguous token is gone.
                    "sec": ["17 cfr", "securities and exchange"],
                    "faa": ["faa", "14 cfr"]
                }
                title_map = {
                    "40": "epa",
                    "29": "osha",
                    "21": "fda",
                    "49": "hazmat",
                    "17": "sec",
                    "14": "faa",
                }
                cname_lower = config_name.lower()
                dname_lower = self.config.get("domain", {}).get("name", "").lower() if self.config else ""
                target_agency_name = ""
                if self.config and "domain" in self.config:
                    cfr_title = str(self.config["domain"].get("cfr_title", ""))
                    if cfr_title in title_map:
                        target_agency_name = title_map[cfr_title]

                if not target_agency_name:
                    for a_key in agency_map:
                        if a_key in cname_lower or a_key in dname_lower:
                            target_agency_name = a_key
                            break

                text_lower = got_text.lower()
                # F16 — A SELF-CORRECTION IS A CONSTRUCTION, NOT A VOCABULARY.
                #
                # This tested `any(word in text)` over
                # ["wait","actually","revised","current","settled","standard",
                #  "corrected","rather"]. Two of those — "standard" and "current" —
                # are unavoidable in regulatory prose, so the multi-numeric hedge
                # guard switched itself off on ordinary sentences:
                #
                #   "The standard limit is 5 kg or 10 kg."          -> ACCEPTED
                #   "The limit is 5 kg or 10 kg."                   -> rejected
                #
                # Identical hedge; one word apart. A model writing "under the
                # current standard" — which is how regulatory text reads — got a
                # free pass to offer two rival values and be graded on the one that
                # happened to be right. That is the exploit the guard exists to
                # stop, and eight common words disabled it.
                #
                # What the guard is actually for is a genuine self-correction, where
                # a later value SUPERSEDES an earlier one ("wait, actually it's
                # 10 kg"). That has a recognisable shape, so match the shape.
                # A bare adjective is not a retraction.
                has_settlement = bool(_CORRECTION_PHRASE.search(text_lower))

                def get_governing_agency(pos: int):
                    matches = []
                    for agency_key, kws in agency_map.items():
                        for kw in kws:
                            pattern = r"\b" + r"\s+".join(re.escape(w) for w in kw.split()) + r"\b"
                            for m in re.finditer(pattern, text_lower[:pos]):
                                matches.append((m.start(), agency_key))
                    if matches:
                        matches.sort(key=lambda x: x[0], reverse=True)
                        return matches[0][1]
                    return None

                aligned_items = [item for item in aligned_got if item["type"] == "NUM"]
                valid_match = False
                for m_val in matching_values:
                    m_items = [it for it in aligned_items if abs(it["aligned_value"] - m_val) <= effective_tol]
                    m_pos = min(it.get("start", 0) for it in m_items) if m_items else 0

                    m_agency = get_governing_agency(m_pos)
                    if target_agency_name and m_agency and m_agency != target_agency_name:
                        continue

                    unresolved_hallucination = False
                    for nm_val in non_matching_values:
                        # F5 — this comparison was `> effective_tol`, which selected
                        # every token EXCEPT the one carrying nm_val (in practice,
                        # the MATCHING token). `nm_pos` therefore reported the
                        # matching value's position to the agency-proximity test,
                        # and the CoT exemption above would have read the wrong
                        # tokens too. Selects the nm_val tokens now, as the name says.
                        nm_items = [it for it in aligned_items if abs(it["aligned_value"] - nm_val) <= effective_tol]
                        nm_pos = min(it.get("start", 0) for it in nm_items) if nm_items else 0

                        nm_str = str(int(nm_val)) if nm_val == int(nm_val) else str(nm_val)
                        # F6 — `is_citation_num` used to live here:
                        #
                        #   bool(re.search(r"\b" + re.escape(nm_str) +
                        #                  r"\s*(?:cfr|usc|part|section|subpart)\b", text_lower))
                        #
                        # It matched on VALUE, not on position, so any hallucinated
                        # quantity that happened to equal a number appearing before
                        # a citation keyword was forgiven. In every domain the CFR
                        # title itself is such a number: with "49 CFR 173.202" in
                        # the text, a decoy of "49 kg" was laundered into a pass —
                        # 49 for hazmat, 40 for EPA, 29 for OSHA, and so on. Found
                        # by the adversarial sweep, confirmed in all 12 domains.
                        #
                        # It is also now redundant: align() drops citation-span
                        # numbers before adjudication, so a genuine citation number
                        # can no longer reach this loop at all. Removing it closes
                        # the hole without losing any legitimate forgiveness.
                        is_citation_num = False

                        nm_agency = get_governing_agency(nm_pos)
                        is_foreign_decoy = bool(target_agency_name and nm_agency and nm_agency != target_agency_name)
                        # F16b — A RETRACTION MUST SIT BETWEEN THE TWO NUMBERS.
                        #
                        # `has_settlement` only asked whether a corrective phrase
                        # appeared ANYWHERE in the response. So an ordinary opening
                        # sentence — "This section supersedes the 1998 rule." or
                        # "Apologies for the delay." — switched the hedge guard off
                        # for the rest of the text, and the corpus itself contains
                        # those triggers 1,993 times.
                        #
                        # Round 1 replaced a word list with a phrase list and the
                        # same attack worked with ten new prefixes, because the
                        # defect was never the vocabulary. It was that POSITION was
                        # not required.
                        #
                        # A genuine self-correction retracts something already said:
                        # the corrective phrase comes AFTER the value being
                        # withdrawn and AT OR BEFORE the value replacing it. A
                        # prefix sits before both and can never satisfy that, no
                        # matter which words it uses.
                        _corr = [mm.start() for mm
                                 in _CORRECTION_PHRASE.finditer(text_lower)]
                        nm_is_superseded = (m_pos > nm_pos
                                            and any(nm_pos < c <= m_pos for c in _corr))
                        # F4 — `is_target_proximate` used to sit in this disjunction:
                        #
                        #     is_target_proximate = (m_agency == target_agency_name)
                        #
                        # It forgave EVERY conflicting value as soon as the matching
                        # value was preceded by an in-domain agency mention. That is
                        # not a hallucination test, it is an unconditional pass: with
                        # "49 CFR" anywhere upstream, "the limit is 0.5 kg or 40 kg or
                        # 7 kg" graded CORRECT, while the identical sentence without
                        # the citation was correctly rejected. A hallucinated answer
                        # laundered into an audit receipt is the worst failure this
                        # engine has.
                        #
                        # It existed to paper over F1 — citation numbers polluting the
                        # conflict set. Now that citation spans are masked in the
                        # aligner, the pollution is gone at the root and the blanket
                        # forgiveness has nothing legitimate left to forgive. Deleting
                        # it restores the guard. `is_foreign_decoy` (a DIFFERENT
                        # agency's number) is a real rule and stays.
                        # F12 — CHAIN-OF-THOUGHT EXEMPTION POLARITY. Resolved
                        # 2026-07-26; rationale and the discarded alternative are
                        # in docs/DECISION-cot-polarity.md.
                        #
                        # This read m_items — the tokens that MATCH the expected
                        # answer — which meant a value found ONLY in a scratchpad
                        # was credited even when the model's stated answer
                        # contradicted it. Under that reading, a model that
                        # reasoned "0.015" and then told the user "25" graded
                        # CORRECT. The engine's own headline claim is that
                        # reasoning traces are stripped and only the final answer
                        # is graded; that behaviour was the opposite of it, and it
                        # is gameable — emit every plausible value inside <think>
                        # and score well regardless of what you conclude.
                        #
                        # The exemption's purpose is to forgive a CONFLICTING
                        # number that came from the scratchpad, which is nm_items.
                        # A response that deliberates and then commits to an
                        # answer is still graded on the answer it committed to.
                        is_cot_reasoned = any(it.get("is_cot", False) for it in nm_items)

                        # F7 — a QUALIFYING figure about a different quantity is
                        # not a conflicting claim about this one. See
                        # _dimensionally_disjoint. This is the exemption that
                        # makes the engine domain-general: without it every
                        # regulatory sentence carrying an altitude, a filing
                        # window or a duration beside its answer graded WRONG,
                        # in every domain config, not only FAA and SEC.
                        scales = (self.config or {}).get("_unit_scales_tuples") or UNIT_SCALES
                        is_other_quantity = _dimensionally_disjoint(m_items, nm_items, scales)

                        if not (is_foreign_decoy or nm_is_superseded or is_cot_reasoned
                                or is_citation_num or is_other_quantity):
                            unresolved_hallucination = True
                            break

                    if not unresolved_hallucination:
                        valid_match = True
                        break

                if valid_match:
                    return True, f"numeric evaluation complete (tolerance {effective_tol:g})"
                else:
                    return False, f"multi-numeric hallucination exploit detected: multiple conflicting numbers in response {sorted(distinct_nums)}"
            else:
                return False, f"multi-numeric hallucination exploit detected: multiple conflicting numbers in response {sorted(distinct_nums)}"

        matched = any(abs(expected_num - val) <= effective_tol for val in aligned_values)
        if matched:
            return True, f"numeric evaluation complete (tolerance {effective_tol:g})"
        return False, f"numeric evaluation complete (tolerance {effective_tol:g})"
