# SPDX-FileCopyrightText: 2026 SpanProof Labs
# SPDX-License-Identifier: MIT
import re
from typing import Optional, List, Dict, Any
from .ast_parser import SemanticParser, HypotheticalClauseNode, CodeFenceNode, BooleanAssertionNode, XMLFenceNode
from ..core.context import PipelineContext
from ..core.utils import (KNOWN_UNITS, UNIT_MAP, UNIT_SCALES, is_known_unit, restore_exponent, norm_token, _safe_stem,
                          fold_unit)

# ── F1: regulatory citation spans ────────────────────────────────────────────
# A number inside a citation is an ADDRESS, not a quantity. "49 CFR 173.202"
# contains no measurement, but the tokenizer used to emit 173.202 as a NUM,
# where it collided with the real answer and tripped the multi-numeric
# hallucination guard. Measured effect before this fix: a correct answer flipped
# to WRONG on 43/175 control-correct eval items (100% of the numeric lane) purely
# for citing its source.
#
# The old guard here only skipped a number IMMEDIATELY FOLLOWED by "CFR"/"USC"
# — i.e. the title ("49"), never the section number after it, which is the one
# that actually collides. Both directions are covered now.
#
# Matched against post-lex() text: lowercased, with "§" already replaced by a
# space. Anchored on an explicit citation keyword, so a bare decimal is never
# masked — masking is a suppression of a CONFLICT signal, and over-masking would
# blind the guard rather than fix it.
# WHY THE SHAPE OF THE NUMBER MATTERS, not just the keyword in front of it.
#
# The first version of this pattern masked any number following a citation
# keyword. An adversarial sweep broke it in one line: writing "section" in front
# of a decoy deleted the decoy from the conflict set, so
#     "The answer is 3, see section 40."      graded CORRECT
#     "The answer is 3, or 40."               graded WRONG (correctly)
# — a hallucinated quantity laundered into a pass by one word, in all 12 domain
# configs. A first attempt to fix it by requiring the masked number to carry no
# unit ("an address never has a unit") closed only the unit-bearing lane; the
# unitless numeric lane has no unit to test, so it stayed open.
#
# The durable discriminator is STRUCTURAL. A CFR section address is dotted —
# 173.202, 261.24, 1910.1000 — and a bare integer is not an address unless a
# keyword explicitly qualifies it inside a full citation. So:
#
#   STRONG anchor (a title + CFR/USC): trust it, but still require either a
#     dotted section or an explicit part/subpart keyword, so a bare "49 CFR 40"
#     cannot be used as a hiding place either.
#   WEAK anchor (a bare "section"/"part"/"paragraph" with no title): mask ONLY a
#     dotted address. A bare integer after a weak keyword is indistinguishable
#     from a decoy, so it is left in the conflict set.
#
# The deliberate trade: "under part 173, the limit is 0.5 kg" (weak anchor, bare
# integer) is no longer masked and can still flip a correct answer. That is a
# FALSE NEGATIVE — an unfairly harsh grade. The alternative is a FALSE POSITIVE —
# a hallucination sold as correct. For a compliance instrument those are not
# comparable costs, and this errs toward the harsh one on purpose.
_CIT_TAIL = (r"(?:\s*\([0-9a-z]+\))*"
             r"(?:\s*(?:-|to|through|and)\s*\d+(?:\.\d+)*(?!\d)"
             r"(?!\s*(?:cfr|c\.|usc|u\.|fr\b|stat))(?:\s*\([0-9a-z]+\))*)*")
_CIT_ANCHOR = r"(?:cfr|c\.\s?f\.\s?r\.|usc|u\.\s?s\.\s?c\.|fr|stat)"
# Abbreviated forms included: the sweep showed the verdict otherwise depended on
# whether a model wrote "Sec. 173.202" or "section 173.202" — same citation, same
# answer, different grade. Safe to admit now that a WEAK anchor only ever masks a
# DOTTED address, so a bare "pt 5" cannot hide anything.
# "sec."/"secs." were held out until F14. numeric.py's agency_map used to match
# the bare token "sec" as the SEC, so the word forgave conflicting numbers through
# an unrelated path and admitting it here would have looked like a citation fix
# while riding a pre-existing false-positive channel. That token is gone from
# agency_map now, so the abbreviation is safe to accept — and it is still only
# ever able to mask a DOTTED address, so "see sec. 40" cannot hide anything.
_CIT_KEYWORD = (r"(?:parts?|pts?\.?|subparts?|sections?|secs?\.?|subsecs?\.?"
                r"|paragraphs?|paras?\.?|appendix|appendices"
                r"|chapters?|chs?\.?|titles?)")

# F7b — NAMED REGULATORY INSTRUMENTS: Form 10-K · Schedule 13G · Form S-1.
#
# The digits belong to the instrument's NAME, exactly as the digits in
# "49 CFR 173.202" belong to an address. The tokenizer emitted them as
# quantities, so "the Form 10-K is due in 60 days" carried a phantom 10 that
# collided with the answer 60 and tripped the multi-numeric guard. Same class of
# defect as F1; measured on 3 of the 6 SEC domain tests.
#
# It obeys the STRUCTURAL rule the sweep established above, because "form" and
# "rule" are weak anchors and a bare integer behind a weak anchor is a laundering
# hole ("The answer is 3, see rule 40."). An instrument designator is not a bare
# integer: it carries an alphabetic component — 10-K, 8-K, 13G, S-1 — that a
# quantity never has. So the letter is REQUIRED, and "rule 40" is deliberately
# left in the conflict set. False-negative direction, on purpose, same as F1.
_INSTRUMENT_KEYWORD = r"(?:forms?|schedules?|rules?|regulations?)"
_INSTRUMENT_DESIGNATOR = (r"(?:[a-z]{1,3}-\d{1,4}[a-z]?"      # S-1, SB-2
                          r"|\d{1,4}(?:\.\d+)?-?[a-z]{1,2})")  # 10-K, 8-K, 13G

_CITATION_SPAN_PAT = re.compile(
    # STRONG, dotted section:      49 CFR 173.202(a)(1) · 29 U.S.C. 1910.1000
    r"\b\d{1,2}\s*" + _CIT_ANCHOR + r"\.?\s*\d+\.\d+" + _CIT_TAIL +
    r"|"
    # STRONG, keyword-qualified:   49 CFR Part 173 · 40 CFR subpart 261
    r"\b\d{1,2}\s*" + _CIT_ANCHOR + r"\.?\s*" + _CIT_KEYWORD + r"\s*\d+(?:\.\d+)*" + _CIT_TAIL +
    r"|"
    # WEAK anchor — DOTTED ONLY:   section 173.202 · paragraph 173.185(f)(2)
    r"\b" + _CIT_KEYWORD + r"\s*\d+\.\d+" + _CIT_TAIL +
    r"|"
    # INSTRUMENT — LETTERED DESIGNATOR ONLY:  Form 10-K · Schedule 13G · Form S-1
    r"\b" + _INSTRUMENT_KEYWORD + r"\s+" + _INSTRUMENT_DESIGNATOR + r"\b",
    re.IGNORECASE,
)


# F2b — when may a UNIT bind to a NUMBER?
#
# The aligner used to bind the NEAREST unit at ANY distance, so in
# "60 Wh (173.185)" the section number silently acquired "Wh" and became a rival
# 173.185 Wh measurement that collided with the real answer. But a flat distance
# cap is too blunt: in "between 5 and 10 mg/l" the trailing unit legitimately
# distributes backwards across the whole numeric list, and capping distance
# breaks that (it did — tests/test_adversarial_crucible.py::test_range_expression_accepted).
#
# So the rule is direction-aware:
#   unit AFTER the number  — bind if everything between them is other numbers and
#                            list connectives ("5 and 10 mg/l", "5, 10 or 15 kg").
#                            Prose in between means the unit belongs to something
#                            else.
#   unit BEFORE the number — bind only if truly adjacent. Units follow their
#                            numbers in this corpus, so a preceding unit that is
#                            not touching is someone else's. This is the case
#                            that disarms "60 Wh (173.185)".
#
# KNOWN LIMIT, corrected 2026-07-26: an earlier version of this comment claimed
# this rule also covers the "§ 173.202" form. It does not. lex() rewrites "§" to
# a space BEFORE _citation_spans() runs, so the anchor is gone and a BARE
# "§173.202" is never masked — it is only saved when a title survives alongside
# it ("49 CFR § 173.202" still grades correctly). Blast radius on today's corpus
# is zero (it contains no "§"), but table_lookup.py and pipeline.py both EMIT
# §-form citations, so this goes live the moment real model output arrives.
# Polarity is false-negative: a correct answer graded harshly, never a wrong one
# passed.
#
# The bridge is capped so the scan stays O(1) per number and the engine keeps its
# linear-time guarantee.
_UNIT_BRIDGE_MAX = 40
_UNIT_BACKWARD_MAX_GAP = 1
# The bridge may contain other numbers, list connectives, and the symbol
# characters that lead a unit token ("-5 °C" bridges " °" because the unit
# regex starts matching at the "c"). It may NOT contain letters or brackets —
# those mean prose or a parenthesised citation, i.e. a different owner.
_NUMERIC_LIST_BRIDGE = re.compile(
    r"^[\s\d.,;:°µ%/]*(?:(?:and|or|to|through|-|~)[\s\d.,;:°µ%/]*)*$", re.IGNORECASE)


# Used only when align() has no trustworthy text: distance can still be judged
# from the tokens' own offsets, but the bridge CONTENT cannot, so the bound is
# tight. This must never be more permissive than the explicit path.
_UNIT_ADJACENCY_STRICT = 2


def _cache_matches(text: str, resolved: List[Dict[str, Any]]) -> bool:
    """True iff `text` is plausibly the text these tokens were produced from.

    align() falls back to the last-tagged text when a legacy 3-arg caller gives
    it none. That text belongs to whatever was tagged last, which may be a
    DIFFERENT string — tagging `expected` after `got` was enough to turn
    (5.0, None) into (5.0, 'kg') by making a distant unit look adjacent.

    Rather than trust or guess, verify: a token's recorded span must actually
    contain its own raw value in the candidate text. Cheap, exact, and it fails
    closed.
    """
    probes = [r for r in resolved if r.get("raw") and isinstance(r.get("start"), int)][:4]
    if not probes:
        return False
    for r in probes:
        seg = text[r["start"]:r["end"]].strip().lower()
        if seg != str(r["raw"]).strip().lower():
            return False
    return True


def _unit_directly_attached(num_end: int, u_start: int, text: str) -> bool:
    """True iff a unit sits IMMEDIATELY after a number — "40 kg", "0.5kg".

    Deliberately stricter than _unit_binds: the list-distributing rule that lets
    a trailing unit reach back over "5 and 10 mg/l" must NOT apply here. In
    "Per 49 CFR 173.185, 60 Wh" the bridge from the section number to "Wh" is
    ", 60 " — a perfectly good numeric list — so the permissive rule would treat
    the citation as a measurement and un-mask it, undoing F1 (measured: 6 -> 39
    flipped items when this was written with _unit_binds). An intervening digit
    means the unit belongs to that digit, not to us.
    """
    if u_start < num_end:
        return False
    bridge = text[num_end:u_start]
    if len(bridge) > 2 or any(c.isdigit() for c in bridge):
        return False
    return bridge.strip(" \t") == "" or not bridge.strip(" \t").isalnum()


def _unit_binds(num_start: int, num_end: int, u_start: int, u_end: int, text: str) -> bool:
    """True iff the unit at [u_start,u_end) may claim the number at [num_start,num_end)."""
    if u_start >= num_end:                      # unit follows the number
        bridge = text[num_end:u_start]
        if len(bridge) > _UNIT_BRIDGE_MAX:
            return False
        return bool(_NUMERIC_LIST_BRIDGE.match(bridge))
    return (num_start - u_end) <= _UNIT_BACKWARD_MAX_GAP  # unit precedes it


# F9 — OPEN-SET CLAIM. "UN1090, UN1203, and all other codes" enumerates two
# items and then claims the rest of an unbounded set. In a compliance setting
# that is precisely the failure a verdict engine is bought to catch: the scored
# answer is a shipping-code set, and an over-claim graded CORRECT is laundered
# into an audit receipt.
#
# Shared by tag() (which emits an in-band sentinel token) and enrich() (which
# latches a context flag). BOTH are needed, and the reason is the whole defect:
# the sentinel was the only signal, and set_equality's laundering retry rebuilt
# the payload as ", ".join(got_set) — which destroys the space in "all other",
# so the sentinel regex no longer matched on pass 2 and the hallucination was
# accepted. Any detection carried as a TOKEN can be erased by a rewrite of the
# text it lives in; only context state survives. Verified erasure path:
#     PASS1 yields, laundered payload = 'allother, un1090, un1203'
#     sentinel present after laundering? False  ->  PASS2 accepts
_OPEN_SET_PAT = re.compile(
    r"\b(?:all|any)\s+(?:other|applicable|relevant|codes|provisions)\b"
    r"|\betc\.?\b"
    r"|\band\s+(?:others?|similar|equivalent)\b",
    re.IGNORECASE,
)


# F24 — a leading CARRIER CLAUSE is packaging, not a set member.
#
# The set lane splits the response on commas to build the response set, so a
# leading "The answer is" / "Based on the table," becomes a member. Worse, the
# existing filler strip below deletes the words but not the whitespace, and
# norm_token() removes spaces, so the residue FUSES onto the first real member:
#   "The answer is absorbent, non-combustible"
#     -> " answer  absorbent, non-combustible" -> {"answerabsorbent", ...}
# — one bogus member added AND one true member destroyed, reported as
# "extraneous tokens".
#
# THE VOCABULARY IS CLOSED ON PURPOSE. Every alternative below is a fixed
# phrase, or a fixed stem followed by an OPTIONAL determiner and a CLOSED list
# of content-free nouns, terminated by a comma or colon. There is deliberately
# no `.*` and no `[^,]*`: a wildcard here would consume arbitrary content-
# bearing text before the delimiter, and a set answer's delimiter IS the comma,
# so a wildcard turns this into a false-acceptance channel —
#   "As specified for passenger aircraft only, <gold>."   (wrong scope, credited)
#   "Based on the table 8, <gold>"                        (fabricated member eaten)
# Both are rejected by this pattern because "for passenger" and "8" are not in
# the noun list and do not terminate the stem.
#
# EXCLUDED ON PURPOSE, each for a measured reason:
#   "depending on ..."  a conditional non-answer, not a carrier. Stripping it
#                       credits a hedge; it also buys zero false-rejection.
#   "both", "following", "this is"   appear as real members in the bank
#                       (GT-E-000002's key is "both lithium metal and ...").
#   "per"               CFR prose is full of "per package", "per person".
_SET_CARRIER_NOUN = (r"(?:tables?|charts?|lists?|regulations?|sections?|rules?"
                     r"|standards?|columns?|entries|entry|texts?|appendix"
                     r"|citations?|authority|above|foregoing)")
_SET_CARRIER = re.compile(
    r"^\s*(?:"
    # "The answer is:" · "The correct answer would be,"
    r"(?:the\s+)?(?:correct\s+|final\s+|short\s+|direct\s+)?answers?"
    r"\s+(?:is|are|would\s+be)\s*[,:]?\s*"
    # "Based on the table," · "According to the regulation:" · "As listed in the section,"
    r"|(?:based\s+(?:up)?on|according\s+to"
    r"|as\s+(?:shown|listed|stated|indicated|set\s+forth|specified))"
    r"(?:\s+(?:in|on|by)\b)?(?:\s+the\b)?(?:\s+" + _SET_CARRIER_NOUN + r")?\s*[,:]\s*"
    # "They are," · "Those are:"
    r"|(?:they|these|those)\s+are\s*[,:]?\s*"
    # "The required elements are:"
    r"|the\s+(?:items|values|codes|requirements|elements|materials)\s+are\s*[,:]?\s*"
    r")",
    re.IGNORECASE,
)
_CARRIER_MAX_PEELS = 3


def _strip_set_carrier(s: str) -> str:
    """Peel a bounded number of leading carrier clauses. O(1) iterations, no
    recursion, no backtracking — the pattern is anchored and wildcard-free."""
    for _ in range(_CARRIER_MAX_PEELS):
        m = _SET_CARRIER.match(s)
        if not m or m.end() == 0:
            break
        rest = s[m.end():]
        if not rest.strip():
            break           # never strip the whole answer away
        s = rest
    return s


# F26 — A TABLE ADDRESS IS AN ADDRESS, exactly as a citation is.
#
# F1 established the principle: "a number inside a citation is an ADDRESS, not a
# quantity", and masking those spans stopped a section number colliding with the
# answer. A table CELL is addressed the same way — by column name and row label — and
# the row label of a numeric table is itself numbers:
#
#   2. Published at 40 CFR 141.857, column "Minimum number of samples per month",
#      row "1,001 to 2,500".
#
# The answer is 2. "1,001" and "2,500" are the coordinates of the cell it was read
# from. The multi-numeric guard saw [2.0, 1001.0, 2500.0] and rejected a correct,
# well-grounded answer as a hallucination — measured on 214 EPA items, every one
# failing its OWN gold answer. A model that cites the row it read is doing the thing
# this product asks for and was being penalised for it, which is the same
# self-contradiction found in the boolean and set lanes.
#
# THE PATTERN IS DELIBERATELY NARROW, because the last round proved that masking is
# where laundering channels are born. It requires the literal word row/column/entry/
# line, then optional connective words, then a QUOTED string — and it masks only what
# is inside the quotes. There is no wildcard outside the quote delimiters, so a bare
# number cannot be smuggled in beside one:
#   'the limit is 0.5 kg or 40 kg'          untouched — no row/column, no quotes
#   'the limit is 5, row "1,001 to 2,500"'  masks the coordinates only; 5 is graded
_TABLE_ADDRESS_PAT = re.compile(
    r"\b(?:row|column|col|entry|line)s?\b"
    r"(?:\s+(?:for|of|labell?ed|titled|named|headed))?"
    r"\s*[:=]?\s*"
    r"(?:\"[^\"]{0,120}\"|“[^”]{0,120}”|'[^']{0,120}')",
    re.IGNORECASE,
)


def _citation_spans(text: str) -> List[tuple]:
    """Half-open [start, end) character spans of regulatory citations AND table
    addresses — both are places, not quantities.

    Single linear pass per pattern; the engine's O(N) guarantee is preserved.
    """
    if not text:
        return []
    spans = [(m.start(), m.end()) for m in _CITATION_SPAN_PAT.finditer(text)]
    spans += [(m.start(), m.end()) for m in _TABLE_ADDRESS_PAT.finditer(text)]
    return spans


def _in_spans(start: int, end: int, spans: List[tuple]) -> bool:
    """True iff [start, end) falls inside any span."""
    for s, e in spans:
        if start >= s and end <= e:
            return True
    return False


class LexicalExtractor:
    def __init__(self, config: Optional[dict] = None):
        self._config = config

    def lex(self, text: str, ctx: Optional["PipelineContext"] = None) -> str:
        """
        Dual-pass sanitization:
        1) Strip XML <think> tags.
        2) Quarantine Markdown CodeFences if surrounded by conversational text.
        3) Remove null bytes/invisibles.
        """
        if text is None:
            return ""
        text = str(text)

        # ⛔ REJOIN THE EXPONENT BEFORE ANYTHING TOKENISES IT.
        #
        # Folding the UNIT was not enough. eCFR writes µg/m³ as "µg/m<SU>3</SU>",
        # so once tags are stripped the text reads "µg/m 3" and the lexer emits
        # UNIT("µg/m") followed by a separate NUM(3). The multi-numeric guard then
        # sees two conflicting numbers — 3 and 50 — in a gold of "50 µg/m 3" and
        # refuses the item:
        #
        #   GT-K-ENF-000022  "multiple conflicting numbers in response [3.0, 50.0]"
        #
        # Three items of 340 failed their own oracle for this reason, and the unit
        # involved is the one OSHA's entire exposure-limit corpus is written in.
        # The repair has to happen HERE, before tokenisation, because by the time
        # a unit is being folded the stray number already exists.
        text = restore_exponent(text)

        # Quarantine CodeFence and XMLFence blocks using the AST Parser
        parser = SemanticParser(text)
        nodes = parser.parse()
        
        # Excise XML reasoning tags
        xml_nodes = [n for n in nodes if isinstance(n, XMLFenceNode)]
        for node in reversed(xml_nodes):
            if ctx:
                ctx.trace_log.append({"module": "PARSER", "action": f"AST: Excised {node.tag_name} block."})
            text = text[:node.start] + text[node.end:]
            
        # Excise CodeFence blocks (quarantine them from got_text_lexed)
        # We must recalculate nodes because text has changed (or use offsets)
        # Safer to parse again:
        parser2 = SemanticParser(text)
        nodes2 = parser2.parse()
        # Calculate length of non-fence text
        fence_nodes = [n for n in nodes2 if isinstance(n, CodeFenceNode)]
        total_fence_len = sum(n.end - n.start for n in fence_nodes)

        # F10 — SHAPE FIRST, then the wrapper heuristic.
        #
        # The rule used to be the character count alone: more than 15 characters
        # of prose around a fence and EVERY fence was excised as untrusted. That
        # conflates two unrelated things — "a fence appears next to prose", which
        # is how essentially every chat model returns structured output, and "a
        # fence carries injected content that must not be trusted". Measured
        # consequence: expected '{"action": "deny"}' against
        #     Here is your response:\n```json\n{"action":"deny"}\n```\nHope this helps!
        # threw away the answer and graded the greeting, normalising the whole
        # response to 'hereisyourresponse:hopethishelps!'. A false negative on
        # the single most common real-world response shape for structured output.
        #
        # The expected value already says which case this is. If the answer key
        # is itself structured, the fence IS the answer and prose around it is
        # packaging — isolate the fence no matter how chatty the wrapper. Only
        # when the key is not structured does the wrapper heuristic decide, and
        # its threshold is now a config knob rather than a magic number.
        expected_text = (getattr(ctx, "expected_text", "") or "") if ctx is not None else ""
        expected_is_structured = expected_text.strip()[:1] in ("{", "[")

        wrapper_cap = 15
        if self._config:
            wrapper_cap = self._config.get("parsing", {}).get("code_fence_wrapper_max_chars", 15)

        if fence_nodes and expected_is_structured:
            if ctx:
                ctx.trace_log.append({"module": "PARSER", "action": "AST: Isolated CodeFence block (expected value is structured)."})
            text = fence_nodes[0].content.strip()
        elif len(text.strip()) - total_fence_len > wrapper_cap:
            # Substantial conversational wrapper exists. Quarantine the CodeFence.
            for node in reversed(fence_nodes):
                if ctx:
                    ctx.trace_log.append({"module": "PARSER", "action": "AST: Quarantined CodeFence block."})
                text = text[:node.start] + " " + text[node.end:]
        else:
            # Just isolate the first CodeFence block
            if fence_nodes:
                if ctx:
                    ctx.trace_log.append({"module": "PARSER", "action": "AST: Isolated CodeFence block."})
                text = fence_nodes[0].content.strip()

        # Remove null bytes and invisible Unicode characters
        text = text.replace("\x00", "")
        text = re.sub(r"[\u200b\u200c\u200d\u200e\u200f\ufeff]", "", text)
        text = text.replace("\xa0", " ").replace("§", " ")
        text = (
            text.replace("‘", "'")
            .replace("’", "'")
            .replace("“", '"')
            .replace("”", '"')
            .replace("—", "-")
            .replace("–", "-")
            # ⛔ ADDED 2026-08-05 — U+2212 MINUS SIGN and the rest of the dash family.
            # The CFR typesets negative values with a real minus sign ("−50 dBc"), not an
            # ASCII hyphen. Without this fold, a response of "-50" was graded WRONG against
            # a gold of "−50" — identical values, rejected on a codepoint. The engine then
            # reported it as a caught hallucination, which INFLATES the catch rate: the
            # defect made the product look better than it was, in the demo output a buyer
            # reads. Found by grading a live frontier model against 47 CFR 27.53.
            .replace("−", "-")      # U+2212 minus sign
            .replace("‐", "-")      # U+2010 hyphen
            .replace("‑", "-")      # U+2011 non-breaking hyphen
            .replace("‒", "-")      # U+2012 figure dash
            .replace("﹘", "-")      # U+FE58 small em dash
            .replace("－", "-")      # U+FF0D fullwidth hyphen-minus
        )

        # Strip markdown formatting markers (*, _, `, ~, #, |)
        text = re.sub(r"[*_`~#|]", " ", text)
        # Strip leading question echo e.g. "is it forbidden? " or "could the answer be yes? "
        text = re.sub(r"^(?:could|would|can|might|is|are|does|should)[^?]*\?\s*", "", text, flags=re.IGNORECASE)
        # Also strip rhetorical question echoes anywhere in the text e.g. "is it permitted? no."
        #
        # ANCHORED AT A SENTENCE BOUNDARY, because unanchored this deleted answers.
        # The pattern used to start at ANY modal verb and run to the next "?", so
        #   "No. The limit is 500 kg. Is that clear? Yes."
        # matched from the "is" inside "the limit is 500 kg" and took the answer with
        # it, leaving "no. the limit yes." The item then failed with "could not parse
        # a numerical value" — a correct answer, scored wrong, on all 11 titles.
        # A rhetorical question the model poses is a whole clause, so requiring it to
        # BEGIN a sentence strips exactly what was intended and nothing else.
        text = re.sub(r"(?:^|(?<=[.!?\n]))\s*(?:could|would|can|might|is|are|does|should)\b[^?]*\?\s*",
                      " ", text, flags=re.IGNORECASE)
        # Strip foreign-jurisdiction / out-of-scope clauses (ADR, IMDG, IATA, TDG, EU, etc.)
        text = re.sub(r"(?:under|per|in|according\s+to)\s+(?:European|EU|ADR|IMDG|IATA|ICAO|TDG|Canad(?:a|ian)|RID|GHS|UN\s+Model|REACH|CLP|Australian|British|UK)\b[^.;]*[.;]?\s*", "", text, flags=re.IGNORECASE)
        
        # Strip hypothetical/conditional preamble clauses using AST parser
        parser2 = SemanticParser(text)
        nodes2 = parser2.parse()
        hypo_nodes = [n for n in nodes2 if isinstance(n, HypotheticalClauseNode)]
        for node in reversed(hypo_nodes):
            if ctx:
                ctx.trace_log.append({"module": "PARSER", "action": "AST: Excised hypothetical clause."})
            text = text[:node.start] + text[node.end:]
            
        # Strip leading bullet/list index markers (e.g., 1., (a), a)) at start of string or newlines
        #
        # ONLY WHEN IT IS ACTUALLY A LIST. This is a normalisation step that was
        # deciding correctness: when the ANSWER IS a bare number or a single letter —
        # Packing Group "I", hazard class "8", an MCL of "2" — the marker and the
        # answer are the same characters, so
        #   "2. See 40 CFR 141.857."  ->  "see 40 cfr 141.857."
        # and the item failed with "could not parse a numerical value", while the
        # identical answer written "The answer is 2. See 40 CFR 141.857." passed.
        # That is a false rejection triggered purely by answer formatting, and it hit
        # the exact_match and numeric lanes hardest because their answers are short.
        #
        # A genuine enumeration has more than one marker, or has markers on their own
        # lines. A single marker at the head of a one-line response is an answer.
        _MARKER = r"(?:\([a-zA-Z0-9]+\)|(?:\d+|[a-zA-Z]|i{1,3}|iv|v)[\.)])"
        newline_markers = re.findall(r"\n\s*" + _MARKER + r"\s+", text)
        head_markers = re.findall(r"^\s*" + _MARKER + r"\s+", text)
        if len(newline_markers) + len(head_markers) >= 2 or newline_markers:
            text = re.sub(r"(^|\n)\s*" + _MARKER + r"\s+", r"\1 ", text)
        # Strip optional/negated phrases for set extraction (NOT permitted/allowed — those are definitive boolean answers)
        text = re.sub(r"\b[a-z0-9_-]+\s+(?:is|are)\s+(?:optional|recommended|suggested|not\s+required)\b", "", text, flags=re.IGNORECASE)
        # Normalize whitespace per line and convert to lowercase
        lines = [re.sub(r"\s+", " ", line).strip() for line in text.splitlines()]
        text = "\n".join(line for line in lines if line)
        text = text.lower()

        # Strategic Override for Scientific Synonyms
        if self._config and "domain" in self._config and "entity_synonyms" in self._config["domain"]:
            syns = self._config["domain"]["entity_synonyms"]
            # Sort keys by length descending so multi-word phrases match before substrings
            for k in sorted(syns.keys(), key=len, reverse=True):
                text = re.sub(r"\b" + re.escape(k.lower()) + r"\b", syns[k].lower(), text)

        return text

    def tag(self, text: str) -> list[dict]:
        """Layer 2: The Tagger.
        Entity Extraction without Mutation. Extracts raw spans for numbers, units, boolean polarities, and identifiers.

        Requires str. lex() tolerates None (returns ""), but tag() also feeds the
        RAW text to SemanticParser at step 5, which raised a bare
        "TypeError: expected string or bytes-like object" on None/int input.
        The guard turns that into a clear, typed error at the entry point.
        """
        if not isinstance(text, str):
            from ..pipeline import InvalidResponseError
            raise InvalidResponseError(
                f"tag() requires str, received {type(text).__name__}")
        text_lexed = self.lex(text)
        # F2b — align() needs the surrounding text to decide whether a unit
        # may reach a number. Every call path tags `got` immediately before
        # aligning it, so caching the last lexed text here keeps the public
        # 3-arg align() signature working for the callers in tools/.
        self._last_lexed = text_lexed
        tags = []

        # 0. Infinite Set Hallucination Check
        if _OPEN_SET_PAT.search(text_lexed):
            tags.append({"type": "IDENTIFIER", "raw": "INFINITE_SET_HALLUCINATION", "start": 0, "end": 0})


        # 1. Boolean Entity Extraction via AST
        parser = SemanticParser(text_lexed)
        for node in parser.parse():
            if isinstance(node, BooleanAssertionNode):
                tags.append({
                    "type": "BOOLEAN", 
                    "raw": node.raw, 
                    "start": node.start, 
                    "end": node.end,
                    "value": node.polarity  # Inject AST computed polarity directly
                })

        # 2. Numeric Entity Extraction (Numbers, magnitude words, fractions)
        # F2 — BOUNDED UNIT ADJACENCY. This pattern used to end in a bare \b, which
        # made a unit glued to its number unreadable: against "0.5kg" the 5-k
        # junction is not a word boundary, so the regex backtracked and matched
        # only "0" (fabricating a value that appears nowhere in the response —
        # see F3 in tests/test_citation_masking.py), and against "500g" it failed
        # to match at all. The terminator now also accepts the position directly
        # before a unit-initial character, so the number ends where the unit
        # begins. The leading (?<![a-zA-Z0-9]) still prevents matching inside an
        # identifier such as UN1090.
        _num_end = r"(?:\b|(?=[a-zA-Z%µ°]))"
        num_pattern = re.compile(
            r"(?<![a-zA-Z0-9])(?:(?:(?:-?\d+(?:\.\d+)?|(?:a\s+)?half|(?:a\s+)?quarter|(?:a\s+)?third)\s*(?:a\s+)?(?:thousand|million|billion|trillion))|"
            r"(?:a\s+)?half(?:\s+a)?|(?:a\s+)?quarter(?:\s+of\s+a)?|(?:a\s+)?third(?:\s+of\s+a)?|"
            # `-?\.\d+` added 2026-08-05: the CFR writes decimals in legal-drafting style with
            # no leading zero (".01", ".354"). Without this branch the tokenizer skipped the
            # dot and read ".01" as 1 — a silent 100x error. Placed AFTER the plain-number
            # branch so "0.01" still matches there first; the alternation stays anchored and
            # non-backtracking, so the linear-time guarantee holds.
            r"-?\d+(?:\.\d+)?\s*/\s*\d+|-?\d{1,3}(?:,\d{3})+(?:\.\d+)?|-?\d+(?:\.\d+)?|-?\.\d+|,-?\d{1,2}|-?\d+,-?\d{1,2})"
            + _num_end,
            re.IGNORECASE,
        )
        _cfr_cite_pat = re.compile(r"\s*(?:cfr|usc|u\.s\.c|fr|stat)\b", re.IGNORECASE)
        # F1 — CITATION SPANS. Numbers inside a regulatory citation are addresses,
        # not quantities. They are still emitted as NUM tokens (exact_match and
        # set_equality items may have a citation AS their answer), but they are
        # flagged so the numeric/range aligner can drop them before the
        # multi-numeric conflict test. Marking, not deleting, is what keeps this
        # fix scoped to the one lane where a citation number is never the answer.
        citation_spans = _citation_spans(text_lexed)
        for m in num_pattern.finditer(text_lexed):
            # Skip numbers that are part of regulatory citations (e.g. "49 CFR", "29 USC")
            after = text_lexed[m.end():]
            if _cfr_cite_pat.match(after):
                continue
            tags.append({"type": "NUM", "raw": m.group(0), "start": m.start(), "end": m.end(),
                         "in_citation": _in_spans(m.start(), m.end(), citation_spans)})

        # 3. Unit Entity Extraction
        # F2 — the leading \b is relaxed to also admit a unit that starts
        # immediately after a digit, so "kg" is extracted from "0.5kg". Without
        # this the number parses but binds to no unit, and the expected-side unit
        # filter in numeric.py then discards it.
        # F13c — the trailing \b could not close a SYMBOL-ONLY unit. After "%" or
        # "°" there is no word character, so at end-of-string (or before
        # punctuation) \b fails and the unit is never emitted at all. Against a
        # response of "50%" the tokenizer produced NUM 50.0 and no UNIT, the
        # number arrived dimensionless, and numeric.py's expected-unit filter
        # discarded it — so a gold of "50 percent" scored a correct answer WRONG
        # and the demo reported it as a caught hallucination.
        #
        # This is why folding alone did not fix percent: there was nothing to
        # fold. Three separate layers had to be right — the token had to be
        # EMITTED (here), TAGGABLE (KNOWN_UNITS), and COMPARED folded (align and
        # numeric). Fixing any one alone left the defect in place, which is how
        # it survived as an xfail through several attempts.
        unit_pattern = re.compile(r"(?:\b|(?<=\d))([a-z%µ°/\-]+[0-9]*)(?:\b|(?<=[%µ°]))",
                                  re.IGNORECASE)
        if self._config:
            known = self._config["_known_units_set"]
            umap_keys = set(self._config["units"]["unit_map"].keys())
        else:
            known = KNOWN_UNITS
            umap_keys = set(UNIT_MAP.keys())
        for m in unit_pattern.finditer(text_lexed):
            raw_u = m.group(0).lower()
            raw_clean = raw_u.replace("-", "")
            # ⚡ A DERIVED UNIT IS KNOWN WHEN ITS COMPONENTS ARE.
            #
            # This membership test was a flat set lookup, and the set held exactly
            # two compound units — "mg/l" and "ug/l" — so "mg/kg" emitted NO UNIT
            # token at all. With no unit token the numeric adjudicator could not
            # parse the item's own gold, and every denominator-bearing item in the
            # FDA corpus graded False against its own answer key: 5,617 of 5,617.
            #
            # The repair that carries "/kg" into the gold is worthless without
            # this — it turns a wrongly-flat answer into an unparseable one.
            if (raw_clean in known or raw_clean in umap_keys
                    or ("/" in raw_clean and is_known_unit(raw_clean, known))):
                tags.append({"type": "UNIT", "raw": raw_clean, "start": m.start(), "end": m.end()})

        # 4. Identifier Entity Extraction
        if self._config:
            # Config-driven: use pre-compiled patterns from config
            combined_pat = "|".join(p.pattern for p in self._config["_compiled_id_patterns"])
            id_pattern = re.compile(r"\b(?:" + combined_pat + r")\b", re.IGNORECASE)
            stopwords = self._config["_stopwords_set"]
        else:
            id_pattern = re.compile(
                r"\b(?:(?:un|na|id)\s*\d{4}|[a-z]{1,3}\d{1,4}[a-z0-9]*|pg\s*(?:i{1,3}|iv|v|1|2|3)|\d+(?:\.\d+)?(?:\([a-z0-9]+\))*|[a-z])\b",
                re.IGNORECASE,
            )
            stopwords = {"is", "are", "the", "and", "or", "to", "in", "on", "of", "a", "an", "code", "codes", "with", "for", "by", "this", "that", "requirement", "requirements", "subpart", "part", "section"}
        for m in id_pattern.finditer(text_lexed):
            raw_val = m.group(0)
            if raw_val not in stopwords:
                tags.append({"type": "IDENTIFIER", "raw": raw_val, "start": m.start(), "end": m.end()})

        # 5. Extract entities from XML reasoning tags (<think>, <scratchpad>) if present in raw text
        parser_raw = SemanticParser(text)
        raw_nodes = parser_raw.parse()
        xml_nodes = [n for n in raw_nodes if isinstance(n, XMLFenceNode)]
        for xn in xml_nodes:
            cot_text = xn.content
            cot_spans = _citation_spans(cot_text)
            for m in num_pattern.finditer(cot_text):
                after = cot_text[m.end():]
                if _cfr_cite_pat.match(after):
                    continue
                tags.append({"type": "NUM", "raw": m.group(0), "start": xn.start + m.start(), "end": xn.start + m.end(), "is_cot": True,
                             "in_citation": _in_spans(m.start(), m.end(), cot_spans)})
            for m in unit_pattern.finditer(cot_text):
                raw_u = m.group(0).lower()
                raw_clean = raw_u.replace("-", "")
                if raw_clean in known or raw_clean in umap_keys:
                    tags.append({"type": "UNIT", "raw": raw_clean, "start": xn.start + m.start(), "end": xn.start + m.end(), "is_cot": True})

        # 6. F1 SAFETY VALVE — a citation address never carries a unit.
        #
        # Without this, the mask was a laundering channel: "the limit is 0.5 kg,
        # see section 40 kg" put the decoy 40 inside a citation span, the aligner
        # dropped it, and a hallucinated quantity graded CORRECT — while the same
        # decoy without the word "section" was correctly rejected. An attacker
        # only had to write a citation keyword in front of the number they wanted
        # hidden. That is precisely the failure mode of tools/verbatim_guard.py,
        # which normalizes away the very corruption it exists to catch, and the
        # reason this fix is scoped rather than trusted.
        #
        # "49 CFR 173.202" has no unit on 173.202, so it stays masked.
        # "section 40 kg" has one, so 40 is a QUANTITY and the guard still sees it.
        # Runs after unit extraction because it needs the UNIT tags to exist.
        _units = [t for t in tags if t["type"] == "UNIT"]
        if _units:
            for t in tags:
                if t["type"] == "NUM" and t.get("in_citation"):
                    if any(_unit_directly_attached(t["end"], u["start"], text_lexed)
                           for u in _units):
                        t["in_citation"] = False

        return tags

    def resolve(self, tags: list[dict]) -> list[dict]:
        """Layer 3: The Resolver.
        Semantic Translation. Converts raw extracted entity strings into typed Python objects.
        """
        resolved = []
        mult_map = {"thousand": 1000.0, "million": 1000000.0, "billion": 1000000000.0, "trillion": 1000000000000.0}

        for t in tags:
            ttype = t["type"]
            raw = t["raw"].lower().strip()

            if ttype == "NUM":
                clean = raw
                # Strip thousands separators (e.g. '1,000' → '1000') before any parsing
                if re.match(r"-?\d{1,3}(,\d{3})+", clean):
                    clean = clean.replace(",", "")
                m_frac = re.search(r"(\d+)\s*/\s*(\d+)", clean)
                if m_frac:
                    denom = float(m_frac.group(2))
                    val = float(m_frac.group(1)) / denom if denom != 0 else float('inf')
                    resolved.append({"type": "NUM", "value": val, "raw": raw, "start": t["start"], "end": t["end"], "is_cot": t.get("is_cot", False), "in_citation": t.get("in_citation", False)})
                    continue

                clean = re.sub(r"\b(?:a\s+)?half(?:\s+a)?\b", "0.5", clean)
                clean = re.sub(r"\b(?:a\s+)?quarter(?:\s+of\s+a)?\b", "0.25", clean)
                clean = re.sub(r"\b(?:a\s+)?third(?:\s+of\s+a)?\b", "0.3333", clean)

                m_mult = re.search(r"(\d+(?:\.\d+)?)\s*(?:a\s+)?(thousand|million|billion|trillion)", clean)
                if m_mult:
                    val = float(m_mult.group(1)) * mult_map[m_mult.group(2)]
                    resolved.append({"type": "NUM", "value": val, "raw": raw, "start": t["start"], "end": t["end"], "is_cot": t.get("is_cot", False), "in_citation": t.get("in_citation", False)})
                    continue

                clean = re.sub(r"(?:^|\s|\b)(\d*),(?!\s)(\d{1,2})\b", r" \1.\2", clean)
                try:
                    val = float(clean.strip())
                    resolved.append({"type": "NUM", "value": val, "raw": raw, "start": t["start"], "end": t["end"], "is_cot": t.get("is_cot", False), "in_citation": t.get("in_citation", False)})
                except ValueError:
                    pass

            elif ttype == "UNIT":
                if self._config:
                    u_std = self._config["units"]["unit_map"].get(raw, raw)
                else:
                    u_std = UNIT_MAP.get(raw, raw)
                resolved.append({"type": "UNIT", "value": u_std, "raw": raw, "start": t["start"], "end": t["end"], "is_cot": t.get("is_cot", False), "in_citation": t.get("in_citation", False)})

            elif ttype == "BOOLEAN":
                bool_val = t.get("value")
                if bool_val is not None:
                    resolved.append({"type": "BOOLEAN", "value": bool_val, "raw": raw, "start": t["start"], "end": t["end"], "is_cot": t.get("is_cot", False), "in_citation": t.get("in_citation", False)})
                else:
                    if self._config:
                        yes_set = self._config["_yes_set"]
                        no_set = self._config["_no_set"]
                    else:
                        yes_set = {"not prohibited", "not restricted", "not forbidden", "not unlawful", "yes", "permitted", "allowed", "true", "approved", "required", "applicable", "exception to the prohibition", "exempted material", "exemption"}
                        no_set = {"no", "forbidden", "prohibited", "false", "disallowed", "unauthorized", "banned", "denied", "unlawful", "restricted", "inapplicable", "waived", "exempt", "unnecessary", "not permitted", "not allowed", "not required"}
                    if raw in yes_set:
                        resolved.append({"type": "BOOLEAN", "value": True, "raw": raw, "start": t["start"], "end": t["end"], "is_cot": t.get("is_cot", False), "in_citation": t.get("in_citation", False)})
                    elif raw in no_set:
                        resolved.append({"type": "BOOLEAN", "value": False, "raw": raw, "start": t["start"], "end": t["end"], "is_cot": t.get("is_cot", False), "in_citation": t.get("in_citation", False)})

            elif ttype == "IDENTIFIER":
                val = norm_token(raw)
                val = _safe_stem(val)
                resolved.append({"type": "IDENTIFIER", "value": val, "raw": raw, "start": t["start"], "end": t["end"], "is_cot": t.get("is_cot", False), "in_citation": t.get("in_citation", False)})

        return resolved

    def align(self, expected_resolved: list[dict], got_resolved: list[dict], rule_type: str,
              text: Optional[str] = None) -> list[dict]:
        """Layer 4: The Aligner.
        Handles contextual relationships (e.g. mapping units to numbers, unit scale conversions).
        """
        aligned = []
        if text is None:
            # Legacy 3-arg callers only. The cached text belongs to whatever was
            # tagged last, which is not necessarily these tokens — so VALIDATE it
            # against them before trusting it. A text shorter than the tokens'
            # own offsets provably did not produce them, and using it anyway made
            # a distant unit bind by accident (measured: (5.0, None) became
            # (5.0, 'kg') purely by reversing two tag() calls). Fail safe: with
            # no trustworthy text, no distance judgement is possible, so fall
            # back to the conservative rule rather than an accidental one.
            cached = getattr(self, "_last_lexed", None)
            if cached is not None and _cache_matches(cached, got_resolved):
                text = cached
        if rule_type in ("numeric", "range"):
            eu = next((r["value"] for r in expected_resolved if r["type"] == "UNIT"), None)
            units_in_got = [r for r in got_resolved if r["type"] == "UNIT"]

            for item in got_resolved:
                if item["type"] == "NUM":
                    # F1 — a number inside a regulatory citation is an address,
                    # not a quantity. Dropped HERE rather than at tag() time so
                    # that exact_match/set_equality, where a citation can BE the
                    # answer, keep seeing it. This is the whole scoping argument
                    # for the fix.
                    if item.get("in_citation"):
                        continue
                    val = item["value"]
                    # F2b — BOUNDED unit adjacency. This used to bind the NEAREST
                    # unit at ANY distance, so in "60 Wh (173.185)" the section
                    # number silently acquired "Wh" and became a rival 173.185 Wh
                    # measurement, colliding with the real answer. A unit now has
                    # to actually be adjacent to claim a number; anything further
                    # away leaves the number dimensionless, and numeric.py's
                    # expected-unit filter then drops it.
                    #
                    # This is what catches the two citation forms the span mask
                    # cannot see: a bare "(173.185)", and "§ 173.185" (lex()
                    # rewrites § to a space before the mask ever runs, so the
                    # anchor keyword is already gone). Neither carries a unit.
                    if units_in_got:
                        best_u = min(units_in_got, key=lambda u: min(abs(u["start"] - item["end"]), abs(item["start"] - u["end"])))
                        if text is None:
                            # No trustworthy text. The bridge CONTENT cannot be
                            # inspected, but distance still can — the tokens carry
                            # their own offsets. Use the plain distance bound
                            # rather than binding unconditionally, so a legacy
                            # 3-arg call cannot reach a MORE permissive verdict
                            # than an explicit one. Binding here was what made
                            # "The value is 5 and the recorded unit for it is kg"
                            # yield (5.0, 'kg') when expected happened to be
                            # tagged last.
                            gap = min(abs(best_u["start"] - item["end"]),
                                      abs(item["start"] - best_u["end"]))
                            gu = best_u["value"] if gap <= _UNIT_ADJACENCY_STRICT else None
                        elif _unit_binds(item.get("start", 0), item.get("end", 0),
                                         best_u["start"], best_u["end"], text):
                            gu = best_u["value"]
                        else:
                            gu = None
                    else:
                        gu = None
                    aligned_val = val
                    final_u = gu
                    if eu and gu and eu != gu:
                        # F13 — fold NOTATION before deciding the units differ.
                        # This compared raw tokens, so "%" vs "percent" and
                        # "year" vs "yr" read as a unit mismatch, found no scale
                        # entry, and left the number labelled with a unit that
                        # numeric.py's expected-unit filter then discarded. The
                        # model had answered correctly. Nine tests were carried
                        # as xfail against this one comparison.
                        #
                        # Folding is NOT conversion: it only recognises two
                        # spellings of the SAME unit, so the value is untouched.
                        # A genuine scale difference still falls through to
                        # UNIT_SCALES below, which adjusts the value as well.
                        fe, fg = fold_unit(eu), fold_unit(gu)
                        if fe == fg:
                            final_u = eu
                        else:
                            scales = (self._config["_unit_scales_tuples"]
                                      if self._config else UNIT_SCALES)
                            if (eu, gu) in scales:
                                aligned_val = val / scales[(eu, gu)]
                                final_u = eu
                            elif (gu, eu) in scales:
                                aligned_val = val * scales[(gu, eu)]
                                final_u = eu
                            elif (fe, fg) in scales:
                                aligned_val = val / scales[(fe, fg)]
                                final_u = eu
                            elif (fg, fe) in scales:
                                aligned_val = val * scales[(fg, fe)]
                                final_u = eu
                    aligned.append({"type": "NUM", "aligned_value": aligned_val, "original": val, "unit": final_u, "start": item.get("start", 0), "end": item.get("end", 0), "is_cot": item.get("is_cot", False)})
        elif rule_type == "boolean":
            for item in got_resolved:
                if item["type"] == "BOOLEAN":
                    aligned.append({"type": "BOOLEAN", "value": item["value"]})
        elif rule_type in ("exact_match", "set_equality"):
            # in_citation is carried through but NOT acted on here. exact_match
            # and set_equality can legitimately have a citation AS the answer, so
            # the decision to ignore citation tokens belongs to the adjudicator,
            # which can compare against the expected side first. See
            # set_equality.py (F11).
            for item in got_resolved:
                if item["type"] == "IDENTIFIER":
                    aligned.append({"type": "IDENTIFIER", "value": item["value"], "raw": item["raw"],
                                    "in_citation": item.get("in_citation", False)})
                elif item["type"] == "NUM":
                    aligned.append({"type": "NUM", "value": item["value"], "raw": item["raw"],
                                    "in_citation": item.get("in_citation", False)})
        return aligned

    def enrich(self, ctx: "PipelineContext") -> None:
        """Layer 4.5: The Enricher.

        Performs all regex-based text analysis that was previously embedded in
        adjudicate(). Runs once, caches results on ctx, so adjudicate() can
        remain a pure logic engine with zero regex calls.

        Mutates ctx in-place.
        """
        ctx.trace_log.append({"module": "ENRICH", "action": "ENRICH: Extracted semantic flags and regulatory citations."})
        got_text = ctx.got_text
        lex_got = self.lex(got_text, ctx)
        ctx.got_text_lexed = lex_got

        # F9 — latch the open-set claim. Assigned with `or` rather than `=` on
        # purpose: enrich() re-runs over the laundered payload, and the claim
        # was made in the ORIGINAL response. Once seen it stays seen.
        ctx.has_open_set_claim = ctx.has_open_set_claim or bool(_OPEN_SET_PAT.search(lex_got))

        # --- Boolean polarity detection ---
        if ctx.rule_type == "boolean":
            if (re.match(r"yes\b", lex_got) or "is permitted" in lex_got
                    or "is allowed" in lex_got or "not prohibited" in lex_got
                    or "not restricted" in lex_got):
                ctx.got_boolean_polarity = True
            elif (re.match(r"no(?:t(?:hing)?)?\b", lex_got) or "is prohibited" in lex_got
                  or "is forbidden" in lex_got or "is not permitted" in lex_got
                  or "is not allowed" in lex_got):
                ctx.got_boolean_polarity = False

        # --- Citation extraction ---
        if ctx.citation:
            neg_cite = (
                r"(?:\b17\d\.\d+(?:\([0-9a-z]+\))*\s+(?:does\s+not\s+apply|is\s+not\s+applicable"
                r"|is\s+inapplicable|is\s+exempt)\b|\b(?:exempt\s+from|not\s+covered\s+by)\s+17\d\.\d+)"
            )
            ctx.citation_inverted = bool(re.search(neg_cite, lex_got))
            ctx.has_para_range = bool(re.search(
                r"\b\d{2,3}\.\d+(?:\([a-z0-9]+\))*\(([a-z0-9]+)\)\s*(?:[-–—]|to)\s*"
                r"(?:\d{2,3}\.\d+)?(?:\([a-z0-9]+\))*\(([a-z0-9]+)\)",
                lex_got, re.IGNORECASE,
            ))

        # --- Numeric guards ---
        if ctx.rule_type in ("numeric", "range"):
            # Parse expected numeric for pattern building
            exp_res = ctx.expected_resolved
            exp_nums = [r["value"] for r in exp_res if r["type"] == "NUM"]
            exp_num = exp_nums[0] if exp_nums else None
            if exp_num is None:
                m_num = re.search(r"-?(?:\d+(?:\.\d+)?|\.\d+)", self.lex(ctx.expected_text))
                exp_num = float(m_num.group(0)) if m_num else None

            if exp_num is not None:
                try:
                    e_str = str(int(exp_num)) if exp_num == int(exp_num) else str(exp_num)
                except (OverflowError, ValueError):
                    e_str = str(exp_num)

                # The target as it may be WRITTEN: "12500" or "12,500". Both guards
                # below used to match only the bare digits, so any comma-formatted
                # value slipped past them: "More than 12,500 pounds" scored correct
                # against a published maximum of 12,500 pounds. Measured 2026-09-22 on
                # bank-v2: 216 flipped-comparator answers accepted, all comma values.
                # Same defect for decimals written the way regulations write them:
                # ".50 caliber" for 0.5 (ITAR, 4 flipped answers accepted after the
                # comma fix). A decimal target also matches an optional leading zero
                # and trailing zeros.
                e_pat = re.escape(e_str)
                sign = "-" if e_str.startswith("-") else ""
                int_part, _, frac = e_str.lstrip("-").partition(".")
                alts = [e_pat]
                if int_part.isdigit() and len(int_part) > 3:
                    alts.append(re.escape(sign + f"{int(int_part):,}" + (f".{frac}" if frac else "")))
                if frac.isdigit():
                    lead = "0?" if int_part in ("", "0") else re.escape(int_part)
                    alts.append(re.escape(sign) + lead + r"\." + re.escape(frac) + r"0*(?!\d)")
                if len(alts) > 1:
                    e_pat = "(?:" + "|".join(alts) + ")"

                # Inequality detection
                ineq_pattern = r"\b(?:greater\s+than|less\s+than|at\s+least|more\s+than|exceeds|minimum|[><]=?)\s*" + e_pat
                ctx.numeric_inequality = bool(re.search(ineq_pattern, lex_got))

                # Numeric negation detection
                neg_num_prefix = r"\b(?:not|never|no|isn't|cannot|doesn't|does\s+not|isn\s*t)\s+(?:\w+\s+){0,3}" + e_pat
                ctx.numeric_negated = bool(re.search(neg_num_prefix, lex_got))

            # Zero-term detection
            zero_terms = ("no limit", "unlimited", "none", "zero", "no restriction",
                          "n/a", "na", "not applicable", "n.a.", "no requirement",
                          "not required", "exempt", "no restrictions", "no requirements")
            ctx.has_zero_term = bool(re.search(
                r"\b(?:" + "|".join(re.escape(w) for w in zero_terms) + r")\b",
                lex_got, re.IGNORECASE,
            ))

            # Range expression detection
            ctx.has_range_expression = bool(re.search(
                r"\b(?:between|from)\s+\d+(?:\.\d+)?\s*(?:[a-z%µ°/\-]+)?\s*(?:and|to|-)\s*\d+(?:\.\d+)?\b",
                lex_got, re.IGNORECASE,
            ))

        # --- Exact-match negation detection ---
        if ctx.rule_type == "exact_match":
            exp_str = str(ctx.expected_text)
            exp_lexed = self.lex(exp_str)
            # ⛔ THE EXPECTED TOKEN NEEDS WORD BOUNDARIES.
            #
            # re.escape(exp_lexed) was spliced in bare. For a single-letter gold
            # like packing group "I", the pattern matched the "i" INSIDE another
            # word — so the commonest opening in all of regulatory drafting,
            #
            #     "Except as otherwise provided in this subpart, Packing group I."
            #                                   ^^ this "i"
            #
            # read as an explicit negation of the answer, and a CORRECT response
            # was scored wrong. 14 shipped bank items with gold "I" were affected,
            # and the failure runs in the direction that inflates the caught-error
            # rate — the direction that flatters the seller.
            #
            # A regression from my own packing-group work: I widened what counts
            # as an assertion without checking what already consumed the token.
            _exp_re = r"\b" + re.escape(exp_lexed) + r"\b"
            neg_prefix = (r"\b(not|never|incorrect|false|isn't|cannot|except|excluding|other\s+than)"
                          r"\s+(?:\w+\s+){0,4}" + _exp_re)
            neg_suffix = (_exp_re +
                          r"\s+(?:(?:is|does|do|did|will|would|has|have|had|can|could|should|shall|may|might)\s+)?"
                          r"(?:completely\s+|totally\s+)?"
                          r"(?:not|incorrect|false|wrong|invalid|inapplicable|excluded|excepted)")
            ctx.exact_negated = bool(
                re.search(neg_prefix, lex_got) or re.search(neg_suffix, lex_got)
            )

        # --- F16: boolean hedging ---
        # A determination that offers BOTH polarities is not an answer. The
        # polarity reader above matches the FIRST yes/no marker and stops, so
        # "yes or no" scored as "yes" — measured at 139 of 139 boolean items in
        # the shipped bank, a 100% leak in the lane whose entire purpose is a
        # yes/no determination.
        #
        # Scoped deliberately to a DISJUNCTION spanning opposite polarities.
        # "Yes, but not for passenger aircraft" is a qualified answer, not a
        # hedge, and must keep passing — so a bare negation anywhere in the
        # sentence is NOT sufficient to trip this.
        _YES = r"(?:yes|true|permitted|allowed|authorized|required|applicable)"
        _NO = r"(?:no|false|forbidden|prohibited|not\s+permitted|not\s+allowed|"
        _NO += r"unauthorized|not\s+required|inapplicable|excepted)"
        if re.search(rf"\b{_YES}\b\s*(?:,|;)?\s*or\s+{_NO}\b", lex_got) or \
           re.search(rf"\b{_NO}\b\s*(?:,|;)?\s*or\s+{_YES}\b", lex_got) or \
           re.search(rf"\beither\s+{_YES}\s+or\s+{_NO}\b", lex_got) or \
           re.search(rf"\beither\s+{_NO}\s+or\s+{_YES}\b", lex_got):
            ctx.boolean_hedged = True

        # --- Disjunction detection ---
        # F18 — computed for exact_match as well as set_equality. It was
        # set-only, so exact_match had no way to see a hedge that was not a
        # citation: "II or III", "60 L or 30 kg", "A54 or B120" all scored
        # CORRECT via the conversational-wrapper fallback, which finds the gold
        # answer as a substring and never asks what else was offered. Measured at
        # 223 of 326 table_lookup items, whose resolved values are packing
        # groups, quantities and provision codes rather than section numbers.
        if ctx.rule_type in ("set_equality", "exact_match", "structured_match"):
            # F21 — this required WORD characters on both sides of "or", so any
            # alternative bounded by ")", "%", "±", "≤" or a trailing "." never
            # set the flag: "Class II (special controls) or Class I (general
            # controls)" sailed past F18 and the wrapper fallback accepted the
            # hedge. Measured: 2,723 residual hedge leaks, 2,723/2,723 fitting
            # this one gap, worst lane FDA at 74.12%.
            #
            # Now a standalone "or"/"either..or" regardless of what flanks it.
            # Deliberately broad: merely setting has_disjunction rejects nothing
            # on its own — exact_match still requires >=2 rival candidates with
            # the gold among them (F18), and set_equality requires a multi-member
            # expected set — so prose "or" in a wrapper cannot flip a verdict
            # without an actual rival present.
            ctx.has_disjunction = bool(re.search(r"\bor\b", lex_got))

        # --- CFR section extraction (used by exact_match) ---
        # F17 — this was r"\b17\d\.\d+\b": hardcoded to 49 CFR 170-179, i.e. to
        # hazmat. exact_match uses it to reject a response offering MULTIPLE
        # competing section numbers, so outside 49 CFR the guard never fired and
        # "211.84 or 211.86" graded CORRECT. Measured across the packs before the
        # fix: 49 CFR rejected the hedge; FDA, FAA, SEC, NRC and FCC all accepted
        # it. The multi-agency build is what exposed it — on one title the
        # hardcoding is invisible.
        #
        # Now any dotted section designator, which covers 173.243, 211.84,
        # 91.159, 20.1201, 73.682, 1910.1000 and 240.13d-1. Over-matching is safe
        # here: the guard only fires when the EXPECTED answer is itself one of
        # the citations found, so a stray dotted number cannot trigger it alone.
        ctx.got_citations = set(re.findall(r"\b\d{1,4}\.\d+(?:[a-z]{1,2})?(?:-\d+)?\b", lex_got))

        # --- Set: clean got_text for set_equality token extraction ---
        if ctx.rule_type == "set_equality":
            cleaned = lex_got
            # F24 — SYMMETRY GUARD. If the KEY itself opens with the same
            # carrier, those words are part of the answer and are stripped from
            # NEITHER side. Response-side-only deletion can otherwise only
            # SHRINK the response set (-> a missing member -> rejection); this
            # closes the one path by which it could delete a member the key has.
            if not _SET_CARRIER.match(str(ctx.expected_text or "")):
                cleaned = _strip_set_carrier(cleaned)
            cleaned = re.sub(
                r"\b[a-z0-9_-]+\s+(?:is|are)\s+(?:optional|recommended|suggested|permitted|allowed|not\s+required)\b",
                "", cleaned, flags=re.IGNORECASE,
            )
            cleaned = re.sub(
                r"\b(?:codes|code|are|is|the|required|must|comply|with)\b",
                "", cleaned, flags=re.IGNORECASE,
            )
            ctx.set_cleaned_got = cleaned

            # None-term detection for set none matching
            ctx.has_none_term = bool(re.search(
                r"\b(no|none|zero|n/a)\b", lex_got, re.IGNORECASE,
            ))

