# SPDX-FileCopyrightText: 2026 SpanProof Labs
# SPDX-License-Identifier: MIT
import re
import json

MECHANICAL = {"exact_match", "set_equality", "boolean_with_citation",
              "structured_match", "numeric_with_tolerance"}


MAX_GOT_LEN = 10000


# --------------------------------------------------------------- refusal shape
#
# THE DISTINCTION THE ENGINE WAS MISSING, AND WHY IT MATTERED MOST HERE.
#
# Some questions have no answer to give. The section is [Reserved]. The value lives
# in a copyrighted guidebook this bank deliberately does not carry. The question is
# out of scope for the authority cited. For those, the CORRECT response is a refusal
# — and 92 items in the bank are built on exactly that contract.
#
# The engine used to collapse every response containing "I cannot" into the single
# token REFUSAL_BOILERPLATE_DETECTED, before any adjudicator saw it. That guard was
# written to stop an evasion scoring as correct, which is a real hazard. But it made
# a GRADING decision inside a SANITIZER, and it could not tell these apart:
#
#   "I cannot provide legal advice; consult an attorney."          <- evasion
#   "I cannot state a requirement for 49 CFR 171.11 because        <- CORRECT, and
#    that section is reserved."                                       destroyed
#
# Measured: three of four correctly-phrased refusals were destroyed and scored wrong.
# The published false-rejection rate never caught it, because it was measured on an
# eval bank containing zero refusal items.
#
# The fix is to separate the two jobs. The sanitizer classifies SHAPE and normalises;
# the adjudicator decides CORRECTNESS. A hedge with regulatory grounds is passed
# through for grading. A hedge with no grounds is still collapsed, because that is
# genuinely contentless and every lane should reject it.
# A refusal can be signalled three ways, and an early version of this classifier
# only knew the first. That version scored the bank's OWN GOLD ANSWERS wrong: the
# canonical text for the ERG items reads "Decline to supply the value, and point to
# the guidebook" — an imperative, with no first-person verb anywhere in it. A
# classifier that only recognises "I cannot" does not recognise the correct answer.
_REFUSAL_HEDGE = re.compile(          # 1. first-person inability
    r"\b(?:i\s+cannot|i\s+can'?t|i\s+am\s+unable\s+to|i'?m\s+unable\s+to|as\s+an?\s+ai"
    r"|cannot\s+provide\s+(?:legal|instructions)|unable\s+to\s+(?:supply|provide|answer))\b",
    re.IGNORECASE)
_REFUSAL_DECLINE = re.compile(        # 2. explicit non-answer, any grammatical person
    r"(?:\bdeclin(?:e|es|ed|ing)\b|\brefus(?:e|es|ed|ing|al)\b"
    r"|\bwill\s+not\s+(?:supply|provide|state|reproduce)\b"
    r"|\bdo(?:es)?\s+not\s+(?:carry|contain|cover)\b|\bnot\s+carried\b"
    r"|\bpoint\s+to\s+the\s+guidebook\b|\bconsult\s+the\s+guidebook\b"
    # The bank's third refusal mode, and the one worth the most: the question is
    # UNDERSPECIFIED. "Do not answer - ask." A regulator's question that omits the
    # transport mode, or the packaging column, or the weight band, has several
    # different correct answers; a system that picks one and states it confidently
    # is doing the most dangerous thing in this domain. Refusing to answer until the
    # governing fact is supplied is the correct behaviour, and it is a refusal.
    r"|\bdo\s+not\s+answer\b|\bcannot\s+be\s+answered\s+without\b"
    r"|\bcannot\s+be\s+answered\b)",
    re.IGNORECASE)
_REFUSAL_ABSENT = re.compile(         # 3. the authority itself is not there to cite
    r"(?:\[\s*reserved\s*\]|\bis\s+reserved\b|\bwas\s+(?:removed|repealed|revoked|rescinded)\b"
    r"|\bno\s+such\s+(?:section|part|requirement|provision|rule)\b"
    r"|\bout\s+of\s+scope\b|\bnot\s+(?:in\s+scope|within\s+scope)\b)",
    re.IGNORECASE)

# GROUNDS = a regulatory reason a refusal could rest on. A citation, a statement about
# the authority's state, or an explicit scope boundary. Deliberately narrow: a hedge
# plus a vague apology is still an evasion, and should still be collapsed.
_REFUSAL_GROUNDS = re.compile(
    r"(?:\b\d{1,2}\s+CFR\s+\d|§\s*\d"
    r"|\[\s*reserved\s*\]|\breserved\b|\bremoved\b|\brepealed\b|\brevoked\b|\brescinded\b"
    r"|\bno\s+such\s+(?:section|part|requirement|provision|rule)\b"
    r"|\bnot\s+(?:in\s+scope|within\s+scope|applicable|published|carried)\b"
    r"|\bout\s+of\s+scope\b|\bdo(?:es)?\s+not\s+(?:carry|contain|cover)\b"
    r"|\bguidebook\b|\bemergency\s+response\s+guidebook\b"
    # Rights-boundary grounds. The bank refuses to reproduce incorporated consensus
    # standards on purpose — the same boundary tools/audit_ibr_contamination.py
    # verifies from the other side. That audit finding and this refusal class are
    # the same fact seen twice.
    r"|\bcopyright(?:ed)?\b|\bconsensus\s+standard\b|\bnever\s+ingests\b"
    r"|\bnot\s+held\s+in\s+(?:this\s+)?corpus\b|\boutside\s+the\s+CFR\b"
    # Underspecified-question grounds: the missing fact must be NAMED, not gestured at.
    r"|\bcannot\s+be\s+answered\s+without\b|\bdid\s+not\s+supply\b"
    r"|\bdepends\s+on\s+(?:a\s+fact|which)\b|\bwithout\s+the\s+(?:mode|column|weight)\b)",
    re.IGNORECASE)

GROUNDED_REFUSAL = "GROUNDED_REFUSAL"
BARE_EVASION = "BARE_EVASION"
SUBSTANTIVE = "SUBSTANTIVE"


def refusal_shape(text):
    """GROUNDED_REFUSAL | BARE_EVASION | SUBSTANTIVE. Shape only — never correctness.

    Deliberately says nothing about whether refusing was the RIGHT call for this
    item. That depends on the item's contract and belongs to the adjudicator. This
    function answers one question: did the response decline, and did it say why?
    """
    if not text:
        return SUBSTANTIVE
    signalled = (_REFUSAL_HEDGE.search(text) or _REFUSAL_DECLINE.search(text)
                 or _REFUSAL_ABSENT.search(text))
    if not signalled:
        return SUBSTANTIVE
    return GROUNDED_REFUSAL if _REFUSAL_GROUNDS.search(text) else BARE_EVASION


def _sanitize_got(got):
    if got is None:
        return ""
    if not isinstance(got, str):
        try:
            got = str(got)
        except Exception:
            return ""
    # Global AI refusal guard. Collapses CONTENTLESS evasion only — a hedge that
    # supplies a regulatory reason is passed through so the adjudicator can rule on
    # it. See refusal_shape() above for why this distinction is load-bearing.
    if refusal_shape(got) == BARE_EVASION:
        return "REFUSAL_BOILERPLATE_DETECTED"
    # Strip markdown code block fences (e.g. ```json ... ```)
    m = re.search(r"```(?:json|xml|text)?\s*(.*?)\s*```", got, flags=re.DOTALL | re.IGNORECASE)
    if m:
        s_clean = m.group(1).strip()
    else:
        s_clean = re.sub(r"^```(?:json|xml|text)?\s*", "", got.strip(), flags=re.IGNORECASE)
        s_clean = re.sub(r"\s*```$", "", s_clean).strip()
    if (s_clean.startswith("{") and s_clean.endswith("}")) or (s_clean.startswith("[") and s_clean.endswith("]")):
        try:
            obj = json.loads(s_clean)
            if isinstance(obj, dict):
                # Check for OpenAI / Anthropic agent tool-call JSON wrappers
                if "name" in obj and "arguments" in obj:
                    args = obj["arguments"]
                    if isinstance(args, str) and args.strip().startswith("{"):
                        try:
                            args = json.loads(args)
                        except Exception:
                            pass
                    if isinstance(args, dict):
                        for k, v in args.items():
                            if any(kw in k.lower() for kw in ("response", "answer", "result", "final")):
                                got = str(v)
                                break
                else:
                    for k, v in obj.items():
                        if any(kw in k.lower() for kw in ("answer", "result", "final", "response")):
                            got = str(v)
                            break
        except Exception:
            pass
    # Restrict XML tag stripper to CoT reasoning wrappers e.g. <think>, <reasoning>, <cot>
    got = re.sub(r"<(?:think|thinking|thought|reasoning|cot|system_2_trace)>.*?</(?:think|thinking|thought|reasoning|cot|system_2_trace)>", "", got, flags=re.IGNORECASE | re.DOTALL)
    # Head + Tail truncation to preserve final conclusions in ultra-long CoT outputs (>10k chars)
    if len(got) > MAX_GOT_LEN:
        got = got[:1000] + " " + got[-9000:]
    return got


# ------------------------------------------------------------- normalization
def norm_text(s):
    """Case, whitespace, section signs, markdown formatting, Roman numerals, invisible Unicode, and smart punctuation are forgiven."""
    s = _sanitize_got(s)
    s = s.replace("\x00", "")
    s = re.sub(r"[\u200b\u200c\u200d\u200e\u200f\ufeff]", "", s)
    s = s.replace("\xa0", " ")
    s = s.replace("§", " ").replace("§", " ")
    s = (s.replace("‘", "'").replace("’", "'")
           .replace("“", '"').replace("”", '"')
           .replace("—", "-").replace("–", "-"))
    # Normalize Unicode superscripts and caret exponents (e.g. m³ or m^3 -> m3)
    s = s.replace("¹", "1").replace("²", "2").replace("³", "3").replace("⁴", "4")
    s = re.sub(r"([a-zA-Z°])\^([0-9]+)", r"\1\2", s)
    s = re.sub(r"[*_`~#|]", " ", s)
    s = re.sub(r"-{2,}", " ", s)
    # Hazard Division vs Class synonymy (e.g. Class 2.1 == Division 2.1; Division 3.0 == Division 3)
    s = re.sub(r"\b(?:class|division|div)\s*(\d+(?:\.\d+)?)\b", r"div \1", s, flags=re.IGNORECASE)
    s = re.sub(r"\bdiv\s*(\d+)\.0\b", r"div \1", s, flags=re.IGNORECASE)
    # Temperature unit normalization
    s = re.sub(r"\b(?:degrees?|deg\.?)\s*celsius\b", "°c", s, flags=re.IGNORECASE)
    s = re.sub(r"\b(?:degrees?|deg\.?)\s*fahrenheit\b", "°f", s, flags=re.IGNORECASE)
    s = re.sub(r"\b(?:degrees?|deg\.?)\s*c\b", "°c", s, flags=re.IGNORECASE)
    s = re.sub(r"\b(?:degrees?|deg\.?)\s*f\b", "°f", s, flags=re.IGNORECASE)
    # ⛔ ADDED 2026-08-05 — BARE ANGULAR DEGREES. The four rules above fold only degrees
    # of TEMPERATURE. An angle ("20 degrees from horizontal", 10 CFR 50.55a) was left
    # unfolded, so a response of "20°" graded WRONG against a gold of "20 degrees" —
    # same value, different notation, reported as a caught hallucination. Runs AFTER the
    # temperature rules so "degrees celsius" is already consumed and cannot be clipped.
    s = re.sub(r"(?<=\d)\s*(?:degrees?|deg\.?)(?![a-z])", "°", s, flags=re.IGNORECASE)
    # Convert compound rate units using "per" e.g. "mg per kg" -> "mg/kg"
    s = re.sub(r"\b([a-z]+)\s+per\s+([a-z0-9]+)\b", r"\1/\2", s, flags=re.IGNORECASE)
    # Conversational CFR citation normalization
    s = re.sub(r"\bcode\s+of\s+federal\s+regulations\b", "cfr", s, flags=re.IGNORECASE)
    s = re.sub(r"\bsection\s+(\d{2,3}\.\d+)\s+of\s+title\s+(\d{1,2})\b", r"\2 cfr \1", s, flags=re.IGNORECASE)
    s = re.sub(r"\btitle\s*(\d{1,2}),?\s*(?:of\s+the\s+)?cfr,?\s*section\s*(\d+)\b", r"\1 cfr \2", s, flags=re.IGNORECASE)
    s = re.sub(r"\btitle\s*(\d{1,2}),?\s*part\s*(\d{2,3}),?\s*section\s*(\d+)\b", r"\1 cfr \2.\3", s, flags=re.IGNORECASE)
    s = re.sub(r"\bpart\s*(\d{2,3}),?\s*section\s*(\d+)\b", r"\1.\2", s, flags=re.IGNORECASE)
    # Distributive UN/NA/ID prefix normalization
    s = re.sub(r"\b(un|na|id)\s*(?:numbers?|number\(s\)|codes?|code\(s\)|ids?|id\(s\))?\s*(?:are|is|assigned|of)?\s*(\d{4})\s*(?:and|or|,)\s*(\d{4})\b", r"\1\2 \1\3", s, flags=re.IGNORECASE)
    s = re.sub(r"\bpacking\s*group\b", "pg", s, flags=re.IGNORECASE)
    # Expand crammed packing group syntax e.g. PG1 -> pg 1, PGIII -> pg iii
    s = re.sub(r"\bpg([123])\b", r"pg \1", s, flags=re.IGNORECASE)
    s = re.sub(r"\bpg(i{1,3}|iv|v)\b", r"pg \1", s, flags=re.IGNORECASE)
    # Context-aware Roman numeral and spelled-out packing group conversion
    s = re.sub(r"\b(packing group|pg|group|zone)\s*(?:three|iii)\b", r"\1 3", s, flags=re.IGNORECASE)
    s = re.sub(r"\b(packing group|pg|group|zone)\s*(?:two|ii)\b", r"\1 2", s, flags=re.IGNORECASE)
    s = re.sub(r"\b(packing group|pg|group|zone)\s*(?:one|i)\b", r"\1 1", s, flags=re.IGNORECASE)
    # CFR Roman numeral bracket normalization (e.g. [i] or [ii] -> (i) or (ii))
    s = re.sub(r"\[(i{1,3}|iv|v|vi{1,3}|ix|x)\]", r"(\1)", s, flags=re.IGNORECASE)
    # Strip leading list index markers (e.g. 1. B1 -> B1 or 2) IB3 -> IB3)
    s = re.sub(r"(?:^|\n)\s*\d+[\.)]\s+", " ", s)
    s = re.sub(r"\s+", " ", s)
    return s.strip().lower().rstrip(".")


def norm_token(s):
    """Identifier normalization: 'UN 1203' == 'un1203'; '173.243' == '§ 173.243'."""
    t = norm_text(s).replace(" ", "")
    t = t.strip("'\"`’‘“”")
    if t.startswith("(") and t.endswith(")") and t.count("(") == 1 and t.count(")") == 1:
        t = t[1:-1]
    return t


def _safe_stem(x):
    return x[:-1] if len(x) > 3 and x.endswith("s") and not x.endswith("ss") else x


def safe_split_set(text, split_regex):
    text = str(text)
    def replacer(m):
        s = m.group(0)
        s = s.replace(',', '\x00').replace(';', '\x01').replace('&', '\x02').replace('\n', '\x03').replace('.', '\x06')
        s = re.sub(r"\band\b", "\x04", s, flags=re.IGNORECASE)
        s = re.sub(r"\bas\s+well\s+as\b", "\x05", s, flags=re.IGNORECASE)
        return s
    
    protected = re.sub(r"\([^)]*\)", replacer, text)
    parts = re.split(split_regex, protected, flags=re.IGNORECASE)
    
    res = []
    for p in parts:
        if p and p.strip():
            p = p.replace('\x00', ',').replace('\x01', ';').replace('\x02', '&').replace('\x03', '\n').replace('\x06', '.')
            p = p.replace('\x04', 'and').replace('\x05', 'as well as')
            res.append(p.strip())
    return res


def split_set(s):
    t = norm_text(s)
    t = re.sub(r"\([^)]*\)", "", t)
    t = re.sub(r"(?:^|(?<=\n)|(?<=,)|(?<=\t)|(?<=\s))\s*\([a-z0-9]\)\s*", " ", t, flags=re.IGNORECASE)
    t = re.sub(r"\b(?:as\s+well\s+as|along\s+with|in\s+addition\s+to|coupled\s+with|together\s+with)\b", ",", t, flags=re.IGNORECASE)
    t = re.sub(r"\b(?:with\s+the\s+exception\s+of|except(?:\s+for)?|excluding|other\s+than|aside\s+from)\s+[a-z0-9_-]+\b", "", t, flags=re.IGNORECASE)
    t = re.sub(r"\b[a-z0-9_-]+\s+(?:is|are)\s+(?:optional|recommended|suggested|permitted|allowed|not\s+required)\b", "", t, flags=re.IGNORECASE)
    t = re.sub(r"\b[a-z0-9_-]+\s+(?:is|are)\s+not\b", "", t, flags=re.IGNORECASE)
    t = re.sub(r"\b(?:not|no|is not|are not)\s+[a-z0-9_-]+\b", "", t, flags=re.IGNORECASE)
    parts = safe_split_set(t, r"[\n\r\t,;/|*&+]|\s+[-–—]\s+|\band\b|\bor\b")
    return {norm_token(p) for p in parts if norm_token(p)}


STOPWORDS = {'as', 'an', 'ai', 'language', 'model', 'the', 'answer', 'is', 'are', 'was', 'were',
             'assigned', 'special', 'provisions', 'provision', 'section', 'code', 'codes', 'requirements',
             'requirement', 'required', 'must', 'be', 'but', 'shall', 'per', 'according', 'to', 'under',
             'cfr', 'for', 'of', 'in', 'and', 'or', 'with', 'by', 'this', 'that', 'these', 'those',
             'following', 'below', 'above', 'based', 'on', 'certainly', 'sure', 'yes', 'no', 'here',
             'list', 'packing', 'group', 'class', 'hazard', 'item', 'items', 'value', 'values',
             'detail', 'details', 'you', 'comply', 'compliance', 'apply', 'applies', 'applicable', 'refer', 'see', 'use',
             'both', 'all', 'either', 'neither', 'none', 'each'}


def extract_set_elements(text, expected_elements):
    norm_t = norm_text(text)
    if not any("(" in str(x) for x in (expected_elements if isinstance(expected_elements, (list, tuple, set)) else [expected_elements])):
        norm_t = re.sub(r"\([^)]*\)", "", norm_t)
    norm_t = re.sub(r"(?:^|(?<=\n)|(?<=,)|(?<=\t)|(?<=\s))\s*\([a-z0-9]\)\s*", " ", norm_t, flags=re.IGNORECASE)
    norm_t = re.sub(r"\b(?:as\s+well\s+as|along\s+with|in\s+addition\s+to|coupled\s+with|together\s+with)\b", ",", norm_t, flags=re.IGNORECASE)
    # Strip negated/optional phrases e.g. "with the exception of T2", "T2 is optional", "except T2"
    norm_t = re.sub(r"\b(?:with\s+the\s+exception\s+of|except(?:\s+for)?|excluding|other\s+than|aside\s+from)\s+[a-z0-9_-]+\b", "", norm_t, flags=re.IGNORECASE)
    norm_t = re.sub(r"\b[a-z0-9_-]+\s+(?:is|are)\s+(?:optional|recommended|suggested|permitted|allowed|not\s+required)\b", "", norm_t, flags=re.IGNORECASE)
    norm_t = re.sub(r"\b[a-z0-9_-]+\s+(?:is|are)\s+not\b", "", norm_t, flags=re.IGNORECASE)
    norm_t = re.sub(r"\b(?:not|no|is not|are not)\s+[a-z0-9_-]+\b", "", norm_t, flags=re.IGNORECASE)
    raw_parts = safe_split_set(norm_t, r"[\n\r\t,;/|*&+]|\s+[-–—]\s+|\band\b|\bor\b")
    elements = set()
    e_norms = {norm_token(x) for x in (expected_elements if isinstance(expected_elements, (list, tuple, set)) else [expected_elements])}
    # Add stem forms (strip trailing 's' safely if len > 3)
    e_stems = {_safe_stem(x) for x in e_norms}
    
    is_word_set = any(not re.match(r"^[a-z]{1,3}\d{1,4}[a-z0-9]*$", x) for x in e_norms)
    for p in raw_parts:
        tok = norm_token(p)
        tok_stem = _safe_stem(tok)
        if tok and (tok in e_norms or tok_stem in e_stems):
            elements.add(tok_stem if tok_stem in e_stems else tok)
            continue
        words = p.split()
        non_filler = [w for w in words if w not in STOPWORDS]
        if not non_filler:
            continue
        for w in non_filler:
            w_norm = norm_token(w)
            w_stem = _safe_stem(w_norm)
            if w_stem in e_stems or w_norm in e_norms:
                elements.add(w_stem if w_stem in e_stems else w_norm)
            elif is_word_set or _is_code_or_unit(w_norm) or re.match(r"^[a-z]{1,3}\d{1,4}[a-z0-9]*$", w_norm):
                elements.add(w_norm)
    return elements


BOOL_YES = re.compile(r"(?:\bthe answer is\s+)?\b(yes|permitted|allowed|true|affirmative|positive|approved|required|mandatory|obligatory|necessary|compulsory|authorizes?|permits?|grants?|sanctions?|applicable|exception to the prohibition|exempted material|exemption)\b", re.IGNORECASE)
BOOL_NO = re.compile(r"(?:\bthe answer is\s+)?\b(no|not permitted|forbidden|prohibited|false|negative|disallowed|unauthorized|banned|denied|unlawful|restricted|inapplicable|waived|exempt|unnecessary)\b", re.IGNORECASE)


def as_bool(s):
    if isinstance(s, bool):
        return s
    if not isinstance(s, str):
        return None
    s_clean = re.sub(r"<(thinking|thought|reasoning)>.*?</\1>", "", s, flags=re.DOTALL | re.IGNORECASE)
    t = norm_text(s_clean)
    # Strip verbose preambles before measuring prefix window
    prev_t = None
    while t != prev_t:
        prev_t = t
        t = re.sub(r"^(?:based\s+on\s+[^:.,\n]*[:.,\n]|after\s+[^:.,\n]*[:.,\n]|my\s+determination\s+is:?|the\s+(?:final\s+)?answer\s+is:?)\s*", "", t, flags=re.IGNORECASE)
    # Boolean Fence-Sitting Guard: reject responses that refuse to commit (e.g. "yes and no", "yes/no")
    if re.search(r"^\s*(?:yes\s+(?:and|or|but)\s+no|yes\s*/\s*no|no\s+(?:and|or|but)\s+yes|no\s*/\s*yes)\b", t, flags=re.IGNORECASE):
        return None
    # Mid-Stream Self-Correction Guard: if response contains a correction signal, discard pre-correction text without consuming target
    t = re.sub(r"\b(?:wait,?\s*correction:?|actually,?(?=\s+(?:yes|no))|i\s*apologize,?\s*correction:?)\b\s*", "", t, flags=re.IGNORECASE)
    # Strip leading question echo e.g. "is it forbidden? " or "could the answer be yes? "
    t = re.sub(r"^(?:could|would|can|might|is|are|does|should)[^?]*\?\s*", "", t, flags=re.IGNORECASE)
    # Also strip rhetorical question echoes anywhere in the text e.g. "is it permitted? no."
    t = re.sub(r"\b(?:could|would|can|might|is|are|does|should)[^?]*\?\s*", "", t, flags=re.IGNORECASE)
    # Check explicit conclusion determination statements e.g. "the actual answer is no"
    m_ans = re.search(r"\bthe\s+(?:actual|final|correct|true)\s+answer\s+is\s+(yes|no|true|false)\b", t, flags=re.IGNORECASE)
    if m_ans:
        return m_ans.group(1).lower() in ("yes", "true")
    # Strip decoy phrases e.g. "some might say yes" or "one could argue yes"
    t = re.sub(r"\b(?:some|others|one|people)\s+(?:might|may|would|could)?\s*(?:say|think|guess|argue|claim)\s+yes\b", "", t, flags=re.IGNORECASE)
    # Compound Conjunction Reversal e.g. "Yes, but 172.504 actually prohibits this" -> "No"
    t = re.sub(r"\byes,?\s+(?:but|however|although|except|save\s+for)\b.*?\b(?:prohibits?|forbids?|forbidden|prohibited|disallows?|illegal|not\s+permitted|cannot)\b", "no", t, flags=re.IGNORECASE)
    # Map double negatives to affirmative/negative polarities
    t = re.sub(r"\bnot\s+(?:forbidden|prohibited|unlawful|illegal|restricted)\b", "permitted", t)
    t = re.sub(r"\bnot\s+(?:permitted|allowed|authorized|legal)\b", "forbidden", t)
    t = re.sub(r"\bno,?\s+(?:it\s+is\s+)?permitted\b", "yes, it is permitted", t)
    # Neutralize past-tense / historical permission framing e.g. "was previously permitted"
    t_clean_quotes = re.sub(r"\b(?:was|were|previously|formerly|historically)\s+(?:permitted|allowed|authorized|acceptable|required|valid)\b", "", t, flags=re.IGNORECASE)
    prefix = t_clean_quotes[:250]
    m_yes = BOOL_YES.search(prefix)
    m_no = BOOL_NO.search(prefix)
    if m_yes and not m_no:
        return True
    if m_no and not m_yes:
        return False
    if m_yes and m_no:
        return True if m_yes.start() < m_no.start() else False
    
    # CoT fallback: check concluding determination marker in the full text
    m_tail = re.search(r"(?:therefore|conclusion|answer is|result is|thus)[^.\n]*?\b(yes|no|true|false|permitted|prohibited)\b", t)
    if m_tail:
        w = m_tail.group(1)
        if w in ("yes", "true", "permitted"):
            return True
        if w in ("no", "false", "prohibited"):
            return False
    return None


# A CFR section (title, part.section, paragraph) e.g. 40 CFR 262.13 vs 49 CFR 173.202.
#
# The part group is 1-3 digits, but a ONE-digit part is only accepted when an explicit
# "NN CFR" title precedes it (enforced in cite_parts below). Reason: several titles put
# their operative content in single-digit parts — 38 CFR parts 3 and 4, 47 CFR part 2 —
# and the previous 2-3 digit floor made every such citation invisible. The engine could
# not see "38 CFR 4.14" or "47 CFR 2.106" at all, so the boolean adjudicator's
# grounding block (which runs only `if req_parts:`) silently did not execute for them:
# NOTE: this citation is SYNTHETIC, deliberately chosen because
# "4.14" is a substring of "14.144", verified non-existent against
# the official eCFR Part 14 XML on 2026-09-03.
# a response citing 38 CFR 14.144 scored CORRECT against a required 38 CFR 4.14,
# because "4.14" is a substring of "14.144". 3,033 such citations already sit in the
# shipped banks, 2,911 of them in bank-47cfr.json.
# The title requirement preserves the original protection the 2-3 digit floor provided:
# a bare "1.5" or "2.0" in prose is a decimal, not a citation, and still does not match.
CITE_RE = re.compile(r"(?:(\d{1,2})\s*cfr\s*)?(?<![\d.])(\d{1,3}\.\d+)((?:\([0-9a-z]+\))*)", re.IGNORECASE)


def cite_parts(s, default_title="49"):
    """{(section, paragraph_path)} for every citation in the text; includes title if specified e.g. ('40:262.13', '')."""
    t_text = norm_text(s)
    # Neutralize excluded paragraph phrases e.g. "excluding paragraph (c)" or "except (c)"
    t_text = re.sub(r"\b(?:excluding|except(?:\s+for)?|other\s+than|aside\s+from)\s+(?:paragraph\s+)?(?:\([a-z0-9]+\)|[a-z0-9]+)\b", "", t_text, flags=re.IGNORECASE)
    # Expand hyphenated ranges e.g. "172.504 - 172.507" -> "172.504, 172.505, 172.506, 172.507"
    def expand_ranges(m):
        title_prefix = m.group(1) or ""
        part = m.group(2)
        if not title_prefix and len(part) == 1:
            return m.group(0)
        end_title = m.group(4)
        if end_title and title_prefix and end_title.split()[0] != title_prefix.split()[0]:
            return m.group(0)
        start_sec = int(m.group(3))
        end_sec = int(m.group(5))
        if 0 < end_sec - start_sec <= 20:
            return ", ".join(f"{title_prefix}{part}.{i}" for i in range(start_sec, end_sec + 1))
        return m.group(0)
    t_text = re.sub(
        r"(\b\d{1,2}\s*cfr\s*)?\b(\d{1,3})\.(\d+)\s*(?:[-–—]|to)\s*(?:(\d{1,2}\s*cfr\s*)?\2\.)?(\d+)\b(?!\.\d)",
        expand_ranges, t_text, flags=re.IGNORECASE,
    )

    # Expand paragraph ranges e.g. "173.202(a)-(c)" or "173.202(b)(1)-(3)"
    def expand_para_ranges(m):
        title_prefix = m.group(1) or ""
        prefix = m.group(2)
        if not title_prefix and len(prefix.split(".", 1)[0]) == 1:
            return m.group(0)
        p1 = m.group(3)
        p2 = m.group(4)
        if p1.isdigit() and p2.isdigit():
            i1 = int(p1)
            i2 = int(p2)
            if 0 < i2 - i1 <= 10:
                return ", ".join(f"{title_prefix}{prefix}({i})" for i in range(i1, i2 + 1))
        elif len(p1) == 1 and len(p2) == 1 and p1.isalpha() and p2.isalpha():
            c1 = ord(p1.lower())
            c2 = ord(p2.lower())
            if 0 < c2 - c1 <= 10:
                return ", ".join(f"{title_prefix}{prefix}({chr(c)})" for c in range(c1, c2 + 1))
        return m.group(0)
    t_text = re.sub(
        r"(\b\d{1,2}\s*cfr\s*)?\b(\d{1,3}\.\d+(?:\([a-z0-9]+\))*)\(([a-z0-9]+)\)\s*(?:[-–—]|to)\s*(?:(?:\d{1,2}\s*cfr\s*)?\2)?\(([a-z0-9]+)\)",
        expand_para_ranges, t_text, flags=re.IGNORECASE,
    )

    # Expand relative paragraph lists e.g. "173.202(a), (b), and (c)" -> "173.202(a), 173.202(b), and 173.202(c)"
    def expand_relative_paras(m):
        title_prefix = m.group(1) or ""
        base_cite = m.group(2)
        sec_base = base_cite.split("(")[0]
        if not title_prefix and len(sec_base.split(".", 1)[0]) == 1:
            return m.group(0)
        tail = m.group(3)
        expanded = re.sub(
            r"([,\s]+(?:and\s+)?)\(([0-9a-z]+)\)",
            lambda rm: f"{rm.group(1)}{title_prefix}{sec_base}({rm.group(2)})",
            tail,
        )
        return f"{title_prefix}{base_cite}{expanded}"
    t_text = re.sub(
        r"(\b\d{1,2}\s*cfr\s*)?\b(\d{1,3}\.\d+\([0-9a-z]+\))((?:[,\s]+(?:and\s+)?\([0-9a-z]+\))+)",
        expand_relative_paras, t_text, flags=re.IGNORECASE,
    )

    # Expand trailing relative sections e.g. "172.504, .505, and .506" -> "172.504, 172.505, and 172.506"
    def expand_trailing_secs(m):
        title_prefix = m.group(1) or ""
        base_part = m.group(2)
        if not title_prefix and len(base_part) == 1:
            return m.group(0)
        sec1 = m.group(3)
        tail = m.group(4)
        def rel_sub(rm):
            return f", {title_prefix}{base_part}.{rm.group(1)}"
        expanded_tail = re.sub(r"[,\s]+and\s+\.(\d+)", f" and {title_prefix}{base_part}.\\1", tail)
        expanded_tail = re.sub(r"[,\s]+\.(\d+)", rel_sub, expanded_tail)
        return f"{title_prefix}{base_part}.{sec1}{expanded_tail}"
    t_text = re.sub(
        r"(\b\d{1,2}\s*cfr\s*)?\b(\d{1,3})\.(\d+)((?:[,\s]+(?:and\s+)?\.\d+)+)\b",
        expand_trailing_secs, t_text, flags=re.IGNORECASE,
    )

    out = set()
    for m in CITE_RE.finditer(t_text):
        title = m.group(1)
        sec = m.group(2)
        para = m.group(3) or ""
        # A one-digit part is only a citation when a title says so. Without this,
        # every decimal in prose ("1.5 hours", "2.0 mg") becomes a fake pin.
        if not title and len(sec.split(".", 1)[0]) == 1:
            continue
        if not title:
            title = default_title
        sec_key = f"{title}:{sec}" if title else sec
        out.add((sec_key, para))
    return out


def cites(s, default_title="49"):
    """Bare-section token set — retained for callers that only ground at section level."""
    return {sec for sec, _ in cite_parts(s, default_title=default_title)}


# ------------------------------------------------------- prose vs token guard
# PINNED MIRROR of tools/setkey.py::is_atomic_element. grade_eval.py is the
# single file a buyer runs (build_repro_kit ships this file ALONE), so it must
# stay import-free; the mirror keeps it standalone. --selftest asserts byte
# parity with setkey.is_atomic_element whenever setkey is importable, so the two
# cannot drift silently. If you change one, change both.
_WS = re.compile(r"\s+")
_AND = re.compile(r"\band\b", re.IGNORECASE)
_OR = re.compile(r"\bor\b", re.IGNORECASE)
_CLAUSE = re.compile(
    r"\b(shall|must|may|will|would|should|can|cannot|"
    r"means?|meant|includes?|included|consists?|"
    r"is|are|was|were|be|been|being|has|have|had|"
    r"who|whom|whose|which|that|"
    r"except|unless|provided|pursuant|subject|"
    r"if|when|whenever|where|while|during|until|"
    r"not|no|any|each|every|other|than|"
    r"this|these|those|such)\b",
    re.IGNORECASE,
)
_ELEMENT_MAX_CHARS = 100
_ELEMENT_MAX_WORDS = 12


def _n_atomic(s):
    return _WS.sub(" ", (s or "")).strip()


def is_atomic_element(e):
    """True when `e` is a code or a short name, not a clause of prose. Mirror of
    setkey.is_atomic_element (see note above)."""
    e = _n_atomic(e)
    if not e or e.endswith(":"):
        return False
    if len(e) > _ELEMENT_MAX_CHARS or len(e.split()) > _ELEMENT_MAX_WORDS:
        return False
    if "," in e or ";" in e or "|" in e:
        return False
    if _AND.search(e) or _OR.search(e):
        return False
    if _CLAUSE.search(e):
        return False
    if re.search(r"\.\s+\S", e):
        return False
    if re.match(r"^\([a-z0-9ivxlc]+\)\s", e, re.IGNORECASE):
        return False
    return True


# A canonical token is an identifier / code / citation / number-with-unit, or a
# short (<=4 word) defined term — the shapes an exact_match answer legitimately
# takes. Anything else that reaches exact_match is regulatory PROSE, and a
# byte-strict matcher on prose rewards transcription and punishes understanding.
_CODE_UNIT_RES = (
    re.compile(r"(?:un|na)\s?\d{3,4}", re.IGNORECASE),          # UN3090, NA 1993
    re.compile(r"(?:\d{1,2}\s*cfr\s*)?§?\s*\d+\.\d+[a-z0-9()]*", re.IGNORECASE),  # 173.185(f)
    re.compile(r"-?\d[\d,]*(?:\.\d+)?\s*[a-z%µ°/.\-]{0,12}", re.IGNORECASE),  # 90 days, 5 L
    re.compile(r"[a-z0-9][a-z0-9/\-]{0,5}", re.IGNORECASE),      # X, B33, IB2, T4
)


def _is_code_or_unit(s):
    t = _n_atomic(s)
    return any(rx.fullmatch(t) for rx in _CODE_UNIT_RES)


def is_canonical_token_answer(expected):
    """True iff `expected` is an atomic token AND (a code/citation/number-unit
    shape OR a <=4-word defined term). False => regulatory prose => route to the
    judgment tier rather than byte-grade it."""
    e = _n_atomic("" if expected is None else str(expected))
    if not is_atomic_element(e):
        return False
    return _is_code_or_unit(e) or (1 <= len(e.split()) <= 4)


def _atomic_parts(expected):
    """Split `expected` into the enumeration members a set grader would grade,
    preserving the whitespace is_atomic_element needs (split_set strips it)."""
    if isinstance(expected, (list, tuple)):
        raw = [str(x) for x in expected]
    else:
        raw = re.split(r"[,;]|\band\b", "" if expected is None else str(expected),
                       flags=re.IGNORECASE)
    out = []
    for p in raw:
        p = re.sub(r"^\s*(?:and|or)\s+", "", (p or "").strip(), flags=re.IGNORECASE)
        p = p.strip().strip(".").strip()
        if p:
            out.append(p)
    return out


def is_prose_not_token_set(expected):
    """True when `expected` is NOT a bounded set of >=2 atomic tokens — i.e. it is
    prose, and structured_match must refuse to substring-grade it."""
    parts = _atomic_parts(expected)
    if len(parts) < 2:
        return True
    return not all(is_atomic_element(p) for p in parts)




KNOWN_UNITS = {"wh", "kwh", "mwh", "l", "litres", "liters", "liter", "ml", "mls", "gal", "gals", "gallons", "kg", "kgs", "kilo", "kilos", "g", "mg", "lbs", "lb", "pounds", "oz", "ozs", "day", "days", "hour", "hours", "week", "weeks", "year", "years", "month", "months", "mm", "cm", "m", "km", "m3", "m2", "cm3", "cm2", "mm3", "mm2", "psi", "bar", "kpa", "°c", "celsius", "c", "°f", "fahrenheit", "f", "k", "kelvin", "%", "percent", "pct", "percents", "ug/l", "mg/l",
                # Time abbreviations. A unit the lexer cannot TAG can never be
                # folded, so "3 yr" against a gold of "3 years" was not a
                # comparison failure — "yr" never became a UNIT token at all, and
                # the number arrived dimensionless. Folding alone did not fix it;
                # the token has to be recognisable first. Kept to durations, where
                # the abbreviation is unambiguous. "min" is minute, never minimum;
                # "mo" is month; "sec" is second, never section — the citation
                # masker removes section addresses well before this point.
                #
                # ⚠ SCOPE IS DELIBERATELY NARROW. A first attempt also added
                # "degree"/"degrees"/"°" and "percentage" here. Those paths
                # ALREADY worked through a different route, and adding them
                # changed how the existing tokens tagged: "20 degrees" vs "20°"
                # and "100 degrees celsius" vs "100°c" both broke, and percent
                # regressed. Two of those were regression tests locking in fixes
                # made on 2026-08-05. Only genuinely UNTAGGABLE abbreviations
                # belong here; if a form already grades correctly, leave it alone.
                "yr", "yrs", "hr", "hrs", "mo", "mos", "wk", "wks",
                # ⚡ EXPOSURE AND DOSE BASE UNITS — the vocabulary of every
                # domain this engine is aimed at, and it was missing.
                #
                # These are ATOMS, not compounds. Adding "mg/m3" as a literal
                # would have fixed mg/m3 and left µg/m3, mg/kg/day, mEq/kg and
                # every future derived unit broken — the enumerated-scope defect
                # this repository produces more reliably than any other. With the
                # atoms present, is_known_unit composes them: any combination of
                # a known numerator over a known denominator is known.
                #
                # Measured need: 29 CFR 1910 carries 187 ppm and 78 µg/m3
                # occurrences plus Table Z-1's ~500 substances; the FDA corpus
                # needs mcg, mEq and IU. None of them lexed before this.
                "µg", "ug", "mcg", "ng", "ppm", "ppb", "ppt",
                "meq", "mmol", "mol", "iu", "dl", "cc", "mppcf",
                # the ALIAS TARGETS, not just the abbreviations. "min" folds to
                # "minute", so a rate of mcg/kg/min is only known if "minute"
                # itself is — otherwise the compound check fails on its own
                # canonical form, which is the most confusing way to fail.
                "minute", "minutes", "second", "seconds",
                # the phrase-fold targets (_UNIT_PHRASES): "square feet" -> ft2
                "ft2", "ft3"}
UNIT_MAP = {"litres": "l", "liters": "l", "liter": "l", "gallons": "gal", "gals": "gal", "pounds": "lbs", "lb": "lbs", "kilo": "kg", "kilos": "kg", "kgs": "kg", "mls": "ml", "grams": "g", "kilograms": "kg", "milligrams": "mg", "ozs": "oz", "celsius": "°c", "c": "°c", "fahrenheit": "°f", "f": "°f", "kelvin": "k", "percent": "%", "pct": "%", "percents": "%", "µg/l": "ug/l", "ug/l": "ug/l", "mg/l": "mg/l",
            # µ and mc are the SAME PREFIX written three ways. Only the compound
            # "µg/l" was mapped, so a bare "µg" — and therefore every µg-based
            # derived unit, µg/m3 among them — folded to a different token than
            # "ug" and compared unequal to its own synonym.
            "µg": "ug", "mcg": "ug", "μg": "ug"}

# --------------------------------------------------------------------------
# CANONICAL UNIT FOLDING — one definition, shared by the aligner and numeric.
#
# These are NOTATIONS OF THE SAME UNIT: "50 percent" and "50%" are the same
# answer written two ways, and grading them as different answers is a defect in
# the grader, not a wrong answer by the model.
#
# ⚠ What is deliberately NOT here: cross-unit conversion (hour->day, kg->lb,
# inch->mil). Those change the expressed dimension, the questions ask for the
# value "as published", and folding them makes the grader LENIENT in a way a
# buyer can attack. Leniency is the more expensive failure. Scale conversion
# between related units stays in UNIT_SCALES, which is applied separately and
# adjusts the VALUE as well as the label.
#
# WHY IT MOVED HERE: an equivalent table lived in adjudicators/numeric.py, which
# parsing/lexer.py cannot import. So LexicalExtractor.align() compared RAW unit
# tokens — `eu != gu` on the strings "%" and "percent" — found no match, found no
# scale, and left the number carrying a unit the expected-unit filter then
# dropped. Nine tests were carried as xfail against exactly that. Two modules
# owning two spellings of the same rule is how it happened; one definition both
# import is the fix.
# --------------------------------------------------------------------------
_UNIT_ALIAS = {
    "degree": "°", "degrees": "°", "deg": "°", "degs": "°", "arcdegree": "°",
    "percent": "%", "pct": "%", "percentage": "%", "percents": "%", "percentages": "%",
    "yr": "year", "yrs": "year",
    "hr": "hour", "hrs": "hour",
    "min": "minute", "mins": "minute",
    "sec": "second", "secs": "second",
    "mo": "month", "mos": "month",
    "wk": "week", "wks": "week",
}


# ⚡ THE EXPONENT IS SEPARATE MARKUP, AND STRIPPING TAGS LEAVES A SPACE.
#
# eCFR writes mg/m³ as "mg/m<SU>3</SU>". Once tags become spaces the text reads
# "mg/m 3", so a unit lexer that stops at whitespace sees "mg/m" and then a stray
# number 3 — and a naive \bmg/m3\b pattern scores ZERO on the single most
# important unit in the OSHA corpus, where 50 occurrences and a ~500-substance
# PEL table are written that way.
#
# This is the same defect that hid the body-surface-area doses in the FDA bank:
# openFDA renders mg/m² as "mg/m 2", the denominator whitelist held "m2", and 171
# cytotoxic doses were recorded as flat. Two different corpora, one root cause —
# so the repair belongs HERE, in the shared unit model, not in either extractor.
# ⛔ THE SLASH IS REQUIRED, and leaving it out was a live defect for one commit.
#
# A first version matched \b(m|cm|mm|ft|in|yd)\s+([23])\b — which also matches the
# ORDINARY ENGLISH "in 3 days", rewriting it to "in3 days" and destroying the
# number in any response that used the word. This function runs on EVERY lexed
# string, including a model's free prose, so a false positive here corrupts
# grading everywhere.
#
# Every real case found today carries a slash: mg/m 3, µg/m 3, mg/m 2. Requiring
# it makes the pattern unable to fire on prose at all, which is the right trade —
# a missed exponent is a visible grading failure, a corrupted sentence is silent.
_EXPONENT_GAP = re.compile(r"(/\s*(?:m|cm|mm|ft|yd))\s+([23])\b", re.IGNORECASE)
_SUPERSCRIPT = {"²": "2", "³": "3"}

# ⛔ A UNIT WRITTEN AS A PHRASE WAS INVISIBLE, AND IT FAILED 51 CORRECT ANSWERS.
#
# EPA writes tolerance tables as "Parts per million: 30". A model shown that
# span answers "30 parts per million" — and the grader failed it against gold
# "30 ppm", because "ppm" is in the vocabulary while the phrase never lexes as
# a unit at all (the token pattern cannot match three words). Measured on the
# 40 CFR three-arm run: the arm HOLDING the gold span scored 15% — below
# closed-book — with 51 of 60 "failures" being correct answers in phrase form.
# Casebook instance #14: the instrument, not the world.
#
# Phrases fold to the canonical atom BEFORE tokenisation, exactly like the
# exponent repair above — one shared fix, both the expected and response paths.
_UNIT_PHRASES = [
    (re.compile(r"\bparts\s+per\s+million\b", re.IGNORECASE), "ppm"),
    (re.compile(r"\bparts\s+per\s+billion\b", re.IGNORECASE), "ppb"),
    (re.compile(r"\bparts\s+per\s+trillion\b", re.IGNORECASE), "ppt"),
    (re.compile(r"\bsquare\s+(?:feet|foot)\b", re.IGNORECASE), "ft2"),
    (re.compile(r"\bcubic\s+(?:feet|foot)\b", re.IGNORECASE), "ft3"),
    (re.compile(r"\bsquare\s+met(?:er|re)s?\b", re.IGNORECASE), "m2"),
    (re.compile(r"\bcubic\s+met(?:er|re)s?\b", re.IGNORECASE), "m3"),
]


# ⛔ THE SEC SPELLS ITS NUMBERS, AND 16 CORRECT ANSWERS FAILED FOR IT.
#
# 17 CFR writes "six months", "five years", "five business days". A model shown
# the pinned span echoes the words; gold is "6 months"; the grader cannot parse
# a numeral it never sees. Casebook #15 — third member of the same family as
# the exponent split (#13) and the phrase units (#14): SURFACE FORM variance
# between the source text and the canonical gold.
#
# The fold is deliberately narrow: a number-word converts ONLY when a unit word
# (optionally preceded by business/calendar/working) follows it. Blanket-folding
# would invent numbers inside ordinary prose ("one of the parties") and feed the
# multi-numeric conflict guard false positives — the exact class of self-inflicted
# instrument damage this file keeps a casebook about.
_WORD_NUMS = {"one":"1","two":"2","three":"3","four":"4","five":"5","six":"6",
              "seven":"7","eight":"8","nine":"9","ten":"10","eleven":"11",
              "twelve":"12","fifteen":"15","twenty":"20","thirty":"30",
              "forty":"40","forty-five":"45","fifty":"50","sixty":"60",
              "ninety":"90"}
_UNIT_WORDS_FOR_NUM = (r"(?:business\s+|calendar\s+|working\s+)?"
                       r"(?:years?|months?|weeks?|days?|hours?|minutes?|"
                       r"seconds?|percent|times)")
_WORD_NUM_RE = re.compile(
    r"\b(" + "|".join(sorted(_WORD_NUMS, key=len, reverse=True)) + r")\s+"
    r"(?=" + _UNIT_WORDS_FOR_NUM + r"\b)", re.IGNORECASE)


def restore_exponent(s):
    """Rejoin a unit with the exponent markup separated from it, and fold
    multi-word unit phrases to the canonical atom the vocabulary knows."""
    if not isinstance(s, str) or not s:
        return s
    for ch, digit in _SUPERSCRIPT.items():
        s = s.replace(ch, digit)
    s = s.replace("^", "")
    s = _EXPONENT_GAP.sub(r"\1\2", s)
    for pat, atom in _UNIT_PHRASES:
        s = pat.sub(atom, s)
    s = _WORD_NUM_RE.sub(lambda m: _WORD_NUMS[m.group(1).lower()] + " ", s)
    return s


def _fold_atom(w):
    """Fold ONE unit component. Order matters: alias before de-pluralising so
    "yrs" and "degrees" resolve, then again after so a plural of an alias target
    ("percentages") still lands. UNIT_MAP last — it holds the older
    dimension-preserving spellings ("liters" -> "l") that predate this table."""
    w = _UNIT_ALIAS.get(w, w)
    if w.endswith("s") and len(w) > 2:
        w = w[:-1]
    w = _UNIT_ALIAS.get(w, w)
    return UNIT_MAP.get(w, w)


def fold_unit(u):
    """Canonical form of a unit label, or the input unchanged if unrecognised.

    ⚡ DERIVED UNITS ARE FIRST-CLASS, because a measurement engine that cannot
    represent one is missing the thing metrology is built on.

    Before this, the only compound units that existed were "mg/l" and "ug/l" —
    two literals someone added when they hit that case. Everything else with a
    slash was invisible: the lexer emitted no UNIT token for "mg/kg", so the
    numeric adjudicator could not parse the item's OWN GOLD, and every
    denominator-bearing item graded False against itself. Measured on the FDA
    corpus: 5,617 items, 100% of them, failing on their own answer key.

    A dose of 100 mg/kg is not 100 mg. Keeping the components joined is what
    stops "100 mg" from ever satisfying "100 mg/kg" — see units_equivalent.
    """
    if not isinstance(u, str):
        return u
    w = restore_exponent(u).strip().lower().rstrip(".,;:!?)")
    if not w:
        return u
    if "/" in w:
        # fold each component; "mg / kg / day" -> "mg/kg/day"
        parts = [p.strip() for p in w.split("/")]
        if all(parts):
            folded = "/".join(_fold_atom(p) for p in parts)
            # a literal entry (mg/l) still wins, preserving prior behaviour
            return UNIT_MAP.get(w, folded)
    return _fold_atom(w)


def unit_components(u):
    """The ordered components of a (possibly derived) unit label."""
    if not isinstance(u, str):
        return []
    w = u.strip().lower().rstrip(".,;:!?)")
    return [p.strip() for p in w.split("/") if p.strip()] if w else []


def is_known_unit(u, known=None):
    """True when EVERY component of a unit is recognised.

    ⛔ NOT an enumeration. Adding "mg/kg" to a list would have fixed mg/kg and
    left mg/m2, mcg/kg/min, mEq/kg/day and every future derived unit broken —
    the enumerated-scope defect this repository produces more reliably than any
    other. A derived unit is known exactly when its parts are.
    """
    known = KNOWN_UNITS if known is None else known
    parts = unit_components(u)
    if not parts:
        return False
    if len(parts) == 1:
        return parts[0] in known
    return all(p in known or _fold_atom(p) in known for p in parts)


def units_equivalent(a, b):
    """True when two unit labels denote the same unit written differently.

    ⚠ A derived unit is equivalent only to a derived unit with the SAME
    components in the SAME order. "mg" never satisfies "mg/kg": the grader that
    accepted it would mark a model correct for answering a flat dose when the
    label states a weight-based one.
    """
    if a is None or b is None:
        return a == b
    return fold_unit(a) == fold_unit(b)

UNIT_SCALES = {
    ("kg", "g"): 1000.0,
    ("g", "kg"): 0.001,
    ("g", "mg"): 1000.0,
    ("mg", "g"): 0.001,
    ("kg", "mg"): 1000000.0,
    ("mg", "kg"): 0.000001,
    ("l", "ml"): 1000.0,
    ("ml", "l"): 0.001,
    ("m", "cm"): 100.0,
    ("cm", "m"): 0.01,
    ("m", "mm"): 1000.0,
    ("mm", "m"): 0.001,
    # Convention (enforced by every other entry and by LexicalExtractor.align):
    #   key (A, B) -> value V means 1 A == V B.
    # 1 km == 1000 m, so ("km","m") is 1000.0 and ("m","km") is 0.001.
    # These two were inverted; the inversion made the engine grade "5000 m"
    # WRONG against an expected "5 km" (5000 / 0.001 = 5,000,000).
    ("km", "m"): 1000.0,
    ("m", "km"): 0.001,
    ("mg/l", "ug/l"): 1000.0,
    ("ug/l", "mg/l"): 0.001,
}


# ── F7: physical dimensions, derived rather than declared ────────────────────
# The multi-numeric guard used to treat EVERY second figure in a response as a
# competing claim. Legitimate regulatory prose almost always carries a
# qualifying figure alongside the answer — an altitude beside an airspeed, a
# filing window beside a threshold — so the guard rejected correct answers
# across every domain. Measured: 6 of 6 FAA/SEC domain tests, and the defect is
# domain-independent (the same sentence fails under the HAZMAT config).
#
# Two numbers only compete if they measure THE SAME KIND OF THING. That is a
# dimension question, and the domain config already answers it: a conversion
# factor between two units exists precisely when those units measure the same
# dimension. So the dimension classes are the connected components of the
# unit-conversion graph — no hardcoded dimension table, and a new domain pack
# gets correct dimensions simply by declaring its conversions.
#
# A unit with no declared conversion is its own class. That is the conservative
# direction: it can only ever make two numbers look MORE alike, never less.
_DIM_CACHE: dict = {}


def unit_dimension_map(scales) -> dict:
    """Map each unit to a representative of its dimension class.

    Union-find over the conversion pairs in `scales`. Built once per distinct
    scales table and cached, so the per-comparison cost is a dict lookup and
    the engine's linear-time guarantee is untouched.
    """
    key = id(scales)
    cached = _DIM_CACHE.get(key)
    if cached is not None:
        return cached

    parent: dict = {}

    def find(u):
        parent.setdefault(u, u)
        root = u
        while parent[root] != root:
            root = parent[root]
        while parent[u] != root:      # path compression
            parent[u], u = root, parent[u]
        return root

    for a, b in scales:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    dims = {u: find(u) for u in parent}
    _DIM_CACHE[key] = dims
    return dims


def same_dimension(u1, u2, scales=None) -> bool:
    """True iff two units measure the same physical dimension.

    Identical units always match. Otherwise they must be connected in the
    conversion graph. `None` (a dimensionless number) is never the same
    dimension as a real unit — see `_dimensionally_disjoint` for why that
    asymmetry is load-bearing rather than an oversight.
    """
    if u1 == u2:
        return True
    if not u1 or not u2:
        return False
    dims = unit_dimension_map(scales if scales is not None else UNIT_SCALES)
    return dims.get(u1, u1) == dims.get(u2, u2)
