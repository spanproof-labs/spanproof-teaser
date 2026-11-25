"""Source-consistent comparators — the deterministic answer to "No more than 5 years."

WHY. The numeric adjudicator rejects any response that wraps the target value in an
inequality ("at least 150 feet") or a negation ("does not exceed 0.5 rem"). That stops a
model hedging around a value the regulation states flatly. But regulations state most
constants WITH a comparator, and a correct free-text answer repeats it. Measured
2026-09-22 on 4,406 bank items: restating the regulation's own comparator passed 0 times.

THE RULE. A guard rejection is waived only when EVERY comparator the response attaches to
the target value is a comparator the pinned source span attaches to that same value, and
no bare negation of the value remains once those comparator phrases are removed. So:

    source "shall not exceed 12,500 pounds"
      "No more than 12,500 pounds."     -> MAX == MAX       waived
      "More than 12,500 pounds."        -> GT  not in {MAX} still rejected
      "Less than 12,500 pounds."        -> LT  not in {MAX} still rejected (strictness differs)
      "Not 12,500 pounds."              -> bare negation     still rejected
    source "12,500 pounds" (no comparator)
      "At least 12,500 pounds."         -> MIN not in {}     still rejected (the hedge)

Waiving the guard does not accept the answer: every later numeric check (value, unit,
tolerance, rival numbers) still runs. Pure stdlib, deterministic, no I/O.
"""
from __future__ import annotations

import re

MAX, LT, MIN, GT, BY, NOT_BEFORE = "MAX", "LT", "MIN", "GT", "DEADLINE", "NOT_BEFORE"

# Longest phrases first within the list: "not more than" must win over "more than".
_LEADING = [
    # Any "not exceed" is a maximum: "does/shall/need/to not exceed", and the bare
    # "(ii) Not exceed 90 percent" of a list item.
    (r"not\s+exceeds?", MAX),
    # Inclusive forms: "equal to or greater than" is >=, not >. Without these the longest
    # match was "greater than" and the class came out GT.
    (r"equal\s+to\s+or\s+(?:greater|larger|more|higher)\s+than", MIN),
    (r"(?:greater|larger|more|higher)\s+than\s+or\s+equal\s+to", MIN),
    (r"equal\s+to\s+or\s+(?:less|smaller|fewer|lower)\s+than", MAX),
    (r"(?:less|smaller|fewer|lower)\s+than\s+or\s+equal\s+to", MAX),
    (r"not\s+be\s+(?:less|fewer|lower|smaller)\s+than", MIN),
    (r"not\s+be\s+(?:more|greater|higher|larger)\s+than", MAX),
    (r"at\s+or\s+(?:under|below)", MAX), (r"at\s+or\s+(?:over|above)", MIN),
    (r"not\s+in\s+excess\s+of", MAX),
    (r"not\s+more\s+than", MAX), (r"no\s+more\s+than", MAX),
    (r"not\s+greater\s+than", MAX), (r"no\s+greater\s+than", MAX),
    (r"no\s+higher\s+than", MAX), (r"not\s+higher\s+than", MAX),
    (r"not\s+to\s+exceed", MAX), (r"not\s+exceeding", MAX), (r"never\s+exceed(?:s|ing)?", MAX),
    (r"a\s+maximum\s+of", MAX), (r"maximum\s+of", MAX), (r"at\s+most", MAX), (r"up\s+to", MAX),
    (r"not\s+less\s+than", MIN), (r"no\s+less\s+than", MIN),
    (r"not\s+fewer\s+than", MIN), (r"no\s+fewer\s+than", MIN),
    (r"no\s+lower\s+than", MIN), (r"not\s+lower\s+than", MIN),
    (r"a\s+minimum\s+of", MIN), (r"minimum\s+of", MIN), (r"at\s+least", MIN),
    (r"no\s+later\s+than", BY), (r"not\s+later\s+than", BY), (r"within", BY),
    (r"no\s+earlier\s+than", NOT_BEFORE), (r"not\s+earlier\s+than", NOT_BEFORE),
    (r"no\s+sooner\s+than", NOT_BEFORE), (r"not\s+sooner\s+than", NOT_BEFORE),
    (r"less\s+than", LT), (r"fewer\s+than", LT), (r"lower\s+than", LT), (r"below", LT), (r"under", LT),
    (r"more\s+than", GT), (r"greater\s+than", GT), (r"higher\s+than", GT), (r"in\s+excess\s+of", GT),
    (r"exceed(?:s|ing)?", GT), (r"above", GT), (r"over", GT),
]
_LEAD_RES = [(re.compile(r"(?:^|(?<=[^a-z]))" + p + r"\s*(?:\$|approximately\s+)?$"), c)
             for p, c in _LEADING]


# One pass over the whole text: does ANY comparator phrase occur at all? Most graded
# answers are bare values ("5 years."), and without this gate every one of them paid for
# ~48 anchored searches per number — +43% grading time measured on 2026-09-23.
_ANY = re.compile(r"(?:^|(?<=[^a-z]))(?:" + "|".join(p for p, _ in _LEADING) + r")(?![a-z])"
                  r"|\bor\s+(?:less|fewer|lower|under|below|smaller|shorter|more|greater|higher"
                  r"|longer|over|above|larger)\b")


def _leading(before: str):
    """The comparator phrase ending `before`, choosing the LONGEST phrase that matches.
    Order of the table must not decide it: "not exceeding" (a maximum) also ends in
    "exceeding" (a minimum's opposite). An earlier cut sorted by regex-source length and
    classified "not exceeding 1 year" as GT, which let 79 reversed limits through."""
    best = None
    for rx, cls in _LEAD_RES:
        hit = rx.search(before)
        if hit and (best is None or hit.start() < best[0].start()):
            best = (hit, cls)
    return best
_TRAILING = re.compile(
    r"^(?:\s*[a-z%°µ/.\-]+){0,3}?\s*\)?\s*,?\s*or\s+"
    r"(less|fewer|lower|under|below|smaller|shorter|more|greater|higher|longer|over|above|larger)\b")
_TRAIL_CLASS = {"less": MAX, "fewer": MAX, "lower": MAX, "under": MAX, "below": MAX,
                "smaller": MAX, "shorter": MAX,
                "more": MIN, "greater": MIN, "higher": MIN, "longer": MIN, "over": MIN,
                "above": MIN, "larger": MIN}
_NUM = re.compile(r"(?<![\w.])(\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+\.\d+|\.\d+|\d+)(?!\d)")
_NEG = r"\b(?:not|never|no|isn't|cannot|doesn't|does\s+not|isn\s*t)\s+(?:\w+\s+){0,3}$"
# "<number> <unit words> (" immediately before a value: the value is a conversion.
_PAREN_CONV = re.compile(
    r"(?<![\w.])(?:\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+\.\d+|\.\d+|\d+)\s*[a-z%°µ/.\-]*(?:\s+[a-z%°µ/.\-]+){0,2}\s*\(\s*$")


def _fold(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower().replace("’", "'"))


def _same(a: float, b: float) -> bool:
    return abs(a - b) <= 1e-9 * max(1.0, abs(b))


def _occurrences(text: str, value: float):
    for m in _NUM.finditer(text):
        try:
            v = float(m.group(1).replace(",", ""))
        except ValueError:
            continue
        if _same(v, value):
            yield m


def comparators(text: str, value: float) -> tuple[set, list]:
    """Comparator classes attached to `value` in `text`, and the (start, end) spans of
    the phrases that carried them."""
    t = _fold(text)
    classes, spans = set(), []
    if not _ANY.search(t):
        return classes, spans
    for m in _occurrences(t, value):
        before = t[max(0, m.start() - 48): m.start()]
        lead = _leading(before)
        if lead:
            hit, cls = lead
            classes.add(cls)
            spans.append((m.start() - (len(before) - hit.start()), m.start()))
        # A parenthetical conversion inherits the comparator of the quantity it
        # converts: "at least 46 m (150 ft)" puts MIN on 150 as well as on 46.
        conv = None if lead else _PAREN_CONV.search(t[max(0, m.start() - 60): m.start()])
        if conv:
            outer_start = m.start() - (len(t[max(0, m.start() - 60): m.start()]) - conv.start())
            outer = _leading(t[max(0, outer_start - 48): outer_start])
            if outer:
                classes.add(outer[1])
        tail = _TRAILING.match(t[m.end(): m.end() + 40])
        if tail:
            classes.add(_TRAIL_CLASS[tail.group(1)])
            spans.append((m.end(), m.end() + tail.end()))
    return classes, spans


def source_consistent(response: str, source: str | None, value: float) -> tuple[bool | None, str]:
    """Judge the response's comparator on `value` against the pinned `source`.

    True   consistent: the inequality/negation guards may be waived.
    False  definitely inconsistent: the response puts a comparator on the value that the
           source (which states exactly one) does not. A final rejection.
    None   undecided (no source, no comparator in the response, a source that attaches
           several comparators to the value, or a bare negation left over). The caller
           falls back to the guards, unchanged.
    """
    if not source or not source.strip():
        return None, "no pinned source span"
    got, spans = comparators(response, value)
    if not got:
        return None, "no comparator attached to the target value in the response"
    have, _ = comparators(source, value)
    if len(have) > 1:
        # The span puts more than one comparator on this value ("less than 24 feet ... but
        # greater than 24 feet"). Which one the answer refers to is not decidable here, so
        # nothing is waived and the guards decide, as they did before this module existed.
        return None, (f"source attaches several comparators {sorted(have)} to {value:g}; "
                      f"ambiguous, not waived")
    extra = got - have
    if extra:
        return False, (f"response comparator {sorted(extra)} on {value:g} is not what the "
                       f"source states ({sorted(have) or 'no comparator'})")
    t = list(_fold(response))
    for s, e in spans:
        t[s:e] = " " * (e - s)
    stripped = "".join(t)
    for m in _occurrences(stripped, value):
        if re.search(_NEG, stripped[max(0, m.start() - 60): m.start()]):
            return None, f"bare negation of {value:g} remains outside the comparator"
    return True, f"comparator {sorted(got)} on {value:g} matches the pinned source"
