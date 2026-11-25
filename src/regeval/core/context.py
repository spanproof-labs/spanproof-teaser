# SPDX-FileCopyrightText: 2026 SpanProof Labs
# SPDX-License-Identifier: MIT
from dataclasses import dataclass, field
from typing import Any, List, Dict, Optional

from ..sources import operative_quote as _operative_quote

def _supporting(d):
    """Every authority the item pins, beyond the one named as `citation`.

    Read from an explicit `supporting_citations` list when the eval adapter supplied
    one, otherwise derived from a raw knowledge record's own `citations` array — so
    this works on both shapes without the caller having to know which it holds.
    """
    if not isinstance(d, dict):
        return []
    explicit = d.get("supporting_citations")
    if isinstance(explicit, (list, tuple)):
        return [str(x) for x in explicit if x]
    out = []
    for c in (d.get("citations") or []):
        if isinstance(c, dict):
            cc = c.get("citation_canonical") or c.get("citation")
            if cc:
                out.append(str(cc))
        elif c:
            out.append(str(c))
    return out


class YieldForLaundering(Exception):
    def __init__(self, target_module: str, payload: Any):
        self.target_module = target_module
        self.payload = payload
        super().__init__(f"Yielding to {target_module}")

@dataclass
class PipelineContext:
    """Typed data contract passed between pipeline layers."""
    rule_type: str
    got_text: str
    expected_text: str
    expected_resolved: List[Dict[str, Any]] = field(default_factory=list)
    citation: Optional[str] = None
    # The item's OTHER pinned authorities. Needed because `citation` is sometimes a
    # SOURCE DOCUMENT rather than the authority an answer rests on: an LOI-lane item
    # names "PHMSA Interpretation 00-0362" (where the question came from) while the
    # answer is grounded in 49 CFR 107.601 (what makes it true). A grounding check
    # that only accepts the former rejects correct, properly-cited answers.
    supporting_citations: List[str] = field(default_factory=list)
    tolerance: Optional[float] = None
    boolean_answer: Optional[Any] = None
    config_name: str = ""

    # --- Tagger-enrichment fields (populated by enrich(), consumed by adjudicate) ---
    got_boolean_polarity: Optional[bool] = None
    got_citations: Optional[set] = field(default_factory=set)
    citation_inverted: bool = False
    has_para_range: bool = False
    numeric_inequality: bool = False
    numeric_negated: bool = False
    has_zero_term: bool = False
    has_range_expression: bool = False
    exact_negated: bool = False
    has_disjunction: bool = False
    # F9 — LATCHING. Set true the first time an open-set claim is seen in the
    # response and never cleared, because the laundering retry rewrites
    # ctx.got_text and re-runs enrich() over the rewritten payload. A detection
    # signal that lives only in the text does not survive that rewrite; this one
    # has to. See SetEqualityAdjudicator.grade.
    has_open_set_claim: bool = False
    # F16 — the response asserts BOTH polarities joined by a disjunction
    # ("yes or no", "permitted or forbidden"). That is a hedge, not an answer,
    # and the boolean lane accepted 139 of 139 of them because polarity was read
    # from the FIRST determination and the rest of the sentence was never
    # examined. Latching, for the same reason has_open_set_claim latches: a
    # laundering rewrite must not be able to erase a detection.
    boolean_hedged: bool = False
    set_cleaned_got: str = ""
    has_none_term: bool = False
    got_text_lexed: str = ""
    trace_log: List[Dict[str, Any]] = field(default_factory=list)
    ttl: int = field(default=3)
    # The pinned regulation span the answer must agree with (regeval.sources). Read only by
    # the comparator waiver (regeval.comparator): a guard rejection is waived when the
    # response's comparator on the target value is the one this span states.
    source_text: Optional[str] = None
    comparator_waiver: Optional[str] = None

    @classmethod
    def from_dict(cls, rule_type: str, got_text: str, expected_text: str,
                  d: Optional[Dict[str, Any]] = None, config_name: str = "") -> "PipelineContext":
        """Build a PipelineContext from a legacy kwargs dict."""
        d = d or {}
        cfg_name = config_name or d.get("config_name", "")
        if not cfg_name and isinstance(d, dict) and "domain" in d:
            cfg_name = d["domain"].get("name", "") or str(d["domain"].get("cfr_title", ""))

        return cls(
            rule_type=rule_type,
            got_text=str(got_text),
            expected_text=str(expected_text),
            expected_resolved=d.get("expected_resolved", []),
            citation=d.get("citation") or d.get("required_citation"),
            supporting_citations=_supporting(d),
            tolerance=float(d.get("tolerance", 0) or 0),
            boolean_answer=d.get("boolean_answer"),
            config_name=cfg_name,
            source_text=(d.get("source_text") if isinstance(d.get("source_text"), str)
                         else _operative_quote(d)),
        )
