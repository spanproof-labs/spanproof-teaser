# SPDX-FileCopyrightText: 2026 SpanProof Labs
# SPDX-License-Identifier: MIT
from typing import Any, List, Dict
from ..core.context import PipelineContext
from .base import BaseAdjudicator

class RangeAdjudicator(BaseAdjudicator):
    def grade(self, ctx: PipelineContext, expected_val: Any, aligned_got: List[Dict[str, Any]]) -> tuple[bool, str]:
        ctx.trace_log.append({"module": "ADJUDICATOR", "action": f"ADJUDICATOR [{ctx.rule_type.upper()}]: Executing deterministic logic."})
        got_text = ctx.got_text
        if not isinstance(expected_val, list) or len(expected_val) < 2:
            return False, f"invalid range expected bounds: {expected_val}"
        min_val, max_val = sorted([float(expected_val[0]), float(expected_val[1])])
        
        expected_resolved = ctx.expected_resolved
        eu = next((r["value"] for r in expected_resolved if r["type"] == "UNIT"), None)
        
        if eu:
            aligned_values = [item["aligned_value"] for item in aligned_got if item["type"] == "NUM" and item.get("unit") == eu]
        else:
            aligned_values = [item["aligned_value"] for item in aligned_got if item["type"] == "NUM"]
        
        if not aligned_values:
            return False, f"could not parse a numerical value from response: {got_text[:80]!r}"
        
        in_range = [v for v in aligned_values if min_val <= v <= max_val]
        if in_range:
            return True, f"numeric evaluation complete (value inside [{min_val}, {max_val}])"
        return False, f"numeric evaluation complete (values {aligned_values} outside [{min_val}, {max_val}])"
