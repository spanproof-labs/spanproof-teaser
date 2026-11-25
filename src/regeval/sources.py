"""The regulation span a bank item is pinned to — offline, read-only.

Used by the comparator waiver (regeval.comparator) and by the opt-in grounded judge
(src/judge/). A cfr_section_context pin quotes only a section CAPTION, which cannot state a
value or its comparator, so it is never a source.
"""
from __future__ import annotations

import glob
import json
import os
import re

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_INDEX: dict | None = None


def operative_quote(item: dict | None) -> str | None:
    """The first pinned span on `item` that carries operative text."""
    for pin in (item or {}).get("citations") or []:
        if not isinstance(pin, dict) or pin.get("pin_type") == "cfr_section_context":
            continue
        text = (pin.get("quote") or {}).get("text")
        if isinstance(text, str) and text.strip():
            return text
    return None


_BANK_ID = re.compile(r"^(?:GT|FDA)-")


def pinned_source(item_id: str | None, root: str = _ROOT) -> str | None:
    """The operative span of the bank item named by item_id (or eval_id).

    The index costs ~5 s to build (95 MB of banks), so an id that cannot name a bank item
    ("req_001" in a customer's log) returns None without building it."""
    global _INDEX
    if not item_id or not _BANK_ID.match(str(item_id)):
        return None
    if _INDEX is None:
        idx = {}
        paths = [os.path.join(root, "items", "bank.json")] + sorted(
            glob.glob(os.path.join(root, "items", "bank-v2", "bank-*.json")))
        for path in paths:
            try:
                with open(path, encoding="utf-8") as fh:
                    doc = json.load(fh)
            except (OSError, ValueError):
                continue
            for it in (doc if isinstance(doc, list) else doc.get("items", [])):
                q = operative_quote(it)
                if q:
                    for k in ("item_id", "eval_id"):
                        if it.get(k):
                            idx[it[k]] = q
        _INDEX = idx
    return _INDEX.get(item_id)
