# SPDX-FileCopyrightText: 2026 SpanProof Labs
# SPDX-License-Identifier: MIT
from abc import ABC, abstractmethod
from typing import Any, List, Dict, Callable, Optional
from ..core.context import PipelineContext

class BaseAdjudicator(ABC):
    def __init__(self, config: dict, lex_fn: Callable[..., str]):
        self.config = config
        self.lex = lex_fn

    @abstractmethod
    def grade(self, ctx: PipelineContext, expected_val: Any, aligned_got: List[Dict[str, Any]]) -> tuple[bool, str]:
        pass
