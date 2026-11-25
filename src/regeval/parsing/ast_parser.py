# SPDX-FileCopyrightText: 2026 SpanProof Labs
# SPDX-License-Identifier: MIT
import re
from dataclasses import dataclass
from typing import List, Tuple, Optional

@dataclass
class Token:
    type: str
    value: str
    start: int
    end: int

@dataclass
class ASTNode:
    start: int
    end: int
    raw: str

@dataclass
class HypotheticalClauseNode(ASTNode):
    pass

@dataclass
class BooleanAssertionNode(ASTNode):
    polarity: bool

@dataclass
class CodeFenceNode(ASTNode):
    content: str

@dataclass
class XMLFenceNode(ASTNode):
    tag_name: str
    content: str

class Tokenizer:
    def __init__(self, text: str):
        self.text = text
        self.tokens: List[Token] = []
        # Match fences first to avoid tokenizing inside them.
        self.pattern = re.compile(
            r"(?P<XMLFENCE><(?:think|thinking|thought|reasoning|cot|system_2_trace)>.*?</(?:think|thinking|thought|reasoning|cot|system_2_trace)>)|"
            r"(?P<FENCE>```(?:[a-zA-Z]*)\s*.*?\s*```)|"
            r"(?P<WORD>[a-zA-Z0-9]+(?:[-_'][a-zA-Z0-9]+)*)|"
            r"(?P<SPACE>\s+)|"
            r"(?P<PUNCT>[^\w\s`<>]+)|"
            r"(?P<BACKTICK>`+)|"
            r"(?P<ANGLE><|>)"
        , re.DOTALL | re.IGNORECASE)

    def tokenize(self) -> List[Token]:
        for match in self.pattern.finditer(self.text):
            for group_name, value in match.groupdict().items():
                if value is not None:
                    self.tokens.append(Token(type=group_name, value=value, start=match.start(), end=match.end()))
                    break
        return self.tokens

class SemanticParser:
    def __init__(self, text: str):
        self.text = text
        self.tokenizer = Tokenizer(text)
        self.tokens = self.tokenizer.tokenize()
        self.nodes: List[ASTNode] = []

        self.BOOLEAN_YES = {
            "yes", "permitted", "allowed", "true", "affirmative", "positive", "approved", "required",
            "mandatory", "obligatory", "necessary", "compulsory", "authorize", "authorizes", "permit",
            "permits", "grant", "grants", "sanction", "sanctions", "applicable", "exemption"
        }
        self.BOOLEAN_NO = {
            "no", "forbidden", "prohibited", "false", "negative", "disallowed", "unauthorized",
            "banned", "denied", "unlawful", "restricted", "inapplicable", "waived", "exempt", "unnecessary"
        }
        self.NEGATED_YES = {
            "permitted", "allowed", "authorized", "legal",
            "required", "mandatory", "obligatory", "necessary", "compulsory", "applicable"
        }
        self.NEGATED_NO = {
            "forbidden", "prohibited", "unlawful", "illegal", "restricted"
        }

    def parse(self) -> List[ASTNode]:
        idx = 0
        n = len(self.tokens)
        while idx < n:
            tok = self.tokens[idx]
            if tok.type == "FENCE":
                content_match = re.match(r"```(?:[a-zA-Z]*)\s*(.*?)\s*```", tok.value, re.DOTALL)
                content = content_match.group(1) if content_match else ""
                self.nodes.append(CodeFenceNode(start=tok.start, end=tok.end, raw=tok.value, content=content))
                idx += 1
                continue
                
            if tok.type == "XMLFENCE":
                content_match = re.match(r"<(think|thinking|thought|reasoning|cot|system_2_trace)>(.*?)</\1>", tok.value, re.DOTALL | re.IGNORECASE)
                tag_name = content_match.group(1) if content_match else "unknown"
                content = content_match.group(2) if content_match else ""
                self.nodes.append(XMLFenceNode(start=tok.start, end=tok.end, raw=tok.value, tag_name=tag_name, content=content))
                idx += 1
                continue
            
            if tok.type == "WORD":
                val = tok.value.lower()
                # Check Hypothetical
                if val == "if":
                    hypo_node, new_idx = self._parse_hypothetical(idx)
                    if hypo_node:
                        self.nodes.append(hypo_node)
                        idx = new_idx
                        continue
                
                # Check long phrases
                if val == "exception" and self._match_phrase(idx, ["exception", "to", "the", "prohibition"]):
                    end_idx = self._advance_phrase(idx, ["exception", "to", "the", "prohibition"])
                    self.nodes.append(BooleanAssertionNode(start=tok.start, end=self.tokens[end_idx-1].end, raw=self.text[tok.start:self.tokens[end_idx-1].end], polarity=True))
                    idx = end_idx
                    continue

                if val == "exempted" and self._match_phrase(idx, ["exempted", "material"]):
                    end_idx = self._advance_phrase(idx, ["exempted", "material"])
                    self.nodes.append(BooleanAssertionNode(start=tok.start, end=self.tokens[end_idx-1].end, raw=self.text[tok.start:self.tokens[end_idx-1].end], polarity=True))
                    idx = end_idx
                    continue
                
                if val == "exception" and self._match_phrase(idx, ["exception", "to", "the", "prohibitions"]):
                    end_idx = self._advance_phrase(idx, ["exception", "to", "the", "prohibitions"])
                    self.nodes.append(BooleanAssertionNode(start=tok.start, end=self.tokens[end_idx-1].end, raw=self.text[tok.start:self.tokens[end_idx-1].end], polarity=True))
                    idx = end_idx
                    continue

                # Check Boolean with negation
                if val == "not":
                    next_word_idx = self._next_word(idx + 1)
                    if next_word_idx < n:
                        next_val = self.tokens[next_word_idx].value.lower()
                        if next_val in self.NEGATED_NO:
                            self.nodes.append(BooleanAssertionNode(start=tok.start, end=self.tokens[next_word_idx].end, raw=self.text[tok.start:self.tokens[next_word_idx].end], polarity=True))
                            idx = next_word_idx + 1
                            continue
                        elif next_val in self.NEGATED_YES:
                            self.nodes.append(BooleanAssertionNode(start=tok.start, end=self.tokens[next_word_idx].end, raw=self.text[tok.start:self.tokens[next_word_idx].end], polarity=False))
                            idx = next_word_idx + 1
                            continue

                if val in self.BOOLEAN_YES:
                    self.nodes.append(BooleanAssertionNode(start=tok.start, end=tok.end, raw=tok.value, polarity=True))
                elif val in self.BOOLEAN_NO:
                    self.nodes.append(BooleanAssertionNode(start=tok.start, end=tok.end, raw=tok.value, polarity=False))

            idx += 1
        return self.nodes
        
    def _next_word(self, idx: int) -> int:
        while idx < len(self.tokens) and self.tokens[idx].type != "WORD":
            idx += 1
        return idx

    def _match_phrase(self, idx: int, words: List[str]) -> bool:
        w_idx = 0
        curr = idx
        while curr < len(self.tokens) and w_idx < len(words):
            if self.tokens[curr].type == "WORD":
                if self.tokens[curr].value.lower() != words[w_idx]:
                    return False
                w_idx += 1
            curr += 1
        return w_idx == len(words)

    def _advance_phrase(self, idx: int, words: List[str]) -> int:
        w_idx = 0
        curr = idx
        while curr < len(self.tokens) and w_idx < len(words):
            if self.tokens[curr].type == "WORD":
                w_idx += 1
            curr += 1
        return curr

    def _parse_hypothetical(self, start_idx: int) -> Tuple[Optional[HypotheticalClauseNode], int]:
        state = "START"
        idx = start_idx
        n = len(self.tokens)
        
        while idx < n:
            tok = self.tokens[idx]
            
            if tok.type == "PUNCT" and tok.value in {".", ";", "!", "?"}:
                if state == "BOOLEAN":
                    return HypotheticalClauseNode(start=self.tokens[start_idx].start, end=tok.end, raw=self.text[self.tokens[start_idx].start:tok.end]), idx + 1
                else:
                    return None, start_idx

            if tok.type == "WORD":
                val = tok.value.lower()
                if state == "START" and val == "if":
                    state = "IF"
                elif state == "IF":
                    if val in {"this", "it"}:
                        state = "SUBJECT"
                    elif val == "the":
                        state = "THE"
                elif state == "THE":
                    state = "SUBJECT"
                elif state == "SUBJECT":
                    if val in {"were", "was", "had", "is"}:
                        state = "COND_VERB"
                elif state == "COND_VERB":
                    if val in {"would", "could", "might", "should"}:
                        state = "MODAL"
                elif state == "MODAL":
                    if val in {"be", "have", "been"}:
                        state = "AUX"
                    elif val in self.BOOLEAN_NO or val in self.BOOLEAN_YES:
                        state = "BOOLEAN"
                elif state == "AUX":
                    if val in self.BOOLEAN_NO or val in self.BOOLEAN_YES:
                        state = "BOOLEAN"
            
            idx += 1

        if state == "BOOLEAN":
            return HypotheticalClauseNode(start=self.tokens[start_idx].start, end=self.tokens[-1].end, raw=self.text[self.tokens[start_idx].start:self.tokens[-1].end]), idx
        return None, start_idx
