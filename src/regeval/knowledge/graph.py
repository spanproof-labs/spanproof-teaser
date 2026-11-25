# SPDX-FileCopyrightText: 2026 SpanProof Labs
# SPDX-License-Identifier: MIT
# src/regeval/knowledge/graph.py
"""
Zero-dependency Adjacency List for Regulatory Knowledge Graph.
Strictly adheres to src/regeval/ architecture rules.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass(frozen=True)
class Edge:
    target_id: str
    relationship_type: str  # e.g., 'requires', 'exempts', 'overrides'

@dataclass
class Node:
    entity_id: str
    entity_type: str  # e.g., 'substance', 'limit', 'regulation'
    attributes: Dict[str, str] = field(default_factory=dict)
    edges: List[Edge] = field(default_factory=list)

class RegulatoryGraph:
    def __init__(self) -> None:
        self._nodes: Dict[str, Node] = {}

    def add_node(self, node: Node) -> None:
        """Inject a regulatory entity into the graph."""
        self._nodes[node.entity_id] = node

    def add_edge(self, source_id: str, target_id: str, relationship: str) -> None:
        """Connect two entities (e.g., 'EPA_Limit' overrides 'OSHA_PEL')."""
        if source_id in self._nodes and target_id in self._nodes:
            self._nodes[source_id].edges.append(Edge(target_id, relationship))
        else:
            raise KeyError(f"Graph edge creation failed: Missing node(s) {source_id} or {target_id}")

    def get_node(self, entity_id: str) -> Optional[Node]:
        """Retrieve an entity and its relationships in O(1) time."""
        return self._nodes.get(entity_id)
