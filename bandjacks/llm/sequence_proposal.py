"""Sequence proposal builder for validated attack sequences from judge verdicts."""

import uuid
from typing import List, Dict, Tuple, Optional, Set, Any
from dataclasses import dataclass, field
from datetime import datetime
import logging
from neo4j import GraphDatabase

from bandjacks.llm.experimental.judge_client import JudgeVerdict, VerdictType

logger = logging.getLogger(__name__)


@dataclass
class TransitionEdge:
    """Represents a validated transition between techniques."""
    from_technique: str
    to_technique: str
    transition_confidence: float
    judge_confidence: float
    verdict: str  # "validated", "reversed", "bidirectional", "unknown"
    evidence_ids: List[str] = field(default_factory=list)
    

@dataclass 
class SequenceProposal:
    """A proposed attack sequence validated by judge verdicts."""
    sequence_id: str
    intrusion_set_id: str
    intrusion_set_name: str
    techniques: List[Dict[str, str]]  # List of {stix_id, external_id, name}
    edges: List[TransitionEdge]
    overall_confidence: float
    validation_status: str  # "llm-validated", "partial", "unvalidated"
    created_at: datetime = field(default_factory=datetime.utcnow)
    

class TransitionValidator:
    """Validates and categorizes transitions based on judge verdicts."""
    
    def __init__(self, unknown_transition_confidence: float = 0.1):
        """
        Initialize validator.
        
        Args:
            unknown_transition_confidence: Default confidence for unknown verdicts
        """
        self.unknown_transition_confidence = unknown_transition_confidence
    
    def categorize_transitions(
        self, 
        verdicts: List[JudgeVerdict]
    ) -> Tuple[List[TransitionEdge], List[TransitionEdge]]:
        """
        Categorize transitions into validated and uncertain.
        
        Args:
            verdicts: List of judge verdicts
            
        Returns:
            Tuple of (validated_edges, uncertain_edges)
        """
        validated_edges = []
        uncertain_edges = []
        
        for verdict in verdicts:
            if verdict.verdict == VerdictType.UNKNOWN:
                # Unknown verdicts get low transition confidence
                edge = TransitionEdge(
                    from_technique=verdict.from_technique,
                    to_technique=verdict.to_technique,
                    transition_confidence=self.unknown_transition_confidence,
                    judge_confidence=verdict.confidence,  # Judge's confidence in "unknown"
                    verdict="unknown",
                    evidence_ids=verdict.evidence_ids
                )
                uncertain_edges.append(edge)
                
            elif verdict.verdict == VerdictType.FORWARD:
                # i->j validated
                edge = TransitionEdge(
                    from_technique=verdict.from_technique,
                    to_technique=verdict.to_technique,
                    transition_confidence=verdict.confidence,
                    judge_confidence=verdict.confidence,
                    verdict="validated",
                    evidence_ids=verdict.evidence_ids
                )
                validated_edges.append(edge)
                
            elif verdict.verdict == VerdictType.REVERSE:
                # j->i, so reverse the edge
                edge = TransitionEdge(
                    from_technique=verdict.to_technique,
                    to_technique=verdict.from_technique,
                    transition_confidence=verdict.confidence,
                    judge_confidence=verdict.confidence,
                    verdict="reversed",
                    evidence_ids=verdict.evidence_ids
                )
                validated_edges.append(edge)
                
            elif verdict.verdict == VerdictType.BIDIRECTIONAL:
                # Create both directions with reduced confidence
                forward_edge = TransitionEdge(
                    from_technique=verdict.from_technique,
                    to_technique=verdict.to_technique,
                    transition_confidence=verdict.confidence * 0.5,
                    judge_confidence=verdict.confidence,
                    verdict="bidirectional-forward",
                    evidence_ids=verdict.evidence_ids
                )
                reverse_edge = TransitionEdge(
                    from_technique=verdict.to_technique,
                    to_technique=verdict.from_technique,
                    transition_confidence=verdict.confidence * 0.5,
                    judge_confidence=verdict.confidence,
                    verdict="bidirectional-reverse",
                    evidence_ids=verdict.evidence_ids
                )
                validated_edges.extend([forward_edge, reverse_edge])
        
        logger.info(f"Categorized {len(validated_edges)} validated and {len(uncertain_edges)} uncertain transitions")
        return validated_edges, uncertain_edges


class SequenceProposalBuilder:
    """Builds sequence proposals from validated transitions."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """
        Initialize builder with Neo4j connection.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
        """
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.technique_cache = {}
        
    def get_technique_details(self, technique_id: str) -> Dict[str, str]:
        """
        Get technique name and external_id from Neo4j.
        
        Args:
            technique_id: STIX ID of the technique
            
        Returns:
            Dict with name and external_id
        """
        if technique_id in self.technique_cache:
            return self.technique_cache[technique_id]
            
        with self.driver.session() as session:
            query = """
                MATCH (t:AttackPattern {stix_id: $technique_id})
                RETURN t.name as name, t.external_id as external_id
                LIMIT 1
            """
            result = session.run(query, technique_id=technique_id)
            record = result.single()
            
            if record:
                details = {
                    "name": record["name"],
                    "external_id": record["external_id"]
                }
            else:
                details = {
                    "name": technique_id[:30] + "...",
                    "external_id": "Unknown"
                }
            
            self.technique_cache[technique_id] = details
            return details
    
    def build_proposals(
        self,
        validated_edges: List[TransitionEdge],
        intrusion_set_id: str,
        intrusion_set_name: str,
        min_sequence_length: int = 2,
        max_sequences: int = 10
    ) -> List[SequenceProposal]:
        """
        Build sequence proposals from validated edges.
        
        Args:
            validated_edges: List of validated transition edges
            intrusion_set_id: STIX ID of the intrusion set
            intrusion_set_name: Name of the intrusion set
            min_sequence_length: Minimum techniques in a sequence
            max_sequences: Maximum number of sequences to generate
            
        Returns:
            List of sequence proposals
        """
        if not validated_edges:
            logger.warning("No validated edges to build sequences from")
            return []
        
        # Build adjacency graph
        graph = {}
        for edge in validated_edges:
            if edge.from_technique not in graph:
                graph[edge.from_technique] = []
            graph[edge.from_technique].append(edge)
        
        # Find all connected sequences
        sequences = self._find_connected_sequences(graph, min_sequence_length)
        
        # Convert to proposals
        proposals = []
        for sequence_techniques, sequence_edges in sequences[:max_sequences]:
            # Get technique details
            techniques_with_details = []
            for tech_id in sequence_techniques:
                details = self.get_technique_details(tech_id)
                techniques_with_details.append({
                    "stix_id": tech_id,
                    "external_id": details["external_id"],
                    "name": details["name"]
                })
            
            # Calculate overall confidence
            if sequence_edges:
                overall_confidence = sum(e.transition_confidence for e in sequence_edges) / len(sequence_edges)
            else:
                overall_confidence = 0.0
            
            proposal = SequenceProposal(
                sequence_id=f"seq-{intrusion_set_id[-8:]}-{uuid.uuid4().hex[:8]}",
                intrusion_set_id=intrusion_set_id,
                intrusion_set_name=intrusion_set_name,
                techniques=techniques_with_details,
                edges=sequence_edges,
                overall_confidence=overall_confidence,
                validation_status="llm-validated" if overall_confidence >= 0.5 else "partial"
            )
            proposals.append(proposal)
        
        logger.info(f"Built {len(proposals)} sequence proposals for {intrusion_set_name}")
        return proposals
    
    def _find_connected_sequences(
        self,
        graph: Dict[str, List[TransitionEdge]],
        min_length: int
    ) -> List[Tuple[List[str], List[TransitionEdge]]]:
        """
        Find all connected sequences in the graph.
        
        Args:
            graph: Adjacency graph of transitions
            min_length: Minimum sequence length
            
        Returns:
            List of (technique_sequence, edge_sequence) tuples
        """
        sequences = []
        visited_starts = set()
        
        # Try starting from each node
        for start_node in graph:
            if start_node not in visited_starts:
                # Find all paths from this node
                paths = self._find_paths_from_node(
                    start_node, graph, set(), [start_node], []
                )
                
                for path, edges in paths:
                    if len(path) >= min_length:
                        sequences.append((path, edges))
                        # Mark all nodes in path as visited starts
                        visited_starts.update(path)
        
        # Sort by confidence and length
        sequences.sort(key=lambda x: (
            sum(e.transition_confidence for e in x[1]) / len(x[1]) if x[1] else 0,
            len(x[0])
        ), reverse=True)
        
        return sequences
    
    def _find_paths_from_node(
        self,
        node: str,
        graph: Dict[str, List[TransitionEdge]],
        visited: Set[str],
        path: List[str],
        edges: List[TransitionEdge]
    ) -> List[Tuple[List[str], List[TransitionEdge]]]:
        """
        Recursively find all paths from a node.
        
        Args:
            node: Current node
            graph: Adjacency graph
            visited: Set of visited nodes
            path: Current path
            edges: Current edges
            
        Returns:
            List of (path, edges) tuples
        """
        if node not in graph or node in visited:
            return [(path, edges)]
        
        visited.add(node)
        all_paths = []
        
        for edge in graph[node]:
            if edge.to_technique not in visited:
                new_paths = self._find_paths_from_node(
                    edge.to_technique,
                    graph,
                    visited.copy(),
                    path + [edge.to_technique],
                    edges + [edge]
                )
                all_paths.extend(new_paths)
        
        if not all_paths:
            return [(path, edges)]
        
        return all_paths
    
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()


class AnalystReviewFormatter:
    """Formats sequence proposals for analyst review."""
    
    @staticmethod
    def format_proposals(
        proposals: List[SequenceProposal],
        uncertain_edges: Optional[List[TransitionEdge]] = None,
        include_stix_ids: bool = False
    ) -> str:
        """
        Format proposals for human review.
        
        Args:
            proposals: List of sequence proposals
            uncertain_edges: Optional list of uncertain transitions
            include_stix_ids: Whether to include STIX IDs in output
            
        Returns:
            Formatted string for review
        """
        lines = []
        lines.append("=" * 80)
        lines.append("SEQUENCE PROPOSALS FOR ANALYST REVIEW")
        lines.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("=" * 80)
        lines.append("")
        
        if proposals:
            lines.append("VALIDATED SEQUENCES")
            lines.append("-" * 40)
            lines.append("")
            
            for proposal in proposals:
                lines.append(f"Sequence ID: {proposal.sequence_id}")
                lines.append(f"Intrusion Set: {proposal.intrusion_set_name}")
                lines.append(f"Overall Confidence: {proposal.overall_confidence:.1%}")
                lines.append(f"Validation Status: {proposal.validation_status}")
                lines.append(f"Techniques: {len(proposal.techniques)}")
                lines.append("")
                lines.append("Technique Flow:")
                
                for i, tech in enumerate(proposal.techniques, 1):
                    lines.append(f"  {i}. [{tech['external_id']}] {tech['name']}")
                    if include_stix_ids:
                        lines.append(f"      ({tech['stix_id']})")
                    
                    # Show edge details if not last technique
                    if i <= len(proposal.edges):
                        edge = proposal.edges[i-1]
                        verdict_marker = {
                            "validated": "✓",
                            "reversed": "↔",
                            "bidirectional-forward": "⇄",
                            "bidirectional-reverse": "⇄",
                            "unknown": "?"
                        }.get(edge.verdict, "?")
                        
                        lines.append(f"      ↓ {verdict_marker} (confidence: {edge.transition_confidence:.1%})")
                
                lines.append("")
                lines.append("-" * 40)
                lines.append("")
        
        if uncertain_edges:
            lines.append("")
            lines.append("UNCERTAIN TRANSITIONS (Need More Evidence)")
            lines.append("-" * 40)
            lines.append("")
            
            for edge in uncertain_edges:
                lines.append(f"  ? {edge.from_technique[:40]}...")
                lines.append(f"      ↓ (confidence: {edge.transition_confidence:.1%})")
                lines.append(f"    {edge.to_technique[:40]}...")
                lines.append("")
        
        return "\n".join(lines)