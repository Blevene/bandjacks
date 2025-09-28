"""Evidence pack builder for LLM judge context."""

import hashlib
import json
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import logging

from opensearchpy import OpenSearch
from neo4j import GraphDatabase

from .sequence_extractor import PairwiseStatistics
from bandjacks.llm.tactic_priors import TacticPriors
from bandjacks.loaders.embedder import encode

logger = logging.getLogger(__name__)


@dataclass
class EvidenceSnippet:
    """Evidence snippet from document sources."""
    doc_id: str
    text: str
    source: str
    score: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TechniqueContext:
    """Context information for a technique."""
    technique_id: str
    name: str
    description: str
    tactic: str
    subtechniques: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)


@dataclass
class EvidencePack:
    """Complete evidence package for LLM judge."""
    pair: Dict[str, str]  # {"from_technique": "T1566", "to_technique": "T1059"}
    statistics: Dict[str, float]  # Pairwise stats from PTG
    tactic_context: Dict[str, Any]  # Tactic progression context
    technique_details: Dict[str, TechniqueContext]  # Full technique info
    graph_hints: List[str]  # Reasoning hints from knowledge graph
    evidence_snippets: List[EvidenceSnippet]  # Top-K document evidence
    historical_flows: List[Dict[str, Any]]  # Flows containing this transition
    retrieval_hash: str  # Hash for caching
    created_at: datetime = field(default_factory=datetime.utcnow)


class EvidencePackBuilder:
    """Builds comprehensive evidence packages for LLM judge context."""
    
    def __init__(
        self,
        neo4j_uri: str,
        neo4j_user: str,
        neo4j_password: str,
        opensearch_url: str,
        opensearch_index: str = "attack_nodes"
    ):
        """
        Initialize evidence pack builder.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username  
            neo4j_password: Neo4j password
            opensearch_url: OpenSearch URL
            opensearch_index: OpenSearch index name
        """
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.opensearch = OpenSearch([opensearch_url])
        self.os_index = opensearch_index
        self.tactic_priors = TacticPriors()
        
        # Cache for technique details
        self.technique_cache = {}
    
    def build_evidence_pack(
        self,
        from_technique: str,
        to_technique: str,
        stats: PairwiseStatistics,
        top_k_evidence: int = 5,
        include_flows: bool = True
    ) -> EvidencePack:
        """
        Build comprehensive evidence pack for a technique pair.
        
        Args:
            from_technique: Source technique ID
            to_technique: Target technique ID
            stats: Pairwise statistics containing this pair
            top_k_evidence: Number of evidence snippets to retrieve
            include_flows: Whether to include historical flow information
            
        Returns:
            Complete evidence pack for LLM judge
        """
        # Get basic pair info
        pair_info = {"from_technique": from_technique, "to_technique": to_technique}
        
        # Extract pairwise statistics
        pair_stats = self._extract_pair_statistics(from_technique, to_technique, stats)
        
        # Get technique details from Neo4j
        from_details = self._get_technique_context(from_technique)
        to_details = self._get_technique_context(to_technique)
        
        technique_details = {
            "from": from_details,
            "to": to_details
        }
        
        # Build tactic context
        tactic_context = self._build_tactic_context(from_details, to_details)
        
        # Generate graph-based reasoning hints
        graph_hints = self._generate_graph_hints(from_technique, to_technique, from_details, to_details)
        
        # Retrieve evidence snippets from OpenSearch
        evidence_snippets = self._retrieve_evidence_snippets(
            from_technique, to_technique, from_details, to_details, top_k_evidence
        )
        
        # Get historical flows (if requested)
        historical_flows = []
        if include_flows:
            historical_flows = self._get_historical_flows(from_technique, to_technique)
        
        # Generate retrieval hash for caching
        retrieval_hash = self._generate_retrieval_hash(
            from_technique, to_technique, pair_stats, tactic_context, 
            evidence_snippets, historical_flows
        )
        
        # Build complete evidence pack
        evidence_pack = EvidencePack(
            pair=pair_info,
            statistics=pair_stats,
            tactic_context=tactic_context,
            technique_details=technique_details,
            graph_hints=graph_hints,
            evidence_snippets=evidence_snippets,
            historical_flows=historical_flows,
            retrieval_hash=retrieval_hash
        )
        
        logger.info(f"Built evidence pack for {from_technique} -> {to_technique} "
                   f"with {len(evidence_snippets)} snippets, {len(historical_flows)} flows")
        
        return evidence_pack
    
    def _extract_pair_statistics(
        self, 
        from_technique: str, 
        to_technique: str, 
        stats: PairwiseStatistics
    ) -> Dict[str, float]:
        """Extract relevant statistics for this technique pair."""
        
        pair_key = (from_technique, to_technique)
        reverse_key = (to_technique, from_technique)
        
        pair_count = stats.pair_counts.get(pair_key, 0)
        reverse_count = stats.pair_counts.get(reverse_key, 0)
        
        conditional_prob = stats.conditional_probs.get(pair_key, 0.0)
        reverse_prob = stats.conditional_probs.get(reverse_key, 0.0)
        
        asymmetry = stats.asymmetry_scores.get(pair_key, 0.0)
        
        from_frequency = stats.technique_counts.get(from_technique, 0)
        to_frequency = stats.technique_counts.get(to_technique, 0)
        
        return {
            "pair_count": pair_count,
            "reverse_count": reverse_count,
            "conditional_prob": conditional_prob,
            "reverse_prob": reverse_prob,
            "asymmetry": asymmetry,
            "from_frequency": from_frequency,
            "to_frequency": to_frequency,
            "total_flows": stats.total_flows,
            "directional_strength": conditional_prob - reverse_prob
        }
    
    def _get_technique_context(self, technique_id: str) -> TechniqueContext:
        """Get comprehensive context for a technique from Neo4j."""
        
        if technique_id in self.technique_cache:
            return self.technique_cache[technique_id]
        
        with self.driver.session() as session:
            query = """
                MATCH (t:AttackPattern {stix_id: $tech_id})
                OPTIONAL MATCH (t)-[:HAS_TACTIC]->(tac:Tactic)
                OPTIONAL MATCH (t)-[:SUBTECHNIQUE_OF]->(parent:AttackPattern)
                OPTIONAL MATCH (sub:AttackPattern)-[:SUBTECHNIQUE_OF]->(t)
                OPTIONAL MATCH (t)-[:DETECTS]->(ds:DataSource)
                WITH t, tac, parent, collect(DISTINCT sub.stix_id) as subtechniques,
                     collect(DISTINCT ds.name) as data_sources
                RETURN t.stix_id as technique_id,
                       t.name as name,
                       t.description as description,
                       t.x_mitre_platforms as platforms,
                       tac.shortname as tactic,
                       parent.stix_id as parent_technique,
                       subtechniques,
                       data_sources
            """
            
            result = session.run(query, tech_id=technique_id)
            record = result.single()
            
            if not record:
                # Fallback for unknown techniques
                context = TechniqueContext(
                    technique_id=technique_id,
                    name="Unknown Technique",
                    description="Technique not found in knowledge base",
                    tactic="unknown"
                )
            else:
                context = TechniqueContext(
                    technique_id=record["technique_id"],
                    name=record["name"] or "Unknown",
                    description=record["description"] or "",
                    tactic=record["tactic"] or "unknown",
                    subtechniques=record["subtechniques"] or [],
                    platforms=record["platforms"] or [],
                    data_sources=record["data_sources"] or []
                )
        
        self.technique_cache[technique_id] = context
        return context
    
    def _build_tactic_context(
        self, 
        from_details: TechniqueContext, 
        to_details: TechniqueContext
    ) -> Dict[str, Any]:
        """Build tactic progression context."""
        
        from_tactic = from_details.tactic
        to_tactic = to_details.tactic
        
        # Get tactic prior probability
        tactic_prior = self.tactic_priors.get_tactic_prior(from_tactic, to_tactic)
        
        # Get rationale
        rationale = self.tactic_priors.get_transition_rationale(from_tactic, to_tactic)
        
        # Determine progression type
        if from_tactic == to_tactic:
            progression_type = "intra-tactic"
        elif tactic_prior > 0.5:
            progression_type = "natural_progression"
        elif tactic_prior > 0.2:
            progression_type = "possible_progression"
        else:
            progression_type = "unusual_progression"
        
        return {
            "from_tactic": from_tactic,
            "to_tactic": to_tactic,
            "tactic_prior": tactic_prior,
            "rationale": rationale,
            "progression_type": progression_type,
            "kill_chain_distance": self._calculate_kill_chain_distance(from_tactic, to_tactic)
        }
    
    def _calculate_kill_chain_distance(self, from_tactic: str, to_tactic: str) -> int:
        """Calculate distance in kill chain between tactics."""
        
        kill_chain_order = [
            "initial-access", "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery", "lateral-movement",
            "collection", "command-and-control", "exfiltration", "impact"
        ]
        
        try:
            from_idx = kill_chain_order.index(from_tactic)
            to_idx = kill_chain_order.index(to_tactic)
            return abs(to_idx - from_idx)
        except ValueError:
            return -1  # Unknown tactics
    
    def _generate_graph_hints(
        self, 
        from_technique: str, 
        to_technique: str,
        from_details: TechniqueContext,
        to_details: TechniqueContext
    ) -> List[str]:
        """Generate reasoning hints from knowledge graph patterns."""
        
        hints = []
        
        with self.driver.session() as session:
            # Check for shared software/groups
            shared_query = """
                MATCH (t1:AttackPattern {stix_id: $from_tech})<-[:USES]-(actor)
                MATCH (actor)-[:USES]->(t2:AttackPattern {stix_id: $to_tech})
                WITH actor, labels(actor) as actor_types
                RETURN collect(DISTINCT actor.name) as shared_actors,
                       collect(DISTINCT actor_types[0]) as actor_types
            """
            
            result = session.run(shared_query, from_tech=from_technique, to_tech=to_technique)
            record = result.single()
            
            if record and record["shared_actors"]:
                actors = record["shared_actors"][:3]  # Limit to top 3
                actor_type = record["actor_types"][0] if record["actor_types"] else "actors"
                hints.append(f"Both techniques used by {actor_type}: {', '.join(actors)}")
            
            # Check for sequential patterns in existing flows
            sequence_query = """
                MATCH (a1:AttackAction {attack_pattern_ref: $from_tech})-[:NEXT]->(a2:AttackAction {attack_pattern_ref: $to_tech})
                MATCH (e:AttackEpisode)-[:CONTAINS]->(a1)
                MATCH (e)-[:CONTAINS]->(a2)
                RETURN count(*) as sequence_count,
                       collect(DISTINCT e.source_id)[0..3] as sample_sources
            """
            
            result = session.run(sequence_query, from_tech=from_technique, to_tech=to_technique)
            record = result.single()
            
            if record and record["sequence_count"] > 0:
                count = record["sequence_count"]
                sources = record["sample_sources"] or []
                hints.append(f"Sequential pattern observed in {count} flow(s)")
                if sources:
                    hints.append(f"Found in sources: {', '.join(sources)}")
        
        # Add tactic-based hints
        tactic_hint = self.tactic_priors.get_transition_rationale(
            from_details.tactic, to_details.tactic
        )
        if tactic_hint and tactic_hint not in hints:
            hints.append(f"Tactic progression: {tactic_hint}")
        
        # Add platform compatibility hints
        from_platforms = set(from_details.platforms)
        to_platforms = set(to_details.platforms)
        common_platforms = from_platforms.intersection(to_platforms)
        
        if common_platforms:
            hints.append(f"Compatible platforms: {', '.join(list(common_platforms)[:3])}")
        
        return hints
    
    def _retrieve_evidence_snippets(
        self,
        from_technique: str,
        to_technique: str, 
        from_details: TechniqueContext,
        to_details: TechniqueContext,
        top_k: int
    ) -> List[EvidenceSnippet]:
        """Retrieve relevant evidence snippets from OpenSearch."""
        
        try:
            # Build search query combining technique names and descriptions
            search_terms = [
                from_details.name,
                to_details.name,
                f"{from_details.tactic} tactic",
                f"{to_details.tactic} tactic"
            ]
            
            # Add specific technique IDs
            if from_technique.startswith("T"):
                search_terms.append(from_technique)
            if to_technique.startswith("T"):
                search_terms.append(to_technique)
            
            query_text = " ".join(search_terms)
            
            # Perform hybrid search (vector + text)
            search_body = {
                "size": top_k * 2,  # Get more candidates, then filter
                "query": {
                    "bool": {
                        "should": [
                            # Vector similarity search
                            {
                                "knn": {
                                    "embedding": {
                                        "vector": encode(query_text),
                                        "k": top_k
                                    }
                                }
                            },
                            # Text search on technique names
                            {
                                "multi_match": {
                                    "query": f"{from_details.name} {to_details.name}",
                                    "fields": ["name^3", "description^2", "content"],
                                    "type": "best_fields"
                                }
                            },
                            # Technique ID search
                            {
                                "terms": {
                                    "technique_ids": [from_technique, to_technique]
                                }
                            }
                        ]
                    }
                },
                "_source": ["name", "description", "content", "source", "technique_ids", "url"]
            }
            
            response = self.opensearch.search(index=self.os_index, body=search_body)
            
            snippets = []
            for hit in response["hits"]["hits"][:top_k]:
                source_doc = hit["_source"]
                
                # Extract relevant text snippet
                text_content = (
                    source_doc.get("content", "") or 
                    source_doc.get("description", "") or 
                    source_doc.get("name", "")
                )[:500]  # Limit snippet length
                
                snippet = EvidenceSnippet(
                    doc_id=hit["_id"],
                    text=text_content,
                    source=source_doc.get("source", "Unknown"),
                    score=hit["_score"],
                    metadata={
                        "url": source_doc.get("url"),
                        "technique_ids": source_doc.get("technique_ids", [])
                    }
                )
                snippets.append(snippet)
            
            return snippets
            
        except Exception as e:
            logger.warning(f"Failed to retrieve evidence snippets: {e}")
            return []
    
    def _get_historical_flows(
        self, 
        from_technique: str, 
        to_technique: str,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Get historical flows containing this technique transition."""
        
        flows = []
        
        with self.driver.session() as session:
            query = """
                MATCH (a1:AttackAction {attack_pattern_ref: $from_tech})-[:NEXT]->(a2:AttackAction {attack_pattern_ref: $to_tech})
                MATCH (e:AttackEpisode)-[:CONTAINS]->(a1)
                MATCH (e)-[:CONTAINS]->(a2)
                OPTIONAL MATCH (e)-[:ATTRIBUTED_TO]->(g:IntrusionSet)
                RETURN e.flow_id as flow_id,
                       e.episode_id as episode_id,
                       e.source_id as source_id,
                       e.name as flow_name,
                       g.name as intrusion_set,
                       a1.order as from_order,
                       a2.order as to_order
                ORDER BY e.created DESC
                LIMIT $limit
            """
            
            result = session.run(query, 
                from_tech=from_technique, 
                to_tech=to_technique,
                limit=limit
            )
            
            for record in result:
                flow_info = {
                    "flow_id": record["flow_id"],
                    "episode_id": record["episode_id"],
                    "source_id": record["source_id"],
                    "flow_name": record["flow_name"],
                    "intrusion_set": record["intrusion_set"],
                    "sequence_gap": abs((record["to_order"] or 0) - (record["from_order"] or 0)) if record["from_order"] and record["to_order"] else None
                }
                flows.append(flow_info)
        
        return flows
    
    def _generate_retrieval_hash(
        self,
        from_technique: str,
        to_technique: str,
        pair_stats: Dict[str, float],
        tactic_context: Dict[str, Any],
        evidence_snippets: List[EvidenceSnippet],
        historical_flows: List[Dict[str, Any]]
    ) -> str:
        """Generate deterministic hash for evidence pack caching."""
        
        # Create reproducible hash based on key components
        hash_components = {
            "pair": f"{from_technique}->{to_technique}",
            "stats": {k: round(v, 6) for k, v in pair_stats.items()},  # Round for stability
            "tactic": tactic_context.get("progression_type", ""),
            "evidence_ids": [s.doc_id for s in evidence_snippets],
            "flow_ids": [f.get("flow_id", "") for f in historical_flows]
        }
        
        hash_string = json.dumps(hash_components, sort_keys=True)
        return hashlib.sha256(hash_string.encode()).hexdigest()
    
    def close(self):
        """Close database connections."""
        if self.driver:
            self.driver.close()


def build_evidence_pack_for_pair(
    from_technique: str,
    to_technique: str,
    stats: PairwiseStatistics,
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    opensearch_url: str,
    top_k_evidence: int = 5
) -> EvidencePack:
    """
    Convenience function to build evidence pack for a single pair.
    
    Args:
        from_technique: Source technique ID
        to_technique: Target technique ID
        stats: Pairwise statistics
        neo4j_uri: Neo4j connection URI
        neo4j_user: Neo4j username
        neo4j_password: Neo4j password
        opensearch_url: OpenSearch URL
        top_k_evidence: Number of evidence snippets
        
    Returns:
        Evidence pack for LLM judge
    """
    builder = EvidencePackBuilder(
        neo4j_uri, neo4j_user, neo4j_password, opensearch_url
    )
    
    try:
        return builder.build_evidence_pack(
            from_technique, to_technique, stats, top_k_evidence
        )
    finally:
        builder.close()