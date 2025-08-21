"""Enhanced search with filtering, reranking, and context awareness."""

from typing import List, Optional, Dict, Any, Set
from opensearchpy import OpenSearch
from bandjacks.loaders.embedder import encode
from bandjacks.loaders.search_nodes import ttx_search_kb


# Kill chain phase mapping for common techniques
TECHNIQUE_TO_PHASE = {
    "T1566": "initial-access",
    "T1566.001": "initial-access",
    "T1566.002": "initial-access",
    "T1190": "initial-access",
    "T1059": "execution",
    "T1059.001": "execution",
    "T1059.003": "execution",
    "T1059.005": "execution",
    "T1059.007": "execution",
    "T1547": "persistence",
    "T1547.001": "persistence",
    "T1543": "persistence",
    "T1055": "defense-evasion",
    "T1055.012": "defense-evasion",
    "T1027": "defense-evasion",
    "T1140": "defense-evasion",
    "T1555": "credential-access",
    "T1555.003": "credential-access",
    "T1003": "credential-access",
    "T1083": "discovery",
    "T1057": "discovery",
    "T1082": "discovery",
    "T1005": "collection",
    "T1113": "collection",
    "T1056": "collection",
    "T1071": "command-and-control",
    "T1071.001": "command-and-control",
    "T1102": "command-and-control",
    "T1041": "exfiltration",
    "T1048": "exfiltration",
}

# Commonly paired techniques
TECHNIQUE_RELATIONSHIPS = {
    "T1566": ["T1059", "T1204", "T1547"],  # Phishing often leads to execution and persistence
    "T1059.001": ["T1105", "T1140", "T1547"],  # PowerShell often downloads, decodes, persists
    "T1055": ["T1055.012", "T1140", "T1036"],  # Process injection with specific subtechniques
    "T1005": ["T1041", "T1071", "T1048"],  # Collection usually followed by exfiltration
    "T1555": ["T1005", "T1041"],  # Credential access often with collection/exfil
    "T1071": ["T1041", "T1105", "T1102"],  # C2 often with exfil and tool transfer
}


class EnhancedSearch:
    """Enhanced search with filtering and context awareness."""
    
    def __init__(self, os_url: str, index: str):
        """Initialize enhanced search."""
        self.os_url = os_url
        self.index = index
        self.client = OpenSearch(os_url, timeout=30)
    
    def search_with_filtering(
        self,
        text: str,
        min_score: float = 0.7,
        tactic_filter: Optional[str] = None,
        phase_filter: Optional[str] = None,
        top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Search with semantic filtering and phase constraints.
        
        Args:
            text: Query text
            min_score: Minimum similarity score (0-1)
            tactic_filter: Filter by specific tactic
            phase_filter: Filter by kill chain phase
            top_k: Number of results to return
            
        Returns:
            Filtered and ranked results
        """
        # Get initial results (fetch more for filtering)
        initial_results = ttx_search_kb(
            self.os_url,
            self.index,
            text,
            top_k=max(top_k * 4, 20),  # Get extra for filtering
            kb_types=["AttackPattern"]
        )
        
        # Apply minimum score filter
        filtered = [r for r in initial_results if r.get('score', 0) >= min_score]
        
        # Apply phase filter if provided
        if phase_filter:
            phase_filtered = []
            for result in filtered:
                tech_id = result.get('external_id', '')
                if TECHNIQUE_TO_PHASE.get(tech_id) == phase_filter:
                    phase_filtered.append(result)
            filtered = phase_filtered if phase_filtered else filtered[:2]  # Keep top 2 if no phase matches
        
        # Apply tactic filter if provided
        if tactic_filter and tactic_filter != phase_filter:
            # This would require querying Neo4j for tactic relationships
            # For now, we'll use phase as proxy
            pass
        
        # Return top K
        return filtered[:top_k]
    
    def rerank_by_context(
        self,
        results: List[Dict[str, Any]],
        found_techniques: Set[str],
        boost_related: float = 1.2,
        boost_subtechnique: float = 1.3
    ) -> List[Dict[str, Any]]:
        """
        Rerank results based on already found techniques.
        
        Args:
            results: Initial search results
            found_techniques: Set of technique IDs already found
            boost_related: Score multiplier for related techniques
            boost_subtechnique: Score multiplier for subtechniques
            
        Returns:
            Reranked results
        """
        reranked = []
        
        for result in results:
            tech_id = result.get('external_id', '')
            score = result.get('score', 0)
            
            # Boost subtechniques of found techniques
            if '.' in tech_id:
                parent = tech_id.split('.')[0]
                if parent in found_techniques:
                    score *= boost_subtechnique
                    result['boost_reason'] = f"Subtechnique of {parent}"
            
            # Boost related techniques
            for found_tech in found_techniques:
                if found_tech in TECHNIQUE_RELATIONSHIPS:
                    if tech_id in TECHNIQUE_RELATIONSHIPS[found_tech]:
                        score *= boost_related
                        result['boost_reason'] = f"Commonly paired with {found_tech}"
                        break
            
            result['adjusted_score'] = score
            reranked.append(result)
        
        # Sort by adjusted score
        reranked.sort(key=lambda x: x.get('adjusted_score', 0), reverse=True)
        
        return reranked
    
    def search_for_phase_techniques(
        self,
        phase: str,
        context_text: str = "",
        top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Search for techniques in a specific kill chain phase.
        
        Args:
            phase: Kill chain phase (e.g., 'initial-access')
            context_text: Optional context to guide search
            top_k: Number of results
            
        Returns:
            Techniques for that phase
        """
        # Build search query based on phase
        phase_queries = {
            "initial-access": "delivery mechanism entry point initial access phishing exploit",
            "execution": "execute run script command process launch start invoke",
            "persistence": "startup boot registry scheduled task service autostart maintain",
            "defense-evasion": "hide evade bypass disable obfuscate masquerade inject",
            "credential-access": "password credential steal dump harvest keylog browser",
            "discovery": "enumerate scan discover query list find reconnaissance",
            "collection": "collect gather steal archive compress data files",
            "command-and-control": "C2 communicate beacon callback tunnel protocol",
            "exfiltration": "exfiltrate send transmit upload transfer data out"
        }
        
        query = phase_queries.get(phase, phase)
        if context_text:
            query = f"{context_text} {query}"
        
        # Search with phase filter
        return self.search_with_filtering(
            query,
            phase_filter=phase,
            top_k=top_k
        )
    
    def find_missing_techniques(
        self,
        found_techniques: Set[str],
        report_text: str,
        top_k: int = 3
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Find techniques that might be missing based on kill chain gaps.
        
        Args:
            found_techniques: Already found technique IDs
            report_text: Full report text for context
            top_k: Suggestions per gap
            
        Returns:
            Dictionary of phase -> suggested techniques
        """
        # Determine which phases are covered
        covered_phases = set()
        for tech_id in found_techniques:
            if tech_id in TECHNIQUE_TO_PHASE:
                covered_phases.add(TECHNIQUE_TO_PHASE[tech_id])
        
        suggestions = {}
        
        # Check for logical gaps
        if len(covered_phases) >= 2:
            # Must have initial access
            if "initial-access" not in covered_phases:
                suggestions["initial-access"] = self.search_for_phase_techniques(
                    "initial-access",
                    report_text[:500],  # Use beginning of report
                    top_k
                )
            
            # If execution exists, should have persistence
            if "execution" in covered_phases and "persistence" not in covered_phases:
                suggestions["persistence"] = self.search_for_phase_techniques(
                    "persistence",
                    report_text,
                    top_k
                )
            
            # If collection exists, should have exfiltration
            if "collection" in covered_phases and "exfiltration" not in covered_phases:
                suggestions["exfiltration"] = self.search_for_phase_techniques(
                    "exfiltration",
                    report_text,
                    top_k
                )
            
            # Multi-stage attacks need C2
            if len(covered_phases) > 3 and "command-and-control" not in covered_phases:
                suggestions["command-and-control"] = self.search_for_phase_techniques(
                    "command-and-control",
                    report_text,
                    top_k
                )
        
        return suggestions


def enhanced_vector_search(
    os_url: str,
    index: str,
    text: str,
    context: Optional[Dict[str, Any]] = None,
    min_score: float = 0.7,
    top_k: int = 5
) -> List[Dict[str, Any]]:
    """
    Enhanced vector search with filtering and context awareness.
    
    Args:
        os_url: OpenSearch URL
        index: Index name
        text: Query text
        context: Optional context with found_techniques, current_phase
        min_score: Minimum similarity threshold
        top_k: Number of results
        
    Returns:
        Filtered and reranked results
    """
    searcher = EnhancedSearch(os_url, index)
    
    # Get phase filter from context
    phase_filter = None
    if context and 'current_phase' in context:
        phase_filter = context['current_phase']
    
    # Search with filtering
    results = searcher.search_with_filtering(
        text,
        min_score=min_score,
        phase_filter=phase_filter,
        top_k=top_k * 2  # Get extra for reranking
    )
    
    # Rerank by context if available
    if context and 'found_techniques' in context:
        results = searcher.rerank_by_context(
            results,
            set(context['found_techniques'])
        )
    
    return results[:top_k]