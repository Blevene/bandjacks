"""Graph analysis utilities for attack path analysis."""

import logging
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict
import json
import networkx as nx
import numpy as np
from neo4j import GraphDatabase
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class ChokePointAnalysis:
    """Results from choke point analysis."""
    analysis_id: str
    model_id: str
    betweenness_centrality: Dict[str, float]  # node -> centrality
    edge_betweenness: Dict[Tuple[str, str], float]  # edge -> centrality
    dominators: Dict[str, Set[str]]  # target -> dominators
    min_cut_nodes: Set[str]
    min_cut_edges: Set[Tuple[str, str]]
    articulation_points: Set[str]  # Critical nodes whose removal disconnects graph
    bridges: Set[Tuple[str, str]]  # Critical edges whose removal disconnects graph
    top_choke_points: List[Tuple[str, float]]  # Top N critical nodes with scores
    parameters: Dict[str, Any]
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PathAnalysis:
    """Analysis of paths between source and target sets."""
    source_set: Set[str]
    target_set: Set[str]
    all_paths: List[List[str]]
    shortest_paths: List[List[str]]
    path_union_nodes: Set[str]
    path_union_edges: Set[Tuple[str, str]]
    critical_nodes: Set[str]  # Nodes that appear in all paths
    critical_edges: Set[Tuple[str, str]]  # Edges that appear in all paths


class GraphAnalyzer:
    """Analyzes attack graphs for critical nodes and choke points."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """
        Initialize graph analyzer.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
        """
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self._graph_cache = {}
    
    def analyze_choke_points(
        self,
        model_id: str,
        source_techniques: Optional[List[str]] = None,
        target_techniques: Optional[List[str]] = None,
        k_paths: int = 50,
        top_n: int = 10
    ) -> ChokePointAnalysis:
        """
        Analyze graph for choke points and critical nodes.
        
        Args:
            model_id: PTG model identifier
            source_techniques: Optional source node set
            target_techniques: Optional target node set
            k_paths: Number of paths to consider for analysis
            top_n: Number of top choke points to return
            
        Returns:
            Choke point analysis results
        """
        logger.info(f"Analyzing choke points for model {model_id}")
        
        # Load graph
        G = self._load_ptg_as_networkx(model_id)
        
        # Calculate betweenness centrality
        node_betweenness = nx.betweenness_centrality(G, weight='weight')
        edge_betweenness = nx.edge_betweenness_centrality(G, weight='weight')
        
        # Find articulation points and bridges
        articulation_points = set()
        bridges = set()
        
        # For directed graphs, work with undirected version for connectivity
        G_undirected = G.to_undirected()
        if nx.is_connected(G_undirected):
            articulation_points = set(nx.articulation_points(G_undirected))
            bridges = set(nx.bridges(G_undirected))
        
        # Analyze paths if source/target provided
        dominators = {}
        min_cut_nodes = set()
        min_cut_edges = set()
        
        if source_techniques and target_techniques:
            # Find dominators for each target
            for target in target_techniques:
                if target in G:
                    # For each source, find dominators to target
                    target_dominators = set()
                    for source in source_techniques:
                        if source in G and source != target:
                            try:
                                # Find all simple paths (limited to avoid explosion)
                                paths = list(nx.all_simple_paths(
                                    G, source, target, cutoff=10
                                ))[:k_paths]
                                
                                if paths:
                                    # Find nodes that appear in all paths
                                    path_nodes = [set(path[1:-1]) for path in paths]  # Exclude source/target
                                    if path_nodes:
                                        common_nodes = path_nodes[0]
                                        for pn in path_nodes[1:]:
                                            common_nodes &= pn
                                        target_dominators.update(common_nodes)
                            except nx.NetworkXNoPath:
                                continue
                    
                    if target_dominators:
                        dominators[target] = target_dominators
            
            # Find min-cut between source and target sets
            try:
                # Create super source/sink for min-cut
                G_cut = G.copy()
                super_source = "SUPER_SOURCE"
                super_target = "SUPER_TARGET"
                
                # Add super nodes
                for source in source_techniques:
                    if source in G:
                        G_cut.add_edge(super_source, source, weight=1000)
                
                for target in target_techniques:
                    if target in G:
                        G_cut.add_edge(target, super_target, weight=1000)
                
                # Find minimum node cut
                try:
                    min_cut_nodes = nx.minimum_node_cut(G_cut, super_source, super_target)
                    # Remove super nodes if they ended up in cut
                    min_cut_nodes.discard(super_source)
                    min_cut_nodes.discard(super_target)
                except nx.NetworkXError:
                    min_cut_nodes = set()
                
                # Find minimum edge cut
                try:
                    min_cut_value, (set1, set2) = nx.minimum_cut(
                        G_cut, super_source, super_target, capacity='weight'
                    )
                    # Extract edges crossing the cut
                    for u in set1:
                        for v in set2:
                            if G.has_edge(u, v):
                                min_cut_edges.add((u, v))
                except nx.NetworkXError:
                    min_cut_edges = set()
                    
            except Exception as e:
                logger.warning(f"Min-cut calculation failed: {e}")
        
        # Rank nodes by criticality score
        criticality_scores = {}
        for node in G.nodes():
            score = 0.0
            
            # Betweenness centrality component
            score += node_betweenness.get(node, 0) * 10
            
            # Articulation point bonus
            if node in articulation_points:
                score += 5
            
            # Dominator bonus
            dominator_count = sum(1 for doms in dominators.values() if node in doms)
            score += dominator_count * 3
            
            # Min-cut membership bonus
            if node in min_cut_nodes:
                score += 4
            
            criticality_scores[node] = score
        
        # Get top choke points
        top_choke_points = sorted(
            criticality_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )[:top_n]
        
        return ChokePointAnalysis(
            analysis_id=f"choke-{model_id[:8]}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            model_id=model_id,
            betweenness_centrality=dict(node_betweenness),
            edge_betweenness=dict(edge_betweenness),
            dominators=dominators,
            min_cut_nodes=min_cut_nodes,
            min_cut_edges=min_cut_edges,
            articulation_points=articulation_points,
            bridges=bridges,
            top_choke_points=top_choke_points,
            parameters={
                "source_techniques": source_techniques,
                "target_techniques": target_techniques,
                "k_paths": k_paths,
                "graph_nodes": G.number_of_nodes(),
                "graph_edges": G.number_of_edges()
            }
        )
    
    def analyze_paths(
        self,
        model_id: str,
        source_set: Set[str],
        target_set: Set[str],
        max_paths: int = 100,
        max_length: int = 10
    ) -> PathAnalysis:
        """
        Analyze paths between source and target sets.
        
        Args:
            model_id: PTG model identifier
            source_set: Source techniques
            target_set: Target techniques
            max_paths: Maximum paths to analyze
            max_length: Maximum path length
            
        Returns:
            Path analysis results
        """
        G = self._load_ptg_as_networkx(model_id)
        
        all_paths = []
        shortest_paths = []
        path_union_nodes = set()
        path_union_edges = set()
        
        for source in source_set:
            if source not in G:
                continue
            
            for target in target_set:
                if target not in G or source == target:
                    continue
                
                try:
                    # Find shortest path
                    shortest = nx.shortest_path(G, source, target, weight='weight')
                    shortest_paths.append(shortest)
                    
                    # Find all simple paths (limited)
                    paths = list(nx.all_simple_paths(
                        G, source, target, cutoff=max_length
                    ))[:max_paths // len(source_set)]
                    
                    all_paths.extend(paths)
                    
                    # Build path union
                    for path in paths:
                        path_union_nodes.update(path)
                        for i in range(len(path) - 1):
                            path_union_edges.add((path[i], path[i+1]))
                            
                except nx.NetworkXNoPath:
                    continue
        
        # Find critical nodes/edges (appear in all paths)
        critical_nodes = set()
        critical_edges = set()
        
        if all_paths:
            # Nodes that appear in every path (excluding endpoints)
            path_node_sets = [set(path[1:-1]) for path in all_paths]
            if path_node_sets:
                critical_nodes = path_node_sets[0]
                for pn in path_node_sets[1:]:
                    critical_nodes &= pn
            
            # Edges that appear in every path
            path_edge_sets = [
                set(zip(path[:-1], path[1:])) 
                for path in all_paths
            ]
            if path_edge_sets:
                critical_edges = path_edge_sets[0]
                for pe in path_edge_sets[1:]:
                    critical_edges &= pe
        
        return PathAnalysis(
            source_set=source_set,
            target_set=target_set,
            all_paths=all_paths,
            shortest_paths=shortest_paths,
            path_union_nodes=path_union_nodes,
            path_union_edges=path_union_edges,
            critical_nodes=critical_nodes,
            critical_edges=critical_edges
        )
    
    def compute_reachability(
        self,
        model_id: str,
        source_techniques: List[str],
        max_hops: int = 5
    ) -> Dict[str, Dict[str, Any]]:
        """
        Compute reachability from source techniques.
        
        Args:
            model_id: PTG model identifier
            source_techniques: Starting techniques
            max_hops: Maximum hops to consider
            
        Returns:
            Reachability information per technique
        """
        G = self._load_ptg_as_networkx(model_id)
        
        reachability = {}
        
        for source in source_techniques:
            if source not in G:
                continue
            
            # BFS to find reachable nodes
            distances = nx.single_source_shortest_path_length(
                G, source, cutoff=max_hops
            )
            
            # Get path probabilities using Dijkstra
            path_probs = nx.single_source_dijkstra_path_length(
                G, source, weight='weight'
            )
            
            reachability[source] = {
                "reachable_nodes": len(distances),
                "hop_distribution": dict(defaultdict(int)),
                "max_probability_paths": {},
                "average_distance": np.mean(list(distances.values())) if distances else 0
            }
            
            # Count nodes at each hop distance
            for node, dist in distances.items():
                reachability[source]["hop_distribution"][dist] = \
                    reachability[source]["hop_distribution"].get(dist, 0) + 1
            
            # Top 10 most likely reachable nodes
            top_reachable = sorted(
                path_probs.items(),
                key=lambda x: x[1]
            )[:10]
            
            reachability[source]["max_probability_paths"] = dict(top_reachable)
        
        return reachability
    
    def _load_ptg_as_networkx(self, model_id: str) -> nx.DiGraph:
        """
        Load PTG model as NetworkX directed graph.
        
        Args:
            model_id: Model identifier
            
        Returns:
            NetworkX DiGraph
        """
        if model_id in self._graph_cache:
            return self._graph_cache[model_id]
        
        G = nx.DiGraph()
        
        with self.driver.session() as session:
            # Load nodes
            node_query = """
                MATCH (t:AttackPattern)
                WHERE EXISTS {
                    MATCH (t)-[:NEXT_P {model_id: $model_id}]-()
                }
                RETURN DISTINCT t.stix_id as tech_id, t.name as name
            """
            
            result = session.run(node_query, {"model_id": model_id})
            for record in result:
                G.add_node(record["tech_id"], name=record["name"])
            
            # Load edges with probabilities
            edge_query = """
                MATCH (t1:AttackPattern)-[r:NEXT_P {model_id: $model_id}]->(t2:AttackPattern)
                RETURN t1.stix_id as from_tech,
                       t2.stix_id as to_tech,
                       r.p as probability
            """
            
            result = session.run(edge_query, {"model_id": model_id})
            for record in result:
                # Use negative log probability as weight (for shortest path algorithms)
                # This makes high probability edges have low weight
                prob = record["probability"]
                if prob > 0:
                    weight = -np.log(prob)
                else:
                    weight = 1000  # Large weight for zero probability
                
                G.add_edge(
                    record["from_tech"],
                    record["to_tech"],
                    probability=prob,
                    weight=weight
                )
        
        # Cache for reuse
        self._graph_cache[model_id] = G
        
        logger.info(f"Loaded PTG {model_id} as NetworkX graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
        return G
    
    def export_graph_for_visualization(
        self,
        model_id: str,
        layout: str = "spring"
    ) -> Dict[str, Any]:
        """
        Export graph data for visualization.
        
        Args:
            model_id: Model identifier
            layout: Layout algorithm (spring, circular, kamada_kawai)
            
        Returns:
            Graph data for visualization
        """
        G = self._load_ptg_as_networkx(model_id)
        
        # Compute layout
        if layout == "spring":
            pos = nx.spring_layout(G, k=2, iterations=50)
        elif layout == "circular":
            pos = nx.circular_layout(G)
        elif layout == "kamada_kawai":
            pos = nx.kamada_kawai_layout(G)
        else:
            pos = nx.spring_layout(G)
        
        # Convert to visualization format
        nodes = []
        for node in G.nodes():
            nodes.append({
                "id": node,
                "label": G.nodes[node].get("name", node),
                "x": pos[node][0] * 1000,  # Scale up
                "y": pos[node][1] * 1000,
                "size": G.degree(node)
            })
        
        edges = []
        for u, v, data in G.edges(data=True):
            edges.append({
                "source": u,
                "target": v,
                "weight": data.get("probability", 0),
                "label": f"{data.get('probability', 0):.2f}"
            })
        
        return {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "model_id": model_id,
                "node_count": G.number_of_nodes(),
                "edge_count": G.number_of_edges(),
                "layout": layout
            }
        }
    
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()