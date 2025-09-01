"""Clustering algorithms for technique and actor analysis."""

import logging
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from collections import defaultdict
import numpy as np
from neo4j import GraphDatabase

logger = logging.getLogger(__name__)


@dataclass
class TechniqueCluster:
    """A cluster of related techniques."""
    cluster_id: int
    techniques: List[str]
    technique_names: Dict[str, str] = field(default_factory=dict)
    dominant_tactics: List[str] = field(default_factory=list)
    size: int = 0
    density: float = 0.0  # Internal edge density
    cohesion: float = 0.0  # Average internal edge weight
    hub_techniques: List[str] = field(default_factory=list)  # High-degree nodes
    
    def __post_init__(self):
        self.size = len(self.techniques)


@dataclass
class ClusterProfile:
    """Profile of a technique cluster."""
    cluster_id: int
    name: str  # Human-readable name based on tactics
    description: str
    technique_count: int
    actor_count: int  # Number of actors using this cluster
    avg_coverage: float  # Average detection coverage
    priority_score: float  # Priority for defensive investment


class TechniqueClusterer:
    """Cluster techniques based on co-occurrence patterns."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """Initialize clusterer with Neo4j connection."""
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    
    def close(self):
        """Close database connection."""
        self.driver.close()
    
    def cluster_techniques_louvain(
        self,
        weight_metric: str = "npmi",
        min_weight: float = 0.1,
        resolution: float = 1.0
    ) -> List[TechniqueCluster]:
        """
        Cluster techniques using Louvain community detection.
        
        Args:
            weight_metric: Metric to use for edge weights (npmi, pmi, lift)
            min_weight: Minimum edge weight to include
            resolution: Resolution parameter for Louvain (higher = more clusters)
            
        Returns:
            List of technique clusters
        """
        with self.driver.session() as session:
            # First, create/update the co-occurrence graph projection
            # Check if graph exists and drop if needed
            try:
                session.run("CALL gds.graph.drop('techCoOccur', false)")
            except:
                pass  # Graph doesn't exist, that's fine
            
            # Build weighted co-occurrence edges
            logger.info("Building co-occurrence graph...")
            
            # Create technique nodes and co-occurrence edges with weights
            create_graph_query = """
            // First, get all technique pairs with their co-occurrence metrics
            MATCH (e:AttackEpisode)-[:CONTAINS]->(a1:AttackAction)
            MATCH (e)-[:CONTAINS]->(a2:AttackAction)
            WHERE a1.attack_pattern_ref < a2.attack_pattern_ref
            AND a1.attack_pattern_ref IS NOT NULL
            AND a2.attack_pattern_ref IS NOT NULL
            WITH a1.attack_pattern_ref as tech1, 
                 a2.attack_pattern_ref as tech2, 
                 count(DISTINCT e) as cooccur_count
            WITH tech1, tech2, cooccur_count
            
            // Calculate total episodes and marginals for PMI
            MATCH (e_all:AttackEpisode)
            WITH tech1, tech2, cooccur_count, count(DISTINCT e_all) as total_episodes
            
            MATCH (e1:AttackEpisode)-[:CONTAINS]->(a1:AttackAction {attack_pattern_ref: tech1})
            WITH tech1, tech2, cooccur_count, total_episodes, count(DISTINCT e1) as count1
            
            MATCH (e2:AttackEpisode)-[:CONTAINS]->(a2:AttackAction {attack_pattern_ref: tech2})
            WITH tech1, tech2, cooccur_count, total_episodes, count1, count(DISTINCT e2) as count2
            
            // Calculate metrics
            WITH tech1, tech2,
                 cooccur_count,
                 count1, count2, total_episodes,
                 CASE WHEN count1 * count2 = 0 THEN 0
                      ELSE (1.0 * cooccur_count * total_episodes) / (count1 * count2)
                 END as lift,
                 CASE WHEN count1 = 0 OR count2 = 0 OR cooccur_count = 0 THEN 0
                      ELSE log((1.0 * cooccur_count * total_episodes) / (count1 * count2))
                 END as pmi
            WHERE cooccur_count >= 2  // Min support
            
            // Create nodes and relationships
            MERGE (t1:TechniqueNode {technique_id: tech1})
            MERGE (t2:TechniqueNode {technique_id: tech2})
            MERGE (t1)-[r:CO_OCCURS]-(t2)
            SET r.weight = cooccur_count,
                r.lift = lift,
                r.pmi = pmi,
                r.npmi = CASE WHEN pmi <= 0 THEN 0 
                             ELSE pmi / (-log((1.0 * cooccur_count) / total_episodes)) 
                        END
            """
            
            session.run(create_graph_query)
            
            # Create graph projection for GDS
            projection_query = f"""
            CALL gds.graph.project(
                'techCoOccur',
                'TechniqueNode',
                {{
                    CO_OCCURS: {{
                        orientation: 'UNDIRECTED',
                        properties: ['{weight_metric}']
                    }}
                }},
                {{
                    relationshipProperties: '{weight_metric}'
                }}
            )
            """
            
            try:
                result = session.run(projection_query)
                graph_info = result.single()
                logger.info(f"Graph projected with {graph_info['nodeCount']} nodes and {graph_info['relationshipCount']} edges")
            except Exception as e:
                logger.error(f"Failed to project graph: {e}")
                # Fallback to manual clustering
                return self._cluster_techniques_manual(session, weight_metric, min_weight)
            
            # Run Louvain community detection
            louvain_query = f"""
            CALL gds.louvain.stream('techCoOccur', {{
                relationshipWeightProperty: '{weight_metric}',
                resolution: {resolution},
                includeIntermediateCommunities: false
            }})
            YIELD nodeId, communityId
            WITH gds.util.asNode(nodeId) AS node, communityId
            RETURN communityId, 
                   collect(node.technique_id) as techniques,
                   count(*) as size
            ORDER BY size DESC
            """
            
            result = session.run(louvain_query)
            
            clusters = []
            for record in result:
                if record['size'] < 2:  # Skip singleton clusters
                    continue
                    
                cluster = TechniqueCluster(
                    cluster_id=record['communityId'],
                    techniques=record['techniques']
                )
                
                # Get technique names and tactics
                details_query = """
                MATCH (t:AttackPattern)
                WHERE t.stix_id IN $techniques
                OPTIONAL MATCH (t)-[:HAS_TACTIC]->(tac:Tactic)
                RETURN t.stix_id as id, t.name as name,
                       collect(DISTINCT tac.shortname) as tactics
                """
                details_result = session.run(details_query, techniques=cluster.techniques)
                
                all_tactics = []
                for detail in details_result:
                    cluster.technique_names[detail['id']] = detail['name']
                    all_tactics.extend(detail['tactics'])
                
                # Find dominant tactics
                tactic_counts = defaultdict(int)
                for tactic in all_tactics:
                    if tactic:
                        tactic_counts[tactic] += 1
                
                cluster.dominant_tactics = sorted(
                    tactic_counts.keys(),
                    key=lambda x: tactic_counts[x],
                    reverse=True
                )[:3]
                
                # Calculate cluster density and find hubs
                density_query = """
                MATCH (t1:TechniqueNode)-[r:CO_OCCURS]-(t2:TechniqueNode)
                WHERE t1.technique_id IN $techniques 
                AND t2.technique_id IN $techniques
                AND t1.technique_id < t2.technique_id
                RETURN count(r) as edge_count,
                       avg(r[$metric]) as avg_weight
                """
                density_result = session.run(
                    density_query, 
                    techniques=cluster.techniques,
                    metric=weight_metric
                ).single()
                
                if density_result:
                    max_edges = (cluster.size * (cluster.size - 1)) / 2
                    cluster.density = density_result['edge_count'] / max_edges if max_edges > 0 else 0
                    cluster.cohesion = density_result['avg_weight'] or 0
                
                # Find hub techniques (highest degree within cluster)
                hub_query = """
                MATCH (t1:TechniqueNode)-[r:CO_OCCURS]-(t2:TechniqueNode)
                WHERE t1.technique_id IN $techniques 
                AND t2.technique_id IN $techniques
                WITH t1.technique_id as tech, count(r) as degree
                RETURN tech, degree
                ORDER BY degree DESC
                LIMIT 3
                """
                hub_result = session.run(hub_query, techniques=cluster.techniques)
                cluster.hub_techniques = [r['tech'] for r in hub_result]
                
                clusters.append(cluster)
            
            # Clean up
            try:
                session.run("CALL gds.graph.drop('techCoOccur')")
                session.run("MATCH (n:TechniqueNode) DETACH DELETE n")
            except:
                pass
            
            return clusters
    
    def _cluster_techniques_manual(
        self,
        session,
        weight_metric: str,
        min_weight: float
    ) -> List[TechniqueCluster]:
        """
        Manual clustering fallback using simple connected components.
        """
        # Get weighted edges
        query = """
        MATCH (e:AttackEpisode)-[:CONTAINS]->(a1:AttackAction)
        MATCH (e)-[:CONTAINS]->(a2:AttackAction)
        WHERE a1.attack_pattern_ref < a2.attack_pattern_ref
        WITH a1.attack_pattern_ref as tech1, 
             a2.attack_pattern_ref as tech2, 
             count(DISTINCT e) as weight
        WHERE weight >= $min_weight
        RETURN tech1, tech2, weight
        """
        
        result = session.run(query, min_weight=min_weight)
        
        # Build adjacency list
        adjacency = defaultdict(set)
        for record in result:
            adjacency[record['tech1']].add(record['tech2'])
            adjacency[record['tech2']].add(record['tech1'])
        
        # Find connected components
        visited = set()
        clusters = []
        cluster_id = 0
        
        for node in adjacency:
            if node not in visited:
                # BFS to find component
                component = set()
                queue = [node]
                
                while queue:
                    current = queue.pop(0)
                    if current not in visited:
                        visited.add(current)
                        component.add(current)
                        queue.extend(adjacency[current] - visited)
                
                if len(component) >= 2:
                    clusters.append(TechniqueCluster(
                        cluster_id=cluster_id,
                        techniques=list(component)
                    ))
                    cluster_id += 1
        
        return clusters
    
    def profile_clusters(
        self,
        clusters: List[TechniqueCluster]
    ) -> List[ClusterProfile]:
        """
        Create profiles for technique clusters.
        
        Args:
            clusters: List of technique clusters
            
        Returns:
            List of cluster profiles with metadata
        """
        profiles = []
        
        with self.driver.session() as session:
            for cluster in clusters:
                # Get actor usage
                actor_query = """
                MATCH (g:IntrusionSet)<-[:ATTRIBUTED_TO]-(e:AttackEpisode)
                MATCH (e)-[:CONTAINS]->(a:AttackAction)
                WHERE a.attack_pattern_ref IN $techniques
                RETURN count(DISTINCT g) as actor_count
                """
                actor_result = session.run(actor_query, techniques=cluster.techniques)
                actor_count = actor_result.single()['actor_count']
                
                # Get detection coverage
                coverage_query = """
                MATCH (t:AttackPattern)
                WHERE t.stix_id IN $techniques
                OPTIONAL MATCH (t)<-[:DETECTS]-(d:DetectionStrategy)
                WITH count(DISTINCT t) as total,
                     count(DISTINCT CASE WHEN d IS NOT NULL THEN t END) as covered
                RETURN CASE WHEN total = 0 THEN 0 
                           ELSE 100.0 * covered / total 
                       END as coverage_pct
                """
                coverage_result = session.run(coverage_query, techniques=cluster.techniques)
                avg_coverage = coverage_result.single()['coverage_pct']
                
                # Generate name and description
                tactic_names = cluster.dominant_tactics[:2] if cluster.dominant_tactics else ['mixed']
                name = f"{'-'.join(tactic_names).title()} Cluster {cluster.cluster_id}"
                
                description = f"Cluster of {cluster.size} techniques"
                if cluster.dominant_tactics:
                    description += f" focused on {', '.join(cluster.dominant_tactics)}"
                description += f". Used by {actor_count} actors."
                
                # Calculate priority score (higher = more important)
                # Based on: actor usage, size, low coverage, density
                priority_score = (
                    actor_count * 10 +  # Actor usage is most important
                    cluster.size * 2 +  # Larger clusters are important
                    (100 - avg_coverage) * 0.5 +  # Low coverage increases priority
                    cluster.density * 20  # Dense clusters are cohesive
                )
                
                profiles.append(ClusterProfile(
                    cluster_id=cluster.cluster_id,
                    name=name,
                    description=description,
                    technique_count=cluster.size,
                    actor_count=actor_count,
                    avg_coverage=avg_coverage,
                    priority_score=priority_score
                ))
        
        # Sort by priority
        profiles.sort(key=lambda x: x.priority_score, reverse=True)
        
        return profiles
    
    def find_cluster_gaps(
        self,
        cluster: TechniqueCluster
    ) -> Dict[str, Any]:
        """
        Identify detection gaps in a cluster.
        
        Args:
            cluster: Technique cluster to analyze
            
        Returns:
            Dictionary of gap analysis results
        """
        with self.driver.session() as session:
            # Get uncovered techniques
            gap_query = """
            MATCH (t:AttackPattern)
            WHERE t.stix_id IN $techniques
            OPTIONAL MATCH (t)<-[:DETECTS]-(d:DetectionStrategy)
            OPTIONAL MATCH (t)<-[:MITIGATES]-(m:CoursOfAction)
            RETURN t.stix_id as technique_id,
                   t.name as technique_name,
                   EXISTS((t)<-[:DETECTS]-()) as has_detection,
                   EXISTS((t)<-[:MITIGATES]-()) as has_mitigation,
                   count(DISTINCT d) as detection_count,
                   count(DISTINCT m) as mitigation_count
            """
            
            result = session.run(gap_query, techniques=cluster.techniques)
            
            gaps = {
                'no_detection': [],
                'no_mitigation': [],
                'neither': [],
                'coverage_stats': {
                    'total_techniques': 0,
                    'detected': 0,
                    'mitigated': 0,
                    'covered': 0
                }
            }
            
            for record in result:
                gaps['coverage_stats']['total_techniques'] += 1
                
                if record['has_detection']:
                    gaps['coverage_stats']['detected'] += 1
                if record['has_mitigation']:
                    gaps['coverage_stats']['mitigated'] += 1
                if record['has_detection'] or record['has_mitigation']:
                    gaps['coverage_stats']['covered'] += 1
                
                tech_info = {
                    'id': record['technique_id'],
                    'name': record['technique_name']
                }
                
                if not record['has_detection'] and not record['has_mitigation']:
                    gaps['neither'].append(tech_info)
                elif not record['has_detection']:
                    gaps['no_detection'].append(tech_info)
                elif not record['has_mitigation']:
                    gaps['no_mitigation'].append(tech_info)
            
            # Calculate percentages
            total = gaps['coverage_stats']['total_techniques']
            if total > 0:
                gaps['coverage_stats']['detection_pct'] = (
                    100.0 * gaps['coverage_stats']['detected'] / total
                )
                gaps['coverage_stats']['mitigation_pct'] = (
                    100.0 * gaps['coverage_stats']['mitigated'] / total
                )
                gaps['coverage_stats']['overall_pct'] = (
                    100.0 * gaps['coverage_stats']['covered'] / total
                )
            
            return gaps