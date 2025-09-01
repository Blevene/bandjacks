"""Co-occurrence analytics for technique analysis without temporal sequences."""

import logging
import math
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from collections import defaultdict
from neo4j import GraphDatabase
import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class CooccurrenceMetrics:
    """Metrics for a co-occurring technique pair."""
    technique_a: str
    technique_b: str
    count: int  # Co-occurrence count
    support_a: int  # Episodes containing A
    support_b: int  # Episodes containing B
    total_episodes: int
    confidence_a_to_b: float  # P(B|A)
    confidence_b_to_a: float  # P(A|B)
    lift: float  # lift(A,B) = P(A,B) / (P(A) * P(B))
    pmi: float  # Pointwise Mutual Information
    npmi: float  # Normalized PMI [-1, 1]
    
    @property
    def support_ab(self) -> int:
        """Support for both techniques together."""
        return self.count
    
    @property
    def jaccard(self) -> float:
        """Jaccard similarity coefficient."""
        union = self.support_a + self.support_b - self.count
        return self.count / union if union > 0 else 0.0


@dataclass
class TechniqueBundle:
    """A frequently co-occurring set of techniques."""
    techniques: List[str]
    support: int  # Number of episodes containing all techniques
    confidence: float  # Confidence of bundle occurrence
    lift: float  # Lift of the bundle
    tactics: List[str] = field(default_factory=list)
    intrusion_sets: List[str] = field(default_factory=list)
    

@dataclass 
class ActorProfile:
    """Technique profile for an intrusion set."""
    intrusion_set_id: str
    intrusion_set_name: str
    techniques: List[str]
    technique_counts: Dict[str, int]
    total_episodes: int
    tf_idf_vector: Optional[np.ndarray] = None
    dominant_tactics: List[str] = field(default_factory=list)
    signature_techniques: List[str] = field(default_factory=list)  # High TF-IDF techniques


class CooccurrenceAnalyzer:
    """Analyze technique co-occurrences without requiring temporal sequences."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """Initialize the analyzer with Neo4j connection."""
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        
    def close(self):
        """Close database connection."""
        self.driver.close()
        
    def calculate_global_cooccurrence(
        self, 
        min_support: int = 2,
        min_episodes_per_pair: int = 2,
        exclude_revoked: bool = True
    ) -> List[CooccurrenceMetrics]:
        """
        Calculate global co-occurrence metrics across all episodes.
        
        Args:
            min_support: Minimum episodes containing a technique
            min_episodes_per_pair: Minimum episodes for a pair
            exclude_revoked: Exclude revoked techniques
            
        Returns:
            List of co-occurrence metrics sorted by NPMI
        """
        with self.driver.session() as session:
            # Get episode-technique mappings
            query = """
            MATCH (e:AttackEpisode)-[:CONTAINS]->(a:AttackAction)
            WHERE a.attack_pattern_ref IS NOT NULL
            WITH e, collect(DISTINCT a.attack_pattern_ref) AS techniques
            WHERE size(techniques) >= 2
            RETURN e.stix_id as episode_id, techniques
            """
            
            result = session.run(query)
            
            # Build co-occurrence matrix
            pair_counts = defaultdict(int)
            technique_counts = defaultdict(int)
            episode_count = 0
            
            for record in result:
                episode_count += 1
                techniques = record["techniques"]
                
                # Count individual techniques
                for tech in techniques:
                    technique_counts[tech] += 1
                
                # Count pairs
                for i, tech_a in enumerate(techniques):
                    for tech_b in techniques[i+1:]:
                        # Order pair consistently
                        pair = tuple(sorted([tech_a, tech_b]))
                        pair_counts[pair] += 1
            
            # Calculate metrics for each pair
            metrics = []
            for (tech_a, tech_b), count in pair_counts.items():
                if count < min_episodes_per_pair:
                    continue
                    
                support_a = technique_counts[tech_a]
                support_b = technique_counts[tech_b]
                
                if support_a < min_support or support_b < min_support:
                    continue
                
                # Calculate metrics
                confidence_a_to_b = count / support_a if support_a > 0 else 0
                confidence_b_to_a = count / support_b if support_b > 0 else 0
                
                # Lift
                expected = (support_a * support_b) / episode_count if episode_count > 0 else 0
                lift = count / expected if expected > 0 else 0
                
                # PMI
                p_a = support_a / episode_count
                p_b = support_b / episode_count  
                p_ab = count / episode_count
                
                if p_a > 0 and p_b > 0 and p_ab > 0:
                    pmi = math.log2(p_ab / (p_a * p_b))
                    # Normalize PMI
                    npmi = pmi / (-math.log2(p_ab)) if p_ab > 0 else 0
                else:
                    pmi = 0
                    npmi = 0
                
                metrics.append(CooccurrenceMetrics(
                    technique_a=tech_a,
                    technique_b=tech_b,
                    count=count,
                    support_a=support_a,
                    support_b=support_b,
                    total_episodes=episode_count,
                    confidence_a_to_b=confidence_a_to_b,
                    confidence_b_to_a=confidence_b_to_a,
                    lift=lift,
                    pmi=pmi,
                    npmi=npmi
                ))
            
            # Sort by NPMI (best de-biased metric)
            metrics.sort(key=lambda x: x.npmi, reverse=True)
            
            return metrics
    
    def calculate_actor_cooccurrence(
        self,
        intrusion_set_id: str,
        min_support: int = 1
    ) -> List[CooccurrenceMetrics]:
        """
        Calculate co-occurrence metrics for a specific intrusion set.
        
        Args:
            intrusion_set_id: STIX ID of the intrusion set
            min_support: Minimum episode support
            
        Returns:
            List of co-occurrence metrics for this actor
        """
        with self.driver.session() as session:
            # Get episodes for this intrusion set
            query = """
            MATCH (g:IntrusionSet {stix_id: $group_id})<-[:ATTRIBUTED_TO]-(e:AttackEpisode)
            MATCH (e)-[:CONTAINS]->(a:AttackAction)
            WHERE a.attack_pattern_ref IS NOT NULL
            WITH e, collect(DISTINCT a.attack_pattern_ref) AS techniques
            WHERE size(techniques) >= 2
            RETURN e.stix_id as episode_id, techniques
            """
            
            result = session.run(query, group_id=intrusion_set_id)
            
            # Build co-occurrence matrix for this actor
            pair_counts = defaultdict(int)
            technique_counts = defaultdict(int)
            episode_count = 0
            
            for record in result:
                episode_count += 1
                techniques = record["techniques"]
                
                # Count individual techniques
                for tech in techniques:
                    technique_counts[tech] += 1
                
                # Count pairs
                for i, tech_a in enumerate(techniques):
                    for tech_b in techniques[i+1:]:
                        pair = tuple(sorted([tech_a, tech_b]))
                        pair_counts[pair] += 1
            
            # Calculate metrics
            metrics = []
            for (tech_a, tech_b), count in pair_counts.items():
                support_a = technique_counts[tech_a]
                support_b = technique_counts[tech_b]
                
                if support_a < min_support or support_b < min_support:
                    continue
                
                # Calculate metrics with small sample adjustments
                # Add pseudocounts for stability with small N
                confidence_a_to_b = (count + 0.5) / (support_a + 1)
                confidence_b_to_a = (count + 0.5) / (support_b + 1)
                
                # Lift with Laplace smoothing
                expected = ((support_a + 1) * (support_b + 1)) / (episode_count + 2)
                lift = (count + 0.5) / expected if expected > 0 else 0
                
                # PMI with additive smoothing
                p_a = (support_a + 0.5) / (episode_count + 1)
                p_b = (support_b + 0.5) / (episode_count + 1)
                p_ab = (count + 0.5) / (episode_count + 1)
                
                if p_a > 0 and p_b > 0 and p_ab > 0:
                    pmi = math.log2(p_ab / (p_a * p_b))
                    npmi = pmi / (-math.log2(p_ab)) if p_ab > 0 else 0
                else:
                    pmi = 0
                    npmi = 0
                
                metrics.append(CooccurrenceMetrics(
                    technique_a=tech_a,
                    technique_b=tech_b,
                    count=count,
                    support_a=support_a,
                    support_b=support_b,
                    total_episodes=episode_count,
                    confidence_a_to_b=confidence_a_to_b,
                    confidence_b_to_a=confidence_b_to_a,
                    lift=lift,
                    pmi=pmi,
                    npmi=npmi
                ))
            
            metrics.sort(key=lambda x: x.npmi, reverse=True)
            return metrics
    
    def extract_technique_bundles(
        self,
        intrusion_set_id: Optional[str] = None,
        min_support: int = 2,
        min_size: int = 3,
        max_size: int = 5
    ) -> List[TechniqueBundle]:
        """
        Extract frequently co-occurring technique bundles.
        
        Uses frequent itemset mining to find technique combinations.
        
        Args:
            intrusion_set_id: Optional actor filter
            min_support: Minimum episode support
            min_size: Minimum bundle size
            max_size: Maximum bundle size
            
        Returns:
            List of technique bundles sorted by lift
        """
        with self.driver.session() as session:
            if intrusion_set_id:
                query = """
                MATCH (g:IntrusionSet {stix_id: $group_id})<-[:ATTRIBUTED_TO]-(e:AttackEpisode)
                MATCH (e)-[:CONTAINS]->(a:AttackAction)
                WHERE a.attack_pattern_ref IS NOT NULL
                WITH e, collect(DISTINCT a.attack_pattern_ref) AS techniques
                WHERE size(techniques) >= $min_size
                RETURN techniques, count(e) as support
                """
                params = {"group_id": intrusion_set_id, "min_size": min_size}
            else:
                query = """
                MATCH (e:AttackEpisode)-[:CONTAINS]->(a:AttackAction)
                WHERE a.attack_pattern_ref IS NOT NULL
                WITH e, collect(DISTINCT a.attack_pattern_ref) AS techniques
                WHERE size(techniques) >= $min_size
                RETURN techniques, count(e) as support
                """
                params = {"min_size": min_size}
            
            result = session.run(query, **params)
            
            # Count itemsets
            itemset_counts = defaultdict(int)
            total_episodes = 0
            all_techniques = set()
            
            for record in result:
                techniques = set(record["techniques"])
                support = record["support"]
                total_episodes += support
                all_techniques.update(techniques)
                
                # Generate itemsets of different sizes
                for size in range(min_size, min(len(techniques) + 1, max_size + 1)):
                    for itemset in self._generate_combinations(techniques, size):
                        itemset_counts[frozenset(itemset)] += support
            
            # Calculate bundle metrics
            bundles = []
            
            # Get individual technique supports for lift calculation
            tech_supports = {}
            if intrusion_set_id:
                tech_query = """
                MATCH (g:IntrusionSet {stix_id: $group_id})<-[:ATTRIBUTED_TO]-(e:AttackEpisode)
                MATCH (e)-[:CONTAINS]->(a:AttackAction)
                WHERE a.attack_pattern_ref IS NOT NULL
                WITH a.attack_pattern_ref as tech, count(DISTINCT e) as support
                RETURN tech, support
                """
                tech_result = session.run(tech_query, group_id=intrusion_set_id)
            else:
                tech_query = """
                MATCH (e:AttackEpisode)-[:CONTAINS]->(a:AttackAction)
                WHERE a.attack_pattern_ref IS NOT NULL
                WITH a.attack_pattern_ref as tech, count(DISTINCT e) as support
                RETURN tech, support
                """
                tech_result = session.run(tech_query)
            
            for record in tech_result:
                tech_supports[record["tech"]] = record["support"]
            
            for itemset, support in itemset_counts.items():
                if support < min_support:
                    continue
                
                techniques = list(itemset)
                
                # Calculate confidence (support / support of least common item)
                min_individual_support = min(tech_supports.get(t, 1) for t in techniques)
                confidence = support / min_individual_support if min_individual_support > 0 else 0
                
                # Calculate lift
                expected = total_episodes
                for tech in techniques:
                    tech_prob = tech_supports.get(tech, 1) / total_episodes
                    expected *= tech_prob
                expected *= total_episodes
                
                lift = support / expected if expected > 0 else 0
                
                # Get tactics for bundle
                tactic_query = """
                MATCH (t:AttackPattern)-[:HAS_TACTIC]->(tac:Tactic)
                WHERE t.stix_id IN $techniques
                RETURN DISTINCT tac.shortname as tactic
                """
                tactic_result = session.run(tactic_query, techniques=techniques)
                tactics = [r["tactic"] for r in tactic_result if r["tactic"]]
                
                bundles.append(TechniqueBundle(
                    techniques=techniques,
                    support=support,
                    confidence=confidence,
                    lift=lift,
                    tactics=tactics,
                    intrusion_sets=[intrusion_set_id] if intrusion_set_id else []
                ))
            
            # Sort by lift (best indicator of interesting bundles)
            bundles.sort(key=lambda x: x.lift, reverse=True)
            
            return bundles
    
    def build_actor_profiles(self) -> List[ActorProfile]:
        """
        Build technique profiles for all intrusion sets.
        
        Returns:
            List of actor profiles with TF-IDF vectors
        """
        with self.driver.session() as session:
            # Get all intrusion sets with their techniques
            query = """
            MATCH (g:IntrusionSet)<-[:ATTRIBUTED_TO]-(e:AttackEpisode)
            MATCH (e)-[:CONTAINS]->(a:AttackAction)
            WHERE a.attack_pattern_ref IS NOT NULL
            WITH g, a.attack_pattern_ref as tech, count(DISTINCT e) as freq
            WITH g, collect({technique: tech, count: freq}) as tech_data, 
                 sum(freq) as total_count,
                 count(DISTINCT tech) as unique_techniques
            WHERE unique_techniques > 0
            RETURN g.stix_id as id, g.name as name, tech_data, total_count
            """
            
            result = session.run(query)
            profiles = []
            
            # Build document frequency for IDF calculation
            doc_freq = defaultdict(int)
            actor_data = []
            
            for record in result:
                actor_data.append(record)
                techniques = {td["technique"] for td in record["tech_data"]}
                for tech in techniques:
                    doc_freq[tech] += 1
            
            total_actors = len(actor_data)
            
            # Build profiles with TF-IDF
            all_techniques = sorted(doc_freq.keys())
            tech_to_idx = {tech: i for i, tech in enumerate(all_techniques)}
            
            for record in actor_data:
                tech_counts = {td["technique"]: td["count"] for td in record["tech_data"]}
                total_count = record["total_count"]
                
                # Calculate TF-IDF vector
                tf_idf_vector = np.zeros(len(all_techniques))
                signature_techs = []
                
                for tech, count in tech_counts.items():
                    tf = count / total_count  # Term frequency
                    idf = math.log(total_actors / doc_freq[tech])  # Inverse document frequency
                    tf_idf = tf * idf
                    
                    idx = tech_to_idx[tech]
                    tf_idf_vector[idx] = tf_idf
                    
                    # Track high TF-IDF techniques as signatures
                    if tf_idf > 0.1:  # Threshold for signature techniques
                        signature_techs.append((tech, tf_idf))
                
                # Get dominant tactics
                tactic_query = """
                MATCH (g:IntrusionSet {stix_id: $group_id})<-[:ATTRIBUTED_TO]-(e:AttackEpisode)
                MATCH (e)-[:CONTAINS]->(a:AttackAction)
                MATCH (t:AttackPattern {stix_id: a.attack_pattern_ref})-[:HAS_TACTIC]->(tac:Tactic)
                WITH tac.shortname as tactic, count(DISTINCT a) as count
                RETURN tactic, count
                ORDER BY count DESC
                LIMIT 3
                """
                tactic_result = session.run(tactic_query, group_id=record["id"])
                dominant_tactics = [r["tactic"] for r in tactic_result if r["tactic"]]
                
                # Sort signature techniques by TF-IDF
                signature_techs.sort(key=lambda x: x[1], reverse=True)
                signature_technique_ids = [t[0] for t in signature_techs[:10]]  # Top 10
                
                profiles.append(ActorProfile(
                    intrusion_set_id=record["id"],
                    intrusion_set_name=record["name"] or record["id"],
                    techniques=list(tech_counts.keys()),
                    technique_counts=tech_counts,
                    total_episodes=total_count,
                    tf_idf_vector=tf_idf_vector,
                    dominant_tactics=dominant_tactics,
                    signature_techniques=signature_technique_ids
                ))
            
        return profiles
    
    def calculate_actor_similarity(
        self,
        profiles: Optional[List[ActorProfile]] = None,
        min_similarity: float = 0.3
    ) -> List[Tuple[str, str, float]]:
        """
        Calculate pairwise actor similarity based on technique usage.
        
        Args:
            profiles: Actor profiles (will build if not provided)
            min_similarity: Minimum similarity threshold
            
        Returns:
            List of (actor1, actor2, similarity) tuples
        """
        if profiles is None:
            profiles = self.build_actor_profiles()
        
        similarities = []
        
        for i, profile1 in enumerate(profiles):
            for profile2 in profiles[i+1:]:
                # Calculate cosine similarity
                vec1 = profile1.tf_idf_vector
                vec2 = profile2.tf_idf_vector
                
                if vec1 is not None and vec2 is not None:
                    dot_product = np.dot(vec1, vec2)
                    norm1 = np.linalg.norm(vec1)
                    norm2 = np.linalg.norm(vec2)
                    
                    if norm1 > 0 and norm2 > 0:
                        similarity = dot_product / (norm1 * norm2)
                        
                        if similarity >= min_similarity:
                            similarities.append((
                                profile1.intrusion_set_id,
                                profile2.intrusion_set_id,
                                float(similarity)
                            ))
        
        # Sort by similarity
        similarities.sort(key=lambda x: x[2], reverse=True)
        
        return similarities
    
    def identify_bridging_techniques(
        self,
        min_actors: int = 3
    ) -> List[Tuple[str, int, float]]:
        """
        Identify techniques that bridge multiple actors (high betweenness).
        
        Args:
            min_actors: Minimum actors using the technique
            
        Returns:
            List of (technique, actor_count, avg_importance) tuples
        """
        with self.driver.session() as session:
            query = """
            MATCH (g:IntrusionSet)<-[:ATTRIBUTED_TO]-(e:AttackEpisode)
            MATCH (e)-[:CONTAINS]->(a:AttackAction)
            WHERE a.attack_pattern_ref IS NOT NULL
            WITH a.attack_pattern_ref as tech, 
                 count(DISTINCT g) as actor_count,
                 count(DISTINCT e) as episode_count,
                 collect(DISTINCT g.stix_id) as actors
            WHERE actor_count >= $min_actors
            RETURN tech, actor_count, episode_count, actors
            ORDER BY actor_count DESC, episode_count DESC
            """
            
            result = session.run(query, min_actors=min_actors)
            
            bridging = []
            for record in result:
                # Calculate average importance (episodes per actor)
                avg_importance = record["episode_count"] / record["actor_count"]
                
                bridging.append((
                    record["tech"],
                    record["actor_count"],
                    avg_importance
                ))
            
            return bridging
    
    def _generate_combinations(self, items: set, size: int) -> List[List]:
        """Generate all combinations of given size from items."""
        from itertools import combinations
        return list(combinations(items, size))