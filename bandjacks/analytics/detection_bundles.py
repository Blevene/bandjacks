"""Detection bundle recommendations based on co-occurrence patterns."""

import logging
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from collections import defaultdict
from neo4j import GraphDatabase

logger = logging.getLogger(__name__)


@dataclass
class DetectionRecommendation:
    """A recommended detection or mitigation."""
    technique_id: str
    technique_name: str
    detection_type: str  # 'data_source', 'detection_rule', 'mitigation'
    recommendation_id: str
    recommendation_name: str
    confidence: float
    coverage_impact: float  # Percentage coverage improvement
    implementation_cost: str  # 'low', 'medium', 'high'
    

@dataclass
class DetectionBundle:
    """A bundle of detection recommendations."""
    bundle_id: str
    name: str
    description: str
    techniques_covered: List[str]
    recommendations: List[DetectionRecommendation]
    total_coverage_improvement: float
    implementation_complexity: str  # 'low', 'medium', 'high'
    priority_score: float
    actors_covered: List[str] = field(default_factory=list)
    

@dataclass
class CoverageReport:
    """Coverage analysis report."""
    current_coverage: float
    potential_coverage: float
    coverage_by_tactic: Dict[str, float]
    top_gaps: List[Dict[str, Any]]
    recommended_bundles: List[DetectionBundle]


class DetectionBundleGenerator:
    """Generate detection bundle recommendations."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """Initialize with Neo4j connection."""
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    
    def close(self):
        """Close database connection."""
        self.driver.close()
    
    def generate_bundle_for_techniques(
        self,
        techniques: List[str],
        bundle_name: Optional[str] = None
    ) -> DetectionBundle:
        """
        Generate detection bundle for a set of techniques.
        
        Args:
            techniques: List of technique IDs
            bundle_name: Optional name for the bundle
            
        Returns:
            Detection bundle with recommendations
        """
        with self.driver.session() as session:
            recommendations = []
            covered_techniques = set()
            
            # Get data sources that can detect these techniques
            data_source_query = """
            MATCH (t:AttackPattern)<-[:DETECTS]-(dc:DataComponent)<-[:HAS_COMPONENT]-(ds:DataSource)
            WHERE t.stix_id IN $techniques
            WITH ds, dc, collect(DISTINCT t) as detected_techniques
            RETURN ds.stix_id as ds_id,
                   ds.name as ds_name,
                   dc.stix_id as dc_id,
                   dc.name as dc_name,
                   [t IN detected_techniques | t.stix_id] as technique_ids,
                   size(detected_techniques) as coverage_count
            ORDER BY coverage_count DESC
            """
            
            ds_result = session.run(data_source_query, techniques=techniques)
            
            for record in ds_result:
                for tech_id in record['technique_ids']:
                    if tech_id not in covered_techniques:
                        # Get technique name
                        tech_name_result = session.run(
                            "MATCH (t:AttackPattern {stix_id: $id}) RETURN t.name as name",
                            id=tech_id
                        ).single()
                        
                        recommendations.append(DetectionRecommendation(
                            technique_id=tech_id,
                            technique_name=tech_name_result['name'] if tech_name_result else tech_id,
                            detection_type='data_source',
                            recommendation_id=record['dc_id'],
                            recommendation_name=f"{record['ds_name']}: {record['dc_name']}",
                            confidence=0.8,  # Data sources have high confidence
                            coverage_impact=100.0 / len(techniques),  # Simple percentage
                            implementation_cost='medium'
                        ))
                        covered_techniques.add(tech_id)
            
            # Get mitigations for uncovered techniques
            uncovered = set(techniques) - covered_techniques
            if uncovered:
                mitigation_query = """
                MATCH (t:AttackPattern)<-[:MITIGATES]-(m:CoursOfAction)
                WHERE t.stix_id IN $techniques
                RETURN t.stix_id as tech_id,
                       t.name as tech_name,
                       m.stix_id as mit_id,
                       m.name as mit_name,
                       m.description as mit_desc
                LIMIT 20
                """
                
                mit_result = session.run(mitigation_query, techniques=list(uncovered))
                
                for record in mit_result:
                    if record['tech_id'] not in covered_techniques:
                        recommendations.append(DetectionRecommendation(
                            technique_id=record['tech_id'],
                            technique_name=record['tech_name'],
                            detection_type='mitigation',
                            recommendation_id=record['mit_id'],
                            recommendation_name=record['mit_name'],
                            confidence=0.6,  # Mitigations have lower confidence
                            coverage_impact=100.0 / len(techniques),
                            implementation_cost='high'
                        ))
                        covered_techniques.add(record['tech_id'])
            
            # Calculate total coverage improvement
            total_coverage = (len(covered_techniques) / len(techniques)) * 100 if techniques else 0
            
            # Determine implementation complexity
            costs = [r.implementation_cost for r in recommendations]
            if 'high' in costs:
                complexity = 'high'
            elif 'medium' in costs:
                complexity = 'medium'
            else:
                complexity = 'low'
            
            # Calculate priority score
            priority_score = total_coverage * (1.0 if complexity == 'low' else 0.7 if complexity == 'medium' else 0.5)
            
            # Get actors using these techniques
            actor_query = """
            MATCH (g:IntrusionSet)<-[:ATTRIBUTED_TO]-(e:AttackEpisode)
            MATCH (e)-[:CONTAINS]->(a:AttackAction)
            WHERE a.attack_pattern_ref IN $techniques
            RETURN DISTINCT g.stix_id as actor_id, g.name as actor_name
            LIMIT 10
            """
            actor_result = session.run(actor_query, techniques=techniques)
            actors = [r['actor_id'] for r in actor_result]
            
            return DetectionBundle(
                bundle_id=f"bundle_{hash(tuple(sorted(techniques))) % 100000}",
                name=bundle_name or f"Detection Bundle for {len(techniques)} Techniques",
                description=f"Covers {len(covered_techniques)}/{len(techniques)} techniques with {len(recommendations)} recommendations",
                techniques_covered=list(covered_techniques),
                recommendations=recommendations,
                total_coverage_improvement=total_coverage,
                implementation_complexity=complexity,
                priority_score=priority_score,
                actors_covered=actors
            )
    
    def recommend_bundles_for_actor(
        self,
        intrusion_set_id: str,
        max_bundles: int = 5
    ) -> List[DetectionBundle]:
        """
        Recommend detection bundles for a specific actor.
        
        Args:
            intrusion_set_id: STIX ID of the intrusion set
            max_bundles: Maximum number of bundles to recommend
            
        Returns:
            List of recommended detection bundles
        """
        with self.driver.session() as session:
            # Get actor's techniques grouped by co-occurrence
            tech_query = """
            MATCH (g:IntrusionSet {stix_id: $actor_id})<-[:ATTRIBUTED_TO]-(e:AttackEpisode)
            MATCH (e)-[:CONTAINS]->(a:AttackAction)
            WHERE a.attack_pattern_ref IS NOT NULL
            WITH e, collect(DISTINCT a.attack_pattern_ref) as episode_techniques
            WHERE size(episode_techniques) >= 2
            RETURN episode_techniques, count(e) as frequency
            ORDER BY frequency DESC
            LIMIT 10
            """
            
            result = session.run(tech_query, actor_id=intrusion_set_id)
            
            bundles = []
            seen_techniques = set()
            
            for record in result:
                # Skip if most techniques already covered
                new_techniques = set(record['episode_techniques']) - seen_techniques
                if len(new_techniques) < 2:
                    continue
                
                # Generate bundle for this technique group
                bundle = self.generate_bundle_for_techniques(
                    list(new_techniques),
                    f"Bundle for {record['frequency']} Episodes"
                )
                
                if bundle.recommendations:
                    bundles.append(bundle)
                    seen_techniques.update(new_techniques)
                
                if len(bundles) >= max_bundles:
                    break
            
            # Sort by priority score
            bundles.sort(key=lambda x: x.priority_score, reverse=True)
            
            return bundles[:max_bundles]
    
    def analyze_coverage(
        self,
        scope: str = 'global',
        scope_id: Optional[str] = None
    ) -> CoverageReport:
        """
        Analyze detection coverage for a scope.
        
        Args:
            scope: 'global' or 'actor'
            scope_id: ID for actor scope
            
        Returns:
            Coverage analysis report
        """
        with self.driver.session() as session:
            if scope == 'actor' and scope_id:
                # Actor-specific coverage
                base_query = """
                MATCH (g:IntrusionSet {stix_id: $actor_id})<-[:ATTRIBUTED_TO]-(e:AttackEpisode)
                MATCH (e)-[:CONTAINS]->(a:AttackAction)
                MATCH (t:AttackPattern {stix_id: a.attack_pattern_ref})
                """
                params = {'actor_id': scope_id}
            else:
                # Global coverage
                base_query = """
                MATCH (t:AttackPattern)
                WHERE NOT t.x_mitre_is_subtechnique
                """
                params = {}
            
            # Calculate current coverage
            coverage_query = base_query + """
            OPTIONAL MATCH (t)<-[:DETECTS]-(d)
            OPTIONAL MATCH (t)<-[:MITIGATES]-(m)
            WITH count(DISTINCT t) as total,
                 count(DISTINCT CASE WHEN d IS NOT NULL THEN t END) as detected,
                 count(DISTINCT CASE WHEN m IS NOT NULL THEN t END) as mitigated
            RETURN total, detected, mitigated,
                   100.0 * detected / total as detection_coverage,
                   100.0 * mitigated / total as mitigation_coverage,
                   100.0 * (detected + mitigated) / (total * 2) as overall_coverage
            """
            
            coverage_result = session.run(coverage_query, **params).single()
            
            current_coverage = coverage_result['overall_coverage'] if coverage_result else 0
            
            # Coverage by tactic
            tactic_query = base_query + """
            OPTIONAL MATCH (t)-[:HAS_TACTIC]->(tac:Tactic)
            OPTIONAL MATCH (t)<-[:DETECTS]-(d)
            WITH tac.shortname as tactic,
                 count(DISTINCT t) as total,
                 count(DISTINCT CASE WHEN d IS NOT NULL THEN t END) as detected
            WHERE tactic IS NOT NULL
            RETURN tactic,
                   100.0 * detected / total as coverage
            ORDER BY coverage ASC
            """
            
            tactic_result = session.run(tactic_query, **params)
            coverage_by_tactic = {r['tactic']: r['coverage'] for r in tactic_result}
            
            # Find top gaps
            gaps_query = base_query + """
            WHERE NOT EXISTS((t)<-[:DETECTS]-())
            AND NOT EXISTS((t)<-[:MITIGATES]-())
            OPTIONAL MATCH (t)-[:HAS_TACTIC]->(tac:Tactic)
            RETURN t.stix_id as technique_id,
                   t.name as technique_name,
                   collect(DISTINCT tac.shortname) as tactics
            LIMIT 20
            """
            
            gaps_result = session.run(gaps_query, **params)
            top_gaps = [
                {
                    'technique_id': r['technique_id'],
                    'technique_name': r['technique_name'],
                    'tactics': r['tactics']
                }
                for r in gaps_result
            ]
            
            # Generate recommended bundles
            if top_gaps:
                gap_techniques = [g['technique_id'] for g in top_gaps[:10]]
                main_bundle = self.generate_bundle_for_techniques(
                    gap_techniques,
                    "Priority Gap Coverage Bundle"
                )
                recommended_bundles = [main_bundle]
            else:
                recommended_bundles = []
            
            # Calculate potential coverage with recommendations
            potential_coverage = current_coverage
            if recommended_bundles:
                potential_coverage += recommended_bundles[0].total_coverage_improvement
            
            return CoverageReport(
                current_coverage=current_coverage,
                potential_coverage=min(potential_coverage, 100.0),
                coverage_by_tactic=coverage_by_tactic,
                top_gaps=top_gaps,
                recommended_bundles=recommended_bundles
            )
    
    def find_minimal_detection_set(
        self,
        techniques: List[str],
        max_detections: int = 10
    ) -> List[DetectionRecommendation]:
        """
        Find minimal set of detections to cover techniques.
        
        Uses a greedy set cover algorithm to find the smallest
        set of detections that covers the most techniques.
        
        Args:
            techniques: List of technique IDs to cover
            max_detections: Maximum number of detections to recommend
            
        Returns:
            Minimal set of detection recommendations
        """
        with self.driver.session() as session:
            # Get all possible detections and their coverage
            detection_query = """
            MATCH (t:AttackPattern)<-[:DETECTS]-(dc:DataComponent)
            WHERE t.stix_id IN $techniques
            WITH dc, collect(DISTINCT t.stix_id) as covered_techniques
            MATCH (dc)<-[:HAS_COMPONENT]-(ds:DataSource)
            RETURN dc.stix_id as detection_id,
                   ds.name + ': ' + dc.name as detection_name,
                   covered_techniques,
                   size(covered_techniques) as coverage_count
            ORDER BY coverage_count DESC
            """
            
            result = session.run(detection_query, techniques=techniques)
            
            # Greedy set cover
            uncovered = set(techniques)
            selected_detections = []
            
            detections_data = list(result)
            
            while uncovered and len(selected_detections) < max_detections and detections_data:
                # Find detection that covers the most uncovered techniques
                best_detection = None
                best_coverage = set()
                best_idx = -1
                
                for idx, detection in enumerate(detections_data):
                    coverage = set(detection['covered_techniques']) & uncovered
                    if len(coverage) > len(best_coverage):
                        best_detection = detection
                        best_coverage = coverage
                        best_idx = idx
                
                if best_detection:
                    # Add to selected detections
                    for tech_id in best_coverage:
                        tech_name_result = session.run(
                            "MATCH (t:AttackPattern {stix_id: $id}) RETURN t.name as name",
                            id=tech_id
                        ).single()
                        
                        selected_detections.append(DetectionRecommendation(
                            technique_id=tech_id,
                            technique_name=tech_name_result['name'] if tech_name_result else tech_id,
                            detection_type='data_source',
                            recommendation_id=best_detection['detection_id'],
                            recommendation_name=best_detection['detection_name'],
                            confidence=0.8,
                            coverage_impact=100.0 / len(techniques),
                            implementation_cost='medium'
                        ))
                    
                    # Update uncovered set
                    uncovered -= best_coverage
                    
                    # Remove used detection from candidates
                    if best_idx >= 0:
                        detections_data.pop(best_idx)
                else:
                    break
            
            return selected_detections