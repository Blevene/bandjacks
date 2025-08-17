"""Query optimization and index management."""

from typing import List, Dict, Any
from neo4j import GraphDatabase


class QueryOptimizer:
    """Manages query optimization and indexes."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """
        Initialize query optimizer.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
        """
        self.driver = GraphDatabase.driver(
            neo4j_uri,
            auth=(neo4j_user, neo4j_password)
        )
    
    def create_indexes(self) -> Dict[str, bool]:
        """
        Create performance indexes.
        
        Returns:
            Dictionary of index creation results
        """
        indexes = {
            # Node property indexes
            "AttackPattern_stix_id": "CREATE INDEX IF NOT EXISTS FOR (n:AttackPattern) ON (n.stix_id)",
            "AttackPattern_name": "CREATE INDEX IF NOT EXISTS FOR (n:AttackPattern) ON (n.name)",
            "IntrusionSet_stix_id": "CREATE INDEX IF NOT EXISTS FOR (n:IntrusionSet) ON (n.stix_id)",
            "IntrusionSet_name": "CREATE INDEX IF NOT EXISTS FOR (n:IntrusionSet) ON (n.name)",
            "Software_stix_id": "CREATE INDEX IF NOT EXISTS FOR (n:Software) ON (n.stix_id)",
            "Software_name": "CREATE INDEX IF NOT EXISTS FOR (n:Software) ON (n.name)",
            "Mitigation_stix_id": "CREATE INDEX IF NOT EXISTS FOR (n:Mitigation) ON (n.stix_id)",
            "CandidateNode_status": "CREATE INDEX IF NOT EXISTS FOR (n:CandidateNode) ON (n.status)",
            "CandidateNode_created": "CREATE INDEX IF NOT EXISTS FOR (n:CandidateNode) ON (n.created_at)",
            
            # Text indexes for search
            "AttackPattern_text": """
                CREATE FULLTEXT INDEX attackpattern_text IF NOT EXISTS
                FOR (n:AttackPattern)
                ON EACH [n.name, n.description]
            """,
            "IntrusionSet_text": """
                CREATE FULLTEXT INDEX intrusionset_text IF NOT EXISTS
                FOR (n:IntrusionSet)
                ON EACH [n.name, n.description, n.aliases]
            """,
            "Software_text": """
                CREATE FULLTEXT INDEX software_text IF NOT EXISTS
                FOR (n:Software)
                ON EACH [n.name, n.description]
            """
        }
        
        results = {}
        with self.driver.session() as session:
            for name, query in indexes.items():
                try:
                    session.run(query)
                    results[name] = True
                except Exception as e:
                    print(f"Failed to create index {name}: {e}")
                    results[name] = False
        
        return results
    
    def analyze_query_performance(self, query: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Analyze query performance using EXPLAIN and PROFILE.
        
        Args:
            query: Cypher query to analyze
            params: Query parameters
            
        Returns:
            Performance analysis results
        """
        with self.driver.session() as session:
            # Get query plan
            explain_query = f"EXPLAIN {query}"
            plan_result = session.run(explain_query, params or {})
            plan = plan_result.consume().plan
            
            # Get profile if small result set expected
            profile_query = f"PROFILE {query}"
            profile_result = session.run(profile_query, params or {})
            profile = profile_result.consume().profile
            
            return {
                "plan": self._format_plan(plan) if plan else None,
                "profile": self._format_profile(profile) if profile else None,
                "estimated_rows": plan.arguments.get("EstimatedRows", 0) if plan else 0
            }
    
    def _format_plan(self, plan) -> Dict[str, Any]:
        """Format query plan for readability."""
        return {
            "operator": plan.operator_type,
            "estimated_rows": plan.arguments.get("EstimatedRows", 0),
            "identifiers": plan.identifiers,
            "children": [self._format_plan(child) for child in plan.children]
        }
    
    def _format_profile(self, profile) -> Dict[str, Any]:
        """Format query profile for readability."""
        return {
            "operator": profile.operator_type,
            "rows": profile.rows,
            "db_hits": profile.db_hits,
            "time": profile.time,
            "children": [self._format_profile(child) for child in profile.children]
        }
    
    def optimize_common_queries(self) -> List[Dict[str, Any]]:
        """
        Optimize common query patterns.
        
        Returns:
            List of optimization recommendations
        """
        recommendations = []
        
        with self.driver.session() as session:
            # Check for missing indexes
            check_query = """
                MATCH (n:AttackPattern)-[:USES]-(g:IntrusionSet)
                RETURN count(*) as count
            """
            
            profile = self.analyze_query_performance(check_query)
            
            if profile.get("profile", {}).get("db_hits", 0) > 10000:
                recommendations.append({
                    "type": "index",
                    "recommendation": "Consider adding composite index on relationship patterns",
                    "impact": "high"
                })
            
            # Check for cartesian products
            cartesian_query = """
                MATCH (a:AttackPattern), (b:AttackPattern)
                WHERE a.name CONTAINS 'lateral' AND b.name CONTAINS 'persistence'
                RETURN count(*) as count
            """
            
            plan = self.analyze_query_performance(cartesian_query)
            
            if "CartesianProduct" in str(plan.get("plan", {})):
                recommendations.append({
                    "type": "query",
                    "recommendation": "Avoid cartesian products by adding relationship constraints",
                    "impact": "high"
                })
            
            # Check node counts for optimization hints
            count_query = """
                MATCH (n)
                RETURN labels(n)[0] as label, count(*) as count
                ORDER BY count DESC
            """
            
            result = session.run(count_query)
            
            for record in result:
                if record["count"] > 10000:
                    recommendations.append({
                        "type": "partition",
                        "recommendation": f"Consider partitioning {record['label']} nodes (count: {record['count']})",
                        "impact": "medium"
                    })
        
        return recommendations
    
    def create_query_hints(self, query_type: str) -> str:
        """
        Generate query hints for common patterns.
        
        Args:
            query_type: Type of query (search, traversal, aggregation)
            
        Returns:
            Optimized query template with hints
        """
        hints = {
            "search": """
                // Use index hints for large searches
                MATCH (n:AttackPattern)
                USING INDEX n:AttackPattern(name)
                WHERE n.name CONTAINS $search_term
                RETURN n
                LIMIT 100
            """,
            
            "traversal": """
                // Use variable-length paths with limits
                MATCH path = (start:AttackPattern {stix_id: $start_id})-[*1..3]-(end)
                WHERE NOT end:Archive
                WITH path, length(path) as pathLength
                ORDER BY pathLength
                LIMIT 100
                RETURN path
            """,
            
            "aggregation": """
                // Use WITH for intermediate aggregations
                MATCH (g:IntrusionSet)-[:USES]->(t:AttackPattern)
                WITH g, count(t) as technique_count
                WHERE technique_count > 5
                RETURN g.name, technique_count
                ORDER BY technique_count DESC
            """
        }
        
        return hints.get(query_type, "// No specific hints for this query type")
    
    def close(self):
        """Close the driver."""
        if self.driver:
            self.driver.close()