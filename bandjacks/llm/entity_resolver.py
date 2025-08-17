"""Resolve extracted entities to existing STIX IDs in the knowledge base."""

import re
from typing import Optional, Dict, List, Any, Tuple
from neo4j import GraphDatabase
from fuzzywuzzy import fuzz
import Levenshtein


class EntityResolver:
    """Resolve extracted entity names to STIX IDs in Neo4j knowledge base."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """
        Initialize entity resolver with Neo4j connection.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
        """
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.cache = {}  # Cache resolved entities
        self._load_aliases()
    
    def _load_aliases(self):
        """Load known entity aliases from the knowledge base."""
        self.aliases = {}
        
        with self.driver.session() as session:
            # Load intrusion set aliases
            result = session.run("""
                MATCH (n:IntrusionSet)
                WHERE n.revoked = false OR n.revoked IS NULL
                RETURN n.stix_id as id, n.name as name, n.aliases as aliases
            """)
            
            for record in result:
                name = record["name"]
                stix_id = record["id"]
                aliases = record.get("aliases", []) or []
                
                # Index by primary name
                self.aliases[name.lower()] = stix_id
                
                # Index by aliases
                for alias in aliases:
                    if alias:
                        self.aliases[alias.lower()] = stix_id
            
            # Load software aliases
            result = session.run("""
                MATCH (n:Software)
                WHERE n.revoked = false OR n.revoked IS NULL
                RETURN n.stix_id as id, n.name as name, n.aliases as aliases
            """)
            
            for record in result:
                name = record["name"]
                stix_id = record["id"]
                aliases = record.get("aliases", []) or []
                
                self.aliases[name.lower()] = stix_id
                for alias in aliases:
                    if alias:
                        self.aliases[alias.lower()] = stix_id
    
    def resolve_entity(
        self,
        entity_name: str,
        entity_type: Optional[str] = None,
        threshold: float = 0.85
    ) -> Optional[str]:
        """
        Resolve an entity name to a STIX ID.
        
        Args:
            entity_name: Name of the entity to resolve
            entity_type: Optional STIX type hint (intrusion-set, malware, tool)
            threshold: Minimum similarity score for fuzzy matching (0-1)
            
        Returns:
            STIX ID if found, None otherwise
        """
        if not entity_name:
            return None
        
        # Check cache first
        cache_key = f"{entity_name}:{entity_type}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        name_lower = entity_name.lower().strip()
        
        # 1. Try exact match in aliases
        if name_lower in self.aliases:
            stix_id = self.aliases[name_lower]
            self.cache[cache_key] = stix_id
            return stix_id
        
        # 2. Try pattern-based matching for common formats
        stix_id = self._match_by_pattern(entity_name, entity_type)
        if stix_id:
            self.cache[cache_key] = stix_id
            return stix_id
        
        # 3. Try fuzzy matching against known entities
        stix_id = self._fuzzy_match(entity_name, entity_type, threshold)
        if stix_id:
            self.cache[cache_key] = stix_id
            return stix_id
        
        # 4. Try database search
        stix_id = self._search_database(entity_name, entity_type, threshold)
        if stix_id:
            self.cache[cache_key] = stix_id
            return stix_id
        
        # Not found
        self.cache[cache_key] = None
        return None
    
    def resolve_technique(self, technique_ref: str) -> Optional[str]:
        """
        Resolve a technique reference to a STIX ID.
        
        Args:
            technique_ref: Technique ID (e.g., "T1566.001") or name
            
        Returns:
            STIX ID for the attack-pattern if found
        """
        if not technique_ref:
            return None
        
        # Check cache
        cache_key = f"technique:{technique_ref}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        with self.driver.session() as session:
            # First try by external ID
            if re.match(r"T\d{4}(?:\.\d{3})?", technique_ref):
                result = session.run("""
                    MATCH (t:AttackPattern)
                    WHERE t.external_id = $ref 
                       OR $ref IN t.external_references
                       OR t.name CONTAINS $ref
                    AND (t.revoked = false OR t.revoked IS NULL)
                    RETURN t.stix_id as id
                    LIMIT 1
                """, ref=technique_ref)
                
                record = result.single()
                if record:
                    stix_id = record["id"]
                    self.cache[cache_key] = stix_id
                    return stix_id
            
            # Try by name
            result = session.run("""
                MATCH (t:AttackPattern)
                WHERE toLower(t.name) = toLower($name)
                   OR toLower(t.name) CONTAINS toLower($name)
                AND (t.revoked = false OR t.revoked IS NULL)
                RETURN t.stix_id as id
                ORDER BY CASE 
                    WHEN toLower(t.name) = toLower($name) THEN 0
                    ELSE 1
                END
                LIMIT 1
            """, name=technique_ref)
            
            record = result.single()
            if record:
                stix_id = record["id"]
                self.cache[cache_key] = stix_id
                return stix_id
        
        self.cache[cache_key] = None
        return None
    
    def _match_by_pattern(self, entity_name: str, entity_type: Optional[str]) -> Optional[str]:
        """Match entity by common naming patterns."""
        name_lower = entity_name.lower()
        
        # APT group patterns
        apt_patterns = [
            (r"apt[\s-]?(\d+)", "intrusion-set"),
            (r"ta[\s-]?(\d+)", "intrusion-set"),
            (r"g\d{4}", "intrusion-set"),
            (r"unc\d+", "intrusion-set"),
            (r"dev-\d+", "intrusion-set"),
            (r"fin\d+", "intrusion-set"),
            (r"carbanak", "intrusion-set"),
            (r"lazarus", "intrusion-set"),
            (r"cozy\s?bear", "intrusion-set"),
            (r"fancy\s?bear", "intrusion-set")
        ]
        
        for pattern, expected_type in apt_patterns:
            if re.search(pattern, name_lower):
                if entity_type and entity_type != expected_type:
                    continue
                    
                # Search in database by pattern
                with self.driver.session() as session:
                    result = session.run("""
                        MATCH (n)
                        WHERE toLower(n.name) =~ $pattern
                           OR ANY(alias IN n.aliases WHERE toLower(alias) =~ $pattern)
                        AND (n.revoked = false OR n.revoked IS NULL)
                        RETURN n.stix_id as id
                        LIMIT 1
                    """, pattern=f".*{pattern}.*")
                    
                    record = result.single()
                    if record:
                        return record["id"]
        
        return None
    
    def _fuzzy_match(
        self,
        entity_name: str,
        entity_type: Optional[str],
        threshold: float
    ) -> Optional[str]:
        """Fuzzy match against known aliases."""
        name_lower = entity_name.lower()
        best_match = None
        best_score = 0
        
        for alias, stix_id in self.aliases.items():
            # Skip if type doesn't match
            if entity_type and not stix_id.startswith(entity_type):
                continue
            
            # Calculate similarity
            score = fuzz.ratio(name_lower, alias) / 100.0
            
            # Also try token set ratio for partial matches
            token_score = fuzz.token_set_ratio(name_lower, alias) / 100.0
            score = max(score, token_score * 0.9)  # Slightly penalize token matches
            
            if score > best_score and score >= threshold:
                best_score = score
                best_match = stix_id
        
        return best_match
    
    def _search_database(
        self,
        entity_name: str,
        entity_type: Optional[str],
        threshold: float
    ) -> Optional[str]:
        """Search database for matching entities."""
        with self.driver.session() as session:
            # Build query based on entity type
            if entity_type == "intrusion-set":
                node_label = "IntrusionSet"
            elif entity_type == "malware":
                node_label = "Software"
                type_filter = "AND n.type = 'malware'"
            elif entity_type == "tool":
                node_label = "Software"
                type_filter = "AND n.type = 'tool'"
            elif entity_type in ["malware", "tool"]:
                node_label = "Software"
                type_filter = ""
            else:
                # Search all entity types
                return self._search_all_types(session, entity_name, threshold)
            
            # Search specific type
            query = f"""
                MATCH (n:{node_label})
                WHERE (n.revoked = false OR n.revoked IS NULL)
                {type_filter if entity_type in ["malware", "tool"] else ""}
                RETURN n.stix_id as id, n.name as name, n.aliases as aliases
            """
            
            result = session.run(query)
            
            best_match = None
            best_score = 0
            
            for record in result:
                name = record["name"]
                stix_id = record["id"]
                aliases = record.get("aliases", []) or []
                
                # Check name similarity
                score = self._calculate_similarity(entity_name, name)
                if score > best_score and score >= threshold:
                    best_score = score
                    best_match = stix_id
                
                # Check aliases
                for alias in aliases:
                    if alias:
                        score = self._calculate_similarity(entity_name, alias)
                        if score > best_score and score >= threshold:
                            best_score = score
                            best_match = stix_id
            
            return best_match
    
    def _search_all_types(
        self,
        session,
        entity_name: str,
        threshold: float
    ) -> Optional[str]:
        """Search across all entity types."""
        query = """
            MATCH (n)
            WHERE n:IntrusionSet OR n:Software OR n:AttackPattern
            AND (n.revoked = false OR n.revoked IS NULL)
            RETURN n.stix_id as id, n.name as name, 
                   n.aliases as aliases, labels(n) as labels
        """
        
        result = session.run(query)
        
        best_match = None
        best_score = 0
        
        for record in result:
            name = record["name"]
            stix_id = record["id"]
            aliases = record.get("aliases", []) or []
            
            # Check name similarity
            score = self._calculate_similarity(entity_name, name)
            if score > best_score and score >= threshold:
                best_score = score
                best_match = stix_id
            
            # Check aliases
            for alias in aliases:
                if alias:
                    score = self._calculate_similarity(entity_name, alias)
                    if score > best_score and score >= threshold:
                        best_score = score
                        best_match = stix_id
        
        return best_match
    
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate similarity between two strings."""
        if not str1 or not str2:
            return 0.0
        
        str1_lower = str1.lower().strip()
        str2_lower = str2.lower().strip()
        
        # Exact match
        if str1_lower == str2_lower:
            return 1.0
        
        # Levenshtein similarity
        lev_sim = 1 - (Levenshtein.distance(str1_lower, str2_lower) / 
                      max(len(str1_lower), len(str2_lower)))
        
        # Token set similarity (handles word order differences)
        token_sim = fuzz.token_set_ratio(str1_lower, str2_lower) / 100.0
        
        # Partial ratio (substring matching)
        partial_sim = fuzz.partial_ratio(str1_lower, str2_lower) / 100.0
        
        # Weight the different similarities
        return max(lev_sim * 0.4 + token_sim * 0.4 + partial_sim * 0.2, 
                  token_sim,  # Prioritize token matches for multi-word names
                  partial_sim * 0.8)  # Slightly penalize partial matches
    
    def batch_resolve(
        self,
        entities: List[Tuple[str, Optional[str]]],
        threshold: float = 0.85
    ) -> Dict[str, Optional[str]]:
        """
        Resolve multiple entities in batch.
        
        Args:
            entities: List of (entity_name, entity_type) tuples
            threshold: Minimum similarity threshold
            
        Returns:
            Dict mapping entity names to STIX IDs (or None)
        """
        results = {}
        
        for entity_name, entity_type in entities:
            stix_id = self.resolve_entity(entity_name, entity_type, threshold)
            results[entity_name] = stix_id
        
        return results
    
    def close(self):
        """Close the Neo4j connection."""
        if self.driver:
            self.driver.close()