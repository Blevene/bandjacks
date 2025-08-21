"""Detection bundle loader for STIX 2.1 detection strategies, analytics, and log sources."""

import json
import logging
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime
from neo4j import GraphDatabase, Session

logger = logging.getLogger(__name__)


class DetectionLoader:
    """Load and process detection strategies, analytics, and log sources."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """
        Initialize detection loader with Neo4j connection.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
        """
        self.driver = GraphDatabase.driver(
            neo4j_uri,
            auth=(neo4j_user, neo4j_password)
        )
    
    def ingest_detection_bundle(
        self,
        bundle: Dict[str, Any],
        collection: str = "detection-strategies",
        version: str = "latest",
        domain: str = "enterprise-attack"
    ) -> Dict[str, Any]:
        """
        Ingest a STIX 2.1 bundle containing detection strategies, analytics, and log sources.
        
        Args:
            bundle: STIX 2.1 bundle with detection objects
            collection: Source collection name
            version: Collection version
            domain: ATT&CK domain
            
        Returns:
            Summary of ingestion results
        """
        with self.driver.session() as session:
            # Validate bundle structure
            if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
                raise ValueError("Invalid bundle format")
            
            objects = bundle.get("objects", [])
            
            # Separate objects by type
            detection_strategies = []
            analytics = []
            log_sources = []
            relationships = []
            
            for obj in objects:
                obj_type = obj.get("type")
                if obj_type == "x-mitre-detection-strategy":
                    detection_strategies.append(obj)
                elif obj_type == "x-mitre-analytic":
                    analytics.append(obj)
                elif obj_type == "x-mitre-log-source":
                    log_sources.append(obj)
                elif obj_type == "relationship":
                    relationships.append(obj)
            
            # Process in order: log sources -> analytics -> strategies -> relationships
            log_source_count = self._process_log_sources(session, log_sources, collection, version, domain)
            analytic_count = self._process_analytics(session, analytics, collection, version, domain)
            strategy_count = self._process_detection_strategies(session, detection_strategies, collection, version, domain)
            relationship_count = self._process_detection_relationships(session, relationships, collection, version)
            
            # Build HAS_ANALYTIC relationships from strategy analytics arrays
            has_analytic_count = self._build_has_analytic_relationships(session, detection_strategies)
            
            # Build USES_LOG_SOURCE relationships from analytic log sources arrays
            uses_log_source_count = self._build_uses_log_source_relationships(session, analytics)
            
            return {
                "success": True,
                "detection_strategies": strategy_count,
                "analytics": analytic_count,
                "log_sources": log_source_count,
                "detects_relationships": relationship_count,
                "has_analytic_relationships": has_analytic_count,
                "uses_log_source_relationships": uses_log_source_count,
                "total_objects": len(objects)
            }
    
    def _process_log_sources(
        self,
        session: Session,
        log_sources: List[Dict[str, Any]],
        collection: str,
        version: str,
        domain: str
    ) -> int:
        """Process and create LogSource nodes."""
        count = 0
        for ls in log_sources:
            stix_id = ls.get("id")
            name = ls.get("name", "")
            description = ls.get("description", "")
            created = ls.get("created", datetime.utcnow().isoformat())
            modified = ls.get("modified", datetime.utcnow().isoformat())
            
            # Extract permutations
            permutations = ls.get("x_mitre_log_source_permutations", [])
            permutations_json = json.dumps(permutations) if permutations else "[]"
            
            result = session.run("""
                MERGE (ls:LogSource {stix_id: $stix_id})
                ON CREATE SET 
                    ls.created_ts = timestamp(),
                    ls.created = $created
                SET 
                    ls.type = 'x-mitre-log-source',
                    ls.name = $name,
                    ls.description = $description,
                    ls.modified = $modified,
                    ls.x_mitre_log_source_permutations = $permutations,
                    ls.source_collection = $collection,
                    ls.source_version = $version,
                    ls.source_domain = $domain
                RETURN ls
            """, 
                stix_id=stix_id,
                name=name,
                description=description,
                created=created,
                modified=modified,
                permutations=permutations_json,
                collection=collection,
                version=version,
                domain=domain
            )
            
            if result.single():
                count += 1
                logger.debug(f"Created/updated LogSource: {name} ({stix_id})")
        
        return count
    
    def _process_analytics(
        self,
        session: Session,
        analytics: List[Dict[str, Any]],
        collection: str,
        version: str,
        domain: str
    ) -> int:
        """Process and create Analytic nodes."""
        count = 0
        for analytic in analytics:
            stix_id = analytic.get("id")
            name = analytic.get("name", "")
            description = analytic.get("description", "")
            created = analytic.get("created", datetime.utcnow().isoformat())
            modified = analytic.get("modified", datetime.utcnow().isoformat())
            
            # Extract key fields
            platforms = analytic.get("platforms", [])
            x_mitre_detects = analytic.get("x_mitre_detects", "")
            x_mitre_mutable_elements = analytic.get("x_mitre_mutable_elements", [])
            x_mitre_log_sources = analytic.get("x_mitre_log_sources", [])
            revoked = analytic.get("revoked", False)
            x_mitre_deprecated = analytic.get("x_mitre_deprecated", False)
            
            # Convert arrays to JSON for storage
            platforms_json = json.dumps(platforms) if platforms else "[]"
            mutable_elements_json = json.dumps(x_mitre_mutable_elements) if x_mitre_mutable_elements else "[]"
            log_sources_json = json.dumps(x_mitre_log_sources) if x_mitre_log_sources else "[]"
            
            result = session.run("""
                MERGE (a:Analytic {stix_id: $stix_id})
                ON CREATE SET 
                    a.created_ts = timestamp(),
                    a.created = $created
                SET 
                    a.type = 'x-mitre-analytic',
                    a.name = $name,
                    a.description = $description,
                    a.modified = $modified,
                    a.platforms = $platforms,
                    a.x_mitre_detects = $x_mitre_detects,
                    a.x_mitre_mutable_elements = $mutable_elements,
                    a.x_mitre_log_sources = $log_sources,
                    a.revoked = $revoked,
                    a.x_mitre_deprecated = $x_mitre_deprecated,
                    a.source_collection = $collection,
                    a.source_version = $version,
                    a.source_domain = $domain
                RETURN a
            """, 
                stix_id=stix_id,
                name=name,
                description=description,
                created=created,
                modified=modified,
                platforms=platforms_json,
                x_mitre_detects=x_mitre_detects,
                mutable_elements=mutable_elements_json,
                log_sources=log_sources_json,
                revoked=revoked,
                x_mitre_deprecated=x_mitre_deprecated,
                collection=collection,
                version=version,
                domain=domain
            )
            
            if result.single():
                count += 1
                logger.debug(f"Created/updated Analytic: {name} ({stix_id})")
        
        return count
    
    def _process_detection_strategies(
        self,
        session: Session,
        strategies: List[Dict[str, Any]],
        collection: str,
        version: str,
        domain: str
    ) -> int:
        """Process and create DetectionStrategy nodes."""
        count = 0
        for strategy in strategies:
            stix_id = strategy.get("id")
            name = strategy.get("name", "")
            description = strategy.get("description", "")
            created = strategy.get("created", datetime.utcnow().isoformat())
            modified = strategy.get("modified", datetime.utcnow().isoformat())
            
            # Extract key fields
            x_mitre_attack_spec_version = strategy.get("x_mitre_attack_spec_version", "")
            x_mitre_version = strategy.get("x_mitre_version", "")
            x_mitre_domains = strategy.get("x_mitre_domains", [])
            x_mitre_analytics = strategy.get("x_mitre_analytics", [])
            revoked = strategy.get("revoked", False)
            x_mitre_deprecated = strategy.get("x_mitre_deprecated", False)
            external_references = strategy.get("external_references", [])
            object_marking_refs = strategy.get("object_marking_refs", [])
            
            # Convert arrays to JSON for storage
            domains_json = json.dumps(x_mitre_domains) if x_mitre_domains else "[]"
            analytics_json = json.dumps(x_mitre_analytics) if x_mitre_analytics else "[]"
            ext_refs_json = json.dumps(external_references) if external_references else "[]"
            marking_refs_json = json.dumps(object_marking_refs) if object_marking_refs else "[]"
            
            # Extract DET ID from external references if present
            det_id = None
            for ref in external_references:
                if ref.get("external_id", "").startswith("DET"):
                    det_id = ref["external_id"]
                    break
            
            result = session.run("""
                MERGE (ds:DetectionStrategy {stix_id: $stix_id})
                ON CREATE SET 
                    ds.created_ts = timestamp(),
                    ds.created = $created
                SET 
                    ds.type = 'x-mitre-detection-strategy',
                    ds.name = $name,
                    ds.description = $description,
                    ds.modified = $modified,
                    ds.det_id = $det_id,
                    ds.x_mitre_attack_spec_version = $attack_spec_version,
                    ds.x_mitre_version = $x_mitre_version,
                    ds.x_mitre_domains = $domains,
                    ds.x_mitre_analytics = $analytics,
                    ds.revoked = $revoked,
                    ds.x_mitre_deprecated = $x_mitre_deprecated,
                    ds.external_references = $ext_refs,
                    ds.object_marking_refs = $marking_refs,
                    ds.source_collection = $collection,
                    ds.source_version = $version,
                    ds.source_domain = $domain
                RETURN ds
            """, 
                stix_id=stix_id,
                name=name,
                description=description,
                created=created,
                modified=modified,
                det_id=det_id,
                attack_spec_version=x_mitre_attack_spec_version,
                x_mitre_version=x_mitre_version,
                domains=domains_json,
                analytics=analytics_json,
                revoked=revoked,
                x_mitre_deprecated=x_mitre_deprecated,
                ext_refs=ext_refs_json,
                marking_refs=marking_refs_json,
                collection=collection,
                version=version,
                domain=domain
            )
            
            if result.single():
                count += 1
                logger.debug(f"Created/updated DetectionStrategy: {name} ({stix_id})")
        
        return count
    
    def _process_detection_relationships(
        self,
        session: Session,
        relationships: List[Dict[str, Any]],
        collection: str,
        version: str
    ) -> int:
        """Process and create DETECTS relationships."""
        count = 0
        for rel in relationships:
            if rel.get("relationship_type") != "detects":
                continue
            
            source_ref = rel.get("source_ref")
            target_ref = rel.get("target_ref")
            created = rel.get("created", datetime.utcnow().isoformat())
            modified = rel.get("modified", datetime.utcnow().isoformat())
            
            # Get attack_spec_version from relationship properties
            attack_spec_version = rel.get("x_mitre_attack_spec_version", "")
            
            result = session.run("""
                MATCH (ds:DetectionStrategy {stix_id: $source_ref})
                MATCH (ap:AttackPattern {stix_id: $target_ref})
                MERGE (ds)-[d:DETECTS]->(ap)
                SET 
                    d.created = $created,
                    d.modified = $modified,
                    d.attack_spec_version = $attack_spec_version,
                    d.source_collection = $collection,
                    d.source_version = $version
                RETURN d
            """,
                source_ref=source_ref,
                target_ref=target_ref,
                created=created,
                modified=modified,
                attack_spec_version=attack_spec_version,
                collection=collection,
                version=version
            )
            
            if result.single():
                count += 1
                logger.debug(f"Created DETECTS relationship: {source_ref} -> {target_ref}")
        
        return count
    
    def _build_has_analytic_relationships(
        self,
        session: Session,
        strategies: List[Dict[str, Any]]
    ) -> int:
        """Build HAS_ANALYTIC relationships from strategy analytics arrays."""
        count = 0
        for strategy in strategies:
            stix_id = strategy.get("id")
            analytics = strategy.get("x_mitre_analytics", [])
            
            for analytic_ref in analytics:
                result = session.run("""
                    MATCH (ds:DetectionStrategy {stix_id: $strategy_id})
                    MATCH (a:Analytic {stix_id: $analytic_id})
                    MERGE (ds)-[ha:HAS_ANALYTIC]->(a)
                    RETURN ha
                """,
                    strategy_id=stix_id,
                    analytic_id=analytic_ref
                )
                
                if result.single():
                    count += 1
                    logger.debug(f"Created HAS_ANALYTIC: {stix_id} -> {analytic_ref}")
        
        return count
    
    def _build_uses_log_source_relationships(
        self,
        session: Session,
        analytics: List[Dict[str, Any]]
    ) -> int:
        """Build USES_LOG_SOURCE relationships from analytic log sources arrays."""
        count = 0
        for analytic in analytics:
            stix_id = analytic.get("id")
            log_sources = analytic.get("x_mitre_log_sources", [])
            
            for log_source_entry in log_sources:
                # Each log source entry has a reference and keys
                log_source_ref = log_source_entry.get("log_source_ref")
                keys = log_source_entry.get("keys", [])
                keys_json = json.dumps(keys) if keys else "[]"
                
                if log_source_ref:
                    result = session.run("""
                        MATCH (a:Analytic {stix_id: $analytic_id})
                        MATCH (ls:LogSource {stix_id: $log_source_id})
                        MERGE (a)-[uls:USES_LOG_SOURCE]->(ls)
                        SET uls.keys = $keys
                        RETURN uls
                    """,
                        analytic_id=stix_id,
                        log_source_id=log_source_ref,
                        keys=keys_json
                    )
                    
                    if result.single():
                        count += 1
                        logger.debug(f"Created USES_LOG_SOURCE: {stix_id} -> {log_source_ref}")
        
        return count
    
    def get_detection_coverage(
        self,
        technique_id: str,
        include_revoked: bool = False,
        include_deprecated: bool = False
    ) -> Dict[str, Any]:
        """
        Get detection coverage for a specific technique.
        
        Args:
            technique_id: ATT&CK technique ID (e.g., T1003)
            include_revoked: Include revoked detection strategies
            include_deprecated: Include deprecated detection strategies
            
        Returns:
            Detection coverage information
        """
        with self.driver.session() as session:
            # Build filter conditions
            filters = []
            if not include_revoked:
                filters.append("NOT ds.revoked")
            if not include_deprecated:
                filters.append("NOT ds.x_mitre_deprecated")
            
            filter_clause = " AND ".join(filters) if filters else "TRUE"
            
            # Get detection strategies for the technique
            query = f"""
                MATCH (ap:AttackPattern)
                WHERE ap.external_id = $technique_id OR ap.external_id STARTS WITH ($technique_id + '.')
                OPTIONAL MATCH (ds:DetectionStrategy)-[:DETECTS]->(ap)
                WHERE {filter_clause}
                OPTIONAL MATCH (ds)-[:HAS_ANALYTIC]->(a:Analytic)
                OPTIONAL MATCH (a)-[:USES_LOG_SOURCE]->(ls:LogSource)
                RETURN 
                    ap.external_id as technique_id,
                    ap.name as technique_name,
                    collect(DISTINCT {{
                        strategy_id: ds.stix_id,
                        strategy_name: ds.name,
                        det_id: ds.det_id
                    }}) as strategies,
                    collect(DISTINCT {{
                        analytic_id: a.stix_id,
                        analytic_name: a.name,
                        platforms: a.platforms
                    }}) as analytics,
                    collect(DISTINCT {{
                        log_source_id: ls.stix_id,
                        log_source_name: ls.name
                    }}) as log_sources
            """
            
            result = session.run(query, technique_id=technique_id)
            record = result.single()
            
            if not record:
                return {
                    "technique_id": technique_id,
                    "technique_name": None,
                    "detection_strategies": [],
                    "analytics": [],
                    "log_sources": [],
                    "coverage_status": "no_technique"
                }
            
            # Filter out null entries from collections
            strategies = [s for s in record["strategies"] if s["strategy_id"]]
            analytics = [a for a in record["analytics"] if a["analytic_id"]]
            log_sources = [ls for ls in record["log_sources"] if ls["log_source_id"]]
            
            # Determine coverage status
            if strategies:
                coverage_status = "covered"
            else:
                coverage_status = "uncovered"
            
            return {
                "technique_id": record["technique_id"],
                "technique_name": record["technique_name"],
                "detection_strategies": strategies,
                "analytics": analytics,
                "log_sources": log_sources,
                "coverage_status": coverage_status,
                "strategy_count": len(strategies),
                "analytic_count": len(analytics),
                "log_source_count": len(log_sources)
            }
    
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()