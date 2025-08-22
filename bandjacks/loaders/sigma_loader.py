"""Sigma rule loader for ingestion and management."""

import json
import logging
import os
import hashlib
import zipfile
import tempfile
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from pathlib import Path
from neo4j import GraphDatabase, Session
import httpx
from bandjacks.llm.sigma_validator import SigmaValidator

logger = logging.getLogger(__name__)


class SigmaLoader:
    """Load and manage Sigma detection rules."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str, 
                 blob_base: str = "s3://sigma-rules/"):
        """
        Initialize Sigma loader with Neo4j connection.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
            blob_base: Base path for blob storage
        """
        self.driver = GraphDatabase.driver(
            neo4j_uri,
            auth=(neo4j_user, neo4j_password)
        )
        self.blob_base = blob_base
        self.validator = SigmaValidator()
    
    def ingest_sigma_rules(
        self,
        repo_url: Optional[str] = None,
        zip_url: Optional[str] = None,
        rules: Optional[List[Dict[str, Any]]] = None,
        link_analytics: Optional[List[Dict[str, str]]] = None
    ) -> Dict[str, Any]:
        """
        Ingest Sigma rules from various sources.
        
        Args:
            repo_url: Git repository URL to clone
            zip_url: ZIP archive URL to download
            rules: List of rule dictionaries with yaml_content
            link_analytics: Optional list of {analytic_id, rule_id} mappings
            
        Returns:
            Ingestion summary with statistics
        """
        ingested_rules = []
        
        # Collect rules from source
        if repo_url:
            ingested_rules.extend(self._ingest_from_repo(repo_url))
        elif zip_url:
            ingested_rules.extend(self._ingest_from_zip(zip_url))
        elif rules:
            ingested_rules.extend(self._process_rule_list(rules))
        else:
            return {
                "success": False,
                "error": "Must provide repo_url, zip_url, or rules list",
                "inserted": 0,
                "updated": 0,
                "rejected": []
            }
        
        # Process and store rules
        with self.driver.session() as session:
            inserted = 0
            updated = 0
            rejected = []
            warnings = []
            
            for rule_entry in ingested_rules:
                yaml_content = rule_entry["yaml_content"]
                metadata = rule_entry.get("metadata", {})
                
                # Validate rule
                is_valid, rule_data, errors = self.validator.validate_rule(yaml_content, metadata)
                
                if not is_valid:
                    rejected.append({
                        "rule": metadata.get("path", "unknown"),
                        "errors": errors
                    })
                    continue
                
                # Store YAML in blob storage (simplified for now - just store path)
                blob_uri = self._store_yaml_blob(rule_data.get("rule_id", "unknown"), yaml_content)
                rule_data["blob_uri"] = blob_uri
                
                # Create or update SigmaRule node
                result = self._upsert_sigma_rule(session, rule_data)
                if result["created"]:
                    inserted += 1
                else:
                    updated += 1
                
                # Create TARGETS_LOG_SOURCE relationships
                self._create_log_source_relationships(session, rule_data)
                
                # Optionally create DETECTS relationships from ATT&CK tags
                if rule_data.get("attack_techniques"):
                    self._create_detects_relationships(session, rule_data)
            
            # Process analytic links if provided
            linked = 0
            if link_analytics:
                for link in link_analytics:
                    if self._link_to_analytic(session, link["analytic_id"], link["rule_id"], 
                                            link.get("confidence", 85)):
                        linked += 1
            
            return {
                "success": True,
                "inserted": inserted,
                "updated": updated,
                "rejected": rejected,
                "warnings": warnings,
                "linked_analytics": linked,
                "trace_id": None
            }
    
    def _ingest_from_repo(self, repo_url: str) -> List[Dict[str, Any]]:
        """
        Clone repository and extract Sigma rules.
        
        Args:
            repo_url: Git repository URL
            
        Returns:
            List of rule entries
        """
        rules = []
        
        # For now, simulate with error message
        # In production, would use GitPython or subprocess to clone
        logger.warning(f"Repository ingestion not yet implemented for {repo_url}")
        
        return rules
    
    def _ingest_from_zip(self, zip_url: str) -> List[Dict[str, Any]]:
        """
        Download ZIP archive and extract Sigma rules.
        
        Args:
            zip_url: URL to ZIP archive
            
        Returns:
            List of rule entries
        """
        rules = []
        
        try:
            # Download ZIP file
            with httpx.Client() as client:
                response = client.get(zip_url, follow_redirects=True)
                response.raise_for_status()
            
            # Extract to temp directory
            with tempfile.TemporaryDirectory() as tmpdir:
                zip_path = Path(tmpdir) / "sigma.zip"
                zip_path.write_bytes(response.content)
                
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    zf.extractall(tmpdir)
                
                # Find all .yml files
                for yaml_file in Path(tmpdir).rglob("*.yml"):
                    # Skip non-rule files
                    if any(skip in str(yaml_file) for skip in [".github", "tests", "config"]):
                        continue
                    
                    try:
                        yaml_content = yaml_file.read_text()
                        
                        # Extract metadata
                        relative_path = str(yaml_file.relative_to(tmpdir))
                        metadata = {
                            "path": relative_path,
                            "repo_url": zip_url,
                            "commit_sha": hashlib.md5(zip_url.encode()).hexdigest()[:7]  # Fake commit
                        }
                        
                        rules.append({
                            "yaml_content": yaml_content,
                            "metadata": metadata
                        })
                    except Exception as e:
                        logger.warning(f"Failed to read {yaml_file}: {e}")
        
        except Exception as e:
            logger.error(f"Failed to ingest from ZIP {zip_url}: {e}")
        
        return rules
    
    def _process_rule_list(self, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process list of rule dictionaries.
        
        Args:
            rules: List of rule dicts with yaml_content
            
        Returns:
            Normalized rule entries
        """
        processed = []
        
        for rule in rules:
            if "yaml_content" not in rule and "yaml" in rule:
                rule["yaml_content"] = rule["yaml"]
            
            if "yaml_content" in rule:
                metadata = rule.get("metadata", {})
                if not metadata.get("path"):
                    metadata["path"] = f"rule_{len(processed)}.yml"
                
                processed.append({
                    "yaml_content": rule["yaml_content"],
                    "metadata": metadata
                })
        
        return processed
    
    def _store_yaml_blob(self, rule_id: str, yaml_content: str) -> str:
        """
        Store YAML content in blob storage.
        
        Args:
            rule_id: Rule identifier
            yaml_content: YAML content to store
            
        Returns:
            Blob URI
        """
        # For now, just return a simulated URI
        # In production, would store to S3/Azure/GCS
        safe_id = rule_id.replace(":", "_").replace("/", "_")
        blob_uri = f"{self.blob_base}{safe_id}/rule.yml"
        
        # TODO: Actual blob storage implementation
        logger.debug(f"Would store rule to {blob_uri}")
        
        return blob_uri
    
    def _upsert_sigma_rule(self, session: Session, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create or update SigmaRule node.
        
        Args:
            session: Neo4j session
            rule_data: Validated rule data
            
        Returns:
            Result with created flag
        """
        # Convert lists to JSON for storage
        json_fields = ["tags", "attack_techniques", "platforms", "keys", "references", "false_positives"]
        for field in json_fields:
            if field in rule_data and isinstance(rule_data[field], list):
                rule_data[field] = json.dumps(rule_data[field])
        
        # Convert logsource dict to JSON
        if "logsource" in rule_data and isinstance(rule_data["logsource"], dict):
            rule_data["logsource_json"] = json.dumps(rule_data["logsource"])
        
        query = """
            MERGE (sr:SigmaRule {rule_id: $rule_id})
            ON CREATE SET 
                sr.created_ts = timestamp(),
                sr.first_seen = datetime()
            SET 
                sr.title = $title,
                sr.status = $status,
                sr.description = $description,
                sr.author = $author,
                sr.license = $license,
                sr.severity = $severity,
                sr.tags = $tags,
                sr.attack_techniques = $attack_techniques,
                sr.platforms = $platforms,
                sr.logsource_product = $logsource_product,
                sr.logsource_service = $logsource_service,
                sr.logsource_category = $logsource_category,
                sr.logsource_json = $logsource_json,
                sr.keys = $keys,
                sr.references = $references,
                sr.false_positives = $false_positives,
                sr.repo_url = $repo_url,
                sr.path = $path,
                sr.commit_sha = $commit_sha,
                sr.sha256_yaml = $sha256_yaml,
                sr.blob_uri = $blob_uri,
                sr.ingested_at = $ingested_at,
                sr.last_updated = datetime()
            WITH sr, sr.created_ts = timestamp() as was_created
            RETURN sr, was_created
        """
        
        # Set defaults for optional fields
        params = {
            "rule_id": rule_data.get("rule_id"),
            "title": rule_data.get("title", ""),
            "status": rule_data.get("status", "experimental"),
            "description": rule_data.get("description"),
            "author": rule_data.get("author"),
            "license": rule_data.get("license"),
            "severity": rule_data.get("severity"),
            "tags": rule_data.get("tags", "[]"),
            "attack_techniques": rule_data.get("attack_techniques", "[]"),
            "platforms": rule_data.get("platforms", "[]"),
            "logsource_product": rule_data.get("logsource_product"),
            "logsource_service": rule_data.get("logsource_service"),
            "logsource_category": rule_data.get("logsource_category"),
            "logsource_json": rule_data.get("logsource_json"),
            "keys": rule_data.get("keys", "[]"),
            "references": rule_data.get("references", "[]"),
            "false_positives": rule_data.get("false_positives", "[]"),
            "repo_url": rule_data.get("repo_url"),
            "path": rule_data.get("path"),
            "commit_sha": rule_data.get("commit_sha"),
            "sha256_yaml": rule_data.get("sha256_yaml"),
            "blob_uri": rule_data.get("blob_uri"),
            "ingested_at": rule_data.get("ingested_at")
        }
        
        result = session.run(query, **params)
        record = result.single()
        
        return {
            "created": record["was_created"] if record else False,
            "rule": dict(record["sr"]) if record else None
        }
    
    def _create_log_source_relationships(self, session: Session, rule_data: Dict[str, Any]):
        """
        Create TARGETS_LOG_SOURCE relationships.
        
        Args:
            session: Neo4j session
            rule_data: Rule data with logsource info
        """
        if not rule_data.get("logsource_product"):
            return
        
        # Try to match with existing LogSource nodes
        query = """
            MATCH (sr:SigmaRule {rule_id: $rule_id})
            MATCH (ls:LogSource)
            WHERE ls.name CONTAINS $product 
               OR ls.description CONTAINS $product
               OR $product IN ls.x_mitre_log_source_permutations
            MERGE (sr)-[tls:TARGETS_LOG_SOURCE]->(ls)
            SET tls.keys = $keys,
                tls.matched_on = 'product'
            RETURN tls
        """
        
        keys = rule_data.get("keys", "[]")
        if isinstance(keys, list):
            keys = json.dumps(keys)
        
        result = session.run(
            query,
            rule_id=rule_data["rule_id"],
            product=rule_data["logsource_product"],
            keys=keys
        )
        
        count = len(list(result))
        if count > 0:
            logger.debug(f"Created {count} TARGETS_LOG_SOURCE relationships for {rule_data['rule_id']}")
    
    def _create_detects_relationships(self, session: Session, rule_data: Dict[str, Any]):
        """
        Create DETECTS relationships from ATT&CK tags.
        
        Args:
            session: Neo4j session
            rule_data: Rule data with attack_techniques
        """
        techniques = rule_data.get("attack_techniques", [])
        if isinstance(techniques, str):
            techniques = json.loads(techniques)
        
        if not techniques:
            return
        
        for technique in techniques:
            # Clean technique ID (remove 'attack.' prefix if present)
            technique_id = technique.replace("attack.", "").upper()
            
            query = """
                MATCH (sr:SigmaRule {rule_id: $rule_id})
                MATCH (ap:AttackPattern)
                WHERE ap.external_id = $technique_id 
                   OR ap.external_id STARTS WITH ($technique_id + '.')
                MERGE (sr)-[d:DETECTS]->(ap)
                SET d.source = 'sigma_tag',
                    d.created = coalesce(d.created, datetime())
                RETURN d
            """
            
            result = session.run(
                query,
                rule_id=rule_data["rule_id"],
                technique_id=technique_id
            )
            
            if result.single():
                logger.debug(f"Created DETECTS relationship: {rule_data['rule_id']} -> {technique_id}")
    
    def link_sigma_to_analytic(
        self,
        analytic_id: str,
        rule_ids: List[str],
        confidence: int = 85
    ) -> Dict[str, Any]:
        """
        Link Sigma rules to an Analytic.
        
        Args:
            analytic_id: STIX ID of the Analytic
            rule_ids: List of Sigma rule IDs
            confidence: Confidence score (0-100)
            
        Returns:
            Linking result
        """
        with self.driver.session() as session:
            linked = 0
            failed = []
            
            for rule_id in rule_ids:
                if self._link_to_analytic(session, analytic_id, rule_id, confidence):
                    linked += 1
                    
                    # Also update Analytic's external_references
                    self._update_analytic_references(session, analytic_id, rule_id)
                else:
                    failed.append(rule_id)
            
            return {
                "success": True,
                "linked": linked,
                "failed": failed
            }
    
    def _link_to_analytic(
        self,
        session: Session,
        analytic_id: str,
        rule_id: str,
        confidence: int
    ) -> bool:
        """
        Create IMPLEMENTED_BY relationship.
        
        Args:
            session: Neo4j session
            analytic_id: Analytic STIX ID
            rule_id: Sigma rule ID
            confidence: Confidence score
            
        Returns:
            True if successful
        """
        query = """
            MATCH (a:Analytic {stix_id: $analytic_id})
            MATCH (sr:SigmaRule {rule_id: $rule_id})
            MERGE (a)-[ib:IMPLEMENTED_BY]->(sr)
            SET ib.source = 'sigma',
                ib.confidence = $confidence,
                ib.created = coalesce(ib.created, datetime()),
                ib.updated = datetime()
            RETURN ib
        """
        
        result = session.run(
            query,
            analytic_id=analytic_id,
            rule_id=rule_id,
            confidence=confidence
        )
        
        return result.single() is not None
    
    def _update_analytic_references(
        self,
        session: Session,
        analytic_id: str,
        rule_id: str
    ):
        """
        Update Analytic's external_references with Sigma URL.
        
        Args:
            session: Neo4j session
            analytic_id: Analytic STIX ID
            rule_id: Sigma rule ID
        """
        # Get Sigma rule details
        get_rule_query = """
            MATCH (sr:SigmaRule {rule_id: $rule_id})
            RETURN sr.repo_url as repo_url, sr.path as path
        """
        
        result = session.run(get_rule_query, rule_id=rule_id)
        record = result.single()
        
        if record and record["repo_url"] and record["path"]:
            # Construct URL (simplified - would need proper URL construction)
            sigma_url = f"{record['repo_url']}/blob/main/{record['path']}"
            
            # Update Analytic's external_references
            update_query = """
                MATCH (a:Analytic {stix_id: $analytic_id})
                WITH a, 
                     CASE WHEN a.external_references IS NULL 
                          THEN '[]' 
                          ELSE a.external_references 
                     END as refs_json
                WITH a, apoc.convert.fromJsonList(refs_json) as refs
                WITH a, refs + [{
                    source_name: 'sigma',
                    url: $sigma_url,
                    description: 'Sigma rule implementation'
                }] as new_refs
                SET a.external_references = apoc.convert.toJson(new_refs)
                RETURN a
            """
            
            # Note: In production, would use proper JSON manipulation
            # For now, just log that we would update
            logger.debug(f"Would add Sigma reference {sigma_url} to Analytic {analytic_id}")
    
    def unlink_sigma_from_analytic(
        self,
        analytic_id: str,
        rule_id: str
    ) -> Dict[str, Any]:
        """
        Remove link between Sigma rule and Analytic.
        
        Args:
            analytic_id: Analytic STIX ID
            rule_id: Sigma rule ID
            
        Returns:
            Unlink result
        """
        with self.driver.session() as session:
            query = """
                MATCH (a:Analytic {stix_id: $analytic_id})-[ib:IMPLEMENTED_BY]->(sr:SigmaRule {rule_id: $rule_id})
                DELETE ib
                RETURN count(ib) as deleted
            """
            
            result = session.run(query, analytic_id=analytic_id, rule_id=rule_id)
            record = result.single()
            
            deleted = record["deleted"] if record else 0
            
            return {
                "success": deleted > 0,
                "deleted": deleted
            }
    
    def get_sigma_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        Get details of a Sigma rule.
        
        Args:
            rule_id: Sigma rule ID
            
        Returns:
            Rule details or None
        """
        with self.driver.session() as session:
            query = """
                MATCH (sr:SigmaRule {rule_id: $rule_id})
                OPTIONAL MATCH (sr)-[:TARGETS_LOG_SOURCE]->(ls:LogSource)
                OPTIONAL MATCH (sr)-[:DETECTS]->(ap:AttackPattern)
                OPTIONAL MATCH (a:Analytic)-[:IMPLEMENTED_BY]->(sr)
                RETURN sr {
                    .*,
                    log_sources: collect(DISTINCT ls.name),
                    techniques: collect(DISTINCT ap.external_id),
                    analytics: collect(DISTINCT {
                        analytic_id: a.stix_id,
                        analytic_name: a.name
                    })
                } as rule
            """
            
            result = session.run(query, rule_id=rule_id)
            record = result.single()
            
            if record:
                rule = dict(record["rule"])
                
                # Parse JSON fields
                for field in ["tags", "attack_techniques", "platforms", "keys", "references", "false_positives"]:
                    if field in rule and rule[field]:
                        try:
                            rule[field] = json.loads(rule[field])
                        except:
                            pass
                
                return rule
            
            return None
    
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()