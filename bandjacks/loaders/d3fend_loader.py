"""D3FEND ontology loader and integration with ATT&CK framework.

Provides two ingestion modes:
- MVP/fallback: built-in subset mapping for quick bootstrap without network
- Full OWL: parse official D3FEND OWL and construct techniques/artifacts
"""

import json
import logging
import re
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from neo4j import GraphDatabase
import requests
from rdflib import Graph, Namespace, RDF, RDFS, URIRef, Literal

logger = logging.getLogger(__name__)


class D3FENDLoader:
    """Load and integrate D3FEND ontology with ATT&CK framework."""
    
    # D3FEND ontology URLs
    D3FEND_JSON_URL = "https://d3fend.mitre.org/ontologies/d3fend.json"
    D3FEND_RDF_URL = "https://d3fend.mitre.org/ontologies/d3fend.owl"
    
    # Mapping between ATT&CK Mitigations and D3FEND techniques (subset for MVP)
    ATTACK_TO_D3FEND_MAPPINGS = {
        # Network defense mappings
        "M1037": ["d3f:NetworkTrafficFiltering", "d3f:NetworkSegmentation"],  # Filter Network Traffic
        "M1031": ["d3f:NetworkIntrusionPrevention"],  # Network Intrusion Prevention
        "M1030": ["d3f:NetworkSegmentation"],  # Network Segmentation
        
        # Endpoint defense mappings
        "M1038": ["d3f:ExecutionPrevention", "d3f:ProcessTermination"],  # Execution Prevention
        "M1040": ["d3f:BehaviorPrevention", "d3f:ProcessAnalysis"],  # Behavior Prevention on Endpoint
        "M1045": ["d3f:CodeSigning", "d3f:ExecutableAllowlisting"],  # Code Signing
        
        # Authentication & Access
        "M1032": ["d3f:MultiFactorAuthentication"],  # Multi-factor Authentication
        "M1036": ["d3f:AccountLocking", "d3f:UserAccountPermissions"],  # Account Use Policies
        "M1026": ["d3f:PrivilegedAccountManagement"],  # Privileged Account Management
        
        # Data Protection
        "M1041": ["d3f:DiskEncryption", "d3f:FileEncryption"],  # Encrypt Sensitive Information
        "M1047": ["d3f:SystemAuditing", "d3f:LogAnalysis"],  # Audit
        "M1029": ["d3f:RemoteDataStorage", "d3f:DataBackup"],  # Remote Data Storage
    }
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """
        Initialize D3FEND loader.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
        """
        self.driver = GraphDatabase.driver(
            neo4j_uri,
            auth=(neo4j_user, neo4j_password)
        )
    
    def load_d3fend_ontology(self, prefer_owl: bool = True) -> Dict[str, Any]:
        """
        Load D3FEND ontology. Attempt full OWL parse; fall back to MVP subset.

        Returns a dict keyed by compact technique IDs (e.g., d3f:NetworkSegmentation)
        with fields: name, description, category, artifacts (list[str]).
        """
        # First try to parse the official OWL if requested
        if prefer_owl:
            try:
                logger.info("Fetching D3FEND OWL ontology...")
                g = Graph()
                g.parse(self.D3FEND_RDF_URL, format="xml")  # Explicitly use XML format

                # Define namespaces
                D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")
                SKOS = Namespace("http://www.w3.org/2004/02/skos/core#")
                OWL = Namespace("http://www.w3.org/2002/07/owl#")

                techniques: Dict[str, Any] = {}

                # Find the DefensiveTechnique base class
                defensive_technique_class = D3F.DefensiveTechnique
                
                # Helper function to get all subclasses recursively
                def get_all_subclasses(parent, visited=None):
                    if visited is None:
                        visited = set()
                    if parent in visited:
                        return set()
                    visited.add(parent)
                    
                    subclasses = set()
                    for s in g.subjects(RDFS.subClassOf, parent):
                        if isinstance(s, URIRef) and str(s).startswith("http://d3fend.mitre.org"):
                            subclasses.add(s)
                            # Recursively get subclasses
                            subclasses.update(get_all_subclasses(s, visited))
                    return subclasses
                
                # Get all defensive technique subclasses
                all_technique_classes = get_all_subclasses(defensive_technique_class)
                all_technique_classes.add(defensive_technique_class)  # Include the base class
                
                # Also find techniques by other patterns
                # Look for classes with d3fend-kb-article (indicates documented techniques)
                for s, p, o in g.triples((None, D3F['d3fend-kb-article'], None)):
                    if isinstance(s, URIRef) and str(s).startswith("http://d3fend.mitre.org"):
                        all_technique_classes.add(s)
                
                # Process each technique class
                for tech_class in all_technique_classes:
                    # Skip if it's not actually a class
                    if not any(g.triples((tech_class, RDF.type, OWL.Class))):
                        continue
                    
                    # Build compact ID: d3f:LocalName
                    local_name = str(tech_class).split('#')[-1]
                    
                    # Skip certain non-technique classes
                    if local_name in ['DefensiveTechnique', 'Thing', 'NamedIndividual']:
                        continue
                    
                    compact_id = f"d3f:{local_name}"

                    # Extract name/label
                    name_val = None
                    for p in [RDFS.label, D3F['d3fend-label'], SKOS.prefLabel]:
                        labels = list(g.objects(tech_class, p))
                        if labels:
                            name_val = str(labels[0])
                            break
                    if not name_val:
                        # Convert CamelCase to readable name
                        name_val = re.sub(r'([A-Z])', r' \1', local_name).strip()

                    # Extract description/definition
                    desc_val = None
                    for p in [D3F['definition'], D3F['d3fend-kb-article'], SKOS.definition]:
                        defs = list(g.objects(tech_class, p))
                        if defs:
                            desc_val = str(defs[0])
                            # Truncate very long descriptions but keep meaningful content
                            if len(desc_val) > 500:
                                desc_val = desc_val[:497] + "..."
                            break
                    if not desc_val:
                        desc_val = f"Defensive technique: {name_val}"

                    # Get parent category
                    category = None
                    for parent in g.objects(tech_class, RDFS.subClassOf):
                        if isinstance(parent, URIRef) and str(parent).startswith("http://d3fend.mitre.org"):
                            parent_name = str(parent).split('#')[-1]
                            # Skip the base DefensiveTechnique class
                            if parent_name != 'DefensiveTechnique':
                                category = parent_name
                                # Make category name more readable
                                category = re.sub(r'([A-Z])', r' \1', category).strip()
                                break
                    
                    if not category:
                        # Try to infer category from technique name
                        if 'Network' in local_name or 'Traffic' in local_name:
                            category = "Network Defense"
                        elif 'File' in local_name or 'Process' in local_name or 'Memory' in local_name:
                            category = "Endpoint Defense"
                        elif 'Authentic' in local_name or 'Credential' in local_name:
                            category = "Identity Defense"
                        elif 'Encrypt' in local_name or 'Backup' in local_name:
                            category = "Data Defense"
                        else:
                            category = "General Defense"

                    # Extract artifacts or related objects
                    artifacts: List[str] = []
                    
                    # Look for what this technique produces, analyzes, or affects
                    artifact_predicates = [
                        D3F['produces'], D3F['analyzes'], D3F['filters'],
                        D3F['monitors'], D3F['validates'], D3F['blocks'],
                        D3F['encrypts'], D3F['authenticates']
                    ]
                    
                    for pred in artifact_predicates:
                        for obj in g.objects(tech_class, pred):
                            if isinstance(obj, URIRef):
                                artifact_name = str(obj).split('#')[-1]
                                # Make artifact name readable
                                artifact_name = re.sub(r'([A-Z])', r' \1', artifact_name).strip()
                                if artifact_name not in artifacts:
                                    artifacts.append(artifact_name)
                    
                    # If no artifacts found, create generic ones based on technique type
                    if not artifacts:
                        if 'Log' in local_name or 'Audit' in local_name:
                            artifacts = ["Audit Logs", "Event Records"]
                        elif 'Filter' in local_name:
                            artifacts = ["Filter Rules", "Access Control Lists"]
                        elif 'Encrypt' in local_name:
                            artifacts = ["Encryption Keys", "Encrypted Data"]
                        elif 'Authentic' in local_name:
                            artifacts = ["Authentication Tokens", "Credentials"]
                        elif 'Monitor' in local_name:
                            artifacts = ["Monitoring Data", "Alerts"]

                    techniques[compact_id] = {
                        "name": name_val,
                        "description": desc_val,
                        "category": category,
                        "artifacts": artifacts[:5],  # Limit to 5 artifacts
                    }

                if techniques:
                    logger.info(f"Parsed {len(techniques)} D3FEND techniques from OWL")
                    return techniques
                else:
                    logger.warning("OWL parsed but found no techniques; falling back to MVP subset")
            except Exception as e:
                logger.warning(f"Failed to parse D3FEND OWL ({e}); falling back to MVP subset")

        # Fallback MVP subset (static)
        try:
            logger.info("Loading D3FEND MVP subset techniques...")
            d3fend_techniques = {
                "d3f:NetworkTrafficFiltering": {
                    "name": "Network Traffic Filtering",
                    "description": "Filtering network traffic based on defined criteria",
                    "category": "Network Defense",
                    "artifacts": ["Firewall Rules", "IDS Signatures"]
                },
                "d3f:NetworkSegmentation": {
                    "name": "Network Segmentation", 
                    "description": "Dividing network into isolated segments",
                    "category": "Network Defense",
                    "artifacts": ["VLAN Configuration", "Network ACLs"]
                },
                "d3f:NetworkIntrusionPrevention": {
                    "name": "Network Intrusion Prevention",
                    "description": "Detecting and preventing network intrusions",
                    "category": "Network Defense",
                    "artifacts": ["IPS Rules", "Network Sensors"]
                },
                "d3f:ExecutionPrevention": {
                    "name": "Execution Prevention",
                    "description": "Preventing execution of unauthorized code",
                    "category": "Endpoint Defense",
                    "artifacts": ["Application Control Policy", "Code Signing Certificates"]
                },
                "d3f:ProcessTermination": {
                    "name": "Process Termination",
                    "description": "Terminating malicious processes",
                    "category": "Endpoint Defense",
                    "artifacts": ["EDR Policy", "Process Blocklist"]
                },
                "d3f:BehaviorPrevention": {
                    "name": "Behavior Prevention",
                    "description": "Preventing malicious behaviors",
                    "category": "Endpoint Defense",
                    "artifacts": ["HIPS Rules", "Behavioral Indicators"]
                },
                "d3f:ProcessAnalysis": {
                    "name": "Process Analysis",
                    "description": "Analyzing process behavior for threats",
                    "category": "Endpoint Defense",
                    "artifacts": ["Process Logs", "Memory Dumps"]
                },
                "d3f:CodeSigning": {
                    "name": "Code Signing",
                    "description": "Verifying code authenticity via signatures",
                    "category": "Application Defense",
                    "artifacts": ["Signing Certificates", "Certificate Store"]
                },
                "d3f:ExecutableAllowlisting": {
                    "name": "Executable Allowlisting",
                    "description": "Allowing only approved executables",
                    "category": "Application Defense",
                    "artifacts": ["Allowlist Policy", "Hash Database"]
                },
                "d3f:MultiFactorAuthentication": {
                    "name": "Multi-factor Authentication",
                    "description": "Requiring multiple authentication factors",
                    "category": "Identity Defense",
                    "artifacts": ["MFA Policy", "Authentication Logs"]
                },
                "d3f:AccountLocking": {
                    "name": "Account Locking",
                    "description": "Locking accounts after failed attempts",
                    "category": "Identity Defense",
                    "artifacts": ["Account Policy", "Lockout Events"]
                },
                "d3f:UserAccountPermissions": {
                    "name": "User Account Permissions",
                    "description": "Managing user account permissions",
                    "category": "Identity Defense",
                    "artifacts": ["Permission Matrix", "RBAC Policy"]
                },
                "d3f:PrivilegedAccountManagement": {
                    "name": "Privileged Account Management",
                    "description": "Managing privileged accounts securely",
                    "category": "Identity Defense",
                    "artifacts": ["PAM Solution", "Privilege Logs"]
                },
                "d3f:DiskEncryption": {
                    "name": "Disk Encryption",
                    "description": "Encrypting data at rest on disk",
                    "category": "Data Defense",
                    "artifacts": ["Encryption Keys", "BitLocker Policy"]
                },
                "d3f:FileEncryption": {
                    "name": "File Encryption",
                    "description": "Encrypting individual files",
                    "category": "Data Defense",
                    "artifacts": ["Encryption Policy", "Key Management"]
                },
                "d3f:SystemAuditing": {
                    "name": "System Auditing",
                    "description": "Auditing system activities",
                    "category": "Detection",
                    "artifacts": ["Audit Policy", "Event Logs"]
                },
                "d3f:LogAnalysis": {
                    "name": "Log Analysis",
                    "description": "Analyzing logs for threats",
                    "category": "Detection",
                    "artifacts": ["SIEM Rules", "Log Aggregation"]
                },
                "d3f:RemoteDataStorage": {
                    "name": "Remote Data Storage",
                    "description": "Storing data in remote locations",
                    "category": "Data Defense",
                    "artifacts": ["Backup Policy", "Cloud Storage"]
                },
                "d3f:DataBackup": {
                    "name": "Data Backup",
                    "description": "Creating data backups",
                    "category": "Data Defense",
                    "artifacts": ["Backup Schedule", "Recovery Plan"]
                }
            }
            
            logger.info(f"Loaded {len(d3fend_techniques)} D3FEND techniques (MVP subset)")
            return d3fend_techniques
            
        except Exception as e:
            logger.error(f"Failed to load D3FEND ontology: {e}")
            raise
    
    def create_d3fend_nodes(self, d3fend_data: Dict[str, Any]) -> int:
        """
        Create D3FEND technique nodes in Neo4j.
        
        Args:
            d3fend_data: D3FEND ontology data
            
        Returns:
            Number of nodes created
        """
        with self.driver.session() as session:
            created_count = 0
            
            for technique_id, technique_data in d3fend_data.items():
                result = session.run(
                    """
                    MERGE (d:D3fendTechnique {d3fend_id: $technique_id})
                    SET d.name = $name,
                        d.description = $description,
                        d.category = $category,
                        d.created = datetime(),
                        d.modified = datetime()
                    RETURN d.d3fend_id as id
                    """,
                    technique_id=technique_id,
                    name=technique_data["name"],
                    description=technique_data["description"],
                    category=technique_data["category"]
                )
                
                if result.single():
                    created_count += 1
                    
                    # Create digital artifact nodes
                    for artifact_name in technique_data.get("artifacts", []):
                        session.run(
                            """
                            MERGE (a:DigitalArtifact {name: $artifact_name})
                            SET a.created = COALESCE(a.created, datetime()),
                                a.modified = datetime()
                            WITH a
                            MATCH (d:D3fendTechnique {d3fend_id: $technique_id})
                            MERGE (d)-[:PRODUCES]->(a)
                            """,
                            artifact_name=artifact_name,
                            technique_id=technique_id
                        )
            
            logger.info(f"Created {created_count} D3FEND technique nodes")
            return created_count
    
    def create_counters_relationships(self) -> int:
        """
        Create COUNTERS relationships between D3FEND techniques and ATT&CK techniques.
        
        Returns:
            Number of relationships created
        """
        with self.driver.session() as session:
            relationships_created = 0
            
            # First, map Mitigations to D3FEND techniques
            for mitigation_id, d3fend_ids in self.ATTACK_TO_D3FEND_MAPPINGS.items():
                for d3fend_id in d3fend_ids:
                    # Create relationship from D3FEND to Mitigation
                    result = session.run(
                        """
                        MATCH (m:Mitigation)
                        WHERE m.external_id = $mitigation_id OR m.stix_id CONTAINS $mitigation_id
                        MATCH (d:D3fendTechnique {d3fend_id: $d3fend_id})
                        MERGE (d)-[:IMPLEMENTS]->(m)
                        RETURN count(*) as created
                        """,
                        mitigation_id=mitigation_id,
                        d3fend_id=d3fend_id
                    )
                    
                    result_single = result.single()
                    if result_single and result_single.get("created", 0) > 0:
                        relationships_created += 1
            
            # Now create COUNTERS relationships from D3FEND to AttackPatterns
            # via the Mitigation relationships
            result = session.run(
                """
                MATCH (d:D3fendTechnique)-[:IMPLEMENTS]->(m:Mitigation)
                MATCH (m)-[:MITIGATES]->(t:AttackPattern)
                MERGE (d)-[c:COUNTERS]->(t)
                SET c.confidence = COALESCE(c.confidence, 0.8),
                    c.created = COALESCE(c.created, datetime()),
                    c.via_mitigation = m.stix_id
                RETURN count(c) as counters_created
                """
            )
            
            result_single = result.single()
            counters_count = result_single["counters_created"] if result_single else 0
            logger.info(f"Created {counters_count} COUNTERS relationships")
            
            return relationships_created + counters_count
    
    def get_defense_techniques_for_attack(
        self, 
        attack_pattern_id: str
    ) -> List[Dict[str, Any]]:
        """
        Get D3FEND techniques that counter a specific attack pattern.
        
        Args:
            attack_pattern_id: ATT&CK pattern STIX ID
            
        Returns:
            List of D3FEND techniques with metadata
        """
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (t:AttackPattern {stix_id: $attack_id})
                OPTIONAL MATCH (d:D3fendTechnique)-[c:COUNTERS]->(t)
                OPTIONAL MATCH (d)-[:PRODUCES]->(a:DigitalArtifact)
                RETURN d.d3fend_id as technique_id,
                       d.name as technique_name,
                       d.description as description,
                       d.category as category,
                       c.confidence as confidence,
                       c.via_mitigation as via_mitigation,
                       collect(DISTINCT a.name) as artifacts
                ORDER BY c.confidence DESC
                """,
                attack_id=attack_pattern_id
            )
            
            defenses = []
            for record in result:
                if record["technique_id"]:
                    defenses.append({
                        "technique_id": record["technique_id"],
                        "name": record["technique_name"],
                        "description": record["description"],
                        "category": record["category"],
                        "confidence": record["confidence"] or 0.8,
                        "via_mitigation": record["via_mitigation"],
                        "artifacts": record["artifacts"] or []
                    })
            
            return defenses
    
    def compute_minimal_defense_set(
        self,
        flow_id: str,
        budget: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Compute minimal set of D3FEND techniques to defend against a flow.
        Uses greedy algorithm to maximize coverage with minimum techniques.
        
        Args:
            flow_id: Attack flow ID
            budget: Optional maximum number of techniques to recommend
            
        Returns:
            Recommended defense set with coverage metrics
        """
        with self.driver.session() as session:
            # Get all attack patterns in the flow
            flow_techniques = session.run(
                """
                MATCH (e:AttackEpisode {flow_id: $flow_id})-[:CONTAINS]->(a:AttackAction)
                RETURN DISTINCT a.attack_pattern_ref as technique_id
                """,
                flow_id=flow_id
            ).data()
            
            if not flow_techniques:
                return {
                    "flow_id": flow_id,
                    "error": "Flow not found or has no techniques",
                    "recommendations": []
                }
            
            technique_ids = [t["technique_id"] for t in flow_techniques]
            
            # Get all possible D3FEND counters for these techniques
            counters_query = """
                MATCH (t:AttackPattern)
                WHERE t.stix_id IN $technique_ids
                OPTIONAL MATCH (d:D3fendTechnique)-[c:COUNTERS]->(t)
                RETURN t.stix_id as attack_id,
                       t.name as attack_name,
                       collect({
                           technique_id: d.d3fend_id,
                           name: d.name,
                           category: d.category,
                           confidence: c.confidence
                       }) as counters
            """
            
            counters_data = session.run(
                counters_query,
                technique_ids=technique_ids
            ).data()
            
            # Greedy algorithm: select D3FEND techniques that cover most attacks
            selected_defenses = []
            covered_attacks = set()
            defense_coverage = {}
            
            # Build coverage map
            for attack_data in counters_data:
                attack_id = attack_data["attack_id"]
                for counter in attack_data["counters"]:
                    if counter["technique_id"]:
                        if counter["technique_id"] not in defense_coverage:
                            defense_coverage[counter["technique_id"]] = {
                                "info": counter,
                                "covers": set()
                            }
                        defense_coverage[counter["technique_id"]]["covers"].add(attack_id)
            
            # Greedy selection
            remaining_attacks = set(technique_ids)
            
            while remaining_attacks and (budget is None or len(selected_defenses) < budget):
                # Find defense that covers most remaining attacks
                best_defense = None
                best_coverage = 0
                
                for defense_id, defense_data in defense_coverage.items():
                    if defense_id not in [d["technique_id"] for d in selected_defenses]:
                        coverage = len(defense_data["covers"].intersection(remaining_attacks))
                        if coverage > best_coverage:
                            best_coverage = coverage
                            best_defense = defense_id
                
                if best_defense is None:
                    break
                
                # Add best defense to selection
                defense_info = defense_coverage[best_defense]["info"]
                covered = defense_coverage[best_defense]["covers"].intersection(remaining_attacks)
                
                selected_defenses.append({
                    "technique_id": best_defense,
                    "name": defense_info["name"],
                    "category": defense_info["category"],
                    "confidence": defense_info["confidence"] or 0.8,
                    "covers_count": len(covered),
                    "covers": list(covered)
                })
                
                covered_attacks.update(covered)
                remaining_attacks.difference_update(covered)
            
            # Calculate metrics
            total_attacks = len(technique_ids)
            covered_count = len(covered_attacks)
            coverage_percentage = (covered_count / total_attacks * 100) if total_attacks > 0 else 0
            
            return {
                "flow_id": flow_id,
                "total_attack_techniques": total_attacks,
                "covered_techniques": covered_count,
                "coverage_percentage": round(coverage_percentage, 2),
                "uncovered_techniques": list(remaining_attacks),
                "recommendations": selected_defenses,
                "defense_count": len(selected_defenses),
                "expected_impact": {
                    "high": covered_count >= total_attacks * 0.8,
                    "narrative": f"Recommended {len(selected_defenses)} defensive techniques "
                               f"covering {coverage_percentage:.1f}% of attack surface"
                }
            }
    
    def initialize(self) -> Dict[str, Any]:
        """
        Initialize D3FEND integration - load ontology and create relationships.
        
        Returns:
            Summary of initialization
        """
        try:
            # Load D3FEND ontology
            d3fend_data = self.load_d3fend_ontology()
            
            # Create D3FEND nodes
            nodes_created = self.create_d3fend_nodes(d3fend_data)
            
            # Create COUNTERS relationships
            relationships_created = self.create_counters_relationships()
            
            return {
                "success": True,
                "d3fend_techniques": len(d3fend_data),
                "nodes_created": nodes_created,
                "relationships_created": relationships_created,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"D3FEND initialization failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()