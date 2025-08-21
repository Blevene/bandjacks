"""Convert LLM extraction results to STIX 2.1 bundles with provenance."""

import uuid
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import re


class STIXBuilder:
    """Build STIX 2.1 bundles from LLM extraction results."""
    
    def __init__(self, entity_resolver=None):
        """
        Initialize STIX builder.
        
        Args:
            entity_resolver: Optional EntityResolver instance for KB matching
        """
        self.entity_resolver = entity_resolver
        self.created_objects = {}  # Track objects created in this session
        
    def build_bundle(
        self,
        extraction_results: Dict[str, Any],
        source_metadata: Dict[str, Any],
        extraction_metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Build a STIX 2.1 bundle from extraction results.
        
        Args:
            extraction_results: Raw output from LLM extraction
            source_metadata: Info about source document (url, hash, etc)
            extraction_metadata: Info about extraction process (model, timestamp, etc)
            
        Returns:
            STIX 2.1 bundle with SDOs, SROs, and provenance
        """
        objects = []
        relationships = []
        
        # Create report object for source document
        report = self._create_report_object(source_metadata, extraction_metadata)
        objects.append(report)
        report_id = report["id"]
        
        # Process extracted claims
        claims = extraction_results.get("claims", [])
        for claim in claims:
            # Extract entities and techniques from claim
            entities, techniques = self._process_claim(claim, report_id, extraction_metadata)
            objects.extend(entities)
            objects.extend(techniques)
            
            # Create relationships
            rels = self._create_relationships(claim, entities, techniques, report_id, extraction_metadata)
            relationships.extend(rels)
        
        # Process standalone entities (IOCs, infrastructure)
        standalone_entities = self._process_entities(
            extraction_results.get("entities", {}),
            report_id,
            extraction_metadata
        )
        objects.extend(standalone_entities)
        
        # Build final bundle
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "created": datetime.utcnow().isoformat() + "Z",
            "objects": objects + relationships
        }
        
        return bundle
    
    def _create_report_object(
        self,
        source_metadata: Dict[str, Any],
        extraction_metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a STIX report object for the source document."""
        report_id = f"report--{uuid.uuid4()}"
        
        report = {
            "type": "report",
            "id": report_id,
            "spec_version": "2.1",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": source_metadata.get("title", "Extracted Threat Report"),
            "description": f"CTI extracted from {source_metadata.get('url', 'document')}",
            "published": source_metadata.get("timestamp", datetime.utcnow().isoformat() + "Z"),
            "object_refs": [],  # Will be populated with extracted objects
            "x_bj_source": source_metadata,
            "x_bj_extraction": extraction_metadata
        }
        
        return report
    
    def _process_claim(
        self,
        claim: Dict[str, Any],
        report_id: str,
        extraction_metadata: Dict[str, Any]
    ) -> Tuple[List[Dict], List[Dict]]:
        """
        Process a single claim to extract entities and techniques.
        
        Returns:
            Tuple of (entity_objects, technique_objects)
        """
        entities = []
        techniques = []
        
        # Extract actor/malware entity
        actor_name = claim.get("actor", "")
        if actor_name and actor_name.lower() not in ["unknown", "unattributed"]:
            entity = self._create_entity_object(
                actor_name,
                claim,
                report_id,
                extraction_metadata
            )
            if entity:
                entities.append(entity)
        
        # Extract techniques from mappings
        mappings = claim.get("mappings", [])
        for mapping in mappings:
            technique_id = mapping.get("external_id", "")
            if technique_id and re.match(r"T\d{4}(?:\.\d{3})?", technique_id):
                # Create enhanced claim with mapping info
                enhanced_claim = claim.copy()
                enhanced_claim["technique_name"] = mapping.get("name", "")
                enhanced_claim["stix_id"] = mapping.get("stix_id", "")
                enhanced_claim["confidence"] = mapping.get("confidence", 50)
                enhanced_claim["rationale"] = mapping.get("rationale", "")
                
                technique = self._create_technique_object(
                    technique_id,
                    enhanced_claim,
                    report_id,
                    extraction_metadata
                )
                if technique:
                    techniques.append(technique)
        
        return entities, techniques
    
    def _create_entity_object(
        self,
        entity_name: str,
        claim: Dict[str, Any],
        report_id: str,
        extraction_metadata: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Create a STIX entity object (intrusion-set, malware, tool)."""
        
        # Determine entity type based on context
        entity_type = self._determine_entity_type(entity_name, claim)
        
        # Try to resolve to existing KB entity
        stix_id = None
        if self.entity_resolver:
            stix_id = self.entity_resolver.resolve_entity(entity_name, entity_type)
        
        # Generate new ID if not found
        if not stix_id:
            stix_id = f"{entity_type}--{uuid.uuid4()}"
        
        # Check if we already created this object
        if stix_id in self.created_objects:
            # Update provenance on existing object
            obj = self.created_objects[stix_id]
            self._add_provenance(obj, claim, report_id, extraction_metadata)
            return None  # Don't duplicate
        
        # Create new object
        entity = {
            "type": entity_type,
            "id": stix_id,
            "spec_version": "2.1",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": entity_name,
            "description": claim.get("activity", ""),
            "x_bj_provenance": self._create_provenance(claim, report_id, extraction_metadata),
            "x_bj_confidence": claim.get("confidence", 50),
            "x_bj_evidence": claim.get("evidence", ""),
            "x_bj_line_refs": claim.get("lines", [])
        }
        
        self.created_objects[stix_id] = entity
        return entity
    
    def _create_technique_object(
        self,
        technique_id: str,
        claim: Dict[str, Any],
        report_id: str,
        extraction_metadata: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Create a STIX attack-pattern object for a technique."""
        
        # Use pre-resolved STIX ID from LLM mapping if available
        stix_id = claim.get("stix_id")
        
        # Fallback to entity resolver
        if not stix_id and self.entity_resolver:
            stix_id = self.entity_resolver.resolve_technique(technique_id)
        
        # Generate ID based on technique ID if still not found
        if not stix_id:
            # Standard format: attack-pattern--[uuid]
            # We'll use a deterministic UUID based on technique ID for consistency
            namespace = uuid.UUID('6ba7b810-9dad-11d1-80b4-00c04fd430c8')  # Standard namespace
            stix_id = f"attack-pattern--{uuid.uuid5(namespace, technique_id)}"
        
        # Check if already created
        if stix_id in self.created_objects:
            obj = self.created_objects[stix_id]
            self._add_provenance(obj, claim, report_id, extraction_metadata)
            return None
        
        technique = {
            "type": "attack-pattern",
            "id": stix_id,
            "spec_version": "2.1",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": claim.get("technique_name", technique_id),
            "description": claim.get("activity", ""),
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": technique_id,
                    "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
                }
            ],
            "x_bj_provenance": self._create_provenance(claim, report_id, extraction_metadata),
            "x_bj_confidence": claim.get("confidence", 50),
            "x_bj_evidence": claim.get("evidence", ""),
            "x_bj_line_refs": claim.get("lines", [])
        }
        
        self.created_objects[stix_id] = technique
        return technique
    
    def _create_relationships(
        self,
        claim: Dict[str, Any],
        entities: List[Dict],
        techniques: List[Dict],
        report_id: str,
        extraction_metadata: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Create STIX relationship objects between entities and techniques."""
        relationships = []
        
        for entity in entities:
            for technique in techniques:
                # Determine relationship type
                rel_type = "uses"  # Default for actor/malware -> technique
                
                rel_id = f"relationship--{uuid.uuid4()}"
                relationship = {
                    "type": "relationship",
                    "id": rel_id,
                    "spec_version": "2.1",
                    "created": datetime.utcnow().isoformat() + "Z",
                    "modified": datetime.utcnow().isoformat() + "Z",
                    "relationship_type": rel_type,
                    "source_ref": entity["id"],
                    "target_ref": technique["id"],
                    "description": claim.get("activity", ""),
                    "x_bj_provenance": self._create_provenance(claim, report_id, extraction_metadata),
                    "x_bj_confidence": claim.get("confidence", 50),
                    "x_bj_evidence": claim.get("evidence", ""),
                    "x_bj_line_refs": claim.get("lines", [])
                }
                
                relationships.append(relationship)
        
        return relationships
    
    def _process_entities(
        self,
        entities_dict: Dict[str, Any],
        report_id: str,
        extraction_metadata: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Process standalone entities like IOCs and infrastructure."""
        objects = []
        
        # Process vulnerabilities
        for vuln in entities_dict.get("vulnerabilities", []):
            vuln_obj = self._create_vulnerability_object(vuln, report_id, extraction_metadata)
            if vuln_obj:
                objects.append(vuln_obj)
        
        # Process infrastructure
        for infra in entities_dict.get("infrastructure", []):
            indicator = self._create_indicator_object(infra, report_id, extraction_metadata)
            if indicator:
                objects.append(indicator)
        
        # Process file hashes
        for hash_info in entities_dict.get("hashes", []):
            indicator = self._create_hash_indicator(hash_info, report_id, extraction_metadata)
            if indicator:
                objects.append(indicator)
        
        return objects
    
    def _create_vulnerability_object(
        self,
        cve: str,
        report_id: str,
        extraction_metadata: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Create a STIX vulnerability object."""
        # Generate deterministic ID for CVE
        namespace = uuid.UUID('6ba7b810-9dad-11d1-80b4-00c04fd430c8')
        vuln_id = f"vulnerability--{uuid.uuid5(namespace, cve)}"
        
        if vuln_id in self.created_objects:
            return None
        
        vuln = {
            "type": "vulnerability",
            "id": vuln_id,
            "spec_version": "2.1",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": cve,
            "external_references": [
                {
                    "source_name": "cve",
                    "external_id": cve,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve}"
                }
            ],
            "x_bj_provenance": {
                "report_id": report_id,
                "extraction": extraction_metadata
            }
        }
        
        self.created_objects[vuln_id] = vuln
        return vuln
    
    def _create_indicator_object(
        self,
        infra: Dict[str, Any],
        report_id: str,
        extraction_metadata: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Create a STIX indicator object for infrastructure."""
        value = infra.get("value", "")
        infra_type = infra.get("type", "")
        
        if not value:
            return None
        
        # Create pattern based on type
        if infra_type == "domain":
            pattern = f"[domain-name:value = '{value}']"
        elif infra_type == "ip":
            pattern = f"[ipv4-addr:value = '{value}']"
        else:
            pattern = f"[network-traffic:value = '{value}']"
        
        # Generate deterministic ID
        namespace = uuid.UUID('6ba7b810-9dad-11d1-80b4-00c04fd430c8')
        indicator_id = f"indicator--{uuid.uuid5(namespace, value)}"
        
        if indicator_id in self.created_objects:
            return None
        
        indicator = {
            "type": "indicator",
            "id": indicator_id,
            "spec_version": "2.1",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": f"{infra_type}: {value}",
            "description": infra.get("context", ""),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": datetime.utcnow().isoformat() + "Z",
            "x_bj_provenance": {
                "report_id": report_id,
                "extraction": extraction_metadata
            }
        }
        
        self.created_objects[indicator_id] = indicator
        return indicator
    
    def _create_hash_indicator(
        self,
        hash_info: Dict[str, Any],
        report_id: str,
        extraction_metadata: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Create a STIX indicator for file hashes."""
        hash_value = hash_info.get("value", "")
        hash_type = hash_info.get("type", "SHA256").lower()
        malware_name = hash_info.get("malware", "")
        
        if not hash_value:
            return None
        
        # Create STIX pattern
        pattern = f"[file:hashes.{hash_type} = '{hash_value.lower()}']"
        
        # Generate deterministic ID
        namespace = uuid.UUID('6ba7b810-9dad-11d1-80b4-00c04fd430c8')
        indicator_id = f"indicator--{uuid.uuid5(namespace, hash_value)}"
        
        if indicator_id in self.created_objects:
            return None
        
        indicator = {
            "type": "indicator",
            "id": indicator_id,
            "spec_version": "2.1",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": f"{malware_name} hash" if malware_name else f"File hash ({hash_type})",
            "description": f"{hash_type} hash for {malware_name}" if malware_name else "",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": datetime.utcnow().isoformat() + "Z",
            "x_bj_provenance": {
                "report_id": report_id,
                "extraction": extraction_metadata,
                "malware": malware_name
            }
        }
        
        self.created_objects[indicator_id] = indicator
        return indicator
    
    def _determine_entity_type(self, entity_name: str, claim: Dict[str, Any]) -> str:
        """Determine STIX type for an entity based on context."""
        name_lower = entity_name.lower()
        activity = claim.get("activity", "").lower()
        
        # Check for malware indicators
        malware_keywords = ["malware", "ransomware", "trojan", "backdoor", "rat", "dropper",
                           "loader", "crypter", "miner", "worm", "virus", "botnet"]
        if any(keyword in name_lower for keyword in malware_keywords):
            return "malware"
        
        # Check for tool indicators
        tool_keywords = ["mimikatz", "cobalt strike", "metasploit", "powershell", "psexec",
                        "bloodhound", "sharphound", "rubeus", "lazagne"]
        if any(keyword in name_lower for keyword in tool_keywords):
            return "tool"
        
        # Check for known APT patterns
        apt_patterns = [r"apt\d+", r"ta\d+", r"g\d{4}", r"unc\d+", r"dev-\d+"]
        if any(re.match(pattern, name_lower) for pattern in apt_patterns):
            return "intrusion-set"
        
        # Check activity context
        if "group" in activity or "actor" in activity or "apt" in activity:
            return "intrusion-set"
        
        # Default to intrusion-set for threat actors
        return "intrusion-set"
    
    def _create_provenance(
        self,
        claim: Dict[str, Any],
        report_id: str,
        extraction_metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create provenance metadata for an object."""
        return {
            "report_id": report_id,
            "extraction": {
                "timestamp": extraction_metadata.get("timestamp"),
                "method": extraction_metadata.get("method", "llm"),
                "model": extraction_metadata.get("model", "gemini-2.5-flash"),
                "confidence": claim.get("confidence", 50)
            },
            "evidence": {
                "text": claim.get("evidence", ""),
                "lines": claim.get("lines", []),
                "activity": claim.get("activity", "")
            }
        }
    
    def _add_provenance(
        self,
        obj: Dict[str, Any],
        claim: Dict[str, Any],
        report_id: str,
        extraction_metadata: Dict[str, Any]
    ) -> None:
        """Add additional provenance to an existing object."""
        if "x_bj_provenance_history" not in obj:
            obj["x_bj_provenance_history"] = []
        
        # Add new provenance entry
        obj["x_bj_provenance_history"].append(
            self._create_provenance(claim, report_id, extraction_metadata)
        )
        
        # Update confidence if higher
        new_confidence = claim.get("confidence", 50)
        if new_confidence > obj.get("x_bj_confidence", 0):
            obj["x_bj_confidence"] = new_confidence
            obj["x_bj_evidence"] = claim.get("evidence", "")
            obj["x_bj_line_refs"] = claim.get("lines", [])