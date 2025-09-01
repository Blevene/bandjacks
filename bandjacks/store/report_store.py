"""Report store for managing STIX Report objects and relationships."""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from neo4j import GraphDatabase, Session

logger = logging.getLogger(__name__)


class ReportStore:
    """Store for managing Report SDOs and their relationships."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """Initialize the report store."""
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    
    def close(self):
        """Close the database connection."""
        if self.driver:
            self.driver.close()
    
    def upsert_bundle(self, bundle: Dict[str, Any]) -> Dict[str, Any]:
        """
        Upsert a STIX bundle to the graph.
        
        Creates nodes for all SDOs and relationships for all SROs.
        Returns summary of created/updated entities.
        """
        with self.driver.session() as session:
            result = {
                "created": [],
                "updated": [],
                "relationships": [],
                "rejected": [],
                "warnings": []
            }
            
            # Process objects (SDOs)
            for obj in bundle.get("objects", []):
                if obj.get("type") == "relationship":
                    # Handle SRO
                    self._upsert_relationship(session, obj, result)
                else:
                    # Handle SDO
                    self._upsert_object(session, obj, result)
            
            return result
    
    def _upsert_object(self, session: Session, obj: Dict[str, Any], result: Dict[str, Any]):
        """Upsert a single STIX object."""
        try:
            obj_type = obj.get("type", "unknown")
            obj_id = obj.get("id")
            
            if not obj_id:
                result["rejected"].append({
                    "id": "unknown",
                    "reason": "Missing STIX ID"
                })
                return
            
            # Map STIX type to Neo4j label
            label_map = {
                "report": "Report",
                "campaign": "Campaign",
                "intrusion-set": "IntrusionSet",
                "attack-pattern": "AttackPattern",
                "tool": "Software",
                "malware": "Software",
                "course-of-action": "CourseOfAction",
                "identity": "Identity",
                "location": "Location",
                "infrastructure": "Infrastructure"
            }
            
            label = label_map.get(obj_type, "STIXObject")
            
            # Build properties
            props = {
                "stix_id": obj_id,
                "type": obj_type,
                "spec_version": obj.get("spec_version", "2.1"),
                "name": obj.get("name", ""),
                "created": obj.get("created", datetime.utcnow().isoformat()),
                "modified": obj.get("modified", datetime.utcnow().isoformat())
            }
            
            # Add optional properties
            if obj.get("description"):
                props["description"] = obj["description"]
            
            if obj.get("external_references"):
                for ref in obj["external_references"]:
                    if ref.get("external_id"):
                        props["external_id"] = ref["external_id"]
                        break
            
            if obj.get("first_seen"):
                props["first_seen"] = obj["first_seen"]
            if obj.get("last_seen"):
                props["last_seen"] = obj["last_seen"]
            
            if obj.get("x_bj_status"):
                props["x_bj_status"] = obj["x_bj_status"]
            
            if obj.get("x_bj_provenance"):
                props["x_bj_provenance"] = str(obj["x_bj_provenance"])
            
            # For Software, add software_type
            if obj_type in ["tool", "malware"]:
                props["software_type"] = obj_type
            
            # Upsert node
            query = f"""
                MERGE (n:{label} {{stix_id: $stix_id}})
                SET n += $props
                RETURN n.stix_id as id, 
                       n.created < $modified as was_updated
            """
            
            res = session.run(query, stix_id=obj_id, props=props, modified=props["modified"])
            record = res.single()
            
            if record:
                if record["was_updated"]:
                    result["updated"].append(obj_id)
                else:
                    result["created"].append(obj_id)
            
            # If this is a Report with object_refs, create DESCRIBES edges
            if obj_type == "report" and obj.get("object_refs"):
                self._create_describes_edges(session, obj_id, obj["object_refs"], result)
            
        except Exception as e:
            logger.error(f"Failed to upsert object {obj.get('id')}: {e}")
            result["rejected"].append({
                "id": obj.get("id", "unknown"),
                "reason": str(e)
            })
    
    def _create_describes_edges(self, session: Session, report_id: str, object_refs: List[str], result: Dict[str, Any]):
        """Create DESCRIBES edges from Report to referenced objects."""
        for ref_id in object_refs:
            try:
                query = """
                    MATCH (r:Report {stix_id: $report_id})
                    MATCH (target {stix_id: $ref_id})
                    MERGE (r)-[d:DESCRIBES]->(target)
                    SET d.created = coalesce(d.created, datetime())
                    RETURN target.stix_id as id
                """
                
                res = session.run(query, report_id=report_id, ref_id=ref_id)
                if res.single():
                    logger.debug(f"Created DESCRIBES edge: {report_id} -> {ref_id}")
                else:
                    result["warnings"].append(f"Could not create DESCRIBES edge to {ref_id} (target not found)")
            except Exception as e:
                logger.error(f"Failed to create DESCRIBES edge to {ref_id}: {e}")
                result["warnings"].append(f"Failed to create DESCRIBES edge to {ref_id}: {str(e)}")
    
    def _upsert_relationship(self, session: Session, sro: Dict[str, Any], result: Dict[str, Any]):
        """Upsert a STIX relationship."""
        try:
            rel_type = sro.get("relationship_type", "").upper().replace("-", "_")
            source_ref = sro.get("source_ref")
            target_ref = sro.get("target_ref")
            
            if not all([rel_type, source_ref, target_ref]):
                result["rejected"].append({
                    "id": sro.get("id", "unknown"),
                    "reason": "Missing relationship fields"
                })
                return
            
            # Build relationship properties
            props = {
                "stix_id": sro.get("id"),
                "created": sro.get("created", datetime.utcnow().isoformat()),
                "modified": sro.get("modified", datetime.utcnow().isoformat())
            }
            
            if sro.get("confidence"):
                props["confidence"] = sro["confidence"]
            
            # Map STIX time bounds to graph properties
            if sro.get("start_time"):
                props["first_seen"] = sro["start_time"]
            elif sro.get("first_seen"):
                props["first_seen"] = sro["first_seen"]
            
            if sro.get("stop_time"):
                props["last_seen"] = sro["stop_time"]
            elif sro.get("last_seen"):
                props["last_seen"] = sro["last_seen"]
            
            # Create relationship
            query = f"""
                MATCH (source {{stix_id: $source_ref}})
                MATCH (target {{stix_id: $target_ref}})
                MERGE (source)-[r:{rel_type}]->(target)
                SET r += $props
                RETURN r.stix_id as id
            """
            
            res = session.run(
                query,
                source_ref=source_ref,
                target_ref=target_ref,
                props=props
            )
            
            if res.single():
                result["relationships"].append(sro.get("id"))
            else:
                result["warnings"].append(
                    f"Could not create relationship: {source_ref} -> {target_ref}"
                )
            
        except Exception as e:
            logger.error(f"Failed to upsert relationship {sro.get('id')}: {e}")
            result["rejected"].append({
                "id": sro.get("id", "unknown"),
                "reason": str(e)
            })
    
    def get_report_with_relationships(self, report_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a report with all its DESCRIBES relationships.
        """
        with self.driver.session() as session:
            # Get report node
            report_query = """
                MATCH (r:Report {stix_id: $report_id})
                RETURN r
            """
            
            report_result = session.run(report_query, report_id=report_id)
            report_record = report_result.single()
            
            if not report_record:
                return None
            
            report = dict(report_record["r"])
            
            # Get DESCRIBES relationships
            describes_query = """
                MATCH (r:Report {stix_id: $report_id})-[:DESCRIBES]->(target)
                RETURN target.stix_id as id, 
                       target.type as type,
                       target.name as name,
                       target.external_id as external_id
            """
            
            describes_result = session.run(describes_query, report_id=report_id)
            
            entities = {
                "attack_patterns": [],
                "intrusion_sets": [],
                "software": [],
                "campaigns": []
            }
            
            for record in describes_result:
                entity = {
                    "id": record["id"],
                    "name": record["name"],
                    "external_id": record.get("external_id")
                }
                
                if record["type"] == "attack-pattern":
                    entities["attack_patterns"].append(entity)
                elif record["type"] == "intrusion-set":
                    entities["intrusion_sets"].append(entity)
                elif record["type"] in ["tool", "malware"]:
                    entities["software"].append(entity)
                elif record["type"] == "campaign":
                    entities["campaigns"].append(entity)
            
            # Get campaign details if exists
            campaign_query = """
                MATCH (r:Report {stix_id: $report_id})-[:DESCRIBES]->(c:Campaign)
                OPTIONAL MATCH (c)-[:ATTRIBUTED_TO]->(i:IntrusionSet)
                OPTIONAL MATCH (c)-[:USES]->(t:AttackPattern)
                OPTIONAL MATCH (c)-[:HAS_FLOW]->(f:AttackFlow)
                RETURN c.stix_id as campaign_id,
                       c.name as campaign_name,
                       c.x_bj_status as status,
                       c.first_seen as first_seen,
                       c.last_seen as last_seen,
                       collect(DISTINCT i.name) as intrusion_sets,
                       count(DISTINCT t) as technique_count,
                       f.id as flow_id
            """
            
            campaign_result = session.run(campaign_query, report_id=report_id)
            campaign_record = campaign_result.single()
            
            campaign_info = None
            if campaign_record and campaign_record["campaign_id"]:
                campaign_info = {
                    "id": campaign_record["campaign_id"],
                    "name": campaign_record["campaign_name"],
                    "status": campaign_record.get("status"),
                    "first_seen": campaign_record.get("first_seen"),
                    "last_seen": campaign_record.get("last_seen"),
                    "intrusion_sets": campaign_record["intrusion_sets"],
                    "technique_count": campaign_record["technique_count"],
                    "flow_id": campaign_record.get("flow_id")
                }
            
            # Parse provenance if stored as string
            if report.get("x_bj_provenance") and isinstance(report["x_bj_provenance"], str):
                import json
                try:
                    report["x_bj_provenance"] = json.loads(report["x_bj_provenance"])
                except:
                    pass
            
            return {
                "report": report,
                "entities": entities,
                "campaign": campaign_info
            }
    
    def get_reports_list(
        self,
        limit: int = 50,
        skip: int = 0,
        include_provisional: bool = False
    ) -> List[Dict[str, Any]]:
        """Get list of reports with summary information."""
        with self.driver.session() as session:
            where_clause = ""
            if not include_provisional:
                where_clause = "WHERE NOT EXISTS((r)-[:DESCRIBES]->(:Campaign {x_bj_status: 'provisional'}))"
            
            query = f"""
                MATCH (r:Report)
                {where_clause}
                OPTIONAL MATCH (r)-[:DESCRIBES]->(e)
                WITH r, count(DISTINCT e) as entity_count,
                     collect(DISTINCT labels(e)[0]) as entity_types
                RETURN r.stix_id as id,
                       r.name as name,
                       r.description as description,
                       r.published as published,
                       r.created as created,
                       entity_count,
                       entity_types
                ORDER BY r.created DESC
                SKIP $skip
                LIMIT $limit
            """
            
            result = session.run(query, skip=skip, limit=limit)
            
            reports = []
            for record in result:
                reports.append({
                    "id": record["id"],
                    "name": record["name"],
                    "description": record.get("description"),
                    "published": record.get("published"),
                    "created": record["created"],
                    "entity_count": record["entity_count"],
                    "entity_types": record["entity_types"]
                })
            
            return reports