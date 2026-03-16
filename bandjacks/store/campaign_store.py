"""Campaign store for managing Campaign SDOs and provisional campaign merging."""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from neo4j import GraphDatabase, Session

logger = logging.getLogger(__name__)


class CampaignStore:
    """Store for managing Campaign SDOs and their relationships."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """Initialize the campaign store."""
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    
    def close(self):
        """Close the database connection."""
        if self.driver:
            self.driver.close()
    
    def get_campaign(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        """Get a campaign with all its relationships."""
        with self.driver.session() as session:
            query = """
                MATCH (c:Campaign {stix_id: $campaign_id})
                OPTIONAL MATCH (c)-[:ATTRIBUTED_TO]->(i:IntrusionSet)
                OPTIONAL MATCH (c)-[:USES]->(t:AttackPattern)
                OPTIONAL MATCH (c)-[:USES]->(s:Software)
                OPTIONAL MATCH (c)-[:TARGETS]->(target)
                OPTIONAL MATCH (c)-[:HAS_FLOW]->(f:AttackFlow)
                OPTIONAL MATCH (r:Report)-[:DESCRIBES]->(c)
                RETURN c,
                       collect(DISTINCT i) as intrusion_sets,
                       collect(DISTINCT t) as techniques,
                       collect(DISTINCT s) as software,
                       collect(DISTINCT target) as targets,
                       f as flow,
                       collect(DISTINCT r.stix_id) as report_ids
            """
            
            result = session.run(query, campaign_id=campaign_id)
            record = result.single()
            
            if not record or not record["c"]:
                return None
            
            campaign = dict(record["c"])
            
            # Parse provenance if stored as string
            if campaign.get("x_bj_provenance") and isinstance(campaign["x_bj_provenance"], str):
                import json
                try:
                    campaign["x_bj_provenance"] = json.loads(campaign["x_bj_provenance"])
                except Exception:
                    pass
            
            return {
                "campaign": campaign,
                "intrusion_sets": [dict(i) for i in record["intrusion_sets"] if i],
                "techniques": [dict(t) for t in record["techniques"] if t],
                "software": [dict(s) for s in record["software"] if s],
                "targets": [dict(t) for t in record["targets"] if t],
                "flow": dict(record["flow"]) if record["flow"] else None,
                "report_ids": record["report_ids"]
            }
    
    def get_campaigns_list(
        self,
        include_provisional: bool = False,
        limit: int = 50,
        skip: int = 0
    ) -> List[Dict[str, Any]]:
        """Get list of campaigns with summary information."""
        with self.driver.session() as session:
            where_clause = ""
            if not include_provisional:
                where_clause = "WHERE c.x_bj_status IS NULL OR c.x_bj_status <> 'provisional'"
            
            query = f"""
                MATCH (c:Campaign)
                {where_clause}
                OPTIONAL MATCH (c)-[:ATTRIBUTED_TO]->(i:IntrusionSet)
                OPTIONAL MATCH (c)-[:USES]->(t:AttackPattern)
                OPTIONAL MATCH (c)-[:HAS_FLOW]->(f:AttackFlow)
                RETURN c.stix_id as id,
                       c.name as name,
                       c.description as description,
                       c.first_seen as first_seen,
                       c.last_seen as last_seen,
                       c.x_bj_status as status,
                       c.created as created,
                       collect(DISTINCT i.name) as intrusion_sets,
                       count(DISTINCT t) as technique_count,
                       f.id as flow_id
                ORDER BY c.created DESC
                SKIP $skip
                LIMIT $limit
            """
            
            result = session.run(query, skip=skip, limit=limit)
            
            campaigns = []
            for record in result:
                campaigns.append({
                    "id": record["id"],
                    "name": record["name"],
                    "description": record.get("description"),
                    "first_seen": record.get("first_seen"),
                    "last_seen": record.get("last_seen"),
                    "status": record.get("status"),
                    "created": record["created"],
                    "intrusion_sets": record["intrusion_sets"],
                    "technique_count": record["technique_count"],
                    "flow_id": record.get("flow_id")
                })
            
            return campaigns
    
    def merge_campaigns(
        self,
        from_ids: List[str],
        into_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Merge multiple campaigns into one.
        
        This migrates all relationships from source campaigns to the target,
        marks source campaigns as deprecated, and updates provisional status.
        """
        with self.driver.session() as session:
            result = {
                "merged_into": into_id,
                "from_campaigns": from_ids,
                "relationships_migrated": 0,
                "errors": []
            }
            
            try:
                # Check if target campaign exists or needs to be created
                check_query = """
                    MATCH (c:Campaign {stix_id: $campaign_id})
                    RETURN c
                """
                existing = session.run(check_query, campaign_id=into_id).single()
                
                if not existing:
                    # Create new merged campaign
                    create_query = """
                        CREATE (c:Campaign {
                            stix_id: $campaign_id,
                            type: 'campaign',
                            spec_version: '2.1',
                            name: $name,
                            description: $description,
                            created: $created,
                            modified: $modified,
                            x_bj_status: 'confirmed'
                        })
                        RETURN c
                    """
                    session.run(
                        create_query,
                        campaign_id=into_id,
                        name=name or "Merged Campaign",
                        description=description or f"Merged from {len(from_ids)} provisional campaigns",
                        created=datetime.utcnow().isoformat(),
                        modified=datetime.utcnow().isoformat()
                    )
                else:
                    # Update existing campaign to confirmed
                    update_query = """
                        MATCH (c:Campaign {stix_id: $campaign_id})
                        SET c.x_bj_status = 'confirmed',
                            c.modified = $modified
                        RETURN c
                    """
                    session.run(
                        update_query,
                        campaign_id=into_id,
                        modified=datetime.utcnow().isoformat()
                    )
                
                # Migrate relationships from each source campaign
                for from_id in from_ids:
                    # Migrate ATTRIBUTED_TO relationships
                    migrate_attributed = """
                        MATCH (from:Campaign {stix_id: $from_id})-[r:ATTRIBUTED_TO]->(target)
                        MATCH (into:Campaign {stix_id: $into_id})
                        MERGE (into)-[:ATTRIBUTED_TO {
                            confidence: r.confidence,
                            first_seen: r.first_seen,
                            last_seen: r.last_seen,
                            migrated_from: $from_id,
                            migrated_at: $timestamp
                        }]->(target)
                        RETURN count(r) as count
                    """
                    res = session.run(
                        migrate_attributed,
                        from_id=from_id,
                        into_id=into_id,
                        timestamp=datetime.utcnow().isoformat()
                    )
                    result["relationships_migrated"] += res.single()["count"]
                    
                    # Migrate USES relationships (techniques and software)
                    migrate_uses = """
                        MATCH (from:Campaign {stix_id: $from_id})-[r:USES]->(target)
                        MATCH (into:Campaign {stix_id: $into_id})
                        MERGE (into)-[:USES {
                            first_seen: r.first_seen,
                            last_seen: r.last_seen,
                            migrated_from: $from_id,
                            migrated_at: $timestamp
                        }]->(target)
                        RETURN count(r) as count
                    """
                    res = session.run(
                        migrate_uses,
                        from_id=from_id,
                        into_id=into_id,
                        timestamp=datetime.utcnow().isoformat()
                    )
                    result["relationships_migrated"] += res.single()["count"]
                    
                    # Migrate HAS_FLOW relationships
                    migrate_flows = """
                        MATCH (from:Campaign {stix_id: $from_id})-[r:HAS_FLOW]->(flow)
                        MATCH (into:Campaign {stix_id: $into_id})
                        MERGE (into)-[:HAS_FLOW {
                            version: r.version,
                            created_ts: r.created_ts,
                            migrated_from: $from_id,
                            migrated_at: $timestamp
                        }]->(flow)
                        RETURN count(r) as count
                    """
                    res = session.run(
                        migrate_flows,
                        from_id=from_id,
                        into_id=into_id,
                        timestamp=datetime.utcnow().isoformat()
                    )
                    result["relationships_migrated"] += res.single()["count"]
                    
                    # Migrate TARGETS relationships
                    migrate_targets = """
                        MATCH (from:Campaign {stix_id: $from_id})-[r:TARGETS]->(target)
                        MATCH (into:Campaign {stix_id: $into_id})
                        MERGE (into)-[:TARGETS {
                            migrated_from: $from_id,
                            migrated_at: $timestamp
                        }]->(target)
                        RETURN count(r) as count
                    """
                    res = session.run(
                        migrate_targets,
                        from_id=from_id,
                        into_id=into_id,
                        timestamp=datetime.utcnow().isoformat()
                    )
                    result["relationships_migrated"] += res.single()["count"]
                    
                    # Update DESCRIBES relationships from Reports
                    update_describes = """
                        MATCH (r:Report)-[rel:DESCRIBES]->(from:Campaign {stix_id: $from_id})
                        MATCH (into:Campaign {stix_id: $into_id})
                        MERGE (r)-[:DESCRIBES {
                            migrated_from: $from_id,
                            migrated_at: $timestamp
                        }]->(into)
                        RETURN count(rel) as count
                    """
                    res = session.run(
                        update_describes,
                        from_id=from_id,
                        into_id=into_id,
                        timestamp=datetime.utcnow().isoformat()
                    )
                    result["relationships_migrated"] += res.single()["count"]
                    
                    # Mark source campaign as deprecated
                    deprecate_query = """
                        MATCH (c:Campaign {stix_id: $from_id})
                        SET c.x_bj_status = 'deprecated',
                            c.x_bj_merged_into = $into_id,
                            c.x_bj_merged_at = $timestamp,
                            c.modified = $timestamp
                        RETURN c
                    """
                    session.run(
                        deprecate_query,
                        from_id=from_id,
                        into_id=into_id,
                        timestamp=datetime.utcnow().isoformat()
                    )
                
                # Update time bounds on merged campaign
                update_bounds_query = """
                    MATCH (c:Campaign {stix_id: $into_id})
                    OPTIONAL MATCH (c)-[r:USES|ATTRIBUTED_TO]-()
                    WITH c, collect(r.first_seen) as first_dates, collect(r.last_seen) as last_dates
                    SET c.first_seen = reduce(min = null, d in first_dates | 
                        CASE WHEN d IS NULL THEN min
                             WHEN min IS NULL THEN d
                             WHEN d < min THEN d
                             ELSE min END),
                        c.last_seen = reduce(max = null, d in last_dates |
                        CASE WHEN d IS NULL THEN max
                             WHEN max IS NULL THEN d
                             WHEN d > max THEN d
                             ELSE max END)
                    RETURN c
                """
                session.run(update_bounds_query, into_id=into_id)
                
                result["success"] = True
                
            except Exception as e:
                logger.error(f"Campaign merge failed: {e}")
                result["errors"].append(str(e))
                result["success"] = False
            
            return result
    
    def get_provisional_campaigns(self) -> List[Dict[str, Any]]:
        """Get all provisional campaigns that may need merging."""
        with self.driver.session() as session:
            query = """
                MATCH (c:Campaign {x_bj_status: 'provisional'})
                OPTIONAL MATCH (c)-[:ATTRIBUTED_TO]->(i:IntrusionSet)
                OPTIONAL MATCH (r:Report)-[:DESCRIBES]->(c)
                RETURN c.stix_id as id,
                       c.name as name,
                       c.created as created,
                       collect(DISTINCT i.name) as intrusion_sets,
                       collect(DISTINCT r.name) as reports
                ORDER BY c.created DESC
            """
            
            result = session.run(query)
            
            campaigns = []
            for record in result:
                campaigns.append({
                    "id": record["id"],
                    "name": record["name"],
                    "created": record["created"],
                    "intrusion_sets": record["intrusion_sets"],
                    "reports": record["reports"]
                })
            
            return campaigns