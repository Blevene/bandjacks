"""Graph traversal and exploration endpoints."""

from fastapi import APIRouter, HTTPException, Depends, Query
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from bandjacks.services.api.deps import get_neo4j_session
import json


router = APIRouter(prefix="/graph", tags=["graph"])


class GraphNode(BaseModel):
    """Graph node representation."""
    stix_id: str
    type: str
    name: str
    description: Optional[str] = None
    properties: Dict[str, Any] = {}


class GraphEdge(BaseModel):
    """Graph edge representation."""
    source: str
    target: str
    type: str
    properties: Dict[str, Any] = {}


class GraphResponse(BaseModel):
    """Graph subgraph response."""
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    metadata: Dict[str, Any] = {}


class AttackFlowRequest(BaseModel):
    """Attack flow request."""
    technique_id: str = Field(..., description="STIX ID of the center technique")
    depth: int = Field(2, ge=1, le=5, description="Traversal depth")
    include_mitigations: bool = Field(True, description="Include mitigations")
    include_groups: bool = Field(True, description="Include threat groups")
    include_software: bool = Field(True, description="Include software/tools")


@router.post("/attack_flow",
    response_model=GraphResponse,
    summary="Build Attack Flow",
    description="""
    Build an attack flow subgraph centered on a technique.
    
    Returns a graph containing:
    - **Center technique** with its properties
    - **Tactics** linked via HAS_TACTIC relationships
    - **Threat groups** that use the technique (optional)
    - **Software/tools** that implement it (optional)
    - **Mitigations** that counter it (optional)
    - **Related techniques** within the specified depth
    
    The graph can be used for visualization or further analysis.
    """,
    responses={
        200: {"description": "Attack flow graph successfully built"},
        404: {"description": "Technique not found"},
        500: {"description": "Internal server error"}
    }
)
async def get_attack_flow(
    request: AttackFlowRequest,
    neo4j_session=Depends(get_neo4j_session)
) -> GraphResponse:
    nodes = []
    edges = []
    node_ids = set()
    
    # Get the center technique
    technique_query = """
        MATCH (t:AttackPattern {stix_id: $technique_id})
        OPTIONAL MATCH (t)-[:HAS_TACTIC]->(tactic:Tactic)
        RETURN t, collect(tactic) as tactics
    """
    
    result = neo4j_session.run(technique_query, technique_id=request.technique_id)
    record = result.single()
    
    if not record:
        raise HTTPException(status_code=404, detail=f"Technique {request.technique_id} not found")
    
    # Add center technique
    technique = dict(record["t"])
    nodes.append(GraphNode(
        stix_id=technique["stix_id"],
        type="attack-pattern",
        name=technique.get("name", ""),
        description=technique.get("description", ""),
        properties={
            "is_subtechnique": technique.get("x_mitre_is_subtechnique", False),
            "revoked": technique.get("revoked", False)
        }
    ))
    node_ids.add(technique["stix_id"])
    
    # Add tactics
    for tactic in record["tactics"]:
        if tactic:
            tactic_dict = dict(tactic)
            if tactic_dict["stix_id"] not in node_ids:
                nodes.append(GraphNode(
                    stix_id=tactic_dict["stix_id"],
                    type="tactic",
                    name=tactic_dict.get("name", ""),
                    description=tactic_dict.get("description", ""),
                    properties={"shortname": tactic_dict.get("shortname", "")}
                ))
                node_ids.add(tactic_dict["stix_id"])
            
            edges.append(GraphEdge(
                source=technique["stix_id"],
                target=tactic_dict["stix_id"],
                type="HAS_TACTIC",
                properties={}
            ))
    
    # Get related entities based on depth
    if request.depth >= 1:
        # Groups using this technique
        if request.include_groups:
            group_query = """
                MATCH (g:IntrusionSet)-[:USES]->(t:AttackPattern {stix_id: $technique_id})
                WHERE g.revoked = false OR g.revoked IS NULL
                RETURN g
                LIMIT 10
            """
            
            group_result = neo4j_session.run(group_query, technique_id=request.technique_id)
            
            for record in group_result:
                group = dict(record["g"])
                if group["stix_id"] not in node_ids:
                    nodes.append(GraphNode(
                        stix_id=group["stix_id"],
                        type="intrusion-set",
                        name=group.get("name", ""),
                        description=group.get("description", ""),
                        properties={"aliases": group.get("aliases", [])}
                    ))
                    node_ids.add(group["stix_id"])
                
                edges.append(GraphEdge(
                    source=group["stix_id"],
                    target=technique["stix_id"],
                    type="USES",
                    properties={}
                ))
        
        # Software using this technique
        if request.include_software:
            software_query = """
                MATCH (s:Software)-[:USES]->(t:AttackPattern {stix_id: $technique_id})
                WHERE s.revoked = false OR s.revoked IS NULL
                RETURN s
                LIMIT 10
            """
            
            software_result = neo4j_session.run(software_query, technique_id=request.technique_id)
            
            for record in software_result:
                software = dict(record["s"])
                if software["stix_id"] not in node_ids:
                    nodes.append(GraphNode(
                        stix_id=software["stix_id"],
                        type=software.get("type", "software"),
                        name=software.get("name", ""),
                        description=software.get("description", ""),
                        properties={}
                    ))
                    node_ids.add(software["stix_id"])
                
                edges.append(GraphEdge(
                    source=software["stix_id"],
                    target=technique["stix_id"],
                    type="USES",
                    properties={}
                ))
        
        # Mitigations
        if request.include_mitigations:
            mitigation_query = """
                MATCH (m:Mitigation)-[:MITIGATES]->(t:AttackPattern {stix_id: $technique_id})
                WHERE m.revoked = false OR m.revoked IS NULL
                RETURN m
                LIMIT 10
            """
            
            mitigation_result = neo4j_session.run(mitigation_query, technique_id=request.technique_id)
            
            for record in mitigation_result:
                mitigation = dict(record["m"])
                if mitigation["stix_id"] not in node_ids:
                    nodes.append(GraphNode(
                        stix_id=mitigation["stix_id"],
                        type="mitigation",
                        name=mitigation.get("name", ""),
                        description=mitigation.get("description", ""),
                        properties={}
                    ))
                    node_ids.add(mitigation["stix_id"])
                
                edges.append(GraphEdge(
                    source=mitigation["stix_id"],
                    target=technique["stix_id"],
                    type="MITIGATES",
                    properties={}
                ))
    
    # Get related techniques if depth > 1
    if request.depth > 1:
        related_query = """
            MATCH (t:AttackPattern {stix_id: $technique_id})
            OPTIONAL MATCH (t)-[:RELATED_TO]-(related:AttackPattern)
            WHERE related.revoked = false OR related.revoked IS NULL
            RETURN related
            LIMIT 5
        """
        
        related_result = neo4j_session.run(related_query, technique_id=technique_id)
        
        for record in related_result:
            if record["related"]:
                related = dict(record["related"])
                if related["stix_id"] not in node_ids:
                    nodes.append(GraphNode(
                        stix_id=related["stix_id"],
                        type="attack-pattern",
                        name=related.get("name", ""),
                        description=related.get("description", ""),
                        properties={
                            "is_subtechnique": related.get("x_mitre_is_subtechnique", False)
                        }
                    ))
                    node_ids.add(related["stix_id"])
                
                edges.append(GraphEdge(
                    source=technique["stix_id"],
                    target=related["stix_id"],
                    type="RELATED_TO",
                    properties={}
                ))
    
    return GraphResponse(
        nodes=nodes,
        edges=edges,
        metadata={
            "center_node": technique_id,
            "depth": request.depth,
            "node_count": len(nodes),
            "edge_count": len(edges)
        }
    )


@router.get("/neighbors/{node_id}")
async def get_node_neighbors(
    node_id: str,
    relationship_types: Optional[List[str]] = Query(
        None,
        description="Filter by relationship types"
    ),
    direction: str = Query(
        "both",
        regex="^(incoming|outgoing|both)$",
        description="Relationship direction"
    ),
    limit: int = Query(50, ge=1, le=200),
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """
    Get immediate neighbors of a node.
    
    Returns all nodes connected to the specified node with their relationships.
    """
    # Build relationship filter
    rel_filter = ""
    if relationship_types:
        rel_types = "|".join(relationship_types)
        rel_filter = f":{rel_types}"
    
    # Build direction-specific query
    if direction == "outgoing":
        query = f"""
            MATCH (n {{stix_id: $node_id}})-[r{rel_filter}]->(neighbor)
            WHERE neighbor.revoked = false OR neighbor.revoked IS NULL
            RETURN n, type(r) as rel_type, neighbor, 
                   properties(r) as rel_props, 'outgoing' as direction
            LIMIT $limit
        """
    elif direction == "incoming":
        query = f"""
            MATCH (n {{stix_id: $node_id}})<-[r{rel_filter}]-(neighbor)
            WHERE neighbor.revoked = false OR neighbor.revoked IS NULL
            RETURN n, type(r) as rel_type, neighbor,
                   properties(r) as rel_props, 'incoming' as direction
            LIMIT $limit
        """
    else:  # both
        query = f"""
            MATCH (n {{stix_id: $node_id}})-[r{rel_filter}]-(neighbor)
            WHERE neighbor.revoked = false OR neighbor.revoked IS NULL
            RETURN n, type(r) as rel_type, neighbor,
                   properties(r) as rel_props,
                   CASE WHEN startNode(r) = n THEN 'outgoing' ELSE 'incoming' END as direction
            LIMIT $limit
        """
    
    result = neo4j_session.run(query, node_id=node_id, limit=limit)
    
    neighbors = []
    relationships = []
    center_node = None
    
    for record in result:
        if not center_node and record["n"]:
            center_node = dict(record["n"])
        
        if record["neighbor"]:
            neighbor = dict(record["neighbor"])
            neighbors.append({
                "stix_id": neighbor.get("stix_id"),
                "type": neighbor.get("type"),
                "name": neighbor.get("name"),
                "description": neighbor.get("description", "")[:200]
            })
            
            relationships.append({
                "type": record["rel_type"],
                "direction": record["direction"],
                "target": neighbor.get("stix_id"),
                "properties": dict(record["rel_props"]) if record["rel_props"] else {}
            })
    
    if not center_node:
        raise HTTPException(status_code=404, detail=f"Node {node_id} not found")
    
    return {
        "center_node": {
            "stix_id": center_node.get("stix_id"),
            "type": center_node.get("type"),
            "name": center_node.get("name")
        },
        "neighbors": neighbors,
        "relationships": relationships,
        "neighbor_count": len(neighbors)
    }


@router.post("/path")
async def find_path(
    source_id: str,
    target_id: str,
    max_length: int = 5,
    relationship_types: Optional[List[str]] = None,
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """
    Find shortest path between two nodes.
    
    Returns the shortest path(s) between source and target nodes.
    """
    # Build relationship filter
    rel_filter = ""
    if relationship_types:
        rel_types = "|".join(relationship_types)
        rel_filter = f"[:{rel_types}*..{max_length}]"
    else:
        rel_filter = f"[*..{max_length}]"
    
    query = f"""
        MATCH path = shortestPath(
            (source {{stix_id: $source_id}})-{rel_filter}-(target {{stix_id: $target_id}})
        )
        RETURN path, length(path) as path_length
    """
    
    result = neo4j_session.run(
        query,
        source_id=source_id,
        target_id=target_id
    )
    
    paths = []
    
    for record in result:
        if record["path"]:
            path = record["path"]
            nodes = []
            edges = []
            
            # Extract nodes
            for node in path.nodes:
                node_dict = dict(node)
                nodes.append({
                    "stix_id": node_dict.get("stix_id"),
                    "type": node_dict.get("type"),
                    "name": node_dict.get("name")
                })
            
            # Extract relationships
            for rel in path.relationships:
                edges.append({
                    "type": rel.type,
                    "source": dict(rel.start_node).get("stix_id"),
                    "target": dict(rel.end_node).get("stix_id")
                })
            
            paths.append({
                "length": record["path_length"],
                "nodes": nodes,
                "edges": edges
            })
    
    if not paths:
        return {
            "source": source_id,
            "target": target_id,
            "paths": [],
            "message": "No path found within specified constraints"
        }
    
    return {
        "source": source_id,
        "target": target_id,
        "paths": paths,
        "shortest_length": min(p["length"] for p in paths)
    }


@router.post("/subgraph")
async def extract_subgraph(
    node_ids: List[str],
    include_relationships: bool = True,
    expand_depth: int = 0,
    neo4j_session=Depends(get_neo4j_session)
) -> GraphResponse:
    """
    Extract a subgraph containing specified nodes.
    
    Returns all specified nodes and optionally their relationships
    and expanded neighborhood.
    """
    nodes = []
    edges = []
    node_set = set()
    
    # Get specified nodes
    node_query = """
        MATCH (n)
        WHERE n.stix_id IN $node_ids
        RETURN n
    """
    
    result = neo4j_session.run(node_query, node_ids=node_ids)
    
    for record in result:
        node = dict(record["n"])
        nodes.append(GraphNode(
            stix_id=node["stix_id"],
            type=node.get("type", "unknown"),
            name=node.get("name", ""),
            description=node.get("description", ""),
            properties={}
        ))
        node_set.add(node["stix_id"])
    
    # Get relationships between nodes
    if include_relationships and len(node_set) > 1:
        rel_query = """
            MATCH (n1)-[r]-(n2)
            WHERE n1.stix_id IN $node_ids 
              AND n2.stix_id IN $node_ids
              AND id(n1) < id(n2)
            RETURN n1.stix_id as source, n2.stix_id as target, 
                   type(r) as rel_type, properties(r) as props
        """
        
        rel_result = neo4j_session.run(rel_query, node_ids=list(node_set))
        
        for record in rel_result:
            edges.append(GraphEdge(
                source=record["source"],
                target=record["target"],
                type=record["rel_type"],
                properties=dict(record["props"]) if record["props"] else {}
            ))
    
    # Expand if requested
    if expand_depth > 0:
        expand_query = """
            MATCH (n)-[r]-(neighbor)
            WHERE n.stix_id IN $node_ids
              AND NOT neighbor.stix_id IN $node_ids
              AND (neighbor.revoked = false OR neighbor.revoked IS NULL)
            RETURN DISTINCT neighbor, type(r) as rel_type,
                   n.stix_id as connected_to
            LIMIT 50
        """
        
        expand_result = neo4j_session.run(
            expand_query,
            node_ids=list(node_set)
        )
        
        for record in expand_result:
            neighbor = dict(record["neighbor"])
            if neighbor["stix_id"] not in node_set:
                nodes.append(GraphNode(
                    stix_id=neighbor["stix_id"],
                    type=neighbor.get("type", "unknown"),
                    name=neighbor.get("name", ""),
                    description=neighbor.get("description", ""),
                    properties={"expanded": True}
                ))
                node_set.add(neighbor["stix_id"])
                
                edges.append(GraphEdge(
                    source=record["connected_to"],
                    target=neighbor["stix_id"],
                    type=record["rel_type"],
                    properties={"expanded": True}
                ))
    
    return GraphResponse(
        nodes=nodes,
        edges=edges,
        metadata={
            "requested_nodes": len(node_ids),
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "expanded": expand_depth > 0
        }
    )