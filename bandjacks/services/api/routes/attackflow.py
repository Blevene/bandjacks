"""Attack Flow 2.0 standardization bridge endpoints."""

import json
import uuid
import hashlib
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, Field
import httpx

from bandjacks.services.api.deps import get_neo4j_session
from bandjacks.services.api.settings import settings
from bandjacks.llm.attack_flow_validator import AttackFlowValidator
from bandjacks.llm.flow_builder import FlowBuilder
from bandjacks.llm.attack_flow_simulator import AttackFlowSimulator


router = APIRouter(prefix="/attackflow", tags=["attackflow"])


# Attack Flow 2.0 schema URL
ATTACK_FLOW_SCHEMA_URL = "https://center-for-threat-informed-defense.github.io/attack-flow/stix/attack-flow-schema-2.0.0.json"


class AttackFlowIngestRequest(BaseModel):
    """Request to ingest an Attack Flow 2.0 document."""
    flow_json: Dict[str, Any] = Field(..., description="Attack Flow 2.0 JSON document")
    validate_schema: bool = Field(True, description="Validate against official schema")
    source_id: Optional[str] = Field(None, description="Optional source identifier")


class AttackFlowIngestResponse(BaseModel):
    """Response from Attack Flow ingestion."""
    flow_id: str = Field(..., description="Internal flow ID")
    status: str = Field(..., description="Ingestion status")
    normalized_nodes: int = Field(..., description="Number of nodes created")
    normalized_edges: int = Field(..., description="Number of edges created")
    warnings: List[str] = Field(default_factory=list, description="Any warnings during ingestion")
    sha256: Optional[str] = Field(None, description="SHA256 hash of the flow JSON")
    storage_uri: Optional[str] = Field(None, description="Storage location of the original flow")


class AttackFlowResponse(BaseModel):
    """Attack Flow retrieval response."""
    flow_id: str = Field(..., description="Internal flow ID")
    original_json: Dict[str, Any] = Field(..., description="Original Attack Flow JSON")
    normalized_ids: List[str] = Field(..., description="Normalized graph node IDs")
    metadata: Dict[str, Any] = Field(..., description="Flow metadata")


def validate_attack_flow_schema(flow_json: Dict[str, Any]) -> List[str]:
    """
    Validate Attack Flow JSON against official schema.
    
    Args:
        flow_json: Attack Flow JSON to validate
        
    Returns:
        List of validation errors (empty if valid)
    """
    # Use the new validator with official schema
    validator = AttackFlowValidator()
    is_valid, errors = validator.validate(flow_json)
    return errors if not is_valid else []


def normalize_to_episode_action(flow_json: Dict[str, Any], neo4j_session) -> Dict[str, Any]:
    """
    Normalize Attack Flow 2.0 to internal AttackEpisode/AttackAction format.
    
    Args:
        flow_json: Attack Flow JSON document
        neo4j_session: Neo4j session for persistence
        
    Returns:
        Normalization result with counts
    """
    flow_id = str(uuid.uuid4())
    nodes_created = 0
    edges_created = 0
    warnings = []
    
    # Extract markings for preservation
    markings_map = {}  # Map object IDs to their markings
    
    objects = flow_json.get("objects", [])
    
    # Extract markings from all objects
    for obj in objects:
        obj_id = obj.get("id")
        if obj_id:
            markings_map[obj_id] = {
                "object_marking_refs": obj.get("object_marking_refs", []),
                "created_by_ref": obj.get("created_by_ref"),
                "granular_markings": obj.get("granular_markings", [])
            }
    
    # Find the attack-flow object
    flow_obj = None
    for obj in objects:
        if obj.get("type") == "attack-flow":
            flow_obj = obj
            break
    
    if not flow_obj:
        raise ValueError("No attack-flow object found in bundle")
    
    # Create AttackEpisode node
    episode_name = flow_obj.get("name", "Unnamed Flow")
    episode_desc = flow_obj.get("description", "")
    
    # Get markings for the flow object
    flow_markings = markings_map.get(flow_obj.get("id", ""), {})
    
    # Calculate SHA256 hash of the flow JSON
    flow_json_str = json.dumps(flow_json, sort_keys=True)
    flow_sha256 = hashlib.sha256(flow_json_str.encode()).hexdigest()
    
    # Generate storage URI (in production, this would be actual blob storage)
    storage_uri = f"s3://attack-flows/{flow_id}/original.json"
    
    result = neo4j_session.run("""
        CREATE (e:AttackEpisode {
            flow_id: $flow_id,
            name: $name,
            description: $description,
            created: datetime(),
            modified: datetime(),
            source_type: 'attack-flow-2.0',
            original_id: $original_id,
            object_marking_refs: $object_marking_refs,
            created_by_ref: $created_by_ref,
            granular_markings: $granular_markings,
            sha256: $sha256,
            storage_uri: $storage_uri
        })
        RETURN e
    """, flow_id=flow_id, name=episode_name, description=episode_desc,
        original_id=flow_obj.get("id", ""),
        object_marking_refs=json.dumps(flow_markings.get("object_marking_refs", [])),
        created_by_ref=flow_markings.get("created_by_ref"),
        granular_markings=json.dumps(flow_markings.get("granular_markings", [])),
        sha256=flow_sha256,
        storage_uri=storage_uri)
    
    if result.single():
        nodes_created += 1
    
    # Process attack-action objects
    action_map = {}  # Map original IDs to our action IDs
    
    for obj in objects:
        if obj.get("type") == "attack-action":
            action_id = str(uuid.uuid4())
            technique_id = obj.get("technique_id", "")
            action_name = obj.get("name", "Unknown Action")
            action_desc = obj.get("description", "")
            confidence = obj.get("confidence", 50)
            
            # Find corresponding AttackPattern
            pattern_result = neo4j_session.run("""
                MATCH (t:AttackPattern)
                WHERE t.external_id = $technique_id OR t.stix_id CONTAINS $technique_id
                RETURN t.stix_id as pattern_id
                LIMIT 1
            """, technique_id=technique_id)
            
            pattern_record = pattern_result.single()
            pattern_ref = pattern_record["pattern_id"] if pattern_record else None
            
            if not pattern_ref:
                warnings.append(f"Technique {technique_id} not found in knowledge base")
            
            # Get markings for this action
            action_markings = markings_map.get(obj.get("id", ""), {})
            
            # Create AttackAction node
            result = neo4j_session.run("""
                CREATE (a:AttackAction {
                    action_id: $action_id,
                    name: $name,
                    description: $description,
                    technique_id: $technique_id,
                    attack_pattern_ref: $pattern_ref,
                    confidence: $confidence,
                    original_id: $original_id,
                    order: $order,
                    object_marking_refs: $object_marking_refs,
                    created_by_ref: $created_by_ref,
                    granular_markings: $granular_markings
                })
                RETURN a
            """, action_id=action_id, name=action_name, description=action_desc,
                technique_id=technique_id, pattern_ref=pattern_ref,
                confidence=confidence, original_id=obj.get("id", ""),
                order=obj.get("order", 0),
                object_marking_refs=json.dumps(action_markings.get("object_marking_refs", [])),
                created_by_ref=action_markings.get("created_by_ref"),
                granular_markings=json.dumps(action_markings.get("granular_markings", [])))
            
            if result.single():
                nodes_created += 1
                action_map[obj.get("id")] = action_id
            
            # Link to episode
            neo4j_session.run("""
                MATCH (e:AttackEpisode {flow_id: $flow_id})
                MATCH (a:AttackAction {action_id: $action_id})
                CREATE (e)-[:CONTAINS]->(a)
            """, flow_id=flow_id, action_id=action_id)
            edges_created += 1
            
            # Link to AttackPattern if found
            if pattern_ref:
                neo4j_session.run("""
                    MATCH (a:AttackAction {action_id: $action_id})
                    MATCH (t:AttackPattern {stix_id: $pattern_ref})
                    CREATE (a)-[:OF_TECHNIQUE]->(t)
                """, action_id=action_id, pattern_ref=pattern_ref)
                edges_created += 1
    
    # Process relationships (flow edges)
    for obj in objects:
        if obj.get("type") == "relationship":
            source_id = obj.get("source_ref")
            target_id = obj.get("target_ref")
            
            if source_id in action_map and target_id in action_map:
                # Create NEXT edge between actions
                neo4j_session.run("""
                    MATCH (a1:AttackAction {action_id: $source_action})
                    MATCH (a2:AttackAction {action_id: $target_action})
                    CREATE (a1)-[:NEXT {probability: $prob}]->(a2)
                """, source_action=action_map[source_id],
                    target_action=action_map[target_id],
                    prob=obj.get("confidence", 0.5))
                edges_created += 1
    
    return {
        "flow_id": flow_id,
        "nodes_created": nodes_created,
        "edges_created": edges_created,
        "warnings": warnings,
        "sha256": flow_sha256,
        "storage_uri": storage_uri
    }


@router.post("/ingest",
    response_model=AttackFlowIngestResponse,
    summary="Ingest Attack Flow 2.0",
    description="""
    Ingest an Attack Flow 2.0 JSON document.
    
    This endpoint:
    - Validates the flow against the Attack Flow 2.0 schema
    - Stores the raw JSON for preservation
    - Normalizes to internal AttackEpisode/AttackAction format
    - Creates graph nodes and relationships
    
    The flow can later be retrieved in original or normalized format.
    """,
    responses={
        200: {"description": "Flow successfully ingested"},
        400: {"description": "Invalid Attack Flow format"},
        500: {"description": "Internal server error"}
    }
)
async def ingest_attack_flow(
    request: AttackFlowIngestRequest,
    neo4j_session=Depends(get_neo4j_session)
) -> AttackFlowIngestResponse:
    """Ingest an Attack Flow 2.0 document."""
    
    try:
        # Validate schema if requested
        if request.validate_schema:
            errors = validate_attack_flow_schema(request.flow_json)
            if errors:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={"message": "Attack Flow validation failed", "errors": errors}
                )
        
        # Store raw JSON (in production, this would go to blob storage)
        # For now, store as property on the episode node
        
        # Normalize to internal format
        result = normalize_to_episode_action(request.flow_json, neo4j_session)
        
        # Store original JSON with the episode
        neo4j_session.run("""
            MATCH (e:AttackEpisode {flow_id: $flow_id})
            SET e.original_json = $json_str
        """, flow_id=result["flow_id"], 
            json_str=json.dumps(request.flow_json))
        
        return AttackFlowIngestResponse(
            flow_id=result["flow_id"],
            status="success",
            normalized_nodes=result["nodes_created"],
            normalized_edges=result["edges_created"],
            warnings=result["warnings"],
            sha256=result.get("sha256"),
            storage_uri=result.get("storage_uri")
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to ingest Attack Flow: {str(e)}"
        )


@router.get("/{flow_id}",
    response_model=AttackFlowResponse,
    summary="Get Attack Flow",
    description="""
    Retrieve an Attack Flow by ID.
    
    Returns both the original Attack Flow 2.0 JSON and the
    normalized node IDs created in the graph.
    """,
    responses={
        200: {"description": "Flow retrieved successfully"},
        404: {"description": "Flow not found"},
        500: {"description": "Internal server error"}
    }
)
async def get_attack_flow(
    flow_id: str,
    neo4j_session=Depends(get_neo4j_session)
) -> AttackFlowResponse:
    """Get an Attack Flow by ID."""
    
    try:
        # Get the episode and original JSON
        result = neo4j_session.run("""
            MATCH (e:AttackEpisode {flow_id: $flow_id})
            OPTIONAL MATCH (e)-[:CONTAINS]->(a:AttackAction)
            RETURN e.name as name,
                   e.description as description,
                   e.created as created,
                   e.original_json as original_json,
                   e.sha256 as sha256,
                   e.storage_uri as storage_uri,
                   e.object_marking_refs as object_marking_refs,
                   e.created_by_ref as created_by_ref,
                   e.granular_markings as granular_markings,
                   collect(DISTINCT a.action_id) as action_ids
        """, flow_id=flow_id)
        
        record = result.single()
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Attack Flow {flow_id} not found"
            )
        
        # Parse original JSON
        original_json = {}
        if record["original_json"]:
            try:
                original_json = json.loads(record["original_json"])
            except:
                pass
        
        # Parse markings if they exist
        markings_metadata = {}
        if record["object_marking_refs"]:
            try:
                markings_metadata["object_marking_refs"] = json.loads(record["object_marking_refs"])
            except:
                pass
        if record["created_by_ref"]:
            markings_metadata["created_by_ref"] = record["created_by_ref"]
        if record["granular_markings"]:
            try:
                markings_metadata["granular_markings"] = json.loads(record["granular_markings"])
            except:
                pass
        
        return AttackFlowResponse(
            flow_id=flow_id,
            original_json=original_json,
            normalized_ids=[flow_id] + (record["action_ids"] or []),
            metadata={
                "name": record["name"],
                "description": record["description"],
                "created": str(record["created"]) if record["created"] else None,
                "action_count": len(record["action_ids"]) if record["action_ids"] else 0,
                "sha256": record["sha256"],
                "storage_uri": record["storage_uri"],
                **markings_metadata
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve Attack Flow: {str(e)}"
        )


@router.get("/render/{flow_id}",
    summary="Render Attack Flow",
    description="""
    Get a viewer-friendly representation of an Attack Flow.
    
    Returns the flow in a format optimized for visualization tools,
    with nodes and edges formatted for graph rendering.
    """,
    responses={
        200: {"description": "Flow rendered successfully"},
        404: {"description": "Flow not found"},
        500: {"description": "Internal server error"}
    }
)
async def render_attack_flow(
    flow_id: str,
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """Render an Attack Flow for visualization."""
    
    try:
        # Get flow structure
        nodes_result = neo4j_session.run("""
            MATCH (e:AttackEpisode {flow_id: $flow_id})
            OPTIONAL MATCH (e)-[:CONTAINS]->(a:AttackAction)
            OPTIONAL MATCH (a)-[:OF_TECHNIQUE]->(t:AttackPattern)
            RETURN e, collect({
                action: a,
                technique: t
            }) as actions
        """, flow_id=flow_id)
        
        record = nodes_result.single()
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Attack Flow {flow_id} not found"
            )
        
        # Build nodes array
        nodes = []
        edges = []
        
        # Add episode as root node
        episode = dict(record["e"])
        nodes.append({
            "id": flow_id,
            "type": "episode",
            "label": episode.get("name", "Flow"),
            "properties": {
                "description": episode.get("description", "")
            }
        })
        
        # Add action nodes
        for action_data in record["actions"]:
            if action_data["action"]:
                action = dict(action_data["action"])
                technique = dict(action_data["technique"]) if action_data["technique"] else None
                
                nodes.append({
                    "id": action["action_id"],
                    "type": "action",
                    "label": action.get("name", "Action"),
                    "properties": {
                        "technique_id": action.get("technique_id", ""),
                        "technique_name": technique.get("name") if technique else "",
                        "confidence": action.get("confidence", 50),
                        "order": action.get("order", 0)
                    }
                })
        
        # Get edges between actions
        edges_result = neo4j_session.run("""
            MATCH (e:AttackEpisode {flow_id: $flow_id})
            MATCH (e)-[:CONTAINS]->(a1:AttackAction)
            MATCH (a1)-[n:NEXT]->(a2:AttackAction)
            RETURN a1.action_id as source, a2.action_id as target, n.probability as probability
        """, flow_id=flow_id)
        
        for edge in edges_result:
            edges.append({
                "source": edge["source"],
                "target": edge["target"],
                "type": "next",
                "properties": {
                    "probability": edge["probability"] or 0.5
                }
            })
        
        return {
            "flow_id": flow_id,
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "node_count": len(nodes),
                "edge_count": len(edges),
                "format": "viewer-friendly"
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to render Attack Flow: {str(e)}"
        )


class AttackFlowGenerateRequest(BaseModel):
    """Request to generate an Attack Flow."""
    techniques: List[str] = Field(..., description="List of technique IDs (e.g., ['T1003', 'T1059'])")
    name: str = Field("Generated Attack Flow", description="Name for the flow")
    description: str = Field("", description="Description of the flow")
    conditions: Optional[List[Dict[str, Any]]] = Field(None, description="Conditional branches")
    operators: Optional[List[Dict[str, Any]]] = Field(None, description="Logical operators (AND/OR)")
    assets: Optional[List[Dict[str, Any]]] = Field(None, description="Assets involved")
    sequence: Optional[List[Tuple[str, str]]] = Field(None, description="Edge sequence as (source, target) tuples")
    scope: str = Field("incident", description="Flow scope: incident, campaign, or global")


class AttackFlowGenerateResponse(BaseModel):
    """Response from Attack Flow generation."""
    flow_json: Dict[str, Any] = Field(..., description="Generated Attack Flow 2.0 JSON")
    validation_status: str = Field(..., description="Validation status")
    validation_errors: List[str] = Field(default_factory=list, description="Any validation errors")


@router.post("/generate",
    response_model=AttackFlowGenerateResponse,
    summary="Generate Attack Flow",
    description="""
    Generate a valid Attack Flow 2.0 document from techniques and conditions.
    
    This endpoint creates a complete Attack Flow bundle with:
    - Attack actions for each technique
    - Conditions for branching logic
    - Operators for AND/OR combinations
    - Assets for targeted systems
    - Relationships defining the flow sequence
    
    The generated flow is validated against the official schema.
    """,
    responses={
        200: {"description": "Flow successfully generated"},
        400: {"description": "Invalid generation parameters"},
        500: {"description": "Internal server error"}
    }
)
async def generate_attack_flow(
    request: AttackFlowGenerateRequest,
    neo4j_session=Depends(get_neo4j_session)
) -> AttackFlowGenerateResponse:
    """Generate an Attack Flow 2.0 document."""
    
    try:
        # Initialize flow builder with Neo4j for technique lookups
        flow_builder = FlowBuilder(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        # Build internal flow from techniques
        flow_data = flow_builder.build_from_techniques(
            techniques=request.techniques,
            name=request.name,
            description=request.description,
            mode="sequential"  # Use sequential mode for Attack Flow generation
        )
        
        # Export to STIX Attack Flow 2.0 format
        flow_json = flow_builder.export_to_stix_attack_flow(
            flow_data=flow_data,
            scope=request.scope,
            marking_refs=request.marking_refs if hasattr(request, 'marking_refs') else None
        )
        
        # Validate the generated flow
        validator = AttackFlowValidator()
        is_valid, errors = validator.validate(flow_json)
        
        flow_builder.close()
        
        return AttackFlowGenerateResponse(
            flow_json=flow_json,
            validation_status="valid" if is_valid else "invalid",
            validation_errors=errors
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate Attack Flow: {str(e)}"
        )
    finally:
        if 'generator' in locals():
            generator.close()


class AttackFlowSimulateRequest(BaseModel):
    """Request to simulate an Attack Flow."""
    flow_id: Optional[str] = Field(None, description="ID of stored flow to simulate")
    flow_json: Optional[Dict[str, Any]] = Field(None, description="Attack Flow JSON to simulate")
    initial_conditions: Dict[str, Any] = Field(default_factory=dict, description="Initial conditions/state")
    max_steps: int = Field(100, description="Maximum simulation steps")
    check_coverage: bool = Field(True, description="Check detection coverage during simulation")


class AttackFlowSimulateResponse(BaseModel):
    """Response from Attack Flow simulation."""
    simulation_id: str = Field(..., description="Unique simulation ID")
    flow_name: str = Field(..., description="Name of simulated flow")
    status: str = Field(..., description="Simulation status")
    summary: Dict[str, Any] = Field(..., description="Simulation summary statistics")
    execution_path: List[Dict[str, Any]] = Field(..., description="Detailed execution path")
    coverage_analysis: Optional[Dict[str, Any]] = Field(None, description="Coverage analysis results")
    visualization: Dict[str, Any] = Field(..., description="Visualization data")


@router.post("/simulate",
    response_model=AttackFlowSimulateResponse,
    summary="Simulate Attack Flow",
    description="""
    Simulate the execution of an Attack Flow.
    
    This endpoint:
    - Steps through the flow evaluating conditions
    - Tracks execution path and outcomes
    - Checks detection coverage for techniques (optional)
    - Identifies coverage gaps
    - Provides visualization data
    
    You can simulate either a stored flow (by ID) or provide the flow JSON directly.
    """,
    responses={
        200: {"description": "Simulation completed"},
        400: {"description": "Invalid simulation parameters"},
        404: {"description": "Flow not found"},
        500: {"description": "Internal server error"}
    }
)
async def simulate_attack_flow(
    request: AttackFlowSimulateRequest,
    neo4j_session=Depends(get_neo4j_session)
) -> AttackFlowSimulateResponse:
    """Simulate an Attack Flow execution."""
    
    try:
        # Get the flow to simulate
        if request.flow_id:
            # Fetch stored flow
            result = neo4j_session.run("""
                MATCH (e:AttackEpisode {flow_id: $flow_id})
                RETURN e.original_json as flow_json
            """, flow_id=request.flow_id)
            
            record = result.single()
            if not record or not record["flow_json"]:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Flow {request.flow_id} not found"
                )
            
            flow_json = json.loads(record["flow_json"])
            
        elif request.flow_json:
            flow_json = request.flow_json
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Must provide either flow_id or flow_json"
            )
        
        # Initialize simulator
        simulator = AttackFlowSimulator(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        # Run simulation
        result = simulator.simulate(
            attack_flow=flow_json,
            initial_conditions=request.initial_conditions,
            max_steps=request.max_steps,
            check_coverage=request.check_coverage
        )
        
        # Format response
        response = AttackFlowSimulateResponse(
            simulation_id=result["simulation_id"],
            flow_name=result["flow_name"],
            status=result["status"],
            summary=result["summary"],
            execution_path=result["execution_path"],
            visualization=result["visualization"]
        )
        
        if request.check_coverage and "coverage_analysis" in result:
            response.coverage_analysis = result["coverage_analysis"]
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to simulate Attack Flow: {str(e)}"
        )
    finally:
        if 'simulator' in locals():
            simulator.close()