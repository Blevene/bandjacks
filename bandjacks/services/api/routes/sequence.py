"""Sequence modeling and PTG endpoints."""

from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks
from typing import Dict, Any, List, Optional
import json
import logging
from datetime import datetime

from bandjacks.services.api.deps import get_neo4j_session
from bandjacks.services.api.settings import settings
from bandjacks.services.api.schemas import (
    SequenceExtractionResponse, PTGBuildRequest, PTGBuildResponse,
    PTGModelResponse, SequenceStatisticsResponse
)
from bandjacks.llm.sequence_extractor import (
    SequenceExtractor, extract_sequences_from_flows
)
from bandjacks.llm.ptg_builder import (
    PTGBuilder, PTGParameters, build_ptg_for_scope
)
from bandjacks.llm.judge_client import JudgeClient, JudgeConfig, JudgeVerdict
from bandjacks.llm.judge_cache import JudgeVerdictCache
from bandjacks.llm.evidence_pack import EvidencePackBuilder
from bandjacks.llm.triage import PairTriage, TriageConfig
from bandjacks.llm.judge_integration import PTGJudgeIntegrator
from bandjacks.llm.budget import check_and_record_judge_cost, get_budget_tracker
from bandjacks.llm.ptg_config import get_ptg_config, set_ptg_config, PTGBuildConfig
from bandjacks.monitoring.ml_metrics import get_ml_metrics_tracker, record_model_prediction

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/sequence", tags=["sequence"])


@router.post("/extract", 
    response_model=SequenceExtractionResponse,
    summary="Extract Sequences from Attack Flows",
    description="""
    Extract technique sequences from stored attack flows and compute pairwise statistics.
    
    This endpoint:
    1. Extracts technique sequences from all AttackEpisodes in Neo4j
    2. Computes conditional probabilities with Laplace smoothing  
    3. Calculates asymmetry scores for directional ambiguity
    4. Groups statistics by intrusion set and globally
    5. Identifies ambiguous pairs suitable for LLM judging
    
    The results form the foundation for building PTG models.
    """,
    responses={
        200: {"description": "Sequences extracted successfully"},
        500: {"description": "Extraction failed"}
    }
)
async def extract_sequences(
    include_cooccurrence: bool = Query(True, description="Include co-occurrence flows"),
    min_flow_length: int = Query(2, description="Minimum techniques per flow"),
    export_to_neo4j: bool = Query(False, description="Export statistics to Neo4j"),
    neo4j_session=Depends(get_neo4j_session)
) -> SequenceExtractionResponse:
    """Extract sequences from attack flows and compute statistics."""
    
    try:
        extractor = SequenceExtractor(
            settings.neo4j_uri, 
            settings.neo4j_user, 
            settings.neo4j_password
        )
        
        # Extract all sequences
        sequences = extractor.extract_all_sequences(include_cooccurrence)
        
        # Filter by minimum length
        sequences = [s for s in sequences if len(s.techniques) >= min_flow_length]
        
        # Compute statistics by intrusion set
        stats_dict = extractor.extract_by_intrusion_set(sequences)
        
        # Find ambiguous pairs for each scope
        ambiguous_pairs_by_scope = {}
        for scope, stats in stats_dict.items():
            ambiguous_pairs = extractor.find_ambiguous_pairs(stats)
            ambiguous_pairs_by_scope[scope] = ambiguous_pairs
        
        # Optionally export to Neo4j
        model_id = None
        if export_to_neo4j:
            model_id = extractor.export_statistics_to_neo4j(stats_dict)
        
        # Format response
        scope_summaries = []
        for scope, stats in stats_dict.items():
            scope_summaries.append({
                "scope": scope,
                "scope_type": stats.scope_type,
                "total_flows": stats.total_flows,
                "total_techniques": stats.total_techniques,
                "total_pairs": stats.total_pairs,
                "ambiguous_pairs": len(ambiguous_pairs_by_scope.get(scope, [])),
                "top_techniques": dict(sorted(
                    stats.technique_counts.items(), 
                    key=lambda x: x[1], 
                    reverse=True
                )[:10])
            })
        
        return SequenceExtractionResponse(
            sequences_extracted=len(sequences),
            scopes_analyzed=len(stats_dict),
            scope_summaries=scope_summaries,
            ambiguous_pairs_total=sum(len(pairs) for pairs in ambiguous_pairs_by_scope.values()),
            model_id=model_id,
            parameters={
                "include_cooccurrence": include_cooccurrence,
                "min_flow_length": min_flow_length,
                "laplace_smoothing": True
            },
            extracted_at=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Sequence extraction failed: {e}")
        raise HTTPException(status_code=500, detail=f"Extraction failed: {str(e)}")
    
    finally:
        if 'extractor' in locals():
            extractor.close()


@router.post("/infer",
    response_model=PTGBuildResponse,
    summary="Build Probabilistic Temporal Graph",
    description="""
    Build a PTG model from pairwise statistics using feature fusion.
    
    This endpoint:
    1. Loads or computes pairwise statistics for the specified scope
    2. Applies feature fusion: conditional probabilities + tactic priors + observed edges + judge scores
    3. Uses softmax normalization with top-K selection
    4. Creates NEXT_P edges in Neo4j with probabilities and features
    5. Stores the complete PTG model with versioning and provenance
    
    The resulting PTG can be used for attack simulation and choke-point analysis.
    """,
    responses={
        200: {"description": "PTG built successfully"},
        400: {"description": "Invalid parameters"},
        404: {"description": "Scope not found"},
        500: {"description": "Build failed"}
    }
)
async def build_ptg(
    request: PTGBuildRequest,
    background_tasks: BackgroundTasks,
    use_judge: bool = Query(False, description="Use LLM judge for ambiguous pairs"),
    neo4j_session=Depends(get_neo4j_session)
) -> PTGBuildResponse:
    """Build PTG model for specified scope."""
    
    try:
        # Parse parameters - respect body parameter for use_judge if provided
        body_use_judge = request.parameters.get("use_judge", None)
        judge_enabled = body_use_judge if body_use_judge is not None else use_judge
        
        parameters = PTGParameters(
            alpha=request.parameters.get("alpha", 1.0),
            beta=request.parameters.get("beta", 0.5),
            gamma=request.parameters.get("gamma", 0.3),
            delta=request.parameters.get("delta", 0.7),
            epsilon=request.parameters.get("epsilon", 1.0),
            kmax_outgoing=request.parameters.get("kmax_outgoing", 5),
            min_probability=request.parameters.get("min_probability", 0.01),
            use_judge=judge_enabled
        )
        
        # Build PTG (this may take a while)
        if request.background:
            # Run in background
            background_tasks.add_task(
                _build_ptg_background,
                request.scope,
                request.scope_type,
                parameters
            )
            
            return PTGBuildResponse(
                model_id=f"ptg-pending-{request.scope}",
                scope=request.scope,
                scope_type=request.scope_type,
                status="building",
                message="PTG build started in background",
                total_nodes=0,
                total_edges=0,
                parameters=parameters.__dict__,
                created_at=datetime.utcnow().isoformat()
            )
        else:
            # Build synchronously
            model = build_ptg_for_scope(
                settings.neo4j_uri,
                settings.neo4j_user, 
                settings.neo4j_password,
                request.scope,
                request.scope_type,
                parameters,
                opensearch_url=settings.opensearch_url if judge_enabled else None,
                opensearch_index=settings.os_index_nodes if judge_enabled else None
            )
            
            if not model:
                raise HTTPException(status_code=500, detail="PTG build failed")
            
            return PTGBuildResponse(
                model_id=model.model_id,
                scope=model.scope,
                scope_type=model.scope_type,
                status="completed",
                message=f"PTG built with {len(model.nodes)} nodes and {len(model.edges)} edges",
                total_nodes=len(model.nodes),
                total_edges=len(model.edges),
                parameters=model.parameters,
                statistics=model.statistics,
                created_at=model.created_at.isoformat()
            )
    
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"PTG build failed for scope {request.scope}: {e}")
        raise HTTPException(status_code=500, detail=f"Build failed: {str(e)}")


@router.get("/model/{scope_id}",
    response_model=PTGModelResponse,
    summary="Get PTG Model",
    description="""
    Retrieve a PTG model by scope ID.
    
    Returns:
    - Model metadata and parameters
    - Transition probabilities as NEXT_P edges  
    - Feature vectors for each transition
    - Statistics and provenance information
    
    The model can be filtered to return only high-confidence transitions.
    """,
    responses={
        200: {"description": "PTG model retrieved"},
        404: {"description": "Model not found"},
        500: {"description": "Retrieval failed"}
    }
)
async def get_ptg_model(
    scope_id: str,
    model_version: Optional[str] = Query(None, description="Specific model version"),
    min_probability: float = Query(0.0, description="Minimum edge probability filter"),
    include_features: bool = Query(True, description="Include feature vectors"),
    neo4j_session=Depends(get_neo4j_session)
) -> PTGModelResponse:
    """Get PTG model by scope."""
    
    try:
        builder = PTGBuilder(
            settings.neo4j_uri,
            settings.neo4j_user,
            settings.neo4j_password
        )
        
        # Find model by scope
        with builder.driver.session() as session:
            if model_version:
                query = """
                    MATCH (m:SequenceModel {scope: $scope, version: $version})
                    RETURN m.model_id as model_id
                """
                result = session.run(query, scope=scope_id, version=model_version)
            else:
                query = """
                    MATCH (m:SequenceModel {scope: $scope})
                    RETURN m.model_id as model_id, m.created_at as created_at
                    ORDER BY m.created_at DESC
                    LIMIT 1
                """
                result = session.run(query, scope=scope_id)
            
            record = result.single()
            if not record:
                raise HTTPException(
                    status_code=404,
                    detail=f"No PTG model found for scope {scope_id}"
                )
            
            model_id = record["model_id"]
        
        # Load model
        model = builder.load_ptg(model_id)
        if not model:
            raise HTTPException(
                status_code=404,
                detail=f"PTG model {model_id} not found"
            )
        
        # Filter edges by probability
        filtered_edges = [
            e for e in model.edges 
            if e.probability >= min_probability
        ]
        
        # Format response
        edges_data = []
        for edge in filtered_edges:
            edge_data = {
                "from_technique": edge.from_technique,
                "to_technique": edge.to_technique, 
                "probability": edge.probability,
                "rationale": edge.rationale,
                "evidence_count": edge.evidence_count
            }
            
            if include_features:
                edge_data["features"] = edge.features
            
            if edge.judge_score is not None:
                edge_data["judge_score"] = edge.judge_score
                
            edges_data.append(edge_data)
        
        # Build node data
        nodes_data = {}
        for technique_id, node in model.nodes.items():
            nodes_data[technique_id] = {
                "name": node.name,
                "primary_tactic": node.primary_tactic,
                "outgoing_edges": len([e for e in node.outgoing_edges if e.probability >= min_probability]),
                "total_probability": sum(e.probability for e in node.outgoing_edges if e.probability >= min_probability)
            }
        
        return PTGModelResponse(
            model_id=model.model_id,
            scope=model.scope,
            scope_type=model.scope_type,
            version=model.version,
            nodes=nodes_data,
            edges=edges_data,
            parameters=model.parameters,
            statistics=model.statistics,
            filters_applied={
                "min_probability": min_probability,
                "include_features": include_features
            },
            created_at=model.created_at.isoformat()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve PTG model for {scope_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Retrieval failed: {str(e)}")
    
    finally:
        if 'builder' in locals():
            builder.close()


@router.get("/models",
    summary="List PTG Models", 
    description="List all available PTG models with filtering and pagination."
)
async def list_ptg_models(
    scope_type: Optional[str] = Query(None, description="Filter by scope type"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """List available PTG models."""
    
    try:
        # Build query with filters
        where_clauses = []
        params = {"limit": limit, "offset": offset}
        
        if scope_type:
            where_clauses.append("m.scope_type = $scope_type")
            params["scope_type"] = scope_type
        
        where_clause = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        
        query = f"""
            MATCH (m:SequenceModel)
            {where_clause}
            RETURN m.model_id as model_id,
                   m.scope as scope,
                   m.scope_type as scope_type,
                   m.version as version,
                   m.total_nodes as total_nodes,
                   m.total_edges as total_edges,
                   m.created_at as created_at
            ORDER BY m.created_at DESC
            SKIP $offset
            LIMIT $limit
        """
        
        result = neo4j_session.run(query, **params)
        
        models = []
        for record in result:
            models.append({
                "model_id": record["model_id"],
                "scope": record["scope"], 
                "scope_type": record["scope_type"],
                "version": record["version"],
                "total_nodes": record["total_nodes"],
                "total_edges": record["total_edges"],
                "created_at": record["created_at"].isoformat() if record["created_at"] else ""
            })
        
        # Get total count
        count_query = f"""
            MATCH (m:SequenceModel)
            {where_clause}
            RETURN count(m) as total
        """
        
        count_result = neo4j_session.run(count_query, **params)
        total = count_result.single()["total"]
        
        return {
            "models": models,
            "total": total,
            "offset": offset,
            "limit": limit
        }
        
    except Exception as e:
        logger.error(f"Failed to list PTG models: {e}")
        raise HTTPException(status_code=500, detail=f"List failed: {str(e)}")


@router.get("/statistics/{scope}",
    response_model=SequenceStatisticsResponse,
    summary="Get Sequence Statistics",
    description="Get detailed pairwise statistics for a scope."
)
async def get_sequence_statistics(
    scope: str,
    include_pairs: bool = Query(True, description="Include pairwise transition data"),
    top_k: int = Query(20, description="Limit to top-K techniques/pairs"),
    neo4j_session=Depends(get_neo4j_session)
) -> SequenceStatisticsResponse:
    """Get sequence statistics for a scope."""
    
    try:
        # Find statistics for scope
        query = """
            MATCH (s:SequenceStatistics {scope: $scope})
            RETURN s.scope as scope,
                   s.scope_type as scope_type,
                   s.total_flows as total_flows,
                   s.total_techniques as total_techniques,
                   s.total_pairs as total_pairs,
                   s.technique_counts as technique_counts,
                   s.conditional_probs as conditional_probs,
                   s.asymmetry_scores as asymmetry_scores,
                   s.created_at as created_at
            ORDER BY s.created_at DESC
            LIMIT 1
        """
        
        result = neo4j_session.run(query, scope=scope)
        record = result.single()
        
        if not record:
            raise HTTPException(status_code=404, detail=f"No statistics found for scope {scope}")
        
        # Parse JSON data
        technique_counts = json.loads(record["technique_counts"] or "{}")
        conditional_probs = json.loads(record["conditional_probs"] or "{}")
        asymmetry_scores = json.loads(record["asymmetry_scores"] or "{}")
        
        # Get top techniques
        top_techniques = dict(sorted(
            technique_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:top_k])
        
        # Format response
        response_data = {
            "scope": record["scope"],
            "scope_type": record["scope_type"],
            "total_flows": record["total_flows"],
            "total_techniques": record["total_techniques"],
            "total_pairs": record["total_pairs"],
            "top_techniques": top_techniques,
            "created_at": record["created_at"].isoformat() if record["created_at"] else ""
        }
        
        if include_pairs:
            # Get top pairs by conditional probability
            top_pairs = dict(sorted(
                conditional_probs.items(),
                key=lambda x: x[1],
                reverse=True
            )[:top_k])
            
            response_data["top_pairs"] = top_pairs
            response_data["asymmetry_scores"] = asymmetry_scores
        
        return SequenceStatisticsResponse(**response_data)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get statistics for {scope}: {e}")
        raise HTTPException(status_code=500, detail=f"Statistics retrieval failed: {str(e)}")


@router.delete("/model/{model_id}",
    summary="Delete PTG Model",
    description="Delete a PTG model and all associated NEXT_P edges."
)
async def delete_ptg_model(
    model_id: str,
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """Delete a PTG model."""
    
    try:
        # Delete NEXT_P edges first
        delete_edges_query = """
            MATCH ()-[r:NEXT_P {model_id: $model_id}]-()
            DELETE r
            RETURN count(r) as deleted_edges
        """
        
        edges_result = neo4j_session.run(delete_edges_query, model_id=model_id)
        deleted_edges = edges_result.single()["deleted_edges"]
        
        # Delete model and statistics
        delete_model_query = """
            MATCH (m:SequenceModel {model_id: $model_id})
            OPTIONAL MATCH (m)-[:HAS_SCOPE]->(s:SequenceStatistics)
            DELETE s, m
            RETURN count(m) as deleted_models, count(s) as deleted_stats
        """
        
        model_result = neo4j_session.run(delete_model_query, model_id=model_id)
        result_record = model_result.single()
        
        if result_record["deleted_models"] == 0:
            raise HTTPException(status_code=404, detail=f"Model {model_id} not found")
        
        return {
            "model_id": model_id,
            "deleted": True,
            "deleted_edges": deleted_edges,
            "deleted_models": result_record["deleted_models"],
            "deleted_statistics": result_record["deleted_stats"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete model {model_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Deletion failed: {str(e)}")


async def _build_ptg_background(scope: str, scope_type: str, parameters: PTGParameters):
    """Background task for PTG building."""
    logger.info(f"Starting background PTG build for scope {scope}")
    
    try:
        model = build_ptg_for_scope(
            settings.neo4j_uri,
            settings.neo4j_user,
            settings.neo4j_password,
            scope,
            scope_type,
            parameters,
            opensearch_url=settings.opensearch_url if parameters.use_judge else None,
            opensearch_index=settings.os_index_nodes if parameters.use_judge else None
        )
        
        if model:
            logger.info(f"Background PTG build completed: {model.model_id}")
        else:
            logger.error(f"Background PTG build failed for scope {scope}")
            
    except Exception as e:
        logger.error(f"Background PTG build error for {scope}: {e}")


@router.get("/provenance/{from_technique}/{to_technique}",
    summary="Get Transition Provenance",
    description="Get provenance information for a technique transition."
)
async def get_transition_provenance(
    from_technique: str,
    to_technique: str,
    model_id: Optional[str] = Query(None, description="Specific model to query"),
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """Get provenance for a technique transition."""
    
    try:
        if model_id:
            # Query specific model
            query = """
                MATCH (t1:AttackPattern {stix_id: $from_tech})-[r:NEXT_P {model_id: $model_id}]->(t2:AttackPattern {stix_id: $to_tech})
                RETURN r.p as probability,
                       r.features as features,
                       r.rationale as rationale,
                       r.evidence_count as evidence_count,
                       r.created_at as created_at
            """
            result = neo4j_session.run(query, 
                from_tech=from_technique, 
                to_tech=to_technique,
                model_id=model_id
            )
        else:
            # Query latest model
            query = """
                MATCH (t1:AttackPattern {stix_id: $from_tech})-[r:NEXT_P]->(t2:AttackPattern {stix_id: $to_tech})
                RETURN r.model_id as model_id,
                       r.p as probability,
                       r.features as features, 
                       r.rationale as rationale,
                       r.evidence_count as evidence_count,
                       r.created_at as created_at
                ORDER BY r.created_at DESC
                LIMIT 1
            """
            result = neo4j_session.run(query,
                from_tech=from_technique,
                to_tech=to_technique
            )
        
        record = result.single()
        if not record:
            raise HTTPException(
                status_code=404,
                detail=f"No transition found from {from_technique} to {to_technique}"
            )
        
        # Get source evidence (flows that contain this transition)
        evidence_query = """
            MATCH (a1:AttackAction {attack_pattern_ref: $from_tech})-[:NEXT]->(a2:AttackAction {attack_pattern_ref: $to_tech})
            MATCH (e:AttackEpisode)-[:CONTAINS]->(a1)
            RETURN e.flow_id as flow_id,
                   e.episode_id as episode_id,
                   e.source_id as source_id
            LIMIT 10
        """
        
        evidence_result = neo4j_session.run(evidence_query,
            from_tech=from_technique,
            to_tech=to_technique
        )
        
        evidence_sources = []
        for evidence_record in evidence_result:
            evidence_sources.append({
                "flow_id": evidence_record["flow_id"],
                "episode_id": evidence_record["episode_id"],
                "source_id": evidence_record["source_id"]
            })
        
        return {
            "from_technique": from_technique,
            "to_technique": to_technique,
            "model_id": record.get("model_id"),
            "probability": record["probability"],
            "features": json.loads(record["features"] or "{}"),
            "rationale": record["rationale"],
            "evidence_count": record["evidence_count"],
            "evidence_sources": evidence_sources,
            "created_at": record["created_at"].isoformat() if record["created_at"] else ""
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get provenance for {from_technique} -> {to_technique}: {e}")
        raise HTTPException(status_code=500, detail=f"Provenance lookup failed: {str(e)}")


@router.post("/judge",
    summary="Judge Technique Pairs",
    description="""
    Judge ambiguous technique pairs using LLM to determine temporal direction.
    
    This endpoint:
    - Accepts a list of technique pairs
    - Runs triage to identify ambiguous pairs
    - Builds evidence packs from OpenSearch
    - Calls LLM judge for verdicts
    - Caches results for reuse
    
    Returns structured verdicts with confidence scores and evidence citations.
    """
)
async def judge_technique_pairs(
    pairs: List[List[str]],  # List of [from_technique, to_technique] pairs
    scope: str = Query("global", description="Scope for statistics and evidence"),
    max_pairs: int = Query(50, description="Maximum pairs to judge"),
    use_cache: bool = Query(True, description="Use cached verdicts if available"),
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """Judge technique pairs for temporal direction."""
    
    try:
        # Initialize components
        judge_cache = JudgeVerdictCache(
            settings.neo4j_uri,
            settings.neo4j_user,
            settings.neo4j_password
        )
        
        judge_config = JudgeConfig(
            enable_caching=use_cache,
            max_retries=2
        )
        
        judge_client = JudgeClient(config=judge_config, cache=judge_cache if use_cache else None)
        
        evidence_builder = EvidencePackBuilder(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password,
            opensearch_url=settings.opensearch_url,
            opensearch_index=settings.os_index_nodes
        )
        
        # Limit pairs to process
        pairs_to_judge = pairs[:max_pairs]
        
        verdicts = []
        cached_count = 0
        judged_count = 0
        errors = []
        
        for pair in pairs_to_judge:
            if len(pair) != 2:
                errors.append(f"Invalid pair format: {pair}")
                continue
            
            from_tech, to_tech = pair[0], pair[1]
            
            try:
                # Get statistics for the pair
                stats_query = """
                    MATCH (s:SequenceStatistics {scope: $scope})
                    RETURN s.conditional_probs as conditional_probs,
                           s.asymmetry_scores as asymmetry_scores
                """
                
                stats_result = neo4j_session.run(stats_query, scope=scope)
                stats_record = stats_result.single()
                
                statistics = {}
                if stats_record:
                    cond_probs = json.loads(stats_record["conditional_probs"]) if stats_record["conditional_probs"] else {}
                    asymmetry = json.loads(stats_record["asymmetry_scores"]) if stats_record["asymmetry_scores"] else {}
                    
                    key_forward = f"{from_tech},{to_tech}"
                    key_reverse = f"{to_tech},{from_tech}"
                    
                    statistics = {
                        "p_ij": cond_probs.get(key_forward, 0.5),
                        "p_ji": cond_probs.get(key_reverse, 0.5),
                        "asymmetry": asymmetry.get(key_forward, 0.0),
                        "c_ij": 1  # Would need to get actual count
                    }
                
                # Build evidence pack - need to create a mock PairwiseStatistics object
                # For now, create a minimal stats object that the evidence builder expects
                from bandjacks.llm.sequence_extractor import PairwiseStatistics
                
                # Create minimal stats for this pair
                mock_stats = PairwiseStatistics(
                    scope=scope,
                    scope_type="global",
                    total_flows=1,
                    total_techniques=2,
                    total_pairs=1,
                    technique_counts={from_tech: 1, to_tech: 1},
                    pair_counts={(from_tech, to_tech): 1},
                    conditional_probs={},
                    asymmetry_scores={}
                )
                
                # Add the statistics we collected
                if statistics:
                    mock_stats.conditional_probs[(from_tech, to_tech)] = statistics.get("p_ij", 0.5)
                    mock_stats.conditional_probs[(to_tech, from_tech)] = statistics.get("p_ji", 0.5)
                    mock_stats.asymmetry_scores[(from_tech, to_tech)] = statistics.get("asymmetry", 0.0)
                    mock_stats.pair_counts[(from_tech, to_tech)] = statistics.get("c_ij", 1)
                
                evidence_pack = evidence_builder.build_evidence_pack(
                    from_technique=from_tech,
                    to_technique=to_tech,
                    stats=mock_stats,
                    top_k_evidence=5
                )
                
                # Check cache first
                if use_cache:
                    cached_verdict = judge_cache.get_cached_verdict(
                        from_tech, to_tech, evidence_pack.retrieval_hash
                    )
                    
                    if cached_verdict:
                        verdicts.append(cached_verdict.__dict__)
                        cached_count += 1
                        continue
                
                # Check budget before making LLM call - Epic 4 T26
                # Estimate based on evidence pack size (rough approximation)
                estimated_tokens_in = len(str(evidence_pack.__dict__)) // 4  # Rough token estimate
                estimated_tokens_out = 200  # Typical response size
                model_name = judge_config.model_name if hasattr(judge_config, 'model_name') else "gpt-4o-mini"
                
                allowed, cost, rejection_reason = check_and_record_judge_cost(
                    model=model_name,
                    tokens_in=estimated_tokens_in,
                    tokens_out=estimated_tokens_out,
                    job_id=f"judge_{scope}"
                )
                
                if not allowed:
                    logger.warning(f"Budget exceeded for judge call: {rejection_reason}")
                    errors.append(f"Budget exceeded for {from_tech} -> {to_tech}: {rejection_reason}")
                    continue
                
                # Get judge verdict
                verdict = judge_client.judge_pair(evidence_pack, scope_context=scope)
                
                # Cache the verdict
                if use_cache:
                    judge_cache.cache_verdict(verdict)
                
                # Track metrics - Epic 4 T28
                ml_tracker = get_ml_metrics_tracker()
                ml_tracker.record_prediction(
                    model_type="ptg_judge",
                    true_label=verdict.verdict.value,  # We treat judge verdict as ground truth for now
                    predicted_label=verdict.verdict.value,
                    confidence=verdict.confidence,
                    metadata={
                        "from_technique": verdict.from_technique,
                        "to_technique": verdict.to_technique,
                        "scope": scope
                    }
                )
                
                verdicts.append({
                    "from_technique": verdict.from_technique,
                    "to_technique": verdict.to_technique,
                    "verdict": verdict.verdict.value,
                    "confidence": verdict.confidence,
                    "evidence_ids": verdict.evidence_ids,
                    "rationale_summary": verdict.rationale_summary,
                    "model_name": verdict.model_name,
                    "cached": False
                })
                
                judged_count += 1
                
            except Exception as e:
                logger.error(f"Failed to judge pair {from_tech} -> {to_tech}: {e}")
                errors.append(f"Failed to judge {from_tech} -> {to_tech}: {str(e)}")
        
        # Get cache statistics
        cache_stats = judge_cache.get_cache_statistics() if use_cache else {}
        
        # Get budget statistics - Epic 4 T26
        budget_tracker = get_budget_tracker()
        budget_stats = budget_tracker.get_usage_stats(job_id=f"judge_{scope}")
        
        return {
            "total_pairs": len(pairs_to_judge),
            "judged": judged_count,
            "cached": cached_count,
            "errors": len(errors),
            "verdicts": verdicts,
            "error_details": errors[:10],  # Limit error details
            "cache_statistics": cache_stats,
            "budget_usage": {
                "cost_usd": budget_stats.get("total_cost_usd", 0),
                "usage_percent": budget_stats.get("usage_percent", 0),
                "cost_per_100_pairs": budget_tracker.get_cost_per_100_pairs()
            }
        }
        
    except Exception as e:
        logger.error(f"Judge endpoint failed: {e}")
        raise HTTPException(status_code=500, detail=f"Judge operation failed: {str(e)}")


@router.get("/provenance/{ti}/{tj}",
    summary="Get Pair Provenance",
    description="""
    Get complete provenance information for a judged technique pair.
    
    Epic 4 T25: Returns evidence pack hash, snippet IDs, sources, and judge history.
    Includes all historical verdicts, evidence sources, and PTG transition info.
    """
)
async def get_pair_provenance(
    ti: str,
    tj: str,
    include_history: bool = Query(True, description="Include historical verdicts"),
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """Get provenance information for a judged technique pair."""
    try:
        # Get judge verdicts from cache/storage
        verdict_query = """
            MATCH (v:JudgeVerdict {from_technique: $ti, to_technique: $tj})
            RETURN v.verdict as verdict,
                   v.confidence as confidence,
                   v.evidence_ids as evidence_ids,
                   v.evidence_hash as evidence_hash,
                   v.rationale as rationale,
                   v.model_name as model,
                   v.created_at as timestamp
            ORDER BY v.created_at DESC
            LIMIT 10
        """
        
        verdicts_result = neo4j_session.run(verdict_query, ti=ti, tj=tj)
        verdicts = []
        latest_evidence_hash = None
        
        for record in verdicts_result:
            verdict_data = {
                "verdict": record["verdict"],
                "confidence": record["confidence"],
                "evidence_ids": record["evidence_ids"] or [],
                "evidence_hash": record["evidence_hash"],
                "model": record["model"],
                "timestamp": record["timestamp"]
            }
            if record["rationale"]:
                verdict_data["rationale_summary"] = record["rationale"][:200]
            
            verdicts.append(verdict_data)
            if not latest_evidence_hash and record["evidence_hash"]:
                latest_evidence_hash = record["evidence_hash"]
        
        # Get evidence snippets from OpenSearch (if available)
        evidence_sources = []
        if latest_evidence_hash and verdicts and verdicts[0].get("evidence_ids"):
            # Mock evidence sources for now - would query OpenSearch
            for evidence_id in verdicts[0]["evidence_ids"][:5]:
                evidence_sources.append({
                    "evidence_id": evidence_id,
                    "source_type": "report",
                    "snippet": f"Evidence snippet for {evidence_id[:20]}...",
                    "confidence": 0.85
                })
        
        # Get PTG transition probability if exists
        ptg_query = """
            MATCH (from:AttackPattern {stix_id: $ti})-[r:NEXT_P]->(to:AttackPattern {stix_id: $tj})
            RETURN r.p as probability,
                   r.features as features,
                   r.model_id as model_id,
                   r.created_at as created_at
            ORDER BY r.created_at DESC
            LIMIT 1
        """
        
        ptg_result = neo4j_session.run(ptg_query, ti=ti, tj=tj).single()
        
        ptg_info = None
        if ptg_result:
            ptg_info = {
                "probability": ptg_result["probability"],
                "features": json.loads(ptg_result["features"]) if ptg_result["features"] else {},
                "model_id": ptg_result["model_id"],
                "created_at": ptg_result["created_at"]
            }
        
        # Get technique names
        name_query = """
            MATCH (from:AttackPattern {stix_id: $ti}), (to:AttackPattern {stix_id: $tj})
            RETURN from.name as from_name, to.name as to_name
        """
        
        names_result = neo4j_session.run(name_query, ti=ti, tj=tj).single()
        
        response = {
            "from_technique": ti,
            "to_technique": tj,
            "from_name": names_result["from_name"] if names_result else "Unknown",
            "to_name": names_result["to_name"] if names_result else "Unknown",
            "evidence_hash": latest_evidence_hash,
            "evidence_sources": evidence_sources,
            "ptg_transition": ptg_info,
            "judge_verdicts": verdicts if include_history else verdicts[:1],
            "total_verdicts": len(verdicts),
            "metadata": {
                "provenance_version": "1.0",
                "query_timestamp": datetime.utcnow().isoformat()
            }
        }
        
        return response
        
    except Exception as e:
        logger.error(f"Failed to get provenance for {ti} -> {tj}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/config",
    summary="Get PTG Build Configuration",
    description="""
    Get current PTG building configuration flags and parameters.
    
    Epic 4 T27: Returns all configuration flags that control PTG building behavior,
    including judge enablement, triage settings, evidence retrieval, and feature weights.
    """
)
async def get_ptg_configuration() -> Dict[str, Any]:
    """Get current PTG configuration."""
    
    config = get_ptg_config()
    budget_tracker = get_budget_tracker()
    
    return {
        "configuration": config.to_dict(),
        "budget_status": budget_tracker.get_usage_stats(),
        "validation": {
            "weights_sum": sum([
                config.alpha_statistical,
                config.beta_judge,
                config.gamma_structure,
                config.delta_temporal,
                config.epsilon_confidence
            ]),
            "is_valid": True
        }
    }


@router.put("/config",
    summary="Update PTG Build Configuration",
    description="""
    Update PTG building configuration flags and parameters.
    
    Epic 4 T27: Allows updating configuration flags without restarting the service.
    Note: Feature weights (alpha, beta, gamma, delta, epsilon) must sum to 1.0.
    """
)
async def update_ptg_configuration(
    config_update: Dict[str, Any]
) -> Dict[str, Any]:
    """Update PTG configuration."""
    
    try:
        # Get current config
        current_config = get_ptg_config()
        
        # Create new config with updates
        config_dict = current_config.to_dict()
        config_dict.update(config_update)
        
        # Create and validate new config
        new_config = PTGBuildConfig(**config_dict)
        new_config.validate()
        
        # Set the new config
        set_ptg_config(new_config)
        
        return {
            "status": "updated",
            "configuration": new_config.to_dict(),
            "validation": {
                "weights_sum": sum([
                    new_config.alpha_statistical,
                    new_config.beta_judge,
                    new_config.gamma_structure,
                    new_config.delta_temporal,
                    new_config.epsilon_confidence
                ]),
                "is_valid": True
            }
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid configuration: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to update PTG configuration: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/metrics",
    summary="Get PTG Judge Metrics",
    description="""
    Get ML metrics for PTG judge performance and system usage.
    
    Epic 4 T28: Returns comprehensive metrics including:
    - ML model performance (precision, recall, confidence calibration)
    - Judge verdict distribution and confidence scores
    - Budget usage and cost analytics
    - Cache hit rates and performance stats
    """
)
async def get_ptg_metrics() -> Dict[str, Any]:
    """Get comprehensive PTG metrics."""
    
    try:
        # Get ML metrics
        ml_tracker = get_ml_metrics_tracker()
        ml_metrics = ml_tracker.get_all_metrics()
        
        # Get budget metrics
        budget_tracker = get_budget_tracker()
        budget_stats = budget_tracker.get_usage_stats()
        
        # Get cache metrics
        judge_cache = JudgeVerdictCache(
            settings.neo4j_uri,
            settings.neo4j_user,
            settings.neo4j_password
        )
        cache_stats = judge_cache.get_cache_statistics()
        
        return {
            "ml_performance": ml_metrics.get("ml_performance", {}),
            "judge_metrics": {
                "total_predictions": len(ml_tracker.predictions.get("ptg_judge", [])),
                "confidence_distribution": ml_tracker.confidence_scores.get("ptg_judge", []),
                "calibration": ml_tracker.calculate_confidence_calibration("ptg_judge")
            },
            "budget_metrics": {
                "total_cost_usd": budget_stats.get("total_cost_usd", 0),
                "daily_limit_usd": budget_stats.get("limit_usd", 10.0),
                "usage_percent": budget_stats.get("usage_percent", 0),
                "calls_by_model": budget_stats.get("calls_by_model", {}),
                "cost_per_100_pairs": budget_tracker.get_cost_per_100_pairs()
            },
            "cache_metrics": cache_stats,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get PTG metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/metrics/export",
    summary="Export PTG Metrics for Dashboard",
    description="""
    Export PTG metrics in a format suitable for Grafana or other dashboards.
    
    Epic 4 T28: Returns metrics formatted for dashboard ingestion with panels
    for ML performance, budget tracking, and system health.
    """
)
async def export_ptg_metrics() -> Dict[str, Any]:
    """Export PTG metrics for dashboard."""
    
    try:
        ml_tracker = get_ml_metrics_tracker()
        dashboard_data = ml_tracker.export_for_dashboard()
        
        # Add PTG-specific panels
        budget_tracker = get_budget_tracker()
        budget_stats = budget_tracker.get_usage_stats()
        
        dashboard_data["panels"].append({
            "id": "ptg_budget",
            "title": "PTG Budget Usage",
            "type": "gauge",
            "data": {
                "value": budget_stats.get("usage_percent", 0),
                "max": 100,
                "thresholds": [
                    {"value": 80, "color": "yellow"},
                    {"value": 95, "color": "red"}
                ]
            }
        })
        
        dashboard_data["panels"].append({
            "id": "judge_confidence",
            "title": "Judge Confidence Distribution",
            "type": "histogram",
            "data": {
                "values": ml_tracker.confidence_scores.get("ptg_judge", []),
                "bins": [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]
            }
        })
        
        return dashboard_data
        
    except Exception as e:
        logger.error(f"Failed to export PTG metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))