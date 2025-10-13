"""Unified extraction and flow generation pipeline.

Module Status: PRODUCTION
This module consolidates the extraction, embedding, and flow generation
into a single coherent pipeline with review workflow integration.

Primary entry point for all report extraction and attack flow generation.
"""

import logging
import uuid
import time
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

from bandjacks.llm.memory import WorkingMemory
from bandjacks.llm.agents_v2 import (
    SpanFinderAgent,
    RetrieverAgent,
    DiscoveryAgent,
    MapperAgent,
    EvidenceVerifierAgent,
    ConsolidatorAgent,
    KillChainSuggestionsAgent,
    AssemblerAgent,
)
from bandjacks.llm.mapper_optimized import BatchMapperAgent
from bandjacks.llm.batch_retriever import BatchRetrieverAgent
from bandjacks.llm.entity_extractor import EntityExtractionAgent
from bandjacks.llm.entity_consolidator import EntityConsolidatorAgent
from bandjacks.llm.tracker import ExtractionTracker
from bandjacks.llm.flow_builder import FlowBuilder
from bandjacks.loaders.embedder import encode

logger = logging.getLogger(__name__)


class ExtractionPipeline:
    """Unified extraction and flow generation pipeline."""
    
    def __init__(self, neo4j_uri: str = None, neo4j_user: str = None, neo4j_password: str = None):
        """Initialize the extraction pipeline.
        
        Args:
            neo4j_uri: Neo4j connection URI (optional for flow building)
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
        """
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_password = neo4j_password
        self.flow_builder = None
        
        if neo4j_uri:
            self.flow_builder = FlowBuilder(neo4j_uri, neo4j_user, neo4j_password)
    
    def extract_and_build_flow(
        self,
        report_text: str,
        config: Optional[Dict[str, Any]] = None,
        source_id: Optional[str] = None,
        progress_callback: Optional[callable] = None
    ) -> Dict[str, Any]:
        """
        Run complete extraction and flow generation pipeline.
        
        Args:
            report_text: The report text to process
            config: Configuration options for extraction
            source_id: Optional source identifier
            progress_callback: Optional callback function(progress, message) for progress updates
            
        Returns:
            Complete extraction and flow result with review package
        """
        config = config or {}
        tracker = ExtractionTracker()
        
        logger.info("Starting extraction pipeline")
        
        # Step 1: Extract techniques
        extraction_result = self._extract_techniques(report_text, config, tracker, progress_callback)
        
        # Step 2: Generate embeddings for extracted techniques
        embeddings = self._generate_embeddings(extraction_result)
        
        # Step 3: Build attack flow if we have techniques
        flow = None
        if extraction_result.get("techniques"):
            flow = self._build_attack_flow(
                extraction_result,
                report_text,
                source_id
            )
        
        # Step 4: Prepare review package
        review_package = self._prepare_for_review(
            extraction_result,
            flow,
            embeddings,
            source_id,
            config
        )
        
        # Add metrics
        review_package["metrics"] = {
            "extraction_duration_ms": (time.time() - tracker.started_at) * 1000 if hasattr(tracker, 'started_at') else 0,
            "spans_found": tracker.spans_total,
            "techniques_extracted": len(extraction_result.get("techniques", {})),
            "confidence_avg": self._calculate_avg_confidence(extraction_result),
            "entity_extraction_status": extraction_result.get("entities", {}).get("extraction_status", "unknown"),
            "extraction_errors": extraction_result.get("extraction_errors", [])
        }
        
        # Add techniques_count at top level for API compatibility
        review_package["techniques_count"] = len(extraction_result.get("techniques", {}))
        
        logger.info(f"Pipeline complete: {len(extraction_result.get('techniques', {}))} techniques extracted")
        
        return review_package
    
    def _extract_techniques(
        self,
        report_text: str,
        config: Dict[str, Any],
        tracker: ExtractionTracker,
        progress_callback: Optional[callable] = None
    ) -> Dict[str, Any]:
        """Run the extraction agents to identify techniques.
        
        This is the core extraction logic, using the agent chain.
        """
        start_time = time.time()
        logger.info(f"Starting extraction pipeline: text_length={len(report_text)}")
        logger.debug(f"Config: {config}")
        
        # Preprocess text
        processed_text = self._preprocess_text(report_text)
        
        # Initialize working memory with both document text and line index
        mem = WorkingMemory(
            document_text=processed_text,
            line_index=processed_text.splitlines()
        )
        
        # Run agent pipeline

        # NEW: Extract entities first (malware, threat actors, etc.) unless skipped
        if not config.get("skip_entity_extraction", False):
            tracker.set_stage("EntityExtraction")
            if progress_callback:
                progress_callback(30, "Extracting threat entities...")
            EntityExtractionAgent().run(mem, config)
            logger.info(f"Extracted entities: primary={mem.entities.get('primary_entity', {}).get('name')}")
        else:
            logger.info("Entity extraction skipped (skip_entity_extraction=True)")
            mem.entities = {"entities": [], "extraction_status": "skipped"}
        
        tracker.set_stage("SpanFinder")
        if progress_callback:
            progress_callback(35, "Finding technique spans in text...")
        SpanFinderAgent().run(mem, config)
        tracker.set_spans_total(len(mem.spans))
        
        # Apply span limits if configured
        if config.get("max_spans", 0) > 0:
            mem.spans = mem.spans[:config["max_spans"]]
        
        tracker.set_stage("Retriever")
        if progress_callback:
            progress_callback(40, f"Retrieving candidates for {len(mem.spans)} spans...")
        
        # Use batch retriever for efficiency when processing multiple spans
        use_batch = config.get("use_batch_retriever", True) and len(mem.spans) > 1
        logger.info(f"Retriever decision: use_batch={use_batch}, spans={len(mem.spans)}, config_batch={config.get('use_batch_retriever', True)}")
        
        if use_batch:
            logger.info("Using BatchRetrieverAgent for batch processing")
            BatchRetrieverAgent().run(mem, config)
        else:
            logger.info("Using RetrieverAgent for sequential processing")
            RetrieverAgent().run(mem, config)
        
        # Optional discovery phase
        if not config.get("disable_discovery", False):
            # Check retrieval confidence
            avg_score = self._calculate_retrieval_confidence(mem)
            if avg_score < 0.7:
                tracker.set_stage("Discovery")
                DiscoveryAgent().run(mem, config)
        
        tracker.set_stage("Mapper")
        if progress_callback:
            progress_callback(50, "Mapping spans to ATT&CK techniques...")
        # Use batch mapper for speed if configured
        if config.get("use_batch_mapper", False):
            BatchMapperAgent().run(mem, config)
        else:
            MapperAgent().run(mem, config)
        
        tracker.spans_processed = len({
            c.get("span_idx", -1) for c in mem.claims 
            if c.get("span_idx", -1) >= 0
        })
        
        # Optional verification
        if not config.get("skip_verification", False):
            tracker.set_stage("Verifier")
            if progress_callback:
                progress_callback(60, "Verifying evidence...")
            EvidenceVerifierAgent().run(mem, config)
        
        tracker.set_stage("Consolidator")
        if progress_callback:
            progress_callback(65, "Consolidating techniques...")
        ConsolidatorAgent().run(mem, config)
        tracker.counters["techniques"] = len(mem.techniques)
        
        # Consolidate entity claims if they exist
        if hasattr(mem, 'entity_claims') and mem.entity_claims:
            tracker.set_stage("EntityConsolidator")
            if progress_callback:
                progress_callback(68, f"Consolidating {len(mem.entity_claims)} entity claims...")
            EntityConsolidatorAgent().run(mem, config)
            logger.info(f"Entity consolidation complete: {len(getattr(mem, 'consolidated_entities', {}))} unique entities")
        
        # Optional targeted extraction for missing tactics
        if not config.get("disable_targeted_extraction", True):
            self._run_targeted_extraction(mem, config, tracker)
        
        tracker.set_stage("Assembler")
        AssemblerAgent().run(mem, config)
        
        # Extract entities from working memory - they're already in the correct structured format
        entities_struct = mem.entities
        
        # Apply entity consolidation to merge aliases (e.g., APT29 and Cozy Bear)
        if entities_struct and isinstance(entities_struct, dict):
            entities_struct = EntityConsolidatorAgent.consolidate_entities(entities_struct)
            logger.info(f"Entity consolidation applied: {len(entities_struct.get('entities', []))} unique entities")
        
        return {
            "techniques": mem.techniques,
            "claims": mem.claims,
            "entities": entities_struct,  # Structured entities format: {"entities": [{"name": str, "type": str}], "extraction_status": str}
            "spans": [{"text": s.get("text", ""), "line_refs": s.get("line_refs", [])} 
                     for s in mem.spans],
            "extraction_metrics": {
                "total_time": time.time() - tracker.started_at if hasattr(tracker, 'started_at') else 0,
                "spans_total": tracker.spans_total,
                "spans_processed": tracker.spans_processed,
                "techniques_found": tracker.counters.get("techniques", 0)
            }
        }
    
    def _preprocess_text(self, text: str) -> str:
        """Preprocess text for better span detection."""
        import re
        
        # If text is mostly on one line, split on sentence boundaries
        lines = text.splitlines()
        if len(lines) <= 2 and len(text) > 100:
            # Split on sentence endings
            sentences = re.split(r'(?<=[.!?])\s+(?=[A-Z])', text)
            
            # Also split on technique IDs for better isolation
            expanded = []
            for sent in sentences:
                parts = re.split(r'(T\d{4}(?:\.\d{3})?)', sent)
                for i, part in enumerate(parts):
                    if part and part.strip():
                        if re.match(r'^T\d{4}', part):
                            if i > 0 and parts[i-1]:
                                expanded.append(parts[i-1].strip() + " " + part)
                            elif i + 1 < len(parts) and parts[i+1]:
                                expanded.append(part + " " + parts[i+1].strip()[:100])
                            else:
                                expanded.append(part)
                        elif i == 0 or not re.match(r'^T\d{4}', parts[i-1]):
                            expanded.append(part.strip())
            
            return "\n".join(expanded)
        
        return text
    
    def _calculate_retrieval_confidence(self, mem: WorkingMemory) -> float:
        """Calculate average confidence of retrieval results."""
        total = 0
        count = 0
        for candidates in mem.candidates.values():
            for c in candidates:
                total += c.get("score", 0)
                count += 1
        return total / max(1, count)
    
    def _run_targeted_extraction(
        self,
        mem: WorkingMemory,
        config: Dict[str, Any],
        tracker: ExtractionTracker
    ):
        """Run targeted extraction for missing tactics."""
        tracker.set_stage("Suggestions")
        KillChainSuggestionsAgent().run(mem, config)
        
        # Only do targeted extraction if very few techniques found
        if len(mem.techniques) < 2 and hasattr(mem, "inferred_suggestions"):
            missing_tactics = [s["tactic"] for s in mem.inferred_suggestions][:3]
            if missing_tactics:
                logger.info(f"Running targeted extraction for {len(missing_tactics)} tactics")
                # This would require reimplementing targeted extraction logic
                # For now, we skip this to avoid complexity
                pass
    
    def _generate_embeddings(self, extraction_result: Dict[str, Any]) -> Dict[str, List[float]]:
        """Generate embeddings for extracted techniques.
        
        Args:
            extraction_result: The extraction result containing techniques
            
        Returns:
            Dictionary mapping technique IDs to embeddings
        """
        embeddings = {}
        
        for tech_id, tech_data in extraction_result.get("techniques", {}).items():
            # Create text representation for embedding
            text_parts = [
                tech_data.get("name", ""),
                tech_data.get("description", "")
            ]
            
            # Add evidence text if available
            for claim in extraction_result.get("claims", []):
                if claim.get("technique_id") == tech_id:
                    text_parts.append(claim.get("evidence", ""))
            
            # Generate embedding
            text = " ".join(filter(None, text_parts))
            if text:
                try:
                    embedding = encode(text)
                    embeddings[tech_id] = embedding
                except Exception as e:
                    logger.warning(f"Failed to generate embedding for {tech_id}: {e}")
        
        return embeddings
    
    def _build_attack_flow(
        self,
        extraction_result: Dict[str, Any],
        report_text: str,
        source_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Build attack flow from extraction results.
        
        Args:
            extraction_result: The extraction result
            report_text: Original report text
            source_id: Optional source identifier
            
        Returns:
            Attack flow data or None if building fails
        """
        if not self.flow_builder:
            logger.warning("Flow builder not initialized (no Neo4j connection)")
            return None
        
        try:
            # Prepare extraction data in expected format  
            entities_data = extraction_result.get("entities", {"entities": []})
            flow_extraction_data = {
                "extraction_claims": extraction_result.get("claims", []),
                "techniques": extraction_result.get("techniques", {}),
                "chunks": [{
                    "claims": extraction_result.get("claims", []),
                    "entities": entities_data  # Pass structured entities directly
                }]
            }
            
            # Build flow
            logger.info(f"Building flow with {len(flow_extraction_data['extraction_claims'])} claims")
            flow_result = self.flow_builder.build_from_extraction(
                extraction_data=flow_extraction_data,
                source_id=source_id,
                report_text=report_text,
                use_stored_text=False
            )
            
            logger.info(f"Flow build result: {type(flow_result)}, keys: {flow_result.keys() if flow_result else 'None'}")
            
            if flow_result:
                flow_data = {
                    "flow_id": flow_result.get("flow_id"),
                    "flow_name": flow_result.get("name"),
                    "flow_type": "llm_synthesized" if flow_result.get("llm_synthesized") else "deterministic",
                    "steps": flow_result.get("actions", []),
                    "edges": flow_result.get("edges", []),
                    "confidence": flow_result.get("confidence", 0.5)
                }
                logger.info(f"Returning flow data: {flow_data}")
                return flow_data
            else:
                logger.warning("Flow result was None or empty")
                
        except Exception as e:
            logger.error(f"Failed to build attack flow: {e}")
        
        return None
    
    def _prepare_for_review(
        self,
        extraction_result: Dict[str, Any],
        flow: Optional[Dict[str, Any]],
        embeddings: Dict[str, List[float]],
        source_id: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Prepare complete review package for analyst validation.

        Args:
            extraction_result: The extraction results
            flow: Generated attack flow (optional)
            embeddings: Technique embeddings
            source_id: Optional source identifier
            config: Configuration options including auto-approval settings

        Returns:
            Review package ready for analyst validation
        """
        logger.info(f"Preparing review package with flow: {flow is not None}, flow_id: {flow.get('flow_id') if flow else 'None'}")

        config = config or {}

        # Calculate average confidence for auto-approval decision
        avg_confidence = self._calculate_avg_confidence(extraction_result)
        auto_approve = config.get("auto_approve", False)
        auto_approve_threshold = config.get("auto_approve_threshold", 0.9)

        # Determine if auto-approved
        is_auto_approved = auto_approve and avg_confidence >= auto_approve_threshold

        if is_auto_approved:
            logger.info(f"Auto-approved: avg_confidence={avg_confidence:.2f} >= threshold={auto_approve_threshold}")
            status = "auto_approved"
            review_required = False
        else:
            if auto_approve:
                logger.info(f"Manual review required: avg_confidence={avg_confidence:.2f} < threshold={auto_approve_threshold}")
            status = "pending_review"
            review_required = True

        review_package = {
            "extraction_id": str(uuid.uuid4()),
            "source_id": source_id,
            "timestamp": datetime.utcnow().isoformat(),
            "status": status,

            # Extraction results
            "techniques": extraction_result.get("techniques", {}),
            "technique_count": len(extraction_result.get("techniques", {})),
            "claims": extraction_result.get("claims", []),
            "entities": extraction_result.get("entities", {"entities": [], "extraction_status": "not_attempted"}),

            # Evidence mapping for review
            "evidence_map": self._build_evidence_map(extraction_result),

            # Embeddings (store separately or include reference)
            "has_embeddings": len(embeddings) > 0,
            "embedding_count": len(embeddings),

            # Attack flow
            "flow": flow,

            # Review metadata
            "review_required": review_required,
            "auto_approved": is_auto_approved,
            "auto_approve_threshold": auto_approve_threshold,
            "average_confidence": avg_confidence,
            "requires_manual_review": self._requires_manual_review(extraction_result, flow) and not is_auto_approved
        }

        return review_package
    
    def _build_evidence_map(self, extraction_result: Dict[str, Any]) -> Dict[str, List[Dict]]:
        """Build evidence mapping for review UI.
        
        Maps each technique to its supporting evidence.
        """
        evidence_map = {}
        
        for claim in extraction_result.get("claims", []):
            tech_id = claim.get("technique_id")
            if tech_id:
                if tech_id not in evidence_map:
                    evidence_map[tech_id] = []
                
                evidence_map[tech_id].append({
                    "text": claim.get("evidence", ""),
                    "confidence": claim.get("confidence", 0),
                    "span_idx": claim.get("span_idx", -1),
                    "line_refs": claim.get("line_refs", [])
                })
        
        return evidence_map
    
    def _calculate_avg_confidence(self, extraction_result: Dict[str, Any]) -> float:
        """Calculate average confidence across all techniques."""
        confidences = []
        for tech_data in extraction_result.get("techniques", {}).values():
            confidences.append(tech_data.get("confidence", 0.5))
        
        return sum(confidences) / len(confidences) if confidences else 0.0
    
    def _requires_manual_review(
        self,
        extraction_result: Dict[str, Any],
        flow: Optional[Dict[str, Any]]
    ) -> bool:
        """Determine if manual review is required.
        
        Returns True if:
        - Low confidence techniques
        - No flow generated
        - Conflicting evidence
        """
        # Check for low confidence
        avg_confidence = self._calculate_avg_confidence(extraction_result)
        if avg_confidence < 0.7:
            return True
        
        # Check if flow was generated
        if not flow:
            return True
        
        # Check for very few techniques
        if len(extraction_result.get("techniques", {})) < 2:
            return True
        
        return False


def run_extraction_pipeline(
    report_text: str,
    config: Optional[Dict[str, Any]] = None,
    source_id: Optional[str] = None,
    neo4j_config: Optional[Dict[str, str]] = None,
    progress_callback: Optional[callable] = None
) -> Dict[str, Any]:
    """
    Convenience function to run the extraction pipeline.
    
    Args:
        report_text: The report text to process
        config: Configuration options
        source_id: Optional source identifier
        neo4j_config: Neo4j connection config (uri, user, password)
        progress_callback: Optional callback function for progress updates
        
    Returns:
        Complete extraction and flow result with review package
    """
    neo4j_uri = None
    neo4j_user = None
    neo4j_password = None
    
    if neo4j_config:
        neo4j_uri = neo4j_config.get("uri")
        neo4j_user = neo4j_config.get("user")
        neo4j_password = neo4j_config.get("password")
    else:
        # Try to get from settings if available
        try:
            from bandjacks.services.api.settings import settings
            neo4j_uri = settings.neo4j_uri
            neo4j_user = settings.neo4j_user
            neo4j_password = settings.neo4j_password
        except ImportError:
            pass
    
    pipeline = ExtractionPipeline(neo4j_uri, neo4j_user, neo4j_password)
    return pipeline.extract_and_build_flow(report_text, config, source_id, progress_callback)