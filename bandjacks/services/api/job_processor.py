"""Background job processor for async report processing."""

import asyncio
import logging
import math
import os
import uuid
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
from pathlib import Path

from bandjacks.services.api.job_store import FileJobStore
from bandjacks.services.api.redis_job_store import RedisJobStore, get_redis_job_store
from bandjacks.llm.extraction_pipeline import run_extraction_pipeline
from bandjacks.llm.chunked_extractor import ChunkedExtractor
from bandjacks.llm.optimized_chunked_extractor import OptimizedChunkedExtractor
from bandjacks.store.opensearch_report_store import OpenSearchReportStore
from bandjacks.services.api.deps import get_opensearch_client
from bandjacks.services.api.settings import settings

logger = logging.getLogger(__name__)


class JobProcessor:
    """Processes queued jobs asynchronously in the background."""
    
    def __init__(self, job_store: FileJobStore = None, poll_interval: int = 2, use_redis: bool = True):
        """Initialize the job processor.
        
        Args:
            job_store: File-based job store instance (deprecated)
            poll_interval: Seconds between polling for new jobs
            use_redis: Whether to use Redis job store (default: True)
        """
        if use_redis:
            try:
                self.job_store = get_redis_job_store()
                self.use_redis = True
                logger.info(f"Using Redis job store with worker ID: {self.job_store.worker_id}")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis: {e}. Falling back to file store.")
                self.job_store = job_store
                self.use_redis = False
        else:
            self.job_store = job_store
            self.use_redis = False
            
        self.poll_interval = poll_interval
        self.running = False
        self.processing_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
        self.heartbeat_task: Optional[asyncio.Task] = None
        self.current_job_id: Optional[str] = None
    
    def calculate_chunks_and_spans(self, text_length: int) -> Tuple[int, int, int]:
        """Dynamically calculate chunks and spans based on document size.
        
        Args:
            text_length: Length of document text in characters
            
        Returns:
            Tuple of (max_chunks, spans_per_chunk, total_spans)
        """
        # Base parameters
        CHUNK_SIZE = 3000  # Characters per chunk
        MIN_CHUNKS = 3
        MAX_CHUNKS = 50  # Increased for very large docs
        
        # Calculate required chunks
        required_chunks = math.ceil(text_length / CHUNK_SIZE)
        
        # Apply limits with scaling based on document size
        if text_length < 10_000:  # Small docs (< 10KB)
            max_chunks = min(5, required_chunks)
            spans_per_chunk = 15
        elif text_length < 50_000:  # Medium docs (10-50KB)
            max_chunks = min(15, required_chunks)
            spans_per_chunk = 12
        elif text_length < 200_000:  # Large docs (50-200KB)
            max_chunks = min(30, required_chunks)
            spans_per_chunk = 10
        else:  # Very large docs (> 200KB)
            max_chunks = min(MAX_CHUNKS, required_chunks)
            spans_per_chunk = 8
        
        # Ensure minimum coverage
        max_chunks = max(MIN_CHUNKS, max_chunks)
        total_spans = max_chunks * spans_per_chunk
        
        logger.info(f"Document size {text_length} chars → {max_chunks} chunks × {spans_per_chunk} spans = {total_spans} total spans")
        
        return max_chunks, spans_per_chunk, total_spans
        
    async def start(self):
        """Start the job processor background task."""
        if self.running:
            logger.warning("Job processor already running")
            return
            
        self.running = True
        self.processing_task = asyncio.create_task(self._process_loop())
        logger.info("Job processor started")
        
    async def stop(self):
        """Stop the job processor."""
        self.running = False
        
        # Cancel heartbeat if running
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
            try:
                await self.heartbeat_task
            except asyncio.CancelledError:
                pass
        
        # Cancel processing task
        if self.processing_task:
            self.processing_task.cancel()
            try:
                await self.processing_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Job processor stopped")
    
    async def _heartbeat_loop(self, job_id: str):
        """Send periodic heartbeats for the current job.
        
        Args:
            job_id: Job being processed
        """
        try:
            while True:
                # Wait for heartbeat interval
                await asyncio.sleep(settings.redis_heartbeat_interval)
                
                # Update heartbeat
                if self.use_redis:
                    success = self.job_store.update_heartbeat(job_id)
                    if not success:
                        logger.warning(f"Failed to update heartbeat for job {job_id}")
                        break
                    logger.debug(f"Heartbeat updated for job {job_id}")
        except asyncio.CancelledError:
            logger.debug(f"Heartbeat loop cancelled for job {job_id}")
            raise
        except Exception as e:
            logger.error(f"Error in heartbeat loop for job {job_id}: {e}")
        
    async def _process_loop(self):
        """Main processing loop that polls for jobs."""
        logger.info("Job processor loop started")
        
        while self.running:
            try:
                if self.use_redis:
                    # Atomically claim next job from Redis
                    job = self.job_store.claim_and_get_next_job()
                    
                    if job:
                        job_id = job['job_id']
                        logger.info(f"Worker {self.job_store.worker_id} claimed job {job_id}")
                        
                        # Start heartbeat for this job
                        self.current_job_id = job_id
                        if self.heartbeat_task:
                            self.heartbeat_task.cancel()
                        self.heartbeat_task = asyncio.create_task(self._heartbeat_loop(job_id))
                        
                        # Process the job
                        await self._process_job(job_id)
                        
                        # Stop heartbeat
                        if self.heartbeat_task:
                            self.heartbeat_task.cancel()
                            self.heartbeat_task = None
                        self.current_job_id = None
                else:
                    # Legacy file-based processing
                    jobs = self.job_store.get_queued_jobs()
                    
                    for job_id in jobs:
                        if not self.running:
                            break
                            
                        # Process job with lock to prevent concurrent processing
                        async with self._lock:
                            await self._process_job(job_id)
                        
                # Wait before next poll
                await asyncio.sleep(self.poll_interval)
                
            except Exception as e:
                logger.error(f"Error in job processing loop: {e}")
                await asyncio.sleep(self.poll_interval * 2)  # Back off on error
                
    async def _process_job(self, job_id: str):
        """Process a single job with error recovery.
        
        Args:
            job_id: Job identifier
        """
        retry_count = 0
        max_retries = 3
        
        while retry_count < max_retries:
            try:
                # Get job data
                job = self.job_store.get(job_id)
                if not job:
                    logger.warning(f"Job {job_id} not found")
                    return
                    
                # Check if already completed
                if job.get("status") == "completed":
                    return
                    
                # Check retry count
                retry_count = job.get("retry_count", 0)
                if retry_count >= max_retries:
                    logger.error(f"Job {job_id} exceeded max retries")
                    self.job_store.update(job_id, {
                        "status": "failed",
                        "error": "Max retries exceeded",
                        "completed_at": datetime.utcnow().isoformat()
                    })
                    return
                    
                # Mark as processing (Redis store handles this atomically in claim_and_get_next_job)
                if not self.use_redis:
                    self.job_store.update(job_id, {
                        "status": "processing",
                        "started_at": datetime.utcnow().isoformat(),
                        "progress": job.get("checkpoint_progress", 0),
                        "message": f"Processing (attempt {retry_count + 1}/{max_retries})...",
                        "retry_count": retry_count
                    })
            
                logger.info(f"Processing job {job_id} (attempt {retry_count + 1})")
                
                # Extract job parameters
                file_path = job.get("file_path")
                file_name = job.get("file_name", "unknown")
                file_ext = job.get("file_ext", ".txt")
                config = job.get("config", {})
                
                if not file_path or not os.path.exists(file_path):
                    raise ValueError(f"File not found: {file_path}")
                    
                # Process based on file type
                if file_ext == ".pdf":
                    await self._process_pdf_job(job_id, file_path, file_name, config)
                else:
                    await self._process_text_job(job_id, file_path, file_name, config)
                    
                # Success - exit retry loop
                return
                    
            except Exception as e:
                error_msg = str(e)
                logger.error(f"Failed to process job {job_id} (attempt {retry_count + 1}): {error_msg}")
                
                # Check if error is retryable
                retryable_errors = ["503", "overloaded", "rate_limit", "timeout", "429"]
                is_retryable = any(err in error_msg.lower() for err in retryable_errors)
                
                if is_retryable and retry_count < max_retries - 1:
                    # Save checkpoint and retry
                    retry_count += 1
                    wait_time = (2 ** retry_count) * 5  # Exponential backoff: 10s, 20s, 40s
                    
                    self.job_store.update(job_id, {
                        "status": "queued",  # Re-queue for retry
                        "retry_count": retry_count,
                        "checkpoint_progress": job.get("progress", 0),
                        "last_error": error_msg,
                        "message": f"Retrying in {wait_time}s after error: {error_msg[:100]}",
                        "next_retry_at": (datetime.utcnow() + timedelta(seconds=wait_time)).isoformat()
                    })
                    
                    logger.info(f"Job {job_id} will retry in {wait_time}s (attempt {retry_count}/{max_retries})")
                    await asyncio.sleep(wait_time)
                    
                else:
                    # Non-retryable error or max retries exceeded
                    if self.use_redis:
                        self.job_store.fail_job(job_id, error_msg)
                    else:
                        self.job_store.update(job_id, {
                            "status": "failed",
                            "error": error_msg,
                            "completed_at": datetime.utcnow().isoformat(),
                            "message": f"Processing failed after {retry_count + 1} attempts: {error_msg[:200]}",
                            "partial_results": job.get("partial_results", {})
                        })
                    return
            
    async def _process_pdf_job(
        self, 
        job_id: str, 
        pdf_path: str, 
        file_name: str,
        config: Dict[str, Any]
    ):
        """Process a PDF report job.
        
        Args:
            job_id: Job identifier
            pdf_path: Path to PDF file
            file_name: Original filename
            config: Processing configuration
        """
        try:
            # Update progress
            self.job_store.update(job_id, {
                "progress": 10,
                "message": "Extracting text from PDF..."
            })
            
            # Extract text from PDF
            text_content = await self._extract_pdf_text(pdf_path)
            
            # Process the extracted text
            await self._process_report_text(
                job_id=job_id,
                text_content=text_content,
                report_name=file_name,
                config=config,
                source_type="pdf"
            )
            
        finally:
            # Clean up temp file
            if os.path.exists(pdf_path):
                try:
                    os.unlink(pdf_path)
                except Exception as e:
                    logger.warning(f"Failed to delete temp file {pdf_path}: {e}")
                    
    async def _process_text_job(
        self,
        job_id: str,
        text_path: str,
        file_name: str,
        config: Dict[str, Any]
    ):
        """Process a text report job.
        
        Args:
            job_id: Job identifier
            text_path: Path to text file
            file_name: Original filename
            config: Processing configuration
        """
        try:
            # Read text content
            with open(text_path, 'r', encoding='utf-8', errors='ignore') as f:
                text_content = f.read()
                
            # Process the text
            await self._process_report_text(
                job_id=job_id,
                text_content=text_content,
                report_name=file_name,
                config=config,
                source_type="text"
            )
            
        finally:
            # Clean up temp file
            if os.path.exists(text_path):
                try:
                    os.unlink(text_path)
                except Exception as e:
                    logger.warning(f"Failed to delete temp file {text_path}: {e}")
                    
    async def _extract_pdf_text(self, pdf_path: str) -> str:
        """Extract text from PDF file.
        
        Args:
            pdf_path: Path to PDF file
            
        Returns:
            Extracted text content
        """
        try:
            import pdfplumber
            text_parts = []
            with pdfplumber.open(pdf_path) as pdf:
                for page in pdf.pages:
                    text = page.extract_text()
                    if text:
                        text_parts.append(text)
            return "\n\n".join(text_parts)
        except ImportError:
            # Fallback to PyPDF2
            import PyPDF2
            text_parts = []
            with open(pdf_path, 'rb') as f:
                pdf_reader = PyPDF2.PdfReader(f)
                for page in pdf_reader.pages:
                    text = page.extract_text()
                    if text:
                        text_parts.append(text)
            return "\n".join(text_parts)
            
    async def _process_report_text(
        self,
        job_id: str,
        text_content: str,
        report_name: str,
        config: Dict[str, Any],
        source_type: str
    ):
        """Process report text content.
        
        Args:
            job_id: Job identifier
            text_content: Report text content
            report_name: Report name
            config: Processing configuration
            source_type: Source type (pdf, text, etc)
        """
        # Update progress
        self.job_store.update(job_id, {
            "progress": 30,
            "message": "Analyzing document size and preparing extraction..."
        })
        
        # Create report SDO first
        report_sdo = {
            "type": "report",
            "id": f"report--{uuid.uuid4()}",
            "name": report_name or f"Report {datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            "description": text_content[:500],
            "published": datetime.utcnow().isoformat() + "Z",
            "object_refs": []
        }
        
        # Determine extraction strategy based on document size
        text_length = len(text_content)
        logger.info(f"Processing document of {text_length} characters")
        
        # Decision logic for extraction strategy
        USE_CHUNKED_THRESHOLD = 10_000  # 10KB
        
        if text_length < USE_CHUNKED_THRESHOLD:
            # Small document: Use direct extraction pipeline
            logger.info(f"Using direct extraction for small document ({text_length} chars)")
            
            extraction_config = {
                "use_batch_mapper": True,
                "use_batch_retriever": True,
                "skip_verification": config.get("skip_verification", False),
                "max_spans": 30,  # Increased for better coverage
                "disable_discovery": False,
                "disable_targeted_extraction": True
            }
            
            # Neo4j config for flow building
            neo4j_config = {
                "uri": settings.neo4j_uri,
                "user": settings.neo4j_user,
                "password": settings.neo4j_password
            }
            
            # Progress callback to update job status
            def update_progress(progress: int, message: str):
                self.job_store.update(job_id, {
                    "progress": progress,
                    "message": message
                })
                # Also update heartbeat for Redis store
                if self.use_redis and self.current_job_id == job_id:
                    self.job_store.update_heartbeat(job_id)
            
            # Run unified extraction pipeline (extraction + flow + review package)
            pipeline_results = run_extraction_pipeline(
                report_text=text_content,
                config=extraction_config,
                source_id=report_sdo["id"],
                neo4j_config=neo4j_config,
                progress_callback=update_progress
            )
            
        else:
            # Large document: Use chunked extraction with dynamic parameters
            max_chunks, spans_per_chunk, total_spans = self.calculate_chunks_and_spans(text_length)
            
            logger.info(f"Using chunked extraction for large document ({text_length} chars)")
            logger.info(f"Configuration: {max_chunks} chunks, {spans_per_chunk} spans/chunk, {total_spans} total spans")
            
            # Update progress
            self.job_store.update(job_id, {
                "progress": 35,
                "message": f"Processing large document in {max_chunks} chunks..."
            })
            
            # Configure chunked extraction with dynamic parameters
            chunk_config = {
                "use_batch_mapper": True,
                "use_batch_retriever": True,
                "skip_verification": config.get("skip_verification", False),
                "disable_discovery": False,
                "disable_targeted_extraction": True,
                "max_spans": spans_per_chunk,  # Dynamic spans per chunk
                "span_score_threshold": 0.9 if text_length > 100_000 else 0.85,  # Stricter for very large docs
                "confidence_threshold": 60 if text_length > 100_000 else 50
            }
            
            # Use optimized extractor if enabled (default: true)
            use_optimized = os.getenv("USE_OPTIMIZED_EXTRACTOR", "true").lower() == "true"
            
            if use_optimized:
                logger.info("Using OptimizedChunkedExtractor with smart span detection")
                extractor = OptimizedChunkedExtractor(
                    chunk_size=4000,  # Larger chunks for better context
                    overlap=150,      # Less overlap
                    max_chunks=max_chunks,
                    parallel_workers=1,  # Sequential to avoid rate limits
                    window_size=30000,  # ~8K tokens for span detection windows
                    window_overlap=5000  # ~1.5K tokens overlap
                )
            else:
                logger.info("Using standard ChunkedExtractor")
                extractor = ChunkedExtractor(
                    chunk_size=4000,  # Larger chunks for better context
                    overlap=150,      # Less overlap
                    max_chunks=max_chunks,
                    parallel_workers=1  # Sequential to avoid rate limits
                )
            
            # Progress callback for chunked extraction
            def update_chunk_progress(progress: int, message: str):
                self.job_store.update(job_id, {
                    "progress": progress,
                    "message": message
                })
            
            # Run chunked extraction with progress callback
            extraction_results = extractor.extract(
                text=text_content,
                config=chunk_config,
                parallel=True,
                progress_callback=update_chunk_progress
            )
            
            # Build flow from chunked results
            from bandjacks.llm.flow_builder import FlowBuilder
            
            self.job_store.update(job_id, {
                "progress": 70,
                "message": "Building attack flow from extracted techniques..."
            })
            
            flow_builder = FlowBuilder(
                settings.neo4j_uri,
                settings.neo4j_user,
                settings.neo4j_password
            )
            
            # Prepare extraction data for flow building
            flow_extraction_data = {
                "extraction_claims": extraction_results.get("claims", []),
                "techniques": extraction_results.get("techniques", {}),
                "chunks": [{
                    "claims": extraction_results.get("claims", []),
                    "entities": extraction_results.get("entities", {})
                }]
            }
            
            # Build flow
            flow_data = None
            try:
                flow_result = flow_builder.build_from_extraction(
                    extraction_data=flow_extraction_data,
                    source_id=report_sdo["id"],
                    report_text=text_content,
                    use_stored_text=False
                )
                
                if flow_result:
                    flow_data = {
                        "flow_id": flow_result.get("id"),
                        "flow_name": flow_result.get("name"),
                        "flow_type": "llm_synthesized" if flow_result.get("llm_synthesized") else "deterministic",
                        "steps": flow_result.get("actions", []),
                        "edges": flow_result.get("edges", []),
                        "confidence": flow_result.get("confidence", 0.5)
                    }
            except Exception as e:
                logger.error(f"Failed to build flow: {e}")
            
            # Package results similar to pipeline
            pipeline_results = {
                "techniques": extraction_results.get("techniques", {}),
                "technique_count": len(extraction_results.get("techniques", {})),
                "claims": extraction_results.get("claims", []),
                "entities": extraction_results.get("entities", {}),
                "flow": flow_data,
                "evidence_map": {},
                "requires_manual_review": True,
                "metrics": extraction_results.get("metrics", {})
            }
        
        # Extract the results
        extraction_results = {
            "techniques": pipeline_results.get("techniques", {}),
            "techniques_count": pipeline_results.get("technique_count", 0),
            "claims": pipeline_results.get("claims", []),
            "entities": pipeline_results.get("entities", {}),
        }
        
        # Update progress
        self.job_store.update(job_id, {
            "progress": 70,
            "message": "Creating STIX bundle..."
        })
        
        # Create STIX bundle
        bundle = self._create_stix_bundle(report_sdo, extraction_results)
        
        # Get flow data from pipeline results
        flow_data = pipeline_results.get("flow")
        if flow_data:
            self.job_store.update(job_id, {
                "progress": 80,
                "message": "Attack flow generated successfully"
            })
        else:
            logger.warning("No attack flow generated")
        
        # NOTE: Entity graph creation moved to post-review approval
        # We no longer create entities during extraction to ensure the graph
        # is only modified after human review and approval
        
        # Store extracted entities in results for review, but don't create nodes
        entities = pipeline_results.get("entities", {})
        if entities:
            logger.info(f"Extracted entities for review: {len(entities.get('entities', []))} entities")
            # Optionally resolve to existing entities for reference (read-only)
            # This helps show "this might be existing entity X" in review UI
            self._resolve_entities_for_reference(entities, report_sdo["id"])
                
        # Save to OpenSearch
        self.job_store.update(job_id, {
            "progress": 90,
            "message": "Saving to database..."
        })
        
        os_client = get_opensearch_client()
        os_store = OpenSearchReportStore(os_client)
        
        claims = extraction_results.get("claims", [])
        
        os_store.save_report(
            report_id=report_sdo["id"],
            job_id=job_id,
            report_data=report_sdo,
            extraction_result={
                "techniques_count": extraction_results.get("techniques_count", 0),
                "claims_count": len(claims),
                "bundle_preview": bundle,
                "extraction_claims": claims,
                "entities": extraction_results.get("entities", {}),
                "flow": flow_data,
                "review_package": {
                    "evidence_map": pipeline_results.get("evidence_map", {}),
                    "requires_manual_review": pipeline_results.get("requires_manual_review", True),
                    "metrics": pipeline_results.get("metrics", {})
                }
            },
            source_info={
                "type": source_type,
                "content_size": len(text_content)
            },
            raw_text=text_content,
            text_chunks=self._create_text_chunks(text_content)
        )
        
        # Mark job as completed
        result_data = {
            "report_id": report_sdo["id"],
            "techniques_count": extraction_results.get("techniques_count", 0),
            "claims_count": len(claims),
            "flow_generated": flow_data is not None,
            "bundle_size": len(bundle.get("objects", [])),
            "review_required": True
        }
        
        if self.use_redis:
            # Use Redis store's atomic completion
            self.job_store.complete_job(job_id, result_data)
        else:
            # Legacy file-based completion
            self.job_store.update(job_id, {
                "status": "completed",
                "progress": 100,
                "message": f"Extracted {extraction_results.get('techniques_count', 0)} techniques",
                "completed_at": datetime.utcnow().isoformat(),
                "result": result_data
            })
        
        logger.info(f"Completed job {job_id}: {extraction_results.get('techniques_count', 0)} techniques")
        
    def _create_stix_bundle(
        self,
        report_sdo: Dict[str, Any],
        extraction_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create STIX bundle from extraction results."""
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": [report_sdo]
        }
        
        # Add extracted techniques
        for technique_id, technique_data in extraction_results.get("techniques", {}).items():
            technique_obj = {
                "type": "attack-pattern",
                "id": technique_id,
                "name": technique_data.get("name", "Unknown"),
                "x_bj_confidence": technique_data.get("confidence", 50.0)
            }
            bundle["objects"].append(technique_obj)
            report_sdo["object_refs"].append(technique_id)
            
        return bundle
        
    def _create_entity_graph(
        self,
        entities: Dict[str, Any],
        primary_entity: Optional[Dict[str, Any]],
        techniques: Dict[str, Any],
        report_id: str,
        flow_data: Optional[Dict[str, Any]] = None
    ):
        """
        Create entity nodes and relationships in Neo4j.
        
        Creates:
        - Entity nodes (Software, IntrusionSet, etc.)
        - USES relationships (Entity -> AttackPattern)
        - EXTRACTED_FROM relationships (AttackPattern -> Report)
        - ATTRIBUTED_TO relationships (AttackEpisode -> Entity)
        """
        from bandjacks.llm.entity_resolver import EntityResolver
        from neo4j import GraphDatabase
        
        # Initialize entity resolver
        resolver = EntityResolver(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password)
        )
        
        try:
            with driver.session() as session:
                # Process entities in new format
                entity_ids = []
                
                # Handle new format: {"entities": [{"name": str, "type": str}], "extraction_status": str}
                if isinstance(entities, dict) and "entities" in entities:
                    entity_list = entities.get("entities", [])
                    logger.info(f"Processing {len(entity_list)} entities in new format")
                    
                    for entity in entity_list:
                        if isinstance(entity, dict):
                            entity_type = entity.get("type", "unknown")
                            entity_name = entity.get("name", "")
                            
                            if entity_name:
                                # Map entity types to resolver types
                                type_mapping = {
                                    "group": "threat_actor",
                                    "intrusion-set": "threat_actor",
                                    "threat-actor": "threat_actor",
                                    "malware": "malware",
                                    "tool": "software",
                                    "software": "software",
                                    "campaign": "campaign"
                                }
                                
                                resolver_type = type_mapping.get(entity_type.lower(), entity_type)
                                
                                try:
                                    entity_id = resolver.resolve_or_create(
                                        entity=entity,
                                        entity_type=resolver_type,
                                        source_id=report_id
                                    )
                                    if entity_id:
                                        entity_ids.append(entity_id)
                                        logger.info(f"Created/resolved entity: {entity_name} ({resolver_type}) -> {entity_id}")
                                except Exception as e:
                                    logger.warning(f"Failed to resolve entity {entity_name}: {e}")
                
                # Legacy: Handle primary_entity if provided separately
                primary_entity_id = None
                if primary_entity and isinstance(primary_entity, dict):
                    try:
                        primary_entity_id = resolver.resolve_or_create(
                            entity=primary_entity,
                            entity_type=primary_entity.get("type", "malware"),
                            source_id=report_id
                        )
                        if primary_entity_id and primary_entity_id not in entity_ids:
                            entity_ids.append(primary_entity_id)
                            logger.info(f"Primary entity: {primary_entity.get('name')} -> {primary_entity_id}")
                    except Exception as e:
                        logger.warning(f"Failed to resolve primary entity: {e}")
                
                # Create USES relationships from entities to techniques
                for entity_id in entity_ids:
                    for tech_id in techniques.keys():
                        # Ensure technique ID is in STIX format
                        if not tech_id.startswith("attack-pattern--"):
                            # Query for STIX ID from external ID
                            result = session.run(
                                "MATCH (t:AttackPattern) WHERE t.external_id = $ext_id "
                                "RETURN t.stix_id as stix_id LIMIT 1",
                                ext_id=tech_id
                            )
                            record = result.single()
                            if record:
                                tech_stix_id = record["stix_id"]
                            else:
                                continue
                        else:
                            tech_stix_id = tech_id
                        
                        # Create USES relationship
                        session.run("""
                            MATCH (e {stix_id: $entity_id})
                            MATCH (t:AttackPattern {stix_id: $tech_id})
                            MERGE (e)-[:USES]->(t)
                        """, entity_id=entity_id, tech_id=tech_stix_id)
                        
                        logger.debug(f"Created USES: {entity_id} -> {tech_stix_id}")
                
                # Create EXTRACTED_FROM relationships from techniques to report
                session.run("""
                    MERGE (r:Report {stix_id: $report_id})
                    ON CREATE SET r.name = $report_name,
                                  r.created = $created,
                                  r.type = 'report'
                """, report_id=report_id, 
                    report_name=f"Extracted Report {datetime.utcnow().strftime('%Y-%m-%d')}",
                    created=datetime.utcnow().isoformat() + "Z")
                
                for tech_id, tech_data in techniques.items():
                    if not tech_id.startswith("attack-pattern--"):
                        continue
                    
                    session.run("""
                        MATCH (t:AttackPattern {stix_id: $tech_id})
                        MATCH (r:Report {stix_id: $report_id})
                        MERGE (t)-[:EXTRACTED_FROM {
                            confidence: $confidence,
                            evidence: $evidence
                        }]->(r)
                    """, tech_id=tech_id, report_id=report_id,
                        confidence=tech_data.get("confidence", 50),
                        evidence=str(tech_data.get("evidence", []))[:500])
                
                # If we have a flow, create ATTRIBUTED_TO relationship
                if flow_data and primary_entity_id:
                    episode_id = flow_data.get("episode_id")
                    if episode_id:
                        session.run("""
                            MATCH (e:AttackEpisode {episode_id: $episode_id})
                            MATCH (entity {stix_id: $entity_id})
                            MERGE (e)-[:ATTRIBUTED_TO]->(entity)
                        """, episode_id=episode_id, entity_id=primary_entity_id)
                        
                        logger.info(f"Created ATTRIBUTED_TO: {episode_id} -> {primary_entity_id}")
                
        finally:
            resolver.close()
            driver.close()
    
    def _create_text_chunks(
        self, 
        text: str, 
        chunk_size: int = 3000, 
        overlap: int = 200
    ) -> list:
        """Create overlapping text chunks for storage."""
        chunks = []
        for i in range(0, len(text), chunk_size - overlap):
            chunk_text = text[i:i + chunk_size]
            chunks.append({
                "chunk_id": len(chunks),
                "text": chunk_text,
                "start_idx": i,
                "end_idx": min(i + chunk_size, len(text))
            })
        return chunks
    
    def _resolve_entities_for_reference(
        self,
        entities: Dict[str, Any],
        report_id: str
    ):
        """
        Resolve entities to existing nodes for reference only (read-only).
        Does NOT create any new nodes - only looks up existing ones.
        
        This helps show "this might be existing entity X" in the review UI
        without modifying the graph.
        """
        from bandjacks.llm.entity_resolver import EntityResolver
        
        try:
            resolver = EntityResolver(
                neo4j_uri=settings.neo4j_uri,
                neo4j_user=settings.neo4j_user,
                neo4j_password=settings.neo4j_password
            )
            
            # Process entities in new format
            if isinstance(entities, dict) and "entities" in entities:
                entity_list = entities.get("entities", [])
                
                for entity in entity_list:
                    if isinstance(entity, dict):
                        entity_name = entity.get("name", "")
                        entity_type = entity.get("type", "unknown")
                        
                        if entity_name:
                            # Only resolve, don't create
                            existing_id = resolver.resolve_entity(
                                entity_name=entity_name,
                                entity_type=entity_type,
                                threshold=0.85
                            )
                            
                            if existing_id:
                                # Add resolved ID to entity for reference
                                entity["resolved_stix_id"] = existing_id
                                entity["resolution_status"] = "matched_existing"
                                logger.info(f"Resolved '{entity_name}' to existing: {existing_id}")
                            else:
                                entity["resolution_status"] = "new_entity"
                                logger.info(f"'{entity_name}' appears to be a new entity")
                                
        except Exception as e:
            logger.warning(f"Failed to resolve entities for reference: {e}")
            # Non-critical - continue without resolution
        


# Global processor instance
_job_processor: Optional[JobProcessor] = None


def get_job_processor() -> JobProcessor:
    """Get the global job processor instance."""
    global _job_processor
    if _job_processor is None:
        # Always use Redis job store
        _job_processor = JobProcessor(get_redis_job_store())
    return _job_processor