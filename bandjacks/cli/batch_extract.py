#!/usr/bin/env python3
"""
Batch extraction CLI for processing multiple threat reports.

Usage:
    python -m bandjacks.cli.batch_extract ./reports/
    python -m bandjacks.cli.batch_extract --api ./reports/
    python -m bandjacks.cli.batch_extract --workers 5 ./reports/*.pdf
"""

import sys
import json
import time
import asyncio
from pathlib import Path
import argparse
from datetime import datetime
import concurrent.futures
from typing import List, Dict, Any
import httpx

import PyPDF2
from bandjacks.llm.chunked_extractor import extract_chunked
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def extract_text_from_pdf(pdf_path: str) -> str:
    """Extract text from a PDF file."""
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
        text_parts = []
        with open(pdf_path, 'rb') as f:
            pdf_reader = PyPDF2.PdfReader(f)
            for page in pdf_reader.pages:
                text_parts.append(page.extract_text())
        return '\n'.join(text_parts)


class BatchExtractor:
    """Batch extraction processor for threat reports."""

    def __init__(
        self,
        workers: int = 3,
        use_api: bool = False,
        api_url: str = "http://localhost:8000",
        chunk_size: int = 3000,
        max_chunks: int = 10,
        store_in_neo4j: bool = False,
        neo4j_uri: str = None,
        neo4j_user: str = None,
        neo4j_password: str = None,
        skip_entity_extraction: bool = False,
        auto_approve: bool = False,
        auto_approve_threshold: float = 0.80
    ):
        self.workers = workers
        self.use_api = use_api
        self.api_url = api_url
        self.chunk_size = chunk_size
        self.max_chunks = max_chunks
        self.store_in_neo4j = store_in_neo4j
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_password = neo4j_password
        self.skip_entity_extraction = skip_entity_extraction
        self.auto_approve = auto_approve
        self.auto_approve_threshold = auto_approve_threshold
        self.results = []
        self.start_time = time.time()
    
    def extract_text_from_file(self, file_path: Path) -> str:
        """Extract text from various file formats."""
        
        if file_path.suffix.lower() == '.pdf':
            # Use pdfplumber for better extraction
            return extract_text_from_pdf(str(file_path))
        
        elif file_path.suffix.lower() in ['.txt', '.md']:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        
        else:
            raise ValueError(f"Unsupported file format: {file_path.suffix}")
    
    def process_file_direct(self, file_path: Path) -> Dict[str, Any]:
        """Process a single file using direct Python API with chunked extraction."""
        
        start_time = time.time()
        
        result = {
            "file": file_path.name,
            "path": str(file_path),
            "status": "pending",
            "techniques": [],
            "count": 0,
            "processing_time": 0,
            "chunks_used": 0,
            "error": None
        }
        
        try:
            # Extract text
            print(f"📄 Extracting text from {file_path.name}...")
            text = self.extract_text_from_file(file_path)
            result["text_length"] = len(text)
            
            # Configure extraction with optimizations
            config = {
                "use_batch_mapper": True,
                "disable_discovery": True,
                "disable_targeted_extraction": True,
                "skip_verification": True,
                "max_spans": 5,
                "span_score_threshold": 0.85,
                "confidence_threshold": 50.0,
                "model": os.getenv("PRIMARY_LLM", "gemini/gemini-2.5-flash"),
                "skip_entity_extraction": getattr(self, 'skip_entity_extraction', False),
                "auto_approve": getattr(self, 'auto_approve', False),
                "auto_approve_threshold": getattr(self, 'auto_approve_threshold', 0.80),
            }
            
            # Use chunked extraction
            print(f"🔍 Processing {file_path.name} ({len(text)} chars)...")
            extraction_result = extract_chunked(
                text=text,
                config=config,
                chunk_size=self.chunk_size,
                overlap=200,
                max_chunks=self.max_chunks,
                parallel=True
            )
            
            techniques = extraction_result.get("techniques", {})
            result["techniques"] = list(techniques.keys())
            result["count"] = len(techniques)
            result["chunks_used"] = extraction_result.get("metrics", {}).get("total_chunks", 0)
            result["status"] = "success"
            result["technique_details"] = techniques

            # Calculate average confidence for auto-approval
            if techniques:
                confidences = [t.get("confidence", 50.0) / 100.0 for t in techniques.values()]
                result["average_confidence"] = sum(confidences) / len(confidences)
            else:
                result["average_confidence"] = 0.0
            
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            print(f"❌ Error processing {file_path.name}: {e}")
        
        result["processing_time"] = round(time.time() - start_time, 2)
        return result
    
    async def process_file_api_async(self, file_path: Path) -> Dict[str, Any]:
        """Process a single file using the async REST API."""
        
        start_time = time.time()
        
        result = {
            "file": file_path.name,
            "path": str(file_path),
            "status": "pending",
            "techniques": [],
            "count": 0,
            "processing_time": 0,
            "job_id": None,
            "error": None
        }
        
        try:
            # Upload file to async endpoint
            async with httpx.AsyncClient(timeout=300) as client:
                with open(file_path, 'rb') as f:
                    files = {'file': (file_path.name, f, 'application/pdf')}
                    data = {
                        'config': json.dumps({
                            "use_batch_mapper": True,
                            "disable_discovery": True,
                            "skip_verification": True,
                            "confidence_threshold": 50.0
                        })
                    }
                    
                    # Start async job
                    response = await client.post(
                        f"{self.api_url}/v1/reports/ingest_file_async",
                        files=files,
                        data=data
                    )
                    response.raise_for_status()
                    
                    job_data = response.json()
                    job_id = job_data["job_id"]
                    result["job_id"] = job_id
                    
                    # Poll for completion
                    max_polls = 60  # 5 minutes max
                    for _ in range(max_polls):
                        await asyncio.sleep(5)  # Check every 5 seconds
                        
                        status_response = await client.get(
                            f"{self.api_url}/v1/reports/jobs/{job_id}/status"
                        )
                        status_response.raise_for_status()
                        
                        status = status_response.json()
                        
                        if status["status"] == "completed":
                            # Extract results
                            job_result = status.get("result", {})
                            result["count"] = job_result.get("techniques_count", 0)
                            result["status"] = "success"
                            break
                        
                        elif status["status"] == "failed":
                            result["status"] = "error"
                            result["error"] = status.get("error", "Unknown error")
                            break
                    
                    else:
                        # Timeout
                        result["status"] = "error"
                        result["error"] = "Job timeout"
        
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
        
        result["processing_time"] = round(time.time() - start_time, 2)
        return result

    def store_result_in_neo4j(self, result: Dict[str, Any]) -> bool:
        """
        Store extraction result in Neo4j as AttackEpisode with AttackActions.

        If auto-approved, creates full USES relationships to AttackPattern nodes.
        If review required, only creates AttackAction nodes pending review.

        Args:
            result: Extraction result dictionary

        Returns:
            True if successful, False otherwise
        """
        if not self.store_in_neo4j or result["status"] != "success":
            return False

        try:
            from neo4j import GraphDatabase
            import uuid
            from datetime import datetime

            # Check if auto-approved based on extraction config
            is_auto_approved = self.auto_approve and result.get("average_confidence", 0) >= self.auto_approve_threshold

            driver = GraphDatabase.driver(
                self.neo4j_uri,
                auth=(self.neo4j_user, self.neo4j_password)
            )

            with driver.session() as session:
                # Create AttackEpisode node
                episode_id = f"attack-episode--{uuid.uuid4()}"
                episode_name = f"Extracted from {result['file']}"

                session.run("""
                    CREATE (e:AttackEpisode {
                        stix_id: $episode_id,
                        name: $name,
                        created: $created,
                        source_file: $source_file,
                        extraction_timestamp: $timestamp,
                        auto_approved: $auto_approved
                    })
                """, episode_id=episode_id, name=episode_name,
                    created=datetime.utcnow().isoformat() + "Z",
                    source_file=result['file'],
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    auto_approved=is_auto_approved)

                # Create AttackAction nodes for each technique
                action_ids = {}
                for technique_id in result.get("techniques", []):
                    # Get technique details if available
                    tech_details = result.get("technique_details", {}).get(technique_id, {})
                    confidence = tech_details.get("confidence", 50.0)

                    action_id = f"attack-action--{uuid.uuid4()}"
                    action_ids[technique_id] = action_id

                    # Create AttackAction node
                    session.run("""
                        MATCH (e:AttackEpisode {stix_id: $episode_id})
                        CREATE (a:AttackAction {
                            stix_id: $action_id,
                            attack_pattern_ref: $technique_id,
                            confidence: $confidence,
                            created: $created,
                            auto_approved: $auto_approved
                        })
                        CREATE (e)-[:CONTAINS]->(a)
                    """, episode_id=episode_id, action_id=action_id,
                        technique_id=technique_id, confidence=confidence,
                        created=datetime.utcnow().isoformat() + "Z",
                        auto_approved=is_auto_approved)

                    # If auto-approved, create USES relationship to AttackPattern
                    if is_auto_approved:
                        session.run("""
                            MATCH (action:AttackAction {stix_id: $action_id})
                            MATCH (pattern:AttackPattern {stix_id: $technique_id})
                            MERGE (action)-[:USES {
                                confidence: $confidence,
                                auto_approved: true,
                                approved_at: $timestamp
                            }]->(pattern)
                        """, action_id=action_id, technique_id=technique_id,
                            confidence=confidence,
                            timestamp=datetime.utcnow().isoformat() + "Z")

                # Link to extracted entities if available (unless entity extraction was skipped)
                if not self.skip_entity_extraction:
                    entities = result.get("entities", {})
                    if entities and isinstance(entities, dict):
                        for entity in entities.get("entities", []):
                            entity_name = entity.get("name", "")
                            entity_type = entity.get("type", "")

                            if entity_name:
                                # Try to find existing entity node
                                existing = session.run("""
                                    MATCH (n)
                                    WHERE n.name =~ $pattern
                                      AND (n:IntrusionSet OR n:Malware OR n:Tool OR n:Campaign)
                                    RETURN n.stix_id as id
                                    LIMIT 1
                                """, pattern=f"(?i).*{entity_name}.*").single()

                                if existing:
                                    # Link episode to existing entity
                                    session.run("""
                                        MATCH (e:AttackEpisode {stix_id: $episode_id})
                                        MATCH (entity {stix_id: $entity_id})
                                        MERGE (e)-[:ATTRIBUTED_TO]->(entity)
                                    """, episode_id=episode_id, entity_id=existing["id"])

                status_msg = "auto-approved" if is_auto_approved else "pending review"
                print(f"  ✓ Stored in Neo4j: {episode_id} ({len(result.get('techniques', []))} techniques, {status_msg})")
                result["neo4j_episode_id"] = episode_id
                result["auto_approved"] = is_auto_approved
                return True

        except Exception as e:
            print(f"  ⚠ Failed to store in Neo4j: {e}")
            return False
        finally:
            try:
                driver.close()
            except:
                pass

    def process_files(self, file_paths: List[Path]) -> List[Dict[str, Any]]:
        """Process multiple files with parallel workers."""
        
        results = []
        
        if self.use_api:
            # Use async API processing
            print(f"🌐 Using API at {self.api_url}")
            
            async def process_all():
                tasks = []
                for file_path in file_paths:
                    task = self.process_file_api_async(file_path)
                    tasks.append(task)
                
                # Process with limited concurrency
                sem = asyncio.Semaphore(self.workers)
                
                async def process_with_sem(file_path):
                    async with sem:
                        return await self.process_file_api_async(file_path)
                
                tasks = [process_with_sem(fp) for fp in file_paths]
                return await asyncio.gather(*tasks)
            
            results = asyncio.run(process_all())
        
        else:
            # Use direct Python processing with thread pool
            print(f"🐍 Using direct Python with {self.workers} workers")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
                futures = {
                    executor.submit(self.process_file_direct, file_path): file_path
                    for file_path in file_paths
                }
                
                for future in concurrent.futures.as_completed(futures):
                    file_path = futures[future]
                    try:
                        result = future.result(timeout=300)  # 5 minute timeout

                        # Store in Neo4j if requested
                        if self.store_in_neo4j and result["status"] == "success":
                            self.store_result_in_neo4j(result)

                        results.append(result)

                        status_icon = "✅" if result["status"] == "success" else "❌"
                        print(f"{status_icon} {file_path.name}: {result['count']} techniques ({result['processing_time']:.1f}s)")

                    except concurrent.futures.TimeoutError:
                        results.append({
                            "file": file_path.name,
                            "path": str(file_path),
                            "status": "error",
                            "error": "Timeout",
                            "techniques": [],
                            "count": 0,
                            "processing_time": 300
                        })
                        print(f"⏱️ {file_path.name}: Timeout")
                    
                    except Exception as e:
                        results.append({
                            "file": file_path.name,
                            "path": str(file_path),
                            "status": "error",
                            "error": str(e),
                            "techniques": [],
                            "count": 0,
                            "processing_time": 0
                        })
                        print(f"❌ {file_path.name}: {e}")
        
        self.results = results
        return results
    
    def generate_report(self, output_dir: Path) -> tuple[Path, Path]:
        """Generate summary report of batch processing results."""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create summary
        total_time = time.time() - self.start_time
        summary = {
            "timestamp": timestamp,
            "total_files": len(self.results),
            "successful": sum(1 for r in self.results if r["status"] == "success"),
            "failed": sum(1 for r in self.results if r["status"] == "error"),
            "total_techniques": len(set(t for r in self.results for t in r.get("techniques", []))),
            "total_processing_time": total_time,
            "average_time_per_file": total_time / max(1, len(self.results)),
            "configuration": {
                "workers": self.workers,
                "chunk_size": self.chunk_size,
                "max_chunks": self.max_chunks,
                "use_api": self.use_api
            },
            "files": self.results
        }
        
        # Save JSON report
        json_file = output_dir / f"batch_report_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Generate markdown report
        md_file = output_dir / f"batch_report_{timestamp}.md"
        with open(md_file, 'w') as f:
            f.write(f"# Batch Extraction Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write(f"## Summary\n\n")
            f.write(f"- **Total Files:** {summary['total_files']}\n")
            f.write(f"- **Successful:** {summary['successful']}\n")
            f.write(f"- **Failed:** {summary['failed']}\n")
            f.write(f"- **Unique Techniques:** {summary['total_techniques']}\n")
            f.write(f"- **Total Time:** {summary['total_processing_time']:.2f} seconds\n")
            f.write(f"- **Average Time:** {summary['average_time_per_file']:.2f} seconds per file\n\n")
            
            f.write(f"## Configuration\n\n")
            f.write(f"- **Workers:** {self.workers}\n")
            f.write(f"- **Chunk Size:** {self.chunk_size} chars\n")
            f.write(f"- **Max Chunks:** {self.max_chunks}\n")
            f.write(f"- **Mode:** {'API' if self.use_api else 'Direct Python'}\n\n")
            
            f.write(f"## File Results\n\n")
            
            for result in sorted(self.results, key=lambda x: x.get("count", 0), reverse=True):
                status_icon = "✅" if result["status"] == "success" else "❌"
                f.write(f"### {status_icon} {result['file']}\n\n")
                f.write(f"- **Status:** {result['status']}\n")
                f.write(f"- **Techniques Found:** {result['count']}\n")
                f.write(f"- **Processing Time:** {result['processing_time']:.2f}s\n")
                f.write(f"- **Text Length:** {result.get('text_length', 0):,} characters\n")
                
                if result.get("chunks_used"):
                    f.write(f"- **Chunks Processed:** {result['chunks_used']}\n")
                
                if result["status"] == "error":
                    f.write(f"- **Error:** {result['error']}\n")
                
                if result.get("techniques"):
                    f.write(f"\n**Top Techniques:**\n")
                    for tech_id in result["techniques"][:10]:
                        details = result.get("technique_details", {}).get(tech_id, {})
                        name = details.get("name", "Unknown")
                        conf = details.get("confidence", 0)
                        f.write(f"- {tech_id}: {name} ({conf}%)\n")
                    
                    if len(result["techniques"]) > 10:
                        f.write(f"- ... and {len(result['techniques']) - 10} more\n")
                
                f.write("\n")
        
        return json_file, md_file


def main():
    parser = argparse.ArgumentParser(
        description="Batch extract techniques from threat reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process all PDFs in a directory
  python -m bandjacks.cli.batch_extract ./reports/

  # Use async API for processing
  python -m bandjacks.cli.batch_extract --api ./reports/

  # Process with 5 parallel workers
  python -m bandjacks.cli.batch_extract --workers 5 ./reports/*.pdf

  # Process and store in Neo4j for analytics
  python -m bandjacks.cli.batch_extract --store-in-neo4j ./reports/

  # Customize chunking parameters
  python -m bandjacks.cli.batch_extract --chunk-size 4000 --max-chunks 15 ./reports/

  # Full workflow: Extract, store in Neo4j, then analyze
  python -m bandjacks.cli.batch_extract --store-in-neo4j ./reports/
  bandjacks analytics global --format csv --output cooccurrence.csv
        """
    )
    
    parser.add_argument("paths", nargs="+", help="Files or directories to process")
    parser.add_argument("--api", action="store_true", help="Use REST API instead of direct Python")
    parser.add_argument("--api-url", default="http://localhost:8000", help="API base URL")
    parser.add_argument("--workers", type=int, default=3, help="Number of parallel workers")
    parser.add_argument("--chunk-size", type=int, default=3000, help="Size of text chunks")
    parser.add_argument("--max-chunks", type=int, default=10, help="Maximum chunks per document")
    parser.add_argument("--extensions", nargs="+", default=[".pdf", ".txt", ".md"],
                       help="File extensions to process")
    parser.add_argument("--output-dir", default="batch_results", help="Output directory for reports")
    parser.add_argument("--store-in-neo4j", action="store_true",
                       help="Store results in Neo4j for analytics")
    parser.add_argument("--neo4j-uri", default=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
                       help="Neo4j connection URI")
    parser.add_argument("--neo4j-user", default=os.getenv("NEO4J_USER", "neo4j"),
                       help="Neo4j username")
    parser.add_argument("--neo4j-password", default=os.getenv("NEO4J_PASSWORD", "password"),
                       help="Neo4j password")
    parser.add_argument("--skip-entity-extraction", action="store_true",
                       help="Skip entity extraction (faster, techniques only)")
    parser.add_argument("--auto-approve", action="store_true",
                       help="Auto-approve high-confidence techniques and flows")
    parser.add_argument("--auto-approve-threshold", type=float, default=0.80,
                       help="Confidence threshold for auto-approval (0.0-1.0, default: 0.80)")

    args = parser.parse_args()
    
    # Collect all files to process
    files_to_process = []
    
    for path_str in args.paths:
        path = Path(path_str)
        
        if path.is_file():
            # Single file
            if path.suffix.lower() in args.extensions:
                files_to_process.append(path)
        elif path.is_dir():
            # Directory - find all matching files
            for ext in args.extensions:
                files_to_process.extend(path.glob(f"*{ext}"))
                files_to_process.extend(path.glob(f"**/*{ext}"))  # Recursive
        else:
            # Glob pattern
            parent = path.parent
            pattern = path.name
            if parent.exists():
                files_to_process.extend(parent.glob(pattern))
    
    # Remove duplicates and sort
    files_to_process = sorted(list(set(files_to_process)))
    
    if not files_to_process:
        print(f"❌ No files found matching patterns: {args.paths}")
        print(f"   Extensions: {args.extensions}")
        sys.exit(1)
    
    print(f"📁 Found {len(files_to_process)} files to process")
    print(f"⚙️  Configuration:")
    print(f"   - Mode: {'API' if args.api else 'Direct Python'}")
    print(f"   - Workers: {args.workers}")
    print(f"   - Chunk size: {args.chunk_size} chars")
    print(f"   - Max chunks: {args.max_chunks}")
    if args.store_in_neo4j:
        print(f"   - Neo4j storage: Enabled")
        print(f"   - Neo4j URI: {args.neo4j_uri}")
    if args.skip_entity_extraction:
        print(f"   - Entity extraction: Skipped (techniques only)")
    if args.auto_approve:
        print(f"   - Auto-approve: Enabled (threshold: {args.auto_approve_threshold})")
    print("=" * 60)

    # Create batch extractor
    extractor = BatchExtractor(
        workers=args.workers,
        use_api=args.api,
        api_url=args.api_url,
        chunk_size=args.chunk_size,
        max_chunks=args.max_chunks,
        store_in_neo4j=args.store_in_neo4j,
        neo4j_uri=args.neo4j_uri,
        neo4j_user=args.neo4j_user,
        neo4j_password=args.neo4j_password,
        skip_entity_extraction=args.skip_entity_extraction,
        auto_approve=args.auto_approve,
        auto_approve_threshold=args.auto_approve_threshold
    )
    
    # Process files
    results = extractor.process_files(files_to_process)
    
    # Generate report
    print("\n" + "=" * 60)
    print("📊 Generating report...")
    
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    json_file, md_file = extractor.generate_report(output_dir)
    
    # Print summary
    successful = sum(1 for r in results if r["status"] == "success")
    failed = sum(1 for r in results if r["status"] == "error")
    total_techniques = len(set(t for r in results for t in r.get("techniques", [])))
    total_time = time.time() - extractor.start_time
    
    print(f"\n✅ Batch extraction complete!")
    print(f"   • Processed: {len(results)} files")
    print(f"   • Successful: {successful}")
    print(f"   • Failed: {failed}")
    print(f"   • Unique techniques: {total_techniques}")
    print(f"   • Total time: {total_time:.2f} seconds")
    print(f"   • Average time: {total_time/len(results):.2f} seconds per file")
    
    print(f"\n💾 Reports saved:")
    print(f"   • JSON: {json_file}")
    print(f"   • Markdown: {md_file}")


if __name__ == "__main__":
    main()