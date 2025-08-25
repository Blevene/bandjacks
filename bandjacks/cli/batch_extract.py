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
from bandjacks.services.api.routes.reports import extract_text_from_pdf
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class BatchExtractor:
    """Batch extraction processor for threat reports."""
    
    def __init__(
        self,
        workers: int = 3,
        use_api: bool = False,
        api_url: str = "http://localhost:8000",
        chunk_size: int = 3000,
        max_chunks: int = 10
    ):
        self.workers = workers
        self.use_api = use_api
        self.api_url = api_url
        self.chunk_size = chunk_size
        self.max_chunks = max_chunks
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
  
  # Customize chunking parameters
  python -m bandjacks.cli.batch_extract --chunk-size 4000 --max-chunks 15 ./reports/
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
    print("=" * 60)
    
    # Create batch extractor
    extractor = BatchExtractor(
        workers=args.workers,
        use_api=args.api,
        api_url=args.api_url,
        chunk_size=args.chunk_size,
        max_chunks=args.max_chunks
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