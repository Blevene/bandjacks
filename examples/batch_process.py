#!/usr/bin/env python3
"""
Example: Batch process multiple threat reports.

Usage:
    python batch_process.py ./reports/
    python batch_process.py --api ./reports/
"""

import sys
import json
import time
from pathlib import Path
import argparse
from datetime import datetime
import concurrent.futures

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import PyPDF2
import httpx
from bandjacks.llm.agentic_v2 import run_agentic_v2
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def extract_text_from_file(file_path: Path) -> str:
    """Extract text from various file formats."""
    
    if file_path.suffix.lower() == '.pdf':
        text_parts = []
        with open(file_path, 'rb') as f:
            pdf_reader = PyPDF2.PdfReader(f)
            for page in pdf_reader.pages:
                text_parts.append(page.extract_text())
        return '\n'.join(text_parts)
    
    elif file_path.suffix.lower() in ['.txt', '.md']:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    
    else:
        raise ValueError(f"Unsupported file format: {file_path.suffix}")


def process_file_direct(file_path: Path) -> dict:
    """Process a single file using direct Python API."""
    
    start_time = time.time()
    
    result = {
        "file": file_path.name,
        "path": str(file_path),
        "status": "pending",
        "techniques": [],
        "count": 0,
        "processing_time": 0,
        "error": None
    }
    
    try:
        # Extract text
        text = extract_text_from_file(file_path)
        result["text_length"] = len(text)
        
        # Configure extraction
        config = {
            "neo4j_uri": os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            "neo4j_user": os.getenv("NEO4J_USER", "neo4j"),
            "neo4j_password": os.getenv("NEO4J_PASSWORD", "password"),
            "model": os.getenv("PRIMARY_LLM", "gemini/gemini-2.5-flash"),
            "title": file_path.stem,
        }
        
        # Run extraction
        extraction_result = run_agentic_v2(text, config)
        techniques = extraction_result.get("techniques", {})
        
        result["techniques"] = list(techniques.keys())
        result["count"] = len(techniques)
        result["status"] = "success"
        result["technique_details"] = techniques
        
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    result["processing_time"] = round(time.time() - start_time, 2)
    return result


def process_file_api(file_path: Path, api_url: str) -> dict:
    """Process a single file using the REST API."""
    
    start_time = time.time()
    
    result = {
        "file": file_path.name,
        "path": str(file_path),
        "status": "pending",
        "techniques": [],
        "count": 0,
        "processing_time": 0,
        "error": None
    }
    
    try:
        # Extract text
        text = extract_text_from_file(file_path)
        result["text_length"] = len(text)
        
        # Call API
        response = httpx.post(
            f"{api_url}/v1/extract/report",
            json={
                "content": text,
                "method": "agentic_v2",
                "auto_ingest": False,
                "title": file_path.stem
            },
            timeout=120  # 2 minute timeout
        )
        response.raise_for_status()
        
        data = response.json()
        
        # Extract techniques from bundle
        techniques = {}
        for obj in data.get("bundle", {}).get("objects", []):
            if obj.get("type") == "attack-pattern":
                for ext_ref in obj.get("external_references", []):
                    if ext_ref.get("source_name") == "mitre-attack":
                        tech_id = ext_ref.get("external_id")
                        if tech_id:
                            techniques[tech_id] = {
                                "name": obj.get("name"),
                                "confidence": obj.get("x_bj_confidence", 50)
                            }
                            break
        
        result["techniques"] = list(techniques.keys())
        result["count"] = len(techniques)
        result["status"] = "success"
        result["technique_details"] = techniques
        result["extraction_id"] = data.get("extraction_id")
        
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    result["processing_time"] = round(time.time() - start_time, 2)
    return result


def generate_report(results: list, output_dir: Path):
    """Generate a summary report of batch processing results."""
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create summary
    summary = {
        "timestamp": timestamp,
        "total_files": len(results),
        "successful": sum(1 for r in results if r["status"] == "success"),
        "failed": sum(1 for r in results if r["status"] == "error"),
        "total_techniques": len(set(t for r in results for t in r.get("techniques", []))),
        "total_processing_time": sum(r["processing_time"] for r in results),
        "files": results
    }
    
    # Save JSON report
    json_file = output_dir / f"batch_report_{timestamp}.json"
    with open(json_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    # Generate markdown report
    md_file = output_dir / f"batch_report_{timestamp}.md"
    with open(md_file, 'w') as f:
        f.write(f"# Batch Processing Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write(f"## Summary\n\n")
        f.write(f"- **Total Files:** {summary['total_files']}\n")
        f.write(f"- **Successful:** {summary['successful']}\n")
        f.write(f"- **Failed:** {summary['failed']}\n")
        f.write(f"- **Unique Techniques:** {summary['total_techniques']}\n")
        f.write(f"- **Total Time:** {summary['total_processing_time']:.2f} seconds\n")
        f.write(f"- **Average Time:** {summary['total_processing_time']/len(results):.2f} seconds per file\n\n")
        
        f.write(f"## File Results\n\n")
        
        for result in sorted(results, key=lambda x: x["count"], reverse=True):
            status_icon = "✅" if result["status"] == "success" else "❌"
            f.write(f"### {status_icon} {result['file']}\n\n")
            f.write(f"- **Status:** {result['status']}\n")
            f.write(f"- **Techniques Found:** {result['count']}\n")
            f.write(f"- **Processing Time:** {result['processing_time']:.2f}s\n")
            f.write(f"- **Text Length:** {result.get('text_length', 0):,} characters\n")
            
            if result["status"] == "error":
                f.write(f"- **Error:** {result['error']}\n")
            
            if result.get("techniques"):
                f.write(f"\n**Techniques:**\n")
                for tech_id in sorted(result["techniques"][:10]):
                    details = result.get("technique_details", {}).get(tech_id, {})
                    name = details.get("name", "Unknown")
                    conf = details.get("confidence", 0)
                    f.write(f"- {tech_id}: {name} ({conf}%)\n")
                
                if len(result["techniques"]) > 10:
                    f.write(f"- ... and {len(result['techniques']) - 10} more\n")
            
            f.write("\n")
        
        # Technique frequency analysis
        f.write(f"## Most Common Techniques\n\n")
        
        technique_counts = {}
        technique_names = {}
        
        for result in results:
            if result["status"] == "success":
                for tech_id in result.get("techniques", []):
                    technique_counts[tech_id] = technique_counts.get(tech_id, 0) + 1
                    if tech_id in result.get("technique_details", {}):
                        technique_names[tech_id] = result["technique_details"][tech_id].get("name", "Unknown")
        
        sorted_techniques = sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)
        
        for tech_id, count in sorted_techniques[:20]:
            name = technique_names.get(tech_id, "Unknown")
            f.write(f"- **{tech_id}** ({name}): {count} files\n")
    
    return json_file, md_file


def main():
    parser = argparse.ArgumentParser(description="Batch process threat reports")
    parser.add_argument("directory", help="Directory containing reports")
    parser.add_argument("--api", action="store_true", help="Use REST API instead of direct Python")
    parser.add_argument("--api-url", default="http://localhost:8000", help="API base URL")
    parser.add_argument("--workers", type=int, default=3, help="Number of parallel workers")
    parser.add_argument("--extensions", nargs="+", default=[".pdf", ".txt", ".md"], help="File extensions to process")
    
    args = parser.parse_args()
    
    reports_dir = Path(args.directory)
    
    if not reports_dir.exists():
        print(f"❌ Directory not found: {reports_dir}")
        sys.exit(1)
    
    # Find all files to process
    files_to_process = []
    for ext in args.extensions:
        files_to_process.extend(reports_dir.glob(f"*{ext}"))
        files_to_process.extend(reports_dir.glob(f"**/*{ext}"))  # Recursive
    
    # Remove duplicates
    files_to_process = list(set(files_to_process))
    
    if not files_to_process:
        print(f"❌ No files found with extensions: {args.extensions}")
        sys.exit(1)
    
    print(f"📁 Found {len(files_to_process)} files to process")
    print(f"⚙️ Using {'API' if args.api else 'direct Python'} with {args.workers} workers")
    print("=" * 60)
    
    # Process files in parallel
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        if args.api:
            futures = {
                executor.submit(process_file_api, file_path, args.api_url): file_path
                for file_path in files_to_process
            }
        else:
            futures = {
                executor.submit(process_file_direct, file_path): file_path
                for file_path in files_to_process
            }
        
        for future in concurrent.futures.as_completed(futures):
            file_path = futures[future]
            try:
                result = future.result(timeout=180)  # 3 minute timeout
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
                    "processing_time": 180
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
    
    # Generate report
    print("\n" + "=" * 60)
    print("📊 Generating report...")
    
    output_dir = Path("batch_results")
    output_dir.mkdir(exist_ok=True)
    
    json_file, md_file = generate_report(results, output_dir)
    
    # Print summary
    successful = sum(1 for r in results if r["status"] == "success")
    failed = sum(1 for r in results if r["status"] == "error")
    total_techniques = len(set(t for r in results for t in r.get("techniques", [])))
    total_time = sum(r["processing_time"] for r in results)
    
    print(f"\n✅ Batch processing complete!")
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