#!/usr/bin/env python3
"""Test async extraction pipeline with DarkCloud Stealer PDF report."""

import requests
import json
import time
from pathlib import Path
import base64


def extract_pdf_text(pdf_path: str) -> str:
    """Extract text from PDF using pdfplumber."""
    import pdfplumber
    
    text_parts = []
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            text = page.extract_text()
            if text:
                text_parts.append(text)
    
    return "\n\n".join(text_parts)


def run_extraction(content: str, title: str) -> tuple:
    """Run async extraction and return time and results."""
    
    config = {
        "use_async": True,  # Force async pipeline
        "single_pass_threshold": 2000,  # Increase threshold for longer docs
        "max_spans": 20,  # Allow more spans for comprehensive doc
        "span_score_threshold": 0.7,  # Lower threshold to catch more
        "top_k": 8,  # More candidates for better matching
        "cache_llm_responses": True,
        "early_termination_confidence": 85
    }
    
    payload = {
        "method": "agentic_v2",
        "content": content,
        "title": title,
        "config": config
    }
    
    print(f"Starting extraction for: {title}")
    print(f"Content length: {len(content)} characters, {len(content.split())} words")
    
    start_time = time.time()
    
    # Start extraction
    response = requests.post(
        "http://localhost:8000/v1/extract/runs",
        json=payload
    )
    
    if response.status_code != 200:
        print(f"Failed to start: {response.status_code}")
        print(f"Response: {response.text}")
        return 0, {}
    
    run_id = response.json().get("run_id")
    print(f"Run ID: {run_id}")
    
    # Poll for completion with progress updates
    last_stage = None
    for i in range(240):  # 2 minutes max
        time.sleep(0.5)
        
        status_resp = requests.get(
            f"http://localhost:8000/v1/extract/runs/{run_id}/status"
        )
        
        if status_resp.status_code == 200:
            status = status_resp.json()
            
            # Show progress
            current_stage = status.get("stage", "")
            if current_stage != last_stage:
                elapsed = time.time() - start_time
                print(f"  [{elapsed:.1f}s] Stage: {current_stage}")
                last_stage = current_stage
            
            if status.get("state") == "finished":
                result_resp = requests.get(
                    f"http://localhost:8000/v1/extract/runs/{run_id}/result"
                )
                
                if result_resp.status_code == 200:
                    end_time = time.time()
                    result = result_resp.json()
                    return end_time - start_time, result
    
    return 0, {"error": "Timeout"}


def main():
    """Test DarkCloud Stealer PDF extraction."""
    
    pdf_path = "/Volumes/tank/bandjacks/samples/reports/new-darkcloud-stealer-infection-chain.pdf"
    
    print("=" * 80)
    print("DARKCLOUD STEALER PDF EXTRACTION TEST")
    print("=" * 80)
    print(f"\nPDF: {pdf_path}\n")
    
    # Extract text from PDF
    print("Extracting text from PDF...")
    try:
        pdf_text = extract_pdf_text(pdf_path)
        print(f"Extracted {len(pdf_text)} characters from PDF\n")
        
        # Truncate if too long (for testing)
        max_chars = 10000  # Limit for testing
        if len(pdf_text) > max_chars:
            print(f"Truncating to first {max_chars} characters for testing...")
            pdf_text = pdf_text[:max_chars]
            print(f"Final text length: {len(pdf_text)} characters\n")
        
    except Exception as e:
        print(f"Error extracting PDF text: {e}")
        return
    
    # Clear cache for clean test
    print("Clearing cache...")
    requests.post("http://localhost:8000/v1/cache/clear")
    
    # Run extraction
    print("\n" + "=" * 40)
    print("Running Async Extraction Pipeline")
    print("=" * 40 + "\n")
    
    elapsed_time, result = run_extraction(pdf_text, "DarkCloud Stealer Analysis")
    
    if elapsed_time > 0:
        print(f"\n✓ Extraction completed in {elapsed_time:.2f} seconds")
        
        # Check for errors
        if "error" in result:
            print(f"❌ Error: {result['error']}")
            return
        
        # Display metrics
        metrics = result.get("metrics", {})
        print(f"\nExtraction Metrics:")
        print(f"  Run ID: {metrics.get('run_id', 'N/A')}")
        print(f"  Spans total: {metrics.get('spans_total', 0)}")
        print(f"  Spans processed: {metrics.get('spans_processed', 0)}")
        print(f"  Techniques found: {metrics.get('counters', {}).get('techniques', 0)}")
        
        # Show stage timings
        stage_timings = metrics.get("stage_timings", {})
        if stage_timings:
            print(f"\nStage Timings:")
            total_time = sum(stage_timings.values())
            for stage, timing in stage_timings.items():
                pct = (timing / total_time * 100) if total_time > 0 else 0
                print(f"  {stage}: {timing:.2f}s ({pct:.1f}%)")
        
        # Display extracted techniques
        techniques = result.get("techniques", {})
        if techniques:
            print(f"\n{len(techniques)} Techniques Extracted:")
            print("-" * 40)
            
            # Sort by confidence
            sorted_techs = sorted(
                techniques.items(),
                key=lambda x: x[1].get("confidence", 0),
                reverse=True
            )
            
            for tech_id, tech in sorted_techs[:15]:  # Show top 15
                name = tech.get("name", "Unknown")
                confidence = tech.get("confidence", 0)
                evidence_count = len(tech.get("evidence", []))
                print(f"  [{confidence:3d}%] {tech_id}: {name}")
                
                # Show first evidence quote
                evidence = tech.get("evidence", [])
                if evidence and evidence[0]:
                    quote = evidence[0][:100] + "..." if len(evidence[0]) > 100 else evidence[0]
                    print(f"         Evidence: \"{quote}\"")
            
            if len(techniques) > 15:
                print(f"\n  ... and {len(techniques) - 15} more techniques")
        
        # Check cache effectiveness
        print("\n" + "=" * 40)
        print("Cache Statistics")
        print("=" * 40)
        stats = requests.get("http://localhost:8000/v1/cache/stats").json()
        print(f"  Hits: {stats['hits']}")
        print(f"  Misses: {stats['misses']}")
        print(f"  Hit rate: {stats['hit_rate']}")
        print(f"  Cache size: {stats['size']} entries")
        
    else:
        print("❌ Extraction failed or timed out")
    
    print("\n" + "=" * 80)
    print("TEST COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()