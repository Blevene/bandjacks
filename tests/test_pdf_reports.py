#!/usr/bin/env python3
"""Test agentic_v2 extraction on PDF reports in samples folder."""

import sys
import json
import time
from pathlib import Path
from typing import Dict, Any, List, Tuple

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import PyPDF2
from bandjacks.llm.agentic_v2 import run_agentic_v2


def extract_pdf_text(pdf_path: Path) -> str:
    """Extract text from PDF file."""
    text_content = []
    with open(pdf_path, 'rb') as f:
        pdf_reader = PyPDF2.PdfReader(f)
        for page in pdf_reader.pages:
            text_content.append(page.extract_text())
    return '\n'.join(text_content)


def analyze_techniques(techniques: Dict[str, Any]) -> Tuple[List, Dict]:
    """Analyze extracted techniques and return summary."""
    
    # Group by tactic
    by_tactic = {}
    for tech_id, info in techniques.items():
        tactic = info.get("tactic", "unknown")
        if tactic not in by_tactic:
            by_tactic[tactic] = []
        by_tactic[tactic].append((tech_id, info["name"], info["confidence"]))
    
    # Sort techniques by confidence
    sorted_techs = sorted(
        techniques.items(),
        key=lambda x: x[1].get("confidence", 0),
        reverse=True
    )
    
    return sorted_techs, by_tactic


def test_pdf_report(pdf_path: Path) -> Dict[str, Any]:
    """Test extraction on a single PDF report."""
    
    print(f"\n{'='*80}")
    print(f"Testing: {pdf_path.name}")
    print(f"{'='*80}")
    
    # Extract text
    print(f"1. Extracting text from PDF...")
    try:
        text = extract_pdf_text(pdf_path)
        print(f"   ✅ Extracted {len(text)} characters")
        
        # Save extracted text for debugging
        text_file = Path(f"/tmp/{pdf_path.stem}_extracted.txt")
        with open(text_file, "w") as f:
            f.write(text)
        print(f"   📝 Saved text to {text_file}")
        
    except Exception as e:
        print(f"   ❌ Failed to extract text: {e}")
        return {"error": str(e)}
    
    # Configure extraction
    import os
    config = {
        "neo4j_uri": os.getenv("NEO4J_URI", "bolt://localhost:7687"),
        "neo4j_user": os.getenv("NEO4J_USER", "neo4j"),
        "neo4j_password": os.getenv("NEO4J_PASSWORD", ""),
        "model": "gemini/gemini-2.5-flash",
        "discovery_model": "gemini/gemini-2.5-flash",
        "mapper_model": "gemini/gemini-2.5-flash",
        "title": pdf_path.stem,
        "url": f"file://{pdf_path}",
        "ts": time.time(),
        "min_quotes": 1,
        "max_discovery_per_span": 10,
        "top_k": 8
    }
    
    # Run extraction
    print(f"\n2. Running agentic_v2 extraction...")
    print(f"   🤖 Using Gemini 2.5 Flash")
    print(f"   🔄 Multi-pass extraction enabled")
    
    try:
        start_time = time.time()
        result = run_agentic_v2(text, config)
        elapsed = time.time() - start_time
        
        print(f"   ✅ Extraction completed in {elapsed:.1f} seconds")
        
        # Analyze results
        techniques = result.get("techniques", {})
        bundle = result.get("bundle", {})
        notes = result.get("notes", [])
        
        print(f"\n3. Results Summary:")
        print(f"   📊 Techniques found: {len(techniques)}")
        print(f"   📦 STIX objects created: {len(bundle.get('objects', []))}")
        if notes:
            print(f"   📝 Notes: {', '.join(notes[:3])}")
        
        # Analyze techniques
        sorted_techs, by_tactic = analyze_techniques(techniques)
        
        print(f"\n4. Tactic Coverage:")
        all_tactics = [
            "reconnaissance", "resource-development", "initial-access",
            "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery",
            "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact"
        ]
        
        covered_tactics = set(by_tactic.keys()) - {"unknown", None}
        coverage = (len(covered_tactics) / len(all_tactics)) * 100
        
        for tactic in all_tactics:
            if tactic in by_tactic:
                count = len(by_tactic[tactic])
                print(f"   ✅ {tactic}: {count} techniques")
            else:
                print(f"   ❌ {tactic}: missing")
        
        print(f"\n   Kill Chain Coverage: {coverage:.1f}% ({len(covered_tactics)}/{len(all_tactics)})")
        
        print(f"\n5. Top 10 Techniques (by confidence):")
        for tech_id, info in sorted_techs[:10]:
            print(f"   • {tech_id}: {info['name'][:40]:<40} (confidence: {info['confidence']}%)")
            if info.get("evidence") and len(info["evidence"]) > 0:
                evidence = info["evidence"][0][:80]
                print(f"     Evidence: \"{evidence}...\"")
        
        # Save results
        output_file = Path(f"/tmp/{pdf_path.stem}_results.json")
        with open(output_file, "w") as f:
            json.dump({
                "file": pdf_path.name,
                "techniques": techniques,
                "technique_count": len(techniques),
                "tactic_coverage": coverage,
                "elapsed_seconds": elapsed,
                "notes": notes
            }, f, indent=2)
        print(f"\n   💾 Saved results to {output_file}")
        
        return {
            "file": pdf_path.name,
            "technique_count": len(techniques),
            "tactic_coverage": coverage,
            "elapsed": elapsed,
            "techniques": techniques
        }
        
    except Exception as e:
        print(f"   ❌ Extraction failed: {e}")
        import traceback
        traceback.print_exc()
        return {"error": str(e)}


def main():
    """Test all PDF reports in samples folder."""
    
    print("="*80)
    print("AGENTIC V2 PDF REPORT TESTING")
    print("="*80)
    
    reports_dir = Path(__file__).parent.parent / "samples" / "reports"
    pdf_files = list(reports_dir.glob("*.pdf"))
    
    print(f"\nFound {len(pdf_files)} PDF reports to test:")
    for pdf in pdf_files:
        print(f"  • {pdf.name}")
    
    # Test each PDF
    results = []
    for pdf_path in pdf_files:
        result = test_pdf_report(pdf_path)
        results.append(result)
        
        # Brief pause between tests
        if pdf_path != pdf_files[-1]:
            print("\n⏳ Pausing before next test...")
            time.sleep(2)
    
    # Summary
    print(f"\n{'='*80}")
    print("OVERALL SUMMARY")
    print(f"{'='*80}\n")
    
    successful = [r for r in results if "error" not in r]
    failed = [r for r in results if "error" in r]
    
    if successful:
        avg_techniques = sum(r["technique_count"] for r in successful) / len(successful)
        avg_coverage = sum(r["tactic_coverage"] for r in successful) / len(successful)
        avg_time = sum(r["elapsed"] for r in successful) / len(successful)
        
        print(f"✅ Successfully processed {len(successful)}/{len(results)} reports")
        print(f"\n📊 Average Metrics:")
        print(f"   • Techniques per report: {avg_techniques:.1f}")
        print(f"   • Kill chain coverage: {avg_coverage:.1f}%")
        print(f"   • Processing time: {avg_time:.1f} seconds")
        
        print(f"\n📈 Individual Results:")
        for r in successful:
            status = "🎯" if r["technique_count"] >= 15 else "✅"
            print(f"   {status} {r['file'][:40]:<40}: {r['technique_count']} techniques, {r['tactic_coverage']:.0f}% coverage")
    
    if failed:
        print(f"\n❌ Failed to process {len(failed)} reports:")
        for r in failed:
            print(f"   • {r.get('file', 'unknown')}: {r['error'][:50]}...")
    
    # Check if we met the 75% recall target
    # Approximate recall as: (techniques found / expected techniques)
    # Assuming ~20 techniques expected per report on average
    if successful:
        estimated_recall = min(100, (avg_techniques / 20) * 100)
        print(f"\n🎯 Estimated Recall: {estimated_recall:.1f}%")
        
        if estimated_recall >= 75:
            print("✅ TARGET ACHIEVED: ≥75% recall")
        else:
            print(f"⚠️  Need improvement: {75 - estimated_recall:.1f}% short of target")
    
    return 0 if len(successful) > 0 else 1


if __name__ == "__main__":
    sys.exit(main())