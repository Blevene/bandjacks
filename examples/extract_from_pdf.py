#!/usr/bin/env python3
"""
Example: Extract MITRE ATT&CK techniques from a PDF report.

Usage:
    python extract_from_pdf.py threat_report.pdf
"""

import sys
import json
from pathlib import Path
import PyPDF2

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from bandjacks.llm.agentic_v2 import run_agentic_v2
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def extract_text_from_pdf(pdf_path: Path) -> str:
    """Extract text from a PDF file."""
    text_parts = []
    
    with open(pdf_path, 'rb') as f:
        pdf_reader = PyPDF2.PdfReader(f)
        
        print(f"📄 Reading {len(pdf_reader.pages)} pages from {pdf_path.name}...")
        
        for page_num, page in enumerate(pdf_reader.pages, 1):
            page_text = page.extract_text()
            text_parts.append(page_text)
            
            if page_num % 10 == 0:
                print(f"   Processed {page_num} pages...")
    
    return '\n'.join(text_parts)


def main():
    if len(sys.argv) < 2:
        print("Usage: python extract_from_pdf.py <pdf_file>")
        sys.exit(1)
    
    pdf_path = Path(sys.argv[1])
    
    if not pdf_path.exists():
        print(f"❌ File not found: {pdf_path}")
        sys.exit(1)
    
    if not pdf_path.suffix.lower() == '.pdf':
        print(f"❌ Not a PDF file: {pdf_path}")
        sys.exit(1)
    
    print(f"🔍 Extracting MITRE ATT&CK techniques from: {pdf_path.name}")
    print("=" * 60)
    
    # Extract text from PDF
    try:
        text = extract_text_from_pdf(pdf_path)
        print(f"✅ Extracted {len(text)} characters of text")
    except Exception as e:
        print(f"❌ Failed to extract text: {e}")
        sys.exit(1)
    
    # Configure extraction
    config = {
        "neo4j_uri": os.getenv("NEO4J_URI", "bolt://localhost:7687"),
        "neo4j_user": os.getenv("NEO4J_USER", "neo4j"),
        "neo4j_password": os.getenv("NEO4J_PASSWORD", ""),
        "model": os.getenv("PRIMARY_LLM", "gemini/gemini-2.5-flash"),
        "title": pdf_path.stem,  # Use filename without extension as title
    }
    
    print(f"\n🤖 Running extraction with {config['model']}...")
    
    # Run extraction
    try:
        result = run_agentic_v2(text, config)
        techniques = result.get("techniques", {})
        bundle = result.get("bundle", {})
        
        print(f"\n✅ Extraction complete!")
        print(f"   • Found {len(techniques)} techniques")
        print(f"   • Created {len(bundle.get('objects', []))} STIX objects")
        
    except Exception as e:
        print(f"❌ Extraction failed: {e}")
        sys.exit(1)
    
    # Display results
    print("\n📊 Extracted Techniques:")
    print("-" * 60)
    
    # Sort by confidence
    sorted_techniques = sorted(
        techniques.items(),
        key=lambda x: x[1].get('confidence', 0),
        reverse=True
    )
    
    for tech_id, info in sorted_techniques[:20]:  # Show top 20
        confidence = info.get('confidence', 0)
        name = info.get('name', 'Unknown')
        evidence = info.get('evidence', [])
        
        # Confidence indicator
        if confidence >= 80:
            conf_icon = "🟢"
        elif confidence >= 60:
            conf_icon = "🟡"
        else:
            conf_icon = "🔴"
        
        print(f"\n{conf_icon} {tech_id}: {name} ({confidence}% confidence)")
        
        # Show first piece of evidence
        if evidence and isinstance(evidence, list):
            first_evidence = evidence[0] if evidence else "No evidence"
            # Truncate long evidence
            if len(first_evidence) > 100:
                first_evidence = first_evidence[:97] + "..."
            print(f"   Evidence: {first_evidence}")
    
    if len(techniques) > 20:
        print(f"\n... and {len(techniques) - 20} more techniques")
    
    # Save results
    output_dir = Path("extraction_results")
    output_dir.mkdir(exist_ok=True)
    
    # Save techniques summary
    summary_file = output_dir / f"{pdf_path.stem}_techniques.json"
    with open(summary_file, 'w') as f:
        json.dump(techniques, f, indent=2)
    print(f"\n💾 Saved techniques to: {summary_file}")
    
    # Save full STIX bundle
    bundle_file = output_dir / f"{pdf_path.stem}_bundle.json"
    with open(bundle_file, 'w') as f:
        json.dump(bundle, f, indent=2)
    print(f"💾 Saved STIX bundle to: {bundle_file}")
    
    # Generate summary stats
    print("\n📈 Summary Statistics:")
    print("-" * 60)
    
    # Tactic coverage
    tactics = set()
    for info in techniques.values():
        tactic = info.get('tactic', '')
        if tactic:
            tactics.add(tactic)
    
    print(f"Kill chain coverage: {len(tactics)} tactics")
    for tactic in sorted(tactics):
        tactic_techniques = [
            tid for tid, info in techniques.items()
            if info.get('tactic') == tactic
        ]
        print(f"  • {tactic}: {len(tactic_techniques)} techniques")
    
    # Confidence distribution
    high_conf = sum(1 for t in techniques.values() if t.get('confidence', 0) >= 80)
    med_conf = sum(1 for t in techniques.values() if 60 <= t.get('confidence', 0) < 80)
    low_conf = sum(1 for t in techniques.values() if t.get('confidence', 0) < 60)
    
    print(f"\nConfidence distribution:")
    print(f"  🟢 High (≥80%): {high_conf} techniques")
    print(f"  🟡 Medium (60-79%): {med_conf} techniques")
    print(f"  🔴 Low (<60%): {low_conf} techniques")
    
    print("\n✨ Done!")


if __name__ == "__main__":
    main()