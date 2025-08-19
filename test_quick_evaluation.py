#!/usr/bin/env python3
"""
Quick evaluation of extraction pipeline performance.
"""

import sys
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from collections import defaultdict

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from bandjacks.llm.evidence_extractor import EvidenceBasedExtractor
from bandjacks.llm.confidence_scorer import ConfidenceScorer
import PyPDF2


@dataclass
class QuickTest:
    """Simplified test configuration."""
    name: str
    path: Path
    expected_techniques: List[str]  # Just IDs for quick comparison


# Define simplified expected techniques
TESTS = [
    QuickTest(
        name="DarkCloud Stealer",
        path=Path("samples/reports/new-darkcloud-stealer-infection-chain.pdf"),
        expected_techniques=[
            "T1566", "T1566.001", "T1059.001", "T1059.007", 
            "T1027", "T1055", "T1140", "T1071", "T1204.002",
            "T1547", "T1555", "T1555.003", "T1005", "T1041",
            "T1083", "T1057", "T1105"
        ]
    ),
    QuickTest(
        name="TheWizards APT",
        path=Path("samples/reports/TheWizards APT group uses SLAAC spoofing to perform adversary-in-the-middle attacks.pdf"),
        expected_techniques=[
            "T1557", "T1557.001", "T1055", "T1055.001", "T1574.002",
            "T1140", "T1071", "T1071.001", "T1105", "T1547",
            "T1021", "T1021.001", "T1083", "T1057", "T1005"
        ]
    ),
    QuickTest(
        name="Black Basta",
        path=Path("samples/reports/Black Basta Ransomware.json"),
        expected_techniques=[
            "T1486", "T1490", "T1489", "T1055", "T1106",
            "T1059", "T1059.001", "T1059.003", "T1027", "T1140",
            "T1071", "T1105", "T1547", "T1083", "T1057"
        ]
    )
]


def extract_pdf_text_simple(pdf_path: Path) -> str:
    """Extract text from PDF - simplified."""
    if not pdf_path.exists():
        return ""
    
    text_parts = []
    try:
        with open(pdf_path, 'rb') as f:
            pdf_reader = PyPDF2.PdfReader(f)
            # Just extract first 5 pages for speed
            for page_num in range(min(5, len(pdf_reader.pages))):
                page = pdf_reader.pages[page_num]
                page_text = page.extract_text()
                text_parts.append(page_text)
    except Exception as e:
        print(f"Error reading PDF: {e}")
        return ""
    
    return '\n\n'.join(text_parts)


def extract_json_text(json_path: Path) -> str:
    """Extract text from JSON report."""
    if not json_path.exists():
        return ""
    
    try:
        with open(json_path) as f:
            data = json.load(f)
        
        text_parts = []
        for obj in data.get("objects", [])[:20]:  # First 20 objects only
            if "description" in obj:
                text_parts.append(obj["description"])
        
        return "\n\n".join(text_parts)
    except Exception as e:
        print(f"Error reading JSON: {e}")
        return ""


def quick_test_report(test: QuickTest) -> Dict[str, Any]:
    """Run quick test on a single report."""
    print(f"\n{'='*60}")
    print(f"Testing: {test.name}")
    print(f"{'='*60}")
    
    start_time = time.time()
    
    # Extract text based on type
    print("1. Extracting text...")
    if test.path.suffix == ".pdf":
        text = extract_pdf_text_simple(test.path)
    elif test.path.suffix == ".json":
        text = extract_json_text(test.path)
    else:
        print(f"Unknown file type: {test.path.suffix}")
        return {"error": "Unknown file type"}
    
    if not text:
        print("   ✗ No text extracted")
        return {"error": "No text extracted"}
    
    print(f"   ✓ Extracted {len(text)} characters")
    
    # Limit text to first 10KB for speed
    if len(text) > 10000:
        text = text[:10000]
        print(f"   ⚠ Truncated to 10,000 characters for quick test")
    
    # Run extraction with shorter timeout
    print("2. Running extraction (simplified)...")
    extractor = EvidenceBasedExtractor(model="gpt-4o-mini")
    
    try:
        results = extractor.extract_with_evidence(
            source_id=test.name.lower().replace(" ", "_"),
            source_type="text",
            inline_text=text
        )
        print(f"   ✓ Extracted {results['total_claims']} claims")
    except Exception as e:
        print(f"   ✗ Extraction failed: {e}")
        return {"error": str(e)}
    
    # Calculate metrics
    found_ids = set()
    for claim in results.get('claims', []):
        for mapping in claim.get('mappings', []):
            tech_id = mapping.get('external_id')
            if tech_id:
                found_ids.add(tech_id)
                # Add parent technique
                if '.' in tech_id:
                    found_ids.add(tech_id.split('.')[0])
    
    expected = set(test.expected_techniques)
    true_positives = found_ids & expected
    false_positives = found_ids - expected
    false_negatives = expected - found_ids
    
    recall = len(true_positives) / len(expected) if expected else 0
    precision = len(true_positives) / len(found_ids) if found_ids else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    elapsed = time.time() - start_time
    
    print(f"\n📊 Results:")
    print(f"   Recall: {recall:.1%} ({len(true_positives)}/{len(expected)})")
    print(f"   Precision: {precision:.1%}")
    print(f"   F1 Score: {f1:.3f}")
    print(f"   Time: {elapsed:.1f}s")
    
    # Show what was found vs missed
    print(f"\n   Found: {', '.join(sorted(true_positives)[:5])}")
    if len(true_positives) > 5:
        print(f"          (+{len(true_positives)-5} more)")
    print(f"   Missed: {', '.join(sorted(false_negatives)[:5])}")
    if len(false_negatives) > 5:
        print(f"           (+{len(false_negatives)-5} more)")
    
    return {
        "report": test.name,
        "recall": recall,
        "precision": precision,
        "f1": f1,
        "found_count": len(true_positives),
        "expected_count": len(expected),
        "time": elapsed,
        "found_ids": sorted(found_ids),
        "missed_ids": sorted(false_negatives)
    }


def main():
    """Run quick evaluation."""
    print("="*80)
    print("QUICK EXTRACTION EVALUATION")
    print("="*80)
    print("Note: Using truncated text for speed (first 10KB)")
    
    results = []
    
    for test in TESTS:
        try:
            result = quick_test_report(test)
            results.append(result)
        except Exception as e:
            print(f"✗ Test failed: {e}")
            results.append({"report": test.name, "error": str(e)})
    
    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    
    valid_results = [r for r in results if "recall" in r]
    if valid_results:
        avg_recall = sum(r["recall"] for r in valid_results) / len(valid_results)
        avg_precision = sum(r["precision"] for r in valid_results) / len(valid_results)
        avg_f1 = sum(r["f1"] for r in valid_results) / len(valid_results)
        
        print(f"\n📈 Average Performance:")
        print(f"   Recall: {avg_recall:.1%}")
        print(f"   Precision: {avg_precision:.1%}")
        print(f"   F1 Score: {avg_f1:.3f}")
        
        print(f"\n✅ Target Check:")
        print(f"   {'✓' if avg_recall >= 0.75 else '✗'} Recall ≥ 75% (actual: {avg_recall:.1%})")
        
        # Most commonly missed
        all_missed = defaultdict(int)
        for r in valid_results:
            for tech_id in r.get("missed_ids", []):
                all_missed[tech_id] += 1
        
        if all_missed:
            print(f"\n🔍 Most Commonly Missed:")
            for tech_id, count in sorted(all_missed.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"   {tech_id}: missed in {count}/{len(valid_results)} reports")
    
    # Save results
    output_file = Path("/tmp/quick_evaluation_results.json")
    with open(output_file, "w") as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "mode": "quick_truncated",
            "results": results
        }, f, indent=2)
    
    print(f"\n💾 Results saved to: {output_file}")
    
    return avg_recall >= 0.75 if valid_results else False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)