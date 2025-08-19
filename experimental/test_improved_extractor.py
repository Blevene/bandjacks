#!/usr/bin/env python3
"""Test the improved extraction pipeline."""

import sys
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from bandjacks.llm.improved_extractor import ImprovedExtractor


@dataclass
class TestReport:
    """Test report configuration."""
    name: str
    path: Path
    type: str
    expected_techniques: List[str]
    critical_techniques: List[str]  # Must find these


# Define test reports with expected techniques
TEST_REPORTS = [
    TestReport(
        name="DarkCloud Stealer",
        path=Path("samples/reports/new-darkcloud-stealer-infection-chain.pdf"),
        type="pdf",
        expected_techniques=[
            "T1566", "T1566.001",  # Phishing
            "T1059", "T1059.001", "T1059.007",  # PowerShell, JavaScript
            "T1027", "T1140",  # Obfuscation, Deobfuscate
            "T1055", "T1055.012",  # Process Injection
            "T1071", "T1071.001",  # Application Layer Protocol
            "T1547",  # Persistence
            "T1555", "T1555.003",  # Credentials from Password Stores
            "T1005", "T1041",  # Data from Local System, Exfiltration
            "T1083", "T1057",  # File/Process Discovery
            "T1105", "T1204"  # Ingress Tool Transfer, User Execution
        ],
        critical_techniques=["T1566", "T1059.001", "T1055", "T1071", "T1547"]
    ),
    TestReport(
        name="TheWizards APT",
        path=Path("samples/reports/TheWizards APT group uses SLAAC spoofing to perform adversary-in-the-middle attacks.pdf"),
        type="pdf",
        expected_techniques=[
            "T1557", "T1557.001",  # Adversary-in-the-Middle
            "T1055", "T1055.001",  # Process Injection
            "T1574", "T1574.002",  # DLL Side-Loading
            "T1140",  # Deobfuscate/Decode
            "T1071", "T1071.001",  # Application Layer Protocol
            "T1105",  # Ingress Tool Transfer
            "T1547",  # Persistence
            "T1021", "T1021.001",  # Remote Services
            "T1083", "T1057",  # Discovery
            "T1005"  # Data from Local System
        ],
        critical_techniques=["T1557", "T1055", "T1574.002", "T1071", "T1547"]
    ),
    TestReport(
        name="Black Basta",
        path=Path("samples/reports/Black Basta Ransomware.json"),
        type="json",
        expected_techniques=[
            "T1486",  # Data Encrypted for Impact
            "T1490",  # Inhibit System Recovery
            "T1489",  # Service Stop
            "T1055",  # Process Injection
            "T1059", "T1059.001", "T1059.003",  # Command Interpreters
            "T1027", "T1140",  # Obfuscation
            "T1071",  # Application Layer Protocol
            "T1105",  # Ingress Tool Transfer
            "T1547",  # Persistence
            "T1083", "T1057",  # Discovery
            "T1106"  # Native API
        ],
        critical_techniques=["T1486", "T1490", "T1055", "T1071", "T1059"]
    )
]


def test_report(report: TestReport, extractor: ImprovedExtractor) -> Dict[str, Any]:
    """Test extraction on a single report."""
    print(f"\n{'='*60}")
    print(f"Testing: {report.name}")
    print(f"Path: {report.path}")
    print(f"Expected techniques: {len(report.expected_techniques)}")
    print(f"Critical techniques: {report.critical_techniques}")
    print(f"{'='*60}")
    
    if not report.path.exists():
        print(f"  ✗ Report file not found: {report.path}")
        return {"error": "File not found"}
    
    start_time = time.time()
    
    # Run extraction
    print("\nRunning improved extraction...")
    try:
        if report.type == "pdf":
            results = extractor.extract_from_report(
                source_id=report.name.lower().replace(" ", "_"),
                source_type="pdf",
                content_url=str(report.path)
            )
        else:  # json
            results = extractor.extract_from_report(
                source_id=report.name.lower().replace(" ", "_"),
                source_type="json",
                content_url=str(report.path)
            )
        
    except Exception as e:
        print(f"  ✗ Extraction failed: {e}")
        import traceback
        traceback.print_exc()
        return {"error": str(e)}
    
    # Extract found technique IDs
    found_ids = set()
    for claim in results.get("claims", []):
        for mapping in claim.get("mappings", []):
            tech_id = mapping.get("external_id")
            if tech_id:
                found_ids.add(tech_id)
                # Add parent technique
                if '.' in tech_id:
                    found_ids.add(tech_id.split('.')[0])
    
    # Calculate metrics
    expected = set(report.expected_techniques)
    critical = set(report.critical_techniques)
    
    true_positives = found_ids & expected
    false_positives = found_ids - expected
    false_negatives = expected - found_ids
    critical_found = found_ids & critical
    
    recall = len(true_positives) / len(expected) if expected else 0
    precision = len(true_positives) / len(found_ids) if found_ids else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    critical_coverage = len(critical_found) / len(critical) if critical else 0
    
    elapsed = time.time() - start_time
    
    # Display results
    print(f"\n📊 Results:")
    print(f"  Techniques found: {len(found_ids)}")
    print(f"  True positives: {len(true_positives)}")
    print(f"  False positives: {len(false_positives)}")
    print(f"  False negatives: {len(false_negatives)}")
    print(f"\n📈 Metrics:")
    print(f"  Recall: {recall:.1%} ({len(true_positives)}/{len(expected)})")
    print(f"  Precision: {precision:.1%}")
    print(f"  F1 Score: {f1:.3f}")
    print(f"  Critical Coverage: {critical_coverage:.1%} ({len(critical_found)}/{len(critical)})")
    print(f"  Time: {elapsed:.1f}s")
    
    # Show found techniques
    print(f"\n✓ Found techniques:")
    for tech_id in sorted(true_positives)[:10]:
        print(f"    {tech_id}")
    if len(true_positives) > 10:
        print(f"    ... and {len(true_positives)-10} more")
    
    # Show critical techniques status
    print(f"\n🎯 Critical techniques:")
    for tech_id in critical:
        status = "✓" if tech_id in found_ids else "✗"
        print(f"    {status} {tech_id}")
    
    # Show missed techniques
    if false_negatives:
        print(f"\n✗ Missed techniques:")
        for tech_id in sorted(false_negatives)[:5]:
            print(f"    {tech_id}")
        if len(false_negatives) > 5:
            print(f"    ... and {len(false_negatives)-5} more")
    
    # Show entities found
    entities = results.get("entities", {})
    if entities:
        print(f"\n🔍 Entities found:")
        print(f"    Threat Actors: {', '.join(entities.get('threat_actors', [])[:3])}")
        print(f"    Malware: {', '.join(entities.get('malware', [])[:3])}")
        print(f"    Tools: {', '.join(entities.get('tools', [])[:3])}")
    
    # Show kill chain coverage
    kill_chain = results.get("kill_chain_coverage", {})
    if kill_chain:
        print(f"\n🔗 Kill chain coverage:")
        for phase, techs in kill_chain.items():
            if techs:
                print(f"    {phase}: {len(techs)} techniques")
    
    return {
        "report": report.name,
        "recall": recall,
        "precision": precision,
        "f1": f1,
        "critical_coverage": critical_coverage,
        "found_count": len(true_positives),
        "expected_count": len(expected),
        "found_ids": sorted(found_ids),
        "missed_ids": sorted(false_negatives),
        "critical_found": sorted(critical_found),
        "time": elapsed,
        "entities": entities,
        "kill_chain": kill_chain
    }


def main():
    """Run tests on all reports."""
    print("="*80)
    print("IMPROVED EXTRACTION PIPELINE TEST")
    print("="*80)
    print(f"Testing {len(TEST_REPORTS)} reports with improved extraction")
    print("Target: 75% recall with full document processing")
    
    # Initialize extractor
    extractor = ImprovedExtractor(
        model="gpt-4o-mini",
        os_url="http://localhost:9200",
        os_index="bandjacks_attack_nodes-v1"
    )
    
    all_results = []
    
    for report in TEST_REPORTS:
        try:
            result = test_report(report, extractor)
            all_results.append(result)
        except Exception as e:
            print(f"✗ Test failed for {report.name}: {e}")
            all_results.append({
                "report": report.name,
                "error": str(e)
            })
    
    # Calculate overall metrics
    print("\n" + "="*80)
    print("OVERALL RESULTS")
    print("="*80)
    
    valid_results = [r for r in all_results if "recall" in r]
    
    if valid_results:
        avg_recall = sum(r["recall"] for r in valid_results) / len(valid_results)
        avg_precision = sum(r["precision"] for r in valid_results) / len(valid_results)
        avg_f1 = sum(r["f1"] for r in valid_results) / len(valid_results)
        avg_critical = sum(r["critical_coverage"] for r in valid_results) / len(valid_results)
        
        print(f"\n📊 Average Metrics:")
        print(f"  Recall: {avg_recall:.1%}")
        print(f"  Precision: {avg_precision:.1%}")
        print(f"  F1 Score: {avg_f1:.3f}")
        print(f"  Critical Coverage: {avg_critical:.1%}")
        
        print(f"\n✅ Success Criteria:")
        print(f"  {'✓' if avg_recall >= 0.75 else '✗'} Recall ≥ 75% (actual: {avg_recall:.1%})")
        print(f"  {'✓' if avg_precision >= 0.4 else '✗'} Precision ≥ 40% (actual: {avg_precision:.1%})")
        print(f"  {'✓' if avg_critical >= 0.8 else '✗'} Critical techniques ≥ 80% (actual: {avg_critical:.1%})")
        
        # Report-by-report summary
        print(f"\n📋 Report Summary:")
        for r in valid_results:
            status = "✓" if r["recall"] >= 0.75 else "✗"
            print(f"  {status} {r['report']}: {r['recall']:.1%} recall, {r['critical_coverage']:.1%} critical")
        
        # Save results
        output_file = Path("/tmp/improved_extraction_results.json")
        with open(output_file, "w") as f:
            json.dump({
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "mode": "improved_full_document",
                "avg_recall": avg_recall,
                "avg_precision": avg_precision,
                "avg_f1": avg_f1,
                "avg_critical_coverage": avg_critical,
                "reports": all_results
            }, f, indent=2)
        
        print(f"\n💾 Results saved to: {output_file}")
        
        return avg_recall >= 0.75
    
    return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)