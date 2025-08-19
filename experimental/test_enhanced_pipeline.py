#!/usr/bin/env python3
"""
Comprehensive test of enhanced extraction pipeline across multiple reports.
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
from bandjacks.loaders.enhanced_search import EnhancedSearch
import PyPDF2


@dataclass
class ReportTest:
    """Configuration for testing a report."""
    name: str
    path: Path
    type: str  # pdf, json
    malware_type: str  # stealer, apt, ransomware
    expected_techniques: List[Tuple[str, str, str]]  # (ID, name, description)
    must_find: List[str]  # Critical techniques that must be found
    should_find: List[str]  # Important techniques that should be found


# Define expected techniques for each report
DARKCLOUD_TECHNIQUES = [
    ("T1566", "Phishing", "Initial phishing email delivery"),
    ("T1566.001", "Spearphishing Attachment", "RAR/ZIP attachments"),
    ("T1059.001", "PowerShell", "PowerShell script execution"),
    ("T1059.007", "JavaScript", "JavaScript in archives"),
    ("T1027", "Obfuscated Files or Information", "ConfuserEx obfuscation"),
    ("T1027.002", "Software Packing", "ConfuserEx packing"),
    ("T1055", "Process Injection", "Process hollowing"),
    ("T1055.012", "Process Hollowing", "RegAsm.exe hollowing"),
    ("T1140", "Deobfuscate/Decode", "3DES/RC4 decryption"),
    ("T1071", "Application Layer Protocol", "Telegram C2"),
    ("T1071.001", "Web Protocols", "HTTPS for C2"),
    ("T1204.002", "Malicious File", "User execution of attachment"),
    ("T1547", "Boot or Logon Autostart", "Persistence mechanisms"),
    ("T1555", "Credentials from Password Stores", "Browser credential theft"),
    ("T1555.003", "Credentials from Web Browsers", "Browser password theft"),
    ("T1005", "Data from Local System", "File collection"),
    ("T1041", "Exfiltration Over C2", "Data exfiltration via Telegram"),
    ("T1083", "File and Directory Discovery", "File enumeration"),
    ("T1057", "Process Discovery", "Process enumeration"),
    ("T1105", "Ingress Tool Transfer", "Download PowerShell script"),
]

WIZARDS_TECHNIQUES = [
    ("T1557", "Adversary-in-the-Middle", "SLAAC spoofing"),
    ("T1557.001", "LLMNR/NBT-NS Poisoning", "Network spoofing"),
    ("T1055", "Process Injection", "Process injection techniques"),
    ("T1055.001", "Dynamic-link Library Injection", "DLL injection"),
    ("T1574.002", "DLL Side-Loading", "wsc.dll side-loading"),
    ("T1140", "Deobfuscate/Decode", "Payload decoding"),
    ("T1071", "Application Layer Protocol", "C2 communication"),
    ("T1071.001", "Web Protocols", "HTTP/HTTPS C2"),
    ("T1105", "Ingress Tool Transfer", "Download backdoor"),
    ("T1547", "Boot or Logon Autostart", "Persistence"),
    ("T1021", "Remote Services", "Lateral movement"),
    ("T1021.001", "Remote Desktop Protocol", "RDP usage"),
    ("T1083", "File and Directory Discovery", "System enumeration"),
    ("T1057", "Process Discovery", "Process enumeration"),
    ("T1005", "Data from Local System", "Data collection"),
]

BLACKBASTA_TECHNIQUES = [
    ("T1486", "Data Encrypted for Impact", "Ransomware encryption"),
    ("T1490", "Inhibit System Recovery", "Delete shadow copies"),
    ("T1489", "Service Stop", "Stop backup services"),
    ("T1055", "Process Injection", "Process injection"),
    ("T1106", "Native API", "Windows API usage"),
    ("T1059", "Command and Scripting Interpreter", "Script execution"),
    ("T1059.001", "PowerShell", "PowerShell usage"),
    ("T1059.003", "Windows Command Shell", "cmd.exe usage"),
    ("T1027", "Obfuscated Files or Information", "Payload obfuscation"),
    ("T1140", "Deobfuscate/Decode", "Decode payloads"),
    ("T1071", "Application Layer Protocol", "C2 communication"),
    ("T1105", "Ingress Tool Transfer", "Download tools"),
    ("T1547", "Boot or Logon Autostart", "Persistence"),
    ("T1083", "File and Directory Discovery", "Enumerate files"),
    ("T1057", "Process Discovery", "Process enumeration"),
]

# Create test configurations
REPORT_TESTS = [
    ReportTest(
        name="DarkCloud Stealer",
        path=Path("samples/reports/new-darkcloud-stealer-infection-chain.pdf"),
        type="pdf",
        malware_type="stealer",
        expected_techniques=DARKCLOUD_TECHNIQUES,
        must_find=["T1566", "T1059.001", "T1555", "T1071", "T1041"],
        should_find=["T1547", "T1027", "T1055", "T1140", "T1005"]
    ),
    ReportTest(
        name="TheWizards APT",
        path=Path("samples/reports/TheWizards APT group uses SLAAC spoofing to perform adversary-in-the-middle attacks.pdf"),
        type="pdf",
        malware_type="apt",
        expected_techniques=WIZARDS_TECHNIQUES,
        must_find=["T1557", "T1055", "T1574.002", "T1071"],
        should_find=["T1021", "T1140", "T1105", "T1547"]
    ),
    ReportTest(
        name="Black Basta Ransomware",
        path=Path("samples/reports/Black Basta Ransomware.json"),
        type="json",
        malware_type="ransomware",
        expected_techniques=BLACKBASTA_TECHNIQUES,
        must_find=["T1486", "T1490", "T1055", "T1059"],
        should_find=["T1489", "T1106", "T1547", "T1071"]
    ),
]


def extract_text_from_report(report_test: ReportTest) -> str:
    """Extract text from report based on type."""
    if report_test.type == "pdf":
        return extract_pdf_text(report_test.path)
    elif report_test.type == "json":
        with open(report_test.path) as f:
            data = json.load(f)
        # Extract text from STIX bundle
        text_parts = []
        for obj in data.get("objects", []):
            if "description" in obj:
                text_parts.append(obj["description"])
            if "pattern" in obj:
                text_parts.append(obj["pattern"])
        return "\n\n".join(text_parts)
    else:
        raise ValueError(f"Unknown report type: {report_test.type}")


def extract_pdf_text(pdf_path: Path) -> str:
    """Extract text from PDF."""
    if not pdf_path.exists():
        raise FileNotFoundError(f"PDF not found: {pdf_path}")
    
    text_parts = []
    with open(pdf_path, 'rb') as f:
        try:
            pdf_reader = PyPDF2.PdfReader(f)
            for page_num in range(len(pdf_reader.pages)):
                page = pdf_reader.pages[page_num]
                page_text = page.extract_text()
                text_parts.append(f"[Page {page_num+1}]\n{page_text}")
        except Exception as e:
            print(f"Error reading PDF: {e}")
            return ""
    
    return '\n\n'.join(text_parts)


def run_extraction_test(report_test: ReportTest) -> Dict[str, Any]:
    """Run extraction pipeline on a report."""
    print(f"\n{'='*60}")
    print(f"Testing: {report_test.name}")
    print(f"{'='*60}")
    
    start_time = time.time()
    
    # Extract text
    print("1. Extracting text...")
    try:
        text = extract_text_from_report(report_test)
        print(f"   ✓ Extracted {len(text)} characters")
    except Exception as e:
        print(f"   ✗ Failed to extract text: {e}")
        return {"error": str(e)}
    
    # Run evidence-based extraction
    print("2. Running evidence-based extraction...")
    extractor = EvidenceBasedExtractor(model="gpt-4o-mini")
    
    try:
        results = extractor.extract_with_evidence(
            source_id=report_test.name.lower().replace(" ", "_"),
            source_type="text",
            inline_text=text
        )
        print(f"   ✓ Extracted {results['total_claims']} claims")
        print(f"   ✓ Evidence coverage: {results['evidence_summary']['techniques_with_evidence']} techniques")
    except Exception as e:
        print(f"   ✗ Extraction failed: {e}")
        return {"error": str(e)}
    
    # Apply confidence scoring
    print("3. Applying confidence scoring...")
    scorer = ConfidenceScorer()
    
    try:
        final_claims = scorer.recalibrate_all(
            results['claims'],
            {'malware_type': report_test.malware_type}
        )
        print(f"   ✓ Recalibrated {len(final_claims)} claims")
    except Exception as e:
        print(f"   ✗ Confidence scoring failed: {e}")
        final_claims = results['claims']
    
    # Calculate metrics
    print("4. Calculating metrics...")
    metrics = calculate_metrics(final_claims, report_test)
    
    elapsed = time.time() - start_time
    metrics['elapsed_seconds'] = elapsed
    
    # Print summary
    print(f"\n📊 Results Summary:")
    print(f"   Recall: {metrics['recall']:.1%} ({metrics['found_count']}/{metrics['expected_count']})")
    print(f"   Precision: {metrics['precision']:.1%}")
    print(f"   F1 Score: {metrics['f1']:.3f}")
    print(f"   Must-Find Coverage: {metrics['must_find_pct']:.1%}")
    print(f"   Should-Find Coverage: {metrics['should_find_pct']:.1%}")
    print(f"   Time: {elapsed:.1f}s")
    
    return {
        "report": report_test.name,
        "results": results,
        "claims": final_claims,
        "metrics": metrics
    }


def calculate_metrics(claims: List[Dict], report_test: ReportTest) -> Dict[str, Any]:
    """Calculate performance metrics."""
    # Extract found technique IDs
    found_ids = set()
    for claim in claims:
        for mapping in claim.get('mappings', []):
            tech_id = mapping.get('external_id') or mapping.get('technique_id')
            if tech_id:
                found_ids.add(tech_id)
                # Add parent technique
                if '.' in tech_id:
                    found_ids.add(tech_id.split('.')[0])
    
    # Expected technique IDs
    expected_ids = {t[0] for t in report_test.expected_techniques}
    
    # Calculate basic metrics
    true_positives = found_ids & expected_ids
    false_positives = found_ids - expected_ids
    false_negatives = expected_ids - found_ids
    
    recall = len(true_positives) / len(expected_ids) if expected_ids else 0
    precision = len(true_positives) / len(found_ids) if found_ids else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    # Check must-find and should-find
    must_find_found = [t for t in report_test.must_find if t in found_ids]
    should_find_found = [t for t in report_test.should_find if t in found_ids]
    
    return {
        "recall": recall,
        "precision": precision,
        "f1": f1,
        "found_count": len(true_positives),
        "expected_count": len(expected_ids),
        "found_ids": sorted(found_ids),
        "true_positives": sorted(true_positives),
        "false_positives": sorted(false_positives),
        "false_negatives": sorted(false_negatives),
        "must_find_found": must_find_found,
        "must_find_pct": len(must_find_found) / len(report_test.must_find) if report_test.must_find else 0,
        "should_find_found": should_find_found,
        "should_find_pct": len(should_find_found) / len(report_test.should_find) if report_test.should_find else 0,
    }


def generate_comparative_report(all_results: List[Dict]) -> None:
    """Generate comparative analysis report."""
    print("\n" + "="*80)
    print("COMPARATIVE ANALYSIS REPORT")
    print("="*80)
    
    # Calculate overall metrics
    total_recall = sum(r['metrics']['recall'] for r in all_results if 'metrics' in r)
    total_precision = sum(r['metrics']['precision'] for r in all_results if 'metrics' in r)
    total_f1 = sum(r['metrics']['f1'] for r in all_results if 'metrics' in r)
    valid_results = len([r for r in all_results if 'metrics' in r])
    
    if valid_results > 0:
        avg_recall = total_recall / valid_results
        avg_precision = total_precision / valid_results
        avg_f1 = total_f1 / valid_results
        
        print(f"\n📈 OVERALL PERFORMANCE:")
        print(f"   Average Recall: {avg_recall:.1%}")
        print(f"   Average Precision: {avg_precision:.1%}")
        print(f"   Average F1: {avg_f1:.3f}")
        
        # Check success criteria
        print(f"\n✅ SUCCESS CRITERIA:")
        print(f"   {'✓' if avg_recall >= 0.7 else '✗'} Average recall ≥ 70% (actual: {avg_recall:.1%})")
        print(f"   {'✓' if avg_precision >= 0.4 else '✗'} Precision ≥ 40% (actual: {avg_precision:.1%})")
        print(f"   {'✓' if avg_f1 >= 0.5 else '✗'} F1 Score ≥ 0.5 (actual: {avg_f1:.3f})")
    
    # Report-specific analysis
    print(f"\n📊 REPORT-SPECIFIC RESULTS:")
    for result in all_results:
        if 'error' in result:
            print(f"\n{result.get('report', 'Unknown')}: ERROR - {result['error']}")
            continue
            
        metrics = result['metrics']
        print(f"\n{result['report']}:")
        print(f"   Recall: {metrics['recall']:.1%} ({metrics['found_count']}/{metrics['expected_count']} techniques)")
        print(f"   Precision: {metrics['precision']:.1%}")
        print(f"   Must-Find: {metrics['must_find_pct']:.1%} ({len(metrics['must_find_found'])}/{len(result.get('must_find', []))})")
        print(f"   Top Missed: {', '.join(metrics['false_negatives'][:3])}")
    
    # Common patterns analysis
    print(f"\n🔍 PATTERN ANALYSIS:")
    all_missed = defaultdict(int)
    all_found = defaultdict(int)
    
    for result in all_results:
        if 'metrics' in result:
            for tech_id in result['metrics']['false_negatives']:
                all_missed[tech_id] += 1
            for tech_id in result['metrics']['true_positives']:
                all_found[tech_id] += 1
    
    # Most commonly missed
    if all_missed:
        print(f"\n   Most Commonly Missed:")
        for tech_id, count in sorted(all_missed.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"      {tech_id}: missed in {count}/{valid_results} reports")
    
    # Most reliably found
    if all_found:
        print(f"\n   Most Reliably Found:")
        for tech_id, count in sorted(all_found.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"      {tech_id}: found in {count}/{valid_results} reports")
    
    # Save detailed results
    output_file = Path("/tmp/extraction_test_results.json")
    with open(output_file, "w") as f:
        json.dump({
            "test_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "overall_metrics": {
                "avg_recall": avg_recall if valid_results > 0 else 0,
                "avg_precision": avg_precision if valid_results > 0 else 0,
                "avg_f1": avg_f1 if valid_results > 0 else 0
            },
            "report_results": [
                {
                    "report": r.get("report"),
                    "metrics": r.get("metrics"),
                    "error": r.get("error")
                }
                for r in all_results
            ],
            "pattern_analysis": {
                "commonly_missed": dict(all_missed),
                "reliably_found": dict(all_found)
            }
        }, f, indent=2)
    
    print(f"\n💾 Detailed results saved to: {output_file}")


def main():
    """Run comprehensive extraction tests."""
    print("="*80)
    print("ENHANCED EXTRACTION PIPELINE TEST")
    print("="*80)
    print(f"Testing {len(REPORT_TESTS)} reports with enhanced extraction...")
    
    all_results = []
    
    for report_test in REPORT_TESTS:
        try:
            result = run_extraction_test(report_test)
            result['must_find'] = report_test.must_find
            result['should_find'] = report_test.should_find
            all_results.append(result)
        except Exception as e:
            print(f"✗ Test failed for {report_test.name}: {e}")
            all_results.append({
                "report": report_test.name,
                "error": str(e)
            })
    
    # Generate comparative report
    generate_comparative_report(all_results)
    
    # Return success based on average recall
    valid_results = [r for r in all_results if 'metrics' in r]
    if valid_results:
        avg_recall = sum(r['metrics']['recall'] for r in valid_results) / len(valid_results)
        return avg_recall >= 0.7
    
    return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)