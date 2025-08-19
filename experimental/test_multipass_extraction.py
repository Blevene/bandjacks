#!/usr/bin/env python3
"""
Test multi-pass extraction on DarkCloud PDF.
"""

import sys
import json
import time
from pathlib import Path
from typing import Dict, Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from bandjacks.llm.multipass_extractor import MultiPassExtractor
import PyPDF2


# Expected techniques from DarkCloud report
EXPECTED_TECHNIQUES = [
    ("T1566", "Phishing", "Initial phishing email delivery"),
    ("T1566.001", "Spearphishing Attachment", "RAR/ZIP attachments"),
    ("T1059.001", "PowerShell", "PowerShell execution"),
    ("T1027", "Obfuscated Files or Information", "ConfuserEx obfuscation"),
    ("T1055", "Process Injection", "Process hollowing"),
    ("T1140", "Deobfuscate/Decode", "3DES/RC4 decryption"),
    ("T1071", "Application Layer Protocol", "Telegram C2"),
    ("T1071.001", "Web Protocols", "HTTPS for C2"),
    ("T1204.002", "Malicious File", "User execution of attachment"),
    ("T1547", "Boot or Logon Autostart", "Persistence"),
    ("T1555", "Credentials from Password Stores", "Browser credential theft"),
    ("T1005", "Data from Local System", "File collection"),
    ("T1041", "Exfiltration Over C2", "Data exfiltration via Telegram"),
    ("T1083", "File and Directory Discovery", "Searches for files"),
    ("T1057", "Process Discovery", "Enumerates processes"),
]


def extract_pdf_text(pdf_path: Path) -> str:
    """Extract text from PDF."""
    text_parts = []
    
    with open(pdf_path, 'rb') as f:
        pdf_reader = PyPDF2.PdfReader(f)
        
        for page_num in range(len(pdf_reader.pages)):
            page = pdf_reader.pages[page_num]
            page_text = page.extract_text()
            text_parts.append(f"[Page {page_num+1}]\n{page_text}")
    
    return '\n\n'.join(text_parts)


def test_multipass_extraction():
    """Test multi-pass extraction on DarkCloud PDF."""
    
    print("="*80)
    print("MULTI-PASS EXTRACTION TEST - DARKCLOUD STEALER")
    print("="*80)
    
    # Path to PDF
    pdf_path = Path(__file__).parent / "samples" / "reports" / "new-darkcloud-stealer-infection-chain.pdf"
    
    if not pdf_path.exists():
        print(f"❌ PDF not found at {pdf_path}")
        return None
    
    print(f"📄 Testing with: {pdf_path.name}\n")
    
    # Extract PDF text
    print("1. Extracting PDF text...")
    pdf_text = extract_pdf_text(pdf_path)
    print(f"   ✅ Extracted {len(pdf_text)} characters\n")
    
    # Initialize multi-pass extractor
    print("2. Running MULTI-PASS extraction...")
    print("   Pass 1: Primary (high confidence)")
    print("   Pass 2: Exploratory (medium confidence)")
    print("   Pass 3: Gap filling (low confidence + inference)")
    
    start_time = time.time()
    
    extractor = MultiPassExtractor(model="gpt-4o-mini")
    
    # Run multi-pass extraction
    result = extractor.extract_multi_pass(
        source_id="darkcloud-multipass",
        source_type="pdf",
        inline_text=pdf_text
    )
    
    elapsed = time.time() - start_time
    
    print(f"\n   ✅ Multi-pass extraction completed in {elapsed:.1f} seconds")
    print(f"   📊 Total claims: {result.get('total_claims', 0)}")
    
    # Extract techniques from all passes
    all_techniques = set()
    if 'multi_pass_analysis' in result:
        analysis = result['multi_pass_analysis']
        if 'cumulative_techniques' in analysis:
            all_techniques = set(analysis['cumulative_techniques'].keys())
    
    print(f"   🎯 Unique techniques: {len(all_techniques)}")
    
    # Show techniques by pass
    if 'multi_pass_analysis' in result:
        techniques_by_pass = result['multi_pass_analysis'].get('techniques_by_pass', {})
        for pass_name, techniques in techniques_by_pass.items():
            unique_in_pass = set(techniques)
            print(f"   Pass '{pass_name}': {len(unique_in_pass)} techniques")
    
    # Save results
    output_file = Path("/tmp/darkcloud_multipass_results.json")
    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)
    print(f"   💾 Saved to: {output_file}")
    
    return result


def analyze_results(result: Dict[str, Any]):
    """Analyze extraction results against expected techniques."""
    
    print("\n" + "="*80)
    print("RESULTS ANALYSIS")
    print("="*80)
    
    # Extract technique IDs from all claims
    extracted_ids = set()
    for claim in result.get('claims', []):
        for mapping in claim.get('mappings', []):
            ext_id = mapping.get('technique_id')
            if ext_id:
                extracted_ids.add(ext_id)
                # Add parent technique
                if '.' in ext_id:
                    extracted_ids.add(ext_id.split('.')[0])
    
    # Also check cumulative techniques from multi-pass analysis
    if 'multi_pass_analysis' in result:
        cumulative = result['multi_pass_analysis'].get('cumulative_techniques', {})
        extracted_ids.update(cumulative.keys())
    
    expected_ids = {t[0] for t in EXPECTED_TECHNIQUES}
    
    # Calculate metrics
    found = extracted_ids & expected_ids
    missed = expected_ids - extracted_ids
    extra = extracted_ids - expected_ids
    
    recall = len(found) / len(expected_ids) if expected_ids else 0
    precision = len(found) / len(extracted_ids) if extracted_ids else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    print(f"\n📈 METRICS:")
    print(f"   Recall: {recall:.1%} ({len(found)}/{len(expected_ids)} found)")
    print(f"   Precision: {precision:.1%} ({len(found)}/{len(extracted_ids)} correct)")
    print(f"   F1 Score: {f1:.3f}")
    
    print(f"\n✅ CORRECTLY FOUND ({len(found)}):")
    for tid in sorted(found):
        name = next((t[1] for t in EXPECTED_TECHNIQUES if t[0] == tid), "")
        # Get confidence and passes from analysis
        confidence = "N/A"
        passes = []
        if 'multi_pass_analysis' in result:
            cumulative = result['multi_pass_analysis'].get('cumulative_techniques', {})
            if tid in cumulative:
                tech_info = cumulative[tid]
                confidence = tech_info.get('confidence_max', 0)
                passes = tech_info.get('passes_found', [])
        print(f"   {tid}: {name} (confidence: {confidence}%, passes: {', '.join(passes)})")
    
    print(f"\n❌ MISSED ({len(missed)}):")
    for tid in sorted(missed):
        name = next((t[1] for t in EXPECTED_TECHNIQUES if t[0] == tid), "")
        desc = next((t[2] for t in EXPECTED_TECHNIQUES if t[0] == tid), "")
        print(f"   {tid}: {name} - {desc}")
    
    print(f"\n➕ ADDITIONAL FOUND ({len(extra)}):")
    for tid in sorted(extra)[:10]:
        # Check if it's an inferred technique
        is_inferred = False
        for claim in result.get('claims', []):
            if claim.get('type') == 'inferred-technique':
                for mapping in claim.get('mappings', []):
                    if mapping.get('technique_id') == tid:
                        is_inferred = True
                        break
        marker = " [INFERRED]" if is_inferred else ""
        print(f"   {tid}{marker}")
    
    # Show kill chain gap analysis
    if 'multi_pass_analysis' in result:
        gaps = result['multi_pass_analysis'].get('kill_chain_gaps', {})
        if gaps:
            print(f"\n🔍 KILL CHAIN GAPS IDENTIFIED:")
            for phase, suggestions in gaps.items():
                print(f"   {phase}: {'; '.join(suggestions)}")
    
    return {
        'recall': recall,
        'precision': precision,
        'f1': f1,
        'found': len(found),
        'missed': len(missed),
        'extra': len(extra)
    }


def main():
    """Run the multi-pass extraction test."""
    
    # Run multi-pass extraction
    result = test_multipass_extraction()
    
    if result:
        # Analyze results
        metrics = analyze_results(result)
        
        # Final summary
        print("\n" + "="*80)
        print("SUMMARY")
        print("="*80)
        
        if metrics['recall'] > 0.5:  # Better than 50%
            print(f"✅ SUCCESS: Recall reached {metrics['recall']:.1%}")
        elif metrics['recall'] > 0.4:  # Better than 40%
            print(f"✅ IMPROVED: Recall increased to {metrics['recall']:.1%}")
        else:
            print(f"⚠️ Similar performance: {metrics['recall']:.1%} recall")
        
        print(f"📊 F1 Score: {metrics['f1']:.3f}")
        print(f"🎯 Found {metrics['found']}/{len(EXPECTED_TECHNIQUES)} expected techniques")
        
        # Show improvement over single-pass
        print(f"\n📈 Multi-pass advantages:")
        print(f"   - Progressive refinement across {result.get('passes', 0)} passes")
        print(f"   - Kill chain gap analysis for logical completeness")
        print(f"   - Behavioral abstraction for better coverage")
        print(f"   - Inference for implied techniques")
        
        return metrics['recall'] > 0.5  # Success if >50% recall
    
    return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)