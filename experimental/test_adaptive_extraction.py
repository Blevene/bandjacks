#!/usr/bin/env python3
"""
Test the adaptive extraction improvements against the DarkCloud PDF.
Compare with original extraction results.
"""

import sys
import json
import time
from pathlib import Path
from typing import Dict, Any, List

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from bandjacks.llm.adaptive_extractor import AdaptiveExtractor
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


def test_adaptive_extraction():
    """Test the adaptive extractor on DarkCloud PDF."""
    
    print("="*80)
    print("ADAPTIVE EXTRACTION TEST - DARKCLOUD STEALER")
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
    
    # Initialize adaptive extractor
    print("2. Running ADAPTIVE extraction...")
    start_time = time.time()
    
    extractor = AdaptiveExtractor(model="gpt-4o-mini")
    
    # Run extraction - bypass PDF parsing since we already have text
    from bandjacks.loaders.chunker import split_into_chunks
    
    # Chunk the text directly - optimized for better context capture
    chunks = split_into_chunks(
        source_id="darkcloud-adaptive",
        text=pdf_text,
        target_chars=6000,  # Larger chunks for more context
        overlap=500  # More overlap to prevent missing boundary techniques
    )
    
    print(f"   📝 Processing {len(chunks)} chunks...")
    
    # Process all chunks for thorough extraction
    chunk_results = []
    chunks_to_process = chunks  # Process all chunks
    
    for i, chunk in enumerate(chunks_to_process):
        print(f"   Chunk {i+1}/{len(chunks_to_process)}: {len(chunk['text'])} chars")
        
        # Build context from previous findings
        if i > 0 and extractor.context.techniques_found:
            prev_techniques = list(extractor.context.techniques_found.keys())[:5]
            doc_context = f"DarkCloud Stealer report. Previously found: {', '.join(prev_techniques)}"
        else:
            doc_context = "DarkCloud Stealer threat report"
        
        result_chunk = extractor.extract_chunk_adaptive(
            chunk_id=chunk['id'],
            text=chunk['text'],
            document_context=doc_context
        )
        
        chunk_results.append(result_chunk)
        if result_chunk.get('claims'):
            print(f"     → Found {len(result_chunk['claims'])} claims")
    
    # Validation pass - check for commonly missed patterns
    validation_patterns = {
        "telegram": "T1071",  # Application Layer Protocol
        "browser": "T1555",  # Credentials from Password Stores
        "credential": "T1555",
        "startup": "T1547",  # Boot or Logon Autostart
        "registry": "T1547",
        "exfiltrat": "T1041",  # Exfiltration Over C2
        "steal": "T1005",  # Data from Local System
    }
    
    print("\n   🔍 Running validation pass...")
    text_lower = pdf_text.lower()
    suggested_additions = []
    
    for pattern, technique_id in validation_patterns.items():
        if pattern in text_lower:
            # Check if we already found this technique
            found_ids = set()
            for claim in extractor.all_claims:
                for mapping in claim.get('mappings', []):
                    found_ids.add(mapping.get('technique_id', ''))
            
            if technique_id not in found_ids:
                print(f"     ⚠️ Pattern '{pattern}' suggests {technique_id} (not found)")
                suggested_additions.append((pattern, technique_id))
    
    # Build final result similar to extract_document_adaptive
    result = {
        "source_id": "darkcloud-adaptive",
        "source_type": "pdf",
        "extraction_mode": "adaptive",
        "chunks_processed": len(chunks_to_process),
        "total_claims": len(extractor.all_claims),
        "claims": extractor._deduplicate_claims(extractor.all_claims),
        "context": {
            "threat_actors": extractor.context.threat_actors,
            "malware": extractor.context.malware,
            "techniques": list(extractor.context.techniques_found.keys()),
            "kill_chain": dict(extractor.context.kill_chain_phases),
            "unique_aspects": extractor.context.unique_aspects
        },
        "synthesis": extractor._synthesize_attack_narrative(),
        "validation": {
            "patterns_checked": list(validation_patterns.keys()),
            "suggested_additions": suggested_additions
        },
        "metrics": {
            "elapsed_seconds": 0,
            "chunks": len(chunks_to_process),
            "claims_per_chunk": len(extractor.all_claims) / len(chunks_to_process) if chunks_to_process else 0
        }
    }
    
    elapsed = time.time() - start_time
    
    print(f"\n   ✅ Extraction completed in {elapsed:.1f} seconds")
    print(f"   📊 Total claims: {result['total_claims']}")
    print(f"   🎯 Unique techniques: {len(result['context']['techniques'])}")
    
    # Save results
    output_file = Path("/tmp/darkcloud_adaptive_results.json")
    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)
    print(f"   💾 Saved to: {output_file}")
    
    return result


def analyze_results(result: Dict[str, Any]):
    """Analyze extraction results against expected techniques."""
    
    print("\n" + "="*80)
    print("RESULTS ANALYSIS")
    print("="*80)
    
    # Extract technique IDs (check both external_id and technique_id)
    extracted_ids = set()
    for claim in result.get('claims', []):
        for mapping in claim.get('mappings', []):
            # Check both external_id and technique_id fields
            ext_id = mapping.get('external_id') or mapping.get('technique_id')
            if ext_id:
                extracted_ids.add(ext_id)
                # Add parent technique
                if '.' in ext_id:
                    extracted_ids.add(ext_id.split('.')[0])
    
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
        # Find confidence from claims
        confidence = 0
        for claim in result.get('claims', []):
            for mapping in claim.get('mappings', []):
                if mapping.get('external_id') == tid:
                    confidence = max(confidence, mapping.get('confidence', 0))
        print(f"   {tid}: {name} (confidence: {confidence}%)")
    
    print(f"\n❌ MISSED ({len(missed)}):")
    for tid in sorted(missed):
        name = next((t[1] for t in EXPECTED_TECHNIQUES if t[0] == tid), "")
        desc = next((t[2] for t in EXPECTED_TECHNIQUES if t[0] == tid), "")
        print(f"   {tid}: {name} - {desc}")
    
    print(f"\n➕ ADDITIONAL FOUND ({len(extra)}):")
    for tid in sorted(extra)[:10]:
        print(f"   {tid}")
    
    # Show context insights
    if result.get('context'):
        ctx = result['context']
        print(f"\n🔍 CONTEXT INSIGHTS:")
        if ctx.get('threat_actors'):
            print(f"   Actors: {', '.join(ctx['threat_actors'])}")
        if ctx.get('malware'):
            print(f"   Malware: {', '.join(ctx['malware'])}")
        if ctx.get('kill_chain'):
            print(f"   Kill chain phases: {len(ctx['kill_chain'])} covered")
        if ctx.get('unique_aspects'):
            print(f"   Unique aspects: {len(ctx['unique_aspects'])} noted")
    
    # Show synthesis
    if result.get('synthesis'):
        syn = result['synthesis']
        print(f"\n📝 ATTACK SYNTHESIS:")
        if syn.get('narrative'):
            print(f"   {syn['narrative']}")
        if syn.get('confidence_avg'):
            print(f"   Average confidence: {syn['confidence_avg']:.1f}%")
    
    return {
        'recall': recall,
        'precision': precision,
        'f1': f1,
        'found': len(found),
        'missed': len(missed),
        'extra': len(extra)
    }


def compare_with_original():
    """Compare adaptive results with original extraction."""
    
    print("\n" + "="*80)
    print("COMPARISON WITH ORIGINAL EXTRACTION")
    print("="*80)
    
    # Load original results if available
    original_file = Path("/tmp/darkcloud_claims.json")
    if original_file.exists():
        with open(original_file) as f:
            original = json.load(f)
        
        # Count original techniques
        original_techniques = set()
        for claim in original.get('claims', []):
            for mapping in claim.get('mappings', []):
                if mapping.get('external_id'):
                    original_techniques.add(mapping['external_id'])
        
        print(f"\n📊 Original extraction:")
        print(f"   Claims: {original.get('total_claims', 0)}")
        print(f"   Techniques: {len(original_techniques)}")
        print(f"   Recall: ~25% (3/12 techniques)")
    
    # Load adaptive results
    adaptive_file = Path("/tmp/darkcloud_adaptive_results.json")
    if adaptive_file.exists():
        with open(adaptive_file) as f:
            adaptive = json.load(f)
        
        adaptive_techniques = set()
        for claim in adaptive.get('claims', []):
            for mapping in claim.get('mappings', []):
                if mapping.get('external_id'):
                    adaptive_techniques.add(mapping['external_id'])
        
        print(f"\n📊 Adaptive extraction:")
        print(f"   Claims: {adaptive.get('total_claims', 0)}")
        print(f"   Techniques: {len(adaptive_techniques)}")
        
        # Calculate improvement
        if original_file.exists():
            improvement = len(adaptive_techniques) - len(original_techniques)
            print(f"\n📈 Improvement: +{improvement} techniques")
            
            # Show new techniques found
            new_techniques = adaptive_techniques - original_techniques
            if new_techniques:
                print(f"\n🆕 New techniques found by adaptive approach:")
                for tid in sorted(new_techniques)[:10]:
                    print(f"   {tid}")


def main():
    """Run the adaptive extraction test."""
    
    # Run adaptive extraction
    result = test_adaptive_extraction()
    
    if result:
        # Analyze results
        metrics = analyze_results(result)
        
        # Compare with original
        compare_with_original()
        
        # Final summary
        print("\n" + "="*80)
        print("SUMMARY")
        print("="*80)
        
        if metrics['recall'] > 0.25:  # Better than original 25%
            print(f"✅ IMPROVED: Recall increased to {metrics['recall']:.1%}")
        else:
            print(f"⚠️ Similar performance: {metrics['recall']:.1%} recall")
        
        print(f"📊 F1 Score: {metrics['f1']:.3f}")
        print(f"🎯 Found {metrics['found']}/{len(EXPECTED_TECHNIQUES)} expected techniques")
        
        return metrics['recall'] > 0.4  # Success if >40% recall
    
    return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)