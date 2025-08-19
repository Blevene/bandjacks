#!/usr/bin/env python3
"""
Test the full extraction pipeline on the DarkCloud Stealer PDF report.

This script tests:
1. PDF text extraction
2. LLM-based TTP extraction
3. STIX bundle generation
4. Vector search matching
5. Graph ingestion (optional)
"""

import sys
import json
import time
from pathlib import Path
from typing import Dict, Any, List

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from bandjacks.loaders.parse_text import extract_text
from bandjacks.loaders.chunker import split_into_chunks
from bandjacks.llm.extractor import LLMExtractor
from bandjacks.llm.stix_builder import STIXBuilder
from bandjacks.loaders.search_nodes import ttx_search
from bandjacks.services.api.settings import settings
import httpx


# Expected techniques based on DarkCloud report content
EXPECTED_TECHNIQUES = [
    ("T1566", "Phishing", "Phishing emails with malicious attachments"),
    ("T1566.001", "Spearphishing Attachment", "RAR/ZIP attachments"),
    ("T1059.001", "PowerShell", "PowerShell execution for payload delivery"),
    ("T1027", "Obfuscated Files or Information", "ConfuserEx obfuscation"),
    ("T1055", "Process Injection", "Process hollowing technique"),
    ("T1140", "Deobfuscate/Decode Files or Information", "3DES/RC4 decryption"),
    ("T1071", "Application Layer Protocol", "Telegram API for C2"),
    ("T1204.002", "Malicious File", "User opens malicious attachment"),
    ("T1547", "Boot or Logon Autostart Execution", "Persistence mechanism"),
    ("T1555", "Credentials from Password Stores", "Browser credential theft"),
    ("T1005", "Data from Local System", "File theft from Desktop/Documents"),
    ("T1041", "Exfiltration Over C2 Channel", "Data sent via Telegram"),
]


def extract_pdf_text(pdf_path: Path) -> Dict[str, Any]:
    """Extract text from PDF file."""
    print("\n" + "="*80)
    print("STEP 1: PDF TEXT EXTRACTION")
    print("="*80)
    
    if not pdf_path.exists():
        raise FileNotFoundError(f"PDF not found: {pdf_path}")
    
    print(f"📄 Processing: {pdf_path.name}")
    
    # Extract text using the parse_text module with file path
    # We'll use PyPDF2 directly since extract_text expects different input
    import PyPDF2
    
    text_parts = []
    metadata = {}
    
    with open(pdf_path, 'rb') as f:
        pdf_reader = PyPDF2.PdfReader(f)
        num_pages = len(pdf_reader.pages)
        metadata['total_pages'] = num_pages
        
        for page_num in range(num_pages):
            page = pdf_reader.pages[page_num]
            page_text = page.extract_text()
            text_parts.append(f"[Page {page_num+1}]\n{page_text}")
    
    extracted = {
        'text': '\n\n'.join(text_parts),
        'metadata': metadata
    }
    
    print(f"✅ Extracted {len(extracted['text'])} characters")
    print(f"   Pages: {extracted['metadata'].get('total_pages', 'Unknown')}")
    
    # Save for debugging
    debug_file = Path("/tmp/darkcloud_extracted.txt")
    with open(debug_file, "w") as f:
        f.write(extracted['text'])
    print(f"   Saved to: {debug_file}")
    
    return extracted


def test_llm_extraction(text: str) -> Dict[str, Any]:
    """Test LLM extraction on the text."""
    print("\n" + "="*80)
    print("STEP 2: LLM TTP EXTRACTION")
    print("="*80)
    
    # Initialize extractor
    extractor = LLMExtractor(model="gpt-4o-mini")
    
    # Chunk the text
    chunks = split_into_chunks(
        source_id="darkcloud-pdf",
        text=text,
        target_chars=1500,  # Larger chunks for better context
        overlap=200
    )
    
    print(f"📝 Processing {len(chunks)} text chunks...")
    
    all_claims = []
    for i, chunk in enumerate(chunks):
        print(f"   Chunk {i+1}/{len(chunks)}: {len(chunk['text'])} chars")
        
        # Extract from chunk
        result = extractor.extract_chunk(
            chunk_id=chunk['id'],
            text=chunk['text']
        )
        
        if result.get('claims'):
            all_claims.extend(result['claims'])
            print(f"     → Found {len(result['claims'])} claims")
    
    print(f"\n✅ Total claims extracted: {len(all_claims)}")
    
    # Aggregate results
    extraction = {
        "source_id": "darkcloud-pdf-test",
        "source_type": "pdf",
        "title": "DarkCloud Stealer Analysis",
        "chunks_processed": len(chunks),
        "total_claims": len(all_claims),
        "claims": all_claims
    }
    
    # Save for debugging
    debug_file = Path("/tmp/darkcloud_claims.json")
    with open(debug_file, "w") as f:
        json.dump(extraction, f, indent=2)
    print(f"   Saved claims to: {debug_file}")
    
    return extraction


def build_stix_bundle(extraction: Dict[str, Any]) -> Dict[str, Any]:
    """Convert extraction to STIX bundle."""
    print("\n" + "="*80)
    print("STEP 3: STIX BUNDLE GENERATION")
    print("="*80)
    
    builder = STIXBuilder()
    
    # Create report object
    report_id = builder.create_report(
        name=extraction.get("title", "DarkCloud Stealer Report"),
        description="Extracted threat intelligence from DarkCloud Stealer analysis",
        source_url="samples/reports/new-darkcloud-stealer-infection-chain.pdf"
    )
    
    # Process claims into STIX objects
    technique_ids = set()
    for claim in extraction['claims']:
        if claim.get('technique_id'):
            # Create attack pattern
            ap_id = builder.create_attack_pattern(
                technique_id=claim['technique_id'],
                name=claim.get('technique_name', ''),
                confidence=claim.get('confidence', 50),
                evidence=claim.get('evidence', '')
            )
            technique_ids.add(claim['technique_id'])
    
    # Build final bundle
    bundle = builder.build_bundle()
    
    print(f"✅ Generated STIX bundle with {len(bundle['objects'])} objects")
    print(f"   Techniques: {len(technique_ids)}")
    print(f"   Technique IDs: {sorted(technique_ids)}")
    
    # Save bundle
    bundle_file = Path("/tmp/darkcloud_bundle.json")
    with open(bundle_file, "w") as f:
        json.dump(bundle, f, indent=2)
    print(f"   Saved bundle to: {bundle_file}")
    
    return bundle


def test_vector_search(claims: List[Dict]) -> Dict[str, List]:
    """Test vector search for extracted techniques."""
    print("\n" + "="*80)
    print("STEP 4: VECTOR SEARCH VALIDATION")
    print("="*80)
    
    search_results = {}
    
    # Test search for each unique technique claim
    unique_techniques = {}
    for claim in claims:
        if claim.get('technique_id') and claim.get('evidence'):
            tech_id = claim['technique_id']
            if tech_id not in unique_techniques:
                unique_techniques[tech_id] = claim['evidence']
    
    print(f"🔍 Testing vector search for {len(unique_techniques)} techniques...")
    
    for tech_id, evidence in unique_techniques.items():
        # Search using the evidence text
        results = ttx_search(
            os_url=settings.opensearch_url,
            index="bandjacks_attack_nodes-v1",
            text=evidence[:500],  # Limit evidence length
            top_k=5
        )
        
        if results:
            # Check if correct technique is in top results
            found = False
            for r in results:
                if r.get('external_id') == tech_id:
                    found = True
                    break
            
            search_results[tech_id] = {
                'found': found,
                'top_match': results[0] if results else None,
                'score': results[0].get('score', 0) if results else 0
            }
            
            status = "✅" if found else "⚠️"
            print(f"   {status} {tech_id}: Top match = {results[0].get('external_id', 'None')} (score: {results[0].get('score', 0):.3f})")
    
    return search_results


def analyze_results(extraction: Dict, bundle: Dict, search_results: Dict):
    """Analyze and report on extraction results."""
    print("\n" + "="*80)
    print("RESULTS ANALYSIS")
    print("="*80)
    
    # Extract technique IDs from claims
    extracted_techniques = set()
    for claim in extraction['claims']:
        if claim.get('technique_id'):
            extracted_techniques.add(claim['technique_id'])
    
    # Compare with expected
    expected_ids = {t[0] for t in EXPECTED_TECHNIQUES}
    
    found = extracted_techniques & expected_ids
    missed = expected_ids - extracted_techniques
    extra = extracted_techniques - expected_ids
    
    print(f"\n📊 Extraction Performance:")
    print(f"   Expected techniques: {len(expected_ids)}")
    print(f"   Extracted techniques: {len(extracted_techniques)}")
    print(f"   Correctly found: {len(found)} ({len(found)/len(expected_ids)*100:.1f}%)")
    
    if found:
        print(f"\n✅ Found techniques:")
        for tid in sorted(found):
            name = next((t[1] for t in EXPECTED_TECHNIQUES if t[0] == tid), "Unknown")
            print(f"   - {tid}: {name}")
    
    if missed:
        print(f"\n❌ Missed techniques:")
        for tid in sorted(missed):
            name = next((t[1] for t in EXPECTED_TECHNIQUES if t[0] == tid), "Unknown")
            desc = next((t[2] for t in EXPECTED_TECHNIQUES if t[0] == tid), "")
            print(f"   - {tid}: {name} ({desc})")
    
    if extra:
        print(f"\n➕ Additional techniques found:")
        for tid in sorted(extra):
            print(f"   - {tid}")
    
    # Vector search accuracy
    if search_results:
        correct_searches = sum(1 for r in search_results.values() if r['found'])
        print(f"\n🔍 Vector Search Accuracy:")
        print(f"   Correct matches: {correct_searches}/{len(search_results)} ({correct_searches/len(search_results)*100:.1f}%)")
    
    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print(f"✅ Extraction recall: {len(found)/len(expected_ids)*100:.1f}%")
    print(f"✅ Total claims: {len(extraction['claims'])}")
    print(f"✅ STIX objects: {len(bundle['objects'])}")
    
    return {
        'found': list(found),
        'missed': list(missed),
        'extra': list(extra),
        'recall': len(found)/len(expected_ids) if expected_ids else 0
    }


def main():
    """Run the full pipeline test."""
    print("="*80)
    print("DARKCLOUD STEALER - FULL PIPELINE TEST")
    print("="*80)
    
    # Path to PDF
    pdf_path = Path(__file__).parent / "samples" / "reports" / "new-darkcloud-stealer-infection-chain.pdf"
    
    try:
        # Step 1: Extract PDF text
        pdf_data = extract_pdf_text(pdf_path)
        
        # Step 2: Run LLM extraction
        extraction = test_llm_extraction(pdf_data['text'])
        
        # Step 3: Build STIX bundle
        bundle = build_stix_bundle(extraction)
        
        # Step 4: Test vector search
        search_results = test_vector_search(extraction['claims'])
        
        # Step 5: Analyze results
        analysis = analyze_results(extraction, bundle, search_results)
        
        # Save final report
        report = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'pdf': str(pdf_path),
            'extraction': {
                'chunks': extraction['chunks_processed'],
                'claims': extraction['total_claims'],
                'techniques': len(set(c.get('technique_id') for c in extraction['claims'] if c.get('technique_id')))
            },
            'stix': {
                'objects': len(bundle['objects']),
                'techniques': len([o for o in bundle['objects'] if o.get('type') == 'attack-pattern'])
            },
            'analysis': analysis
        }
        
        report_file = Path("/tmp/darkcloud_pipeline_report.json")
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n📄 Full report saved to: {report_file}")
        
        return analysis['recall'] >= 0.6  # Success if 60%+ recall
        
    except Exception as e:
        print(f"\n❌ Pipeline failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)