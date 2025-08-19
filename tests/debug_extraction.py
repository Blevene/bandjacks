#!/usr/bin/env python3
"""Debug script to test extraction with progressive text chunks."""

import json
import requests
import PyPDF2
from pathlib import Path

def test_extraction(text, chunk_name):
    """Test extraction with given text chunk."""
    response = requests.post('http://localhost:8000/v1/extract/report', json={
        'source_url': 'https://unit42.paloaltonetworks.com/darkcloud-stealer',
        'source_type': 'md',
        'content': text,
        'title': f'DarkCloud Test - {chunk_name}',
        'method': 'llm',
        'confidence_threshold': 50.0,
        'auto_ingest': False
    })
    
    if response.status_code != 200:
        return f"ERROR: {response.status_code}"
    
    data = response.json()
    stats = data['stats']
    
    # Count techniques
    techniques = []
    for obj in data['bundle']['objects']:
        if obj['type'] == 'attack-pattern':
            refs = obj.get('external_references', [])
            for ref in refs:
                if ref.get('source_name') == 'mitre-attack':
                    techniques.append(ref.get('external_id', '??'))
                    break
    
    return {
        'claims': stats['claims_extracted'],
        'techniques': len(techniques),
        'technique_ids': techniques,
        'objects': stats['stix_objects_created']
    }


def main():
    # Read PDF
    pdf_path = Path('samples/reports/new-darkcloud-stealer-infection-chain.pdf')
    with open(pdf_path, 'rb') as f:
        reader = PyPDF2.PdfReader(f)
        full_text = ''
        for page in reader.pages:
            full_text += page.extract_text() + '\n'
    
    print(f"Total PDF text length: {len(full_text)} characters")
    print("=" * 60)
    
    # Test with different chunk sizes
    test_sizes = [500, 1000, 2000, 4000, 8000, 12000, len(full_text)]
    
    for size in test_sizes:
        if size > len(full_text):
            size = len(full_text)
        
        print(f"\nTesting with {size} characters...")
        text_chunk = full_text[:size]
        
        # Clean the text to avoid JSON issues
        # Replace problematic characters
        text_chunk = text_chunk.replace('\x00', ' ')  # Null bytes
        text_chunk = text_chunk.replace('\r', '\n')   # Normalize line endings
        
        result = test_extraction(text_chunk, f"{size} chars")
        
        if isinstance(result, str):
            print(f"  ❌ {result}")
        else:
            print(f"  ✅ Claims: {result['claims']}, Techniques: {result['techniques']}, Objects: {result['objects']}")
            if result['technique_ids']:
                print(f"     Techniques found: {', '.join(result['technique_ids'])}")
    
    # Now test the full text with special handling
    print("\n" + "=" * 60)
    print("Testing FULL text with special handling...")
    
    # Clean the full text more aggressively
    clean_text = full_text
    # Remove null bytes and other control characters
    clean_text = ''.join(char if ord(char) >= 32 or char == '\n' else ' ' for char in clean_text)
    # Normalize whitespace
    clean_text = ' '.join(clean_text.split())
    
    result = test_extraction(clean_text, "Full Cleaned")
    if isinstance(result, str):
        print(f"  ❌ {result}")
    else:
        print(f"  ✅ Claims: {result['claims']}, Techniques: {result['techniques']}, Objects: {result['objects']}")
        if result['technique_ids']:
            print(f"     Techniques found: {', '.join(result['technique_ids'])}")


if __name__ == "__main__":
    main()