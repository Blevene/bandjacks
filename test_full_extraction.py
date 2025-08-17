#!/usr/bin/env python3
"""Test full LLM extraction pipeline with real OpenAI."""

import os
import sys
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add project to path
sys.path.insert(0, '/Volumes/tank/bandjacks')

from bandjacks.llm.extractor import extract_with_llm
from bandjacks.llm.stix_converter import llm_to_stix_bundle, apply_safeguards


def test_full_extraction():
    """Test the complete extraction pipeline."""
    
    # Sample threat report text
    threat_report = """
    ## APT29 Campaign Analysis
    
    The threat actor APT29, also known as Cozy Bear, has been conducting 
    sophisticated attacks against government organizations. 
    
    ### Initial Access
    The group primarily uses spearphishing emails with malicious PDF attachments 
    to gain initial access to target networks. These emails are carefully crafted 
    to appear legitimate and often impersonate trusted entities.
    
    ### Execution and Persistence
    Once the malicious attachment is opened, it drops a PowerShell script that 
    executes in memory. The PowerShell script then establishes persistence by 
    creating registry run keys (T1547.001) and scheduled tasks.
    
    ### Credential Access
    APT29 has been observed using Mimikatz to dump credentials from memory, 
    specifically targeting LSASS process memory. They also harvest credentials 
    from web browsers and credential stores.
    
    ### Lateral Movement
    The group moves laterally through the network using Remote Desktop Protocol 
    (RDP) and PowerShell remoting. They have also been seen using PsExec for 
    remote execution on other systems.
    
    ### Command and Control
    For C2 communications, APT29 uses HTTPS traffic to blend in with normal 
    web traffic. They employ domain fronting techniques to hide their actual 
    C2 servers behind legitimate CDN services.
    """
    
    print("=" * 60)
    print("Full LLM Extraction Pipeline Test")
    print("=" * 60)
    
    print("\n1. Extracting TTPs from threat report...")
    print("-" * 40)
    
    try:
        # Note: This would normally connect to real APIs
        # For testing, we'll use a simplified version
        
        # Extract with LLM
        result = extract_with_llm(
            source_id="apt29-report-001",
            source_type="md",
            inline_text=threat_report,
            max_candidates=5,
            chunking_params={"target_chars": 800, "overlap": 100}
        )
        
        print(f"✓ Extraction completed")
        print(f"  Chunks processed: {len(result.get('chunks', []))}")
        
        # Count claims
        total_claims = sum(
            len(chunk.get('claims', [])) 
            for chunk in result.get('chunks', [])
        )
        print(f"  Total claims extracted: {total_claims}")
        
        # Show sample claims
        if result.get('chunks') and result['chunks'][0].get('claims'):
            claim = result['chunks'][0]['claims'][0]
            print(f"\n  Sample claim:")
            print(f"    Type: {claim.get('type')}")
            print(f"    Evidence: {claim.get('span', {}).get('text', '')[:100]}...")
            if claim.get('mappings'):
                print(f"    Mapped to: {claim['mappings'][0].get('stix_id')}")
                print(f"    Confidence: {claim['mappings'][0].get('confidence')}%")
        
        # Convert to STIX
        print("\n2. Converting to STIX Bundle...")
        print("-" * 40)
        
        # Mock KB validator for demo
        def mock_kb_validator(stix_id):
            # Accept common technique patterns
            return any(x in stix_id for x in ['attack-pattern', 'intrusion-set', 'malware', 'tool'])
        
        stix_bundle = llm_to_stix_bundle(result, kb_validator=mock_kb_validator)
        
        print(f"✓ STIX bundle created")
        print(f"  Objects: {len(stix_bundle.get('objects', []))}")
        
        # Count by type
        type_counts = {}
        for obj in stix_bundle.get('objects', []):
            obj_type = obj.get('type')
            type_counts[obj_type] = type_counts.get(obj_type, 0) + 1
        
        for obj_type, count in type_counts.items():
            print(f"    - {obj_type}: {count}")
        
        # Apply safeguards
        print("\n3. Applying Safeguards...")
        print("-" * 40)
        
        safeguarded = apply_safeguards(stix_bundle, max_confidence=85)
        
        # Check for capped confidence
        capped = sum(1 for obj in safeguarded['objects'] 
                    if obj.get('x_bj_confidence_capped'))
        print(f"✓ Safeguards applied")
        print(f"  Confidence capped: {capped} objects")
        
        # Show final bundle summary
        print("\n4. Final STIX Bundle Summary")
        print("-" * 40)
        print(f"Bundle ID: {safeguarded.get('id')}")
        print(f"Created: {safeguarded.get('created')}")
        print(f"Total objects: {len(safeguarded.get('objects', []))}")
        
        # Show sample technique
        techniques = [o for o in safeguarded['objects'] 
                     if o.get('type') == 'attack-pattern']
        if techniques:
            tech = techniques[0]
            print(f"\nSample technique:")
            print(f"  ID: {tech.get('id')}")
            print(f"  Confidence: {tech.get('confidence')}%")
            print(f"  Evidence: {tech.get('x_bj_evidence', '')[:100]}...")
        
        # Save to file
        output_file = "test_extraction_output.json"
        with open(output_file, 'w') as f:
            json.dump(safeguarded, f, indent=2)
        print(f"\n✓ Results saved to {output_file}")
        
        return True
        
    except Exception as e:
        print(f"\n✗ Extraction failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    # Check for API key
    if not os.getenv("OPENAI_API_KEY"):
        print("⚠️  No OPENAI_API_KEY found in environment")
        sys.exit(1)
    
    # Run test
    success = test_full_extraction()
    
    if success:
        print("\n" + "=" * 60)
        print("✅ Full extraction pipeline test completed successfully!")
        print("=" * 60)
    else:
        print("\n⚠️  Test failed. Check the errors above.")
        sys.exit(1)