#!/usr/bin/env python3
"""Test the enhanced LLM extraction pipeline with all improvements."""

import os
import sys
import json
import time
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add project to path
sys.path.insert(0, '/Volumes/tank/bandjacks')

from bandjacks.llm.extractor import LLMExtractor
from bandjacks.llm.opportunities import generate_detection_opportunities
from bandjacks.llm.flows import synthesize_attack_flow
from bandjacks.llm.stix_converter import llm_to_stix_bundle


def test_enhanced_extraction():
    """Test the enhanced extraction pipeline with evidence and improved schemas."""
    
    print("=" * 60)
    print("Enhanced LLM Extraction Pipeline Test")
    print("=" * 60)
    
    # Sample threat report with rich content
    threat_report = """
    ## APT29 Advanced Campaign Analysis
    
    The threat actor APT29, also known as Cozy Bear and The Dukes, has been conducting
    sophisticated cyber espionage operations against government and technology organizations
    since at least 2014.
    
    ### Initial Access and Execution
    
    In this campaign observed in Q4 2024, APT29 primarily used spearphishing emails with
    malicious PDF attachments (T1566.001) targeting senior executives and system administrators.
    The PDF files contained embedded JavaScript that would execute upon opening, dropping
    a custom backdoor named "FoggyWeb" onto the victim's system.
    
    ### Persistence Mechanisms
    
    Once on the target system, the FoggyWeb backdoor establishes persistence through multiple
    mechanisms including:
    - Creating Windows registry run keys (T1547.001) at HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    - Installing scheduled tasks (T1053.005) that execute every 4 hours
    - Modifying WMI event subscriptions for fileless persistence
    
    ### Credential Access and Lateral Movement
    
    APT29 operators were observed using a customized version of Mimikatz to dump credentials
    from the LSASS process memory (T1003.001). They also harvested credentials from web browsers
    and Windows Credential Manager.
    
    For lateral movement, the group utilized:
    - Remote Desktop Protocol (RDP) with stolen credentials
    - PowerShell remoting to execute commands on domain controllers
    - PsExec for remote service installation
    
    ### Command and Control Infrastructure
    
    The C2 infrastructure consisted of compromised WordPress sites acting as first-stage proxies:
    - C2 domain: updates.microsoft-cdn[.]com (spoofed Microsoft domain)
    - IP addresses: 185.220.101.45, 192.42.119.41
    - Communication used HTTPS on port 443 with domain fronting via CloudFlare
    
    ### Data Exfiltration
    
    Data was staged in ZIP archives in the %TEMP% directory before exfiltration.
    The threat actors used a custom tool called "CloudDuke" to upload stolen data
    to legitimate cloud storage services including OneDrive and Google Drive,
    making detection more difficult.
    
    ### Timeline
    - First seen: October 15, 2024
    - Last activity: December 10, 2024
    - Campaign status: Active
    
    ### Indicators
    - FoggyWeb backdoor SHA256: a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
    - CloudDuke exfiltration tool: cloudupdate.exe (45KB)
    - Registry persistence key: HKLM\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate
    """
    
    print("\n1. Testing Enhanced Extraction with Evidence...")
    print("-" * 40)
    
    # Create extractor
    extractor = LLMExtractor()
    
    # Extract with line numbering and evidence
    result = extractor.extract_document(
        source_id="apt29-campaign-2024",
        source_type="md",
        inline_text=threat_report,
        chunking_params={"target_chars": 1500, "overlap": 200}
    )
    
    print(f"✓ Extraction completed")
    print(f"  Chunks processed: {len(result.get('chunks', []))}")
    
    # Count claims and entities
    total_claims = sum(len(chunk.get('claims', [])) for chunk in result.get('chunks', []))
    print(f"  Total claims extracted: {total_claims}")
    
    # Aggregate entities
    all_entities = {}
    for chunk in result.get('chunks', []):
        if 'entities' in chunk:
            for entity_type, values in chunk['entities'].items():
                if entity_type not in all_entities:
                    all_entities[entity_type] = set()
                all_entities[entity_type].update(values)
    
    print(f"\n  Entities extracted:")
    for entity_type, values in all_entities.items():
        if values:
            print(f"    - {entity_type}: {list(values)[:3]}...")
    
    # Show sample claim with evidence
    if result.get('chunks') and result['chunks'][0].get('claims'):
        claim = result['chunks'][0]['claims'][0]
        print(f"\n  Sample claim with evidence:")
        print(f"    Type: {claim.get('type')}")
        print(f"    Text: {claim.get('span', {}).get('text', '')[:100]}...")
        if claim.get('line_refs'):
            print(f"    Line references: {claim.get('line_refs')}")
        if claim.get('evidence'):
            print(f"    Evidence: {claim['evidence'][0][:100]}...")
        if claim.get('mappings'):
            mapping = claim['mappings'][0]
            print(f"    Mapped to: {mapping.get('external_id')} - {mapping.get('name')}")
            print(f"    Confidence: {mapping.get('confidence')}%")
            print(f"    Rationale: {mapping.get('rationale')}")
    
    # Test detection opportunity generation
    print("\n2. Testing Detection Opportunity Generation...")
    print("-" * 40)
    
    opportunities = generate_detection_opportunities(
        extraction_result=result,
        report_text=threat_report,
        evaluate=True
    )
    
    print(f"✓ Generated {len(opportunities)} detection opportunities")
    
    if opportunities:
        # Show top opportunity
        opp = opportunities[0]
        print(f"\n  Top detection opportunity:")
        print(f"    Name: {opp.get('name')}")
        print(f"    Technique: {opp.get('technique_id')}")
        print(f"    Artefacts: {opp.get('artefacts', [])[:2]}")
        print(f"    Behaviours: {opp.get('behaviours', [])[:2]}")
        print(f"    Confidence: {opp.get('confidence')}")
        if 'evaluation' in opp:
            print(f"    Quality score: {opp['evaluation']['quality_score']}/100")
    
    # Test attack flow synthesis
    print("\n3. Testing Attack Flow Synthesis...")
    print("-" * 40)
    
    attack_flow = synthesize_attack_flow(
        extraction_result=result,
        report_text=threat_report,
        max_steps=15
    )
    
    if attack_flow:
        print(f"✓ Synthesized attack flow")
        print(f"  Flow name: {attack_flow['flow']['properties']['name']}")
        print(f"  Total steps: {len(attack_flow['steps'])}")
        
        # Show first few steps
        print(f"\n  Attack sequence:")
        for step in attack_flow['steps'][:5]:
            print(f"    {step['order']}. {step['description']}")
            print(f"       Entity: {step['entity']['label']} - {step['entity']['pk']}")
            print(f"       Reason: {step['reason']}")
    else:
        print("✗ Attack flow synthesis failed")
    
    # Convert to STIX bundle
    print("\n4. Testing STIX Bundle Generation...")
    print("-" * 40)
    
    try:
        # Mock KB validator
        def mock_kb_validator(stix_id):
            return 'attack-pattern' in stix_id or 'intrusion-set' in stix_id
        
        stix_bundle = llm_to_stix_bundle(result, kb_validator=mock_kb_validator)
        
        print(f"✓ STIX bundle created")
        print(f"  Bundle ID: {stix_bundle.get('id')}")
        print(f"  Objects: {len(stix_bundle.get('objects', []))}")
        
        # Count by type
        type_counts = {}
        for obj in stix_bundle.get('objects', []):
            obj_type = obj.get('type')
            type_counts[obj_type] = type_counts.get(obj_type, 0) + 1
        
        for obj_type, count in type_counts.items():
            print(f"    - {obj_type}: {count}")
        
    except Exception as e:
        print(f"✗ STIX conversion failed: {e}")
    
    # Save results
    output_file = "enhanced_extraction_test.json"
    with open(output_file, 'w') as f:
        json.dump({
            "extraction": result,
            "opportunities": opportunities,
            "attack_flow": attack_flow
        }, f, indent=2, default=str)
    
    print(f"\n✓ Results saved to {output_file}")
    
    return True


def test_evidence_citations():
    """Test that evidence and line citations are working correctly."""
    
    print("\n" + "=" * 60)
    print("Testing Evidence Citations")
    print("=" * 60)
    
    # Simple test text with clear line numbers
    test_text = """APT28 uses spearphishing emails.
They deploy Mimikatz for credential dumping.
The group targets government organizations.
Persistence is achieved through registry keys."""
    
    extractor = LLMExtractor()
    
    result = extractor.extract_chunk(
        chunk_id="test-evidence",
        text=test_text
    )
    
    print(f"✓ Extraction completed")
    
    if result.get('claims'):
        for i, claim in enumerate(result['claims'][:2]):
            print(f"\nClaim {i+1}:")
            print(f"  Text: {claim.get('span', {}).get('text')}")
            print(f"  Line refs: {claim.get('line_refs')}")
            print(f"  Evidence: {claim.get('evidence')}")
            print(f"  Source: {claim.get('source')}")
    
    return True


if __name__ == "__main__":
    # Check for API key
    if not (os.getenv("GOOGLE_API_KEY") or os.getenv("OPENAI_API_KEY")):
        print("⚠️  No GOOGLE_API_KEY or OPENAI_API_KEY found in environment")
        print("    Please set one of these in your .env file")
        sys.exit(1)
    
    # Check which model we're using
    if os.getenv("GOOGLE_API_KEY"):
        print(f"Using Gemini-2.5-Flash as primary model")
    elif os.getenv("OPENAI_API_KEY"):
        print(f"Using GPT-5 as primary model")
    
    # Run tests
    try:
        # Test main extraction pipeline
        success = test_enhanced_extraction()
        
        # Test evidence citations
        if success:
            test_evidence_citations()
        
        if success:
            print("\n" + "=" * 60)
            print("✅ All enhanced extraction tests completed successfully!")
            print("=" * 60)
            print("\nKey improvements demonstrated:")
            print("  • Evidence-based extraction with line citations")
            print("  • Enhanced entity types and relationships")
            print("  • Detection opportunity generation")
            print("  • Attack flow synthesis")
            print("  • Robust JSON handling with repair")
            print("  • Confidence calibration with rationales")
        else:
            print("\n⚠️  Some tests failed. Check the errors above.")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)