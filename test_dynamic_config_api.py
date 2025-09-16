#!/usr/bin/env python3
"""Test dynamic configuration and batch Neo4j through API."""

import requests
import json
import time

# Sample threat report text
SAMPLE_REPORT = """
APT29, also known as Cozy Bear, conducted a sophisticated spear phishing campaign 
targeting government organizations. The initial attack vector involved spear phishing 
emails with malicious attachments (T1566.001). 

Once the victim opened the attachment, PowerShell scripts were executed (T1059.001) 
to establish persistence through registry run keys (T1547.001). The malware then 
performed process injection (T1055) to hide in legitimate processes.

The attackers used credential dumping techniques (T1003) to extract passwords from 
LSASS memory. They moved laterally using Windows Remote Management (T1021.006) and 
established command and control channels over HTTPS (T1071.001).

Data was staged in a temporary directory before being compressed (T1560) and 
exfiltrated over the C2 channel (T1041). The group also deployed ransomware 
(T1486) as a final impact technique.
"""

def test_extraction():
    """Test extraction with dynamic configuration."""
    print("Testing extraction with dynamic configuration...")
    
    # Prepare request
    url = "http://localhost:8000/v1/reports/ingest"
    payload = {
        "text": SAMPLE_REPORT,
        "source": "test_dynamic_config",
        "config": {
            "skip_verification": False
        }
    }
    
    # Send request
    response = requests.post(url, json=payload)
    
    if response.status_code == 200:
        result = response.json()
        print(f"✅ Extraction successful!")
        print(f"   Techniques found: {result.get('techniques_count', 0)}")
        
        # Check if our configurations were used
        if 'extraction' in result:
            extraction = result['extraction']
            print(f"   Entities: {len(extraction.get('entities', []))}")
            print(f"   Claims: {len(extraction.get('claims', []))}")
            
            # Check for batch processing evidence
            if 'flow' in extraction:
                flow = extraction['flow']
                print(f"   Flow steps: {len(flow.get('steps', []))}")
                print(f"   Flow type: {flow.get('flow_type', 'unknown')}")
        
        return result
    else:
        print(f"❌ Extraction failed: {response.status_code}")
        print(f"   Error: {response.text}")
        return None

def check_logs_for_config():
    """Check logs for evidence of dynamic configuration."""
    print("\nChecking logs for dynamic configuration usage...")
    
    # Read recent logs
    import subprocess
    result = subprocess.run(
        ["tail", "-100", "/Volumes/tank/bandjacks/extraction_pipeline.log"],
        capture_output=True,
        text=True
    )
    
    log_lines = result.stdout.split('\n')
    
    # Look for evidence of our configurations
    config_evidence = {
        "optimized_extractor": False,
        "chunk_size": False,
        "mapper_batch": False,
        "batch_neo4j": False
    }
    
    for line in log_lines:
        if "OptimizedChunkedExtractor" in line:
            config_evidence["optimized_extractor"] = True
        if "chunk_size" in line or "4000" in line:
            config_evidence["chunk_size"] = True
        if "mapper_batch_size" in line or "batch_size=20" in line:
            config_evidence["mapper_batch"] = True
        if "BatchNeo4j" in line or "batch_helper" in line:
            config_evidence["batch_neo4j"] = True
    
    print("Configuration evidence found:")
    for key, found in config_evidence.items():
        status = "✅" if found else "❌"
        print(f"   {status} {key}: {found}")
    
    return config_evidence

def main():
    print("=" * 60)
    print("Dynamic Configuration & Batch Neo4j Test")
    print("=" * 60)
    
    # Test extraction
    result = test_extraction()
    
    if result:
        # Check logs
        time.sleep(2)  # Give logs time to flush
        config_evidence = check_logs_for_config()
        
        print("\n" + "=" * 60)
        print("Summary:")
        print(f"- Extraction: ✅ Successful")
        print(f"- Techniques extracted: {result.get('techniques_count', 0)}")
        print(f"- Dynamic config active: {'✅' if config_evidence['optimized_extractor'] else '⚠️ Check logs'}")
        print(f"- Batch Neo4j: {'✅' if config_evidence['batch_neo4j'] else '⚠️ Not detected in logs'}")
    else:
        print("\n❌ Test failed - check backend is running")
    
    print("=" * 60)

if __name__ == "__main__":
    main()