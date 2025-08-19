#!/usr/bin/env python3
"""Quick test of improved extractor on single document."""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from bandjacks.llm.improved_extractor import ImprovedExtractor

def main():
    print("Testing improved extractor on DarkCloud PDF...")
    
    # Initialize extractor
    extractor = ImprovedExtractor(
        model="gpt-4o-mini",
        os_url="http://localhost:9200",
        os_index="bandjacks_attack_nodes-v1"
    )
    
    # Test on DarkCloud PDF
    pdf_path = Path("samples/reports/new-darkcloud-stealer-infection-chain.pdf")
    
    if not pdf_path.exists():
        print(f"Error: PDF not found at {pdf_path}")
        return False
    
    try:
        # Run extraction
        results = extractor.extract_from_report(
            source_id="darkcloud_test",
            source_type="pdf",
            content_url=str(pdf_path)
        )
        
        # Show results
        print(f"\nResults:")
        print(f"- Total techniques: {results.get('total_techniques', 0)}")
        print(f"- Entities found: {results.get('entities', {})}")
        print(f"- Kill chain coverage: {list(results.get('kill_chain_coverage', {}).keys())}")
        
        # Extract technique IDs
        found_ids = set()
        for claim in results.get("claims", []):
            for mapping in claim.get("mappings", []):
                tech_id = mapping.get("external_id")
                if tech_id:
                    found_ids.add(tech_id)
        
        print(f"\nTechniques found ({len(found_ids)}):")
        for tech_id in sorted(found_ids)[:10]:
            print(f"  - {tech_id}")
        
        # Check for critical techniques
        critical = ["T1566", "T1059", "T1055", "T1071", "T1547"]
        print(f"\nCritical techniques:")
        for tech_id in critical:
            status = "✓" if tech_id in found_ids else "✗"
            print(f"  {status} {tech_id}")
        
        # Save results
        with open("/tmp/single_improved_test.json", "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to /tmp/single_improved_test.json")
        
        return len(found_ids) > 10
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)