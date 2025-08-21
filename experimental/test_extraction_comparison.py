#!/usr/bin/env python3
"""Compare different extraction approaches to find the best recall."""

import sys
import json
import time
import asyncio
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).parent))

from bandjacks.llm.improved_extractor import ImprovedExtractor
from bandjacks.llm.direct_extractor import DirectTTPExtractor, extract_pdf_text, extract_json_text
from bandjacks.llm.agentic_extractor import extract_with_agents


@dataclass
class TestCase:
    """Test case for extraction."""
    name: str
    path: Path
    expected_techniques: List[str]


# Key techniques we expect to find
TEST_CASES = [
    TestCase(
        name="DarkCloud Stealer",
        path=Path("samples/reports/new-darkcloud-stealer-infection-chain.pdf"),
        expected_techniques=[
            "T1566", "T1566.001",  # Phishing
            "T1059", "T1059.001", "T1059.007",  # PowerShell, JavaScript
            "T1027", "T1140",  # Obfuscation
            "T1055",  # Process Injection
            "T1071",  # C2
            "T1547",  # Persistence
            "T1555", "T1555.003",  # Credentials
            "T1005", "T1041",  # Collection/Exfiltration
            "T1105", "T1204"  # Tool Transfer, User Execution
        ]
    )
]


def test_improved_extractor(test_case: TestCase) -> Dict:
    """Test the improved behavioral extractor."""
    print("\n=== Testing Improved Extractor (Behavioral + Vector Search) ===")
    
    extractor = ImprovedExtractor(
        model="gpt-4o-mini",
        os_url="http://localhost:9200",
        os_index="bandjacks_attack_nodes-v1"
    )
    
    try:
        start = time.time()
        results = extractor.extract_from_report(
            source_id=test_case.name.lower().replace(" ", "_"),
            source_type="pdf",
            content_url=str(test_case.path)
        )
        elapsed = time.time() - start
        
        # Extract technique IDs
        found_ids = set()
        for claim in results.get("claims", []):
            for mapping in claim.get("mappings", []):
                tech_id = mapping.get("external_id")
                if tech_id:
                    found_ids.add(tech_id)
                    if '.' in tech_id:
                        found_ids.add(tech_id.split('.')[0])
        
        recall = len(found_ids & set(test_case.expected_techniques)) / len(test_case.expected_techniques)
        
        print(f"  Found {len(found_ids)} techniques in {elapsed:.1f}s")
        print(f"  Recall: {recall:.1%}")
        print(f"  Techniques: {sorted(found_ids)[:10]}")
        
        return {
            "method": "improved",
            "found_ids": sorted(found_ids),
            "recall": recall,
            "time": elapsed
        }
        
    except Exception as e:
        print(f"  Error: {e}")
        return {"method": "improved", "error": str(e)}


def test_direct_extractor(test_case: TestCase) -> Dict:
    """Test the direct LLM extractor."""
    print("\n=== Testing Direct Extractor (LLM ATT&CK Knowledge) ===")
    
    extractor = DirectTTPExtractor(model="gpt-4o-mini")
    
    try:
        # Extract text
        if test_case.path.suffix == ".pdf":
            text = extract_pdf_text(test_case.path)
        else:
            text = extract_json_text(test_case.path)
        
        if not text:
            return {"method": "direct", "error": "No text extracted"}
        
        start = time.time()
        results = extractor.extract_ttps(
            text=text,
            source_id=test_case.name.lower().replace(" ", "_")
        )
        elapsed = time.time() - start
        
        print(f"  DEBUG: Results keys: {results.keys()}")
        print(f"  DEBUG: Total techniques in results: {results.get('total_techniques', 0)}")
        print(f"  DEBUG: Techniques dict: {list(results.get('techniques', {}).keys())[:5]}")
        
        # Extract technique IDs
        found_ids = set(results.get("techniques", {}).keys())
        
        # Add parent techniques
        for tech_id in list(found_ids):
            if '.' in tech_id:
                found_ids.add(tech_id.split('.')[0])
        
        recall = len(found_ids & set(test_case.expected_techniques)) / len(test_case.expected_techniques)
        
        print(f"  Found {len(found_ids)} techniques in {elapsed:.1f}s")
        print(f"  Recall: {recall:.1%}")
        print(f"  Techniques: {sorted(found_ids)[:10]}")
        
        # Show confidence distribution
        if results.get("techniques"):
            confidences = [info['confidence'] for info in results["techniques"].values()]
            avg_conf = sum(confidences) / len(confidences)
            print(f"  Avg confidence: {avg_conf:.1f}")
        
        return {
            "method": "direct",
            "found_ids": sorted(found_ids),
            "recall": recall,
            "time": elapsed,
            "techniques": results.get("techniques", {})
        }
        
    except Exception as e:
        print(f"  Error: {e}")
        import traceback
        traceback.print_exc()
        return {"method": "direct", "error": str(e)}


async def test_agentic_extractor(test_case: TestCase) -> Dict:
    """Test the multi-agent extractor."""
    print("\n=== Testing Agentic Extractor (Multi-Agent Parallel) ===")
    
    try:
        # Extract text
        if test_case.path.suffix == ".pdf":
            text = extract_pdf_text(test_case.path)
        else:
            text = extract_json_text(test_case.path)
        
        if not text:
            return {"method": "agentic", "error": "No text extracted"}
        
        start = time.time()
        results = await extract_with_agents(
            text=text,
            source_id=test_case.name.lower().replace(" ", "_"),
            model="gpt-4o-mini"
        )
        elapsed = time.time() - start
        
        print(f"  DEBUG: Results keys: {results.keys()}")
        print(f"  DEBUG: Total techniques in results: {results.get('total_techniques', 0)}")
        print(f"  DEBUG: Techniques dict: {list(results.get('techniques', {}).keys())[:5]}")
        
        # Extract technique IDs
        found_ids = set(results.get("techniques", {}).keys())
        
        # Add parent techniques
        for tech_id in list(found_ids):
            if '.' in tech_id:
                found_ids.add(tech_id.split('.')[0])
        
        recall = len(found_ids & set(test_case.expected_techniques)) / len(test_case.expected_techniques)
        
        print(f"  Found {len(found_ids)} techniques in {elapsed:.1f}s")
        print(f"  Recall: {recall:.1%}")
        print(f"  Techniques: {sorted(found_ids)[:10]}")
        
        # Show agent contributions
        print(f"  Entities: {len(results.get('entities', {}).get('threat_actors', []))} actors, "
              f"{len(results.get('entities', {}).get('malware', []))} malware")
        
        return {
            "method": "agentic",
            "found_ids": sorted(found_ids),
            "recall": recall,
            "time": elapsed,
            "entities": results.get("entities", {})
        }
        
    except Exception as e:
        print(f"  Error: {e}")
        import traceback
        traceback.print_exc()
        return {"method": "agentic", "error": str(e)}


async def main():
    """Run comparison tests."""
    print("="*80)
    print("EXTRACTION METHOD COMPARISON TEST")
    print("="*80)
    print("Testing three extraction approaches:")
    print("1. Improved (Behavioral + Vector Search)")
    print("2. Direct (LLM ATT&CK Knowledge)")
    print("3. Agentic (Multi-Agent Parallel)")
    
    for test_case in TEST_CASES:
        print(f"\n{'='*80}")
        print(f"Test Case: {test_case.name}")
        print(f"Expected techniques: {len(test_case.expected_techniques)}")
        print(f"{'='*80}")
        
        if not test_case.path.exists():
            print(f"✗ File not found: {test_case.path}")
            continue
        
        results = []
        
        # Test improved extractor
        results.append(test_improved_extractor(test_case))
        
        # Test direct extractor
        results.append(test_direct_extractor(test_case))
        
        # Test agentic extractor
        results.append(await test_agentic_extractor(test_case))
        
        # Compare results
        print(f"\n{'='*60}")
        print("COMPARISON SUMMARY")
        print(f"{'='*60}")
        
        for result in results:
            if "error" in result:
                print(f"{result['method']:12} - ERROR: {result['error'][:50]}")
            else:
                print(f"{result['method']:12} - Recall: {result['recall']:.1%}, "
                      f"Techniques: {len(result.get('found_ids', []))}, "
                      f"Time: {result['time']:.1f}s")
        
        # Find best approach
        valid_results = [r for r in results if "recall" in r]
        if valid_results:
            best = max(valid_results, key=lambda x: x['recall'])
            print(f"\n🏆 Best recall: {best['method']} with {best['recall']:.1%}")
            
            # Show techniques found by best method
            print(f"\nTechniques found by {best['method']}:")
            expected_set = set(test_case.expected_techniques)
            found_set = set(best.get('found_ids', []))
            
            found_expected = found_set & expected_set
            missed_expected = expected_set - found_set
            extra_found = found_set - expected_set
            
            print(f"  ✓ Found expected: {sorted(found_expected)}")
            print(f"  ✗ Missed expected: {sorted(missed_expected)}")
            print(f"  + Extra found: {sorted(extra_found)[:5]}")
        
        # Save results
        with open("/tmp/extraction_comparison_results.json", "w") as f:
            json.dump({
                "test_case": test_case.name,
                "expected_count": len(test_case.expected_techniques),
                "results": results
            }, f, indent=2)
        
        print(f"\n💾 Results saved to /tmp/extraction_comparison_results.json")


if __name__ == "__main__":
    # Run async main
    asyncio.run(main())