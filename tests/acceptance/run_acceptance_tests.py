#!/usr/bin/env python3
"""Run acceptance tests with proper setup and reporting."""

import sys
import os
import time
import subprocess
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))


def check_services():
    """Check if required services are running."""
    import httpx
    from neo4j import GraphDatabase
    from opensearchpy import OpenSearch
    
    print("Checking services...")
    
    # Check API
    try:
        response = httpx.get("http://localhost:8000/docs", timeout=5)
        print("✅ API is running")
    except:
        print("❌ API is not running. Start with: uvicorn bandjacks.services.api.main:app")
        return False
    
    # Check Neo4j
    try:
        driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "password"))
        driver.verify_connectivity()
        driver.close()
        print("✅ Neo4j is running")
    except:
        print("❌ Neo4j is not running")
        return False
    
    # Check OpenSearch
    try:
        client = OpenSearch(
            hosts=[{"host": "localhost", "port": 9200}],
            http_compress=True,
            use_ssl=False,
            verify_certs=False,
            ssl_show_warn=False
        )
        info = client.info()
        print("✅ OpenSearch is running")
    except:
        print("❌ OpenSearch is not running")
        return False
    
    return True


def run_acceptance_tests():
    """Run the acceptance test suite."""
    print("\n" + "="*80)
    print("BANDJACKS ACCEPTANCE TEST SUITE")
    print("="*80)
    
    # Check services
    if not check_services():
        print("\n⚠️  Please ensure all services are running before running acceptance tests")
        return 1
    
    print("\nRunning acceptance tests...\n")
    
    # Run tests with pytest
    test_dir = Path(__file__).parent
    
    # Test categories
    test_suites = [
        ("Ingestion", "test_e2e_ingestion.py"),
        ("Search", "test_e2e_search.py"),
        ("Extraction", "test_e2e_extraction.py"),
        ("Flows", "test_e2e_flows.py"),
        ("Defense", "test_e2e_defense.py"),
        ("Feedback", "test_e2e_feedback.py"),
    ]
    
    results = {}
    
    for suite_name, test_file in test_suites:
        test_path = test_dir / test_file
        if not test_path.exists():
            print(f"⏭️  Skipping {suite_name} (not implemented)")
            results[suite_name] = "skipped"
            continue
        
        print(f"\n{'='*60}")
        print(f"Running {suite_name} Tests")
        print('='*60)
        
        start_time = time.time()
        
        # Run pytest for this suite
        result = subprocess.run(
            [sys.executable, "-m", "pytest", str(test_path), "-v", "--tb=short"],
            capture_output=False,
            text=True
        )
        
        elapsed = time.time() - start_time
        
        if result.returncode == 0:
            print(f"✅ {suite_name} tests passed ({elapsed:.2f}s)")
            results[suite_name] = "passed"
        else:
            print(f"❌ {suite_name} tests failed ({elapsed:.2f}s)")
            results[suite_name] = "failed"
    
    # Summary
    print("\n" + "="*80)
    print("ACCEPTANCE TEST SUMMARY")
    print("="*80)
    
    for suite_name, status in results.items():
        emoji = "✅" if status == "passed" else "❌" if status == "failed" else "⏭️"
        print(f"{emoji} {suite_name}: {status}")
    
    passed = sum(1 for s in results.values() if s == "passed")
    failed = sum(1 for s in results.values() if s == "failed")
    skipped = sum(1 for s in results.values() if s == "skipped")
    
    print(f"\nTotal: {passed} passed, {failed} failed, {skipped} skipped")
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run_acceptance_tests())