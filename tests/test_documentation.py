#!/usr/bin/env python3
"""Test that documentation is complete and accurate."""

import os
import json
from pathlib import Path


def test_cli_documentation():
    """Verify CLI documentation exists and is comprehensive."""
    print("\n" + "="*60)
    print("Testing CLI Documentation")
    print("="*60)
    
    cli_doc = Path("docs/CLI_USAGE.md")
    assert cli_doc.exists(), "CLI documentation missing"
    
    content = cli_doc.read_text()
    
    # Check for essential sections
    required_sections = [
        "Installation",
        "Configuration", 
        "Command Reference",
        "Query Commands",
        "Review Queue Commands",
        "Administrative Commands",
        "Examples",
        "Environment Variables"
    ]
    
    for section in required_sections:
        assert section in content, f"Missing section: {section}"
        print(f"✓ Section found: {section}")
    
    # Check for command examples
    commands = [
        "query search",
        "query graph",
        "review queue",
        "review approve",
        "review reject",
        "admin health",
        "admin optimize",
        "extract document"
    ]
    
    for cmd in commands:
        assert cmd in content, f"Missing command: {cmd}"
        print(f"✓ Command documented: {cmd}")
    
    print("✅ CLI documentation is comprehensive")
    return True


def test_api_documentation():
    """Verify API documentation exists and covers all endpoints."""
    print("\n" + "="*60)
    print("Testing API Documentation")
    print("="*60)
    
    api_doc = Path("docs/API_DOCUMENTATION.md")
    assert api_doc.exists(), "API documentation missing"
    
    content = api_doc.read_text()
    
    # Check for essential sections
    required_sections = [
        "Overview",
        "Authentication",
        "Common Response Formats",
        "Endpoints",
        "Error Codes",
        "Examples"
    ]
    
    for section in required_sections:
        assert section in content, f"Missing section: {section}"
        print(f"✓ Section found: {section}")
    
    # Check for endpoint documentation
    endpoints = [
        "/v1/catalog/attack/releases",
        "/v1/stix/load/attack",
        "/v1/query/search",
        "/v1/graph/attack_flow",
        "/v1/feedback/relevance",
        "/v1/review_queue/queue",
        "/v1/extract/document"
    ]
    
    for endpoint in endpoints:
        assert endpoint in content, f"Missing endpoint: {endpoint}"
        print(f"✓ Endpoint documented: {endpoint}")
    
    # Check for example code
    assert "```python" in content, "Missing Python examples"
    assert "```bash" in content or "```sh" in content, "Missing bash/curl examples"
    print("✓ Code examples present")
    
    print("✅ API documentation is comprehensive")
    return True


def test_openapi_spec():
    """Verify OpenAPI specification exists and is valid."""
    print("\n" + "="*60)
    print("Testing OpenAPI Specification")
    print("="*60)
    
    openapi_path = Path("docs/openapi.json")
    assert openapi_path.exists(), "OpenAPI spec missing"
    
    with open(openapi_path) as f:
        spec = json.load(f)
    
    # Check required OpenAPI fields
    assert "openapi" in spec, "Missing OpenAPI version"
    assert "info" in spec, "Missing info section"
    assert "paths" in spec, "Missing paths section"
    
    print(f"✓ OpenAPI version: {spec.get('openapi')}")
    print(f"✓ API title: {spec['info'].get('title')}")
    print(f"✓ API version: {spec['info'].get('version')}")
    print(f"✓ Endpoints defined: {len(spec['paths'])}")
    
    # Check for comprehensive endpoint coverage
    required_paths = [
        "/v1/catalog/attack/releases",
        "/v1/query/search",
        "/v1/graph/attack_flow",
        "/v1/review_queue/queue"
    ]
    
    for path in required_paths:
        assert path in spec["paths"], f"Missing path: {path}"
        print(f"✓ Path defined: {path}")
    
    # Check for components
    if "components" in spec:
        if "schemas" in spec["components"]:
            print(f"✓ Schemas defined: {len(spec['components']['schemas'])}")
        if "responses" in spec["components"]:
            print(f"✓ Response templates: {len(spec['components']['responses'])}")
    
    print("✅ OpenAPI specification is valid")
    return True


def test_readme_links():
    """Verify README has correct links to documentation."""
    print("\n" + "="*60)
    print("Testing README Links")
    print("="*60)
    
    readme = Path("docs/README.md")
    assert readme.exists(), "README missing"
    
    content = readme.read_text()
    
    # Check for documentation links
    links = [
        "API_DOCUMENTATION.md",
        "CLI_USAGE.md",
        "openapi.json"
    ]
    
    for link in links:
        assert link in content, f"Missing link to: {link}"
        print(f"✓ Link found: {link}")
    
    # Verify linked files exist
    for link in links:
        link_path = Path(f"docs/{link}")
        assert link_path.exists(), f"Linked file missing: {link}"
        print(f"✓ File exists: {link}")
    
    print("✅ README links are valid")
    return True


def main():
    """Run all documentation tests."""
    print("\n" + "="*60)
    print("DOCUMENTATION VALIDATION SUITE")
    print("="*60)
    
    results = {
        "CLI Documentation": test_cli_documentation(),
        "API Documentation": test_api_documentation(),
        "OpenAPI Spec": test_openapi_spec(),
        "README Links": test_readme_links()
    }
    
    # Summary
    print("\n" + "="*60)
    print("VALIDATION SUMMARY")
    print("="*60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All documentation tests passed!")
        print("\nDocumentation is complete and properly structured:")
        print("• CLI documentation with all commands")
        print("• API documentation with all endpoints")
        print("• Valid OpenAPI specification")
        print("• Proper cross-references in README")
    else:
        print(f"\n❌ {total - passed} tests failed")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())