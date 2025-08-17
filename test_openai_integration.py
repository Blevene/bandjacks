#!/usr/bin/env python3
"""Test OpenAI integration for TTP extraction."""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add project to path
sys.path.insert(0, '/Volumes/tank/bandjacks')

from bandjacks.llm.client import LLMClient
from bandjacks.llm.tools import get_tool_definitions, get_tool_functions
from bandjacks.llm.prompts import get_messages_for_chunk


def test_openai_connection():
    """Test basic OpenAI connection."""
    print("Testing OpenAI Connection...")
    print("-" * 40)
    
    client = LLMClient()
    
    # Check configuration
    if client.openai_api_key:
        print(f"✓ OpenAI API Key configured")
        print(f"  Model: {client.model}")
    else:
        print("✗ No OpenAI API Key found")
        return False
    
    # Test simple completion
    try:
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Say 'Connection successful' if you can read this."}
        ]
        
        response = client.call(messages)
        print(f"✓ API call successful")
        print(f"  Response: {response.get('content', '')[:100]}")
        return True
        
    except Exception as e:
        print(f"✗ API call failed: {e}")
        return False


def test_ttp_extraction():
    """Test TTP extraction with OpenAI."""
    print("\nTesting TTP Extraction...")
    print("-" * 40)
    
    # Sample threat intelligence text
    sample_text = """
    APT29, also known as Cozy Bear, has been observed using spearphishing 
    emails with malicious attachments to gain initial access. Once inside 
    the network, they deploy PowerShell scripts for execution and establish 
    persistence through registry run keys. The group uses Mimikatz for 
    credential dumping and moves laterally using RDP.
    """
    
    client = LLMClient()
    tools = get_tool_definitions()
    
    # Create messages for extraction
    messages = get_messages_for_chunk("test-chunk-001", sample_text)
    
    print("Sending text for analysis:")
    print(f"  {sample_text[:100]}...")
    
    try:
        # Note: This would normally use the tool-calling loop
        # For testing, we'll just do a direct call
        response = client.call(messages, tools=tools)
        
        if response.get("tool_calls"):
            print(f"✓ Model requested {len(response['tool_calls'])} tool calls")
            for tool_call in response["tool_calls"]:
                print(f"  - {tool_call['function']['name']}")
        elif response.get("content"):
            print(f"✓ Model provided response")
            print(f"  Response preview: {response['content'][:200]}...")
        
        return True
        
    except Exception as e:
        print(f"✗ Extraction failed: {e}")
        return False


def test_tool_simulation():
    """Test with simulated tool responses."""
    print("\nTesting with Simulated Tools...")
    print("-" * 40)
    
    from bandjacks.llm.client import execute_tool_loop
    
    # Mock tool functions that return sample data
    def mock_vector_search(**kwargs):
        return [
            {"stix_id": "attack-pattern--1566", "kb_type": "AttackPattern", 
             "score": 0.92, "name_or_snippet": "Spearphishing Attachment"},
            {"stix_id": "attack-pattern--1059-001", "kb_type": "AttackPattern",
             "score": 0.88, "name_or_snippet": "PowerShell"}
        ]
    
    def mock_graph_lookup(stix_id):
        return {
            "stix_id": stix_id,
            "name": "Test Technique",
            "description": "Test description",
            "tactics": ["initial-access"]
        }
    
    def mock_list_tactics():
        return [
            {"shortname": "initial-access", "name": "Initial Access"},
            {"shortname": "execution", "name": "Execution"},
            {"shortname": "persistence", "name": "Persistence"}
        ]
    
    mock_functions = {
        "vector_search_ttx": mock_vector_search,
        "graph_lookup": mock_graph_lookup,
        "list_tactics": mock_list_tactics
    }
    
    sample_text = "APT29 uses spearphishing for initial access."
    messages = get_messages_for_chunk("test-002", sample_text)
    tools = get_tool_definitions()
    
    try:
        # This will make actual API calls but use mock tool responses
        result = execute_tool_loop(
            messages=messages,
            tools=tools,
            tool_functions=mock_functions,
            max_iterations=5
        )
        
        print("✓ Tool loop completed")
        print(f"  Result preview: {result[:200]}...")
        
        # Try to parse as JSON
        import json
        try:
            parsed = json.loads(result)
            print(f"✓ Valid JSON response")
            if "claims" in parsed:
                print(f"  Found {len(parsed['claims'])} claims")
        except:
            print("  Note: Response is not JSON (might be explanation)")
        
        return True
        
    except Exception as e:
        print(f"✗ Tool simulation failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("=" * 50)
    print("OpenAI Integration Test for Bandjacks")
    print("=" * 50)
    
    # Check for API key
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("\n⚠️  No OPENAI_API_KEY found in environment")
        print("   Please add it to your .env file")
        sys.exit(1)
    
    print(f"\n✓ OPENAI_API_KEY found (length: {len(api_key)})")
    
    # Run tests
    results = []
    
    results.append(("Connection", test_openai_connection()))
    
    if results[0][1]:  # Only continue if connection works
        results.append(("TTP Extraction", test_ttp_extraction()))
        results.append(("Tool Simulation", test_tool_simulation()))
    
    # Summary
    print("\n" + "=" * 50)
    print("Test Summary:")
    for name, passed in results:
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"  {name}: {status}")
    
    if all(r[1] for r in results):
        print("\n🎉 All tests passed! OpenAI integration is working.")
    else:
        print("\n⚠️  Some tests failed. Check the output above.")