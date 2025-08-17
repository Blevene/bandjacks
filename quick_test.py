#!/usr/bin/env python3
"""Quick test of Gemini extraction."""

from litellm import completion
import os
import json
import re
from dotenv import load_dotenv

load_dotenv()

# Test extraction
report = """
LockBit 3.0 ransomware targeted healthcare using RDP brute force (T1110).
They deployed Cobalt Strike and used Mimikatz for credential dumping (T1003.001).
Persistence via scheduled tasks (T1053.005) and registry keys (T1547.001).
"""

prompt = """Extract threat activities as JSON array. For each activity include: actor, technique (T-code), and activity description.

Format:
{"claims": [{"actor": "...", "technique": "T####", "activity": "..."}]}

Text to analyze:
""" + report

print("Testing Gemini extraction...")
print("-" * 40)

try:
    response = completion(
        model="gemini/gemini-2.5-flash",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=1000
    )
    
    content = response.choices[0].message.content
    print("Raw response:")
    print(content)
    print("\n" + "-" * 40)
    
    # Extract JSON
    if "```json" in content:
        json_match = re.search(r"```json\s*\n(.*?)\n```", content, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group(1))
        else:
            print("Could not extract JSON from code block")
            data = {}
    else:
        try:
            data = json.loads(content)
        except:
            print("Could not parse as JSON")
            data = {}
    
    if data.get("claims"):
        print("\nExtracted claims:")
        for i, claim in enumerate(data["claims"], 1):
            actor = claim.get("actor", "Unknown")
            technique = claim.get("technique", "")
            activity = claim.get("activity", "Unknown")
            print(f"  {i}. {actor}: {activity}")
            if technique:
                print(f"     Technique: {technique}")
    else:
        print("No claims extracted")
        
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()

print("\n✅ Test complete")