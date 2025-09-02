"""Test evidence quality improvement with sentence-based extraction."""

import json
from bandjacks.llm.memory import WorkingMemory
from bandjacks.llm.agents_v2 import SpanFinderAgent


def test_evidence_quality_comparison():
    """Compare evidence quality before and after sentence-based extraction."""
    
    # Sample cyber threat report text
    sample_text = """
The threat actor APT29, also known as Cozy Bear, initiated their campaign in March 2020.
They used spear-phishing emails containing malicious Office documents as the initial attack vector.
Upon execution, these documents would run PowerShell scripts to download additional payloads.
The group deployed a custom backdoor called SUNSPOT for maintaining persistence.
Lateral movement was achieved through the use of stolen credentials and SMB shares.
The attackers used techniques including T1055 for process injection and T1003.001 for credential dumping.
They established command and control channels using HTTPS traffic to blend in with normal activity.
Data exfiltration occurred over several months before the breach was finally detected.
The campaign targeted government agencies and critical infrastructure sectors.
Mitigation efforts included patching vulnerable systems and implementing enhanced monitoring.
"""
    
    # Create working memory
    lines = [line.strip() for line in sample_text.strip().split('\n') if line.strip()]
    mem = WorkingMemory(
        document_text=sample_text,
        line_index=lines
    )
    
    # Run SpanFinderAgent
    agent = SpanFinderAgent()
    agent.run(mem, {})
    
    print("\n" + "="*80)
    print("EVIDENCE QUALITY ANALYSIS")
    print("="*80)
    
    # Analyze spans
    for i, span in enumerate(mem.spans[:5], 1):  # Show first 5 spans
        print(f"\n--- Span {i} ---")
        print(f"Score: {span.get('score', 0):.2f}")
        print(f"Type: {span.get('type', 'unknown')}")
        print(f"Tactics: {', '.join(span.get('tactics', []))}")
        print(f"Line refs: {span.get('line_refs', [])}")
        print(f"\nEvidence text ({len(span['text'])} chars):")
        print(f"  {span['text'][:200]}..." if len(span['text']) > 200 else f"  {span['text']}")
        
        # Check for complete sentences
        text = span['text']
        is_complete = (
            text[0].isupper() and  # Starts with capital
            text[-1] in '.!?'  # Ends with punctuation
        )
        print(f"\nQuality check:")
        print(f"  - Complete sentence: {'✓' if is_complete else '✗'}")
        print(f"  - Has context: {'✓' if len(text) > 100 else '✗'}")
        print(f"  - Multiple lines: {'✓' if len(span.get('line_refs', [])) > 1 else '✗'}")
    
    # Summary statistics
    print("\n" + "="*80)
    print("SUMMARY STATISTICS")
    print("="*80)
    
    total_spans = len(mem.spans)
    sentence_based = sum(1 for s in mem.spans if 'sentence' in s.get('type', ''))
    avg_length = sum(len(s['text']) for s in mem.spans) / total_spans if total_spans > 0 else 0
    avg_lines = sum(len(s.get('line_refs', [])) for s in mem.spans) / total_spans if total_spans > 0 else 0
    
    print(f"Total spans found: {total_spans}")
    print(f"Sentence-based spans: {sentence_based} ({100*sentence_based/total_spans:.1f}%)")
    print(f"Average evidence length: {avg_length:.0f} characters")
    print(f"Average lines per span: {avg_lines:.1f}")
    
    # Quality metrics
    complete_sentences = sum(1 for s in mem.spans 
                           if s['text'] and s['text'][0].isupper() 
                           and s['text'][-1] in '.!?')
    
    print(f"\nQuality Metrics:")
    print(f"Complete sentences: {complete_sentences}/{total_spans} ({100*complete_sentences/total_spans:.1f}%)")
    
    # Assert quality improvements
    assert total_spans > 0, "Should find spans"
    assert sentence_based > 0, "Should have sentence-based spans"
    assert avg_length > 50, "Evidence should be substantial"
    assert complete_sentences / total_spans > 0.7, "Most evidence should be complete sentences"
    
    print("\n✓ All quality checks passed!")
    return mem


def test_specific_patterns():
    """Test specific pattern detection with sentence context."""
    
    test_cases = [
        {
            "name": "Explicit technique ID",
            "text": "The malware uses process injection. Specifically, it employs T1055 to inject code into legitimate processes. This allows it to evade detection.",
            "expected_in_evidence": ["T1055", "inject code", "legitimate processes"]
        },
        {
            "name": "Multi-stage attack",
            "text": "First, the attacker sends a phishing email. Then they download a payload using PowerShell. Finally, they execute the malware to establish persistence.",
            "expected_in_evidence": ["phishing email", "download", "PowerShell", "execute", "persistence"]
        },
        {
            "name": "Entity with actions",
            "text": "APT29 is known for sophisticated attacks. The group uses custom malware and living-off-the-land techniques. They often target government organizations.",
            "expected_in_evidence": ["APT29", "custom malware", "living-off-the-land", "government"]
        }
    ]
    
    print("\n" + "="*80)
    print("PATTERN-SPECIFIC TESTS")
    print("="*80)
    
    for test in test_cases:
        print(f"\n--- Testing: {test['name']} ---")
        
        lines = [line.strip() for line in test['text'].split('.') if line.strip()]
        mem = WorkingMemory(
            document_text=test['text'],
            line_index=lines
        )
        
        agent = SpanFinderAgent()
        agent.run(mem, {})
        
        if mem.spans:
            span = mem.spans[0]  # Get highest scoring span
            print(f"Evidence extracted: {span['text']}")
            
            # Check expected content
            for expected in test['expected_in_evidence']:
                if expected.lower() in span['text'].lower():
                    print(f"  ✓ Found: {expected}")
                else:
                    print(f"  ✗ Missing: {expected}")
        else:
            print("  ✗ No spans found!")
    
    print("\n✓ Pattern tests completed!")


if __name__ == "__main__":
    # Run tests
    print("Testing evidence quality improvements...")
    test_evidence_quality_comparison()
    test_specific_patterns()
    print("\n" + "="*80)
    print("✅ Evidence quality verification complete!")
    print("="*80)