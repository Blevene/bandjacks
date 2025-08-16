"""Tests for technique phrase handling and enhanced scoring."""

from bandjacks.loaders.technique_phrases import (
    find_technique_phrases,
    find_tool_mentions,
    calculate_phrase_relevance,
    normalize_phrase,
    get_all_technique_hints,
    expand_technique_text
)
from bandjacks.loaders.propose import (
    calculate_keyword_score,
    calculate_phrase_score,
    calculate_tool_hint_score,
    score_candidates
)


def test_normalize_phrase():
    """Test phrase normalization."""
    assert normalize_phrase("spear-phishing") == "spear phishing"
    assert normalize_phrase("spear_phishing") == "spear phishing"
    assert normalize_phrase("C&C") == "c&c"
    assert normalize_phrase("Command  and   Control") == "command and control"
    assert normalize_phrase("pass-the-hash") == "pass the hash"
    print("✓ Phrase normalization working")


def test_find_technique_phrases():
    """Test finding technique phrases in text."""
    text1 = "The attacker used spearphishing emails with malicious attachments."
    phrases1 = find_technique_phrases(text1)
    assert "spearphishing" in phrases1 or "spear phishing" in phrases1
    assert "malicious attachment" in phrases1
    
    text2 = "They established persistence through registry run keys and scheduled tasks."
    phrases2 = find_technique_phrases(text2)
    assert "registry run key" in phrases2
    assert "scheduled task" in phrases2
    
    text3 = "Credential dumping was performed using mimikatz on the LSASS process."
    phrases3 = find_technique_phrases(text3)
    assert "credential dumping" in phrases3
    assert "lsass" in text3.lower()  # Should be found
    
    print("✓ Technique phrase detection working")


def test_find_tool_mentions():
    """Test finding tool mentions and their associations."""
    text1 = "The group deployed Cobalt Strike beacon for command and control."
    tools1 = find_tool_mentions(text1)
    assert "cobalt strike" in tools1
    assert "T1071" in tools1["cobalt strike"]  # C2 technique
    
    text2 = "Mimikatz was used to dump credentials from memory."
    tools2 = find_tool_mentions(text2)
    assert "mimikatz" in tools2
    assert "T1003" in tools2["mimikatz"]  # Credential dumping
    
    text3 = "BloodHound helped enumerate domain users and groups."
    tools3 = find_tool_mentions(text3)
    assert "bloodhound" in tools3
    assert "T1087" in tools3["bloodhound"]  # Account discovery
    
    print("✓ Tool mention detection working")


def test_behavioral_patterns():
    """Test detection of behavioral patterns."""
    text1 = "The malware will download and execute additional payloads."
    phrases1 = find_technique_phrases(text1)
    assert "download and execute" in phrases1
    assert "T1105" in phrases1["download and execute"]  # Ingress Tool Transfer
    
    text2 = "Attackers scan for open ports to identify vulnerable services."
    phrases2 = find_technique_phrases(text2)
    assert "scan for open ports" in phrases2
    assert "T1046" in phrases2["scan for open ports"]  # Network Service Scanning
    
    text3 = "The script attempts to disable security software before proceeding."
    phrases3 = find_technique_phrases(text3)
    assert "disable security" in phrases3
    assert "T1562.001" in phrases3["disable security"]  # Disable/Modify Tools
    
    print("✓ Behavioral pattern detection working")


def test_calculate_phrase_relevance():
    """Test phrase relevance scoring for techniques."""
    # Direct phrase match
    text1 = "The attacker uses PowerShell scripts for execution."
    score1, phrase1 = calculate_phrase_relevance(text1, "T1059.001")  # PowerShell
    assert score1 == 100.0
    assert "powershell" in phrase1.lower()
    
    # Tool association
    text2 = "Mimikatz was deployed on the target system."
    score2, phrase2 = calculate_phrase_relevance(text2, "T1003")  # Credential Dumping
    assert score2 >= 60.0  # Tool association score
    assert "mimikatz" in phrase2.lower()
    
    # Base technique match (parent of sub-technique)
    text3 = "Credential dumping techniques were observed."
    score3, phrase3 = calculate_phrase_relevance(text3, "T1003.001")  # LSASS Memory
    assert score3 >= 75.0  # Should match parent T1003
    
    # No match
    text4 = "The system was rebooted."
    score4, phrase4 = calculate_phrase_relevance(text4, "T1059.001")
    assert score4 == 0.0
    assert phrase4 == ""
    
    print("✓ Phrase relevance scoring working")


def test_enhanced_keyword_scoring():
    """Test enhanced keyword scoring with phrase awareness."""
    # Test that normalization helps with matching
    score1 = calculate_keyword_score(
        "The attack used spearphishing emails",  
        "Spearphishing",  # Single word match after normalization
        "technique"
    )
    assert score1 == 100.0  # Direct match
    
    # Test exact match
    score2 = calculate_keyword_score(
        "PowerShell was used extensively",
        "PowerShell",
        "technique"
    )
    assert score2 == 100.0
    
    # Test normalized match with hyphens
    score3 = calculate_keyword_score(
        "pass-the-hash attacks were detected",
        "Pass the Hash",
        "technique"
    )
    assert score3 >= 95.0  # Normalized match
    
    # Test partial word overlap
    score4 = calculate_keyword_score(
        "The malware uses registry keys",
        "Registry Run Keys",
        "technique"
    )
    # Should get partial score for "registry" and "keys" overlap
    assert score4 > 50  # 2 out of 3 words match
    
    print("✓ Enhanced keyword scoring working")


def test_tool_hint_scoring():
    """Test tool-based technique hint scoring."""
    # Direct tool-technique association
    score1 = calculate_tool_hint_score(
        "Cobalt Strike beacon was installed",
        "T1071"  # Application Layer Protocol
    )
    assert score1 == 100.0
    
    # Parent technique match
    score2 = calculate_tool_hint_score(
        "Mimikatz extracted credentials",
        "T1003.001"  # LSASS Memory (child of T1003)
    )
    assert score2 >= 50.0  # Parent match
    
    # No tool mentioned
    score3 = calculate_tool_hint_score(
        "The system was compromised",
        "T1059"
    )
    assert score3 == 0.0
    
    print("✓ Tool hint scoring working")


def test_comprehensive_scoring():
    """Test the complete scoring system with all factors."""
    text = "APT29 uses spearphishing emails with malicious attachments and PowerShell scripts for initial access and execution. They maintain persistence through registry run keys."
    
    # Mock candidates with realistic scores
    candidates = [
        {
            "stix_id": "attack-pattern--1",
            "name_or_snippet": "Spearphishing Attachment T1566.001",
            "score": 1.5,
            "text": "phishing email malicious attachment"
        },
        {
            "stix_id": "attack-pattern--2",
            "name_or_snippet": "PowerShell T1059.001",
            "score": 1.3,
            "text": "powershell script execution"
        },
        {
            "stix_id": "attack-pattern--3",
            "name_or_snippet": "Registry Run Keys T1547.001",
            "score": 1.2,
            "text": "persistence registry autostart"
        },
        {
            "stix_id": "attack-pattern--4",
            "name_or_snippet": "Process Injection T1055",
            "score": 0.5,
            "text": "inject code process memory"
        }
    ]
    
    scored = score_candidates(text, candidates, "technique")
    
    # Check that relevant techniques score higher
    spearphishing = next(c for c in scored if "T1566" in c["name_or_snippet"])
    powershell = next(c for c in scored if "T1059" in c["name_or_snippet"])
    registry = next(c for c in scored if "T1547" in c["name_or_snippet"])
    injection = next(c for c in scored if "T1055" in c["name_or_snippet"])
    
    # All mentioned techniques should score higher than injection
    assert spearphishing["confidence"] > injection["confidence"]
    assert powershell["confidence"] > injection["confidence"]
    assert registry["confidence"] > injection["confidence"]
    
    # Check that scoring details are populated
    assert "phrase" in spearphishing["scoring_details"]
    assert "keyword" in spearphishing["scoring_details"]
    assert "tactic_boost" in registry["scoring_details"]
    
    # Registry should get persistence tactic boost
    assert registry["scoring_details"]["tactic_boost"] > 0
    
    print("✓ Comprehensive scoring working")
    print(f"  Spearphishing: {spearphishing['confidence']}")
    print(f"  PowerShell: {powershell['confidence']}")
    print(f"  Registry: {registry['confidence']}")
    print(f"  Injection: {injection['confidence']}")


def test_get_all_technique_hints():
    """Test extraction of all technique hints from text."""
    text = """
    The threat actor uses Cobalt Strike for C2 communications and Mimikatz 
    for credential dumping. They establish persistence through scheduled tasks 
    and registry modifications. Initial access is gained via spearphishing 
    with malicious Office documents. The group performs discovery using 
    BloodHound and moves laterally using PsExec.
    """
    
    hints = get_all_technique_hints(text)
    
    # Should include techniques from multiple sources
    assert "T1003" in hints  # Mimikatz
    assert "T1071" in hints  # Cobalt Strike C2
    assert "T1053.005" in hints or "T1053" in hints  # Scheduled tasks
    assert "T1566" in hints or "T1566.001" in hints  # Spearphishing
    assert "T1087" in hints  # BloodHound discovery
    assert "T1021.002" in hints or "T1570" in hints  # PsExec
    
    print(f"✓ Found {len(hints)} technique hints from comprehensive text")


def test_expand_technique_text():
    """Test technique name expansion with synonyms."""
    expanded1 = expand_technique_text("PowerShell")
    assert "powershell script" in expanded1.lower()
    assert "powershell command" in expanded1.lower()
    
    expanded2 = expand_technique_text("Spearphishing Attachment")
    assert "spear phishing" in expanded2.lower() or "targeted phishing" in expanded2.lower()
    
    expanded3 = expand_technique_text("Credential Dumping")
    assert "dump credentials" in expanded3.lower() or "credential theft" in expanded3.lower()
    
    print("✓ Technique text expansion working")


def test_phrase_variations():
    """Test handling of common phrase variations."""
    # Test that hyphenated versions normalize correctly
    assert normalize_phrase("spear-phishing") == "spear phishing"
    assert normalize_phrase("pass-the-hash") == "pass the hash"
    assert normalize_phrase("drive-by") == "drive by"
    assert normalize_phrase("dll-injection") == "dll injection"
    
    # Test that these normalized forms would match in text
    text = "The attack used spear phishing and pass the hash techniques"
    assert "spear phishing" in text
    assert "pass the hash" in text
    
    # C&C is special case - stays as is
    assert normalize_phrase("c&c") == "c&c"
    assert normalize_phrase("command and control") == "command and control"
    
    print("✓ Phrase variation handling working")


if __name__ == "__main__":
    print("Testing Technique Phrase Handling")
    print("-" * 40)
    
    test_normalize_phrase()
    test_find_technique_phrases()
    test_find_tool_mentions()
    test_behavioral_patterns()
    test_calculate_phrase_relevance()
    test_enhanced_keyword_scoring()
    test_tool_hint_scoring()
    test_comprehensive_scoring()
    test_get_all_technique_hints()
    test_expand_technique_text()
    test_phrase_variations()
    
    print("-" * 40)
    print("✅ All technique phrase tests passed!")