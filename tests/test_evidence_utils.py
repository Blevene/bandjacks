"""Test sentence-based evidence extraction utilities."""

import pytest
from bandjacks.llm.evidence_utils import (
    find_sentence_boundaries,
    extract_sentence_evidence,
    extract_sentence_for_line,
    calculate_line_refs
)


class TestSentenceBoundaries:
    """Test sentence boundary detection."""
    
    def test_simple_sentences(self):
        """Test basic sentence detection."""
        text = "This is the first sentence. This is the second. And here's the third!"
        boundaries = find_sentence_boundaries(text)
        assert len(boundaries) == 3
        
        # Extract sentences
        sentences = [text[start:end].strip() for start, end in boundaries]
        assert sentences[0] == "This is the first sentence."
        assert sentences[1] == "This is the second."
        assert sentences[2] == "And here's the third!"
    
    def test_abbreviations(self):
        """Test handling of abbreviations."""
        text = "Dr. Smith from the U.S. visited the U.K. office. He met with Prof. Jones."
        boundaries = find_sentence_boundaries(text)
        assert len(boundaries) == 2
        
        sentences = [text[start:end].strip() for start, end in boundaries]
        assert "Dr. Smith" in sentences[0]
        assert "Prof. Jones" in sentences[1]
    
    def test_multiline_sentences(self):
        """Test sentences spanning multiple lines."""
        text = """The attacker first gained access through a phishing email
that contained malicious attachments. Then they moved laterally
across the network using stolen credentials."""
        boundaries = find_sentence_boundaries(text)
        assert len(boundaries) == 2
        
        sentences = [text[start:end].strip() for start, end in boundaries]
        assert "phishing email" in sentences[0]
        assert "stolen credentials" in sentences[1]
    
    def test_bullet_points(self):
        """Test handling of bullet points."""
        text = """The attack involved:
- Initial compromise via spear phishing
- Credential dumping with Mimikatz
- Lateral movement using PsExec"""
        boundaries = find_sentence_boundaries(text)
        # Should handle bullet points appropriately
        assert len(boundaries) >= 1
    
    def test_empty_text(self):
        """Test empty text handling."""
        boundaries = find_sentence_boundaries("")
        assert boundaries == []
        
        boundaries = find_sentence_boundaries("   ")
        assert len(boundaries) <= 1


class TestEvidenceExtraction:
    """Test evidence extraction functions."""
    
    def test_extract_sentence_evidence(self):
        """Test extracting evidence around a match."""
        text = """The threat actor APT29 was observed using PowerShell for initial execution.
They deployed custom malware called SUNBURST through supply chain compromise.
The malware established persistence via scheduled tasks and registry modifications.
Data exfiltration occurred over HTTPS to command and control servers."""
        
        # Find position of "SUNBURST"
        match_pos = text.find("SUNBURST")
        assert match_pos > 0
        
        # Extract evidence with 1 sentence context
        evidence = extract_sentence_evidence(text, match_pos, context_sentences=1)
        
        assert evidence["quote"]
        assert "SUNBURST" in evidence["quote"]
        assert "PowerShell" in evidence["quote"]  # Previous sentence
        assert "persistence" in evidence["quote"]  # Next sentence
        assert len(evidence["line_refs"]) > 0
    
    def test_extract_with_line_refs(self):
        """Test line reference calculation."""
        text = "Line one.\nLine two has content.\nLine three.\nLine four is here."
        
        # Extract from middle
        match_pos = text.find("content")
        evidence = extract_sentence_evidence(text, match_pos, context_sentences=0)
        
        assert evidence["quote"]
        assert "content" in evidence["quote"]
        assert 2 in evidence["line_refs"]  # Line 2 (1-indexed)
    
    def test_extract_sentence_for_line(self):
        """Test extracting evidence for a specific line."""
        lines = [
            "First line with some text.",
            "The attacker used Mimikatz for credential dumping.",
            "They then moved laterally.",
            "Final line here."
        ]
        text = "\n".join(lines)
        
        # Extract for line 2 (1-indexed)
        evidence = extract_sentence_for_line(text, lines, 2, context_sentences=1)
        
        assert evidence["quote"]
        assert "Mimikatz" in evidence["quote"]
        assert "First line" in evidence["quote"]  # Context before
        assert "laterally" in evidence["quote"]  # Context after
        assert 2 in evidence["line_refs"]
    
    def test_max_length_truncation(self):
        """Test evidence truncation for long text."""
        text = "Start. " + "This is a very long sentence that goes on and on. " * 50 + " End."
        
        match_pos = text.find("Start")
        evidence = extract_sentence_evidence(text, match_pos, context_sentences=10, max_length=200)
        
        assert len(evidence["quote"]) <= 200
        assert "Start" in evidence["quote"]
    
    def test_edge_cases(self):
        """Test various edge cases."""
        # Empty text
        evidence = extract_sentence_evidence("", 0)
        assert evidence["quote"] == ""
        assert evidence["line_refs"] == []
        
        # Position out of bounds
        evidence = extract_sentence_evidence("Test text.", 100)
        assert evidence["quote"] == ""
        
        # Single word text
        evidence = extract_sentence_evidence("Word", 0)
        assert evidence["quote"] == "Word"


class TestLineReferences:
    """Test line reference calculation."""
    
    def test_calculate_line_refs(self):
        """Test basic line reference calculation."""
        text = "Line 1\nLine 2\nLine 3\nLine 4"
        
        # Span covering lines 2-3
        refs = calculate_line_refs(text, 7, 20)
        assert refs == [2, 3]
        
        # Single line
        refs = calculate_line_refs(text, 0, 6)
        assert refs == [1]
        
        # All lines
        refs = calculate_line_refs(text, 0, len(text))
        assert refs == [1, 2, 3, 4]
    
    def test_empty_text_line_refs(self):
        """Test line refs for empty text."""
        refs = calculate_line_refs("", 0, 0)
        assert refs == []
    
    def test_multiline_span(self):
        """Test spans crossing multiple lines."""
        text = """First line here.
Second line with more content.
Third line is shorter.
Fourth and final line."""
        
        # Span from middle of line 2 to middle of line 3
        start = text.find("more content")
        end = text.find("shorter") + len("shorter")
        refs = calculate_line_refs(text, start, end)
        assert 2 in refs
        assert 3 in refs


class TestIntegration:
    """Integration tests with real-world examples."""
    
    def test_cyber_report_extraction(self):
        """Test with cyber threat report text."""
        report = """
Executive Summary:
APT29, also known as Cozy Bear, conducted a sophisticated campaign targeting government agencies.

Attack Timeline:
The initial compromise occurred in March 2020 through spear-phishing emails. The emails contained 
malicious Office documents that executed PowerShell scripts upon opening. These scripts downloaded
and installed a custom backdoor called SUNSPOT.

The threat actor used various techniques including T1055 (Process Injection) and T1003.001 
(LSASS Memory) for credential access. Lateral movement was achieved through T1021.002 (SMB/Windows 
Admin Shares) and T1021.004 (SSH).

Persistence mechanisms included:
- Registry Run Keys (T1547.001)
- Scheduled Tasks (T1053.005)
- WMI Event Subscription (T1546.003)

The campaign resulted in significant data exfiltration before detection in December 2020.
"""
        
        # Test extraction around technique IDs
        match_pos = report.find("T1055")
        evidence = extract_sentence_evidence(report, match_pos, context_sentences=1)
        
        assert "T1055" in evidence["quote"]
        assert "Process Injection" in evidence["quote"]
        assert len(evidence["line_refs"]) > 0
        
        # Test extraction around malware name
        match_pos = report.find("SUNSPOT")
        evidence = extract_sentence_evidence(report, match_pos, context_sentences=1)
        
        assert "SUNSPOT" in evidence["quote"]
        assert "PowerShell" in evidence["quote"]
        
        # Verify we get complete sentences, not fragments
        assert not evidence["quote"].startswith(".")
        assert not evidence["quote"].endswith("The")


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])