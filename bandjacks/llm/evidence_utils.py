"""Utilities for extracting sentence-based evidence from documents."""

import re
import logging
from typing import Dict, List, Tuple, Optional, Any

logger = logging.getLogger(__name__)


def find_sentence_boundaries(text: str) -> List[Tuple[int, int]]:
    """
    Find sentence boundaries in text using regex and heuristics.
    
    Args:
        text: The text to analyze
        
    Returns:
        List of (start, end) tuples for each sentence
    """
    if not text:
        return []
    
    # Common abbreviations that don't end sentences (without periods)
    abbreviations = {
        'Dr', 'Mr', 'Mrs', 'Ms', 'Prof', 'Sr', 'Jr', 
        'Inc', 'Corp', 'Ltd', 'Co', 'vs', 'etc', 'i.e', 
        'e.g', 'cf', 'al', 'et al', 'Ph.D', 'M.D', 'B.A',
        'M.A', 'B.S', 'M.S', 'U.S', 'U.K', 'E.U', 'U.N',
        'U', 'E'  # For U.S., U.K., E.U.
    }
    
    # More sophisticated sentence ending pattern
    # Look for sentence endings but not after abbreviations
    sentences = []
    current_start = 0
    i = 0
    
    while i < len(text):
        # Check for potential sentence ending
        if i < len(text) - 1 and text[i] in '.!?':
            # Look ahead for capital letter or newline
            j = i + 1
            while j < len(text) and text[j] in ' \t':
                j += 1
            
            is_sentence_end = False
            
            # Check if followed by capital letter or newline
            if j < len(text) and (text[j].isupper() or text[j] == '\n'):
                # Check if preceded by abbreviation
                word_before = ""
                k = i - 1
                while k >= 0 and text[k] not in ' \n\t':
                    word_before = text[k] + word_before
                    k -= 1
                
                # Not an abbreviation
                if word_before not in abbreviations:
                    is_sentence_end = True
            
            # Also check for end of text
            elif j >= len(text):
                is_sentence_end = True
            
            if is_sentence_end:
                # Found sentence boundary
                sentences.append((current_start, i + 1))
                current_start = j
                i = j
                continue
        
        # Check for paragraph breaks (double newline)
        elif i < len(text) - 1 and text[i] == '\n' and text[i + 1] == '\n':
            if i > current_start:
                sentences.append((current_start, i))
                # Skip the newlines
                j = i + 2
                while j < len(text) and text[j] in '\n \t':
                    j += 1
                current_start = j
                i = j
                continue
        
        i += 1
    
    # Add final sentence if any
    if current_start < len(text):
        sentences.append((current_start, len(text)))
    
    # Clean up - remove empty sentences
    sentences = [(s, e) for s, e in sentences if s < e and text[s:e].strip()]
    
    # Handle edge case where no sentences were found
    if not sentences:
        return [(0, len(text))]
    
    return sentences


def calculate_line_refs(text: str, start_pos: int, end_pos: int) -> List[int]:
    """
    Calculate line numbers for a text span.
    
    Args:
        text: Full document text
        start_pos: Starting character position
        end_pos: Ending character position
        
    Returns:
        List of 1-indexed line numbers
    """
    if not text or start_pos < 0 or end_pos > len(text):
        return []
    
    # Split text into lines
    lines = text.split('\n')
    
    # Build line start positions
    line_starts = [0]
    for line in lines[:-1]:
        line_starts.append(line_starts[-1] + len(line) + 1)  # +1 for newline
    
    # Find which lines overlap with our span
    line_refs = []
    for i, line_start in enumerate(line_starts):
        line_end = line_starts[i + 1] if i + 1 < len(line_starts) else len(text)
        
        # Check if this line overlaps with our span
        if line_start < end_pos and line_end > start_pos:
            line_refs.append(i + 1)  # 1-indexed
    
    return line_refs


def extract_sentence_evidence(
    text: str, 
    match_position: int, 
    context_sentences: int = 1,
    max_length: int = 1000
) -> Dict[str, Any]:
    """
    Extract complete sentences around a match position as evidence.
    
    Args:
        text: Full document text
        match_position: Character position of the match
        context_sentences: Number of sentences before/after to include
        max_length: Maximum total evidence length
        
    Returns:
        Dictionary with:
        - quote: The extracted evidence text
        - line_refs: Line numbers containing the evidence
        - sentence_indices: (start_idx, end_idx) of sentences included
        - char_positions: (start_pos, end_pos) in original text
    """
    if not text or match_position < 0 or match_position > len(text):
        return {
            "quote": "",
            "line_refs": [],
            "sentence_indices": (0, 0),
            "char_positions": (0, 0)
        }
    
    # Find all sentence boundaries
    sentences = find_sentence_boundaries(text)
    
    if not sentences:
        # Fallback: return a window around the match
        start = max(0, match_position - 100)
        end = min(len(text), match_position + 100)
        return {
            "quote": text[start:end].strip(),
            "line_refs": calculate_line_refs(text, start, end),
            "sentence_indices": (0, 1),
            "char_positions": (start, end)
        }
    
    # Find which sentence contains our match
    match_sentence_idx = 0
    for i, (start, end) in enumerate(sentences):
        if start <= match_position < end:
            match_sentence_idx = i
            break
        elif match_position < start:
            # Match is before this sentence, use previous
            match_sentence_idx = max(0, i - 1)
            break
    else:
        # Match is after all sentences, use last
        match_sentence_idx = len(sentences) - 1
    
    # Calculate range of sentences to include
    start_idx = max(0, match_sentence_idx - context_sentences)
    end_idx = min(len(sentences), match_sentence_idx + context_sentences + 1)
    
    # Extract the evidence text
    if start_idx < len(sentences) and end_idx > start_idx:
        evidence_start = sentences[start_idx][0]
        evidence_end = sentences[end_idx - 1][1]
        
        # Extract and clean the text
        evidence_text = text[evidence_start:evidence_end].strip()
        
        # Limit length if needed
        if len(evidence_text) > max_length:
            # Try to keep the match sentence and trim context
            match_start = sentences[match_sentence_idx][0] - evidence_start
            match_end = sentences[match_sentence_idx][1] - evidence_start
            
            # Center around the match sentence
            half_max = max_length // 2
            trim_start = max(0, match_start - half_max)
            trim_end = min(len(evidence_text), match_end + half_max)
            
            evidence_text = evidence_text[trim_start:trim_end]
            
            # Adjust positions for trimming
            evidence_start += trim_start
            evidence_end = evidence_start + len(evidence_text)
        
        # Calculate line references
        line_refs = calculate_line_refs(text, evidence_start, evidence_end)
        
        return {
            "quote": evidence_text,
            "line_refs": line_refs,
            "sentence_indices": (start_idx, end_idx),
            "char_positions": (evidence_start, evidence_end)
        }
    
    # Fallback if something went wrong
    return {
        "quote": "",
        "line_refs": [],
        "sentence_indices": (0, 0),
        "char_positions": (0, 0)
    }


def extract_sentence_for_line(
    text: str,
    line_index: List[str],
    line_number: int,
    context_sentences: int = 1
) -> Dict[str, Any]:
    """
    Extract complete sentences for a specific line number.
    
    Args:
        text: Full document text
        line_index: List of lines in the document
        line_number: 1-indexed line number
        context_sentences: Number of context sentences
        
    Returns:
        Evidence dictionary with quote and line references
    """
    if not line_index or line_number < 1 or line_number > len(line_index):
        return {
            "quote": "",
            "line_refs": [],
            "sentence_indices": (0, 0),
            "char_positions": (0, 0)
        }
    
    # Calculate character position of the line
    char_pos = 0
    for i in range(line_number - 1):
        char_pos += len(line_index[i]) + 1  # +1 for newline
    
    # Find a good position within the line (middle of first word match)
    line_text = line_index[line_number - 1]
    words = line_text.split()
    if words:
        # Position at first significant word (skip short words)
        for word in words:
            if len(word) > 3:
                word_pos = line_text.find(word)
                if word_pos >= 0:
                    char_pos += word_pos
                    break
    
    return extract_sentence_evidence(text, char_pos, context_sentences)


def merge_overlapping_evidence(
    evidence_list: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Merge overlapping evidence quotes to avoid duplication.
    
    Args:
        evidence_list: List of evidence dictionaries
        
    Returns:
        Merged list with no overlapping quotes
    """
    if not evidence_list:
        return []
    
    # Sort by start position
    sorted_evidence = sorted(
        evidence_list,
        key=lambda x: x.get("char_positions", (0, 0))[0]
    )
    
    merged = []
    current = None
    
    for evidence in sorted_evidence:
        if not evidence.get("quote"):
            continue
            
        if current is None:
            current = evidence.copy()
        else:
            # Check for overlap
            curr_start, curr_end = current.get("char_positions", (0, 0))
            new_start, new_end = evidence.get("char_positions", (0, 0))
            
            if new_start <= curr_end:
                # Merge overlapping evidence
                current["char_positions"] = (curr_start, max(curr_end, new_end))
                current["line_refs"] = sorted(
                    set(current.get("line_refs", []) + evidence.get("line_refs", []))
                )
                # Extend quote if needed (this is simplified, may need text reconstruction)
                if new_end > curr_end:
                    # This is a simplification - in practice you'd reconstruct from text
                    current["quote"] = current["quote"]
            else:
                # No overlap, save current and start new
                merged.append(current)
                current = evidence.copy()
    
    # Don't forget the last one
    if current:
        merged.append(current)
    
    return merged