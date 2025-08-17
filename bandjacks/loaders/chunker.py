"""Text chunking with overlap and metadata preservation."""

from typing import List, Dict, Any, Optional
import re


def split_into_chunks(
    text: str,
    source_id: str,
    target_chars: int = 1200,
    overlap: int = 150,
    metadata: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Split text into overlapping chunks with metadata.
    
    Args:
        text: Full text to chunk
        source_id: Identifier for the source document
        target_chars: Target characters per chunk
        overlap: Number of overlapping characters between chunks
        metadata: Optional metadata from parsing (pages, sections, etc.)
        
    Returns:
        List of chunk dictionaries with id, text, and metadata
    """
    if not text or not text.strip():
        return []
    
    # Extract page information if available
    pages = extract_page_boundaries(text) if metadata and metadata.get("pages") else None
    
    chunks = []
    text_length = len(text)
    chunk_idx = 0
    start = 0
    
    while start < text_length:
        # Calculate end position
        end = min(start + target_chars, text_length)
        
        # Try to break at sentence boundary if not at end
        if end < text_length:
            # Look for sentence endings within last 20% of chunk
            search_start = end - int(target_chars * 0.2)
            sentence_ends = find_sentence_boundaries(text[search_start:end])
            if sentence_ends:
                # Adjust end to last sentence boundary
                end = search_start + sentence_ends[-1]
        
        # Extract chunk text
        chunk_text = text[start:end].strip()
        
        if chunk_text:
            # Determine page number if page info available
            page_num = None
            if pages:
                for page_info in pages:
                    if start >= page_info["start"] and start < page_info["end"]:
                        page_num = page_info["page"]
                        break
            
            # Create chunk ID
            if page_num:
                chunk_id = f"{source_id}#p{page_num}-c{chunk_idx}"
            else:
                chunk_id = f"{source_id}#c{chunk_idx}"
            
            # Build chunk object
            chunk = {
                "id": chunk_id,
                "text": chunk_text,
                "metadata": {
                    "source_id": source_id,
                    "chunk_index": chunk_idx,
                    "start_char": start,
                    "end_char": end,
                    "length": len(chunk_text)
                }
            }
            
            if page_num:
                chunk["metadata"]["page"] = page_num
            
            # Add any section info if we can determine it
            section = extract_section_for_position(text, start, metadata)
            if section:
                chunk["metadata"]["section"] = section
            
            chunks.append(chunk)
            chunk_idx += 1
        
        # Move to next chunk with overlap
        if end >= text_length:
            break
        
        # Calculate next start position with overlap
        start = end - overlap
        
        # Ensure we make progress
        if start <= chunks[-1]["metadata"]["start_char"] if chunks else 0:
            start = end
    
    return chunks


def find_sentence_boundaries(text: str) -> List[int]:
    """Find positions of sentence endings in text."""
    boundaries = []
    
    # Common sentence ending patterns
    patterns = [
        r'\. +',  # Period followed by space
        r'\.\n',  # Period followed by newline
        r'[!?] +',  # Exclamation or question mark followed by space
        r'[!?]\n',  # Exclamation or question mark followed by newline
    ]
    
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            boundaries.append(match.end())
    
    return sorted(set(boundaries))


def extract_page_boundaries(text: str) -> List[Dict[str, int]]:
    """Extract page boundary positions from text with page markers."""
    pages = []
    
    # Look for page markers like "[Page 1]"
    page_pattern = r'\[Page (\d+)\]'
    
    for match in re.finditer(page_pattern, text):
        page_num = int(match.group(1))
        start_pos = match.end()
        
        # Find next page marker or end of text
        next_match = re.search(page_pattern, text[start_pos:])
        if next_match:
            end_pos = start_pos + next_match.start()
        else:
            end_pos = len(text)
        
        pages.append({
            "page": page_num,
            "start": start_pos,
            "end": end_pos
        })
    
    return pages


def extract_section_for_position(text: str, position: int, metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """
    Try to determine which section a text position belongs to.
    
    Args:
        text: Full text
        position: Character position in text
        metadata: Optional metadata with headers/sections
        
    Returns:
        Section name if determinable, None otherwise
    """
    if not metadata:
        return None
    
    # Check for headers in metadata
    headers = metadata.get("headers", [])
    if not headers:
        return None
    
    # Find the most recent header before this position
    last_header = None
    for header in headers:
        header_text = header.get("text", "")
        if header_text in text:
            header_pos = text.find(header_text)
            if header_pos >= 0 and header_pos < position:
                last_header = header_text
    
    return last_header


def merge_chunks(chunks: List[Dict[str, Any]], max_chars: int = 2000) -> List[Dict[str, Any]]:
    """
    Merge small adjacent chunks if they're too small.
    
    Args:
        chunks: List of chunks to potentially merge
        max_chars: Maximum characters for merged chunk
        
    Returns:
        List of potentially merged chunks
    """
    if len(chunks) <= 1:
        return chunks
    
    merged = []
    current = chunks[0]
    
    for next_chunk in chunks[1:]:
        current_len = len(current["text"])
        next_len = len(next_chunk["text"])
        
        # Merge if combined length is reasonable
        if current_len + next_len <= max_chars:
            # Merge chunks
            current = {
                "id": current["id"].split("#")[0] + f"#c{current['metadata']['chunk_index']}-{next_chunk['metadata']['chunk_index']}",
                "text": current["text"] + "\n\n" + next_chunk["text"],
                "metadata": {
                    **current["metadata"],
                    "end_char": next_chunk["metadata"]["end_char"],
                    "length": current_len + next_len + 2,  # +2 for \n\n
                    "merged": True,
                    "original_chunks": [
                        current["metadata"]["chunk_index"],
                        next_chunk["metadata"]["chunk_index"]
                    ]
                }
            }
        else:
            # Save current and start new
            merged.append(current)
            current = next_chunk
    
    # Don't forget the last chunk
    merged.append(current)
    
    return merged