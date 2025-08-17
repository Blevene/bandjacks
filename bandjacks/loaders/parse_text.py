"""Document parsing for various formats."""

import json
import csv
import io
import re
from typing import Optional, Dict, Any
import httpx
from PyPDF2 import PdfReader
from bs4 import BeautifulSoup
import markdown


def extract_text(source_type: str, content_url: Optional[str] = None, inline_text: Optional[str] = None) -> Dict[str, Any]:
    """
    Extract text from various document formats.
    
    Args:
        source_type: Type of document (pdf, html, md, json, csv)
        content_url: URL to fetch content from (s3://, http://, https://)
        inline_text: Raw text content if provided directly
        
    Returns:
        Dict with 'text' and 'metadata' (pages, sections, etc.)
    """
    if inline_text:
        content = inline_text
        is_bytes = False
    elif content_url:
        content = fetch_content(content_url)
        is_bytes = isinstance(content, bytes)
    else:
        raise ValueError("Either content_url or inline_text must be provided")
    
    if source_type == "pdf":
        return extract_pdf(content if is_bytes else content.encode())
    elif source_type == "html":
        return extract_html(content)
    elif source_type == "md":
        return extract_markdown(content)
    elif source_type == "json":
        return extract_json(content)
    elif source_type == "csv":
        return extract_csv(content)
    else:
        raise ValueError(f"Unsupported source_type: {source_type}")


def fetch_content(url: str) -> bytes | str:
    """Fetch content from URL (supports http/https for now)."""
    if url.startswith(("http://", "https://")):
        resp = httpx.get(url, timeout=30)
        resp.raise_for_status()
        # Return bytes for binary content, str for text
        if "application/pdf" in resp.headers.get("content-type", ""):
            return resp.content
        return resp.text
    elif url.startswith("s3://"):
        # S3 support would require boto3 - skip for MVP
        raise NotImplementedError("S3 URLs not yet supported")
    else:
        raise ValueError(f"Unsupported URL scheme: {url}")


def extract_pdf(content: bytes) -> Dict[str, Any]:
    """Extract text from PDF bytes."""
    reader = PdfReader(io.BytesIO(content))
    pages = []
    full_text = []
    
    for i, page in enumerate(reader.pages):
        page_text = page.extract_text()
        pages.append({
            "page": i + 1,
            "text": page_text
        })
        full_text.append(f"[Page {i+1}]\n{page_text}")
    
    return {
        "text": "\n\n".join(full_text),
        "metadata": {
            "pages": pages,
            "total_pages": len(reader.pages)
        }
    }


def extract_html(content: str) -> Dict[str, Any]:
    """Extract text from HTML, preserving some structure."""
    soup = BeautifulSoup(content, 'html.parser')
    
    # Remove script and style elements
    for script in soup(["script", "style"]):
        script.extract()
    
    # Extract title if present
    title = soup.find('title')
    title_text = title.string if title else None
    
    # Extract headers for structure
    headers = []
    for level in range(1, 7):
        for header in soup.find_all(f'h{level}'):
            headers.append({
                "level": level,
                "text": header.get_text(strip=True)
            })
    
    # Get main text
    text = soup.get_text()
    # Clean up whitespace
    lines = (line.strip() for line in text.splitlines())
    chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
    text = '\n'.join(chunk for chunk in chunks if chunk)
    
    return {
        "text": text,
        "metadata": {
            "title": title_text,
            "headers": headers
        }
    }


def extract_markdown(content: str) -> Dict[str, Any]:
    """Extract text from Markdown."""
    # Convert to HTML first, then extract
    html = markdown.markdown(content)
    result = extract_html(html)
    
    # Also extract headers from original markdown
    headers = []
    for line in content.split('\n'):
        if line.startswith('#'):
            level = len(re.match(r'^#+', line).group())
            text = line.lstrip('#').strip()
            headers.append({"level": level, "text": text})
    
    result["metadata"]["markdown_headers"] = headers
    return result


def extract_json(content: str) -> Dict[str, Any]:
    """Extract text from JSON, flattening string fields."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return {"text": content, "metadata": {"format_error": "Invalid JSON"}}
    
    text_parts = []
    
    def extract_strings(obj, path=""):
        """Recursively extract string values from JSON."""
        if isinstance(obj, str):
            text_parts.append(f"{path}: {obj}" if path else obj)
        elif isinstance(obj, dict):
            for key, value in obj.items():
                new_path = f"{path}.{key}" if path else key
                extract_strings(value, new_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                new_path = f"{path}[{i}]" if path else f"[{i}]"
                extract_strings(item, new_path)
    
    extract_strings(data)
    
    return {
        "text": "\n".join(text_parts),
        "metadata": {
            "keys": list(data.keys()) if isinstance(data, dict) else None,
            "type": type(data).__name__
        }
    }


def extract_csv(content: str) -> Dict[str, Any]:
    """Extract text from CSV, joining rows."""
    reader = csv.reader(io.StringIO(content))
    rows = list(reader)
    
    if not rows:
        return {"text": "", "metadata": {"rows": 0}}
    
    # Use first row as headers if it looks like headers
    headers = rows[0] if rows else []
    
    text_parts = []
    for i, row in enumerate(rows[1:] if headers else rows):
        if headers and len(row) == len(headers):
            # Format as key: value pairs
            row_text = "; ".join(f"{h}: {v}" for h, v in zip(headers, row) if v)
        else:
            # Just join values
            row_text = "; ".join(v for v in row if v)
        
        if row_text:
            text_parts.append(f"Row {i+1}: {row_text}")
    
    return {
        "text": "\n".join(text_parts),
        "metadata": {
            "headers": headers,
            "rows": len(rows),
            "columns": len(headers) if headers else (len(rows[0]) if rows else 0)
        }
    }