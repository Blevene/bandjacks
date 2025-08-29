"""Text embedding module using sentence-transformers."""

from sentence_transformers import SentenceTransformer
from typing import List, Optional
import torch

# Global model instance - initialized once per worker
_model = None

def get_model():
    """Load and cache the sentence transformer model."""
    global _model
    if _model is None:
        # Force CPU device to avoid meta tensor issues
        device = 'cpu'
        _model = SentenceTransformer("sentence-transformers/all-mpnet-base-v2", device=device)
        # Ensure model is on the correct device
        _model = _model.to(device)
    return _model

def encode(text: str):
    """Encode text to a 768-dimensional vector."""
    if not text or not text.strip():
        return None
    
    try:
        m = get_model()
        v = m.encode([text], convert_to_numpy=True)[0]
        result = v.tolist()
        
        # Validate the result
        if not isinstance(result, list) or len(result) != 768:
            print(f"[embedder] Invalid vector dimensions: expected 768, got {len(result) if isinstance(result, list) else type(result)}")
            return None
            
        return result
    except Exception as e:
        print(f"[embedder] Error encoding text: {e}")
        return None

def batch_encode(texts: List[str]) -> List[Optional[List[float]]]:
    """Batch encode multiple texts to 768-dimensional vectors.
    
    Args:
        texts: List of text strings to encode
        
    Returns:
        List of vectors (or None for empty texts)
    """
    if not texts:
        return []
    
    try:
        m = get_model()
        
        # Filter out empty texts but track their positions
        valid_texts = []
        valid_indices = []
        results = [None] * len(texts)
        
        for i, text in enumerate(texts):
            if text and text.strip():
                valid_texts.append(text)
                valid_indices.append(i)
        
        if not valid_texts:
            return results
        
        # Batch encode all valid texts at once
        vectors = m.encode(valid_texts, convert_to_numpy=True, show_progress_bar=False)
        
        # Place vectors back in correct positions
        for i, vec in zip(valid_indices, vectors):
            results[i] = vec.tolist()
            
        return results
        
    except Exception as e:
        print(f"[embedder] Error batch encoding texts: {e}")
        # Fallback to sequential encoding
        return [encode(text) for text in texts]