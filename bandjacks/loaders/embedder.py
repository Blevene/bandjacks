"""Text embedding module using sentence-transformers."""

from sentence_transformers import SentenceTransformer
from functools import lru_cache

@lru_cache(maxsize=1)
def get_model():
    """Load and cache the sentence transformer model."""
    return SentenceTransformer("sentence-transformers/all-mpnet-base-v2")  # 768-dim

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