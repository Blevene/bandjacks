"""Token estimation utilities for dynamic chunk sizing."""

import tiktoken
from typing import Optional
import logging

logger = logging.getLogger(__name__)

class TokenEstimator:
    """Estimates token counts for text to prevent LLM context overflows."""
    
    def __init__(self, model: str = "gpt-4"):
        """
        Initialize token estimator.
        
        Args:
            model: Model name for tokenization (default: gpt-4)
        """
        try:
            self.encoder = tiktoken.encoding_for_model(model)
        except KeyError:
            # Fallback to cl100k_base encoding (used by GPT-4)
            self.encoder = tiktoken.get_encoding("cl100k_base")
        
        # Conservative limits for different operations
        self.limits = {
            'span_finder': 3000,      # SpanFinderAgent limit
            'batch_mapper': 2500,     # BatchMapperAgent limit  
            'consolidator': 2000,     # ConsolidatorAgent limit
            'entity_extractor': 2500, # EntityExtractionAgent limit
            'max_chunk': 4000,        # Maximum chunk size (conservative)
        }
        
        # Density-adjusted limits for very dense content
        self.dense_limits = {
            'span_finder': 2000,      # Reduced for dense content
            'batch_mapper': 1500,     # Reduced for dense content
            'consolidator': 1500,     # Reduced for dense content
            'entity_extractor': 1800, # Reduced for dense content
            'max_chunk': 2500,        # Much smaller for dense content
        }
    
    def estimate_tokens(self, text: str) -> int:
        """
        Estimate token count for text.
        
        Args:
            text: Text to estimate tokens for
            
        Returns:
            Estimated token count
        """
        try:
            return len(self.encoder.encode(text))
        except Exception as e:
            logger.warning(f"Token estimation failed, using character-based estimate: {e}")
            # Fallback: ~4 characters per token (conservative)
            return len(text) // 4
    
    def calculate_safe_chunk_size(
        self, 
        content_density: float = 1.0,
        target_operation: str = 'span_finder'
    ) -> int:
        """
        Calculate safe chunk size based on content density and operation.
        
        Args:
            content_density: Density factor (0.5 = sparse, 1.0 = normal, 2.0 = dense)
            target_operation: Operation the chunk will be used for
            
        Returns:
            Safe character count for chunk
        """
        # Use dense limits for high-density content
        if content_density > 1.5:
            token_limit = self.dense_limits.get(target_operation, self.dense_limits['max_chunk'])
            logger.info(f"Using dense limits for {target_operation}: {token_limit} tokens (density: {content_density})")
        else:
            token_limit = self.limits.get(target_operation, self.limits['max_chunk'])
        
        # Adjust for density (dense content = smaller chunks)
        # More aggressive reduction for very dense content
        if content_density > 2.0:
            adjusted_limit = int(token_limit * 0.6)  # 60% of limit for very dense
        elif content_density > 1.5:
            adjusted_limit = int(token_limit * 0.75)  # 75% of limit for dense
        else:
            adjusted_limit = int(token_limit / content_density)
        
        # Convert to approximate character count (4 chars per token average)
        char_limit = adjusted_limit * 4
        
        # Apply safety margin (70% of limit for dense content, 80% for normal)
        safety_factor = 0.7 if content_density > 1.5 else 0.8
        safe_limit = int(char_limit * safety_factor)
        
        # Hard cap for very dense content
        if content_density > 2.0:
            safe_limit = min(safe_limit, 2000)  # Never exceed 2000 chars for very dense
        elif content_density > 1.5:
            safe_limit = min(safe_limit, 3000)  # Never exceed 3000 chars for dense
        
        logger.debug(f"Safe chunk size for {target_operation}: {safe_limit} chars "
                    f"(density: {content_density}, tokens: {adjusted_limit})")
        
        return safe_limit
    
    def should_split_chunk(self, text: str, operation: str = 'span_finder') -> bool:
        """
        Check if text should be split into smaller chunks.
        
        Args:
            text: Text to check
            operation: Target operation
            
        Returns:
            True if text should be split
        """
        tokens = self.estimate_tokens(text)
        limit = self.limits.get(operation, self.limits['max_chunk'])
        
        if tokens > limit:
            logger.info(f"Chunk with {tokens} tokens exceeds {operation} limit of {limit}")
            return True
        return False
    
    def estimate_content_density(self, text: str) -> float:
        """
        Estimate content density based on text characteristics.
        
        Args:
            text: Text to analyze
            
        Returns:
            Density factor (0.5 = sparse, 1.0 = normal, 2.0+ = dense)
        """
        # Count indicators of dense technical content
        technique_count = text.count('T1')
        code_blocks = text.count('```')
        tables = text.count('|')
        
        # Long words indicate technical content
        words = text.split()
        long_words = sum(1 for w in words if len(w) > 10)
        long_word_ratio = long_words / max(len(words), 1)
        
        # Calculate density score
        density = 1.0
        
        # Adjust for technique references (very dense)
        if technique_count > 10:
            density += 0.5
        elif technique_count > 5:
            density += 0.3
        
        # Adjust for code/tables
        if code_blocks > 2 or tables > 20:
            density += 0.3
        
        # Adjust for technical vocabulary
        if long_word_ratio > 0.2:
            density += 0.2
        
        return min(density, 2.5)  # Cap at 2.5x density