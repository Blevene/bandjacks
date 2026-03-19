"""Token estimation and budget tracking utilities for dynamic chunk sizing and LLM cost management."""

import tiktoken
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict
import threading
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


# Fallback cost models for pre-call budget estimation only.
# Primary cost calculation uses litellm.completion_cost() with up-to-date provider pricing.
LLM_COSTS = {
    "gpt-4": {"input": 0.03, "output": 0.06},
    "gpt-4o": {"input": 0.005, "output": 0.015},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "gpt-5": {"input": 0.01, "output": 0.03},  # Estimated
    "gemini/gemini-2.5-flash": {"input": 0.0001, "output": 0.0003},
    "gemini/gemini-2.5-pro": {"input": 0.00125, "output": 0.005},
    "gemini/gemini-pro": {"input": 0.00025, "output": 0.001},
    "claude-3-opus": {"input": 0.015, "output": 0.075},
    "claude-3-sonnet": {"input": 0.003, "output": 0.015},
    "default": {"input": 0.001, "output": 0.002}
}


@dataclass
class BudgetConfig:
    """Configuration for budget enforcement."""
    daily_limit_usd: float = 10.0
    job_limit_usd: float = 5.0
    judge_batch_limit: int = 100  # Max judge calls per batch
    enforce_limits: bool = False  # Monitoring only for now
    warning_threshold: float = 0.8  # Warn at 80% of budget


@dataclass
class BudgetUsage:
    """Track budget usage over time."""
    total_cost_usd: float = 0.0
    total_calls: int = 0
    total_tokens_in: int = 0
    total_tokens_out: int = 0
    calls_by_model: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    cost_by_model: Dict[str, float] = field(default_factory=lambda: defaultdict(float))
    last_reset: datetime = field(default_factory=datetime.utcnow)


class BudgetTracker:
    """Track and enforce LLM usage budgets."""

    def __init__(self, config: Optional[BudgetConfig] = None):
        """
        Initialize budget tracker.

        Args:
            config: Budget configuration
        """
        self.config = config or BudgetConfig()
        self.daily_usage = BudgetUsage()
        self.job_usage = defaultdict(BudgetUsage)
        self.lock = threading.RLock()

        # Start daily reset thread
        self._reset_thread = threading.Thread(target=self._daily_reset_loop, daemon=True)
        self._reset_thread.start()

        logger.info(f"Budget tracker initialized with daily limit: ${self.config.daily_limit_usd}")

    def estimate_cost(
        self,
        model: str,
        tokens_in: int,
        tokens_out: int
    ) -> float:
        """
        Estimate cost for LLM call.

        Args:
            model: Model name
            tokens_in: Input tokens
            tokens_out: Output tokens

        Returns:
            Estimated cost in USD
        """
        costs = LLM_COSTS.get(model, LLM_COSTS["default"])

        input_cost = (tokens_in / 1000.0) * costs["input"]
        output_cost = (tokens_out / 1000.0) * costs["output"]

        return input_cost + output_cost

    def check_budget(
        self,
        estimated_cost: float,
        job_id: Optional[str] = None
    ) -> tuple[bool, str]:
        """
        Check if budget allows for operation.

        Args:
            estimated_cost: Estimated cost for operation
            job_id: Optional job ID for job-level tracking

        Returns:
            Tuple of (allowed, reason_if_rejected)
        """
        if not self.config.enforce_limits:
            return True, ""

        with self.lock:
            # Check daily limit
            if self.daily_usage.total_cost_usd + estimated_cost > self.config.daily_limit_usd:
                return False, f"Daily budget exceeded: ${self.daily_usage.total_cost_usd:.2f} + ${estimated_cost:.2f} > ${self.config.daily_limit_usd}"

            # Check job limit if job_id provided
            if job_id and self.config.job_limit_usd > 0:
                job_usage = self.job_usage[job_id]
                if job_usage.total_cost_usd + estimated_cost > self.config.job_limit_usd:
                    return False, f"Job budget exceeded for {job_id}: ${job_usage.total_cost_usd:.2f} + ${estimated_cost:.2f} > ${self.config.job_limit_usd}"

            # Check warning threshold
            daily_percent = (self.daily_usage.total_cost_usd + estimated_cost) / self.config.daily_limit_usd
            if daily_percent >= self.config.warning_threshold:
                logger.warning(f"Budget warning: {daily_percent:.1%} of daily limit used")

            return True, ""

    def record_usage(
        self,
        model: str,
        tokens_in: int,
        tokens_out: int,
        actual_cost: Optional[float] = None,
        job_id: Optional[str] = None
    ) -> float:
        """
        Record LLM usage.

        Args:
            model: Model used
            tokens_in: Input tokens consumed
            tokens_out: Output tokens generated
            actual_cost: Actual cost if known
            job_id: Optional job ID

        Returns:
            Cost recorded
        """
        cost = actual_cost or self.estimate_cost(model, tokens_in, tokens_out)

        with self.lock:
            # Update daily usage
            self.daily_usage.total_cost_usd += cost
            self.daily_usage.total_calls += 1
            self.daily_usage.total_tokens_in += tokens_in
            self.daily_usage.total_tokens_out += tokens_out
            self.daily_usage.calls_by_model[model] += 1
            self.daily_usage.cost_by_model[model] += cost

            # Update job usage if applicable
            if job_id:
                job_usage = self.job_usage[job_id]
                job_usage.total_cost_usd += cost
                job_usage.total_calls += 1
                job_usage.total_tokens_in += tokens_in
                job_usage.total_tokens_out += tokens_out
                job_usage.calls_by_model[model] += 1
                job_usage.cost_by_model[model] += cost

        return cost

    def check_batch_limit(self, batch_size: int) -> bool:
        """
        Check if batch size is within limits.

        Args:
            batch_size: Number of judge calls in batch

        Returns:
            True if within limits
        """
        return batch_size <= self.config.judge_batch_limit

    def get_usage_stats(self, job_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get current usage statistics.

        Args:
            job_id: Optional job ID for job-specific stats

        Returns:
            Usage statistics
        """
        with self.lock:
            if job_id and job_id in self.job_usage:
                usage = self.job_usage[job_id]
                scope = "job"
                limit = self.config.job_limit_usd
            else:
                usage = self.daily_usage
                scope = "daily"
                limit = self.config.daily_limit_usd

            return {
                "scope": scope,
                "total_cost_usd": round(usage.total_cost_usd, 4),
                "limit_usd": limit,
                "usage_percent": round((usage.total_cost_usd / limit) * 100, 1) if limit > 0 else 0,
                "total_calls": usage.total_calls,
                "total_tokens_in": usage.total_tokens_in,
                "total_tokens_out": usage.total_tokens_out,
                "avg_cost_per_call": round(usage.total_cost_usd / max(1, usage.total_calls), 4),
                "calls_by_model": dict(usage.calls_by_model),
                "cost_by_model": {k: round(v, 4) for k, v in usage.cost_by_model.items()},
                "last_reset": usage.last_reset.isoformat()
            }

    def get_cost_per_100_pairs(self) -> float:
        """
        Calculate average cost per 100 judge pairs.

        Returns:
            Average cost in USD
        """
        with self.lock:
            if self.daily_usage.total_calls == 0:
                return 0.0

            avg_cost_per_call = self.daily_usage.total_cost_usd / self.daily_usage.total_calls
            return round(avg_cost_per_call * 100, 2)

    def reset_job(self, job_id: str):
        """Reset usage for a specific job."""
        with self.lock:
            if job_id in self.job_usage:
                del self.job_usage[job_id]

    def _daily_reset_loop(self):
        """Background thread to reset daily usage."""
        import time
        while True:
            # Sleep until next midnight
            now = datetime.utcnow()
            next_reset = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
            sleep_seconds = (next_reset - now).total_seconds()

            time.sleep(sleep_seconds)

            # Reset daily usage
            with self.lock:
                logger.info(f"Daily budget reset. Previous usage: ${self.daily_usage.total_cost_usd:.2f}")
                self.daily_usage = BudgetUsage()
                # Clean up old job usage
                cutoff = datetime.utcnow() - timedelta(days=1)
                old_jobs = [jid for jid, usage in self.job_usage.items()
                           if usage.last_reset < cutoff]
                for jid in old_jobs:
                    del self.job_usage[jid]


# Global budget tracker instance
_budget_tracker = None


def get_budget_tracker(config: Optional[BudgetConfig] = None) -> BudgetTracker:
    """Get or create global budget tracker instance."""
    global _budget_tracker
    if _budget_tracker is None:
        _budget_tracker = BudgetTracker(config)
    return _budget_tracker


def check_and_record_judge_cost(
    model: str,
    tokens_in: int,
    tokens_out: int,
    job_id: Optional[str] = None
) -> tuple[bool, float, str]:
    """
    Check budget and record judge call cost.

    Args:
        model: Model name
        tokens_in: Input tokens
        tokens_out: Output tokens
        job_id: Optional job ID

    Returns:
        Tuple of (allowed, cost, rejection_reason)
    """
    tracker = get_budget_tracker()

    # Estimate cost
    estimated_cost = tracker.estimate_cost(model, tokens_in, tokens_out)

    # Check budget
    allowed, reason = tracker.check_budget(estimated_cost, job_id)

    if allowed:
        # Record usage
        actual_cost = tracker.record_usage(model, tokens_in, tokens_out, estimated_cost, job_id)
        return True, actual_cost, ""
    else:
        return False, estimated_cost, reason