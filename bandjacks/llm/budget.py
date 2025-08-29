"""Budget tracking and enforcement for LLM judge calls."""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict
import threading
import json

logger = logging.getLogger(__name__)


# Cost models for different LLMs (per 1K tokens)
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
                "total_tokens": usage.total_tokens_in + usage.total_tokens_out,
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