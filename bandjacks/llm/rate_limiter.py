"""Rate limiting for LLM API calls.

Module Status: DEPRECATED
This module is deprecated. Use bandjacks.services.api.middleware.rate_limit instead.
This module will be removed in a future version.
"""

import asyncio
import time
import os
from typing import Dict, Optional
from threading import Lock
import logging
import warnings

logger = logging.getLogger(__name__)

# Show deprecation warning when module is imported
warnings.warn(
    "bandjacks.llm.rate_limiter is deprecated. "
    "Use bandjacks.services.api.middleware.rate_limit instead.",
    DeprecationWarning,
    stacklevel=2
)


class RateLimiter:
    """Simple rate limiter for LLM API calls."""
    
    def __init__(self):
        """Initialize rate limiter with environment configuration."""
        # Rate limit: requests per minute
        self.rate_limit = int(os.getenv("LLM_RATE_LIMIT", "30"))  # 30 requests per minute
        self.window_size = 60  # 1 minute window
        
        # Track request times per model
        self.request_times: Dict[str, list] = {}
        self.lock = Lock()
        
        logger.info(f"Rate limiter initialized: {self.rate_limit} requests per minute")
    
    def _clean_old_requests(self, model: str, current_time: float):
        """Remove requests older than the window size."""
        if model not in self.request_times:
            self.request_times[model] = []
        
        # Remove requests older than window
        cutoff_time = current_time - self.window_size
        self.request_times[model] = [
            t for t in self.request_times[model] 
            if t > cutoff_time
        ]
    
    def should_wait(self, model: str) -> float:
        """Check if we need to wait before making a request.
        
        Args:
            model: The model identifier
            
        Returns:
            Seconds to wait (0 if no wait needed)
        """
        with self.lock:
            current_time = time.time()
            self._clean_old_requests(model, current_time)
            
            # Check if we've hit the rate limit
            if len(self.request_times[model]) >= self.rate_limit:
                # Calculate how long to wait
                oldest_request = self.request_times[model][0]
                wait_time = self.window_size - (current_time - oldest_request)
                if wait_time > 0:
                    logger.warning(f"Rate limit reached for {model}, waiting {wait_time:.2f}s")
                    return wait_time
            
            return 0
    
    def record_request(self, model: str):
        """Record that a request was made.
        
        Args:
            model: The model identifier
        """
        with self.lock:
            current_time = time.time()
            if model not in self.request_times:
                self.request_times[model] = []
            self.request_times[model].append(current_time)
            logger.debug(f"Request recorded for {model}, total in window: {len(self.request_times[model])}")
    
    def wait_if_needed(self, model: str):
        """Block if rate limit is reached.
        
        Args:
            model: The model identifier
        """
        wait_time = self.should_wait(model)
        if wait_time > 0:
            time.sleep(wait_time)
        self.record_request(model)


class CircuitBreaker:
    """Circuit breaker pattern for handling persistent failures."""
    
    def __init__(self):
        """Initialize circuit breaker."""
        self.failure_threshold = int(os.getenv("LLM_CIRCUIT_FAILURE_THRESHOLD", "5"))
        self.recovery_timeout = int(os.getenv("LLM_CIRCUIT_RECOVERY_TIMEOUT", "60"))  # seconds
        self.half_open_requests = int(os.getenv("LLM_CIRCUIT_HALF_OPEN_REQUESTS", "3"))
        
        # Track state per model
        self.states: Dict[str, str] = {}  # "closed", "open", "half_open"
        self.failure_counts: Dict[str, int] = {}
        self.last_failure_time: Dict[str, float] = {}
        self.half_open_successes: Dict[str, int] = {}
        self.lock = Lock()
        
        logger.info(f"Circuit breaker initialized: threshold={self.failure_threshold}, recovery={self.recovery_timeout}s")
    
    def is_open(self, model: str) -> bool:
        """Check if circuit is open (blocking requests).
        
        Args:
            model: The model identifier
            
        Returns:
            True if circuit is open and requests should be blocked
        """
        with self.lock:
            state = self.states.get(model, "closed")
            
            if state == "open":
                # Check if we should move to half-open
                last_failure = self.last_failure_time.get(model, 0)
                if time.time() - last_failure > self.recovery_timeout:
                    logger.info(f"Circuit breaker for {model} moving to half-open state")
                    self.states[model] = "half_open"
                    self.half_open_successes[model] = 0
                    return False
                return True
            
            return False
    
    def record_success(self, model: str):
        """Record a successful request.
        
        Args:
            model: The model identifier
        """
        with self.lock:
            state = self.states.get(model, "closed")
            
            if state == "half_open":
                self.half_open_successes[model] = self.half_open_successes.get(model, 0) + 1
                if self.half_open_successes[model] >= self.half_open_requests:
                    logger.info(f"Circuit breaker for {model} closing after successful recovery")
                    self.states[model] = "closed"
                    self.failure_counts[model] = 0
            elif state == "closed":
                # Reset failure count on success
                self.failure_counts[model] = 0
    
    def record_failure(self, model: str):
        """Record a failed request.
        
        Args:
            model: The model identifier
        """
        with self.lock:
            state = self.states.get(model, "closed")
            self.failure_counts[model] = self.failure_counts.get(model, 0) + 1
            self.last_failure_time[model] = time.time()
            
            if state == "half_open":
                # Immediately open on failure in half-open state
                logger.warning(f"Circuit breaker for {model} opening due to failure in half-open state")
                self.states[model] = "open"
            elif state == "closed" and self.failure_counts[model] >= self.failure_threshold:
                # Open circuit after threshold reached
                logger.warning(f"Circuit breaker for {model} opening after {self.failure_counts[model]} failures")
                self.states[model] = "open"


# Global instances
_rate_limiter: Optional[RateLimiter] = None
_circuit_breaker: Optional[CircuitBreaker] = None


def get_rate_limiter() -> RateLimiter:
    """Get global rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


def get_circuit_breaker() -> CircuitBreaker:
    """Get global circuit breaker instance."""
    global _circuit_breaker
    if _circuit_breaker is None:
        _circuit_breaker = CircuitBreaker()
    return _circuit_breaker