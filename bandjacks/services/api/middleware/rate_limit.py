"""Rate limiting middleware using sliding window algorithm."""

import logging
import os
import time
from typing import Dict, Optional, Tuple
from collections import defaultdict, deque
from datetime import datetime, timedelta
import hashlib
from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import threading

logger = logging.getLogger(__name__)

# Configuration
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
DEFAULT_RATE_LIMIT = int(os.getenv("DEFAULT_RATE_LIMIT", "100"))  # requests per minute
DEFAULT_WINDOW_SIZE = int(os.getenv("RATE_LIMIT_WINDOW", "60"))  # seconds
BURST_ALLOWANCE = float(os.getenv("BURST_ALLOWANCE", "1.5"))  # 1.5x burst allowed

# Endpoint-specific limits
ENDPOINT_LIMITS = {
    "/v1/stix/bundles": 10,  # Heavy operation
    "/v1/extract": 20,  # LLM-intensive
    "/v1/search": 50,  # Moderate
    "/v1/analytics": 30,  # Computation-heavy
    "/v1/flows/build": 15,  # Complex operation
}


class RateLimiter:
    """Sliding window rate limiter implementation."""
    
    def __init__(self, default_limit: int = DEFAULT_RATE_LIMIT, window_size: int = DEFAULT_WINDOW_SIZE):
        """
        Initialize rate limiter.
        
        Args:
            default_limit: Default requests per window
            window_size: Window size in seconds
        """
        self.default_limit = default_limit
        self.window_size = window_size
        self.requests: Dict[str, deque] = defaultdict(deque)
        self.lock = threading.RLock()
        
        # Start cleanup thread
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
    
    def is_allowed(self, key: str, limit: Optional[int] = None) -> Tuple[bool, Dict[str, int]]:
        """
        Check if request is allowed under rate limit.
        
        Args:
            key: Client identifier (IP, user ID, etc.)
            limit: Override limit for this check
            
        Returns:
            Tuple of (allowed, headers_dict)
        """
        with self.lock:
            current_time = time.time()
            request_limit = limit or self.default_limit
            burst_limit = int(request_limit * BURST_ALLOWANCE)
            
            # Get request history for this key
            request_times = self.requests[key]
            
            # Remove old requests outside window
            cutoff_time = current_time - self.window_size
            while request_times and request_times[0] < cutoff_time:
                request_times.popleft()
            
            # Check if under limit
            current_count = len(request_times)
            
            # Calculate remaining requests
            remaining = request_limit - current_count
            
            # Reset time (when oldest request expires)
            reset_time = int(request_times[0] + self.window_size) if request_times else int(current_time + self.window_size)
            
            # Prepare headers
            headers = {
                "X-RateLimit-Limit": str(request_limit),
                "X-RateLimit-Remaining": str(max(0, remaining)),
                "X-RateLimit-Reset": str(reset_time),
                "X-RateLimit-Burst": str(burst_limit)
            }
            
            # Allow if under limit or burst allowance
            if current_count < request_limit:
                request_times.append(current_time)
                return True, headers
            elif current_count < burst_limit:
                # Allow burst but warn
                request_times.append(current_time)
                headers["X-RateLimit-Burst-Used"] = "true"
                return True, headers
            else:
                # Rate limit exceeded
                retry_after = int(request_times[0] + self.window_size - current_time)
                headers["Retry-After"] = str(retry_after)
                return False, headers
    
    def _cleanup_loop(self):
        """Periodic cleanup of old request data."""
        while True:
            time.sleep(300)  # Clean every 5 minutes
            self._cleanup_old_entries()
    
    def _cleanup_old_entries(self):
        """Remove old entries from memory."""
        with self.lock:
            current_time = time.time()
            cutoff_time = current_time - (self.window_size * 2)
            
            keys_to_remove = []
            for key, request_times in self.requests.items():
                # Remove old timestamps
                while request_times and request_times[0] < cutoff_time:
                    request_times.popleft()
                
                # Remove empty entries
                if not request_times:
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                del self.requests[key]
            
            if keys_to_remove:
                logger.debug(f"Cleaned up {len(keys_to_remove)} rate limit entries")


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware for FastAPI."""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.limiter = RateLimiter()
    
    async def dispatch(self, request: Request, call_next):
        """Process request with rate limiting."""
        
        # Skip if disabled
        if not RATE_LIMIT_ENABLED:
            response = await call_next(request)
            return response
        
        # Skip for health checks and docs
        if request.url.path in ["/health", "/docs", "/redoc", "/openapi.json"]:
            response = await call_next(request)
            return response
        
        # Get client identifier
        client_key = self._get_client_key(request)
        
        # Get limit for this endpoint
        limit = self._get_endpoint_limit(request.url.path)
        
        # Check rate limit
        allowed, headers = self.limiter.is_allowed(client_key, limit)
        
        if not allowed:
            # Rate limit exceeded
            retry_after = headers.get("Retry-After", "60")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Retry after {retry_after} seconds",
                headers=headers
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers to response
        for header, value in headers.items():
            response.headers[header] = value
        
        return response
    
    def _get_client_key(self, request: Request) -> str:
        """Get client identifier for rate limiting."""
        
        # Priority: authenticated user > API key > IP address
        
        # Check for authenticated user
        if hasattr(request.state, "user") and request.state.user:
            user_id = request.state.user.get("sub", "")
            if user_id:
                return f"user:{user_id}"
        
        # Check for API key
        api_key = request.headers.get("X-API-Key")
        if api_key:
            # Hash API key for privacy
            key_hash = hashlib.md5(api_key.encode()).hexdigest()[:16]
            return f"api:{key_hash}"
        
        # Fall back to IP address
        client_ip = request.client.host if request.client else "unknown"
        
        # Check for X-Forwarded-For (proxy/load balancer)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
        
        return f"ip:{client_ip}"
    
    def _get_endpoint_limit(self, path: str) -> int:
        """Get rate limit for specific endpoint."""
        
        # Check exact match first
        if path in ENDPOINT_LIMITS:
            return ENDPOINT_LIMITS[path]
        
        # Check prefix match
        for endpoint, limit in ENDPOINT_LIMITS.items():
            if path.startswith(endpoint):
                return limit
        
        # Default limit
        return DEFAULT_RATE_LIMIT


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get or create rate limiter singleton."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


def check_rate_limit(key: str, limit: Optional[int] = None) -> bool:
    """
    Check if request is allowed under rate limit.
    
    Args:
        key: Client identifier
        limit: Optional override limit
        
    Returns:
        True if allowed, False otherwise
    """
    if not RATE_LIMIT_ENABLED:
        return True
    
    limiter = get_rate_limiter()
    allowed, _ = limiter.is_allowed(key, limit)
    return allowed