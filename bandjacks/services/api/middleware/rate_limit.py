"""Rate limiting middleware using Redis-backed sliding window algorithm."""

import logging
import os
import time
from typing import Dict, Optional, Tuple
import hashlib
from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)

# Configuration
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
DEFAULT_RATE_LIMIT = int(os.getenv("DEFAULT_RATE_LIMIT", "100"))  # requests per minute
DEFAULT_WINDOW_SIZE = int(os.getenv("RATE_LIMIT_WINDOW", "60"))  # seconds
BURST_ALLOWANCE = float(os.getenv("BURST_ALLOWANCE", "1.5"))  # 1.5x burst allowed

# Redis configuration
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

# Endpoint-specific limits
ENDPOINT_LIMITS = {
    "/v1/stix/bundles": 10,  # Heavy operation
    "/v1/extract": 20,  # LLM-intensive
    "/v1/search": 50,  # Moderate
    "/v1/analytics": 30,  # Computation-heavy
    "/v1/flows/build": 15,  # Complex operation
    "/v1/sequence/judge": 10,  # LLM judge calls - Epic 4 T26
    "/v1/sequence/infer": 5,  # PTG inference with judge - Epic 4 T26
    "/v1/reports/jobs": 300,  # Job status polling - high frequency allowed
    "/v1/reports/ingest": 30,  # Report ingestion - moderate
    "/v1/reports/ingest_async": 30,  # Async report ingestion
    "/v1/reports/ingest_file_async": 30,  # Async file ingestion
    "/v1/reports/": 200,  # Report retrieval and details - UI needs frequent access for navigation/display
}


def _get_redis_client():
    """Create a Redis client. Returns None if Redis is unavailable."""
    try:
        import redis
        client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, socket_timeout=1, socket_connect_timeout=1)
        client.ping()
        return client
    except Exception as e:
        logger.warning(f"Redis unavailable for rate limiting: {e}")
        return None


class RateLimiter:
    """Redis-backed sliding window rate limiter implementation."""

    def __init__(self, default_limit: int = DEFAULT_RATE_LIMIT, window_size: int = DEFAULT_WINDOW_SIZE):
        """
        Initialize rate limiter.

        Args:
            default_limit: Default requests per window
            window_size: Window size in seconds
        """
        self.default_limit = default_limit
        self.window_size = window_size
        self._redis = None
        self._redis_checked = False

    @property
    def redis(self):
        """Lazy-connect to Redis, caching the client."""
        if not self._redis_checked:
            self._redis = _get_redis_client()
            self._redis_checked = True
        return self._redis

    def _reset_redis(self):
        """Reset Redis connection so next access retries."""
        self._redis = None
        self._redis_checked = False

    def is_allowed(self, key: str, limit: Optional[int] = None) -> Tuple[bool, Dict[str, str]]:
        """
        Check if request is allowed under rate limit.

        Args:
            key: Client identifier (IP, user ID, etc.)
            limit: Override limit for this check

        Returns:
            Tuple of (allowed, headers_dict)
        """
        current_time = time.time()
        request_limit = limit or self.default_limit
        burst_limit = int(request_limit * BURST_ALLOWANCE)

        redis_client = self.redis
        if redis_client is None:
            # Redis unavailable - allow request gracefully
            return True, {
                "X-RateLimit-Limit": str(request_limit),
                "X-RateLimit-Remaining": str(request_limit),
                "X-RateLimit-Reset": str(int(current_time + self.window_size)),
                "X-RateLimit-Burst": str(burst_limit),
            }

        redis_key = f"ratelimit:{key}"
        cutoff_time = current_time - self.window_size

        try:
            pipe = redis_client.pipeline(transaction=True)
            # 1. Remove expired entries
            pipe.zremrangebyscore(redis_key, 0, cutoff_time)
            # 2. Count current window
            pipe.zcard(redis_key)
            # 3. Add this request (score and member both = current timestamp)
            pipe.zadd(redis_key, {str(current_time): current_time})
            # 4. Set TTL for auto-cleanup
            pipe.expire(redis_key, self.window_size)
            results = pipe.execute()

            current_count = results[1]  # ZCARD result (before adding this request)
        except Exception as e:
            logger.warning(f"Redis error during rate limit check: {e}")
            self._reset_redis()
            # Fall back to allowing the request
            return True, {
                "X-RateLimit-Limit": str(request_limit),
                "X-RateLimit-Remaining": str(request_limit),
                "X-RateLimit-Reset": str(int(current_time + self.window_size)),
                "X-RateLimit-Burst": str(burst_limit),
            }

        remaining = request_limit - current_count
        reset_time = int(current_time + self.window_size)

        headers = {
            "X-RateLimit-Limit": str(request_limit),
            "X-RateLimit-Remaining": str(max(0, remaining)),
            "X-RateLimit-Reset": str(reset_time),
            "X-RateLimit-Burst": str(burst_limit),
        }

        if current_count < request_limit:
            # Under normal limit - allowed
            return True, headers
        elif current_count < burst_limit:
            # In burst zone - allowed but flagged
            headers["X-RateLimit-Burst-Used"] = "true"
            return True, headers
        else:
            # Over burst limit - remove the entry we just added
            try:
                redis_client.zrem(redis_key, str(current_time))
            except Exception:
                pass  # Best effort removal
            retry_after = self.window_size
            headers["Retry-After"] = str(retry_after)
            return False, headers


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

        # Log the endpoint being accessed
        logger.debug(f"Rate limit check: path={request.url.path}, client={client_key}, limit={limit}/min")

        # Check rate limit
        allowed, headers = self.limiter.is_allowed(client_key, limit)

        if not allowed:
            # Rate limit exceeded
            retry_after = headers.get("Retry-After", "60")
            logger.warning(f"Rate limit exceeded for {request.url.path} by {client_key} (limit={limit}/min)")
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
