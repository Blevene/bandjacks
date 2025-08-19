"""Request tracing middleware for API observability."""

import uuid
import time
import logging
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import contextvars

# Context variable for trace ID
trace_id_context = contextvars.ContextVar("trace_id", default=None)

logger = logging.getLogger(__name__)


class TracingMiddleware(BaseHTTPMiddleware):
    """Middleware to add trace IDs to all requests for observability."""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with trace ID."""
        # Generate or extract trace ID
        trace_id = request.headers.get("X-Trace-ID")
        if not trace_id:
            trace_id = f"trace-{uuid.uuid4().hex[:16]}"
        
        # Set trace ID in context
        trace_id_context.set(trace_id)
        
        # Add trace ID to request state for easy access
        request.state.trace_id = trace_id
        
        # Track request timing
        start_time = time.time()
        
        # Log request start
        logger.info(
            f"Request started",
            extra={
                "trace_id": trace_id,
                "method": request.method,
                "path": request.url.path,
                "client": request.client.host if request.client else None
            }
        )
        
        try:
            # Process request
            response = await call_next(request)
            
            # Add trace ID to response headers
            response.headers["X-Trace-ID"] = trace_id
            
            # Calculate duration
            duration = time.time() - start_time
            
            # Log request completion
            logger.info(
                f"Request completed",
                extra={
                    "trace_id": trace_id,
                    "status_code": response.status_code,
                    "duration_ms": round(duration * 1000, 2)
                }
            )
            
            return response
            
        except Exception as e:
            # Log error with trace ID
            duration = time.time() - start_time
            logger.error(
                f"Request failed: {str(e)}",
                extra={
                    "trace_id": trace_id,
                    "duration_ms": round(duration * 1000, 2),
                    "error": str(e)
                },
                exc_info=True
            )
            raise


def get_trace_id() -> str:
    """Get current trace ID from context."""
    trace_id = trace_id_context.get()
    if not trace_id:
        # Fallback if called outside request context
        trace_id = f"trace-{uuid.uuid4().hex[:16]}"
        trace_id_context.set(trace_id)
    return trace_id


def inject_trace_id(query: str, params: dict = None) -> dict:
    """Inject trace ID into Neo4j query parameters."""
    if params is None:
        params = {}
    params["_trace_id"] = get_trace_id()
    return params


class TracedLogger:
    """Logger wrapper that includes trace ID in all log messages."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def _log(self, level: int, msg: str, *args, **kwargs):
        """Internal log method with trace ID injection."""
        extra = kwargs.get("extra", {})
        extra["trace_id"] = get_trace_id()
        kwargs["extra"] = extra
        self.logger.log(level, msg, *args, **kwargs)
    
    def debug(self, msg: str, *args, **kwargs):
        self._log(logging.DEBUG, msg, *args, **kwargs)
    
    def info(self, msg: str, *args, **kwargs):
        self._log(logging.INFO, msg, *args, **kwargs)
    
    def warning(self, msg: str, *args, **kwargs):
        self._log(logging.WARNING, msg, *args, **kwargs)
    
    def error(self, msg: str, *args, **kwargs):
        self._log(logging.ERROR, msg, *args, **kwargs)
    
    def critical(self, msg: str, *args, **kwargs):
        self._log(logging.CRITICAL, msg, *args, **kwargs)


def setup_tracing_logger(name: str) -> TracedLogger:
    """Create a logger that automatically includes trace IDs."""
    base_logger = logging.getLogger(name)
    return TracedLogger(base_logger)