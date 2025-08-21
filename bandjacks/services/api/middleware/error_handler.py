"""Global error handling middleware for consistent API responses."""

import logging
import traceback
from typing import Callable
from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from pydantic import ValidationError

from ..schemas import ErrorResponse
from .tracing import get_trace_id

logger = logging.getLogger(__name__)


class ErrorHandlerMiddleware(BaseHTTPMiddleware):
    """Middleware for consistent error handling and response formatting."""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Handle errors and format consistent error responses."""
        try:
            response = await call_next(request)
            return response
            
        except HTTPException as e:
            # Handle FastAPI HTTP exceptions
            trace_id = get_trace_id()
            
            error_response = ErrorResponse(
                error=e.__class__.__name__,
                message=e.detail if isinstance(e.detail, str) else str(e.detail),
                detail={"status_code": e.status_code} if not isinstance(e.detail, dict) else e.detail,
                trace_id=trace_id
            )
            
            logger.warning(
                f"HTTP error: {e.status_code} - {e.detail}",
                extra={
                    "trace_id": trace_id,
                    "status_code": e.status_code,
                    "path": request.url.path
                }
            )
            
            return JSONResponse(
                status_code=e.status_code,
                content=error_response.dict(),
                headers={"X-Trace-ID": trace_id}
            )
            
        except ValidationError as e:
            # Handle Pydantic validation errors
            trace_id = get_trace_id()
            
            error_response = ErrorResponse(
                error="ValidationError",
                message="Request validation failed",
                detail={"validation_errors": e.errors()},
                trace_id=trace_id
            )
            
            logger.warning(
                f"Validation error: {str(e)}",
                extra={
                    "trace_id": trace_id,
                    "path": request.url.path,
                    "errors": e.errors()
                }
            )
            
            return JSONResponse(
                status_code=422,
                content=error_response.dict(),
                headers={"X-Trace-ID": trace_id}
            )
            
        except Exception as e:
            # Handle unexpected errors
            trace_id = get_trace_id()
            
            # Log full traceback for debugging
            logger.error(
                f"Unhandled error: {str(e)}",
                extra={
                    "trace_id": trace_id,
                    "path": request.url.path,
                    "method": request.method,
                    "traceback": traceback.format_exc()
                },
                exc_info=True
            )
            
            # Don't expose internal errors to clients
            error_response = ErrorResponse(
                error="InternalServerError",
                message="An internal error occurred",
                detail={"type": e.__class__.__name__} if logger.isEnabledFor(logging.DEBUG) else None,
                trace_id=trace_id
            )
            
            return JSONResponse(
                status_code=500,
                content=error_response.dict(),
                headers={"X-Trace-ID": trace_id}
            )


def create_error_response(
    error_type: str,
    message: str,
    status_code: int = 400,
    detail: dict = None
) -> JSONResponse:
    """Helper to create consistent error responses."""
    trace_id = get_trace_id()
    
    error_response = ErrorResponse(
        error=error_type,
        message=message,
        detail=detail,
        trace_id=trace_id
    )
    
    return JSONResponse(
        status_code=status_code,
        content=error_response.dict(),
        headers={"X-Trace-ID": trace_id}
    )