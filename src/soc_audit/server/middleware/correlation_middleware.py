"""Correlation ID middleware for request tracking.

Phase 10.4: Adds correlation IDs to all requests for traceability.
"""
from __future__ import annotations

import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from soc_audit.server.logging_config import set_correlation_id, get_correlation_id


class CorrelationIDMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add correlation IDs to all requests.
    
    Phase 10.4: Each request gets a unique correlation ID for traceability.
    """
    
    async def dispatch(self, request: Request, call_next: callable) -> Response:
        """Add correlation ID to request and response."""
        # Try to get correlation ID from header, or generate new one
        corr_id = request.headers.get("X-Correlation-ID")
        if not corr_id:
            corr_id = str(uuid.uuid4())[:8]
        
        # Set in context for logging
        set_correlation_id(corr_id)
        
        # Process request
        response = await call_next(request)
        
        # Add correlation ID to response headers
        response.headers["X-Correlation-ID"] = corr_id
        
        return response
