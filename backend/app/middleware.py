"""Security middleware: headers, rate limiting, CORS."""
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from collections import defaultdict
import time


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiter for scan endpoints."""

    def __init__(self, app, max_requests: int = 60, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window = window_seconds
        self.requests = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        # Only rate-limit mutating API calls
        if request.url.path.startswith("/api/scan") and request.method == "POST":
            client_ip = request.headers.get("X-Forwarded-For", "")
            if client_ip:
                client_ip = client_ip.split(",")[0].strip()
            else:
                client_ip = request.client.host if request.client else "unknown"

            now = time.time()
            # Clean old entries
            self.requests[client_ip] = [
                t for t in self.requests[client_ip] if now - t < self.window
            ]

            if len(self.requests[client_ip]) >= self.max_requests:
                return Response(
                    content='{"detail":"Rate limit exceeded. Please try again later."}',
                    status_code=429,
                    media_type="application/json",
                )

            self.requests[client_ip].append(now)

        response = await call_next(request)
        return response
