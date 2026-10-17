"""
In-Memory Rate Limiting for Expensive Agent Operations.
======================================================
Protects LLM inference budgets and FalkorDB from request flooding.
Implements a thread-safe sliding window rate limiter per client IP / API token.
"""

import time
import threading
from typing import Dict, List
from fastapi import Request, HTTPException, status


class SlidingWindowRateLimiter:
    """Thread-safe sliding window in-memory rate limiter."""

    def __init__(self, max_requests: int = 15, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.lock = threading.Lock()
        self.requests_history: Dict[str, List[float]] = {}

    def is_allowed(self, client_key: str) -> bool:
        now = time.time()
        window_start = now - self.window_seconds

        with self.lock:
            history = self.requests_history.get(client_key, [])
            # Purge timestamps outside the current sliding window
            history = [t for t in history if t > window_start]

            if len(history) >= self.max_requests:
                self.requests_history[client_key] = history
                return False

            history.append(now)
            self.requests_history[client_key] = history
            return True


# Global rate limiter instance: 20 requests per minute per client for triage endpoints
triage_rate_limiter = SlidingWindowRateLimiter(max_requests=20, window_seconds=60)


def rate_limit_triage(request: Request):
    """
    FastAPI dependency enforcing rate limits on expensive LLM / graph triage endpoints.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    auth_header = request.headers.get("authorization", "")
    client_key = f"{client_ip}:{auth_header}"

    if not triage_rate_limiter.is_allowed(client_key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded: Maximum 20 agent triage runs per minute. Please retry shortly.",
            headers={"Retry-After": "60"}
        )
