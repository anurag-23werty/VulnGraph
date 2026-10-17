"""
Tests for Safe Property (auth.py, rate_limiter.py, logger.py, and trust boundaries).
"""

from fastapi.testclient import TestClient
from main import app
from auth import Role, User, require_role
from rate_limiter import SlidingWindowRateLimiter

client = TestClient(app)


def test_auth_roles_hierarchy():
    """Verify role permissions and RBAC checks."""
    analyst_checker = require_role(Role.ANALYST)
    approver_checker = require_role(Role.APPROVER)

    viewer = User(username="v", role=Role.VIEWER)
    analyst = User(username="a", role=Role.ANALYST)
    approver = User(username="p", role=Role.APPROVER)

    # Analyst can pass analyst check
    assert analyst_checker(analyst) == analyst
    # Approver can pass analyst check
    assert analyst_checker(approver) == approver

    # Viewer fails analyst check
    import pytest
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        analyst_checker(viewer)
    assert exc_info.value.status_code == 403

    # Analyst fails approver check
    with pytest.raises(HTTPException) as exc_info:
        approver_checker(analyst)
    assert exc_info.value.status_code == 403


def test_rate_limiter_sliding_window():
    """Verify rate limiter blocks after exceeding window threshold."""
    limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=10)
    client_key = "192.168.1.1:test"

    assert limiter.is_allowed(client_key) is True
    assert limiter.is_allowed(client_key) is True
    assert limiter.is_allowed(client_key) is True
    # 4th request must be blocked
    assert limiter.is_allowed(client_key) is False


def test_request_id_correlation_header():
    """Verify every API response includes X-Request-ID header."""
    res = client.get("/health")
    assert res.status_code == 200
    assert "x-request-id" in res.headers
    assert res.headers["x-request-id"].startswith("req-")
