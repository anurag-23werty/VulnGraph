"""
Authentication and Role-Based Access Control (RBAC) for VulnGraph.
==================================================================
Enforces trust boundaries across three security roles:
  - Viewer: Read-only access to findings, baseline, and graph visualizations.
  - Analyst: Permitted to trigger triage, graph traversals, and LangGraph multi-agent loops.
  - Approver: Authorized to approve or reject staged decisions and dispatch tickets.
  - Admin: Superuser permissions across all operations.
"""

import os
from enum import Enum
from typing import Optional, Dict
from pydantic import BaseModel
from fastapi import Header, HTTPException, status, Depends
from dotenv import load_dotenv

load_dotenv()


class Role(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    APPROVER = "approver"
    ADMIN = "admin"


# Role hierarchy definitions
ROLE_HIERARCHY: Dict[Role, int] = {
    Role.VIEWER: 1,
    Role.ANALYST: 2,
    Role.APPROVER: 3,
    Role.ADMIN: 4,
}


class User(BaseModel):
    username: str
    role: Role


# Pre-configured tokens from environment variables
TOKENS_MAP: Dict[str, User] = {
    os.getenv("ANALYST_TOKEN", "analyst-token-secops"): User(username="analyst_secops", role=Role.ANALYST),
    os.getenv("APPROVER_TOKEN", "approver-token-lead"): User(username="lead_approver", role=Role.APPROVER),
    os.getenv("ADMIN_TOKEN", "admin-token-super"): User(username="admin_security", role=Role.ADMIN),
    os.getenv("VIEWER_TOKEN", "viewer-token-guest"): User(username="guest_viewer", role=Role.VIEWER),
}

# Environment mode
APP_ENV = os.getenv("APP_ENV", "development").lower()


def get_current_user(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
    x_demo_role: Optional[str] = Header(None)
) -> User:
    """
    Extracts and authenticates user identity from Authorization header or X-API-Key.
    In development mode, falls back to demo user with approver privileges for seamless local UI.
    """
    token = None
    if authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
        else:
            token = authorization
    elif x_api_key:
        token = x_api_key

    if token and token in TOKENS_MAP:
        return TOKENS_MAP[token]

    # Support header-based demo role switching in development
    if APP_ENV == "development":
        if x_demo_role and x_demo_role.lower() in [r.value for r in Role]:
            return User(username=f"dev_{x_demo_role.lower()}", role=Role(x_demo_role.lower()))
        # Default development user has APPROVER role so UI works out of the box
        return User(username="local_developer", role=Role.APPROVER)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing or invalid authentication token. Provide Bearer token or X-API-Key."
    )


def require_role(min_role: Role):
    """
    Dependency factory checking that the authenticated user meets the minimum required role.
    """
    def _role_checker(user: User = Depends(get_current_user)) -> User:
        user_level = ROLE_HIERARCHY.get(user.role, 0)
        required_level = ROLE_HIERARCHY.get(min_role, 0)
        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Operation requires at least '{min_role.value}' role. Current role is '{user.role.value}'."
            )
        return user
    return _role_checker
