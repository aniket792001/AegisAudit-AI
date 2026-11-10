"""
Authentication and Authorization Dependencies for FastAPI.
Provides JWT Bearer token validation and Role-Based Access Control (RBAC).
"""

from typing import List, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from models.user_schema import UserRole, UserResponse
from core.security import TokenManager
from db.user_store import UserDatabase

security_scheme = HTTPBearer(auto_error=False)
user_db = UserDatabase()

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme)
) -> UserResponse:
    """
    Extracts Bearer token, decodes JWT, and returns the authenticated user.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided. Include 'Authorization: Bearer <token>' header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    payload = TokenManager.decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub") or payload.get("id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload missing subject identifier.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = user_db.get_user_by_id(user_id)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found or has been deactivated.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user

def get_optional_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme)
) -> Optional[UserResponse]:
    """
    Extracts Bearer token if present, returns None if omitted or invalid.
    Enables zero-friction read-only exploration while write endpoints remain secured.
    """
    if not credentials or not credentials.credentials:
        return None
    try:
        payload = TokenManager.decode_access_token(credentials.credentials)
        if not payload:
            return None
        user_id = payload.get("sub") or payload.get("id")
        if not user_id:
            return None
        return user_db.get_user_by_id(user_id)
    except Exception:
        return None

def require_roles(allowed_roles: List[UserRole]):
    """
    Dependency generator to restrict endpoints to specific user roles.
    """
    def role_checker(current_user: UserResponse = Depends(get_current_user)) -> UserResponse:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: requires one of roles {[r.value for r in allowed_roles]}, but user has role '{current_user.role.value}'."
            )
        return current_user
    return role_checker
