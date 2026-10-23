from typing import Optional
from fastapi import Header, HTTPException, status, Depends
from sqlalchemy.orm import Session
from backend.app.config import settings, PRINCIPAL_MAP
from backend.models.schema import Principal
from backend.app.database import get_db


def get_current_principal(
    authorization: Optional[str] = Header(None),
    x_demo_role: Optional[str] = Header(None)
) -> Principal:
    """
    Resolves principal from Bearer token.
    In DEMO_MODE, allows X-Demo-Role header if token is not provided.
    """
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ", 1)[1].strip()

    if token and token in PRINCIPAL_MAP:
        p_info = PRINCIPAL_MAP[token]
        return Principal(
            principal_id=p_info["principal_id"],
            role=p_info["role"],
            name=p_info["name"]
        )

    # Demo fallback if DEMO_MODE is true
    if settings.DEMO_MODE:
        role = (x_demo_role or "requester").lower()
        if role == "approver":
            return Principal(principal_id="user_approver", role="approver", name="Security Approver")
        elif role == "admin":
            return Principal(principal_id="user_admin", role="admin", name="System Administrator")
        else:
            return Principal(principal_id="user_requester", role="requester", name="Requester User")

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing or invalid Bearer token."
    )


def require_admin(principal: Principal = Depends(get_current_principal)) -> Principal:
    if principal.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required."
        )
    return principal


def require_approver(principal: Principal = Depends(get_current_principal)) -> Principal:
    if principal.role not in ["approver", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Approver privileges required."
        )
    return principal
