from fastapi import APIRouter, Depends, HTTPException, Body
from backend.app.dependencies import require_admin
from backend.security.policy_engine import policy_engine
from backend.models.schema import Principal
from backend.models.policy import PolicySchema

router = APIRouter(prefix="/api/policy", tags=["Policy Engine"])


@router.get("")
def get_current_policy():
    return {
        "version": policy_engine.policy.version,
        "metadata": policy_engine.policy.metadata,
        "parsed": policy_engine.policy.model_dump(),
        "raw_yaml": policy_engine.get_raw_yaml()
    }


@router.put("")
def update_policy(
    yaml_content: str = Body(..., media_type="text/plain"),
    admin: Principal = Depends(require_admin)
):
    try:
        updated = policy_engine.update_policy_yaml(yaml_content)
        return {
            "status": "SUCCESS",
            "message": "Policy updated successfully.",
            "version": updated.version
        }
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Policy validation failed: {str(e)}"
        )
