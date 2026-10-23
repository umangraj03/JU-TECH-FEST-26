import json
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.dependencies import get_current_principal, require_approver
from backend.models.schema import Principal, ApprovalItem, ApprovalActionRequest, ToolDecision
from backend.security.approvals import approval_manager, compute_payload_hash
from backend.security.gateway import gateway

router = APIRouter(prefix="/api/approvals", tags=["Approvals"])


@router.get("", response_model=List[ApprovalItem])
def list_approvals(
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    items = approval_manager.list_approvals(status, db)
    results = []
    for it in items:
        try:
            parsed_args = json.loads(it.arguments_canonical_json).get("arguments", {})
            classes = json.loads(it.affected_data_classes)
        except Exception:
            parsed_args = {}
            classes = []

        results.append(ApprovalItem(
            id=it.id,
            request_id=it.request_id,
            session_id=it.session_id,
            requester_id=it.requester_id,
            requester_role=it.requester_role,
            tool_name=it.tool_name,
            arguments=parsed_args,
            payload_sha256=it.payload_sha256,
            affected_data_classes=classes,
            destination=it.destination,
            risk_reason=it.risk_reason,
            policy_rule_id=it.policy_rule_id,
            status=it.status,
            created_at=it.created_at,
            expires_at=it.expires_at,
            resolved_at=it.resolved_at,
            resolved_by=it.resolved_by
        ))
    return results


@router.post("/{approval_id}/approve")
def approve_ticket(
    approval_id: str,
    action_req: Optional[ApprovalActionRequest] = None,
    approver: Principal = Depends(require_approver),
    db: Session = Depends(get_db)
):
    approval = approval_manager.get_approval(approval_id, db)
    if not approval:
        raise HTTPException(status_code=404, detail="Approval request not found.")

    # 1. Validate payload hash integrity (verify no tampering/swap)
    canonical = approval.arguments_canonical_json
    current_hash = compute_payload_hash(canonical)
    if current_hash != approval.payload_sha256:
        raise HTTPException(status_code=400, detail="Security violation: Action payload hash mismatch.")

    # 2. Validate state, expiration, self-approval, role
    ok, msg, approved_record = approval_manager.validate_and_approve(
        approval_id=approval_id,
        actor_id=approver.principal_id,
        actor_role=approver.role,
        db=db
    )
    if not ok:
        raise HTTPException(status_code=400, detail=msg)

    # 3. Hard Invariant: Fresh Gateway Re-evaluation
    # Freshly run allowlist, destination, taint, and DLP checks.
    # If any mandatory rule now fails, BLOCK despite approval!
    payload_data = json.loads(canonical)
    tool_name = payload_data["tool_name"]
    args = payload_data["arguments"]

    exec_decision: ToolDecision = gateway.evaluate_and_run(
        principal=approver,
        tool_name=tool_name,
        raw_args=args,
        is_tainted=False,
        request_id=approval.request_id,
        session_id=approval.session_id,
        db=db,
        bypass_approval_check=True  # Human approval received, re-checking mandatory rules
    )

    if exec_decision.decision == "BLOCK":
        return {
            "status": "BLOCKED_POST_APPROVAL",
            "message": f"Mandatory security rule violated during post-approval re-check: {exec_decision.explanation}",
            "decision": exec_decision.model_dump()
        }

    return {
        "status": "EXECUTED",
        "message": "Approval verified and action executed successfully.",
        "decision": exec_decision.model_dump()
    }


@router.post("/{approval_id}/reject")
def reject_ticket(
    approval_id: str,
    action_req: Optional[ApprovalActionRequest] = None,
    approver: Principal = Depends(require_approver),
    db: Session = Depends(get_db)
):
    reason = action_req.reason if action_req else None
    ok, msg, _ = approval_manager.reject_approval(
        approval_id=approval_id,
        actor_id=approver.principal_id,
        actor_role=approver.role,
        reason=reason,
        db=db
    )
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "REJECTED", "message": msg}
