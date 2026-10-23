import json
import hashlib
import secrets
import datetime
from typing import Dict, Any, List, Optional, Tuple, cast
from sqlalchemy.orm import Session
from backend.models.db_models import ApprovalModel
from backend.app.config import settings


def canonicalize_payload(tool_name: str, args: Dict[str, Any]) -> str:
    """Produces deterministic canonical JSON string for payload hashing."""
    data = {
        "tool_name": tool_name,
        "arguments": args
    }
    return json.dumps(data, sort_keys=True, separators=(',', ':'))


def compute_payload_hash(canonical_json: str) -> str:
    """Computes SHA-256 hex digest of the canonical action payload."""
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class ApprovalManager:
    def create_approval_request(
        self,
        request_id: str,
        session_id: str,
        requester_id: str,
        requester_role: str,
        tool_name: str,
        arguments: Dict[str, Any],
        affected_data_classes: List[str],
        destination: Optional[str],
        risk_reason: str,
        policy_rule_id: str,
        db: Session
    ) -> ApprovalModel:
        approval_id = f"appr_{secrets.token_urlsafe(24)}"
        canonical = canonicalize_payload(tool_name, arguments)
        payload_hash = compute_payload_hash(canonical)

        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        expires = now + datetime.timedelta(seconds=settings.APPROVAL_TIMEOUT_SECONDS)

        approval = ApprovalModel(
            id=approval_id,
            request_id=request_id,
            session_id=session_id,
            requester_id=requester_id,
            requester_role=requester_role,
            tool_name=tool_name,
            arguments_canonical_json=canonical,
            payload_sha256=payload_hash,
            affected_data_classes=json.dumps(affected_data_classes),
            destination=destination,
            risk_reason=risk_reason,
            policy_rule_id=policy_rule_id,
            status="PENDING",
            created_at=now,
            expires_at=expires
        )
        db.add(approval)
        db.commit()
        db.refresh(approval)
        return approval

    def get_approval(self, approval_id: str, db: Session) -> Optional[ApprovalModel]:
        return db.query(ApprovalModel).filter(ApprovalModel.id == approval_id).first()

    def list_approvals(self, status: Optional[str], db: Session) -> List[ApprovalModel]:
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        expired_tickets = db.query(ApprovalModel).filter(
            ApprovalModel.status == "PENDING",
            ApprovalModel.expires_at < now
        ).all()
        if expired_tickets:
            for t in expired_tickets:
                t.status = "EXPIRED"
            db.commit()

        q = db.query(ApprovalModel)
        if status:
            q = q.filter(ApprovalModel.status == status)
        return q.order_by(ApprovalModel.created_at.desc()).all()

    def validate_and_approve(
        self,
        approval_id: str,
        actor_id: str,
        actor_role: str,
        db: Session
    ) -> Tuple[bool, str, Optional[ApprovalModel]]:
        approval = self.get_approval(approval_id, db)
        if not approval:
            return False, f"Approval request '{approval_id}' not found.", None

        # 1. State check: must be PENDING
        if approval.status != "PENDING":
            return False, f"Approval request is already '{approval.status}'. Cannot be approved.", None

        # Reset narrowed type: Pyright narrows approval.status to Literal["PENDING"] above;
        # cast restores it to ApprovalModel so subsequent status mutations are valid.
        approval = cast(ApprovalModel, approval)

        # 2. Expiration check
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        if now > approval.expires_at:
            approval.status = "EXPIRED"
            db.commit()
            return False, "Approval request has expired.", None

        # 3. Role authorization check: only approver role
        if actor_role != "approver" and actor_role != "admin":
            return False, f"Principal role '{actor_role}' is not authorized to approve. Must be 'approver'.", None

        # 4. Self-approval prevention
        if actor_id == approval.requester_id:
            return False, "Self-approval forbidden: requesters cannot approve their own requests.", None

        approval.status = "APPROVED"
        approval.resolved_at = now
        approval.resolved_by = actor_id
        db.commit()
        db.refresh(approval)
        return True, "Approval granted successfully.", approval

    def reject_approval(
        self,
        approval_id: str,
        actor_id: str,
        actor_role: str,
        reason: Optional[str],
        db: Session
    ) -> Tuple[bool, str, Optional[ApprovalModel]]:
        approval = self.get_approval(approval_id, db)
        if not approval:
            return False, f"Approval request '{approval_id}' not found.", None

        if approval.status != "PENDING":
            return False, f"Approval request is already '{approval.status}'.", None

        # Reset narrowed type (same pattern as validate_and_approve).
        approval = cast(ApprovalModel, approval)

        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        approval.status = "REJECTED"
        approval.resolved_at = now
        approval.resolved_by = actor_id
        if reason:
            approval.risk_reason += f" | Rejected by {actor_id}: {reason}"
        db.commit()
        db.refresh(approval)
        return True, "Approval request rejected.", approval


approval_manager = ApprovalManager()
