import json
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_
from backend.app.database import get_db
from backend.models.db_models import AuditLogModel
from backend.models.schema import AuditLogListResponse, AuditLogItem, AuditVerifyResponse
from backend.security.audit import audit_logger

router = APIRouter(prefix="/api/audit", tags=["Audit Ledger"])


@router.get("", response_model=AuditLogListResponse)
def search_audit_logs(
    decision: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    tool: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    query = db.query(AuditLogModel)

    if decision:
        query = query.filter(AuditLogModel.decision == decision)
    if severity:
        query = query.filter(AuditLogModel.threat_classification == severity)
    if tool:
        query = query.filter(AuditLogModel.tool_name == tool)
    if q:
        search_filter = or_(
            AuditLogModel.explanation.ilike(f"%{q}%"),
            AuditLogModel.entry_id.ilike(f"%{q}%"),
            AuditLogModel.request_id.ilike(f"%{q}%"),
            AuditLogModel.policy_rule_id.ilike(f"%{q}%"),
            AuditLogModel.principal_id.ilike(f"%{q}%")
        )
        query = query.filter(search_filter)

    if start_date:
        try:
            sd = datetime.fromisoformat(start_date)
            query = query.filter(AuditLogModel.timestamp >= sd)
        except Exception:
            pass
    if end_date:
        try:
            ed = datetime.fromisoformat(end_date)
            query = query.filter(AuditLogModel.timestamp <= ed)
        except Exception:
            pass

    total = query.count()
    offset = (page - 1) * page_size
    records = query.order_by(AuditLogModel.id.desc()).offset(offset).limit(page_size).all()

    items = []
    for r in records:
        try:
            payload = json.loads(r.redacted_payload)
        except Exception:
            payload = {}

        items.append(AuditLogItem(
            id=r.id,
            entry_id=r.entry_id,
            timestamp=r.timestamp,
            request_id=r.request_id,
            session_id=r.session_id,
            principal_id=r.principal_id,
            principal_role=r.principal_role,
            category=r.category,
            threat_classification=r.threat_classification,
            risk_score=r.risk_score,
            tool_name=r.tool_name,
            policy_rule_id=r.policy_rule_id,
            decision=r.decision,
            explanation=r.explanation,
            redacted_payload=payload,
            prev_hash=r.prev_hash,
            current_hash=r.current_hash
        ))

    total_pages = (total + page_size - 1) // page_size if total > 0 else 1

    return AuditLogListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )


@router.get("/verify", response_model=AuditVerifyResponse)
def verify_hash_chain(db: Session = Depends(get_db)):
    is_valid, count, last_valid, broken_id, msg = audit_logger.verify_chain(db)
    return AuditVerifyResponse(
        verified=is_valid,
        total_records=count,
        last_verified_entry_id=last_valid,
        broken_entry_id=broken_id,
        message=msg
    )
