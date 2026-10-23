import json
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.app.database import get_db
from backend.models.db_models import AuditLogModel, ApprovalModel
from backend.models.schema import OverviewStats, ThreatStats, ThreatItem, AuditLogItem
from backend.security.audit import audit_logger

router = APIRouter(prefix="/api", tags=["Stats & Monitoring"])


@router.get("/stats/overview", response_model=OverviewStats)
def get_overview_stats(db: Session = Depends(get_db)):
    total_logs = db.query(AuditLogModel).count()
    allowed = db.query(AuditLogModel).filter(AuditLogModel.decision == "ALLOW").count()
    blocked = db.query(AuditLogModel).filter(AuditLogModel.decision == "BLOCK").count()
    approvals = db.query(AuditLogModel).filter(AuditLogModel.decision == "REQUIRE_APPROVAL").count()

    avg_score_row = db.query(func.avg(AuditLogModel.risk_score)).first()
    avg_score = float(avg_score_row[0]) if avg_score_row and avg_score_row[0] is not None else 0.0

    critical_count = db.query(AuditLogModel).filter(AuditLogModel.threat_classification == "CRITICAL").count()
    active_approvals = db.query(ApprovalModel).filter(ApprovalModel.status == "PENDING").count()

    is_valid, _, _, _, _ = audit_logger.verify_chain(db)

    # Risk distribution
    risk_dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for row in db.query(AuditLogModel.threat_classification, func.count(AuditLogModel.id)).group_by(AuditLogModel.threat_classification).all():
        if row[0] in risk_dist:
            risk_dist[row[0]] = row[1]

    # Tool usage
    tool_usage: Dict[str, int] = {}
    for row in db.query(AuditLogModel.tool_name, func.count(AuditLogModel.id)).filter(AuditLogModel.tool_name.isnot(None)).group_by(AuditLogModel.tool_name).all():
        if row[0]:
            tool_usage[row[0]] = row[1]

    # Recent activity
    recent = []
    for r in db.query(AuditLogModel).order_by(AuditLogModel.timestamp.desc()).limit(8).all():
        recent.append({
            "id": r.id,
            "entry_id": r.entry_id,
            "timestamp": r.timestamp.isoformat(),
            "tool": r.tool_name or "inspection",
            "decision": r.decision,
            "threat": r.threat_classification,
            "score": r.risk_score,
            "explanation": r.explanation[:90] + "..." if len(r.explanation) > 90 else r.explanation
        })

    return OverviewStats(
        total_requests=total_logs,
        allowed_count=allowed,
        blocked_count=blocked,
        approval_count=approvals,
        avg_risk_score=round(avg_score, 1),
        critical_threats_count=critical_count,
        active_pending_approvals=active_approvals,
        audit_chain_valid=is_valid,
        recent_activity=recent,
        risk_distribution=risk_dist,
        tool_usage=tool_usage
    )


@router.get("/events")
def get_live_events(
    limit: int = Query(20, ge=1, le=100),
    since_id: Optional[int] = Query(None),
    db: Session = Depends(get_db)
):
    q = db.query(AuditLogModel)
    if since_id is not None:
        q = q.filter(AuditLogModel.id > since_id)
    records = q.order_by(AuditLogModel.id.desc()).limit(limit).all()

    items = []
    for r in records:
        try:
            payload = json.loads(r.redacted_payload)
        except Exception:
            payload = {}
        items.append({
            "id": r.id,
            "entry_id": r.entry_id,
            "timestamp": r.timestamp.isoformat(),
            "request_id": r.request_id,
            "principal_id": r.principal_id,
            "principal_role": r.principal_role,
            "category": r.category,
            "threat": r.threat_classification,
            "risk_score": r.risk_score,
            "tool_name": r.tool_name,
            "policy_rule_id": r.policy_rule_id,
            "decision": r.decision,
            "explanation": r.explanation,
            "payload": payload,
            "current_hash": r.current_hash
        })
    return {"events": items, "count": len(items)}


@router.get("/threats", response_model=ThreatStats)
def get_threat_stats(db: Session = Depends(get_db)):
    threat_logs = db.query(AuditLogModel).filter(AuditLogModel.threat_classification.in_(["HIGH", "CRITICAL"])).all()

    categories: Dict[str, Dict[str, Any]] = {}
    rule_counts: Dict[str, int] = {}

    for log in threat_logs:
        cat = log.category
        if cat not in categories:
            categories[cat] = {
                "count": 0,
                "highest": "HIGH",
                "examples": []
            }
        categories[cat]["count"] += 1
        if log.threat_classification == "CRITICAL":
            categories[cat]["highest"] = "CRITICAL"
        if len(categories[cat]["examples"]) < 3 and log.explanation not in categories[cat]["examples"]:
            categories[cat]["examples"].append(log.explanation)

        rule_counts[log.policy_rule_id] = rule_counts.get(log.policy_rule_id, 0) + 1

    breakdown = [
        ThreatItem(
            category=k,
            count=v["count"],
            highest_severity=v["highest"],
            examples=v["examples"]
        )
        for k, v in categories.items()
    ]

    top_rules = [
        {"rule_id": k, "count": v}
        for k, v in sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    ]

    return ThreatStats(
        total_threats_detected=len(threat_logs),
        breakdown_by_category=breakdown,
        top_matched_rules=top_rules
    )
