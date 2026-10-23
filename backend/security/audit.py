import json
import hashlib
import uuid
import datetime
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from backend.models.db_models import AuditLogModel
from backend.security.dlp import dlp_scanner

GENESIS_HASH = "0" * 64


def compute_audit_hash(
    entry_id: str,
    timestamp_iso: str,
    request_id: str,
    session_id: str,
    principal_id: str,
    principal_role: str,
    category: str,
    threat_classification: str,
    risk_score: float,
    tool_name: Optional[str],
    policy_rule_id: str,
    decision: str,
    explanation: str,
    redacted_payload_json: str,
    prev_hash: str
) -> str:
    payload = {
        "entry_id": entry_id,
        "timestamp": timestamp_iso,
        "request_id": request_id,
        "session_id": session_id,
        "principal_id": principal_id,
        "principal_role": principal_role,
        "category": category,
        "threat_classification": threat_classification,
        "risk_score": round(float(risk_score), 2),
        "tool_name": tool_name or "",
        "policy_rule_id": policy_rule_id,
        "decision": decision,
        "explanation": explanation,
        "redacted_payload": redacted_payload_json,
        "prev_hash": prev_hash
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLogger:
    def log_event(
        self,
        request_id: str,
        session_id: str,
        principal_id: str,
        principal_role: str,
        category: str,
        threat_classification: str,
        risk_score: float,
        tool_name: Optional[str],
        policy_rule_id: str,
        decision: str,
        explanation: str,
        raw_payload: Dict[str, Any],
        db: Session
    ) -> AuditLogModel:
        # 1. Redact secrets & canaries from payload & explanation
        cleaned_payload: Dict[str, Any] = {}
        for k, v in raw_payload.items():
            if isinstance(v, str):
                cleaned_payload[k] = dlp_scanner.redact_sensitive(v)
            elif isinstance(v, (int, float, bool)) or v is None:
                cleaned_payload[k] = v
            else:
                try:
                    str_repr = json.dumps(v)
                    cleaned_payload[k] = json.loads(dlp_scanner.redact_sensitive(str_repr))
                except Exception:
                    cleaned_payload[k] = "[COMPLEX_OBJECT]"

        redacted_explanation = dlp_scanner.redact_sensitive(explanation)
        redacted_json = json.dumps(cleaned_payload, sort_keys=True)

        # 2. Get last hash in chain
        last_entry = db.query(AuditLogModel).order_by(AuditLogModel.id.desc()).first()
        prev_hash = last_entry.current_hash if last_entry else GENESIS_HASH

        entry_id = f"aud_{uuid.uuid4().hex}"
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        timestamp_iso = now.isoformat()

        # 3. Calculate current hash
        current_hash = compute_audit_hash(
            entry_id=entry_id,
            timestamp_iso=timestamp_iso,
            request_id=request_id,
            session_id=session_id,
            principal_id=principal_id,
            principal_role=principal_role,
            category=category,
            threat_classification=threat_classification,
            risk_score=risk_score,
            tool_name=tool_name,
            policy_rule_id=policy_rule_id,
            decision=decision,
            explanation=redacted_explanation,
            redacted_payload_json=redacted_json,
            prev_hash=prev_hash
        )

        record = AuditLogModel(
            entry_id=entry_id,
            timestamp=now,
            request_id=request_id,
            session_id=session_id,
            principal_id=principal_id,
            principal_role=principal_role,
            category=category,
            threat_classification=threat_classification,
            risk_score=risk_score,
            tool_name=tool_name,
            policy_rule_id=policy_rule_id,
            decision=decision,
            explanation=redacted_explanation,
            redacted_payload=redacted_json,
            prev_hash=prev_hash,
            current_hash=current_hash
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    def verify_chain(self, db: Session) -> Tuple[bool, int, Optional[str], Optional[str], str]:
        """
        Verifies the cryptographic integrity of the entire audit hash chain.
        Returns (is_valid, count, last_valid_id, broken_id, message).
        """
        records = db.query(AuditLogModel).order_by(AuditLogModel.id.asc()).all()
        if not records:
            return True, 0, None, None, "Audit log is empty; chain is valid."

        expected_prev = GENESIS_HASH
        last_valid_id = None

        for rec in records:
            # Check previous hash pointer
            if rec.prev_hash != expected_prev:
                return (
                    False,
                    len(records),
                    last_valid_id,
                    rec.entry_id,
                    f"Hash chain broken at entry {rec.entry_id}: expected prev_hash '{expected_prev}', got '{rec.prev_hash}'"
                )

            # Check self-hash computation
            computed = compute_audit_hash(
                entry_id=rec.entry_id,
                timestamp_iso=rec.timestamp.isoformat(),
                request_id=rec.request_id,
                session_id=rec.session_id,
                principal_id=rec.principal_id,
                principal_role=rec.principal_role,
                category=rec.category,
                threat_classification=rec.threat_classification,
                risk_score=rec.risk_score,
                tool_name=rec.tool_name,
                policy_rule_id=rec.policy_rule_id,
                decision=rec.decision,
                explanation=rec.explanation,
                redacted_payload_json=rec.redacted_payload,
                prev_hash=rec.prev_hash
            )

            if computed != rec.current_hash:
                return (
                    False,
                    len(records),
                    last_valid_id,
                    rec.entry_id,
                    f"Tamper detected at entry {rec.entry_id}: computed hash does not match current_hash"
                )

            expected_prev = rec.current_hash
            last_valid_id = rec.entry_id

        return True, len(records), last_valid_id, None, f"Hash chain fully verified across {len(records)} entries."


audit_logger = AuditLogger()
