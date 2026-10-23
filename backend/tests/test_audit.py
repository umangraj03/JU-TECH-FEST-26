import json
import pytest
from backend.models.db_models import AuditLogModel
from backend.security.audit import audit_logger


def test_audit_redacts_canaries_and_secrets(test_db):
    canary = "CANARY-CUST-88392-SECRET"
    record = audit_logger.log_event(
        request_id="req_audit_test",
        session_id="sess_1",
        principal_id="user_test",
        principal_role="requester",
        category="TEST_CATEGORY",
        threat_classification="CRITICAL",
        risk_score=90.0,
        tool_name="send_email",
        policy_rule_id="RULE-MANDATORY-03",
        decision="BLOCK",
        explanation=f"Attempted transmission containing canary token {canary}",
        raw_payload={"secret": canary, "api_key": "ak_1234567890abcdef123456"},
        db=test_db
    )

    # In database, explanation and payload must be redacted
    assert canary not in record.explanation
    assert "[REDACTED_CANARY]" in record.explanation
    assert canary not in record.redacted_payload
    assert "[REDACTED_CANARY]" in record.redacted_payload
    assert "ak_1234567890abcdef123456" not in record.redacted_payload


def test_hash_chain_validity_and_tamper_detection(client, test_db):
    # Log 3 events
    for i in range(3):
        audit_logger.log_event(
            request_id=f"req_{i}",
            session_id="sess_chain",
            principal_id="user_chain",
            principal_role="requester",
            category="TEST",
            threat_classification="LOW",
            risk_score=10.0,
            tool_name="search_documents",
            policy_rule_id="RULE-ALLOW-DEFAULT",
            decision="ALLOW",
            explanation=f"Valid query {i}",
            raw_payload={"query": f"test {i}"},
            db=test_db
        )

    # 1. Chain must initially verify successfully
    is_valid, count, last_id, broken_id, msg = audit_logger.verify_chain(test_db)
    assert is_valid is True
    assert count >= 3
    assert broken_id is None

    # Check via verify endpoint
    res = client.get("/api/audit/verify")
    assert res.status_code == 200
    assert res.json()["verified"] is True

    # 2. Tamper with an existing record's decision or payload
    tampered_entry = test_db.query(AuditLogModel).order_by(AuditLogModel.id.asc()).first()
    tampered_entry.explanation = "TAMPERED EXPLANATION"
    test_db.commit()

    # 3. Chain verification must detect the tamper
    is_valid_tampered, count_t, last_id_t, broken_t, msg_t = audit_logger.verify_chain(test_db)
    assert is_valid_tampered is False
    assert broken_t == tampered_entry.entry_id
    assert "tamper detected" in msg_t.lower()

    # Verify endpoint reflects tamper
    res_tampered = client.get("/api/audit/verify")
    assert res_tampered.json()["verified"] is False
    assert res_tampered.json()["broken_entry_id"] == tampered_entry.entry_id
