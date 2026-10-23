import datetime
import pytest
from backend.models.schema import Principal
from backend.security.approvals import approval_manager, compute_payload_hash, canonicalize_payload
from backend.security.gateway import gateway


def test_self_approval_forbidden(test_db):
    appr = approval_manager.create_approval_request(
        request_id="req_self_1",
        session_id="sess_1",
        requester_id="user_requester",
        requester_role="requester",
        tool_name="update_customer_record",
        arguments={"customer_id": "CUST-CONF-101", "field": "email", "new_value": "test@acme-corp.internal"},
        affected_data_classes=["confidential"],
        destination=None,
        risk_reason="Write operation",
        policy_rule_id="RULE-APPROVAL-01",
        db=test_db
    )

    # Requester attempts to approve their own request
    ok, msg, _ = approval_manager.validate_and_approve(
        approval_id=appr.id,
        actor_id="user_requester",
        actor_role="approver",  # Even if they spoof role, requester_id matches actor_id
        db=test_db
    )
    assert ok is False
    assert "self-approval forbidden" in msg.lower()


def test_wrong_role_cannot_approve(test_db):
    appr = approval_manager.create_approval_request(
        request_id="req_role_1",
        session_id="sess_1",
        requester_id="user_requester",
        requester_role="requester",
        tool_name="update_customer_record",
        arguments={"customer_id": "CUST-CONF-101", "field": "email", "new_value": "test@acme-corp.internal"},
        affected_data_classes=["confidential"],
        destination=None,
        risk_reason="Write operation",
        policy_rule_id="RULE-APPROVAL-01",
        db=test_db
    )

    ok, msg, _ = approval_manager.validate_and_approve(
        approval_id=appr.id,
        actor_id="other_requester",
        actor_role="requester",  # Role is not approver
        db=test_db
    )
    assert ok is False
    assert "not authorized to approve" in msg.lower()


def test_expired_approval_rejected(test_db):
    appr = approval_manager.create_approval_request(
        request_id="req_exp_1",
        session_id="sess_1",
        requester_id="user_requester",
        requester_role="requester",
        tool_name="update_customer_record",
        arguments={"customer_id": "CUST-CONF-101", "field": "email", "new_value": "test@acme-corp.internal"},
        affected_data_classes=["confidential"],
        destination=None,
        risk_reason="Write operation",
        policy_rule_id="RULE-APPROVAL-01",
        db=test_db
    )

    # Artificially expire the ticket
    appr.expires_at = datetime.datetime.utcnow() - datetime.timedelta(seconds=10)
    test_db.commit()

    ok, msg, _ = approval_manager.validate_and_approve(
        approval_id=appr.id,
        actor_id="user_approver",
        actor_role="approver",
        db=test_db
    )
    assert ok is False
    assert "expired" in msg.lower()


def test_approval_replay_rejected(test_db):
    appr = approval_manager.create_approval_request(
        request_id="req_rep_1",
        session_id="sess_1",
        requester_id="user_requester",
        requester_role="requester",
        tool_name="update_customer_record",
        arguments={"customer_id": "CUST-CONF-101", "field": "email", "new_value": "test@acme-corp.internal"},
        affected_data_classes=["confidential"],
        destination=None,
        risk_reason="Write operation",
        policy_rule_id="RULE-APPROVAL-01",
        db=test_db
    )

    # First approval succeeds
    ok1, _, _ = approval_manager.validate_and_approve(
        approval_id=appr.id,
        actor_id="user_approver",
        actor_role="approver",
        db=test_db
    )
    assert ok1 is True

    # Replay attempt fails
    ok2, msg2, _ = approval_manager.validate_and_approve(
        approval_id=appr.id,
        actor_id="user_approver",
        actor_role="approver",
        db=test_db
    )
    assert ok2 is False
    assert "already" in msg2.lower()


def test_payload_swap_tamper_detected(client, approver_headers, test_db):
    """
    If attacker attempts to approve an altered payload,
    hash mismatch prevents execution.
    """
    appr = approval_manager.create_approval_request(
        request_id="req_swap_1",
        session_id="sess_1",
        requester_id="user_requester",
        requester_role="requester",
        tool_name="update_customer_record",
        arguments={"customer_id": "CUST-CONF-101", "field": "email", "new_value": "legit@acme-corp.internal"},
        affected_data_classes=["confidential"],
        destination=None,
        risk_reason="Write operation",
        policy_rule_id="RULE-APPROVAL-01",
        db=test_db
    )

    # Tamper with stored canonical json behind the scenes (swap payload)
    tampered_canonical = canonicalize_payload(
        "update_customer_record",
        {"customer_id": "CUST-CONF-101", "field": "email", "new_value": "hacked@evil.test"}
    )
    appr.arguments_canonical_json = tampered_canonical
    test_db.commit()

    # Attempt to approve via API
    res = client.post(f"/api/approvals/{appr.id}/approve", headers=approver_headers)
    assert res.status_code == 400
    assert "hash mismatch" in res.json()["detail"].lower()


def test_mandatory_deny_stays_blocked_even_after_approval(client, approver_headers, test_db):
    """
    Hard Invariant:
    If an action has a mandatory-deny violation (e.g. unapproved destination or canary leak),
    fresh gateway re-check BLOCKS it despite approval.
    """
    # Create approval for export to unapproved domain
    appr = approval_manager.create_approval_request(
        request_id="req_mand_1",
        session_id="sess_1",
        requester_id="user_requester",
        requester_role="requester",
        tool_name="export_report",
        arguments={"report_id": "REP-INT-01", "destination": "unapproved.evil.test", "format": "json"},
        affected_data_classes=["internal"],
        destination="unapproved.evil.test",
        risk_reason="Export request",
        policy_rule_id="RULE-APPROVAL-02",
        db=test_db
    )

    # Call approve endpoint
    res = client.post(f"/api/approvals/{appr.id}/approve", headers=approver_headers)
    data = res.json()
    assert data["status"] == "BLOCKED_POST_APPROVAL"
    assert "mandatory" in data["message"].lower()
    assert data["decision"]["decision"] == "BLOCK"
