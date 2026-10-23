import pytest
from backend.models.schema import Principal
from backend.security.gateway import gateway


def test_requester_cannot_access_confidential_customer_record(test_db):
    requester = Principal(principal_id="user_requester", role="requester", name="Requester")
    decision = gateway.evaluate_and_run(
        principal=requester,
        tool_name="get_customer_record",
        raw_args={"customer_id": "CUST-CONF-101"},
        is_tainted=False,
        request_id="req_test_authz_1",
        session_id="sess_test",
        db=test_db
    )
    assert decision.decision == "BLOCK"
    assert decision.policy_rule_id == "RULE-AUTHZ-02"
    assert len(decision.explanation) > 0
    assert "confidential" in decision.explanation.lower()


def test_approver_can_access_confidential_customer_record(test_db):
    approver = Principal(principal_id="user_approver", role="approver", name="Approver")
    decision = gateway.evaluate_and_run(
        principal=approver,
        tool_name="get_customer_record",
        raw_args={"customer_id": "CUST-CONF-101"},
        is_tainted=False,
        request_id="req_test_authz_2",
        session_id="sess_test",
        db=test_db
    )
    assert decision.decision == "ALLOW"
    assert decision.executed is True
    assert decision.result is not None
    assert decision.result["id"] == "CUST-CONF-101"


def test_requester_disallowed_tool(test_db):
    requester = Principal(principal_id="user_requester", role="requester", name="Requester")
    # send_email is not in requester allowed_tools
    decision = gateway.evaluate_and_run(
        principal=requester,
        tool_name="send_email",
        raw_args={"recipient": "partner.example.com", "subject": "Test", "body": "Test"},
        is_tainted=False,
        request_id="req_test_authz_3",
        session_id="sess_test",
        db=test_db
    )
    assert decision.decision == "BLOCK"
    assert decision.policy_rule_id == "RULE-AUTHZ-01"
    assert len(decision.explanation) > 0


def test_admin_only_policy_update(client, requester_headers, admin_headers):
    # Requester attempting policy update fails with 403
    res_req = client.put("/api/policy", content="invalid: yaml", headers=requester_headers)
    assert res_req.status_code == 403
    assert res_req.json()["detail"] == "Admin privileges required."
