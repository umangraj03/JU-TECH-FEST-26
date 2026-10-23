import pytest
from backend.models.schema import Principal
from backend.security.gateway import gateway
from backend.tools.registry import tool_registry
from backend.tools.base import DirectToolInvocationForbidden


def test_hard_invariant_direct_tool_invocation_impossible(test_db):
    """
    Hard Invariant:
    Tools are executable ONLY through gateway.execute().
    Direct call without gateway context must raise DirectToolInvocationForbidden.
    """
    tool = tool_registry.get("search_documents")
    assert tool is not None

    with pytest.raises(DirectToolInvocationForbidden) as excinfo:
        # Attempting direct execution bypassing gateway
        tool.execute({"query": "sustainability"}, context=None, db_session=test_db)

    assert "Direct tool invocation forbidden" in str(excinfo.value)


def test_unknown_tool_blocked(test_db):
    requester = Principal(principal_id="user_requester", role="requester", name="Requester")
    decision = gateway.evaluate_and_run(
        principal=requester,
        tool_name="non_existent_hack_tool",
        raw_args={"foo": "bar"},
        is_tainted=False,
        request_id="req_test_unknown",
        session_id="sess_test",
        db=test_db
    )
    assert decision.decision == "BLOCK"
    assert decision.policy_rule_id == "RULE-AUTHZ-01"
    assert len(decision.explanation) > 0


def test_extra_arguments_forbidden_schema_validation(test_db):
    """Schema rejects extra arguments because extra='forbid'."""
    requester = Principal(principal_id="user_requester", role="requester", name="Requester")
    decision = gateway.evaluate_and_run(
        principal=requester,
        tool_name="search_documents",
        raw_args={"query": "public report", "unauthorized_extra_arg": "injection"},
        is_tainted=False,
        request_id="req_test_extra_arg",
        session_id="sess_test",
        db=test_db
    )
    assert decision.decision == "BLOCK"
    assert "schema validation failed" in decision.explanation.lower()


def test_tainted_destination_mandatory_blocked(test_db):
    """
    Hard Invariant:
    Tainted destinations are MANDATORY BLOCKED with RULE-MANDATORY-01.
    """
    approver = Principal(principal_id="user_approver", role="approver", name="Approver")
    decision = gateway.evaluate_and_run(
        principal=approver,
        tool_name="send_email",
        raw_args={
            "recipient": "partner.example.com",
            "subject": "Confidential Report",
            "body": "Automated email"
        },
        is_tainted=True,  # Destination derived from untrusted content!
        request_id="req_test_taint",
        session_id="sess_test",
        db=test_db
    )
    assert decision.decision == "BLOCK"
    assert decision.policy_rule_id == "RULE-MANDATORY-01"
    assert decision.tainted is True
    assert "tainted" in decision.explanation.lower()
