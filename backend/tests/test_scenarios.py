import pytest


def test_scenario_1_legit_public_report_summary(client, requester_headers):
    """Scenario 1: Legit public report summary -> ALLOW."""
    res = client.post("/api/scenarios/scenario_1/run", headers=requester_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["passed"] is True
    assert data["actual_decision"] == "ALLOW"
    assert data["result"]["overall_decision"] == "ALLOW"
    assert "summary" in data["result"]["response"].lower()


def test_scenario_2_indirect_prompt_injection(client, requester_headers):
    """Scenario 2: Retrieved document with injection -> flagged High/Critical, neutralized/blocked."""
    res = client.post("/api/scenarios/scenario_2/run", headers=requester_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["passed"] is True
    assert data["actual_decision"] == "BLOCK"
    assert data["result"]["risk_score"] >= 50.0
    assert data["result"]["threat_level"] in ["HIGH", "CRITICAL"]


def test_scenario_3_restricted_customer_record_access(client, requester_headers):
    """Scenario 3: Requester asks for restricted customer record -> BLOCK with reason."""
    res = client.post("/api/scenarios/scenario_3/run", headers=requester_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["passed"] is True
    assert data["actual_decision"] == "BLOCK"
    decisions = data["result"]["decisions"]
    assert any(d["policy_rule_id"] == "RULE-AUTHZ-02" for d in decisions)


def test_scenario_4_unapproved_or_lookalike_domain_exfiltration(client, approver_headers):
    """Scenario 4: Confidential data sent to lookalike domain -> BLOCK, logged."""
    res = client.post("/api/scenarios/scenario_4/run", headers=approver_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["passed"] is True
    assert data["actual_decision"] == "BLOCK"
    decisions = data["result"]["decisions"]
    assert any(d["policy_rule_id"] == "RULE-MANDATORY-02" for d in decisions)


def test_scenario_5_sensitive_write_approval_flow(client, requester_headers, approver_headers):
    """Scenario 5: Sensitive write -> REQUIRE_APPROVAL -> approver approves -> fresh re-check -> executes."""
    # Step A: Requester triggers action -> REQUIRE_APPROVAL
    res = client.post("/api/scenarios/scenario_5/run", headers=requester_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["passed"] is True
    assert data["actual_decision"] == "REQUIRE_APPROVAL"

    decisions = data["result"]["decisions"]
    appr_id = decisions[0]["approval_id"]
    assert appr_id is not None

    # Step B: Approver approves the ticket -> fresh re-check passes -> executes
    res_appr = client.post(f"/api/approvals/{appr_id}/approve", headers=approver_headers)
    assert res_appr.status_code == 200
    appr_data = res_appr.json()
    assert appr_data["status"] == "EXECUTED"
    assert appr_data["decision"]["executed"] is True
    assert appr_data["decision"]["decision"] == "ALLOW"


def test_scenario_6_benign_requests_suite(client, requester_headers):
    """Scenario 6: >= 5 varied benign requests -> all ALLOW with 0 false positives."""
    res = client.post("/api/scenarios/scenario_6/run", headers=requester_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["passed"] is True
    assert data["actual_decision"] == "ALLOW"
    suite = data["suite_results"]
    assert len(suite) >= 5
    for item in suite:
        assert item["passed"] is True
        assert item["overall_decision"] == "ALLOW"
        assert item["risk_score"] < 25.0
