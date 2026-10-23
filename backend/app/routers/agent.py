import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.dependencies import get_current_principal
from backend.models.schema import Principal, AgentRunRequest, AgentRunResponse, SecurityFinding, ToolDecision
from backend.security.scanner import scanner
from backend.security.gateway import gateway
from backend.security.audit import audit_logger
from backend.security.dlp import dlp_scanner
from backend.agent.mock_agent import mock_agent

router = APIRouter(prefix="/api/agent", tags=["Agent"])


@router.post("/run", response_model=AgentRunResponse)
def run_agent_workflow(
    request: AgentRunRequest,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db)
):
    request_id = f"req_{uuid.uuid4().hex[:12]}"
    session_id = request.session_id or f"sess_{principal.principal_id}"

    # 1. Input Scan Layer (direct prompt inspection)
    scan_res = scanner.scan(request.message, is_untrusted_context=False)
    findings: List[SecurityFinding] = [
        SecurityFinding(
            rule_id=r["rule_id"],
            category=r["category"],
            severity=r["severity"],
            evidence=r["evidence"],
            score=float(r.get("weight", 0.0))
        )
        for r in scan_res.reasons
    ]

    # Pre-execution block if direct prompt injection is Critical or High (>= 50)
    if scan_res.threat_score >= 50.0:
        explanation = f"Prompt injection / credential extraction detected: {scan_res.reasons[0]['evidence'] if scan_res.reasons else 'Threat score exceeds threshold'}"
        audit_logger.log_event(
            request_id=request_id,
            session_id=session_id,
            principal_id=principal.principal_id,
            principal_role=principal.role,
            category="INJECTION_BLOCKED",
            threat_classification="CRITICAL",
            risk_score=scan_res.threat_score,
            tool_name=None,
            policy_rule_id="RULE-MANDATORY-04",
            decision="BLOCK",
            explanation=explanation,
            raw_payload={"message": request.message, "reasons": scan_res.reasons},
            db=db
        )
        return AgentRunResponse(
            request_id=request_id,
            session_id=session_id,
            overall_decision="BLOCK",
            decisions=[
                ToolDecision(
                    tool_name="prompt_inspection",
                    decision="BLOCK",
                    policy_rule_id="RULE-MANDATORY-04",
                    explanation=explanation,
                    executed=False
                )
            ],
            response="Execution halted: Message violates security policies for prompt injection.",
            findings=findings,
            risk_score=scan_res.threat_score,
            threat_level=scan_res.severity
        )

    # 2. Agent (proposes tool calls)
    proposed_calls, agent_reply, was_tainted = mock_agent.run_agent(
        principal=principal,
        user_message=request.message,
        request_id=request_id,
        session_id=session_id,
        db=db
    )

    decisions: List[ToolDecision] = []
    overall = "ALLOW"

    # If no tools were needed, reply directly
    if not proposed_calls:
        # Output filter
        clean_reply = dlp_scanner.redact_sensitive(agent_reply)
        return AgentRunResponse(
            request_id=request_id,
            session_id=session_id,
            overall_decision="ALLOW",
            decisions=[],
            response=clean_reply,
            findings=findings,
            risk_score=scan_res.threat_score,
            threat_level=scan_res.severity
        )

    # 3. Security Gateway: Evaluate each proposed tool call
    for call in proposed_calls:
        tool_name = call["tool_name"]
        args = call["args"]
        call_tainted = call["is_tainted"] or was_tainted

        # Check if the args contain an injection pattern or canary
        args_scan = scanner.scan(str(args), is_untrusted_context=call_tainted)
        if args_scan.reasons:
            findings.extend([
                SecurityFinding(
                    rule_id=r["rule_id"],
                    category=r["category"],
                    severity=r["severity"],
                    evidence=r["evidence"],
                    score=float(r.get("weight", 0.0))
                )
                for r in args_scan.reasons
            ])

        decision = gateway.evaluate_and_run(
            principal=principal,
            tool_name=tool_name,
            raw_args=args,
            is_tainted=call_tainted,
            request_id=request_id,
            session_id=session_id,
            db=db
        )
        decisions.append(decision)

    # 4. Overall Decision Precedence:
    # MANDATORY_DENY / BLOCK > REQUIRE_APPROVAL > ALLOW
    if any(d.decision == "BLOCK" for d in decisions):
        overall = "BLOCK"
    elif any(d.decision == "REQUIRE_APPROVAL" for d in decisions):
        overall = "REQUIRE_APPROVAL"
    else:
        overall = "ALLOW"

    # 5. Output Filter: Redact any sensitive leakage in final response
    clean_reply = dlp_scanner.redact_sensitive(agent_reply)

    # If all executed, format nice summary response
    if overall == "ALLOW":
        exec_summaries = []
        for d in decisions:
            if d.executed and d.result:
                exec_summaries.append(f"Tool {d.tool_name} returned: {d.result}")
        if exec_summaries:
            clean_reply += "\n" + "\n".join(exec_summaries)
    elif overall == "REQUIRE_APPROVAL":
        appr_ids = [d.approval_id for d in decisions if d.approval_id]
        clean_reply = f"Operation requires approval. Ticket(s) generated: {', '.join(appr_ids)}. Pending review by an authorized approver."
    else:
        blocked_explanations = [d.explanation for d in decisions if d.decision == "BLOCK"]
        clean_reply = f"Security Gateway blocked proposed action: {' '.join(blocked_explanations)}"

    # Recalculate combined risk score
    highest_finding_score = max([f.score for f in findings], default=scan_res.threat_score)
    final_score = max(scan_res.threat_score, highest_finding_score)
    if overall == "BLOCK" and final_score < 75.0:
        final_score = 75.0

    severity = "CRITICAL" if final_score >= 75.0 else ("HIGH" if final_score >= 50.0 else ("MEDIUM" if final_score >= 25.0 else "LOW"))

    return AgentRunResponse(
        request_id=request_id,
        session_id=session_id,
        overall_decision=overall,
        decisions=decisions,
        response=clean_reply,
        findings=findings,
        risk_score=round(final_score, 1),
        threat_level=severity
    )
