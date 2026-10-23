import json
import secrets
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from pydantic import ValidationError

from backend.models.schema import Principal, ToolDecision, SecurityFinding
from backend.models.db_models import DocumentModel, CustomerRecordModel
from backend.tools.base import GatewayExecutionContext, DirectToolInvocationForbidden
from backend.tools.registry import tool_registry
from backend.tools.schemas import TOOL_ARG_SCHEMAS
from backend.security.policy_engine import policy_engine
from backend.security.dlp import dlp_scanner
from backend.security.approvals import approval_manager, canonicalize_payload
from backend.security.audit import audit_logger


class SecurityGateway:
    def __init__(self):
        # Master secret generated at gateway startup, shared strictly with registered tools
        self._execution_secret = secrets.token_hex(32)
        tool_registry.bind_gateway_secret(self._execution_secret)

    def execute(
        self,
        principal: Principal,
        tool_name: str,
        arguments: Dict[str, Any],
        request_id: str,
        db: Session
    ) -> Dict[str, Any]:
        """
        Hard Invariant:
        Tools are executable ONLY through gateway.execute().
        No other code path may call a tool.
        """
        tool = tool_registry.get(tool_name)
        if not tool:
            raise ValueError(f"Tool '{tool_name}' not found.")

        # Create authorized context containing private gateway secret
        context = GatewayExecutionContext(
            execution_token=self._execution_secret,
            request_id=request_id,
            principal_role=principal.role
        )

        return tool.execute(arguments, context=context, db_session=db)

    def evaluate_and_run(
        self,
        principal: Principal,
        tool_name: str,
        raw_args: Dict[str, Any],
        is_tainted: bool,
        request_id: str,
        session_id: str,
        db: Session,
        bypass_approval_check: bool = False  # Used during approval re-evaluation
    ) -> ToolDecision:
        """
        Step 4 Gateway Pipeline:
        allowlist -> schema validation -> authorization -> taint check ->
        data classification -> destination check -> DLP -> policy decision.
        """
        # 1. Allowlist Check
        tool = tool_registry.get(tool_name)
        if not tool or tool_name not in policy_engine.policy.tools:
            explanation = f"Tool '{tool_name}' is not allowed or unknown."
            audit_logger.log_event(
                request_id=request_id,
                session_id=session_id,
                principal_id=principal.principal_id,
                principal_role=principal.role,
                category="TOOL_INVOCATION",
                threat_classification="HIGH",
                risk_score=75.0,
                tool_name=tool_name,
                policy_rule_id="RULE-AUTHZ-01",
                decision="BLOCK",
                explanation=explanation,
                raw_payload={"args": raw_args},
                db=db
            )
            return ToolDecision(
                tool_name=tool_name,
                decision="BLOCK",
                policy_rule_id="RULE-AUTHZ-01",
                explanation=explanation,
                executed=False
            )

        # 2. Schema Validation Check
        schema_cls = TOOL_ARG_SCHEMAS.get(tool_name)
        if not schema_cls:
            explanation = f"Missing schema validator for tool '{tool_name}'."
            return ToolDecision(
                tool_name=tool_name,
                decision="BLOCK",
                policy_rule_id="RULE-AUTHZ-01",
                explanation=explanation,
                executed=False
            )

        try:
            validated_model = schema_cls.model_validate(raw_args)
            validated_args = validated_model.model_dump()
        except ValidationError as e:
            explanation = f"Tool argument schema validation failed: {str(e)}"
            audit_logger.log_event(
                request_id=request_id,
                session_id=session_id,
                principal_id=principal.principal_id,
                principal_role=principal.role,
                category="SCHEMA_VALIDATION",
                threat_classification="HIGH",
                risk_score=60.0,
                tool_name=tool_name,
                policy_rule_id="RULE-AUTHZ-01",
                decision="BLOCK",
                explanation=explanation,
                raw_payload={"args": raw_args, "validation_error": str(e)},
                db=db
            )
            return ToolDecision(
                tool_name=tool_name,
                decision="BLOCK",
                policy_rule_id="RULE-AUTHZ-01",
                explanation=explanation,
                executed=False
            )

        # 3. Role Tool Authorization
        allowed, err = policy_engine.check_role_tool_allowed(principal.role, tool_name)
        if not allowed:
            explanation = err or f"Role '{principal.role}' unauthorized for tool '{tool_name}'."
            audit_logger.log_event(
                request_id=request_id,
                session_id=session_id,
                principal_id=principal.principal_id,
                principal_role=principal.role,
                category="AUTHORIZATION",
                threat_classification="HIGH",
                risk_score=70.0,
                tool_name=tool_name,
                policy_rule_id="RULE-AUTHZ-01",
                decision="BLOCK",
                explanation=explanation,
                raw_payload={"args": validated_args},
                db=db
            )
            return ToolDecision(
                tool_name=tool_name,
                decision="BLOCK",
                policy_rule_id="RULE-AUTHZ-01",
                explanation=explanation,
                executed=False
            )

        # 4. Record Access Authorization & Classification Check
        affected_classes = ["public"]
        if tool_name == "get_customer_record":
            cust_id = validated_args.get("customer_id")
            record = db.query(CustomerRecordModel).filter(CustomerRecordModel.id == cust_id).first()
            if record:
                affected_classes = [record.classification]
                allowed_class, class_err = policy_engine.check_record_class_allowed(principal.role, record.classification)
                if not allowed_class:
                    explanation = class_err or f"Role '{principal.role}' cannot access '{record.classification}' customer records."
                    audit_logger.log_event(
                        request_id=request_id,
                        session_id=session_id,
                        principal_id=principal.principal_id,
                        principal_role=principal.role,
                        category="AUTHORIZATION",
                        threat_classification="HIGH",
                        risk_score=80.0,
                        tool_name=tool_name,
                        policy_rule_id="RULE-AUTHZ-02",
                        decision="BLOCK",
                        explanation=explanation,
                        raw_payload={"customer_id": cust_id, "classification": record.classification},
                        db=db
                    )
                    return ToolDecision(
                        tool_name=tool_name,
                        decision="BLOCK",
                        policy_rule_id="RULE-AUTHZ-02",
                        explanation=explanation,
                        executed=False
                    )

        if tool_name in ["summarize_report", "export_report"]:
            report_id = validated_args.get("report_id")
            doc = db.query(DocumentModel).filter(DocumentModel.id == report_id).first()
            if doc:
                affected_classes = [doc.classification]
                allowed_class, class_err = policy_engine.check_record_class_allowed(principal.role, doc.classification)
                if not allowed_class:
                    explanation = class_err or f"Role '{principal.role}' cannot access '{doc.classification}' report."
                    audit_logger.log_event(
                        request_id=request_id,
                        session_id=session_id,
                        principal_id=principal.principal_id,
                        principal_role=principal.role,
                        category="AUTHORIZATION",
                        threat_classification="HIGH",
                        risk_score=80.0,
                        tool_name=tool_name,
                        policy_rule_id="RULE-AUTHZ-02",
                        decision="BLOCK",
                        explanation=explanation,
                        raw_payload={"report_id": report_id, "classification": doc.classification},
                        db=db
                    )
                    return ToolDecision(
                        tool_name=tool_name,
                        decision="BLOCK",
                        policy_rule_id="RULE-AUTHZ-02",
                        explanation=explanation,
                        executed=False
                    )

        # 5. Taint & Provenance Checks
        dest_field = validated_args.get("destination") or validated_args.get("recipient")
        if is_tainted and dest_field:
            # Hard Invariant: Tainted destinations are MANDATORY BLOCKED
            explanation = f"MANDATORY DENY: Destination '{dest_field}' originated from untrusted content (tainted)."
            audit_logger.log_event(
                request_id=request_id,
                session_id=session_id,
                principal_id=principal.principal_id,
                principal_role=principal.role,
                category="TAINT_VIOLATION",
                threat_classification="CRITICAL",
                risk_score=95.0,
                tool_name=tool_name,
                policy_rule_id="RULE-MANDATORY-01",
                decision="BLOCK",
                explanation=explanation,
                raw_payload={"args": validated_args, "is_tainted": True},
                db=db
            )
            return ToolDecision(
                tool_name=tool_name,
                decision="BLOCK",
                policy_rule_id="RULE-MANDATORY-01",
                explanation=explanation,
                tainted=True,
                executed=False
            )

        # 6. Destination Check (Exact match against allowlist; defeat lookalikes and query leaks)
        if dest_field:
            # Query leak check
            leak_detected, leak_err = dlp_scanner.check_embedded_query_leak(str(validated_args))
            if leak_detected:
                explanation = f"MANDATORY DENY: {leak_err}"
                audit_logger.log_event(
                    request_id=request_id,
                    session_id=session_id,
                    principal_id=principal.principal_id,
                    principal_role=principal.role,
                    category="EGRESS_VIOLATION",
                    threat_classification="CRITICAL",
                    risk_score=95.0,
                    tool_name=tool_name,
                    policy_rule_id="RULE-MANDATORY-02",
                    decision="BLOCK",
                    explanation=explanation,
                    raw_payload={"args": validated_args},
                    db=db
                )
                return ToolDecision(
                    tool_name=tool_name,
                    decision="BLOCK",
                    policy_rule_id="RULE-MANDATORY-02",
                    explanation=explanation,
                    executed=False
                )

            # Domain allowlist check
            valid_dest, dest_err = dlp_scanner.validate_destination_exact(
                dest_field, policy_engine.policy.approved_destinations
            )
            if not valid_dest:
                explanation = f"MANDATORY DENY: Destination '{dest_field}' failed allowlist: {dest_err}"
                audit_logger.log_event(
                    request_id=request_id,
                    session_id=session_id,
                    principal_id=principal.principal_id,
                    principal_role=principal.role,
                    category="EGRESS_VIOLATION",
                    threat_classification="CRITICAL",
                    risk_score=90.0,
                    tool_name=tool_name,
                    policy_rule_id="RULE-MANDATORY-02",
                    decision="BLOCK",
                    explanation=explanation,
                    raw_payload={"args": validated_args},
                    db=db
                )
                return ToolDecision(
                    tool_name=tool_name,
                    decision="BLOCK",
                    policy_rule_id="RULE-MANDATORY-02",
                    explanation=explanation,
                    executed=False
                )

        # 7. DLP & Canary Check
        canaries = dlp_scanner.detect_canaries(str(validated_args))
        if canaries and dest_field:
            explanation = f"MANDATORY DENY: Canary token leakage detected in outbound action to '{dest_field}'."
            audit_logger.log_event(
                request_id=request_id,
                session_id=session_id,
                principal_id=principal.principal_id,
                principal_role=principal.role,
                category="DLP_LEAKAGE",
                threat_classification="CRITICAL",
                risk_score=100.0,
                tool_name=tool_name,
                policy_rule_id="RULE-MANDATORY-03",
                decision="BLOCK",
                explanation=explanation,
                raw_payload={"canaries_count": len(canaries)},
                db=db
            )
            return ToolDecision(
                tool_name=tool_name,
                decision="BLOCK",
                policy_rule_id="RULE-MANDATORY-03",
                explanation=explanation,
                executed=False
            )

        # Egress budget check
        if tool_name in ["send_email", "export_report"]:
            payload_size = len(str(validated_args))
            budget_ok, budget_err = dlp_scanner.check_and_update_egress_budget(
                session_id, payload_size, db, policy_engine.policy.limits.session_egress_budget_bytes
            )
            if not budget_ok:
                explanation = budget_err or "Cumulative session egress budget exceeded."
                audit_logger.log_event(
                    request_id=request_id,
                    session_id=session_id,
                    principal_id=principal.principal_id,
                    principal_role=principal.role,
                    category="EGRESS_BUDGET",
                    threat_classification="HIGH",
                    risk_score=75.0,
                    tool_name=tool_name,
                    policy_rule_id="RULE-DLP-01",
                    decision="BLOCK",
                    explanation=explanation,
                    raw_payload={"size_bytes": payload_size},
                    db=db
                )
                return ToolDecision(
                    tool_name=tool_name,
                    decision="BLOCK",
                    policy_rule_id="RULE-DLP-01",
                    explanation=explanation,
                    executed=False
                )

        # 8. Approval Workflow Check
        needs_approval, approval_reason = policy_engine.check_tool_requires_approval(tool_name, validated_args)
        if "confidential" in affected_classes and tool_name in ["export_report", "send_email"]:
            needs_approval = True
            approval_reason = f"Tool '{tool_name}' involves confidential data export."

        if needs_approval and not bypass_approval_check:
            # Create approval ticket
            rule_id = "RULE-APPROVAL-01" if tool.is_write else "RULE-APPROVAL-02"
            appr = approval_manager.create_approval_request(
                request_id=request_id,
                session_id=session_id,
                requester_id=principal.principal_id,
                requester_role=principal.role,
                tool_name=tool_name,
                arguments=validated_args,
                affected_data_classes=affected_classes,
                destination=dest_field,
                risk_reason=approval_reason or "Sensitive operation requires human authorization.",
                policy_rule_id=rule_id,
                db=db
            )
            explanation = f"Action escalated to approval queue: {approval_reason}"
            audit_logger.log_event(
                request_id=request_id,
                session_id=session_id,
                principal_id=principal.principal_id,
                principal_role=principal.role,
                category="APPROVAL_REQUIRED",
                threat_classification="MEDIUM",
                risk_score=35.0,
                tool_name=tool_name,
                policy_rule_id=rule_id,
                decision="REQUIRE_APPROVAL",
                explanation=explanation,
                raw_payload={"approval_id": appr.id, "args": validated_args},
                db=db
            )
            return ToolDecision(
                tool_name=tool_name,
                decision="REQUIRE_APPROVAL",
                policy_rule_id=rule_id,
                explanation=explanation,
                approval_id=appr.id,
                tainted=is_tainted,
                executed=False
            )

        # 9. All Checks Pass -> ALLOW and EXECUTE
        exec_result = self.execute(
            principal=principal,
            tool_name=tool_name,
            arguments=validated_args,
            request_id=request_id,
            db=db
        )

        # Apply data minimization
        tool_config = policy_engine.policy.tools.get(tool_name)
        minimized = dlp_scanner.minimize_data(exec_result, tool_config.field_allowlist if tool_config else [])

        explanation = f"Execution permitted by policy for tool '{tool_name}'."
        audit_logger.log_event(
            request_id=request_id,
            session_id=session_id,
            principal_id=principal.principal_id,
            principal_role=principal.role,
            category="EXECUTION",
            threat_classification="LOW",
            risk_score=5.0,
            tool_name=tool_name,
            policy_rule_id="RULE-ALLOW-DEFAULT",
            decision="ALLOW",
            explanation=explanation,
            raw_payload={"result_summary": list(minimized.keys())},
            db=db
        )

        return ToolDecision(
            tool_name=tool_name,
            decision="ALLOW",
            policy_rule_id="RULE-ALLOW-DEFAULT",
            explanation=explanation,
            tainted=is_tainted,
            executed=True,
            result=minimized
        )


gateway = SecurityGateway()
