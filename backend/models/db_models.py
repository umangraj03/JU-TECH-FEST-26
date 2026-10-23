import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    entry_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    request_id = Column(String(64), index=True, nullable=False)
    session_id = Column(String(64), index=True, nullable=False)
    principal_id = Column(String(64), nullable=False)
    principal_role = Column(String(32), nullable=False)
    category = Column(String(64), nullable=False)
    threat_classification = Column(String(32), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score = Column(Float, nullable=False, default=0.0)
    tool_name = Column(String(64), nullable=True)
    policy_rule_id = Column(String(64), nullable=False)
    decision = Column(String(32), nullable=False)  # ALLOW, BLOCK, REQUIRE_APPROVAL
    explanation = Column(Text, nullable=False)
    redacted_payload = Column(Text, nullable=False)  # JSON string
    prev_hash = Column(String(64), nullable=False)
    current_hash = Column(String(64), nullable=False)


class ApprovalModel(Base):
    __tablename__ = "approvals"

    id = Column(String(64), primary_key=True)
    request_id = Column(String(64), index=True, nullable=False)
    session_id = Column(String(64), index=True, nullable=False)
    requester_id = Column(String(64), nullable=False)
    requester_role = Column(String(32), nullable=False)
    tool_name = Column(String(64), nullable=False)
    arguments_canonical_json = Column(Text, nullable=False)
    payload_sha256 = Column(String(64), nullable=False)
    affected_data_classes = Column(Text, nullable=False)  # JSON list
    destination = Column(String(256), nullable=True)
    risk_reason = Column(Text, nullable=False)
    policy_rule_id = Column(String(64), nullable=False)
    status = Column(String(32), default="PENDING", nullable=False)  # PENDING, APPROVED, REJECTED, EXPIRED
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(64), nullable=True)


class SessionBudgetModel(Base):
    __tablename__ = "session_budgets"

    session_id = Column(String(64), primary_key=True)
    total_egress_bytes = Column(Integer, default=0, nullable=False)
    tool_call_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)


class DocumentModel(Base):
    __tablename__ = "documents"

    id = Column(String(64), primary_key=True)
    title = Column(String(256), nullable=False)
    classification = Column(String(32), nullable=False)  # public, internal, confidential
    author = Column(String(128), nullable=False)
    content = Column(Text, nullable=False)
    is_malicious = Column(Boolean, default=False, nullable=False)
    attack_type = Column(String(64), nullable=True)


class CustomerRecordModel(Base):
    __tablename__ = "customer_records"

    id = Column(String(64), primary_key=True)
    name = Column(String(128), nullable=False)
    company = Column(String(128), nullable=False)
    tier = Column(String(32), nullable=False)
    email = Column(String(128), nullable=False)
    phone = Column(String(64), nullable=False)
    classification = Column(String(32), default="confidential", nullable=False)
    canary_token = Column(String(64), nullable=False)
    data = Column(Text, nullable=False)  # JSON
